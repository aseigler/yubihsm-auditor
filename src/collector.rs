//! Polling, cursor management, hash-chain checking, and log index advancement.

use crate::{
    codes,
    config::{Config, Device, DeviceInfoSource},
    event::{self, AuditEvent, LogEntry, PollContext, TickAnchor},
    probe,
    sink::Sink,
    state::DeviceState,
};
use anyhow::{Context, Result};
use std::collections::{BTreeMap, HashMap};
use yubihsm::{Client, authentication::Credentials, connector::Connector};

/// What a single poll of one device accomplished.
#[derive(Clone, Debug, Default)]
pub struct PollOutcome {
    pub entries_returned: usize,
    pub entries_new: usize,
    pub events_emitted: usize,
    pub chain_mismatches: usize,
    pub chain_unverified: usize,
    pub advanced_to: Option<u16>,
    pub log_store_used: Option<u8>,
    pub log_store_capacity: Option<u8>,
    /// True when no session was opened because the device reported no new log
    /// activity.
    pub skipped: bool,
}

/// Device serial, firmware, and log utilisation, however they were obtained.
#[derive(Clone, Debug)]
pub struct Snapshot {
    pub source: &'static str,
    pub serial: Option<String>,
    pub version: Option<String>,
    pub log_store_used: Option<u8>,
    pub log_store_capacity: Option<u8>,
}

impl Snapshot {
    fn empty(source: &'static str) -> Self {
        Self {
            source,
            serial: None,
            version: None,
            log_store_used: None,
            log_store_capacity: None,
        }
    }

    fn from_probe(info: &probe::DeviceInfo) -> Self {
        Self {
            source: DeviceInfoSource::Connector.as_str(),
            serial: Some(info.serial()),
            version: Some(info.version()),
            log_store_used: Some(info.log_store_used),
            log_store_capacity: Some(info.log_store_capacity),
        }
    }

    fn from_session(info: &yubihsm::device::Info) -> Self {
        Self {
            source: DeviceInfoSource::Session.as_str(),
            serial: Some(info.serial_number.to_string()),
            version: Some(format!(
                "{}.{}.{}",
                info.major_version, info.minor_version, info.build_version
            )),
            log_store_used: Some(info.log_store_used),
            log_store_capacity: Some(info.log_store_capacity),
        }
    }
}

/// Open an authenticated session with a device.
pub fn connect(device: &Device) -> Result<Client> {
    let password = device.password()?;
    let credentials = Credentials::from_password(device.auth_key_id, password.as_bytes());
    let connector = Connector::http(&device.http_config());
    Client::open(connector, credentials, true).with_context(|| {
        format!(
            "{}: authenticating to {} with key 0x{:04x}",
            device.name,
            device.connector_url(),
            device.auth_key_id
        )
    })
}

/// Poll one device: ask whether there is anything to collect, and collect it.
///
/// With `device_info_source = "connector"` the question is answered by an
/// unauthenticated `GetDeviceInfo`, which the device does not log. If the answer
/// is no, this returns without ever opening a session — and so without adding
/// the `create_session`/`authenticate_session`/`get_log_entries` entries a poll
/// would otherwise contribute to the device's own 62-entry buffer.
pub fn poll(
    config: &Config,
    device: &Device,
    sink: &mut dyn Sink,
    dry_run: bool,
) -> Result<PollOutcome> {
    let probed = match config.device_info_source {
        DeviceInfoSource::Connector => Some(probe::fetch(device)?),
        DeviceInfoSource::Session | DeviceInfoSource::None => None,
    };

    if let Some(info) = &probed
        && let Some(outcome) = try_fast_path(config, device, info, sink, dry_run)?
    {
        return Ok(outcome);
    }

    let client = connect(device)?;
    poll_device(config, device, &client, probed.as_ref(), sink, dry_run)
}

/// Decide whether this poll can be answered without a session, and if so emit
/// the heartbeat and return.
///
/// `Ok(None)` means "connect and do the real thing".
fn try_fast_path(
    config: &Config,
    device: &Device,
    info: &probe::DeviceInfo,
    sink: &mut dyn Sink,
    dry_run: bool,
) -> Result<Option<PollOutcome>> {
    // A dry run never records the baseline, so letting it skip would let it
    // coast on a baseline some earlier real run left behind.
    if !config.fast_path_enabled() || dry_run {
        return Ok(None);
    }

    let mut state = DeviceState::load(&config.state_dir, &device.name)?;

    if let Some(reason) = poll_reason(config, &state, info) {
        tracing::debug!(device = %device.name, reason, "polling in full");
        return Ok(None);
    }

    let snapshot = Snapshot::from_probe(info);
    let context = poll_context(device, &snapshot, event::now_epoch());

    if config.emit_device_status {
        sink.write(
            device,
            &context.skipped_status_event(state.sequence, state.boot_session),
        )?;
        sink.flush()
            .with_context(|| format!("{}: flushing events to sink", device.name))?;
    }

    state.polls_skipped += 1;
    state.updated_at = Some(event::iso8601(context.observed_at_epoch));
    state.save(&config.state_dir, &device.name)?;

    Ok(Some(PollOutcome {
        events_emitted: usize::from(config.emit_device_status),
        log_store_used: Some(info.log_store_used),
        log_store_capacity: Some(info.log_store_capacity),
        skipped: true,
        ..Default::default()
    }))
}

/// Why this poll cannot be answered from unauthenticated device info alone.
///
/// `None` means the fast path is safe. Pure, so the decision is testable without
/// a device.
fn poll_reason(
    config: &Config,
    state: &DeviceState,
    info: &probe::DeviceInfo,
) -> Option<&'static str> {
    // No baseline: we have never completed a poll for this device.
    let Some(baseline) = state.last_log_store_used else {
        return Some("no recorded log utilisation baseline");
    };

    // Entries are only freed by `set-log-index` or a reset, so between polls the
    // count only rises. Movement in either direction is worth a look — a drop
    // means a reset, a reboot, or another consumer advancing the index.
    if info.log_store_used != baseline {
        return Some("log utilisation changed");
    }

    // Once the buffer is full the device overwrites its oldest entries and the
    // count stops moving, so a pinned maximum proves nothing.
    if info.log_store_capacity == 0 {
        return Some("device reported no log capacity");
    }
    if info.log_store_used >= info.log_store_capacity {
        return Some("log buffer is full, so the count cannot rise");
    }

    // A different HSM behind the same endpoint invalidates the baseline.
    if state
        .serial
        .as_deref()
        .is_some_and(|serial| serial != info.serial())
    {
        return Some("device serial does not match the recorded one");
    }

    // The count is unauthenticated, so agreement is a hint with an expiry date,
    // not proof. Anything that could hold it still — a stuck connector, a
    // network attacker, a firmware quirk — gets at most this many polls before we
    // go and look for ourselves.
    if config.force_full_poll_every > 0 && state.polls_skipped >= config.force_full_poll_every {
        return Some("skip ceiling reached");
    }

    None
}

/// Read, transform, emit, and (unless `dry_run`) acknowledge the audit log.
pub fn poll_device(
    config: &Config,
    device: &Device,
    client: &Client,
    probed: Option<&probe::DeviceInfo>,
    sink: &mut dyn Sink,
    dry_run: bool,
) -> Result<PollOutcome> {
    let snapshot = match config.device_info_source {
        // Already fetched over the connector, before we decided to connect.
        DeviceInfoSource::Connector => match probed {
            Some(info) => Snapshot::from_probe(info),
            None => Snapshot::empty(DeviceInfoSource::Connector.as_str()),
        },
        DeviceInfoSource::Session => {
            let info = client
                .device_info()
                .with_context(|| format!("{}: get device info", device.name))?;
            Snapshot::from_session(&info)
        }
        DeviceInfoSource::None => Snapshot::empty(DeviceInfoSource::None.as_str()),
    };

    let logs = client
        .get_log_entries()
        .with_context(|| format!("{}: get log entries", device.name))?;

    let mut state = DeviceState::load(&config.state_dir, &device.name)?;
    let observed_at = event::now_epoch();

    let mut outcome = PollOutcome {
        entries_returned: logs.entries.len(),
        log_store_used: snapshot.log_store_used,
        log_store_capacity: snapshot.log_store_capacity,
        ..Default::default()
    };

    if let Some(previous_serial) = &state.serial
        && let Some(serial) = &snapshot.serial
        && previous_serial != serial
    {
        tracing::warn!(
            device = %device.name,
            expected = %previous_serial,
            found = %serial,
            source = snapshot.source,
            "device serial changed: the endpoint now fronts a different HSM"
        );
    }

    let context = poll_context(device, &snapshot, observed_at);

    // Copy out of the crate's private entry type as soon as we read it.
    let raw_entries: Vec<LogEntry> = logs
        .entries
        .iter()
        .map(|entry| LogEntry {
            item: entry.item,
            cmd: entry.cmd,
            length: entry.length,
            session_key: entry.session_key,
            target_key: entry.target_key,
            second_key: entry.second_key,
            result: entry.result,
            tick: entry.tick,
            digest: entry.digest.0,
        })
        .collect();

    if tracing::enabled!(tracing::Level::TRACE) {
        for entry in &raw_entries {
            tracing::trace!(
                device = %device.name,
                item = entry.item,
                cmd = entry.cmd.to_u8(),
                length = entry.length,
                session_key = entry.session_key,
                target_key = entry.target_key,
                second_key = entry.second_key,
                result = entry.result.to_u8(),
                tick = entry.tick,
                digest = %event::hex(&entry.digest),
                "raw log entry"
            );
        }
    }

    // Enrichment issues its own audited commands, so only pay for it when
    // there is something new to describe.
    let catalog = if config.enrich_objects && !select_new(&raw_entries, &state).is_empty() {
        ObjectCatalog::build(client, device)
    } else {
        ObjectCatalog::default()
    };

    let transformed = transform(
        config,
        &context,
        &raw_entries,
        &state,
        logs.unlogged_boot_events,
        logs.unlogged_auth_events,
        &catalog,
        observed_at,
    );

    let Transformed {
        new_entries,
        events,
        sequence,
        boot_session,
        chain_mismatches,
        chain_unverified,
    } = transformed;

    outcome.entries_new = new_entries.len();
    outcome.chain_mismatches = chain_mismatches;
    outcome.chain_unverified = chain_unverified;

    if logs.unlogged_boot_events > 0 || logs.unlogged_auth_events > 0 {
        tracing::warn!(
            device = %device.name,
            boot_events = logs.unlogged_boot_events,
            auth_events = logs.unlogged_auth_events,
            "device reports events it could not log: the audit trail has gaps"
        );
    }

    for audit_event in &events {
        sink.write(device, audit_event)?;
    }
    sink.flush()
        .with_context(|| format!("{}: flushing events to sink", device.name))?;
    outcome.events_emitted = events.len();

    if config.verify_chain && outcome.chain_mismatches > 0 {
        tracing::error!(
            device = %device.name,
            mismatches = outcome.chain_mismatches,
            "log hash chain did not verify; see README (\"Hash chain\") before treating as tampering"
        );
    }

    if let Some(percent) = outcome
        .log_store_used
        .zip(outcome.log_store_capacity)
        .and_then(|(used, capacity)| (capacity > 0).then(|| used as u32 * 100 / capacity as u32))
        && percent >= config.log_fill_warn_percent as u32
    {
        tracing::warn!(
            device = %device.name,
            percent,
            "device audit log buffer is filling up"
        );
    }

    // Only acknowledge entries that are already durable in the sink.
    if let Some(last) = new_entries.last() {
        if dry_run {
            tracing::info!(
                device = %device.name,
                log_item = last.item,
                "dry run: not advancing log index and not saving state"
            );
        } else {
            if config.advance_log_index {
                client
                    .set_log_index(last.item)
                    .with_context(|| format!("{}: set log index to {}", device.name, last.item))?;
                outcome.advanced_to = Some(last.item);
            }
            state.last_item = Some(last.item);
            state.last_digest = Some(event::hex(&last.digest));
            state.last_tick = Some(last.tick);
        }
    }

    if !dry_run {
        if config.fast_path_enabled() {
            refresh_fast_path_baseline(device, &mut state);
        }
        if snapshot.serial.is_some() {
            state.serial = snapshot.serial.clone();
        }
        state.sequence = sequence;
        state.boot_session = boot_session;
        state.updated_at = Some(event::iso8601(observed_at));
        state.save(&config.state_dir, &device.name)?;
    }

    Ok(outcome)
}

/// Re-read `log_store_used` now that this poll's own entries are in the buffer.
///
/// The figure captured at the start of the poll is already stale: reading the log
/// and acknowledging it are themselves audited, so they land after the read.
/// Storing the pre-read value would make the next poll see a difference every
/// time and the fast path would never fire.
///
/// On failure the baseline is cleared, which costs a full poll next cycle. That
/// is the safe direction.
fn refresh_fast_path_baseline(device: &Device, state: &mut DeviceState) {
    match probe::fetch(device) {
        Ok(after) => {
            state.last_log_store_used = Some(after.log_store_used);
            state.polls_skipped = 0;
        }
        Err(e) => {
            tracing::warn!(
                device = %device.name,
                error = %e,
                "could not re-read log utilisation; next poll will not take the fast path"
            );
            state.last_log_store_used = None;
            state.polls_skipped = 0;
        }
    }
}

fn poll_context(device: &Device, snapshot: &Snapshot, observed_at: f64) -> PollContext {
    PollContext {
        device_name: device.name.clone(),
        connector_url: device.connector_url(),
        device_info_source: snapshot.source,
        device_serial: snapshot.serial.clone(),
        device_version: snapshot.version.clone(),
        log_store_used: snapshot.log_store_used,
        log_store_capacity: snapshot.log_store_capacity,
        observed_at_epoch: observed_at,
        tick_hz: device.tick_hz,
        tags: device.tags.clone().into_iter().collect::<BTreeMap<_, _>>(),
    }
}

/// Everything derived from one poll, before any side effects.
pub struct Transformed<'a> {
    /// Entries not previously emitted, in device order.
    pub new_entries: Vec<&'a LogEntry>,
    pub events: Vec<AuditEvent>,
    pub sequence: u64,
    pub boot_session: u64,
    pub chain_mismatches: usize,
    pub chain_unverified: usize,
}

/// Pure transformation: raw entries plus saved cursor in, Splunk events out.
///
/// Kept free of I/O so the cursor, reboot-detection, hash-chain, and timestamp
/// logic can be tested without a device.
#[allow(clippy::too_many_arguments)]
pub fn transform<'a>(
    config: &Config,
    context: &PollContext,
    entries: &'a [LogEntry],
    state: &DeviceState,
    unlogged_boot_events: u16,
    unlogged_auth_events: u16,
    catalog: &ObjectCatalog,
    observed_at: f64,
) -> Transformed<'a> {
    let new_entries = select_new(entries, state);

    let mut events: Vec<AuditEvent> = Vec::with_capacity(new_entries.len() + 2);
    let mut sequence = state.sequence;
    let mut boot_session = state.boot_session;
    let mut chain_mismatches = 0;
    let mut chain_unverified = 0;

    let mut previous_digest = state
        .last_digest
        .as_deref()
        .and_then(event::parse_hex16)
        .filter(|_| {
            // Only an entry directly following the one we stored last poll can
            // be chain-checked against that digest.
            match (state.last_item, new_entries.first()) {
                (Some(last), Some(first)) => first.item == last.wrapping_add(1),
                _ => false,
            }
        });

    // Group entries by boot session so ticks are only compared within a session.
    let mut previous_tick = state.last_tick;
    let mut groups: Vec<Vec<usize>> = Vec::new();
    let mut boot_sessions: Vec<u64> = Vec::new();
    for (index, entry) in new_entries.iter().enumerate() {
        let rebooted = event::is_boot_entry(entry)
            || previous_tick.is_some_and(|previous| entry.tick < previous);
        if rebooted || groups.is_empty() {
            // Don't count a reboot we never witnessed: the first entry of a
            // brand new cursor simply opens the first session.
            if rebooted && !(groups.is_empty() && state.last_tick.is_none()) {
                boot_session += 1;
            }
            groups.push(Vec::new());
            boot_sessions.push(boot_session);
        }
        groups.last_mut().expect("group pushed above").push(index);
        previous_tick = Some(entry.tick);
    }

    let anchors = build_anchors(
        &new_entries,
        &groups,
        observed_at,
        context.tick_hz,
        config.poll_interval_secs as f64,
    );

    for (group_index, group) in groups.iter().enumerate() {
        let session = boot_sessions[group_index];
        let anchor = &anchors[group_index];
        for &index in group {
            let entry = new_entries[index];

            let chain_status = match previous_digest {
                Some(previous) => {
                    if event::expected_digest(&previous, entry) == entry.digest {
                        "ok"
                    } else {
                        chain_mismatches += 1;
                        "mismatch"
                    }
                }
                None => {
                    chain_unverified += 1;
                    "unverified"
                }
            };
            previous_digest = Some(entry.digest);

            sequence += 1;
            let mut audit_event = context.entry_event(
                entry,
                sequence,
                session,
                config.verify_chain.then_some(chain_status),
                anchor.estimate(entry.tick),
            );
            catalog.annotate(entry, &mut audit_event);
            events.push(audit_event);
        }
    }

    if unlogged_boot_events > 0 || unlogged_auth_events > 0 {
        events.push(context.unlogged_event(
            sequence,
            boot_session,
            unlogged_boot_events,
            unlogged_auth_events,
        ));
    }

    if config.emit_device_status {
        events.push(context.status_event(sequence, boot_session, new_entries.len()));
    }

    Transformed {
        new_entries,
        events,
        sequence,
        boot_session,
        chain_mismatches,
        chain_unverified,
    }
}

/// Drop entries we have already emitted, keeping device order.
fn select_new<'a>(entries: &'a [LogEntry], state: &DeviceState) -> Vec<&'a LogEntry> {
    let Some(last_item) = state.last_item else {
        return entries.iter().collect();
    };
    entries
        .iter()
        .filter(|entry| {
            // Defensive: a device that was reset re-uses low item numbers, and
            // `is_newer` would reject them. Accept an entry whose digest we
            // have never seen if the log clearly restarted.
            event::is_newer(entry.item, last_item)
        })
        .filter(|entry| {
            state
                .last_digest
                .as_deref()
                .map(|digest| digest != event::hex(&entry.digest))
                .unwrap_or(true)
        })
        .collect()
}

/// Anchor each boot-session group to wall-clock time, newest group first.
fn build_anchors(
    entries: &[&LogEntry],
    groups: &[Vec<usize>],
    observed_at: f64,
    tick_hz: f64,
    uncertainty_secs: f64,
) -> Vec<TickAnchor> {
    let mut anchors: Vec<Option<TickAnchor>> = (0..groups.len()).map(|_| None).collect();
    let mut next_group_start: Option<f64> = None;

    for group_index in (0..groups.len()).rev() {
        let group = &groups[group_index];
        let max_tick = group
            .iter()
            .map(|&index| entries[index].tick)
            .max()
            .unwrap_or(0);
        // The newest session is anchored to "now"; earlier sessions end just
        // before the first entry of the session that followed them.
        let anchor_epoch = next_group_start.unwrap_or(observed_at);
        let anchor = TickAnchor::new(max_tick, anchor_epoch, tick_hz, uncertainty_secs);

        if let Some(&first) = group.first() {
            next_group_start = Some(anchor.estimate(entries[first].tick).epoch);
        }
        anchors[group_index] = Some(anchor);
    }

    anchors
        .into_iter()
        .map(|anchor| anchor.expect("every group gets an anchor"))
        .collect()
}

/// Optional object ID -> label/type map. Requires a key with `list-objects`
/// and `get-object-info`, which a pure auditor key lacks.
#[derive(Default)]
pub struct ObjectCatalog {
    objects: HashMap<u16, (String, String)>,
}

impl ObjectCatalog {
    pub fn build(client: &Client, device: &Device) -> Self {
        let mut objects = HashMap::new();
        match client.list_objects(&[]) {
            Ok(entries) => {
                for entry in entries {
                    let type_name = codes_type_name(entry.object_type);
                    let label = client
                        .get_object_info(entry.object_id, entry.object_type)
                        .map(|info| info.label.to_string())
                        .unwrap_or_default();
                    objects.entry(entry.object_id).or_insert((type_name, label));
                }
            }
            Err(e) => tracing::warn!(
                device = %device.name,
                error = %e,
                "object enrichment failed; auditor keys normally cannot list objects"
            ),
        }
        Self { objects }
    }

    fn annotate(&self, entry: &LogEntry, event: &mut AuditEvent) {
        if self.objects.is_empty() {
            return;
        }
        if entry.session_key != codes::NO_KEY
            && let Some((_, label)) = self.objects.get(&entry.session_key)
        {
            event.session_key_label = non_empty(label);
        }
        if entry.target_key != codes::NO_KEY
            && let Some((type_name, label)) = self.objects.get(&entry.target_key)
        {
            event.target_key_type = Some(type_name.clone());
            event.target_key_label = non_empty(label);
        }
        if entry.second_key != codes::NO_KEY
            && let Some((_, label)) = self.objects.get(&entry.second_key)
        {
            event.second_key_label = non_empty(label);
        }
    }
}

fn non_empty(text: &str) -> Option<String> {
    (!text.is_empty()).then(|| text.to_owned())
}

fn codes_type_name(object_type: yubihsm::object::Type) -> String {
    let raw = format!("{object_type:?}");
    raw.chars()
        .enumerate()
        .flat_map(|(index, ch)| {
            if ch.is_ascii_uppercase() && index != 0 {
                vec!['_', ch.to_ascii_lowercase()]
            } else {
                vec![ch.to_ascii_lowercase()]
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use yubihsm::{command, response};

    fn entry(item: u16, tick: u32, digest: u8) -> LogEntry {
        LogEntry {
            item,
            cmd: command::Code::SignEcdsa,
            length: 32,
            session_key: 4,
            target_key: 0x100,
            second_key: 0xffff,
            result: response::Code::Success(command::Code::SignEcdsa),
            tick,
            digest: [digest; 16],
        }
    }

    #[test]
    fn select_new_skips_consumed_entries() {
        let entries = vec![entry(10, 100, 1), entry(11, 101, 2), entry(12, 102, 3)];
        let state = DeviceState {
            last_item: Some(11),
            last_digest: Some(event::hex(&[2u8; 16])),
            ..Default::default()
        };
        let selected = select_new(&entries, &state);
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].item, 12);
    }

    #[test]
    fn select_new_takes_everything_on_first_run() {
        let entries = vec![entry(1, 1, 1), entry(2, 2, 2)];
        assert_eq!(select_new(&entries, &DeviceState::default()).len(), 2);
    }

    #[test]
    fn select_new_handles_item_wraparound() {
        let entries = vec![entry(65535, 10, 1), entry(0, 11, 2), entry(1, 12, 3)];
        let state = DeviceState {
            last_item: Some(65535),
            ..Default::default()
        };
        let selected = select_new(&entries, &state);
        assert_eq!(
            selected.iter().map(|e| e.item).collect::<Vec<_>>(),
            vec![0, 1]
        );
    }

    #[test]
    fn anchors_walk_back_from_now() {
        let owned = [entry(1, 100, 1), entry(2, 130, 2)];
        let entries: Vec<&LogEntry> = owned.iter().collect();
        let groups = vec![vec![0, 1]];
        let anchors = build_anchors(&entries, &groups, 1_000_000.0, 1.0, 60.0);
        assert_eq!(anchors.len(), 1);
        // Newest entry lands at "now", the older one 30 ticks earlier.
        assert!((anchors[0].estimate(130).epoch - 1_000_000.0).abs() < 1e-6);
        assert!((anchors[0].estimate(100).epoch - 999_970.0).abs() < 1e-6);
    }

    #[test]
    fn earlier_boot_session_is_anchored_before_the_reboot() {
        let owned = [entry(1, 500, 1), entry(2, 10, 2), entry(3, 20, 3)];
        let entries: Vec<&LogEntry> = owned.iter().collect();
        let groups = vec![vec![0], vec![1, 2]];
        let anchors = build_anchors(&entries, &groups, 1_000_000.0, 1.0, 60.0);
        // Second session: newest entry (tick 20) at "now", first entry 10 ticks back.
        let reboot_epoch = anchors[1].estimate(10).epoch;
        assert!((reboot_epoch - 999_990.0).abs() < 1e-6);
        // First session's last entry sits at the reboot moment, not in the future.
        assert!(anchors[0].estimate(500).epoch <= reboot_epoch + 1e-9);
    }

    fn test_config() -> Config {
        Config {
            poll_interval_secs: 60,
            state_dir: std::env::temp_dir().join("yubihsm-auditor-tests"),
            advance_log_index: true,
            verify_chain: true,
            enrich_objects: false,
            emit_device_status: true,
            device_info_source: DeviceInfoSource::Session,
            skip_poll_when_unchanged: true,
            force_full_poll_every: 10,
            log_fill_warn_percent: 60,
            output: crate::config::Output::Stdout,
            devices: vec![],
        }
    }

    fn test_context() -> PollContext {
        PollContext {
            device_name: "hsm-1".into(),
            connector_url: "http://10.0.0.1:12345".into(),
            device_info_source: "session",
            device_serial: Some("0000001234".into()),
            device_version: Some("2.4.0".into()),
            log_store_used: Some(3),
            log_store_capacity: Some(62),
            observed_at_epoch: 1_700_000_000.0,
            tick_hz: 1.0,
            tags: BTreeMap::new(),
        }
    }

    /// Build a valid hash chain over `entries`, starting from `seed`.
    fn chain(entries: &mut [LogEntry], seed: [u8; 16]) {
        let mut previous = seed;
        for entry in entries.iter_mut() {
            entry.digest = event::expected_digest(&previous, entry);
            previous = entry.digest;
        }
    }

    #[test]
    fn transform_emits_entries_status_and_verifies_chain() {
        let config = test_config();
        let context = test_context();
        let mut entries = vec![entry(1, 10, 0), entry(2, 20, 0), entry(3, 30, 0)];
        let seed = [0x11u8; 16];
        chain(&mut entries, seed);

        // First poll: nothing known, so the first entry cannot be chain-checked.
        let first = transform(
            &config,
            &context,
            &entries,
            &DeviceState::default(),
            0,
            0,
            &ObjectCatalog::default(),
            1_700_000_000.0,
        );
        assert_eq!(first.new_entries.len(), 3);
        // 3 entries + one device_status heartbeat.
        assert_eq!(first.events.len(), 4);
        assert_eq!(first.sequence, 3);
        assert_eq!(first.chain_unverified, 1);
        assert_eq!(first.chain_mismatches, 0);
        assert_eq!(
            first
                .events
                .iter()
                .filter(|e| e.chain_status == Some("ok"))
                .count(),
            2
        );
        assert_eq!(first.events[3].event_type, "device_status");
        // Timestamps increase with the tick and end at the poll time.
        assert!(first.events[0].time < first.events[1].time);
        assert!((first.events[2].time - 1_700_000_000.0).abs() < 1e-6);

        // Second poll: the device still holds the old entries plus a new one.
        let state = DeviceState {
            last_item: Some(3),
            last_digest: Some(event::hex(&entries[2].digest)),
            last_tick: Some(30),
            sequence: first.sequence,
            ..Default::default()
        };
        let mut all = entries.clone();
        all.push(entry(4, 40, 0));
        chain(&mut all, seed);

        let second = transform(
            &config,
            &context,
            &all,
            &state,
            0,
            0,
            &ObjectCatalog::default(),
            1_700_000_060.0,
        );
        assert_eq!(
            second.new_entries.len(),
            1,
            "already-consumed entries re-appear"
        );
        assert_eq!(second.new_entries[0].item, 4);
        assert_eq!(second.sequence, 4);
        // The stored digest anchors the chain across polls.
        assert_eq!(second.events[0].chain_status, Some("ok"));
        assert_eq!(second.chain_unverified, 0);
    }

    #[test]
    fn transform_flags_a_broken_chain() {
        let config = test_config();
        let mut entries = vec![entry(1, 10, 0), entry(2, 20, 0), entry(3, 30, 0)];
        chain(&mut entries, [0x11u8; 16]);
        // Tamper with the middle entry after the chain was computed.
        entries[1].target_key = 0x999;

        let result = transform(
            &config,
            &test_context(),
            &entries,
            &DeviceState::default(),
            0,
            0,
            &ObjectCatalog::default(),
            1_700_000_000.0,
        );
        // The tampered entry no longer matches the digest it carries. Its
        // successor still links to that (unchanged) digest, so detection is
        // localized to the edited entry.
        assert_eq!(result.chain_mismatches, 1);
        assert_eq!(result.events[1].chain_status, Some("mismatch"));
        assert_eq!(result.events[2].chain_status, Some("ok"));
    }

    #[test]
    fn transform_counts_reboots_and_unlogged_events() {
        let config = test_config();
        let mut entries = vec![
            entry(4, 900, 0),
            LogEntry {
                cmd: command::Code::HsmInitialization,
                length: 0xffff,
                session_key: 0xffff,
                target_key: 0xffff,
                second_key: 0xffff,
                ..entry(5, 1, 0)
            },
            entry(6, 5, 0),
        ];
        chain(&mut entries, [0x22u8; 16]);
        let state = DeviceState {
            last_item: Some(3),
            last_tick: Some(800),
            sequence: 3,
            boot_session: 7,
            ..Default::default()
        };

        let result = transform(
            &config,
            &test_context(),
            &entries,
            &state,
            2,
            5,
            &ObjectCatalog::default(),
            1_700_000_000.0,
        );
        assert_eq!(result.boot_session, 8, "one reboot witnessed");
        assert_eq!(result.events[0].boot_session, 7);
        assert_eq!(result.events[1].event_type, "boot");
        assert_eq!(result.events[1].boot_session, 8);
        // Pre-reboot entries must not be dated after the reboot.
        assert!(result.events[0].time <= result.events[1].time);

        let unlogged = result
            .events
            .iter()
            .find(|e| e.event_type == "unlogged_events")
            .expect("unlogged event emitted");
        assert_eq!(unlogged.unlogged_boot_events, Some(2));
        assert_eq!(unlogged.unlogged_auth_events, Some(5));
    }

    #[test]
    fn transform_can_disable_chain_status_and_heartbeat() {
        let mut config = test_config();
        config.verify_chain = false;
        config.emit_device_status = false;
        let mut entries = vec![entry(1, 10, 0)];
        chain(&mut entries, [0u8; 16]);

        let result = transform(
            &config,
            &test_context(),
            &entries,
            &DeviceState::default(),
            0,
            0,
            &ObjectCatalog::default(),
            1_700_000_000.0,
        );
        assert_eq!(result.events.len(), 1);
        assert_eq!(result.events[0].chain_status, None);
    }

    fn probed(used: u8) -> probe::DeviceInfo {
        probe::DeviceInfo {
            major_version: 2,
            minor_version: 4,
            build_version: 0,
            serial_number: 1234,
            log_store_capacity: 62,
            log_store_used: used,
        }
    }

    fn drained_state(used: u8) -> DeviceState {
        DeviceState {
            serial: Some("0000001234".into()),
            last_item: Some(9),
            last_log_store_used: Some(used),
            ..Default::default()
        }
    }

    #[test]
    fn fast_path_skips_only_when_utilisation_is_unchanged() {
        let config = test_config();
        assert_eq!(poll_reason(&config, &drained_state(2), &probed(2)), None);
        assert_eq!(
            poll_reason(&config, &drained_state(2), &probed(3)),
            Some("log utilisation changed")
        );
        // A drop means a reset or another consumer, which also needs a look.
        assert_eq!(
            poll_reason(&config, &drained_state(5), &probed(2)),
            Some("log utilisation changed")
        );
    }

    #[test]
    fn fast_path_needs_a_baseline() {
        assert!(poll_reason(&test_config(), &DeviceState::default(), &probed(2)).is_some());
    }

    #[test]
    fn fast_path_refuses_a_full_buffer() {
        // At capacity the device overwrites its oldest entries and the count
        // stops moving, so "unchanged" no longer means "nothing happened".
        let full = probe::DeviceInfo {
            log_store_used: 62,
            ..probed(62)
        };
        assert_eq!(
            poll_reason(&test_config(), &drained_state(62), &full),
            Some("log buffer is full, so the count cannot rise")
        );
    }

    #[test]
    fn fast_path_refuses_a_different_device() {
        let mut state = drained_state(2);
        state.serial = Some("0009999999".into());
        assert_eq!(
            poll_reason(&test_config(), &state, &probed(2)),
            Some("device serial does not match the recorded one")
        );
    }

    #[test]
    fn fast_path_expires_after_the_skip_ceiling() {
        let mut config = test_config();
        config.force_full_poll_every = 3;
        let mut state = drained_state(2);

        state.polls_skipped = 2;
        assert_eq!(poll_reason(&config, &state, &probed(2)), None);
        state.polls_skipped = 3;
        assert_eq!(
            poll_reason(&config, &state, &probed(2)),
            Some("skip ceiling reached"),
            "an unauthenticated figure must not suppress collection forever"
        );

        // 0 disables the ceiling.
        config.force_full_poll_every = 0;
        state.polls_skipped = 9_999;
        assert_eq!(poll_reason(&config, &state, &probed(2)), None);
    }

    #[test]
    fn fast_path_is_off_unless_device_info_comes_from_the_connector() {
        let mut config = test_config();
        config.device_info_source = DeviceInfoSource::Session;
        assert!(!config.fast_path_enabled(), "a session is already paid for");
        config.device_info_source = DeviceInfoSource::Connector;
        assert!(config.fast_path_enabled());
        config.skip_poll_when_unchanged = false;
        assert!(!config.fast_path_enabled());
    }

    #[test]
    fn object_type_names_are_snake_case() {
        assert_eq!(
            codes_type_name(yubihsm::object::Type::AsymmetricKey),
            "asymmetric_key"
        );
    }
}
