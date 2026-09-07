//! Transformation of raw log entries into Splunk-friendly events.

use crate::codes::{self, NO_KEY};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use yubihsm::{command, response};

/// A decoded audit log entry.
///
/// The `yubihsm` crate returns log entries from a private module, so its type
/// cannot be named here; we copy the fields into our own struct on read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogEntry {
    /// Position in the device's log.
    pub item: u16,
    pub cmd: command::Code,
    pub length: u16,
    pub session_key: u16,
    pub target_key: u16,
    pub second_key: u16,
    pub result: response::Code,
    /// Device tick counter at the time of the operation.
    pub tick: u32,
    /// Truncated SHA-256 chaining digest.
    pub digest: [u8; DIGEST_LEN],
}

/// Wire size of a log entry, excluding its digest.
pub const ENTRY_BODY_LEN: usize = 16;
/// Size of the truncated digest carried by each entry.
pub const DIGEST_LEN: usize = 16;

/// One event as handed to Splunk. Field names are chosen to be searchable
/// directly (`sourcetype=yubihsm:audit target_key_id=0x0100`).
#[derive(Clone, Debug, Serialize)]
pub struct AuditEvent {
    /// Epoch seconds; becomes Splunk's `_time`.
    pub time: f64,
    pub time_iso: String,
    /// How `time` was derived: `tick_anchor` or `poll_time`.
    pub time_source: &'static str,
    /// Worst-case error of `time`, in seconds.
    pub time_uncertainty_secs: f64,

    /// `command`, `boot`, `unlogged_events`, or `device_status`.
    pub event_type: &'static str,

    pub device_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_serial: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_version: Option<String>,
    pub connector_url: String,
    /// `session`, `connector`, or `none`. `session` values are MAC'd by the
    /// device; `connector` values arrive over plaintext HTTP and are only as
    /// trustworthy as the network path.
    pub device_info_source: &'static str,

    /// Monotonic per-device counter; survives `log_item` wrapping.
    pub sequence: u64,
    /// Increments on every detected device reboot.
    pub boot_session: u64,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_item: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tick: Option<u32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command_code: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command_category: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command_length: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_usage: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_management: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result_code: Option<i16>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_key_id: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_key_id_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_key_label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_key_id: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_key_id_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_key_label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_key_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub second_key_id: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub second_key_id_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub second_key_label: Option<String>,

    /// Hex digest carried by the entry. Unique per entry; use for dedup.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_digest: Option<String>,
    /// `ok`, `mismatch`, or `unverified`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain_status: Option<&'static str>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_store_used: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_store_capacity: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_store_percent_used: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unlogged_boot_events: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unlogged_auth_events: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entries_collected: Option<usize>,
    /// On `device_status`: true when the poll never opened a session because the
    /// device reported no new log activity.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub poll_skipped: Option<bool>,

    /// When the collector read this entry from the device.
    pub observed_at: String,
    pub collector: &'static str,
    pub collector_version: &'static str,

    /// Static per-device labels from config.
    #[serde(flatten)]
    pub tags: BTreeMap<String, String>,
}

/// Context shared by all events produced from a single poll of one device.
pub struct PollContext {
    pub device_name: String,
    pub connector_url: String,
    /// Provenance of the three device-info fields below.
    pub device_info_source: &'static str,
    pub device_serial: Option<String>,
    pub device_version: Option<String>,
    pub log_store_used: Option<u8>,
    pub log_store_capacity: Option<u8>,
    pub observed_at_epoch: f64,
    /// Device clock frequency used to convert ticks into seconds.
    pub tick_hz: f64,
    pub tags: BTreeMap<String, String>,
}

impl PollContext {
    fn base(&self, event_type: &'static str) -> AuditEvent {
        AuditEvent {
            time: self.observed_at_epoch,
            time_iso: iso8601(self.observed_at_epoch),
            time_source: "poll_time",
            time_uncertainty_secs: 0.0,
            event_type,
            device_name: self.device_name.clone(),
            device_serial: self.device_serial.clone(),
            device_version: self.device_version.clone(),
            connector_url: self.connector_url.clone(),
            device_info_source: self.device_info_source,
            sequence: 0,
            boot_session: 0,
            log_item: None,
            tick: None,
            command: None,
            command_code: None,
            command_category: None,
            command_length: None,
            key_usage: None,
            key_management: None,
            result: None,
            result_name: None,
            result_code: None,
            session_key_id: None,
            session_key_id_hex: None,
            session_key_label: None,
            target_key_id: None,
            target_key_id_hex: None,
            target_key_label: None,
            target_key_type: None,
            second_key_id: None,
            second_key_id_hex: None,
            second_key_label: None,
            log_digest: None,
            chain_status: None,
            log_store_used: None,
            log_store_capacity: None,
            log_store_percent_used: None,
            unlogged_boot_events: None,
            unlogged_auth_events: None,
            entries_collected: None,
            poll_skipped: None,
            observed_at: iso8601(self.observed_at_epoch),
            collector: "yubihsm-auditor",
            collector_version: env!("CARGO_PKG_VERSION"),
            tags: self.tags.clone(),
        }
    }

    /// Per-poll heartbeat: proves the collector is alive even when the device
    /// is idle, and carries log buffer utilisation for alerting.
    pub fn status_event(
        &self,
        sequence: u64,
        boot_session: u64,
        entries_collected: usize,
    ) -> AuditEvent {
        let mut event = self.base("device_status");
        event.sequence = sequence;
        event.boot_session = boot_session;
        event.log_store_used = self.log_store_used;
        event.log_store_capacity = self.log_store_capacity;
        event.log_store_percent_used = percent_used(self.log_store_used, self.log_store_capacity);
        event.entries_collected = Some(entries_collected);
        event.poll_skipped = Some(false);
        event
    }

    /// Heartbeat for a poll that took the fast path: the device reported no new
    /// log activity, so no session was opened and no entries were read.
    ///
    /// Still emitted, because collector-liveness alerting keys off
    /// `device_status` arriving every interval.
    pub fn skipped_status_event(&self, sequence: u64, boot_session: u64) -> AuditEvent {
        let mut event = self.status_event(sequence, boot_session, 0);
        event.poll_skipped = Some(true);
        event
    }

    /// Emitted when the device reports events it could not record, which means
    /// the audit trail has a hole.
    pub fn unlogged_event(
        &self,
        sequence: u64,
        boot_session: u64,
        boot_events: u16,
        auth_events: u16,
    ) -> AuditEvent {
        let mut event = self.base("unlogged_events");
        event.sequence = sequence;
        event.boot_session = boot_session;
        event.unlogged_boot_events = Some(boot_events);
        event.unlogged_auth_events = Some(auth_events);
        event
    }

    /// Convert one raw log entry.
    #[allow(clippy::too_many_arguments)]
    pub fn entry_event(
        &self,
        entry: &LogEntry,
        sequence: u64,
        boot_session: u64,
        chain_status: Option<&'static str>,
        estimate: TimeEstimate,
    ) -> AuditEvent {
        let is_boot = is_boot_entry(entry);
        let mut event = self.base(if is_boot { "boot" } else { "command" });

        event.time = estimate.epoch;
        event.time_iso = iso8601(estimate.epoch);
        event.time_source = estimate.source;
        event.time_uncertainty_secs = estimate.uncertainty_secs;

        event.sequence = sequence;
        event.boot_session = boot_session;
        event.log_item = Some(entry.item);
        event.tick = Some(entry.tick);

        event.command = Some(codes::command_name(entry.cmd));
        event.command_code = Some(entry.cmd.to_u8());
        event.command_category = Some(codes::command_category(entry.cmd));
        event.command_length = Some(entry.length);
        event.key_usage = Some(!is_boot && codes::is_key_usage(entry.cmd));
        event.key_management = Some(!is_boot && codes::is_key_management(entry.cmd));

        if !is_boot {
            let result = codes::result_info(entry.result);
            event.result = Some(result.status);
            event.result_name = Some(result.name);
            event.result_code = Some(result.code);
        }

        let (session, target, second) = if is_boot {
            (None, None, None)
        } else {
            (
                key_id(entry.session_key),
                key_id(entry.target_key),
                key_id(entry.second_key),
            )
        };
        event.session_key_id = session;
        event.session_key_id_hex = session.map(hex_id);
        event.target_key_id = target;
        event.target_key_id_hex = target.map(hex_id);
        event.second_key_id = second;
        event.second_key_id_hex = second.map(hex_id);

        event.log_digest = Some(hex(&entry.digest));
        event.chain_status = chain_status;

        event.log_store_used = self.log_store_used;
        event.log_store_capacity = self.log_store_capacity;
        event.log_store_percent_used = percent_used(self.log_store_used, self.log_store_capacity);
        event
    }
}

/// Result of mapping a device tick onto wall-clock time.
#[derive(Clone, Copy, Debug)]
pub struct TimeEstimate {
    pub epoch: f64,
    pub source: &'static str,
    pub uncertainty_secs: f64,
}

/// Anchors device ticks to wall-clock time.
///
/// The device only reports a tick counter, so we anchor the newest entry of a
/// poll to the moment we read it and work backwards. Entries are therefore
/// accurate to within the age of the newest entry, which for a device polled
/// every `poll_interval_secs` is bounded by that interval.
pub struct TickAnchor {
    anchor_tick: u32,
    anchor_epoch: f64,
    tick_hz: f64,
    base_uncertainty_secs: f64,
}

impl TickAnchor {
    pub fn new(
        anchor_tick: u32,
        anchor_epoch: f64,
        tick_hz: f64,
        base_uncertainty_secs: f64,
    ) -> Self {
        Self {
            anchor_tick,
            anchor_epoch,
            tick_hz,
            base_uncertainty_secs,
        }
    }

    pub fn estimate(&self, tick: u32) -> TimeEstimate {
        let delta_ticks = self.anchor_tick as f64 - tick as f64;
        let epoch = self.anchor_epoch - delta_ticks / self.tick_hz;
        TimeEstimate {
            epoch,
            source: "tick_anchor",
            uncertainty_secs: self.base_uncertainty_secs,
        }
    }
}

/// Boot/initialization entries carry no meaningful command or key fields.
pub fn is_boot_entry(entry: &LogEntry) -> bool {
    entry.cmd == yubihsm::command::Code::HsmInitialization
        || (entry.length == 0xffff
            && entry.session_key == NO_KEY
            && entry.target_key == NO_KEY
            && entry.second_key == NO_KEY)
}

/// Re-serialize the 16-byte body of an entry exactly as the device hashes it.
pub fn entry_body(entry: &LogEntry) -> [u8; ENTRY_BODY_LEN] {
    let mut out = [0u8; ENTRY_BODY_LEN];
    out[0..2].copy_from_slice(&entry.item.to_be_bytes());
    out[2] = entry.cmd.to_u8();
    out[3..5].copy_from_slice(&entry.length.to_be_bytes());
    out[5..7].copy_from_slice(&entry.session_key.to_be_bytes());
    out[7..9].copy_from_slice(&entry.target_key.to_be_bytes());
    out[9..11].copy_from_slice(&entry.second_key.to_be_bytes());
    out[11] = entry.result.to_u8();
    out[12..16].copy_from_slice(&entry.tick.to_be_bytes());
    out
}

/// Expected digest of `entry` given the previous entry's digest:
/// `SHA-256(entry_body || previous_digest)` truncated to 16 bytes.
///
/// Body-then-digest, not digest-then-body: confirmed against 5 consecutive
/// real entries from a YubiHSM 2 (see `real_hardware_chain_from_yh2` below).
/// The reversed order was silent before that - it compiled, ran, and simply
/// reported every entry as `mismatch`, which looked identical to "formula is
/// entirely wrong" until enough consecutive real digests ruled out every
/// other candidate (hash function, endianness, truncation end) by brute
/// force and left only the concatenation order.
pub fn expected_digest(previous_digest: &[u8; DIGEST_LEN], entry: &LogEntry) -> [u8; DIGEST_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(entry_body(entry));
    hasher.update(previous_digest);
    let full = hasher.finalize();
    let mut out = [0u8; DIGEST_LEN];
    out.copy_from_slice(&full[..DIGEST_LEN]);
    out
}

/// True when `item` comes after `last`, accounting for the 16-bit wrap.
pub fn is_newer(item: u16, last: u16) -> bool {
    item != last && item.wrapping_sub(last) < 0x8000
}

pub fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

pub fn parse_hex16(text: &str) -> Option<[u8; DIGEST_LEN]> {
    if text.len() != DIGEST_LEN * 2 {
        return None;
    }
    let mut out = [0u8; DIGEST_LEN];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(text.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

fn key_id(id: u16) -> Option<u16> {
    if id == NO_KEY || id == 0 {
        None
    } else {
        Some(id)
    }
}

fn hex_id(id: u16) -> String {
    format!("0x{id:04x}")
}

fn percent_used(used: Option<u8>, capacity: Option<u8>) -> Option<u8> {
    match (used, capacity) {
        (Some(used), Some(capacity)) if capacity > 0 => {
            Some(((used as u32 * 100) / capacity as u32).min(100) as u8)
        }
        _ => None,
    }
}

pub fn now_epoch() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

pub fn iso8601(epoch: f64) -> String {
    let nanos = (epoch * 1e9).round() as i128;
    OffsetDateTime::from_unix_timestamp_nanos(nanos)
        .ok()
        .and_then(|dt| dt.format(&Rfc3339).ok())
        .unwrap_or_else(|| format!("{epoch}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(item: u16, tick: u32) -> LogEntry {
        LogEntry {
            item,
            cmd: command::Code::SignEcdsa,
            length: 32,
            session_key: 4,
            target_key: 0x100,
            second_key: NO_KEY,
            result: response::Code::Success(command::Code::SignEcdsa),
            tick,
            digest: [0u8; DIGEST_LEN],
        }
    }

    #[test]
    fn entry_body_matches_wire_layout() {
        // The all-0xff sample from the yubihsm crate's own test vector.
        let sample = LogEntry {
            item: 1,
            cmd: command::Code::HsmInitialization,
            length: 0xffff,
            session_key: 0xffff,
            target_key: 0xffff,
            second_key: 0xffff,
            result: response::Code::Success(command::Code::Error),
            tick: 0xffff_ffff,
            digest: [0u8; DIGEST_LEN],
        };
        let expected: Vec<u8> = std::iter::once(0u8)
            .chain(std::iter::once(1u8))
            .chain(std::iter::repeat_n(0xffu8, 14))
            .collect();
        assert_eq!(entry_body(&sample).to_vec(), expected);
    }

    /// Real consecutive entries (item 9526-9531) captured via `--log-level
    /// trace` from a production YubiHSM 2, used to pin down and verify the
    /// concatenation order in `expected_digest`. Entry 9526 has no anchor
    /// captured (it's the start of this window), so only the 5 links from
    /// 9527 through 9531 are checked here - each against the *real* digest
    /// of the entry before it, not a synthetic one.
    #[test]
    fn real_hardware_chain_from_yh2() {
        fn hex16(s: &str) -> [u8; DIGEST_LEN] {
            parse_hex16(s).unwrap()
        }
        let entries = [
            (
                entry_from(9526, command::Code::from_u8(103).unwrap(), 2, 4, NO_KEY, NO_KEY, 231, 93_053_330),
                hex16("b00e2dafaf29356ad9f1935c09786a84"),
            ),
            (
                entry_from(9527, command::Code::from_u8(3).unwrap(), 10, NO_KEY, 4, NO_KEY, 131, 93_207_583),
                hex16("d0d58b51fa7de009184934ae46f64f6a"),
            ),
            (
                entry_from(9528, command::Code::from_u8(4).unwrap(), 17, NO_KEY, 4, NO_KEY, 132, 93_207_583),
                hex16("c6e5baa1fe4237062fc3880ec0c3a1e7"),
            ),
            (
                entry_from(9529, command::Code::from_u8(103).unwrap(), 2, 4, NO_KEY, NO_KEY, 231, 93_207_584),
                hex16("8b287a62b0aae1f3e437c6fa130a9bec"),
            ),
            (
                entry_from(9530, command::Code::from_u8(3).unwrap(), 10, NO_KEY, 4, NO_KEY, 131, 93_210_093),
                hex16("a1ccc06e0f9be382aa0200d7c26da166"),
            ),
            (
                entry_from(9531, command::Code::from_u8(4).unwrap(), 17, NO_KEY, 4, NO_KEY, 132, 93_210_094),
                hex16("4d812e0b53e096a7d87c68e11fc2500e"),
            ),
        ];
        for i in 1..entries.len() {
            let previous_digest = entries[i - 1].1;
            let (entry, real_digest) = &entries[i];
            assert_eq!(
                expected_digest(&previous_digest, entry),
                *real_digest,
                "chain link into item {} did not verify",
                entry.item
            );
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn entry_from(
        item: u16,
        cmd: command::Code,
        length: u16,
        session_key: u16,
        target_key: u16,
        second_key: u16,
        result: u8,
        tick: u32,
    ) -> LogEntry {
        LogEntry {
            item,
            cmd,
            length,
            session_key,
            target_key,
            second_key,
            result: response::Code::from_u8(result).unwrap(),
            tick,
            digest: [0u8; DIGEST_LEN],
        }
    }

    #[test]
    fn digest_chain_links() {
        let mut e = entry(5, 100);
        let previous = [0xaau8; DIGEST_LEN];
        let expected = expected_digest(&previous, &e);
        e.digest = expected;
        assert_eq!(expected_digest(&previous, &e), e.digest);
        // A different anchor must not validate.
        assert_ne!(expected_digest(&[0xabu8; DIGEST_LEN], &e), e.digest);
    }

    #[test]
    fn wrapping_order() {
        assert!(is_newer(6, 5));
        assert!(!is_newer(5, 6));
        assert!(!is_newer(5, 5));
        assert!(is_newer(0, 65535));
        assert!(is_newer(3, 65534));
        assert!(!is_newer(65534, 3));
    }

    #[test]
    fn hex_round_trip() {
        let bytes = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        let text = hex(&bytes);
        assert_eq!(text, "00112233445566778899aabbccddeeff");
        assert_eq!(parse_hex16(&text), Some(bytes));
        assert_eq!(parse_hex16("abc"), None);
    }

    #[test]
    fn tick_anchor_walks_backwards() {
        let anchor = TickAnchor::new(1000, 1_000_000.0, 1.0, 60.0);
        let older = anchor.estimate(940);
        assert!((older.epoch - 999_940.0).abs() < 1e-6);
        assert_eq!(older.source, "tick_anchor");
    }

    #[test]
    fn iso8601_formats_utc() {
        assert_eq!(iso8601(0.0), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn boot_entry_detection() {
        let boot = LogEntry {
            cmd: command::Code::HsmInitialization,
            ..entry(1, 0)
        };
        assert!(is_boot_entry(&boot));
        assert!(!is_boot_entry(&entry(2, 5)));
    }

    #[test]
    fn entry_event_sets_key_fields() {
        let ctx = PollContext {
            device_name: "hsm-1".into(),
            connector_url: "http://10.0.0.1:12345".into(),
            device_info_source: "session",
            device_serial: Some("0000001234".into()),
            device_version: Some("2.4.0".into()),
            log_store_used: Some(31),
            log_store_capacity: Some(62),
            observed_at_epoch: 1_700_000_000.0,
            tick_hz: 1.0,
            tags: BTreeMap::new(),
        };
        let event = ctx.entry_event(
            &entry(9, 500),
            42,
            3,
            Some("ok"),
            TimeEstimate {
                epoch: 1_699_999_990.0,
                source: "tick_anchor",
                uncertainty_secs: 60.0,
            },
        );
        assert_eq!(event.event_type, "command");
        assert_eq!(event.command.as_deref(), Some("sign_ecdsa"));
        assert_eq!(event.session_key_id, Some(4));
        assert_eq!(event.target_key_id_hex.as_deref(), Some("0x0100"));
        assert_eq!(event.second_key_id, None);
        assert_eq!(event.key_usage, Some(true));
        assert_eq!(event.log_store_percent_used, Some(50));
        assert_eq!(event.sequence, 42);
    }
}
