//! yubihsm-auditor: collect YubiHSM 2 audit logs over HTTP and transform them
//! into events for Splunk, Wazuh, or any syslog receiver.

mod codes;
mod collector;
mod config;
mod event;
mod probe;
mod sink;
mod state;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use config::Config;
use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(
    name = "yubihsm-auditor",
    version,
    about = "Collect YubiHSM 2 audit logs and emit events for Splunk, Wazuh, or any syslog receiver"
)]
struct Cli {
    /// Path to the TOML configuration file.
    #[arg(short, long, default_value = "yubihsm-auditor.toml", global = true)]
    config: PathBuf,

    /// Read and emit events, but never advance the device log index or the
    /// local cursor.
    #[arg(long, global = true)]
    dry_run: bool,

    /// Log level (error, warn, info, debug, trace). Overrides RUST_LOG.
    #[arg(long, global = true)]
    log_level: Option<String>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Poll every device forever on the configured interval.
    Run,

    /// Poll every device once and exit.
    Once,

    /// Verify connectivity, credentials, and audit configuration. Never
    /// advances the log index.
    Check,

    /// Print a sample configuration file to stdout.
    InitConfig,

    /// Send synthetic events to the configured output. Use this to validate a
    /// destination (HEC token/index, syslog receiver, decoders) before
    /// touching an HSM.
    SampleEvents,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    init_logging(cli.log_level.as_deref());

    match cli.command {
        Command::InitConfig => {
            print!("{}", config::TEMPLATE);
            Ok(())
        }
        Command::Once => {
            let config = Config::load(&cli.config)?;
            let failures = poll_all(&config, cli.dry_run);
            if failures > 0 {
                anyhow::bail!("{failures} device(s) failed to collect");
            }
            Ok(())
        }
        Command::Run => {
            let config = Config::load(&cli.config)?;
            run_forever(&config, cli.dry_run)
        }
        Command::Check => {
            let config = Config::load(&cli.config)?;
            check_all(&config)
        }
        Command::SampleEvents => {
            let config = Config::load(&cli.config)?;
            sample_events(&config)
        }
    }
}

/// Emit one synthetic event of each shape through the real sink.
fn sample_events(config: &Config) -> Result<()> {
    use yubihsm::{command, response};

    let device = config
        .devices
        .first()
        .context("config has no devices to borrow a name/tags from")?;
    let mut sink = sink::build(&config.output)?;

    let observed_at = event::now_epoch();
    let context = event::PollContext {
        device_name: device.name.clone(),
        connector_url: device.connector_url(),
        device_info_source: config.device_info_source.as_str(),
        device_serial: Some("0000000000".to_owned()),
        device_version: Some("0.0.0".to_owned()),
        log_store_used: Some(3),
        log_store_capacity: Some(62),
        observed_at_epoch: observed_at,
        tick_hz: device.tick_hz,
        tags: device.tags.clone().into_iter().collect(),
    };
    let anchor = event::TickAnchor::new(1000, observed_at, device.tick_hz, 0.0);

    let sample =
        |item: u16, cmd: command::Code, result: response::Code, tick: u32| event::LogEntry {
            item,
            cmd,
            length: 96,
            session_key: 4,
            target_key: 0x0100,
            second_key: 0xffff,
            result,
            tick,
            digest: [0xab; 16],
        };

    let entries = [
        sample(
            1,
            command::Code::SignEcdsa,
            response::Code::Success(command::Code::SignEcdsa),
            995,
        ),
        sample(
            2,
            command::Code::SignEcdsa,
            response::Code::DeviceInsufficientPermissions,
            998,
        ),
        sample(
            3,
            command::Code::HsmInitialization,
            response::Code::Success(command::Code::Error),
            1000,
        ),
    ];

    for (index, entry) in entries.iter().enumerate() {
        let audit_event = context.entry_event(
            entry,
            index as u64 + 1,
            0,
            Some("unverified"),
            anchor.estimate(entry.tick),
        );
        sink.write(device, &audit_event)?;
    }
    sink.write(device, &context.status_event(3, 0, entries.len()))?;
    sink.write(device, &context.skipped_status_event(3, 0))?;
    sink.flush()?;

    tracing::info!(events = entries.len() + 2, "sample events delivered");
    Ok(())
}

fn init_logging(level: Option<&str>) {
    let filter = match level {
        Some(level) => EnvFilter::new(level),
        None => EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
    };
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        // Logs go to stderr so the stdout sink stays machine-readable.
        .with_writer(std::io::stderr)
        .init();
}

/// Poll every device once. Returns the number of devices that failed.
///
/// A failure on one device never aborts the others: entries stay on the device
/// until they have been delivered, so the next cycle picks them up.
fn poll_all(config: &Config, dry_run: bool) -> usize {
    let mut sink = match sink::build(&config.output) {
        Ok(sink) => sink,
        Err(e) => {
            tracing::error!(error = %format_chain(&e), "cannot initialise output");
            return config.devices.len();
        }
    };

    let mut failures = 0;
    for device in &config.devices {
        let started = Instant::now();
        let result = collector::poll(config, device, sink.as_mut(), dry_run);

        match result {
            Ok(outcome) if outcome.skipped => tracing::debug!(
                device = %device.name,
                log_store_used = ?outcome.log_store_used,
                elapsed_ms = started.elapsed().as_millis(),
                "no new log activity; skipped the session"
            ),
            Ok(outcome) => tracing::info!(
                device = %device.name,
                returned = outcome.entries_returned,
                new = outcome.entries_new,
                emitted = outcome.events_emitted,
                chain_mismatches = outcome.chain_mismatches,
                advanced_to = ?outcome.advanced_to,
                elapsed_ms = started.elapsed().as_millis(),
                "poll complete"
            ),
            Err(e) => {
                failures += 1;
                tracing::error!(
                    device = %device.name,
                    error = %format_chain(&e),
                    "poll failed; entries remain on the device"
                );
            }
        }
    }
    failures
}

fn run_forever(config: &Config, dry_run: bool) -> Result<()> {
    let interval = Duration::from_secs(config.poll_interval_secs.max(1));
    let shutdown = Arc::new(AtomicBool::new(false));
    {
        let shutdown = shutdown.clone();
        ctrlc::set_handler(move || shutdown.store(true, Ordering::SeqCst))
            .context("installing signal handler")?;
    }

    tracing::info!(
        devices = config.devices.len(),
        interval_secs = interval.as_secs(),
        dry_run,
        "starting collector"
    );

    while !shutdown.load(Ordering::SeqCst) {
        let cycle_start = Instant::now();
        let failures = poll_all(config, dry_run);
        if failures > 0 {
            tracing::warn!(failures, "cycle finished with failures");
        }

        // Sleep in short slices so Ctrl-C is responsive.
        let deadline = cycle_start + interval;
        while Instant::now() < deadline && !shutdown.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(200).min(deadline - Instant::now()));
        }
    }

    tracing::info!("shutting down");
    Ok(())
}

/// Report on each device without consuming anything.
fn check_all(config: &Config) -> Result<()> {
    let mut failures = 0;

    for device in &config.devices {
        println!("device: {}", device.name);
        println!("  connector: {}", device.connector_url());
        println!("  auth key:  0x{:04x}", device.auth_key_id);
        println!("  info via:  {}", config.device_info_source.as_str());

        // Unauthenticated probe first: it needs no credentials, writes no audit
        // entry, and says whether the endpoint is alive before we spend a
        // (logged) authentication attempt on it.
        let probed = match probe::fetch(device) {
            Ok(info) => {
                println!(
                    "  probe:     ok, unauthenticated: serial {} firmware {} log {}/{} used",
                    info.serial(),
                    info.version(),
                    info.log_store_used,
                    info.log_store_capacity
                );
                Some(info)
            }
            Err(e) => {
                if config.device_info_source == config::DeviceInfoSource::Connector {
                    failures += 1;
                }
                println!("  probe:     FAILED: {}", format_chain(&e));
                None
            }
        };

        let client = match collector::connect(device) {
            Ok(client) => client,
            Err(e) => {
                failures += 1;
                println!("  status:    FAILED to authenticate");
                println!("  error:     {}", format_chain(&e));
                println!();
                continue;
            }
        };

        match client.device_info() {
            Ok(info) => {
                println!("  status:    ok");
                println!("  serial:    {}", info.serial_number);
                println!(
                    "  firmware:  {}.{}.{}",
                    info.major_version, info.minor_version, info.build_version
                );
                let percent = if info.log_store_capacity > 0 {
                    info.log_store_used as u32 * 100 / info.log_store_capacity as u32
                } else {
                    0
                };
                println!(
                    "  log store: {}/{} entries used ({}%)",
                    info.log_store_used, info.log_store_capacity, percent
                );

                // The session answer is MAC'd by the device; the probe's is not.
                // A disagreement means something on the network path is editing
                // the plaintext one, or the endpoint moved between the two calls.
                if let Some(probed) = &probed
                    && probed.serial() != info.serial_number.to_string()
                {
                    failures += 1;
                    println!(
                        "  MISMATCH:  probe reported serial {} but the session reports {}",
                        probed.serial(),
                        info.serial_number
                    );
                }
            }
            Err(e) => {
                failures += 1;
                println!("  status:    FAILED to read device info: {e}");
            }
        }

        match client.get_log_entries() {
            Ok(logs) => {
                println!(
                    "  readable:  {} entr(ies) pending (get-log-entries works)",
                    logs.entries.len()
                );
                if logs.unlogged_boot_events > 0 || logs.unlogged_auth_events > 0 {
                    println!(
                        "  WARNING:   {} unlogged boot events, {} unlogged auth events",
                        logs.unlogged_boot_events, logs.unlogged_auth_events
                    );
                }
                if let Some(first) = logs.entries.first() {
                    println!("  first item: {}", first.item);
                }
                if let Some(last) = logs.entries.last() {
                    println!("  last item:  {}", last.item);
                }
            }
            Err(e) => {
                failures += 1;
                println!(
                    "  readable:  FAILED: {e} (does key 0x{:04x} have get-log-entries?)",
                    device.auth_key_id
                );
            }
        }

        // Audit options need `get-option`, which a minimal auditor key lacks.
        match client.get_force_audit_option() {
            Ok(option) => println!("  force audit: {option:?}"),
            Err(_) => println!("  force audit: unknown (key lacks get-option)"),
        }
        match client.get_commands_audit_options() {
            Ok(options) => {
                let off: Vec<String> = options
                    .iter()
                    .filter(|option| option.audit_option() == yubihsm::audit::AuditOption::Off)
                    .map(|option| codes::command_name(option.command_type()))
                    .collect();
                if off.is_empty() {
                    println!("  per-command audit: all audited");
                } else {
                    println!("  per-command audit: NOT audited: {}", off.join(", "));
                }
            }
            Err(_) => println!("  per-command audit: unknown (key lacks get-option)"),
        }

        let state = state::DeviceState::load(&config.state_dir, &device.name)?;
        println!(
            "  cursor:    last_item={:?} sequence={} boot_session={} updated_at={:?}",
            state.last_item, state.sequence, state.boot_session, state.updated_at
        );
        if config.fast_path_enabled() {
            println!(
                "  fast path: enabled, baseline log_store_used={:?}, {} consecutive skip(s), \
                 full poll every {}",
                state.last_log_store_used, state.polls_skipped, config.force_full_poll_every
            );
        }
        println!();
    }

    if failures > 0 {
        anyhow::bail!("{failures} check(s) failed");
    }
    println!("all devices ok");
    Ok(())
}

/// Render an error together with its causes on one line.
///
/// The `yubihsm` crate nests errors whose `Display` output repeats ("I/O error:
/// I/O error: ..."), so consecutive duplicates are collapsed.
fn format_chain(error: &anyhow::Error) -> String {
    let mut parts: Vec<String> = Vec::new();
    for cause in error.chain() {
        let text = cause.to_string();
        if parts.last().map(|last| last == &text).unwrap_or(false) {
            continue;
        }
        parts.push(text);
    }
    parts.join(": ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_chain_collapses_repeats() {
        let error = anyhow::anyhow!("I/O error")
            .context("I/O error")
            .context("connecting to hsm-1");
        assert_eq!(format_chain(&error), "connecting to hsm-1: I/O error");
    }
}
