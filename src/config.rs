//! Configuration file handling (TOML).

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use std::{fs, path::Path, path::PathBuf};

/// Top level configuration.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// How often to poll each device when running in `run` mode.
    #[serde(default = "default_poll_interval")]
    pub poll_interval_secs: u64,

    /// Directory holding per-device cursor state.
    #[serde(default = "default_state_dir")]
    pub state_dir: PathBuf,

    /// Call `set-log-index` after events have been durably written.
    ///
    /// This is what frees space in the device log buffer. Turn it off only if
    /// another consumer owns the log index for these devices.
    #[serde(default = "default_true")]
    pub advance_log_index: bool,

    /// Verify the hash chain linking consecutive log entries.
    #[serde(default = "default_true")]
    pub verify_chain: bool,

    /// Resolve object IDs to labels/types (requires a key with `get-object-info`
    /// and `list-objects`; a pure auditor key does not have these).
    #[serde(default)]
    pub enrich_objects: bool,

    /// Emit a `device_status` event once per poll per device.
    #[serde(default = "default_true")]
    pub emit_device_status: bool,

    /// Where device serial/firmware/log-fill figures come from.
    #[serde(default)]
    pub device_info_source: DeviceInfoSource,

    /// Skip opening a session when the device's `log_store_used` has not moved
    /// since the last poll, i.e. when nothing was logged.
    ///
    /// Only has an effect with `device_info_source = "connector"`: the point is
    /// to learn there is nothing to fetch *without* paying the audit entries a
    /// session costs.
    #[serde(default = "default_true")]
    pub skip_poll_when_unchanged: bool,

    /// Poll in full after this many consecutive skips, whatever the fast path
    /// thinks. Bounds how long a frozen or forged `log_store_used` can suppress
    /// collection. `0` disables the ceiling and is not recommended.
    #[serde(default = "default_force_full_poll_every")]
    pub force_full_poll_every: u32,

    /// Warn when the device log buffer is at least this full (percent).
    #[serde(default = "default_log_fill_warn")]
    pub log_fill_warn_percent: u8,

    /// Where transformed events are written.
    pub output: Output,

    /// Devices to audit.
    pub devices: Vec<Device>,
}

/// A single YubiHSM 2 reachable through a `yubihsm-connector` HTTP endpoint.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Device {
    /// Friendly name; used as the event's `device_name`/syslog HOSTNAME and as
    /// the state file name.
    pub name: String,

    /// Address of the `yubihsm-connector` (IP or DNS name).
    pub addr: String,

    /// Port the connector listens on.
    #[serde(default = "default_connector_port")]
    pub port: u16,

    /// Connect/read/write timeout in milliseconds.
    #[serde(default = "default_connector_timeout")]
    pub timeout_ms: u64,

    /// Object ID of the auditor authentication key.
    pub auth_key_id: u16,

    /// Password, in precedence order: env var, file, inline.
    #[serde(default)]
    pub password_env: Option<String>,
    #[serde(default)]
    pub password_file: Option<PathBuf>,
    #[serde(default)]
    pub password: Option<String>,

    /// Ticks per second of the device's internal clock, used to estimate
    /// wall-clock times for log entries. See README ("Timestamps").
    #[serde(default = "default_tick_hz")]
    pub tick_hz: f64,

    /// Optional Splunk index override for this device (`hec` output only).
    #[serde(default)]
    pub index: Option<String>,

    /// Extra static fields merged into every event from this device
    /// (e.g. `datacenter = "iad1"`, `environment = "prod"`).
    #[serde(default)]
    pub tags: std::collections::BTreeMap<String, String>,
}

/// How to obtain device serial, firmware version, and log buffer utilisation.
#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceInfoSource {
    /// Inside the authenticated session. The values are MAC'd by the device and
    /// cannot be forged or replayed, at the cost of one audit entry per poll.
    #[default]
    Session,

    /// Unauthenticated `GetDeviceInfo` over the connector. Writes no audit
    /// entry, and enables `skip_poll_when_unchanged`, but the values are
    /// plaintext HTTP and a network attacker can forge them.
    Connector,

    /// Don't ask. Events carry no `device_serial`, `device_version`, or
    /// `log_store_*` fields.
    None,
}

impl DeviceInfoSource {
    /// Value stamped on every event so consumers can see how much to trust the
    /// device-identity and log-fill fields.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Session => "session",
            Self::Connector => "connector",
            Self::None => "none",
        }
    }
}

/// Event destination.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Output {
    /// One JSON object per line on stdout.
    Stdout,

    /// Append JSON lines to a file, for pickup by a Splunk universal forwarder.
    File {
        path: PathBuf,
        /// Roll the file once it exceeds this size (0 disables rolling).
        #[serde(default = "default_rotate_bytes")]
        rotate_bytes: u64,
        /// Number of rolled files to keep.
        #[serde(default = "default_rotate_keep")]
        rotate_keep: u8,
    },

    /// Splunk HTTP Event Collector.
    Hec {
        /// Base URL, e.g. `https://splunk.example.com:8088`.
        url: String,
        #[serde(default)]
        token: Option<String>,
        #[serde(default)]
        token_env: Option<String>,
        #[serde(default)]
        token_file: Option<PathBuf>,
        #[serde(default = "default_hec_sourcetype")]
        sourcetype: String,
        #[serde(default = "default_hec_source")]
        source: String,
        #[serde(default)]
        index: Option<String>,
        /// Optional PEM bundle for a private CA.
        #[serde(default)]
        ca_cert_file: Option<PathBuf>,
        /// Use the OS certificate store instead of the bundled roots.
        #[serde(default)]
        use_platform_roots: bool,
        /// Skip TLS verification. Never use outside a lab.
        #[serde(default)]
        tls_insecure: bool,
        #[serde(default = "default_hec_timeout")]
        timeout_ms: u64,
    },

    /// RFC 5424 syslog, one event per message with the JSON event as MSG.
    ///
    /// Generic: anything that can be a syslog receiver can take this,
    /// including Wazuh's manager `<remote>` listener, rsyslog, syslog-ng, or a
    /// SIEM's syslog input.
    Syslog {
        protocol: SyslogProtocol,
        /// Receiver address (IP or DNS name).
        host: String,
        #[serde(default = "default_syslog_port")]
        port: u16,
        /// Wrap the TCP connection in TLS. Ignored for `udp`.
        #[serde(default)]
        tls: bool,
        /// Optional PEM bundle for a private CA (TLS only).
        #[serde(default)]
        ca_cert_file: Option<PathBuf>,
        /// Use the OS certificate store instead of the bundled roots (TLS only).
        #[serde(default)]
        use_platform_roots: bool,
        /// Skip TLS verification. Never use outside a lab.
        #[serde(default)]
        tls_insecure: bool,
        /// Frame each TCP message with an RFC 6587 octet count instead of a
        /// trailing newline. Turn on only if your receiver requires it.
        #[serde(default)]
        octet_counting: bool,
        /// Syslog facility number (0-23). Default 16 = local0.
        #[serde(default = "default_syslog_facility")]
        facility: u8,
        /// APP-NAME field.
        #[serde(default = "default_syslog_app_name")]
        app_name: String,
        /// MSG payload shape: `json` (default) or `cef`.
        #[serde(default)]
        format: SyslogFormat,
        #[serde(default = "default_syslog_timeout")]
        timeout_ms: u64,
    },
}

/// Transport for the `syslog` output.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SyslogProtocol {
    Udp,
    Tcp,
}

/// MSG payload format for the `syslog` output.
#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SyslogFormat {
    /// The event as compact JSON. Generic; needs a JSON-aware decoder
    /// (Wazuh's `JSON_Decoder`, Logstash's `json` filter, ...).
    #[default]
    Json,
    /// ArcSight Common Event Format. Parsed natively by ArcSight, Microsoft
    /// Sentinel, QRadar (with the CEF DSM), and most other commercial SIEMs
    /// without custom parsing rules. Carries a reduced field set: the full
    /// event is still available in the `msg` extension as JSON.
    Cef,
}

fn default_poll_interval() -> u64 {
    60
}
fn default_state_dir() -> PathBuf {
    PathBuf::from("state")
}
fn default_true() -> bool {
    true
}
fn default_log_fill_warn() -> u8 {
    60
}
fn default_force_full_poll_every() -> u32 {
    10
}
fn default_connector_port() -> u16 {
    12345
}
fn default_connector_timeout() -> u64 {
    5000
}
fn default_tick_hz() -> f64 {
    1.0
}
fn default_rotate_bytes() -> u64 {
    128 * 1024 * 1024
}
fn default_rotate_keep() -> u8 {
    5
}
fn default_hec_sourcetype() -> String {
    "yubihsm:audit".to_owned()
}
fn default_hec_source() -> String {
    "yubihsm-auditor".to_owned()
}
fn default_hec_timeout() -> u64 {
    15_000
}
fn default_syslog_port() -> u16 {
    514
}
fn default_syslog_facility() -> u8 {
    16 // local0
}
fn default_syslog_app_name() -> String {
    "yubihsm-auditor".to_owned()
}
fn default_syslog_timeout() -> u64 {
    5_000
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let text = fs::read_to_string(path)
            .with_context(|| format!("reading config {}", path.display()))?;
        let config: Config =
            toml::from_str(&text).with_context(|| format!("parsing config {}", path.display()))?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<()> {
        if self.devices.is_empty() {
            bail!("no devices configured");
        }
        let mut names = std::collections::BTreeSet::new();
        for device in &self.devices {
            if !names.insert(&device.name) {
                bail!("duplicate device name: {}", device.name);
            }
            if device.name.is_empty() {
                bail!("device name must not be empty");
            }
            if device.tick_hz <= 0.0 {
                bail!("{}: tick_hz must be positive", device.name);
            }
            // Surface missing secrets at startup rather than mid-poll.
            device.password()?;
        }
        if let Output::Syslog { facility, .. } = &self.output
            && *facility > 23
        {
            bail!("syslog facility must be 0-23, got {facility}");
        }
        Ok(())
    }

    /// True when a poll may decide, from unauthenticated device info alone, that
    /// there is nothing to collect.
    pub fn fast_path_enabled(&self) -> bool {
        self.skip_poll_when_unchanged && self.device_info_source == DeviceInfoSource::Connector
    }
}

impl Device {
    /// Resolve the auditor key password from the configured source.
    pub fn password(&self) -> Result<String> {
        if let Some(var) = &self.password_env {
            return std::env::var(var).map_err(|_| {
                anyhow!(
                    "{}: environment variable {} is not set (password_env)",
                    self.name,
                    var
                )
            });
        }
        if let Some(path) = &self.password_file {
            let raw = fs::read_to_string(path).with_context(|| {
                format!("{}: reading password_file {}", self.name, path.display())
            })?;
            return Ok(raw.trim_end_matches(['\r', '\n']).to_owned());
        }
        if let Some(inline) = &self.password {
            return Ok(inline.clone());
        }
        Err(anyhow!(
            "{}: set one of password_env, password_file, or password",
            self.name
        ))
    }

    pub fn connector_url(&self) -> String {
        format!("http://{}:{}", self.addr, self.port)
    }

    pub fn http_config(&self) -> yubihsm::connector::HttpConfig {
        yubihsm::connector::HttpConfig {
            addr: self.addr.clone(),
            port: self.port,
            timeout_ms: self.timeout_ms,
        }
    }
}

/// Sample configuration emitted by `init-config`.
pub const TEMPLATE: &str = r##"# yubihsm-auditor configuration
poll_interval_secs = 60
state_dir = "state"

# Advancing the log index is what frees space in the device's 62-entry buffer.
# Only one consumer per device may own the index.
advance_log_index = true

# Verify the SHA-256 hash chain across consecutive entries.
verify_chain = true

# Requires list-objects/get-object-info capabilities, which a pure auditor
# key does not have. Leave false unless you use a broader key.
enrich_objects = false

emit_device_status = true
log_fill_warn_percent = 60

# Where device serial/firmware/log-fill come from.
#   "session"   MAC'd by the device, costs one audit entry per poll (default)
#   "connector" unauthenticated GetDeviceInfo, writes no audit entry, forgeable
#   "none"      don't ask; events omit those fields
# Every event carries device_info_source so the trust level is visible downstream.
device_info_source = "session"

# With device_info_source = "connector", skip opening a session entirely when
# log_store_used has not moved, which takes an idle poll down to zero audit
# entries. Ignored for the other sources, where the session is paid for anyway.
skip_poll_when_unchanged = true

# ...but poll in full every N consecutive skips regardless, so a frozen or
# forged log_store_used cannot suppress collection indefinitely.
force_full_poll_every = 10

# --- Output -----------------------------------------------------------------
# [output]
# type = "stdout"

# [output]
# type = "file"
# path = "/var/log/yubihsm/audit.jsonl"
# rotate_bytes = 134217728
# rotate_keep = 5

# Generic: any syslog receiver, including Wazuh's manager <remote> listener,
# rsyslog, syslog-ng, or a SIEM's syslog input.
[output]
type = "syslog"
protocol = "tcp"
host = "wazuh.example.com"
port = 514
# tls = true
# ca_cert_file = "/etc/ssl/certs/internal-ca.pem"
# use_platform_roots = true
facility = 16
app_name = "yubihsm-auditor"
# format = "cef"                      # "json" (default) or "cef" for ArcSight/Sentinel/QRadar

# [output]
# type = "hec"
# url = "https://splunk.example.com:8088"
# token_env = "SPLUNK_HEC_TOKEN"
# sourcetype = "yubihsm:audit"
# source = "yubihsm-auditor"
# index = "hsm_audit"
# ca_cert_file = "/etc/ssl/certs/internal-ca.pem"
# use_platform_roots = true

# --- Devices ----------------------------------------------------------------
[[devices]]
name = "hsm-iad1-01"
addr = "10.0.10.11"
port = 12345
timeout_ms = 5000
auth_key_id = 4
password_env = "HSM_IAD1_01_PASSWORD"
tick_hz = 1.0

[devices.tags]
environment = "prod"
datacenter = "iad1"

[[devices]]
name = "hsm-iad1-02"
addr = "10.0.10.12"
auth_key_id = 4
password_env = "HSM_IAD1_02_PASSWORD"
"##;
