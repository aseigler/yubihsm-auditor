# Configuration

See `init-config` output for a fully commented file. Key settings:

| Setting                 | Default | Notes                                                                     |
| ----------------------- | ------- | ------------------------------------------------------------------------- |
| `poll_interval_secs`    | `60`    | Also the timestamp uncertainty bound (see [Polling behavior](polling-behavior.md#timestamps)). |
| `state_dir`             | `state` | One JSON cursor file per device. Must survive restarts.                    |
| `advance_log_index`     | `true`  | Calls `set-log-index`. **Only one consumer per device may do this.**        |
| `verify_chain`          | `true`  | Adds `chain_status` to each event.                                         |
| `enrich_objects`        | `false` | Needs `list-objects`/`get-object-info`; issues extra audited commands.      |
| `emit_device_status`    | `true`  | One heartbeat event per device per poll.                                   |
| `log_fill_warn_percent` | `60`    | Warn when the device buffer is this full.                                  |
| `device_info_source`    | `session` | `session`, `connector`, or `none`. See [Polling behavior](polling-behavior.md) and [Security model](security.md). |
| `skip_poll_when_unchanged` | `true` | Skip the session when nothing was logged. Needs `connector`.             |
| `force_full_poll_every` | `10`    | Poll in full after this many consecutive skips.                            |

Per device: `name` (becomes `device_name` in every event, and the syslog
HOSTNAME or Splunk `host`), `addr`, `port`, `timeout_ms`, `auth_key_id`, a
password source, `tick_hz`, an optional `index` override (`hec` output only),
and a `[devices.tags]` table whose keys are merged into every event from that
device.

Passwords and HEC tokens resolve in this order: `*_env` (environment variable),
`*_file`, then inline. Prefer the environment variable or a mode-600 file; an
inline secret sits in the config file forever.

## Output

Output is one of:

```toml
[output]
type = "stdout"                      # JSON lines on stdout

[output]
type = "file"                        # JSON lines, rolled by size
path = "/var/log/yubihsm/audit.jsonl"
rotate_bytes = 134217728
rotate_keep = 5

[output]
type = "syslog"                      # RFC 5424 syslog, generic
protocol = "tcp"                     # "tcp" or "udp"
host = "wazuh.example.com"
port = 514
# tls = true                          # TCP only
# ca_cert_file = "/etc/ssl/certs/internal-ca.pem"   # private CA
# use_platform_roots = true                          # OS trust store
facility = 16                        # local0
app_name = "yubihsm-auditor"

[output]
type = "hec"                         # Splunk HTTP Event Collector
url = "https://splunk.example.com:8088"
token_env = "SPLUNK_HEC_TOKEN"
sourcetype = "yubihsm:audit"
index = "hsm_audit"
# ca_cert_file = "/etc/ssl/certs/internal-ca.pem"   # private CA
# use_platform_roots = true                          # OS trust store
```

HEC delivery batches events (512 KB cap), retries 5xx/429 with backoff, and
fails the poll on a 4xx so a bad token or index cannot silently drop audit data.

The `syslog` output sends one RFC 5424 message per event: `<PRI>1 TIMESTAMP
HOSTNAME APP-NAME PROCID MSGID - JSON`, where `HOSTNAME` is the device name,
`MSGID` is `event_type`, and everything after the `-` is the event as compact
JSON — no vendor-specific structured data, so any syslog receiver can parse it.
Severity is derived from the event (`unlogged_events` and a `chain_status` of
`mismatch` map to `critical`; a failed command to `warning`; key management to
`notice`; everything else to `informational`) so severity-based filtering works
out of the box. `tcp` frames each message with a trailing newline by default
(RFC 6587 non-transparent framing); set `octet_counting = true` if your receiver
requires RFC 6587 octet-counted framing instead. `udp` sends one datagram per
event and cannot signal delivery failure back to the collector — prefer `tcp`
unless your receiver only speaks UDP syslog. TLS wraps the TCP connection
directly (RFC 5425-style); if your receiver only takes plaintext syslog, put a
local relay (`stunnel`, `rsyslog`, `syslog-ng`) in front of it instead.

Set `format = "cef"` to send [ArcSight Common Event
Format](https://www.microfocus.com/documentation/arcsight/arcsight-smartconnectors/pdfdoc/common-event-format-v25/common-event-format-v25.pdf)
instead of JSON as MSG: `CEF:0|Yubico|YubiHSM2|<device_version>|<signature>|<name>|<severity>|<extension>`.
ArcSight, Microsoft Sentinel, QRadar (with the CEF DSM), and most other
commercial SIEMs parse this natively — no custom decoder needed, unlike the
`json` format. The mapping is necessarily lossy (CEF's numbered `cs`/`cn` slots
don't cover every field), so the standard extension keys (`act`, `outcome`,
`cat`, `rt`, `dvchost`, ...) carry the fields a generic CEF consumer already
knows how to display, the domain-specific ones (key IDs, chain status, log
digest, log fill) ride in labelled `cs1`-`cs6`/`cn1`-`cn3` slots, and the `msg`
extension carries the full event as JSON as a fallback. Use `json` instead if
your receiver has (or can be given, e.g. Wazuh's `JSON_Decoder`) a JSON-aware
decoder — it round-trips every field.
