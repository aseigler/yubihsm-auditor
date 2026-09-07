# yubihsm-auditor

Collects the audit log from one or more YubiHSM 2 devices over HTTP
(`yubihsm-connector`), transforms each entry into a flat JSON event, and ships it
to wherever you do detection: syslog (Wazuh, rsyslog, syslog-ng, or any other
syslog receiver), Splunk HTTP Event Collector, a JSON-lines file, or stdout.

The point is accountability: every audited device operation becomes an event
carrying the authentication key that opened the session, the object the
operation touched, the result code, and an estimated wall-clock time, so device
activity can be reconciled against the logs of the applications that talk to the
HSM. Anything the device recorded that no application claims is unaccounted key
usage.

## What it needs on the device

An authentication key configured as an auditor. Only two capabilities are
required:

| Capability        | Used for                                                |
| ----------------- | ------------------------------------------------------- |
| `get-log-entries` | reading the audit log                                   |
| `set-log-index`   | acknowledging entries so the device can reuse the buffer |

Optional, and only if you want the extras:

| Capability                       | Enables                                                   |
| -------------------------------- | --------------------------------------------------------- |
| `get-option`                     | `check` reporting force-audit and per-command audit policy |
| `list-objects`, `get-object-info`| `enrich_objects = true` (object labels/types in events)    |

Creating an auditor key with `yubihsm-shell`, in domain 1, key ID 4:

```
yubihsm> put authkey 0 4 auditor 1 get-log-entries,set-log-index none <password>
```

Two device options matter:

- **Per-command audit** (`SetOption`, `command` tag) decides which commands are
  logged at all. Anything set to `off` never reaches this tool. `check` reports
  which commands are not audited.
- **Force audit** (`SetOption`, `force` tag). When on, the device refuses audited
  operations once its log buffer is full, i.e. it fails closed rather than losing
  audit records. This tool exists to keep that buffer drained; the buffer holds
  only 62 entries, so poll accordingly.

## Build and run

```
cargo build --release
./target/release/yubihsm-auditor init-config > yubihsm-auditor.toml
export HSM_IAD1_01_PASSWORD=...            # per device
export SPLUNK_HEC_TOKEN=...
./target/release/yubihsm-auditor check      # connectivity + audit policy report
./target/release/yubihsm-auditor sample-events   # test the output path only
./target/release/yubihsm-auditor once --dry-run  # read, emit, change nothing
./target/release/yubihsm-auditor run        # poll forever
```

Subcommands:

| Command         | Effect                                                                   |
| --------------- | ------------------------------------------------------------------------ |
| `run`           | Poll every device every `poll_interval_secs` until Ctrl-C.                |
| `once`          | Poll every device once; non-zero exit if any device failed.               |
| `check`         | Probe unauthenticated, authenticate, print device info, log fill, policy, cursor. |
| `sample-events` | Push synthetic events through the configured sink (validates the destination end-to-end). |
| `init-config`   | Print a commented sample configuration.                                   |

Global flags: `--config <path>`, `--dry-run`, `--log-level <level>`. Diagnostics
go to stderr, so the `stdout` sink stays machine-readable.

`--dry-run` reads and emits events but never calls `set-log-index` and never
writes the local cursor, so it is safe to point at a device another collector
owns.

## Configuration

See `init-config` output for a fully commented file. Key settings:

| Setting                 | Default | Notes                                                                     |
| ----------------------- | ------- | ------------------------------------------------------------------------- |
| `poll_interval_secs`    | `60`    | Also the timestamp uncertainty bound (see Timestamps).                     |
| `state_dir`             | `state` | One JSON cursor file per device. Must survive restarts.                    |
| `advance_log_index`     | `true`  | Calls `set-log-index`. **Only one consumer per device may do this.**        |
| `verify_chain`          | `true`  | Adds `chain_status` to each event.                                         |
| `enrich_objects`        | `false` | Needs `list-objects`/`get-object-info`; issues extra audited commands.      |
| `emit_device_status`    | `true`  | One heartbeat event per device per poll.                                   |
| `log_fill_warn_percent` | `60`    | Warn when the device buffer is this full.                                  |
| `device_info_source`    | `session` | `session`, `connector`, or `none`. See below.                             |
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

## Delivery guarantees

Per device, per poll: read log → emit events → **flush the sink** → `set-log-index`
→ save the cursor. The device is only told an entry was consumed after that entry
is durable downstream (fsync for the file sink, HTTP 200 for HEC, a successful
write for `syslog` TCP). A crash or outage at the destination therefore loses
nothing; entries stay on the device and are re-read next cycle. `syslog` over
`udp` is the exception: a successful `send` only means the datagram left the
host, not that the receiver got it, so prefer `tcp` where the delivery
guarantee matters. The failure mode is duplication, not loss: if the
process dies after delivery but before the cursor is written, those entries
are sent again. Deduplicate downstream on `device_serial` + `log_digest`,
which is unique per entry.

One failing device never blocks the others.

## Event schema

One JSON object per event. `event_type` is one of:

- `command` — an audited device operation
- `boot` — a device boot/initialization record
- `unlogged_events` — the device reported events it could not record (audit gap)
- `device_status` — per-poll heartbeat with log buffer utilisation

| Field                                                | Meaning                                                                 |
| ---------------------------------------------------- | ----------------------------------------------------------------------- |
| `time`, `time_iso`                                   | Estimated wall-clock time of the operation; `time` becomes `_time`.      |
| `time_source`, `time_uncertainty_secs`               | `tick_anchor` or `poll_time`, and the error bound.                       |
| `device_name`, `device_serial`, `device_version`     | Device identity. `device_name` is the config name / syslog HOSTNAME / Splunk `host`. |
| `connector_url`                                      | Which connector the entry came through.                                 |
| `device_info_source`                                 | `session` (MAC'd by the device), `connector` (plaintext), or `none`.      |
| `sequence`                                           | Monotonic per-device counter; survives `log_item` wrapping at 65535.     |
| `boot_session`                                       | Incremented on every reboot this collector witnessed.                    |
| `log_item`, `tick`                                   | Raw device log index and tick counter.                                  |
| `command`, `command_code`, `command_category`        | e.g. `sign_ecdsa`, `86`, `sign`.                                        |
| `key_usage`, `key_management`                        | Booleans: key *used* vs key created/changed/deleted.                     |
| `result`, `result_name`, `result_code`               | `success`/`error`, e.g. `device_insufficient_permissions`, `-20`.        |
| `session_key_id`(`_hex`)                             | Authentication key that opened the session — the "who".                  |
| `target_key_id`(`_hex`), `second_key_id`(`_hex`)     | Objects the operation touched — the "what". Omitted when not applicable. |
| `*_label`, `target_key_type`                         | Only when `enrich_objects = true`.                                       |
| `log_digest`, `chain_status`                         | Entry digest and `ok`/`mismatch`/`unverified`.                           |
| `log_store_used`, `log_store_capacity`, `log_store_percent_used` | Device buffer utilisation.                                  |
| `unlogged_boot_events`, `unlogged_auth_events`       | On `unlogged_events` only: size of the audit gap.                        |
| `poll_skipped`                                       | On `device_status` only: the poll never opened a session (nothing new).   |
| `observed_at`                                        | When the collector read the entry.                                       |
| `collector`, `collector_version`                     | Provenance.                                                              |
| *(device tags)*                                      | Your `[devices.tags]` keys, flattened into the event.                    |

## Self-generated log entries

Reading the audit log is itself audited, so the collector shows up in its own
output. Every `Client` method in the `yubihsm` crate goes through
`send_command`, which opens with `self.session()?`; there is no such thing as an
unaudited `Client` call. A full poll therefore contributes:

| Entry | From |
| --- | --- |
| `create_session` | opening the session |
| `authenticate_session` | same |
| `device_info` | only with `device_info_source = "session"` |
| `get_log_entries` | the read |
| `set_log_index` | only when there were new entries and not `--dry-run` |

Four on an idle poll, five when acking. The session is not reused between polls:
the crate's inactivity timeout is 30 s, so any `poll_interval_secs` above that
re-authenticates every cycle. Against a 62-entry buffer that is 6–8 % of your
audit capacity spent per poll on watching the device, and it scales the wrong way
— polling more often for tighter timestamps costs proportionally more buffer.

Two settings cut it down:

- **`device_info_source = "connector"`** issues `GetDeviceInfo` outside the
  session. The device answers unauthenticated `GetDeviceInfo` in the clear and
  records nothing, so this removes the `device_info` entry.
- **`skip_poll_when_unchanged`** (which needs the above) uses the
  `log_store_used` figure that comes back with it to decide whether to open a
  session at all. Entries are only freed by `set-log-index` or a reset, so
  between polls the count only rises; if it has not moved, nothing was logged and
  there is nothing to fetch. **An idle poll then writes no audit entries at
  all.** The heartbeat is still emitted, carrying `poll_skipped = true`, so
  liveness alerting is unaffected.

The baseline for that comparison is re-read *after* acking, because the poll's
own `get_log_entries`/`set_log_index` entries land after the read; comparing
against the pre-read figure would see a difference every time and never skip.

### What you give up

`device_info_source = "connector"` is plaintext HTTP with no HSM
authentication, whereas a session response is R-MAC'd under the SCP03 session
keys and provably fresh. So with `connector`:

- `device_serial`, `device_version`, and `log_store_*` become forgeable by
  anything on the network path. `device_serial` is one of the two fields used for
  dedupe, and the "device serial changed" warning keys off it. Every event carries
  `device_info_source` so consumers can see which events are backed by a MAC.
- A network attacker who *freezes* `log_store_used` suppresses collection: the
  fast path keeps deciding there is nothing to fetch, the buffer fills, and either
  the HSM starts failing audited operations (force-audit on) or silently
  overwrites entries (force-audit off). `force_full_poll_every` bounds that
  window — the default polls in full at least every 10 cycles no matter what the
  probe says. Setting it to `0` removes the ceiling and is not recommended.
- `unlogged_boot_events` / `unlogged_auth_events` are only visible through
  `get-log-entries`. An audit *gap* does not move `log_store_used` (the point is
  that those events could not be recorded), so a gap is reported on the next full
  poll rather than immediately — delayed by at most `force_full_poll_every`
  intervals.

`check` reports both sources when it can reach the device, and fails if the
unauthenticated serial disagrees with the session's.

One implementation note: `Connector::send_message` is public, but the
`connector::Message` it takes is exported `pub(crate)`. The type cannot be named
outside the crate, so `src/probe.rs` reaches it through the public
`From<Vec<u8>>`/`Into<Vec<u8>>` impls and type inference. That compiles and is
stable in behaviour, but it is clearly not an interface the crate intended to
expose; an upstream `Connector::device_info()` would be the better home for this.
A patch that adds exactly that, against `yubihsm.rs` `main` (0.43.0-pre), is in
`upstream/` (`0001-connector-device-info.patch` plus the PR writeup in `PR.md`,
applied in the clone at `upstream/yubihsm.rs`). If it lands,
`src/probe.rs` collapses to a call to `connector.device_info()`.

### Timestamps

The device does not report wall-clock time — only a tick counter that resets on
boot. Each poll anchors the newest entry to the moment it was read and works
backwards using `tick_hz` (default `1.0`, i.e. ticks are treated as seconds).
Estimated times are therefore accurate to roughly the age of the newest entry,
bounded by `poll_interval_secs`; that bound is published on every event as
`time_uncertainty_secs`. Poll more often for tighter times. When a batch spans a
reboot, entries from the earlier boot session are anchored to just before the
first entry of the following session, so pre-reboot entries never appear after
it. `tick` and `boot_session` are always emitted raw, so exact ordering within a
device never depends on the estimate — use `sequence` for that.

### Hash chain

Each entry carries a 16-byte digest chaining it to the previous entry. This tool
checks `digest == SHA-256(entry_body || previous_digest)[0..16]` across
consecutive entries and across polls (the last digest is persisted). Verified
against 5 consecutive real entries captured from a production YubiHSM 2 (see
`real_hardware_chain_from_yh2` in `src/event.rs`) — note the concatenation
order, `entry_body` first: an earlier version of this tool had it reversed,
which compiled and ran fine but made every single entry report `mismatch`
indistinguishably from either a broken chain or a firmware difference. If you
still see `mismatch` on entries you know are healthy and contiguous, that's
more likely a real signal now than a construction bug — though a firmware
version this hasn't been checked against remains possible. `chain_status` is:

- `ok` — links to the preceding entry
- `unverified` — no anchor available (first collection, a gap in the cursor, or
  the first entry after a device reset, whose seed digest this tool does not know)
- `mismatch` — the digest does not follow from the previous one

Treat `mismatch` as a signal to investigate, not as proof of tampering on its
own — cross-check against `log_digest` uniqueness and the surrounding
`sequence`/`tick` values before concluding an entry was altered. Editing one
entry only breaks that entry's own link, so a `mismatch` points at the entry
that changed; if you need to fall back to dedup-only integrity, set
`verify_chain = false` and rely on `log_digest` uniqueness instead.

## Running as a systemd service

`systemd/` has a unit and an environment-file template for running `run`
continuously. Adjust paths/user as needed:

```
useradd --system --home-dir /var/lib/yubihsm-auditor --create-home yubihsm-auditor

install -m 755 target/release/yubihsm-auditor /usr/local/bin/yubihsm-auditor

mkdir -p /etc/yubihsm-auditor /var/log/yubihsm
./target/release/yubihsm-auditor init-config > /etc/yubihsm-auditor/yubihsm-auditor.toml
# edit /etc/yubihsm-auditor/yubihsm-auditor.toml: devices, output (state_dir =
# "/var/lib/yubihsm-auditor/state" and, for the file output,
# path = "/var/log/yubihsm/audit.jsonl")

cp systemd/yubihsm-auditor.env.example /etc/yubihsm-auditor/yubihsm-auditor.env
# edit it with real device passwords / tokens

chown -R yubihsm-auditor:yubihsm-auditor /etc/yubihsm-auditor /var/log/yubihsm
chmod 600 /etc/yubihsm-auditor/yubihsm-auditor.env /etc/yubihsm-auditor/yubihsm-auditor.toml

cp systemd/yubihsm-auditor.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now yubihsm-auditor
journalctl -u yubihsm-auditor -f
```

The unit runs as the dedicated `yubihsm-auditor` user with a sandboxed
`ProtectSystem=strict` profile that only grants write access to
`/var/lib/yubihsm-auditor` (state) and `/var/log/yubihsm` (the `file`
output's log directory) — widen `ReadWritePaths=` in the unit if you point
`state_dir` or the `file` output's `path` somewhere else. Diagnostics go to
stderr, which systemd captures to the journal, so `journalctl -u
yubihsm-auditor` is where poll failures and delivery retries show up — the
event stream itself goes only to the configured `output`, never the journal.

Validate the destination before pointing it at real devices:

```
sudo -u yubihsm-auditor /usr/local/bin/yubihsm-auditor \
  --config /etc/yubihsm-auditor/yubihsm-auditor.toml check
sudo -u yubihsm-auditor /usr/local/bin/yubihsm-auditor \
  --config /etc/yubihsm-auditor/yubihsm-auditor.toml sample-events
```

## Getting events to your SIEM

### Wazuh

Two paths, depending on whether `wazuh-agent` already runs on the same host as
the collector.

**Agent on the same host (recommended when available)**: use the `file`
output and let the agent tail it — no listener to open, no TLS, no PRI/CEF
parsing, and delivery rides the agent's existing encrypted channel to the
manager. See `wazuh/agent-localfile.conf.example` for the agent's
`ossec.conf` `<localfile>` snippet (`log_format = "json"`, no custom decoder
needed — Wazuh parses JSON localfiles natively) and
`wazuh/rules/local_rules-agent.xml` for the manager-side rules, which use the
same bare field names as the syslog path (`<field name="event_type">`, no
prefix) — the `data.*` nesting you'll see in `archives.json`/`alerts.json` is
only how Wazuh serializes the output, not how a rule's `<field name="...">`
addresses a decoded key; confirm with `wazuh-logtest` if you're unsure, its
Phase 2 output prints the bare names a rule should match against. See
"Running as a systemd service" below for getting the binary running
continuously in the first place.

**No local agent** (the collector runs somewhere the manager can reach over
the network, but that host doesn't run an agent): use the `syslog` output
pointed at the Wazuh manager, which needs a `<remote>` syslog listener — see
`wazuh/manager-remote.conf.example` for that `ossec.conf` snippet. Install
`wazuh/decoders/local_decoder.xml` and `wazuh/rules/local_rules.xml` on the
manager (`/var/ossec/etc/decoders/` and `/var/ossec/etc/rules/`); the decoder
recognizes the `yubihsm-auditor` APP-NAME and hands the JSON payload to
Wazuh's JSON decoder, and the rules use the unprefixed field names that
produces.

Install only the rule set matching the path you use — the field prefixes
differ between them, and both are a starting point to check against your
Wazuh version and existing rule IDs, not a drop-in guarantee.

### Elastic / OpenSearch

Use the `file` output and ship it with Filebeat — see
`elastic/filebeat.yml.example` for an `ndjson` filestream input that puts every
event field at the top level. Install the mappings and pipeline once (both APIs
are the same on Elasticsearch and OpenSearch):

```
PUT _component_template/yubihsm-audit-mappings   < elastic/component-template.json
PUT _ingest/pipeline/yubihsm-audit                < elastic/ingest-pipeline.json
PUT _index_template/yubihsm-audit                 < elastic/index-template.json
```

`elastic/component-template.json` maps each event field to a concrete type
(dates, keywords, booleans, etc. instead of Elasticsearch's dynamic-mapping
guesses) and maps `[devices.tags]` values as keywords via a dynamic template,
so arbitrary per-device tags don't hit the mapping-explosion or default
text-analysis behavior. `elastic/ingest-pipeline.json` sets `@timestamp` from
the collector's estimated operation time (`time_iso`) rather than ingest time,
and adds a light ECS overlay (`event.dataset`, `event.action`, `event.outcome`,
`event.category`, `event.severity`) so the data shows up in Elastic's built-in
dashboards and detection rules that expect those fields. Treat all three as a
starting point — check them against your cluster's version before relying on
them, particularly the ECS category/severity mapping, which is a reasonable
default rather than a byte-for-byte ECS spec match.

### Any other syslog receiver

The `syslog` output is plain RFC 5424 with a JSON body by default (see above),
so rsyslog, syslog-ng, journald's syslog listener, or a SIEM's generic syslog
input all take it without extra configuration beyond pointing at the collector
and parsing JSON out of the message. Set `format = "cef"` instead if your
receiver parses CEF natively.

### Splunk

**HEC**: use the `hec` output. `host` is the device name, `sourcetype` defaults
to `yubihsm:audit`, and `time` is set from the event, so Splunk's `_time` is the
estimated operation time rather than the ingest time.

**Universal forwarder**: use the `file` output and the configs in `splunk/`
(`props.conf` for the sourcetype, `inputs.conf` for the file monitor).

Either way, `splunk/props.conf` gives you JSON field extraction, `_time` from the
`time` field, and `TRUNCATE`/line-breaking settings appropriate for JSON lines.

## Correlating with application logs

Have every application that opens an HSM session log the authentication key ID it
authenticates with (and, where it knows it, the object ID it operates on). That
turns reconciliation into a field join.

Unaccounted key usage — device operations no application claims, bucketed by
minute to absorb timestamp uncertainty:

```spl
(index=hsm_audit sourcetype="yubihsm:audit" event_type=command key_usage=true)
  OR (index=app sourcetype="myapp:hsm" action=sign)
| eval key_id = coalesce(target_key_id, hsm_key_id),
       auth_key = coalesce(session_key_id, hsm_auth_key_id),
       src = if(sourcetype=="yubihsm:audit", "device", "app")
| bin _time span=1m
| stats count(eval(src=="device")) AS device_ops,
        count(eval(src=="app"))    AS app_ops
        BY _time, device_name, auth_key, key_id
| where device_ops != app_ops
```

Widen `span` if `time_uncertainty_secs` on your events is larger than a minute.

Key usage by object and application identity:

```spl
index=hsm_audit sourcetype="yubihsm:audit" event_type=command key_usage=true result=success
| stats count BY device_name, session_key_id, target_key_id, command
| sort - count
```

Alert-worthy conditions:

```spl
index=hsm_audit sourcetype="yubihsm:audit"
| where event_type=="unlogged_events"                 /* audit gap on the device */
     OR chain_status=="mismatch"                       /* chain check failed */
     OR (event_type=="command" AND result=="error"
         AND result_name=="device_insufficient_permissions")   /* capability probing */
     OR (event_type=="command" AND key_management==true)       /* key lifecycle change */
     OR log_store_percent_used > 75                    /* collector falling behind */
```

Collector liveness: `device_status` arrives once per device per poll — including
polls that skipped the session, which carry `poll_skipped=true` — so alert on its
absence:

```spl
index=hsm_audit sourcetype="yubihsm:audit" event_type=device_status
| stats latest(_time) AS last_seen BY device_name
| eval age_secs = now() - last_seen
| where age_secs > 300
```

## Operational notes

- **Only one consumer may advance the log index per device.** If you also run
  `yubihsm-shell get audit-logs`, or a second copy of this tool, they will
  consume each other's entries. Give the others `advance_log_index = false` or
  `--dry-run`.
- **The buffer holds 62 entries.** With force-audit on, a full buffer stops
  audited operations. Poll frequently enough for your busiest device and alert on
  `log_store_percent_used`.
- **Reading the log is itself audited.** Expect `get_log_entries`,
  `set_log_index`, `create_session`, and `authenticate_session` entries
  attributed to the auditor key. Filter them out in dashboards with
  `command_category!=audit command_category!=session`. See "Self-generated log
  entries" for the counts and how to reduce them. There is no `close_session`:
  the crate offers no way to close one, so sessions are left to the device's
  inactivity timeout.
- **Keep `state_dir` on durable storage.** Losing it costs the chain anchor and
  the `sequence` continuity (a `unverified` entry and a sequence restart), not
  correctness of new events.
- Devices are polled sequentially in one thread; the workload is a handful of
  small requests per device per interval.
- The connector protocol is plain HTTP, but the session inside it is
  authenticated and encrypted end-to-end with the HSM, so a hostile network can
  observe metadata and drop traffic but cannot forge or read log contents. That
  guarantee does not extend to anything fetched with
  `device_info_source = "connector"`.
- **Unauthenticated `GetDeviceInfo` is a metadata channel to anyone who can reach
  the connector's port,** and one the device does not log. It discloses firmware
  version, serial, and log buffer fill — the last of which, under force-audit,
  tells an attacker when the device is about to start refusing audited
  operations. That is an argument for keeping connector ports reachable only from
  the collector, not against using the call.

## Tests

```
cargo test
```

Covers the cursor/dedup logic including 16-bit wraparound, hash-chain
verification and tamper detection, reboot detection and tick anchoring, code and
result name mapping, entry wire-format re-serialization, state file round-trip,
and secret resolution. The device-facing calls are the untested part; use
`check` and `once --dry-run` against real hardware.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in this project shall be dual licensed as above,
without any additional terms or conditions.
