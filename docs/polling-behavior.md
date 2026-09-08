# Polling behavior, timestamps, and hash chain

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
  records nothing, so this removes the `device_info` entry. See
  [Security model](security.md) for what you give up in exchange.
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

**In practice, this fast path rarely engages during continuous `run` polling.**
`connect()` opens a brand-new session every single `poll()` call — there is no
session reuse across cycles in the current implementation — so every poll
writes its own `create_session`/`authenticate_session` entries. And because
`get_log_entries` and `set_log_index` each write their own audit entry only
*after* they execute, those two entries are never included in the read/ack
that happens during the same poll that created them: they always land as
unfinished business for the *next* cycle to discover. That is a small,
constant, self-perpetuating trickle — every poll leaves roughly two entries
behind for the next one to find — which means the probe's `log_store_used`
essentially never matches the previous poll's baseline while running
continuously, so `skip_poll_when_unchanged` mostly cannot trigger in that mode.
It remains genuinely useful for a `once` run separated from the last poll by a
long gap. `check` reports both sources when it can reach the device, and fails
if the unauthenticated serial disagrees with the session's.

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

## Timestamps

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

## Hash chain

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
`verify_chain = false` and rely on `log_digest` uniqueness instead. See
[Security model](security.md) for why this check is more than cosmetic: it is
the main way to detect an entry that was acknowledged and freed before this
collector ever read it.
