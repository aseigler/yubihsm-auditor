# Security model

This collects the trust and threat-model considerations that are scattered
by topic elsewhere in the docs, in one place for anyone doing a security
review of a deployment.

## Any authenticated key can consume the audit log, not just the auditor's

`GetLogEntries` and `SetLogIndex` are both documented by Yubico as requiring
no specific capability. Any key that can open an authenticated session at
all — regardless of what it's actually permitted to *do* — can read and
acknowledge the audit log. This was confirmed against Yubico's own command
reference and against real-hardware testing during this tool's development:
a key granted only `get-log-entries` (no other capability) could still call
`SetLogIndex` successfully.

That has a real consequence for the accountability model this tool is built
around: a key meant for something narrow (say, signing with one specific
object, with no capabilities that look dangerous) can perform an operation
that gets logged, then immediately call `SetLogIndex` to acknowledge past its
own entry — freeing that slot in the 62-entry ring buffer — before this
collector's next poll ever reads it. The entry is simply gone by the time any
auditor looks. Force-audit mode does not stop this: it only blocks *new*
audited operations once the buffer is genuinely full; it does not restrict
who can call `SetLogIndex` to make room.

**Where this tool actually helps, by design rather than accident:** hash-chain
verification (`verify_chain`, see [Polling behavior](polling-behavior.md#hash-chain))
is a real detector for exactly this. Each entry's digest chains from the
previous one. If an attacker's entry gets acknowledged and skipped before this
collector ever sees it, the next entry the collector *does* see won't chain
from the digest the collector's cursor last persisted — it'll chain from the
erased entry's digest instead, which the collector never recorded. That
surfaces as `chain_status: mismatch` on the very next entry. It can't recover
what was erased, but it can prove something was.

Mitigations, given the device itself won't stop this:

- **Poll frequently.** The vulnerability window is the gap between the
  malicious operation and this collector's next poll. Shrinking
  `poll_interval_secs` shrinks that window, though it can't close it to zero
  — a single `SetLogIndex` call is fast.
- **Minimize how many keys exist on the device at all**, and treat every one
  of them as capable of erasing evidence of its own misuse, not just the ones
  with obviously dangerous capabilities like key management. The
  `get-log-entries`-only auditor key isn't special in this regard — this
  applies to any key on the device.
- **Alert hard on any `chain_status: mismatch`.** Given the above, it isn't
  just "a chain didn't verify" — it may be the only evidence you get that an
  entry was hidden. The sample Wazuh rules (`wazuh/rules/`) already set this
  at a high severity level.

This is a device firmware/design property, not something fixable in this
tool — there is no capability to strip from a key to prevent it, since the
command isn't gated by one.

## Trust levels of `device_info_source`

`device_info_source = "session"` (the default) gets `device_serial`,
`device_version`, and the log-buffer figures from inside the authenticated
session, R-MAC'd under the SCP03 session keys and provably fresh — but costs
one audited `device_info` entry per poll (see
[Polling behavior](polling-behavior.md)).

`device_info_source = "connector"` gets the same figures from the
unauthenticated `GetDeviceInfo` call outside any session — free of audit-log
cost, and it unlocks `skip_poll_when_unchanged`, but it is plaintext HTTP with
no HSM authentication behind it. Concretely, with `connector`:

- `device_serial`, `device_version`, and `log_store_*` become forgeable by
  anything on the network path between the collector and the connector.
  `device_serial` is one of the two fields used for dedupe, and the "device
  serial changed" warning keys off it. Every event carries
  `device_info_source` so downstream consumers can see which events are
  backed by a MAC and which aren't.
- A network attacker who *freezes* `log_store_used` suppresses collection:
  the fast path keeps deciding there is nothing to fetch, the buffer fills,
  and either the HSM starts failing audited operations (force-audit on) or
  silently overwrites entries (force-audit off). `force_full_poll_every`
  bounds that window — the default polls in full at least every 10 cycles no
  matter what the probe says. Setting it to `0` removes the ceiling and is
  not recommended.
- `unlogged_boot_events` / `unlogged_auth_events` are only visible through
  `get-log-entries`. An audit *gap* does not move `log_store_used` (the point
  is that those events could not be recorded), so a gap is reported on the
  next full poll rather than immediately — delayed by at most
  `force_full_poll_every` intervals.

`check` reports both sources when it can reach the device, and fails if the
unauthenticated serial disagrees with the session's — a useful one-shot
sanity check that nothing on the network path is lying to the fast path.

## Unauthenticated `GetDeviceInfo` as a metadata channel

`GetDeviceInfo` is a metadata channel to anyone who can reach the connector's
port, and one the device does not log. It discloses firmware version, serial,
and log buffer fill — the last of which, under force-audit, tells an
attacker when the device is about to start refusing audited operations. That
is an argument for keeping connector ports reachable only from the collector,
not against using the call.

## What the connector protocol does and doesn't protect

The connector protocol is plain HTTP, but the session inside it is
authenticated and encrypted end-to-end with the HSM, so a hostile network can
observe metadata and drop traffic but cannot forge or read log contents.
That guarantee does not extend to anything fetched with
`device_info_source = "connector"` (see above) — that path is plaintext by
design.
