# Operational notes

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
  `command_category!=audit command_category!=session`. See
  [Polling behavior](polling-behavior.md#self-generated-log-entries) for the
  counts and how to reduce them. There is no `close_session`: the crate
  offers no way to close one, so sessions are left to the device's inactivity
  timeout.
- **Keep `state_dir` on durable storage.** Losing it costs the chain anchor and
  the `sequence` continuity (a `unverified` entry and a sequence restart), not
  correctness of new events.
- Devices are polled sequentially in one thread; the workload is a handful of
  small requests per device per interval.
- **Any authenticated key can consume the audit log, not just the auditor's.**
  See [Security model](security.md) for what that means and how
  `chain_status` helps detect it.

## Tests

```
cargo test
```

Covers the cursor/dedup logic including 16-bit wraparound, hash-chain
verification and tamper detection, reboot detection and tick anchoring, code and
result name mapping, entry wire-format re-serialization, state file round-trip,
and secret resolution. The device-facing calls are the untested part; use
`check` and `once --dry-run` against real hardware.
