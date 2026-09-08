# yubihsm-auditor

Collects the audit log from one or more YubiHSM 2 devices over HTTP
(`yubihsm-connector`), transforms each entry into a flat JSON event, and ships it
to wherever you do detection: syslog (Wazuh, rsyslog, syslog-ng, or any other
syslog receiver), Splunk HTTP Event Collector, Elastic/OpenSearch, a JSON-lines
file, or stdout.

The point is accountability: every audited device operation becomes an event
carrying the authentication key that opened the session, the object the
operation touched, the result code, and an estimated wall-clock time, so device
activity can be reconciled against the logs of the applications that talk to the
HSM. Anything the device recorded that no application claims is unaccounted key
usage.

## Getting started

1. **Prepare the device** — create an auditor key. See
   [Device setup](docs/device-setup.md).
2. **Build and run:**

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

   | Command         | Effect                                                                   |
   | --------------- | ------------------------------------------------------------------------ |
   | `run`           | Poll every device every `poll_interval_secs` until Ctrl-C.                |
   | `once`          | Poll every device once; non-zero exit if any device failed.               |
   | `check`         | Probe unauthenticated, authenticate, print device info, log fill, policy, cursor. |
   | `sample-events` | Push synthetic events through the configured sink (validates the destination end-to-end). |
   | `init-config`   | Print a commented sample configuration.                                   |

   Global flags: `--config <path>`, `--dry-run`, `--log-level <level>`.
   Diagnostics go to stderr, so the `stdout` sink stays machine-readable.
   `--dry-run` reads and emits events but never calls `set-log-index` and
   never writes the local cursor, so it is safe to point at a device another
   collector owns.

3. **Configure it** — settings reference and every output type
   (`stdout`/`file`/`syslog`/`hec`). See [Configuration](docs/configuration.md).
4. **Run it continuously.** See
   [Running as a systemd service](docs/deployment.md).
5. **Wire it into your SIEM.** See [SIEM integrations](docs/siem-integrations.md).

## Documentation

- [Device setup](docs/device-setup.md) — auditor key capabilities, audit
  policy options
- [Configuration](docs/configuration.md) — settings reference, output types
  (stdout, file, syslog/CEF, Splunk HEC)
- [Event schema and delivery guarantees](docs/event-schema.md)
- [Polling behavior, timestamps, and hash chain](docs/polling-behavior.md)
- [Security model](docs/security.md) — audit log integrity, trust levels of
  `device_info_source`, what the fast path can and can't protect against
- [Running as a systemd service](docs/deployment.md)
- [SIEM integrations](docs/siem-integrations.md) — Wazuh, Elastic/OpenSearch,
  generic syslog/CEF, Splunk
- [Correlating with application logs](docs/splunk-queries.md) — sample SPL
- [Operational notes](docs/operations.md)

## Tests

```
cargo test
```

Covers the cursor/dedup logic including 16-bit wraparound, hash-chain
verification and tamper detection, reboot detection and tick anchoring, code and
result name mapping, entry wire-format re-serialization, state file round-trip,
and secret resolution. The device-facing calls are the untested part; use
`check` and `once --dry-run` against real hardware. See
[Operational notes](docs/operations.md) for more.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in this project shall be dual licensed as above,
without any additional terms or conditions.
