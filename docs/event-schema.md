# Event schema and delivery guarantees

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
