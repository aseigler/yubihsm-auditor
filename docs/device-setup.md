# Device setup

An authentication key configured as an auditor. Only one capability is
required:

| Capability        | Used for               |
| ----------------- | ----------------------- |
| `get-log-entries` | reading the audit log   |

`SetLogIndex` (what acknowledges entries so the device can reuse the buffer)
is not gated by a capability at all — the device accepts it from any
authenticated key regardless of what's on its capability list. There is
nothing to grant for it; `advance_log_index = true` will work with a key
that only has `get-log-entries`. See [Security model](security.md) for why
that matters beyond just "one less thing to configure."

Optional, and only if you want the extras:

| Capability                        | Enables                                                     |
| ---------------------------------- | ------------------------------------------------------------ |
| `get-option`                       | `check` reporting force-audit and per-command audit policy   |
| `list-objects`, `get-object-info`  | `enrich_objects = true` (object labels/types in events)      |

Creating an auditor key with `yubihsm-shell`, in domain 1, key ID 4:

```
yubihsm> put authkey 0 4 auditor 1 get-log-entries none <password>
```

Two device options matter:

- **Per-command audit** (`SetOption`, `command` tag) decides which commands are
  logged at all. Anything set to `off` never reaches this tool. `check` reports
  which commands are not audited.
- **Force audit** (`SetOption`, `force` tag). When on, the device refuses audited
  operations once its log buffer is full, i.e. it fails closed rather than losing
  audit records. This tool exists to keep that buffer drained; the buffer holds
  only 62 entries, so poll accordingly.
