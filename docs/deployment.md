# Running as a systemd service

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
