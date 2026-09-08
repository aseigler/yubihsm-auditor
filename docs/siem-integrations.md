# Getting events to your SIEM

## Wazuh

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
[Running as a systemd service](deployment.md) for getting the binary running
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
Wazuh version and existing rule IDs, not a drop-in guarantee. In particular,
check for rule ID collisions with anything else you've already installed:

```
grep -rhoE '<rule id="[0-9]+"' /var/ossec/etc/rules/*.xml \
  | grep -oE '[0-9]+' | sort -n | uniq
```

and renumber (every `id="..."`, `if_sid`, `if_matched_sid`, and `same_field`
reference) if the shipped ranges (`100300-100310` / `100330-100340`) collide
with something you already have.

## Elastic / OpenSearch

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

## Any other syslog receiver

The `syslog` output is plain RFC 5424 with a JSON body by default (see
[Configuration](configuration.md)), so rsyslog, syslog-ng, journald's syslog
listener, or a SIEM's generic syslog input all take it without extra
configuration beyond pointing at the collector and parsing JSON out of the
message. Set `format = "cef"` instead if your receiver parses CEF natively.

## Splunk

**HEC**: use the `hec` output. `host` is the device name, `sourcetype` defaults
to `yubihsm:audit`, and `time` is set from the event, so Splunk's `_time` is the
estimated operation time rather than the ingest time.

**Universal forwarder**: use the `file` output and the configs in `splunk/`
(`props.conf` for the sourcetype, `inputs.conf` for the file monitor).

Either way, `splunk/props.conf` gives you JSON field extraction, `_time` from the
`time` field, and `TRUNCATE`/line-breaking settings appropriate for JSON lines.

See [Correlating with application logs](splunk-queries.md) for sample SPL once
events are landing in Splunk.
