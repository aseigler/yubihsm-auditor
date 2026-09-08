# Correlating with application logs

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

See [Security model](security.md) for why `chain_status=="mismatch"` deserves
a higher priority than "verification failed" alone would suggest.

Collector liveness: `device_status` arrives once per device per poll — including
polls that skipped the session, which carry `poll_skipped=true` — so alert on its
absence:

```spl
index=hsm_audit sourcetype="yubihsm:audit" event_type=device_status
| stats latest(_time) AS last_seen BY device_name
| eval age_secs = now() - last_seen
| where age_secs > 300
```
