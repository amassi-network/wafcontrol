# WAF alert ingestion

## Purpose

WAFControl ingests ModSecurity events, stores actionable rule hits, and emits one normalized syslog message per transaction and rule to MapAttack.

## Sources

For Apache, the collector combines rather than selects between:

- every discovered serial ModSecurity audit log;
- every discovered concurrent audit directory;
- the global Apache error log;
- error logs declared by enabled virtual hosts;
- access logs declared by enabled virtual hosts for URI correlation.

The audit representation is processed first because it contains the complete source and destination tuple. Error logs are then used as a fallback for transactions absent from the audit log.

## Filtering

WAFControl stores primary CRS and custom-rule hits, including protocol enforcement and scanner detection.

Only these non-primary events are suppressed:

- CRS 949: inbound anomaly summary;
- CRS 959: outbound anomaly summary;
- CRS 980: correlation report;
- the internal message `WAFControl_deployment_probe`.

Do not reintroduce a fixed allow-list of attack families. New CRS families and managed custom rules must remain visible by default.

## Deduplication

The preferred key is `transaction_id + rule_id`. If a transaction identifier is unavailable, a five-minute signature fallback is used. Within one ingestion run, audit blocks are ordered ahead of error-log blocks so the most complete record is stored.

## Transport reliability

Production sends each normalized event directly to the dedicated
`/run/wafcontrol-rsyslog/syslog.sock` Unix datagram input. Rsyslog creates that socket,
enables local flow control, disables input rate limiting and routes the input to
the MapAttack forwarding ruleset.

Do not replace this path with the process-wide `syslog(3)` socket for normal
operation. That fallback can traverse the asynchronous journald forwarding path
and lose records during bursts. The application retains it only as a degraded
fallback when the dedicated socket is unavailable.

Keep repeated-message reduction disabled. Separate ModSecurity transactions can
produce identical normalized messages and must not be collapsed. The remote TCP
action uses a disk-assisted linked-list queue with infinite retries and saves its
queue on shutdown.

Validate the transport after every deployment:

```bash
test -S /run/wafcontrol-rsyslog/syslog.sock
rsyslogd -N1
journalctl -u rsyslog --since "10 minutes ago" --no-pager
```

## Runtime counters

Each Apache or Nginx Celery task reports:

- discovered audit and error log counts;
- audit and error block counts;
- raw rule hits;
- suppressed summary hits;
- duplicates;
- invalid source addresses;
- skipped requests;
- created attacks;
- ingestion or syslog errors.

Inspect recent results with:

```bash
journalctl -u wafcontrol-celery-worker --since "10 minutes ago" --no-pager \
  | grep "WAF ingestion"
```

A healthy repeat cycle normally reports `created=0 errors=0` when no new attack occurred.

## Backfill procedure

Stop Celery beat and worker, deploy and test the collector, then call `update_waf_attacks_apache()` once from the Django shell. Existing attacks are retained and skipped by the deduplication key. Restart worker and beat only after a second manual call reports `created=0`.

Always compare:

1. the WAFControl `Attack` row count;
2. the sender rsyslog queue and errors;
3. the receiver file for the source host;
4. the MapAttack ingestion count.

Never delete the parser checkpoint or attack table as a routine backfill mechanism.

Compare events as a multiset of normalized payloads, not only as a total count.
Repeated but legitimate alerts can otherwise hide a missing event.

## Known coverage boundary

The ISPConfig administration vhost on TCP/8080 explicitly uses `SecRuleEngine DetectionOnly` and is part of the ModSecurity alert stream. The WAFControl administration vhost on TCP/7000 intentionally keeps `SecRuleEngine Off` and must remain covered by its IP allow-list, firewall logging and authentication monitoring. Recheck the ISPConfig directive after every ISPConfig upgrade because that package may replace its generated vhost.
