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

## Known coverage boundary

The ISPConfig administration vhost and the WAFControl administration vhost intentionally use `SecRuleEngine Off`. Requests to those management interfaces are outside this ModSecurity alert stream and must be covered by access control, firewall logging and authentication monitoring.
