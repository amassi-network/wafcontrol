# Production inventory — ISPConfig 46.28.168.248

Validated on 2026-08-28. This inventory contains no passwords, private keys or database dumps.

## Scope

- Host: `ispconfig2023.w3tel.net` (`46.28.168.248`)
- Web server: Apache 2.4 managed by ISPConfig
- WAF engine: ModSecurity 2.9.7
- Rules: OWASP CRS 4.29.0, pinned
- WAF mode: `DetectionOnly`
- Dashboard: `https://ispconfig2023.w3tel.net:7000/`
- Dashboard IPv4 allow-list: `2.136.9.164/32`
- MapAttack receiver: `46.28.168.76:514/TCP`
- Observation window: 2026-08-28 through 2026-09-11

## Deployed revision

The initial source archive was built from commit `e0cef01ad5632f6fe31519608d6ce965c10b020a`.
The final deployment revision is recorded in `/opt/WafControl/.deployed-revision` after the Apache deployment changes are committed.
Never deploy an unpinned branch head.

## Data path

```text
Apache -> ModSecurity/CRS -> protected ISPConfig vhost
                    |
                    +-> /var/log/apache2/modsec_audit.log
                        -> WAFControl Apache parser (10 s)
                        -> PostgreSQL
                        -> local5/wafcontrol
                        -> rsyslog TCP persistent queue
                        -> 46.28.168.76:514 (MapAttack)
```

WAFControl, PostgreSQL, Redis and MapAttack are not in the HTTP request path.
Their failure must not interrupt Apache.

## Important paths

- Application: `/opt/WafControl`
- Protected environment: `/opt/WafControl/.env` (`0600`)
- Operator credentials: `/root/.wafcontrol_credentials` (`0600`)
- ModSecurity base: `/etc/modsecurity/modsecurity.conf`
- CRS: `/etc/modsecurity/crs/coreruleset-4.29.0`
- WAFControl BEFORE policy: `/etc/modsecurity/wafcontrol/REQUEST-890-WAFCONTROL-BEFORE.conf`
- WAFControl AFTER policy: `/etc/modsecurity/wafcontrol/RESPONSE-990-WAFCONTROL-AFTER.conf`
- Apache include owner: `/etc/apache2/mods-available/security2.conf`
- Audit log: `/var/log/apache2/modsec_audit.log`
- Dashboard vhost: `/etc/apache2/sites-available/wafcontrol-admin.conf`
- Dashboard listener: `/etc/apache2/conf-available/wafcontrol-listen.conf`
- Firewall policy: `/etc/nftables.d/wafcontrol-admin.nft`
- MapAttack forwarding: `/etc/rsyslog.d/60-wafcontrol-mapattack.conf`
- Dedicated alert socket: `/run/wafcontrol-rsyslog/syslog.sock`
- Backups: `/var/backups/wafcontrol`

## Effective include order

1. `/etc/modsecurity/modsecurity.conf`
2. WAFControl BEFORE policy
3. CRS `crs-setup.conf`
4. CRS rules
5. WAFControl AFTER policy

Do not edit CRS vendor files. Keep exclusions in the WAFControl-owned BEFORE/AFTER files.

## Services

- `apache2.service`
- `postgresql.service`
- `redis-server.service`
- `rsyslog.service`
- `wafcontrol.service`
- `wafcontrol-celery-worker.service`
- `wafcontrol-celery-beat.service`
- `wafcontrol-firewall.service`
- `wafcontrol-backup.timer`

## Security decisions

- The dashboard vhost has `SecRuleEngine Off` to avoid a management lockout.
- Apache applies `Require ip 2.136.9.164`.
- nftables drops all other IPv4 sources and all IPv6 traffic to TCP/7000.
- TLS uses the existing valid `*.w3tel.net` certificate managed for ISPConfig.
- Django forces HTTPS and sends HSTS for this origin.
- HSTS `includeSubDomains` and preload stay disabled because the certificate domain is shared by unrelated services.
- Audit parts are `ABFHZ`; raw audit records stay local and only normalized alerts are sent to MapAttack.

## Alert transport

WAFControl emits one RFC3164-compatible `local5` event per newly persisted CRS hit
to `/run/wafcontrol-rsyslog/syslog.sock`. Rsyslog owns this flow-controlled input, disables
input rate limiting and repeated-message reduction, then forwards over TCP using a
disk-assisted queue. The normal system logger remains a degraded fallback only.
Normal detection-to-send latency is 0–10 seconds plus processing and network delay.

The legacy Fail2ban `syslogger.py` action remains limited to SSH, mail and FTP bans.
It is not the ModSecurity event path and must not be labelled as a WAF alert in MapAttack.
The disabled default `apache-modsecurity` jail was not enabled.

The collector merges the global audit log with all discovered virtual-host error logs.
Primary rules such as CRS 913 and 920 are retained; only CRS summary/correlation
families 949, 959 and 980 and the internal deployment probe are suppressed.
Operational counters and the safe backfill procedure are documented in
`docs/operations/ALERT_INGESTION.md`.

## CRS catalog and active-version detection

- The catalog is refreshed from stable OWASP Core Rule Set GitHub releases.
- Apache detection reads the effective includes in `security2.conf`, with the legacy `crs-setup.conf` symlink retained as a fallback.
- Active CRS is `4.29.0` at `/etc/modsecurity/crs/coreruleset-4.29.0`.
- A catalog refresh only updates WAFControl metadata; it does not switch the active CRS release.

## Validated acceptance evidence

- Django migrations: successful.
- Django tests: 78/78 passed.
- `apache2ctl configtest`: `Syntax OK`.
- Four reference HTTPS vhosts returned HTTP 200 before and after activation.
- Allowed source `2.136.9.164` reached the dashboard with HTTP 200.
- A local unauthorized source was dropped by nftables (`HTTP 000`).
- A DetectionOnly XSS probe produced CRS rules 941100, 941110, 941160 and 941390.
- WAFControl stored the true source/destination IP addresses and ports, host and method.
- MapAttack received the four events over TCP.
- An exhaustive payload multiset comparison matched all 271 WAFControl database
  alerts to receiver records after backfill; dedicated-socket burst tests delivered
  5/5 and 20/20 messages.
- The temporary deployment test rule was removed.

Two old Apache workers logged `SIGSEGV` while the module was loaded for the first time.
The master process did not restart, all sites stayed available, and the count remained unchanged through subsequent graceful reloads and probes.
Monitor this counter during the observation window; disable `security2` and restore the snapshot if crashes recur.

## Backup and rollback

Pre-change configuration backup: `/root/pre-wafcontrol-20260828T140414Z`.
First verified application backup checksum file: `/var/backups/wafcontrol/wafcontrol-20260828T141907Z.sha256`.

Fast WAF rollback, without removing WAFControl data:

```bash
a2dismod security2
apache2ctl configtest
apache2ctl -k graceful
```

Full dashboard shutdown:

```bash
systemctl disable --now wafcontrol wafcontrol-celery-worker wafcontrol-celery-beat
systemctl disable --now wafcontrol-firewall
a2dissite wafcontrol-admin
a2disconf wafcontrol-listen
apache2ctl configtest
apache2ctl -k graceful
```

The VM snapshot remains the authoritative full-machine rollback point.
