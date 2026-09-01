# Ironitia production inventory — sanitised reference

Snapshot date: **2026-08-22**
Purpose: record the known-good reference topology without storing credentials.

This is an inventory, not a generic install script. Use
[DEPLOYMENT.md](DEPLOYMENT.md) for a new site.

## Host and application

| Item | Value |
|---|---|
| Public host | `46.28.168.244` |
| OS | Ubuntu 24.04.4 LTS, kernel 6.8.0-136 |
| Application checkout | `/opt/WafControl` |
| Dashboard | `https://ironitia.com:7000/` |
| Allowed dashboard source | `2.136.9.164` |
| Production code revision | `1a2f197` |
| Protected web server | Nginx |
| ModSecurity mode | `DetectionOnly` |
| Active CRS | 4.29.0 |
| ModSecurity audit log | `/var/log/nginx/modsec_audit.log` |
| Managed policy directory | `/etc/nginx/modsec/wafcontrol` |
| Parser state | `/var/lib/wafparser/nginx` |
| MapAttack receiver | `46.28.168.76:514/TCP` |

DNS/TLS use the Ironitia public certificate under
`/etc/letsencrypt/live/ironitia.com/`. Private keys and application secrets
are intentionally omitted.

## Software reference

- Nginx 1.24.0 (Ubuntu package)
- `libnginx-mod-http-modsecurity` 1.0.3
- libmodsecurity 3.0.12 (`libmodsecurity3t64`)
- Python 3.12.3
- Django 5.2.8
- Yubico fido2 2.2.1
- Celery 5.3.0
- PostgreSQL 16.15
- Redis 7.0.15
- rsyslog 8.2312

## Services

These units are enabled and active:

- `nginx.service`
- `postgresql.service`
- `redis-server.service`
- `rsyslog.service`
- `wafcontrol.service`
- `wafcontrol-celery-worker.service`
- `wafcontrol-celery-beat.service`
- `wafcontrol-backup.timer`

Gunicorn uses three workers, a 120-second timeout and
`/run/wafcontrol/gunicorn.sock`. The application and Celery units currently
run as `root:www-data`. This permits current privileged management operations
but remains a documented hardening debt.

## File ownership and modes observed

| Path | Ownership/mode |
|---|---|
| `/opt/WafControl` | `root:root 0755` |
| virtual environment and static files | root-owned |
| `/etc/nginx/modsec` | root-owned |
| managed policy directory | `root:root 0750` |
| managed policy files | `root:root 0640` |
| audit log | `www-data:adm 0640` |
| parser state directory | `root:www-data 0755` |
| rsyslog spool | `syslog:adm 0700` |

## Effective ModSecurity design

The intended include order is:

1. `/etc/nginx/modsec/modsecurity.conf`
2. `/etc/nginx/modsec/ironitia-before-crs.conf`
3. WAFControl BEFORE policy
4. CRS 4.29.0 setup
5. CRS 4.29.0 rule files
6. WAFControl AFTER policy

The 2026-08-22 audit found that the CRS updater could move the AFTER policy before CRS. The deterministic renderer and regression test were deployed in `de77e73`. At 13:39 UTC, production was reordered successfully, `nginx -t` passed, Nginx reloaded and the intended order above was captured.

Effective important directives:

- request body inspection enabled;
- response body inspection disabled;
- relevant-only serial audit log;
- audit sections `ABFHZ`;
- 404 responses excluded from relevant status selection;
- cache/data directory `/var/cache/modsecurity`;
- initial engine mode `DetectionOnly`.

The Ironitia-specific before-CRS file disables inspection for `/api/health`
and `/matomo`. These are site decisions and must not be copied to another
deployment without application-owner review.

## Dashboard access restriction

Nginx listens on `46.28.168.244:7000` with TLS and applies:

```nginx
allow 2.136.9.164;
deny all;
```

At inventory time there was no separate host-firewall rule for port 7000.
Adding defense-in-depth firewall filtering remains recommended.

## Event and syslog path

The Nginx parser runs every 10 seconds. For each newly persisted ModSecurity
transaction it stores the source/destination address and port, classifies the
CRS family and emits one `local5` syslog event with ident `wafcontrol`.

Rsyslog forwards only that program to `46.28.168.76:514` using TCP,
traditional RFC3164 framing, infinite retry and a named 256 MiB disk-assisted
queue. A live established TCP session was observed.

Deployment history worth preserving:

- initial parser activation imported 1,193 alerts still present in the 8 MiB
  audit-log tail;
- subsequent parser cycles created zero duplicate rows;
- three validation events used reserved sources `192.0.2.1`,
  `192.0.2.2` and `192.0.2.3`;
- MapAttack parsing of source/destination addresses and ports was verified.

## Backups and operational gaps

Pre-syslog deployment backups created on the host:

- `/root/wafcontrol-pre-syslog-20260822.dump`
- `/root/wafcontrol-code-pre-syslog-20260822.tar.gz`

No automated PostgreSQL backup was present at the start of the inventory. The daily backup service and timer were installed on 2026-08-22. The first run created PostgreSQL, code and deployment-configuration archives under `/var/backups/wafcontrol`; all checksums passed. The next required step is encrypted off-host replication and a restore rehearsal.

Other known gaps:

- Django `check --deploy` reports W004 and W008 because HSTS and HTTPS redirection are currently enforced at Nginx rather than in Django; the proxy controls must remain part of acceptance evidence;

- off-host backup replication and restore rehearsal remain to be implemented;
- service privilege separation is not yet complete;
- port 7000 restriction relies on Nginx only;
- Fail2ban/CrowdSec feedback is not deployed;
- site exclusions require an application-specific review and expiry process;
- log retention and off-host backup policy require explicit operational owners.

## Evidence commands

Run these after any production change and attach sanitised output:

```bash
cat /opt/WafControl/.deployed-revision
systemctl is-active nginx postgresql redis-server rsyslog \
  wafcontrol wafcontrol-celery-worker wafcontrol-celery-beat
grep '^Include ' /etc/nginx/modsec/main.conf
nginx -t
ss -lntp
ss -ntp | grep '46.28.168.76:514'
rsyslogd -N1
journalctl -u wafcontrol -u wafcontrol-celery-worker \
  -u wafcontrol-celery-beat -u rsyslog --since '-10 minutes' --no-pager
```

Never include `.env`, private keys, database passwords, session cookies or
unredacted personal data in evidence.

## WebAuthn and YubiKey

YubiKey/FIDO2 support was deployed on 2026-08-22 from code revision
`1a2f197`.

- server library: Yubico `fido2 2.2.1`;
- database migration: `wafinstaller.0007_webauthncredential`;
- relying-party ID: `ironitia.com`;
- exact allowed origin: `https://ironitia.com:7000`;
- challenge lifetime: 300 seconds;
- profile tab and password-plus-security-key login endpoints active;
- external CSRF test returned HTTP 403;
- no credential was registered at the end of deployment validation.

The operator must enrol the first physical key interactively from the
allow-listed administrator address. Keep TOTP enabled or enrol a second key
before testing recovery from loss of the primary key. See
[WEBAUTHN_YUBIKEY.md](WEBAUTHN_YUBIKEY.md).
