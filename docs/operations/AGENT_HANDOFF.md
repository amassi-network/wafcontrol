# Agent handoff checklist

Use this checklist when another agent or operator deploys this stack on a new
site. The controlling document is [DEPLOYMENT.md](DEPLOYMENT.md). Do not infer
missing site values from the Ironitia inventory.

## Inputs the requester must supply

- target host and authorised SSH identity;
- reviewed repository URL plus exact tag or commit;
- dashboard DNS name and public IPv4 plus optional IPv6 bind addresses;
- dashboard administrator allow-list CIDRs;
- protected Nginx virtual hosts and upstream ownership;
- certificate/ACME method;
- MapAttack receiver address, TCP port and receiver owner;
- database name/user and a secure way to set new secrets;
- approved backup destination and retention;
- named application owners for observation and exclusion review.

If any target, credential authority, DNS ownership or protected vhost is
ambiguous, stop before mutation.

## Deterministic execution order

- [ ] Read all of `docs/operations/DEPLOYMENT.md`.
- [ ] Capture preflight evidence and a recoverable snapshot.
- [ ] Record OS/package versions and existing config owners.
- [ ] Check out an exact reviewed revision, never an unpinned branch.
- [ ] Render a fresh site bundle with
      `scripts/render_deployment_config.sh`.
- [ ] Review the rendered diff; confirm it contains no unresolved `@@...@@`
      token and no secret.
- [ ] Create a unique PostgreSQL account/database and a unique Django secret.
- [ ] Run migrations, `check --deploy`, static collection and project tests.
- [ ] Install ModSecurity in `DetectionOnly` and a pinned CRS version.
- [ ] Install site exclusions only after application-owner review.
- [ ] Prove include order: base/site/BEFORE/setup/rules/AFTER.
- [ ] Add ModSecurity to each approved protected HTTPS server block.
- [ ] Install TLS dashboard vhost and restrict TCP 7000 in Nginx and firewall.
- [ ] Install/enable Gunicorn, Celery worker, Celery beat and dependencies.
- [ ] Install the dedicated rsyslog Unix socket, TCP forwarding and persistent queue.
- [ ] Prove repeated-message reduction is disabled and burst delivery is lossless.
- [ ] Install/run/check the database and code backup timer.
- [ ] Run every acceptance test in the runbook.
- [ ] Record the exact deployed revision and sanitised evidence.
- [ ] Schedule the 7–14 day observation review before considering blocking.

## Stop conditions

Do not reload or continue if:

- `nginx -t`, Django checks, migrations or tests fail;
- the include order differs from BEFORE → CRS → AFTER;
- a template token remains unresolved;
- port 7000 is reachable from an unauthorised external source;
- the site already uses an unmanaged conflicting WAF;
- a proposed exclusion disables a broad route/site without owner approval;
- MapAttack maps the tuple into wrong fields or loses any event in a burst;
- backup creation or restore verification has not succeeded;
- secrets appear in Git, logs, rendered evidence or command history.

Preserve the previous working configuration and report the exact blocker.

## Evidence bundle to return

Return a concise deployment report containing:

- target hostname/address and deployment timestamp;
- exact Git commit and package versions;
- changed files and installed units;
- redacted effective include order;
- service state and `nginx -t` result;
- allowed-source dashboard result and denied-source result;
- one TEST-NET WAF transaction ID and database tuple;
- corresponding MapAttack receipt, parsed tuple and burst-delivery count;
- backup filename/checksum and timer next-run time;
- ModSecurity mode, CRS version and planned observation end date;
- deviations, known gaps and exact rollback point.

Do not return passwords, keys, cookies, full environment files or production
personal data.

## Site-specific artefacts that must never be copied blindly

- `.env`;
- TLS private keys;
- PostgreSQL dumps;
- `site-before-crs.conf`;
- managed policy output;
- firewall address lists;
- dashboard admin CIDR;
- Nginx application upstreams;
- parser cursor/audit-log state;
- MapAttack receiver credentials or routing.

Generate these afresh or migrate them under an explicitly approved procedure.
