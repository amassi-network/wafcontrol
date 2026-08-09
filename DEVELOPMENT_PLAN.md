# WAFControl Development Plan

This plan turns the evolution roadmap into small, testable delivery increments.

## Milestone 1 — CRS lifecycle safety (completed)

- semantic CRS version comparison;
- idempotent no-change updates;
- configuration rollback on validation or reload failure;
- authentication and CSRF protection for CRS version operations;
- regression tests for the observed 4.25.1 / 4.28.0 inconsistency.

## Milestone 2 — Mutation security and audit (completed)

- remove remaining unjustified CSRF exemptions;
- require authentication and explicit HTTP methods for privileged operations;
- reject absolute paths, traversal, symlinks escaping managed directories, and unsupported file types;
- write configuration through same-directory temporary files under a deployment lock;
- validate configuration before keeping a change and restore the previous file on validation or reload failure;
- create versioned Django migrations;
- record security-sensitive mutation attempts in an append-oriented audit table registered read-only for deployments that expose Django admin;
- add unit and integration tests for authentication, CSRF, path confinement, atomic writes, rollback, and audit creation.

Exit criteria:

- no exposed mutation endpoint is exempt from CSRF;
- a user-controlled filename cannot escape the active CRS rules directory;
- a failed validator or reload leaves the previous file active;
- the initial schema and audit table can be created entirely from committed migrations;
- the complete Django test suite and system checks pass.

Verification completed on 9 August 2026: 20 Django tests, Django system
checks, migration drift detection, clean-database migrations, legacy
`--fake-initial` adoption, Python static checks, shell syntax checks, and Git
whitespace checks all pass.


## Milestone 3A — Managed exclusions and address lists (completed)

- versioned `RuleExclusion`, `AddressList`, and `AddressEntry` models;
- explicit Draft/Approved workflow for CRS exclusions;
- scopes by host, exact/prefix URI, method, variable, rule ID or rule tag;
- source, rationale, owner, start date, expiry and enabled state;
- explicit Trusted, WAF bypass, Block, and Observe semantics;
- event-to-draft assistance and historical impact count for rule IDs;
- WAFControl-owned before/after CRS rendering without vendor-file edits;
- candidate diff, configuration validation, atomic two-file deployment and rollback;
- idempotent Nginx include installer with rollback.

Verification completed on 9 August 2026: 38 Django tests, Django system checks,
clean 0002 to 0003 migration, migration drift detection, full Ruff checks on
the touched Python modules, shell syntax checks, and Git whitespace checks all
pass.

## Milestone 3B — Triage and policy revision workflow

- classify events as attack, false positive, authorised traffic, known scanner or unknown;
- extract the precise matched variable from normalized ModSecurity events;
- preview both affected and suspicious historical events;
- add immutable policy revisions and a two-person approval option;
- schedule automatic expiry and notify owners before exceptions expire;
- add edit/clone operations and regression fixtures executed against ModSecurity.

## Milestone 4 — Applications and policies

- add Application, Policy, PolicyBinding, and immutable ConfigRevision objects;
- configure Off, DetectionOnly, or On, paranoia level, and thresholds per application;
- add policy inheritance, readable overrides, and regression fixtures.

## Milestone 5 — Multi-node control plane

- introduce an unprivileged UI and a minimal privileged agent;
- add mTLS enrolment, node inventory, health, active checksum, and drift detection;
- deploy signed revisions through canary and batches with automatic rollback.

## Milestone 6 — Response and integrations

- publish versioned event and decision APIs;
- export signed, idempotent batches to MapAttack;
- integrate temporary Fail2ban/CrowdSec decisions and trusted-list synchronisation;
- add buffered webhooks, delivery status, retry, and dead-letter handling.

## Milestone 7 — Governance and advanced protection

- RBAC, approvals, append-only audit review, SSO, API tokens, CLI, and GitOps;
- rate limiting, authentication protection, bot controls, OpenAPI inventory, virtual patching, and experimental Coraza support.

