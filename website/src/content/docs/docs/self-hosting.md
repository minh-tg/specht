---
title: Self-hosting responsibilities
description: Understand the single-node deployment, secrets, retention, network access and backup requirements.
---

The documented evaluator deployment is one Go server with its embedded web UI
and a PostgreSQL 17 database. Docker Compose runs both services. Migrations run
at startup by default.

Start with the [local quickstart](../getting-started/). The defaults are for
single-instance evaluation, not an internet-facing production installation.

## Before exposing the server

Put TLS in front of the application. Set trusted proxy addresses explicitly;
do not trust arbitrary forwarding headers. Keep self-service registration closed
unless you intend to allow it. Use first-run setup or invitation links instead.

For a remote database, use verified TLS as described in the
[deployment reference](https://github.com/minh-tg/specht/blob/main/deploy/README.md).
The bundled database uses the private Compose network and does not enable TLS.

Local accounts and OIDC are supported. Use scoped API keys for CI and grant
project access according to the caller's role. Do not reuse an administrator's
password as a CI credential.

## Secrets and retention

Back up database credentials, the JWT signing key and any explicit fingerprint
key separately from public configuration. Gitleaks finding identities depend on
the fingerprint key; changing it changes which findings match across scans.

Raw report payloads are retained for 30 days by default. Expiry removes the raw
payload, not the report row, findings or summaries. A page can therefore keep its
history after the original raw evidence expires. Review retention settings
against your own policy.

## External services

The advisory watcher queries OSV when configured. Enrichment, scanners, OIDC and
notifications may contact external services according to your configuration.
Self-hosting the application does not make those services local.

## Backups and upgrades

Back up Postgres and the secrets needed to restore the installation. Test a
restore before relying on a backup. Preserve volumes when stopping an instance.

Pin released server and adapter versions together once releases are available.
Before the first release, keep both on the same source checkout. Review schema
changes and take a backup before upgrading.

The [deployment reference](https://github.com/minh-tg/specht/blob/main/deploy/README.md)
contains the configuration table, TLS examples and backup, restore and upgrade
procedures. The [security policy](https://github.com/minh-tg/specht/blob/main/SECURITY.md)
explains how to report a vulnerability privately.
