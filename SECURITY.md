# Security Policy

## Supported versions

Specht is pre-1.0. Only the latest release gets security fixes. Until the first
release is tagged, that means the `main` branch.

| Version | Supported |
| --- | --- |
| Latest release | Yes |
| Older releases | No. Upgrade to the latest. |
| `main` | Yes, as the development line |

Releases are listed on the [releases page](https://github.com/minh-tg/specht/releases).
Upgrade notes and database migration behavior are in [deploy/README.md](deploy/README.md).

## Reporting a vulnerability

Do not open a public issue for a vulnerability that has not been fixed. Report it
through GitHub: on the repository's **Security** tab, choose **Report a
vulnerability**. That opens a private advisory that only the maintainers can read.

Please include:

- The affected release or commit, and any deployment settings that matter.
- Steps to reproduce, or a minimal proof of concept.
- What you expected and what happened.
- Any prerequisites for the attack, and the impact as you see it.

## What to expect

Specht is maintained on a best-effort basis. These are targets, not a service
level agreement:

- An acknowledgement within 5 working days.
- An initial assessment, with a severity and a plan, within 10 working days.
- A fix released as soon as it is ready, sooner for severe issues. The advisory
  names the fixed version and credits you, unless you prefer to stay anonymous.

Please keep the details private until a fixed release is available, or until 90
days have passed with no fix, whichever comes first.

## Scope

In scope: the Specht server, the `specht` and `specht-adapter` commands, report
parsing, authentication and authorization, the container images and release
artifacts, the deployment files in `deploy/`, and the CI workflows.

Out of scope: vulnerabilities in a scanner whose output Specht reads, or in a
dependency. Report those upstream as well, and tell us if Specht needs a change
to stay safe.

## Known limits

- **Email ownership is not verified.** Specht sends no email, so it cannot check
  that a person controls the address they sign up with. On an instance where
  anyone can register, someone can create an account with an address they do
  not own. Registration is closed by default; keep it closed and bring people in
  with invite links, or sign in through your identity provider. Admins are listed
  by address in `ADMIN_EMAILS`, so register an address before listing it.
- **Single instance.** The documented deployment is one server and one
  PostgreSQL database. Running several server replicas is not yet supported:
  background jobs and rate limits are per process.
- **Recovering a locked-out admin needs host access.** `specht reset-password`
  and `specht grant-admin` act on the database directly, so whoever can run them
  already controls the instance. See the recovery section of the deploy guide.

## Hardening

The [deploy guide](deploy/README.md) covers TLS, trusted proxies, database
transport security, rate limits and backups. Release images and the checksum
file of the binary archives are signed with keyless Sigstore signing; the guide
shows how to verify an image, and each release lists the commands for the
archives.
