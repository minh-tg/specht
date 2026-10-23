---
title: Evaluate Specht locally
description: Build Specht from source, create your first project and send a scanner report.
---

:::caution[Experimental preview]
There is no tagged release yet. APIs, database schemas and settings may change.
Use an evaluation installation and do not make Specht your only security control.
:::

## Requirements

Install Git, Docker and the Docker Compose plugin. The server has a default
3 GiB container memory limit; leave memory for Postgres and the operating system
as well. You do not need Go or Node on the host for this installation.

## Get the source

```bash
git clone https://github.com/minh-tg/specht.git
cd specht
cp deploy/.env.prod.example deploy/.env.prod
```

## Set your secrets

Open `deploy/.env.prod` in your editor. Set:

- `POSTGRES_PASSWORD` to a password you generate for this database.
- `JWT_SECRET` to at least 32 random bytes.
- `SETUP_TOKEN` to a value of your choice, at least 16 characters. Uncomment
  its line in the example file.

For example, this command generates a random value. Run it separately for each
secret and keep the values out of version control:

```bash
head -c 48 /dev/urandom | base64
```

Keep the environment file private. Do not paste it into an issue or commit it.

## Build and start

Run this from the repository root:

```bash
docker compose -f deploy/docker-compose.yml -f deploy/docker-compose.build.yml \
  --env-file deploy/.env.prod up -d --build
```

The build override is required before the first release. Without it, Compose
tries to pull an image that has not been published.

Check the database and server are ready:

```bash
curl -fsS http://localhost:8080/api/v1/ready
```

Open [localhost:8080](http://localhost:8080), enter the setup token and create the
first administrator. Create a project in the application.

## Send your first report

For a manual evaluation, run one of the [supported scanners](../scanners/),
choose **Upload report** in your project, select the matching scanner and choose
its output file. Specht reads reports; it does not run your local scanner.

Open **Findings** to inspect the results. Severity describes the finding.
**Blocks gate** identifies a finding that blocks the current gate decision.

For a commit-linked workflow, follow the project's CI setup page. Use the
[adapter and CI metadata](../ci-gates/) so the report belongs to the correct
branch, revision and scan context.

## After the evaluation

Stop the stack without deleting its named volumes:

```bash
docker compose -f deploy/docker-compose.yml -f deploy/docker-compose.build.yml \
  --env-file deploy/.env.prod down
```

The `-v` option deletes volumes and their database contents; use it only when you
intend to remove the evaluation data.

Before exposing an installation beyond localhost, read
[self-hosting](../self-hosting/) and the repository's
[deployment reference](https://github.com/minh-tg/specht/blob/main/deploy/README.md).
