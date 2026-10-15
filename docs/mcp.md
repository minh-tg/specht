# Use Specht from an AI assistant (MCP)

`specht-mcp` lets an AI assistant read your findings, check the gate for a pull
request, and preview fixes, over the [Model Context Protocol](https://modelcontextprotocol.io).
It talks to your Specht server with an API key and speaks MCP on standard input
and output, so any MCP client can run it.

It is read-only until you say otherwise. The tools that change state are off by
default (see [Safety](#safety)).

## Install

Download `specht-mcp_<version>_<os>_<arch>` from the
[release page](https://github.com/minh-tg/specht/releases) (`.tar.gz`, or `.zip`
on Windows) and put the `specht-mcp` binary on your `PATH`. Check the download
against `SHA256SUMS`, and verify that file with `cosign verify-blob` as the
release notes describe. `specht-mcp -version` prints the version.

## Configure

`specht-mcp` reads three environment variables:

| Variable | Meaning |
|---|---|
| `API_KEY` | A project API key, or a session token. Required. |
| `API_URL` | Your Specht server. Defaults to `http://localhost:8080`. |
| `MCP_ALLOW_MUTATIONS` | Set to `true` to also offer the tools that change state. Anything but `true` or `false` is an error. |

A project API key (they start with `vuln_`) is enough for the project tools. The
admin, team and watcher tools need a session token, which you get by signing in
(`POST /api/v1/auth/login`); the bridge offers them only when it is given one.

With Claude Code:

```bash
claude mcp add specht \
  -e API_URL=https://specht.example.com \
  -e API_KEY=vuln_... \
  -- specht-mcp
```

With Claude Desktop, add this to its MCP configuration:

```json
{
  "mcpServers": {
    "specht": {
      "command": "/usr/local/bin/specht-mcp",
      "env": {
        "API_URL": "https://specht.example.com",
        "API_KEY": "vuln_..."
      }
    }
  }
}
```

## Safety

Scanner output can contain text an attacker wrote, such as a package description
or a commit message, and an assistant reads that text. A prompt hidden in it could
try to make the assistant suppress findings. So the tools that change state are not
offered unless you set `MCP_ALLOW_MUTATIONS=true`, and even then they act with the
role of the key you gave, so give the bridge the weakest key that does the job.

## Tools

Every credential can use these:

| Tool | What it does |
|---|---|
| `findings_list` | List findings for a project, filtered by severity or status |
| `findings_get` | Show one finding |
| `gate_check` | Check whether a project's gate passes, or only the findings one report introduced |
| `pr_preview` | Preview the pull-request check for a commit |
| `patch_preview` | Preview the safe patch for a finding |
| `notify_preview` | Preview the issue or message Specht would send for a finding |
| `policy_effective` | Show a project's resolved policy and where each value comes from |
| `project_teams` | List the teams linked to a project |
| `waivers_list` | List a project's waivers |
| `waivers_get` | Show one waiver |
| `waiver_events` | Show a waiver's history |

These need a session token, because their routes refuse API keys:

| Tool | What it does |
|---|---|
| `admin_status` | Platform observability snapshot |
| `admin_retention_preview` | Count the settled reports a purge would delete |
| `teams_list` | List all teams |
| `watcher_status` | Check the CVE watcher daemon's health |

These change state and appear only with `MCP_ALLOW_MUTATIONS=true`:

| Tool | What it does |
|---|---|
| `reachability_set` | Record whether a finding is reachable |
| `waivers_create` | Create an approved waiver for specific findings (project manager or admin) |
| `waivers_toggle` | Turn a waiver on or off |

## Troubleshooting

- `API_KEY environment variable is required`: the assistant started the bridge
  without the variable. Set it in the client's configuration, not your shell.
- A tool is missing: the session tools need a session token, and the state-changing
  tools need `MCP_ALLOW_MUTATIONS=true`.
- `403` from a tool: the key's role does not allow it. Creating a waiver, for
  example, needs a project manager or admin.
