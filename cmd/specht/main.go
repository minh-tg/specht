package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/xMinhx/specht/internal/client"
	"github.com/xMinhx/specht/internal/config"
	"github.com/xMinhx/specht/internal/db"
	"github.com/xMinhx/specht/internal/port"
	"github.com/xMinhx/specht/internal/repo"
	"github.com/xMinhx/specht/internal/watcher"
)

type cmd int

const (
	cmdHelp cmd = iota
	cmdProjectsList
	cmdProjectsGet
	cmdFindingsList
	cmdFindingsGet
	cmdFindingsVerify
	cmdFindingsReachability
	cmdGateCheck
	cmdPRPreview
	cmdPatchPreview
	cmdNotifyPreview
	cmdAdminStatus
	cmdAdminRetentionPreview
	cmdAdminRetentionPurge
	cmdPolicyTemplates
	cmdPolicyCreate
	cmdPolicyUpdate
	cmdPolicyDelete
	cmdPolicyApply
	cmdPolicyOverrides
	cmdPolicyEffective
	cmdTeamsList
	cmdTeamsCreate
	cmdTeamsDelete
	cmdTeamMembers
	cmdTeamAdd
	cmdTeamRemove
	cmdProjectTeams
	cmdProjectLink
	cmdProjectUnlink
	cmdStats
	cmdStatsAging
	cmdWatcherBackfill
	cmdWatcherStatus
)

// Gate check exit codes: the CI contract. 0 means the gate passed, 1 means
// the severity threshold was breached, 2 means a usage or runtime error.
const (
	exitGatePass     = 0
	exitGateBreached = 1
	exitGateError    = 2
)

// CLI flag names and shared CLI output formats.
const (
	flagProject       = "--project"
	flagFormat        = "--format"
	flagFinding       = "--finding"
	flagSeverity      = "--severity"
	errInvalidFormat  = "invalid --format %q: want human or json"
	rowFormat3        = "%s\t%s\t%s\n"
	stderrErrorFormat = "error: %v\n"
)

type command struct {
	cmd            cmd
	project        string
	slug           string
	findingID      string
	severity       string
	format         string
	status         string
	state          string
	evidence       string
	limit          int
	since          string
	dryRun         bool
	reportID       string
	introducedOnly bool
	commit         string
	provider       string
	channel        string
	target         string
	linked         bool
	days           int
	name           string
	description    string
	definition     string
	templateID     string
	template       string
	overrides      string
	teamID         string
	userID         string
	teamRole       string
}

func parseArgs(args []string) (command, error) {
	if len(args) < 2 {
		return command{cmd: cmdHelp}, nil
	}

	rest := args[1:]

	if len(rest) == 0 {
		return command{cmd: cmdHelp}, nil
	}

	switch rest[0] {
	case "projects":
		if len(rest) < 2 {
			return command{}, fmt.Errorf("missing subcommand for projects")
		}
		switch rest[1] {
		case "list":
			return command{cmd: cmdProjectsList}, nil
		case "get":
			if len(rest) < 3 {
				return command{}, fmt.Errorf("missing project slug")
			}
			return command{cmd: cmdProjectsGet, slug: rest[2]}, nil
		default:
			return command{}, fmt.Errorf("unknown projects subcommand: %s", rest[1])
		}

	case "findings":
		if len(rest) < 2 {
			return command{}, fmt.Errorf("missing subcommand for findings")
		}
		switch rest[1] {
		case "list":
			c := command{cmd: cmdFindingsList}
			for i := 2; i < len(rest); i++ {
				switch {
				case rest[i] == flagProject && i+1 < len(rest):
					c.project = rest[i+1]
					i++
				case rest[i] == flagSeverity && i+1 < len(rest):
					c.severity = rest[i+1]
					i++
				case rest[i] == "--status" && i+1 < len(rest):
					c.status = rest[i+1]
					i++
				case rest[i] == "--limit" && i+1 < len(rest):
					n, err := strconv.Atoi(rest[i+1])
					if err != nil || n < 0 || n > math.MaxInt32 {
						return command{}, fmt.Errorf("invalid --limit %q: want 0 to %d", rest[i+1], math.MaxInt32)
					}
					c.limit = n
					i++
				}
			}
			if c.project == "" {
				return command{}, fmt.Errorf("--project is required for findings list")
			}
			return c, nil
		case "get":
			if len(rest) < 3 {
				return command{}, fmt.Errorf("missing finding ID")
			}
			return command{cmd: cmdFindingsGet, findingID: rest[2]}, nil
		case "verify":
			if len(rest) < 3 {
				return command{}, fmt.Errorf("missing finding ID")
			}
			return command{cmd: cmdFindingsVerify, findingID: rest[2]}, nil
		case "reachability":
			c := command{cmd: cmdFindingsReachability}
			for i := 2; i < len(rest); i++ {
				switch {
				case rest[i] == flagFinding && i+1 < len(rest):
					c.findingID = rest[i+1]
					i++
				case rest[i] == "--state" && i+1 < len(rest):
					c.state = rest[i+1]
					i++
				case rest[i] == "--evidence" && i+1 < len(rest):
					c.evidence = rest[i+1]
					i++
				}
			}
			if c.findingID == "" {
				return command{}, fmt.Errorf("--finding is required for findings reachability")
			}
			return c, nil
		default:
			return command{}, fmt.Errorf("unknown findings subcommand: %s", rest[1])
		}

	case "stats":
		if len(rest) < 2 {
			return command{}, fmt.Errorf("missing subcommand for stats")
		}
		if rest[1] == "show" && len(rest) >= 3 {
			return command{cmd: cmdStats, slug: rest[2]}, nil
		}
		if rest[1] == "aging" && len(rest) >= 3 {
			return command{cmd: cmdStatsAging, slug: rest[2]}, nil
		}
		return command{}, fmt.Errorf("unknown stats subcommand: %s", rest[1])

	case "gate":
		if len(rest) < 2 {
			return command{}, fmt.Errorf("missing subcommand for gate")
		}
		switch rest[1] {
		case "check":
			c := command{cmd: cmdGateCheck}
			for i := 2; i < len(rest); i++ {
				switch {
				case rest[i] == flagProject && i+1 < len(rest):
					c.project = rest[i+1]
					i++
				case rest[i] == flagSeverity && i+1 < len(rest):
					c.severity = rest[i+1]
					i++
				case rest[i] == flagFormat && i+1 < len(rest):
					c.format = rest[i+1]
					i++
				case rest[i] == "--introduced-only":
					c.introducedOnly = true
				case rest[i] == "--report-id" && i+1 < len(rest):
					c.reportID = rest[i+1]
					i++
				}
			}
			if c.project == "" {
				return command{}, fmt.Errorf("--project is required for gate check")
			}
			if c.introducedOnly && c.reportID == "" {
				return command{}, fmt.Errorf("--report-id is required with --introduced-only")
			}
			if c.format == "" {
				c.format = "human"
			}
			if c.format != "human" && c.format != "json" {
				return command{}, fmt.Errorf(errInvalidFormat, c.format)
			}
			return c, nil
		default:
			return command{}, fmt.Errorf("unknown gate subcommand: %s", rest[1])
		}

	case "pr":
		if len(rest) < 2 {
			return command{}, fmt.Errorf("missing subcommand for pr")
		}
		switch rest[1] {
		case "preview":
			c := command{cmd: cmdPRPreview}
			for i := 2; i < len(rest); i++ {
				switch {
				case rest[i] == flagProject && i+1 < len(rest):
					c.project = rest[i+1]
					i++
				case rest[i] == "--commit" && i+1 < len(rest):
					c.commit = rest[i+1]
					i++
				case rest[i] == "--provider" && i+1 < len(rest):
					c.provider = rest[i+1]
					i++
				case rest[i] == "--report-id" && i+1 < len(rest):
					c.reportID = rest[i+1]
					i++
				case rest[i] == flagSeverity && i+1 < len(rest):
					c.severity = rest[i+1]
					i++
				case rest[i] == flagFormat && i+1 < len(rest):
					c.format = rest[i+1]
					i++
				}
			}
			if c.project == "" {
				return command{}, fmt.Errorf("--project is required for pr preview")
			}
			if c.commit == "" {
				return command{}, fmt.Errorf("--commit is required for pr preview")
			}
			if c.format == "" {
				c.format = "human"
			}
			if c.format != "human" && c.format != "json" {
				return command{}, fmt.Errorf(errInvalidFormat, c.format)
			}
			return c, nil
		default:
			return command{}, fmt.Errorf("unknown pr subcommand: %s", rest[1])
		}

	case "patch":
		if len(rest) < 2 {
			return command{}, fmt.Errorf("missing subcommand for patch")
		}
		switch rest[1] {
		case "preview":
			c := command{cmd: cmdPatchPreview}
			for i := 2; i < len(rest); i++ {
				switch {
				case rest[i] == flagFinding && i+1 < len(rest):
					c.findingID = rest[i+1]
					i++
				case rest[i] == flagFormat && i+1 < len(rest):
					c.format = rest[i+1]
					i++
				}
			}
			if c.findingID == "" {
				return command{}, fmt.Errorf("--finding is required for patch preview")
			}
			if c.format == "" {
				c.format = "human"
			}
			if c.format != "human" && c.format != "json" {
				return command{}, fmt.Errorf(errInvalidFormat, c.format)
			}
			return c, nil
		default:
			return command{}, fmt.Errorf("unknown patch subcommand: %s", rest[1])
		}

	case "notify":
		if len(rest) < 2 {
			return command{}, fmt.Errorf("missing subcommand for notify")
		}
		switch rest[1] {
		case "preview":
			c := command{cmd: cmdNotifyPreview}
			for i := 2; i < len(rest); i++ {
				switch {
				case rest[i] == flagFinding && i+1 < len(rest):
					c.findingID = rest[i+1]
					i++
				case rest[i] == "--channel" && i+1 < len(rest):
					c.channel = rest[i+1]
					i++
				case rest[i] == "--target" && i+1 < len(rest):
					c.target = rest[i+1]
					i++
				case rest[i] == "--linked":
					c.linked = true
				case rest[i] == flagFormat && i+1 < len(rest):
					c.format = rest[i+1]
					i++
				}
			}
			if c.findingID == "" {
				return command{}, fmt.Errorf("--finding is required for notify preview")
			}
			if c.channel == "" {
				return command{}, fmt.Errorf("--channel is required for notify preview")
			}
			if c.target == "" {
				return command{}, fmt.Errorf("--target is required for notify preview")
			}
			if c.format == "" {
				c.format = "human"
			}
			if c.format != "human" && c.format != "json" {
				return command{}, fmt.Errorf(errInvalidFormat, c.format)
			}
			return c, nil
		default:
			return command{}, fmt.Errorf("unknown notify subcommand: %s", rest[1])
		}

	case "admin":
		if len(rest) < 2 {
			return command{}, fmt.Errorf("missing subcommand for admin")
		}
		switch rest[1] {
		case "status":
			c := command{cmd: cmdAdminStatus}
			for i := 2; i < len(rest); i++ {
				switch {
				case rest[i] == flagFormat && i+1 < len(rest):
					c.format = rest[i+1]
					i++
				}
			}
			if c.format == "" {
				c.format = "human"
			}
			if c.format != "human" && c.format != "json" {
				return command{}, fmt.Errorf(errInvalidFormat, c.format)
			}
			return c, nil
		case "retention":
			if len(rest) < 3 {
				return command{}, fmt.Errorf("missing subcommand for admin retention")
			}
			switch rest[2] {
			case "preview", "purge":
				c := command{cmd: cmdAdminRetentionPreview}
				if rest[2] == "purge" {
					c.cmd = cmdAdminRetentionPurge
				}
				for i := 3; i < len(rest); i++ {
					switch {
					case rest[i] == "--days" && i+1 < len(rest):
						n, err := strconv.Atoi(rest[i+1])
						if err != nil {
							return command{}, fmt.Errorf("invalid --days %q: want a positive integer", rest[i+1])
						}
						c.days = n
						i++
					case rest[i] == flagFormat && i+1 < len(rest):
						c.format = rest[i+1]
						i++
					}
				}
				if c.days <= 0 {
					return command{}, fmt.Errorf("--days is required for admin retention (positive integer)")
				}
				if c.format == "" {
					c.format = "human"
				}
				if c.format != "human" && c.format != "json" {
					return command{}, fmt.Errorf(errInvalidFormat, c.format)
				}
				return c, nil
			default:
				return command{}, fmt.Errorf("unknown admin retention subcommand: %s", rest[2])
			}
		default:
			return command{}, fmt.Errorf("unknown admin subcommand: %s", rest[1])
		}

	case "policy":
		if len(rest) < 2 {
			return command{}, fmt.Errorf("missing subcommand for policy")
		}
		switch rest[1] {
		case "templates":
			return command{cmd: cmdPolicyTemplates}, nil
		case "create", "update":
			c := command{cmd: cmdPolicyCreate}
			if rest[1] == "update" {
				c.cmd = cmdPolicyUpdate
			}
			for i := 2; i < len(rest); i++ {
				switch {
				case rest[i] == "--id" && i+1 < len(rest):
					c.templateID = rest[i+1]
					i++
				case rest[i] == "--name" && i+1 < len(rest):
					c.name = rest[i+1]
					i++
				case rest[i] == "--description" && i+1 < len(rest):
					c.description = rest[i+1]
					i++
				case rest[i] == "--definition" && i+1 < len(rest):
					c.definition = rest[i+1]
					i++
				}
			}
			if rest[1] == "update" && c.templateID == "" {
				return command{}, fmt.Errorf("--id is required for policy update")
			}
			if c.name == "" {
				return command{}, fmt.Errorf("--name is required")
			}
			return c, nil
		case "delete":
			c := command{cmd: cmdPolicyDelete}
			for i := 2; i < len(rest); i++ {
				switch {
				case rest[i] == "--id" && i+1 < len(rest):
					c.templateID = rest[i+1]
					i++
				}
			}
			if c.templateID == "" {
				return command{}, fmt.Errorf("--id is required for policy delete")
			}
			return c, nil
		case "apply":
			c := command{cmd: cmdPolicyApply}
			for i := 2; i < len(rest); i++ {
				switch {
				case rest[i] == flagProject && i+1 < len(rest):
					c.project = rest[i+1]
					i++
				case rest[i] == "--template" && i+1 < len(rest):
					c.template = rest[i+1]
					i++
				}
			}
			if c.project == "" {
				return command{}, fmt.Errorf("--project is required for policy apply")
			}
			return c, nil
		case "overrides":
			c := command{cmd: cmdPolicyOverrides}
			for i := 2; i < len(rest); i++ {
				switch {
				case rest[i] == flagProject && i+1 < len(rest):
					c.project = rest[i+1]
					i++
				case rest[i] == "--set" && i+1 < len(rest):
					c.overrides = rest[i+1]
					i++
				}
			}
			if c.project == "" {
				return command{}, fmt.Errorf("--project is required for policy overrides")
			}
			return c, nil
		case "effective":
			c := command{cmd: cmdPolicyEffective}
			for i := 2; i < len(rest); i++ {
				switch {
				case rest[i] == flagProject && i+1 < len(rest):
					c.project = rest[i+1]
					i++
				case rest[i] == flagFormat && i+1 < len(rest):
					c.format = rest[i+1]
					i++
				}
			}
			if c.project == "" {
				return command{}, fmt.Errorf("--project is required for policy effective")
			}
			if c.format == "" {
				c.format = "human"
			}
			if c.format != "human" && c.format != "json" {
				return command{}, fmt.Errorf(errInvalidFormat, c.format)
			}
			return c, nil
		default:
			return command{}, fmt.Errorf("unknown policy subcommand: %s", rest[1])
		}

	case "teams":
		if len(rest) < 2 {
			return command{}, fmt.Errorf("missing subcommand for teams")
		}
		switch rest[1] {
		case "list":
			return command{cmd: cmdTeamsList}, nil
		case "create":
			c := command{cmd: cmdTeamsCreate}
			for i := 2; i < len(rest); i++ {
				switch {
				case rest[i] == "--name" && i+1 < len(rest):
					c.name = rest[i+1]
					i++
				case rest[i] == "--description" && i+1 < len(rest):
					c.description = rest[i+1]
					i++
				}
			}
			if c.name == "" {
				return command{}, fmt.Errorf("--name is required for teams create")
			}
			return c, nil
		case "delete":
			c := command{cmd: cmdTeamsDelete}
			for i := 2; i < len(rest); i++ {
				switch {
				case rest[i] == "--id" && i+1 < len(rest):
					c.teamID = rest[i+1]
					i++
				}
			}
			if c.teamID == "" {
				return command{}, fmt.Errorf("--id is required for teams delete")
			}
			return c, nil
		case "members":
			c := command{cmd: cmdTeamMembers}
			for i := 2; i < len(rest); i++ {
				switch {
				case rest[i] == "--id" && i+1 < len(rest):
					c.teamID = rest[i+1]
					i++
				}
			}
			if c.teamID == "" {
				return command{}, fmt.Errorf("--id is required for teams members")
			}
			return c, nil
		case "add":
			c := command{cmd: cmdTeamAdd}
			for i := 2; i < len(rest); i++ {
				switch {
				case rest[i] == "--id" && i+1 < len(rest):
					c.teamID = rest[i+1]
					i++
				case rest[i] == "--user" && i+1 < len(rest):
					c.userID = rest[i+1]
					i++
				case rest[i] == "--role" && i+1 < len(rest):
					c.teamRole = rest[i+1]
					i++
				}
			}
			if c.teamID == "" || c.userID == "" || c.teamRole == "" {
				return command{}, fmt.Errorf("--id, --user, and --role are required for teams add")
			}
			return c, nil
		case "remove":
			c := command{cmd: cmdTeamRemove}
			for i := 2; i < len(rest); i++ {
				switch {
				case rest[i] == "--id" && i+1 < len(rest):
					c.teamID = rest[i+1]
					i++
				case rest[i] == "--user" && i+1 < len(rest):
					c.userID = rest[i+1]
					i++
				}
			}
			if c.teamID == "" || c.userID == "" {
				return command{}, fmt.Errorf("--id and --user are required for teams remove")
			}
			return c, nil
		default:
			return command{}, fmt.Errorf("unknown teams subcommand: %s", rest[1])
		}

	case "project-teams":
		if len(rest) < 2 {
			return command{}, fmt.Errorf("missing subcommand for project-teams")
		}
		switch rest[1] {
		case "list":
			c := command{cmd: cmdProjectTeams}
			for i := 2; i < len(rest); i++ {
				switch {
				case rest[i] == flagProject && i+1 < len(rest):
					c.project = rest[i+1]
					i++
				}
			}
			if c.project == "" {
				return command{}, fmt.Errorf("--project is required for project-teams list")
			}
			return c, nil
		case "link":
			c := command{cmd: cmdProjectLink}
			for i := 2; i < len(rest); i++ {
				switch {
				case rest[i] == flagProject && i+1 < len(rest):
					c.project = rest[i+1]
					i++
				case rest[i] == "--team" && i+1 < len(rest):
					c.teamID = rest[i+1]
					i++
				case rest[i] == "--role" && i+1 < len(rest):
					c.teamRole = rest[i+1]
					i++
				}
			}
			if c.project == "" || c.teamID == "" || c.teamRole == "" {
				return command{}, fmt.Errorf("--project, --team, and --role are required for project-teams link")
			}
			return c, nil
		case "unlink":
			c := command{cmd: cmdProjectUnlink}
			for i := 2; i < len(rest); i++ {
				switch {
				case rest[i] == flagProject && i+1 < len(rest):
					c.project = rest[i+1]
					i++
				case rest[i] == "--team" && i+1 < len(rest):
					c.teamID = rest[i+1]
					i++
				}
			}
			if c.project == "" || c.teamID == "" {
				return command{}, fmt.Errorf("--project and --team are required for project-teams unlink")
			}
			return c, nil
		default:
			return command{}, fmt.Errorf("unknown project-teams subcommand: %s", rest[1])
		}

	case "help":
		return command{cmd: cmdHelp}, nil

	case "watcher":
		if len(rest) < 2 {
			return command{}, fmt.Errorf("missing subcommand for watcher")
		}
		switch rest[1] {
		case "backfill":
			c := command{cmd: cmdWatcherBackfill}
			for i := 2; i < len(rest); i++ {
				switch {
				case rest[i] == "--since" && i+1 < len(rest):
					c.since = rest[i+1]
					i++
				case rest[i] == "--dry-run":
					c.dryRun = true
				}
			}
			return c, nil
		case "status":
			return command{cmd: cmdWatcherStatus}, nil
		default:
			return command{}, fmt.Errorf("unknown watcher subcommand: %s", rest[1])
		}

	default:
		return command{}, fmt.Errorf("unknown command: %s", rest[0])
	}
}

// formatGateStatus renders a gate evaluation for CLI output. "human" is the
// concise log-friendly summary; "json" is the machine-readable form for CI
// automation (struct field order, so output is deterministic).
func formatGateStatus(gs *client.GateStatus, format string) (string, error) {
	switch format {
	case "", "human":
		return formatGateHuman(gs), nil
	case "json":
		buf, err := json.Marshal(gs)
		if err != nil {
			return "", err
		}
		return string(buf), nil
	default:
		return "", fmt.Errorf(errInvalidFormat, format)
	}
}

func formatGateHuman(gs *client.GateStatus) string {
	var b strings.Builder
	if gs.ThresholdBreached {
		fmt.Fprintf(&b, "gate FAILED: %d blocking finding(s)\n", gs.BlockingCount)
		for _, id := range gs.BlockedBy {
			reach := "unknown"
			if r, ok := gs.BlockedByReachability[id]; ok && r != "" {
				reach = r
			}
			fmt.Fprintf(&b, "  blocked by: %s (reachability: %s)\n", id, reach)
		}
	} else {
		b.WriteString("gate PASSED: no blocking findings\n")
	}
	if gs.WaivedCount > 0 {
		fmt.Fprintf(&b, "  waived: %d finding(s) excluded by active waivers\n", gs.WaivedCount)
	}
	return strings.TrimSuffix(b.String(), "\n")
}

// gateExitCode maps a gate evaluation to the CI exit-code contract.
func gateExitCode(breached bool) int {
	if breached {
		return exitGateBreached
	}
	return exitGatePass
}

// reopenedMark flags regressed findings in the aging table.
func reopenedMark(reopened bool) string {
	if reopened {
		return " (reopened)"
	}
	return ""
}

func run(cl *client.Client, cmd command) error {
	switch cmd.cmd {
	case cmdHelp:
		printHelp()
		return nil

	case cmdProjectsList:
		projects, err := cl.ListProjects()
		if err != nil {
			return err
		}
		if len(projects) == 0 {
			fmt.Println("No projects found.")
			return nil
		}
		for _, p := range projects {
			desc := ""
			if p.Description != nil {
				desc = *p.Description
			}
			fmt.Printf(rowFormat3, p.Slug, p.Name, desc)
		}
		return nil

	case cmdProjectsGet:
		p, err := cl.GetProject(cmd.slug)
		if err != nil {
			return err
		}
		desc := ""
		if p.Description != nil {
			desc = *p.Description
		}
		fmt.Printf("Slug:       %s\nName:       %s\nDescription: %s\n", p.Slug, p.Name, desc)
		return nil

	case cmdFindingsList:
		var severities []string
		if cmd.severity != "" {
			severities = strings.Split(cmd.severity, ",")
		}
		var statuses []string
		if cmd.status != "" {
			statuses = strings.Split(cmd.status, ",")
		}
		findings, err := cl.ListFindings(cmd.project, severities, statuses, int32(cmd.limit), 0)
		if err != nil {
			return err
		}
		if len(findings) == 0 {
			fmt.Println("No findings found.")
			return nil
		}
		for _, f := range findings {
			score := ""
			if f.CurrentScore != nil {
				score = fmt.Sprintf("%.1f", *f.CurrentScore)
			}
			fmt.Printf("%s\t%s\t%s\t%s\t%s\t%s\n", f.ID, f.CurrentSeverity, f.CurrentTitle, f.AnalysisState, f.GateEffect, score)
		}
		return nil

	case cmdFindingsGet:
		f, err := cl.GetFinding(cmd.findingID)
		if err != nil {
			return err
		}
		score := ""
		if f.CurrentScore != nil {
			score = fmt.Sprintf("%.1f", *f.CurrentScore)
		}
		fmt.Printf("ID:           %s\nTitle:        %s\nSeverity:     %s\nScore:        %s\nState:        %s\nAnalysis:     %s\nGate Effect:  %s\nFingerprint:  %s\nKind:         %s\n", f.ID, f.CurrentTitle, f.CurrentSeverity, score, f.State, f.AnalysisState, f.GateEffect, f.Fingerprint, f.FindingKind)
		if f.IntroducedCommitSha != nil && *f.IntroducedCommitSha != "" {
			fmt.Printf("Introduced:   %s\n", *f.IntroducedCommitSha)
		} else {
			fmt.Printf("Introduced:   unattributed\n")
		}
		return nil

	case cmdFindingsVerify:
		res, err := cl.VerifyFinding(cmd.findingID)
		if err != nil {
			return err
		}
		fmt.Printf("finding %s: %s\n", res.FindingID, res.Outcome)
		if res.ReportID != nil {
			fmt.Printf("report: %s\n", *res.ReportID)
		}
		fmt.Printf("detail: %s\n", res.Detail)
		return nil
	case cmdFindingsReachability:
		if cmd.state != "" {
			assess, err := cl.UpsertReachability(cmd.findingID, cmd.state, cmd.evidence)
			if err != nil {
				return err
			}
			fmt.Printf("reachability set: finding=%s state=%s evidence=%q\n", assess.FindingID, assess.State, assess.Evidence)
			return nil
		}
		history, err := cl.ListReachability(cmd.findingID)
		if err != nil {
			return err
		}
		if len(history) == 0 {
			fmt.Println("no reachability assessments for finding")
			return nil
		}
		for _, a := range history {
			fmt.Printf("%s\t%s\t%s\t%s\n", a.CreatedAt, a.State, a.AssessedBy, a.Evidence)
		}
		return nil

	case cmdGateCheck:
		var gs *client.GateStatus
		var err error
		if cmd.introducedOnly {
			gs, err = cl.GetIntroducedGateStatus(cmd.project, cmd.severity, cmd.reportID)
		} else {
			gs, err = cl.GetGateStatus(cmd.project, cmd.severity)
		}
		if err != nil {
			return err
		}
		out, err := formatGateStatus(gs, cmd.format)
		if err != nil {
			return err
		}
		fmt.Println(out)
		if gs.ThresholdBreached {
			os.Exit(exitGateBreached)
		}
		return nil

	case cmdPRPreview:
		preview, err := cl.PreviewPRCheck(cmd.project, cmd.commit, cmd.provider, cmd.reportID, cmd.severity)
		if err != nil {
			return err
		}
		if cmd.format == "json" {
			raw, err := json.MarshalIndent(preview, "", "  ")
			if err != nil {
				return err
			}
			fmt.Println(string(raw))
			return nil
		}
		fmt.Printf("check %s: %s\n%s\n", preview.Conclusion, preview.Title, preview.Summary)
		for _, a := range preview.Annotations {
			fmt.Printf("  %s:%d %s\n", a.File, a.StartLine, a.Title)
		}
		return nil

	case cmdPatchPreview:
		outcome, err := cl.PreviewPatch(cmd.findingID)
		if err != nil {
			return err
		}
		if cmd.format == "json" {
			raw, err := json.MarshalIndent(outcome, "", "  ")
			if err != nil {
				return err
			}
			fmt.Println(string(raw))
			return nil
		}
		if !outcome.Supported || outcome.Proposal == nil {
			fmt.Printf("no patch: %s\n", outcome.Reason)
			return nil
		}
		p := outcome.Proposal
		fmt.Printf("patch %s (%s, confidence %s)\n%s\n", p.ID, p.Class, p.Confidence, p.Rationale)
		for _, e := range p.Edits {
			fmt.Printf("  %s %s %s %s -> %s\n", e.Operation, e.File, e.Package, e.FromVersion, e.ToVersion)
		}
		fmt.Printf("verify: %s\n", p.VerifyBy)
		return nil

	case cmdNotifyPreview:
		notification, err := cl.PreviewNotification(cmd.findingID, cmd.channel, cmd.target, cmd.linked)
		if err != nil {
			return err
		}
		if cmd.format == "json" {
			raw, err := json.MarshalIndent(notification, "", "  ")
			if err != nil {
				return err
			}
			fmt.Println(string(raw))
			return nil
		}
		if !notification.Supported || notification.Plan == nil {
			fmt.Printf("no notification: %s\n", notification.Reason)
			return nil
		}
		plan := notification.Plan
		fmt.Printf("notify %s (%s -> %s): %s\n%s\n", plan.ID, plan.Channel, plan.Target, plan.Title, plan.Body)
		fmt.Printf("dedupe: %s\n", plan.DedupeKey)
		return nil

	case cmdAdminStatus:
		status, err := cl.GetAdminStatus()
		if err != nil {
			return err
		}
		if cmd.format == "json" {
			raw, err := json.MarshalIndent(status, "", "  ")
			if err != nil {
				return err
			}
			fmt.Println(string(raw))
			return nil
		}
		fmt.Printf(
			"projects=%d users=%d open_findings=%d reports=%d\n",
			status.Projects, status.Users, status.OpenFindings, status.Reports,
		)
		return nil

	case cmdAdminRetentionPreview:
		preview, err := cl.PreviewRetention(cmd.days)
		if err != nil {
			return err
		}
		if cmd.format == "json" {
			raw, err := json.MarshalIndent(preview, "", "  ")
			if err != nil {
				return err
			}
			fmt.Println(string(raw))
			return nil
		}
		fmt.Printf("%d settled report(s) older than %d day(s) would be deleted\n", preview.StaleReports, preview.OlderThanDays)
		return nil

	case cmdAdminRetentionPurge:
		result, err := cl.PurgeRetention(cmd.days)
		if err != nil {
			return err
		}
		if cmd.format == "json" {
			raw, err := json.MarshalIndent(result, "", "  ")
			if err != nil {
				return err
			}
			fmt.Println(string(raw))
			return nil
		}
		fmt.Printf("deleted %d settled report(s) older than %d day(s)\n", result.DeletedReports, result.OlderThanDays)
		return nil

	case cmdPolicyTemplates:
		templates, err := cl.ListPolicyTemplates()
		if err != nil {
			return err
		}
		if len(templates) == 0 {
			fmt.Println("No policy templates.")
			return nil
		}
		for _, t := range templates {
			fmt.Printf("%s\t%s\tv%d\n", t.Name, t.ID, t.Version)
		}
		return nil

	case cmdPolicyCreate, cmdPolicyUpdate:
		var definition map[string]string
		if cmd.definition != "" {
			if err := json.Unmarshal([]byte(cmd.definition), &definition); err != nil {
				return fmt.Errorf("invalid --definition %q: want a JSON object", cmd.definition)
			}
		}
		if cmd.cmd == cmdPolicyCreate {
			tmpl, err := cl.CreatePolicyTemplate(cmd.name, cmd.description, definition)
			if err != nil {
				return err
			}
			fmt.Printf("template %s (%s)\n", tmpl.Name, tmpl.ID)
			return nil
		}
		tmpl, err := cl.UpdatePolicyTemplate(cmd.templateID, cmd.name, cmd.description, definition)
		if err != nil {
			return err
		}
		fmt.Printf("template %s v%d\n", tmpl.Name, tmpl.Version)
		return nil

	case cmdPolicyDelete:
		if err := cl.DeletePolicyTemplate(cmd.templateID); err != nil {
			return err
		}
		fmt.Println("template deleted")
		return nil

	case cmdPolicyApply:
		eff, err := cl.SetProjectPolicy(cmd.project, cmd.template)
		if err != nil {
			return err
		}
		fmt.Printf("policy: floor=%s (%s) watcher=%s (%s)\n", eff.SeverityFloor, eff.SeveritySource, eff.WatcherGate, eff.WatcherSource)
		return nil

	case cmdPolicyOverrides:
		var overrides map[string]string
		if cmd.overrides != "" {
			if err := json.Unmarshal([]byte(cmd.overrides), &overrides); err != nil {
				return fmt.Errorf("invalid --set %q: want a JSON object", cmd.overrides)
			}
		}
		eff, err := cl.SetProjectPolicyOverrides(cmd.project, overrides)
		if err != nil {
			return err
		}
		fmt.Printf("policy: floor=%s (%s) watcher=%s (%s)\n", eff.SeverityFloor, eff.SeveritySource, eff.WatcherGate, eff.WatcherSource)
		return nil

	case cmdPolicyEffective:
		eff, err := cl.GetEffectivePolicy(cmd.project)
		if err != nil {
			return err
		}
		if cmd.format == "json" {
			raw, err := json.MarshalIndent(eff, "", "  ")
			if err != nil {
				return err
			}
			fmt.Println(string(raw))
			return nil
		}
		template := "(none)"
		if eff.TemplateName != nil {
			template = fmt.Sprintf("%s v%d", *eff.TemplateName, eff.TemplateVersion)
		}
		fmt.Printf("template: %s\nfloor=%s (%s) watcher=%s (%s)\n", template, eff.SeverityFloor, eff.SeveritySource, eff.WatcherGate, eff.WatcherSource)
		return nil

	case cmdTeamsList:
		teams, err := cl.ListTeams()
		if err != nil {
			return err
		}
		if len(teams) == 0 {
			fmt.Println("No teams.")
			return nil
		}
		for _, t := range teams {
			fmt.Printf(rowFormat3, t.Name, t.ID, t.Description)
		}
		return nil

	case cmdTeamsCreate:
		team, err := cl.CreateTeam(cmd.name, cmd.description)
		if err != nil {
			return err
		}
		fmt.Printf("team %s (%s)\n", team.Name, team.ID)
		return nil

	case cmdTeamsDelete:
		if err := cl.DeleteTeam(cmd.teamID); err != nil {
			return err
		}
		fmt.Println("team deleted")
		return nil

	case cmdTeamMembers:
		members, err := cl.ListTeamMembers(cmd.teamID)
		if err != nil {
			return err
		}
		if len(members) == 0 {
			fmt.Println("No members.")
			return nil
		}
		for _, m := range members {
			fmt.Printf(rowFormat3, m.UserEmail, m.UserID, m.Role)
		}
		return nil

	case cmdTeamAdd:
		member, err := cl.AddTeamMember(cmd.teamID, cmd.userID, cmd.teamRole)
		if err != nil {
			return err
		}
		fmt.Printf("member %s (%s)\n", member.UserID, member.Role)
		return nil

	case cmdTeamRemove:
		if err := cl.RemoveTeamMember(cmd.teamID, cmd.userID); err != nil {
			return err
		}
		fmt.Println("member removed")
		return nil

	case cmdProjectTeams:
		links, err := cl.ListProjectTeams(cmd.project)
		if err != nil {
			return err
		}
		if len(links) == 0 {
			fmt.Println("No linked teams.")
			return nil
		}
		for _, l := range links {
			fmt.Printf(rowFormat3, l.TeamName, l.TeamID, l.Role)
		}
		return nil

	case cmdProjectLink:
		link, err := cl.LinkProjectTeam(cmd.project, cmd.teamID, cmd.teamRole)
		if err != nil {
			return err
		}
		fmt.Printf("linked %s as %s\n", link.TeamName, link.Role)
		return nil

	case cmdProjectUnlink:
		if err := cl.UnlinkProjectTeam(cmd.project, cmd.teamID); err != nil {
			return err
		}
		fmt.Println("team unlinked")
		return nil

	case cmdStats:
		stats, err := cl.GetProjectStats(cmd.slug)
		if err != nil {
			return err
		}
		fmt.Printf("Project Stats for %s:\n", cmd.slug)
		fmt.Printf("  Total Findings:  %d\n", stats.TotalFindings)
		fmt.Printf("  Blocking:        %d\n", stats.BlockingCount)
		fmt.Printf("  Active Waivers:  %d\n", stats.WaiverCount)
		fmt.Printf("  Reports:         %d\n", stats.ReportCount)
		fmt.Println("  By Severity:")
		for _, s := range stats.BySeverity {
			fmt.Printf("    %s: %d total, %d blocking\n", s.Severity, s.Count, s.BlockingCount)
		}
		if stats.LatestReport != nil {
			fmt.Printf("  Latest Scan:     %s by %s (%s)\n", stats.LatestReport.ID, stats.LatestReport.ToolName, stats.LatestReport.Status)
		}
		return nil

	case cmdStatsAging:
		aging, err := cl.GetAging(cmd.slug)
		if err != nil {
			return err
		}
		fmt.Printf("Aging for %s (SLA: critical 7d, high 30d, medium 90d, low 180d):\n", cmd.slug)
		for _, b := range aging.Buckets {
			fmt.Printf("  %-6s %4d finding(s), %d overdue\n", b.Bucket, b.Count, b.Overdue)
		}
		fmt.Printf("  reopened ever: %d\n", aging.Reopened)
		if len(aging.Overdue) > 0 {
			fmt.Println("  Oldest overdue:")
			for _, o := range aging.Overdue {
				fmt.Printf("    %s [%s] %dd (SLA %dd, due %s)%s\n",
					o.Title, o.Severity, o.AgeDays, o.SLADays,
					o.DueDate.Format("2006-01-02"), reopenedMark(o.Reopened))
			}
		}
		return nil

	case cmdWatcherStatus:
		ws, err := cl.GetWatcherStatus()
		if err != nil {
			return err
		}
		if ws.LastSuccessfulPollAt != "" {
			fmt.Printf("Last Successful Poll:  %s\n", ws.LastSuccessfulPollAt)
		} else {
			fmt.Println("Last Successful Poll:  never (cold start)")
		}
		if ws.LastPollAttemptAt != "" {
			fmt.Printf("Last Poll Attempt:     %s\n", ws.LastPollAttemptAt)
		}
		if ws.LastError != "" {
			fmt.Printf("Last Error:            %s\n", ws.LastError)
		}
		fmt.Printf("Consecutive Failures:  %d\n", ws.ConsecutiveFailures)
		switch {
		case ws.Healthy:
			fmt.Println("Status:                healthy")
		case ws.Stale:
			fmt.Printf("Status:                STALE (no successful poll within %s)\n", ws.StalenessWindow)
		default:
			fmt.Println("Status:                FAILING")
		}
		return nil
	}

	return nil
}

func printHelp() {
	fmt.Print(`Usage: specht <command> [subcommand] [flags]

Commands:
  projects list                           List all projects
  projects get <slug>                     Show project details
  findings list --project <slug>          List findings
    [--severity high,critical]             Filter by severity
    [--status open]                        Filter by status
    [--limit N]                            Limit results
  findings get <id>                       Show finding details
  findings verify <id>                    Verify fix against latest rescan
  findings reachability --finding <id>    List reachability assessments (omit --state)
  findings reachability --finding <id> --state <s> [--evidence <e>]
                                          Set reachability (reachable|not_reachable|unknown|not_applicable)
  gate check --project <slug>             Check project gate status
    [--severity critical]                  Severity threshold
    [--format human|json]                  Output format (default human)
                                           Exit codes: 0 pass, 1 threshold breached, 2 error
  pr preview --project <slug> --commit <sha>
    [--provider github] [--report-id <id>] Preview pull-request check (dry-run; publishes nothing)
    [--severity critical] [--format human|json]
  patch preview --finding <id>            Preview safe patch (dry-run; applies nothing)
    [--format human|json]
  notify preview --finding <id> --channel <issue|message> --target <id>
    [--linked] [--format human|json]  Preview tracker/messaging action (dry-run; sends nothing)
  admin status [--format human|json]  Platform observability snapshot (admin only)
  admin retention preview --days <n>  Count settled reports a purge would delete
  admin retention purge --days <n>    Delete settled reports older than the window
  policy templates                    List policy baselines
  policy create --name <n> [--description <d>] [--definition <json>]
  policy update --id <id> --name <n> [--description <d>] [--definition <json>]
  policy delete --id <id>
  policy apply --project <slug> [--template <name>]  Link/unlink a baseline
  policy overrides --project <slug> [--set <json>]   Replace per-key overrides
  policy effective --project <slug>   Show resolved policy with provenance
  teams list | create --name <n> | delete --id <id>
  teams members --id <id> | add --id <id> --user <id> --role <admin|member>
  teams remove --id <id> --user <id>
  project-teams list --project <slug> | link --project <slug> --team <id> --role <r>
  project-teams unlink --project <slug> --team <id>
  stats show <slug>                       Show project statistics
  stats aging <slug>                      Show aging buckets, SLA overdue, reopened
  watcher backfill [--since <ISO8601>]    Run one CVE watcher poll
  watcher status                          Show watcher health (last poll, failures)
    [--dry-run]                           Report only; write nothing
  help                                     Show this help

Environment:
  API_URL   Specht API base URL (default "http://localhost:8080")
  API_KEY   API key for authentication (required for all commands)
  DATABASE_URL   Postgres connection (required for watcher backfill)
`)
}

func main() {
	cmd, err := parseArgs(os.Args)
	if err != nil {
		fmt.Fprintf(os.Stderr, stderrErrorFormat, err)
		os.Exit(2)
	}

	// The watcher backfill talks to the database and OSV directly; it does
	// not use the API client, so it is dispatched before the API_KEY gate.
	if cmd.cmd == cmdWatcherBackfill {
		if err := runWatcherBackfill(cmd); err != nil {
			fmt.Fprintf(os.Stderr, stderrErrorFormat, err)
			os.Exit(2)
		}
		return
	}

	apiURL := os.Getenv("API_URL")
	if apiURL == "" {
		apiURL = "http://localhost:8080"
	}

	token := os.Getenv("API_KEY")
	if token == "" && cmd.cmd != cmdHelp {
		fmt.Fprintln(os.Stderr, "error: API_KEY environment variable is required")
		os.Exit(2)
	}

	cl := client.New(apiURL, client.WithToken(token))

	if err := run(cl, cmd); err != nil {
		fmt.Fprintf(os.Stderr, stderrErrorFormat, err)
		os.Exit(2)
	}
}

// runWatcherBackfill runs one CVE watcher poll against the database and OSV,
// using the same PollDeps wiring as the server daemon (cmd/server/main.go).
// It is a one-shot PollOnce: findings for previously unseen advisories are
// persisted (or reported, with --dry-run) and the watermark advances only on
// a fully successful poll.
func runWatcherBackfill(cmd command) error {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		return errors.New("DATABASE_URL is required for watcher backfill")
	}
	ctx := context.Background()
	pool, err := db.ConnectPool(ctx, dbURL)
	if err != nil {
		return fmt.Errorf("connect db: %w", err)
	}
	defer pool.Close()

	stores := repo.NewPortStores(pool)

	var since time.Time
	if cmd.since != "" {
		since, err = time.Parse(time.RFC3339, cmd.since)
		if err != nil {
			return fmt.Errorf("--since must be an ISO8601 timestamp: %w", err)
		}
	}

	var store watcher.PollStore
	if cmd.dryRun {
		store = discardStore{}
	} else {
		store = watcher.NewPollStore(stores)
	}

	projects, err := stores.Projects.List(ctx)
	if err != nil {
		return fmt.Errorf("list projects: %w", err)
	}
	projectIDs := make([]string, len(projects))
	for i, p := range projects {
		projectIDs[i] = p.ID
	}

	inventoryTTL := config.DefaultInventoryTTL
	if v := os.Getenv("INVENTORY_TTL"); v != "" {
		inventoryTTL, err = time.ParseDuration(v)
		if err != nil {
			return fmt.Errorf("INVENTORY_TTL is invalid: %w", err)
		}
	}
	watcherCfg, err := config.WatcherConfig()
	if err != nil {
		return err
	}

	deps := watcher.PollDeps{
		Client: watcher.NewHTTPClient(watcher.HTTPClientConfig{
			Endpoint: watcherCfg.OSVEndpoint,
			CacheTTL: 0, // one-shot: no cross-call caching
		}),
		Store:    store,
		Projects: projectIDs,
		Inventory: func(ctx context.Context, projectID string, since time.Duration) ([]port.InventoryPackage, error) {
			return stores.Inventory.DistinctInventory(ctx, projectID, since)
		},
		FindGap: stores.Findings.FindScaFindingIDForPurlAndCve,
		GetWatermark: func(ctx context.Context, projectID string) (time.Time, bool, error) {
			st, err := stores.Watcher.GetProjectState(ctx, projectID)
			if errors.Is(err, port.ErrNotFound) {
				return time.Time{}, false, nil
			}
			if err != nil {
				return time.Time{}, false, err
			}
			if st.LastSuccessfulPollAt == nil {
				return time.Time{}, false, nil
			}
			return *st.LastSuccessfulPollAt, true, nil
		},
		SetWatermark: func(ctx context.Context, projectID string, ts time.Time) error {
			if cmd.dryRun {
				return nil // dry-run writes nothing
			}
			return stores.Watcher.UpsertProjectState(ctx, projectID, ts)
		},
		Logger:       slog.Default(),
		InventoryTTL: inventoryTTL,
		Since:        since, // zero → full history
	}

	outcome, err := watcher.PollOnce(ctx, deps)
	if err != nil {
		return fmt.Errorf("watcher backfill: %w", err)
	}
	fmt.Printf("watcher backfill: projects=%d queried=%d created=%d skipped=%d unchanged=%d ignored=%d orphan_skips=%d\n",
		outcome.Projects, outcome.Queried, outcome.Created, outcome.Skipped, outcome.Unchanged, outcome.Ignored, outcome.OrphanSkips)
	if cmd.dryRun {
		fmt.Println("dry-run: nothing was written")
	}
	return nil
}

// discardStore is the PollStore for --dry-run backfills: it accepts every
// decision without persisting anything, so a dry run writes no findings,
// occurrences, events, or evidence.
type discardStore struct{}

func (discardStore) PersistFoundFinding(ctx context.Context, d watcher.Decision) (string, bool, error) {
	return "", true, nil
}

func (discardStore) PersistSkipEvent(ctx context.Context, suppressingID string, ev watcher.Event) error {
	return nil
}
