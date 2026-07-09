package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/xMinhx/specht/internal/client"
)

type cmd int

const (
	cmdHelp cmd = iota
	cmdProjectsList
	cmdProjectsGet
	cmdFindingsList
	cmdFindingsGet
	cmdGateCheck
)

type command struct {
	cmd       cmd
	project   string
	slug      string
	findingID string
	severity  string
	status    string
	limit     int
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
				case rest[i] == "--project" && i+1 < len(rest):
					c.project = rest[i+1]
					i++
				case rest[i] == "--severity" && i+1 < len(rest):
					c.severity = rest[i+1]
					i++
				case rest[i] == "--status" && i+1 < len(rest):
					c.status = rest[i+1]
					i++
				case rest[i] == "--limit" && i+1 < len(rest):
					fmt.Sscanf(rest[i+1], "%d", &c.limit)
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
		default:
			return command{}, fmt.Errorf("unknown findings subcommand: %s", rest[1])
		}

	case "gate":
		if len(rest) < 2 {
			return command{}, fmt.Errorf("missing subcommand for gate")
		}
		switch rest[1] {
		case "check":
			c := command{cmd: cmdGateCheck}
			for i := 2; i < len(rest); i++ {
				switch {
				case rest[i] == "--project" && i+1 < len(rest):
					c.project = rest[i+1]
					i++
				case rest[i] == "--severity" && i+1 < len(rest):
					c.severity = rest[i+1]
					i++
				}
			}
			if c.project == "" {
				return command{}, fmt.Errorf("--project is required for gate check")
			}
			return c, nil
		default:
			return command{}, fmt.Errorf("unknown gate subcommand: %s", rest[1])
		}

	case "help":
		return command{cmd: cmdHelp}, nil

	default:
		return command{}, fmt.Errorf("unknown command: %s", rest[0])
	}
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
			fmt.Printf("%s\t%s\t%s\n", p.Slug, p.Name, desc)
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
		return nil

	case cmdGateCheck:
		gs, err := cl.GetGateStatus(cmd.project, cmd.severity)
		if err != nil {
			return err
		}
		if gs.ThresholdBreached {
			fmt.Printf("gate FAILED: %d blocking finding(s)\n", gs.BlockingCount)
			if len(gs.BlockedBy) > 0 {
				for _, b := range gs.BlockedBy {
					fmt.Printf("  blocked by: %s\n", b)
				}
			}
			os.Exit(1)
		}
		fmt.Println("gate PASSED: no blocking findings")
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
  gate check --project <slug>             Check project gate status
    [--severity critical]                  Severity threshold
  help                                     Show this help

Environment:
  API_URL   Specht API base URL (default "http://localhost:8080")
  API_KEY   API key for authentication (required for all commands)
`)
}

func main() {
	cmd, err := parseArgs(os.Args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(2)
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
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(2)
	}
}
