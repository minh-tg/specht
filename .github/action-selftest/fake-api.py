#!/usr/bin/env python3
"""Fake Specht API for the action self-test.

Answers the calls the adapter makes with a passing verdict for project
"pass" and a blocking verdict for project "blocked":

  POST /api/v1/reports                   ingest one scanner report
  GET  /api/v1/projects/<slug>/pr-check  change-scoped check preview
  GET  /api/v1/projects/<slug>/gate      project-wide gate status
  GET  /api/v1/health                    readiness probe for the workflow

Every request except /api/v1/health must carry the expected bearer token, so
the self-test proves the action wires the API key through to the adapter. It
holds no real data and is never part of a release.

Usage: fake-api.py [--port 8124] [--api-key selftest-key]
"""

import argparse
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8124)
    parser.add_argument("--api-key", default=os.environ.get("SELFTEST_API_KEY", "selftest-key"))
    return parser.parse_args()


ARGS = parse_args()


def is_blocked(slug):
    return slug == "blocked"


def project_and_verb(path):
    parts = path.strip("/").split("/")
    if len(parts) >= 5 and parts[:3] == ["api", "v1", "projects"]:
        return parts[3], parts[4]
    return None, None


def ingest_response(slug):
    if is_blocked(slug):
        return {
            "report_id": "report-blocked",
            "total_findings": 1,
            "threshold_breached": True,
            "scan_mode": "incremental",
            "introduced_count": 1,
            "pre_existing_count": 0,
        }
    return {
        "report_id": "report-pass",
        "total_findings": 0,
        "threshold_breached": False,
        "scan_mode": "incremental",
        "introduced_count": 0,
        "pre_existing_count": 0,
    }


def gate_response(slug):
    if is_blocked(slug):
        return {
            "threshold_breached": True,
            "blocking_count": 1,
            "blocked_by": ["finding-1"],
            "waived_finding_ids": [],
        }
    return {
        "threshold_breached": False,
        "blocking_count": 0,
        "blocked_by": [],
        "waived_finding_ids": [],
    }


def pr_check_response(slug, commit):
    base = {
        "provider": "github",
        "commit_sha": commit,
        "report_id": "report-blocked" if is_blocked(slug) else "report-pass",
        "title": "Specht security gate",
        "truncated": False,
        "waived_count": 0,
    }
    if is_blocked(slug):
        base.update(
            {
                "conclusion": "failure",
                "summary": "1 new blocking finding introduced by this change.",
                "summary_counts": {"high": 1},
                "annotations": [
                    {
                        "external_id": "finding-1",
                        "finding_id": "finding-1",
                        "file": "internal/example/example.go",
                        "start_line": 12,
                        "end_line": 12,
                        "level": "failure",
                        "title": "CVE-2026-0001 in example-package",
                        "message": "Upgrade example-package to 1.2.4.",
                    }
                ],
                "total_mappable": 1,
            }
        )
    else:
        base.update(
            {
                "conclusion": "success",
                "summary": "No new blocking findings introduced by this change.",
                "summary_counts": {},
                "annotations": [],
                "total_mappable": 0,
            }
        )
    return base


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "specht-selftest-fake-api"

    def log_message(self, fmt, *args):
        sys.stdout.write("%s %s\n" % (self.command, self.path))
        sys.stdout.flush()

    def send_json(self, code, payload):
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def read_json(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            return {}
        raw = self.rfile.read(length)
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return {}

    def authorized(self):
        if self.headers.get("Authorization") == "Bearer " + ARGS.api_key:
            return True
        self.send_json(
            401,
            {"error": {"code": "unauthorized", "message": "missing or wrong API key"}},
        )
        return False

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/api/v1/health":
            self.send_json(200, {"status": "ok"})
            return
        if not self.authorized():
            return
        slug, verb = project_and_verb(path)
        if slug is not None and verb == "pr-check":
            self.send_json(200, pr_check_response(slug, ""))
        elif slug is not None and verb == "gate":
            self.send_json(200, gate_response(slug))
        else:
            self.send_json(404, {"error": {"code": "not_found", "message": "no route for " + path}})

    def do_POST(self):
        path = urlparse(self.path).path
        body = self.read_json()
        if not self.authorized():
            return
        if path == "/api/v1/reports":
            slug = str(body.get("project", ""))
            print(
                "ingest project=%r scanner=%r commit=%r introduced_only=%r"
                % (
                    slug,
                    body.get("scanner"),
                    body.get("commit_sha"),
                    body.get("gate_introduced_only"),
                )
            )
            self.send_json(200, ingest_response(slug))
        else:
            self.send_json(404, {"error": {"code": "not_found", "message": "no route for " + path}})


def main():
    server = ThreadingHTTPServer(("127.0.0.1", ARGS.port), Handler)
    server.daemon_threads = True
    print("fake Specht API listening on http://127.0.0.1:%d" % ARGS.port, flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
