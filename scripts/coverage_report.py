#!/usr/bin/env python3
"""Report combined per-file and statement-weighted Go/frontend coverage."""

from __future__ import annotations

import argparse
import json
import math
from collections import defaultdict
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
GENERATED_GO_PREFIX = "internal/db/sqlc/"


def go_module_path() -> str:
    for line in (ROOT / "go.mod").read_text(encoding="utf-8").splitlines():
        if line.startswith("module "):
            return line.removeprefix("module ").strip()
    raise ValueError("go.mod has no module declaration")


def repo_relative(path: str, module: str = "") -> str:
    normalized = path.replace("\\", "/")
    if module and normalized.startswith(f"{module}/"):
        normalized = normalized.removeprefix(f"{module}/")
    elif Path(normalized).is_absolute():
        try:
            normalized = Path(normalized).resolve().relative_to(ROOT).as_posix()
        except ValueError:
            return ""
    return normalized.removeprefix("specht/")


def is_generated_or_test(path: str) -> bool:
    return (
        path.startswith(GENERATED_GO_PREFIX)
        or path.endswith("_test.go")
        or path.endswith(".test.ts")
        or path.endswith(".test.tsx")
        or path.endswith(".spec.ts")
        or path.endswith(".spec.tsx")
        or path.endswith(".d.ts")
        or "/__tests__/" in path
        or path.startswith("frontend/src/test/")
    )


def read_go_profiles(paths: list[Path], module: str) -> dict[str, tuple[int, int]]:
    # Coverage profiles from separate test runs repeat source blocks. Count a
    # block once and mark it covered if any run executed it.
    blocks: defaultdict[str, dict[str, tuple[int, bool]]] = defaultdict(dict)
    modes: set[str] = set()
    for profile in paths:
        with profile.open(encoding="utf-8") as stream:
            for line_number, line in enumerate(stream, start=1):
                line = line.strip()
                if not line:
                    continue
                if line.startswith("mode:"):
                    modes.add(line.partition(":")[2].strip())
                    continue
                try:
                    location, statement_count, execution_count = line.split()
                    raw_path, position = location.rsplit(":", 1)
                    relative_path = repo_relative(raw_path, module)
                    if not relative_path or is_generated_or_test(relative_path):
                        continue
                    statements = int(statement_count)
                    covered = int(execution_count) > 0
                except (ValueError, TypeError) as error:
                    raise ValueError(f"invalid coverage record in {profile}:{line_number}: {line}") from error
                previous = blocks[relative_path].get(position)
                if previous and previous[0] != statements:
                    raise ValueError(f"statement count changed for {relative_path}:{position}")
                blocks[relative_path][position] = (
                    statements,
                    covered or (previous[1] if previous else False),
                )
    if len(modes) > 1:
        raise ValueError(f"incompatible Go coverage modes: {', '.join(sorted(modes))}")

    return {
        path: (
            sum(count for count, _ in file_blocks.values()),
            sum(count for count, covered in file_blocks.values() if covered),
        )
        for path, file_blocks in blocks.items()
        if file_blocks
    }


def read_frontend_coverage(path: Path) -> dict[str, tuple[int, int]]:
    with path.open(encoding="utf-8") as stream:
        data = json.load(stream)

    files: dict[str, tuple[int, int]] = {}
    for raw_path, coverage in data.items():
        relative_path = repo_relative(raw_path)
        if (
            not relative_path.startswith("frontend/src/")
            or is_generated_or_test(relative_path)
        ):
            continue
        statements = coverage.get("s", {})
        total = len(statements)
        if total == 0:
            continue
        files[relative_path] = (total, sum(count > 0 for count in statements.values()))
    return files


def totals(files: dict[str, tuple[int, int]]) -> tuple[float, float, int]:
    if not files:
        return math.nan, math.nan, 0
    per_file_average = sum(covered / total * 100 for total, covered in files.values()) / len(files)
    statements = sum(total for total, _ in files.values())
    covered_statements = sum(covered for _, covered in files.values())
    return per_file_average, covered_statements / statements * 100, len(files)


def print_summary(label: str, files: dict[str, tuple[int, int]]) -> None:
    per_file, aggregate, count = totals(files)
    if count == 0:
        print(f"{label}: no coverable files")
        return
    print(
        f"{label}: {per_file:.1f}% equal-file average; "
        f"{aggregate:.1f}% statement-weighted; {count} coverable files"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--go-profile", action="append", type=Path, required=True)
    parser.add_argument("--frontend-json", type=Path, required=True)
    parser.add_argument("--fail-below", type=float)
    args = parser.parse_args()

    go_files = read_go_profiles(args.go_profile, go_module_path())
    frontend_files = read_frontend_coverage(args.frontend_json)
    combined = go_files | frontend_files

    print_summary("Go", go_files)
    print_summary("Frontend", frontend_files)
    print_summary("Combined", combined)

    per_file_average, _, _ = totals(combined)
    if args.fail_below is not None and per_file_average < args.fail_below:
        print(f"Coverage target not met: {per_file_average:.1f}% < {args.fail_below:.1f}%")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
