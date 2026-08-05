#!/usr/bin/env python3
"""Emit a shields.io endpoint-badge JSON with the transpilation progress.

Counts `status: ported` entries in names.yaml against the total function
count of the firmware. The total comes from ipod-decomp's
decomp/functions.csv (Ghidra function index, header line excluded); it is
hardcoded here because that repo is not present in CI.

Usage: python3 tools/progress.py > progress.json
"""
import json
import os

import yaml

TOTAL_FUNCTIONS = 32189

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def badge_color(pct):
    for threshold, color in [(100, "brightgreen"), (75, "green"),
                             (50, "yellowgreen"), (25, "yellow"),
                             (10, "orange")]:
        if pct >= threshold:
            return color
    return "red"


def load_functions(path):
    """Parse names.yaml, failing with an actionable message on invalid YAML.

    The usual culprit is a `notes:` written as a plain scalar containing an
    unquoted ` #` (ARM immediates like `mov r0, #0`), which YAML reads as a
    comment. Use a `>-` folded block scalar—as every other note does—so the
    `#` stays literal text.
    """
    with open(path) as f:
        try:
            return yaml.safe_load(f)["functions"]
        except yaml.YAMLError as e:
            mark = getattr(e, "problem_mark", None)
            where = f" near {path}:{mark.line + 1}" if mark else ""
            raise SystemExit(
                f"names.yaml is not valid YAML{where}. A ` #` in an unquoted "
                "notes value is read as a comment—use a `>-` block scalar. "
                f"Original error: {e}"
            )


def main():
    functions = load_functions(os.path.join(ROOT, "names.yaml"))
    ported = sum(1 for fn in functions if fn.get("status") == "ported")
    pct = 100.0 * ported / TOTAL_FUNCTIONS
    print(json.dumps({
        "schemaVersion": 1,
        "label": "transpiled",
        "message": f"{ported}/{TOTAL_FUNCTIONS} ({pct:.2f}%)",
        "color": badge_color(pct),
    }))


if __name__ == "__main__":
    main()
