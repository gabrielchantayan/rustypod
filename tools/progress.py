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


def main():
    with open(os.path.join(ROOT, "names.yaml")) as f:
        functions = yaml.safe_load(f)["functions"]
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
