"""Collect 25 audit-log episodes from the live kind cluster.

Order: normal -> normal_misconfig -> abnormal_1 -> abnormal_2 -> abnormal_3,
repeated for 5 rounds. Each run stores only the audit.log lines added while
it ran. Labels are assigned per file from the scenario name only.

Usage (from the repo root): python3 evaluation/collect.py
"""

import csv
import os
import subprocess
import sys
import time
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from detector.parser import parse_file  # noqa: E402

CONTAINER = "pbl-security-control-plane"
AUDIT_LOG = "/var/log/kubernetes/audit.log"
ROUNDS = 5
SETTLE_SECONDS = 2
PAUSE_SECONDS = 8

SCENARIOS = [
    ("normal", "category3/normal.sh", "benign"),
    ("normal_misconfig", "scenarios/normal_misconfig.sh", "benign"),
    ("abnormal_1", "category3/abnormal_1.sh", "attack"),
    ("abnormal_2", "category3/abnormal_2.sh", "attack"),
    ("abnormal_3", "category3/abnormal_3.sh", "attack"),
]

EPISODE_DIR = os.path.join(ROOT, "data", "episodes")
MANIFEST = os.path.join(ROOT, "data", "manifest.csv")
LOG_DIR = os.path.join(ROOT, "tmp", "stage01")
FIELDS = ["episode_id", "scenario", "label", "round", "file",
          "started_at", "total_lines", "sa_requests"]


class CollectError(Exception):
    pass


def env():
    e = dict(os.environ)
    local_bin = os.path.expanduser("~/.local/bin")
    e["PATH"] = local_bin + os.pathsep + e.get("PATH", "")
    return e


def line_count():
    out = subprocess.run(
        ["docker", "exec", CONTAINER, "wc", "-l", AUDIT_LOG],
        check=True, capture_output=True, text=True).stdout
    return int(out.split()[0])


def read_lines(start, end):
    """Return audit.log lines start..end (1-based, inclusive)."""
    if end < start:
        return ""
    return subprocess.run(
        ["docker", "exec", CONTAINER, "sed", "-n", "{},{}p".format(start, end), AUDIT_LOG],
        check=True, capture_output=True, text=True).stdout


def run_once(scenario, script, log_path):
    """Run one script; return (started_at, text) or raise CollectError."""
    before = line_count()
    started_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    with open(log_path, "w", encoding="utf-8") as log:
        rc = subprocess.run(["bash", script], cwd=ROOT, env=env(),
                            stdout=log, stderr=subprocess.STDOUT).returncode
    time.sleep(SETTLE_SECONDS)
    after = line_count()
    if rc != 0:
        raise CollectError("{} exited with code {} (see {})".format(scenario, rc, log_path))
    if after < before:
        raise CollectError("{}: audit.log rotated (lines {} -> {})".format(scenario, before, after))
    return started_at, read_lines(before + 1, after)


def main():
    os.makedirs(EPISODE_DIR, exist_ok=True)
    os.makedirs(LOG_DIR, exist_ok=True)
    rows = []
    episode = 0
    for rnd in range(1, ROUNDS + 1):
        for scenario, script, label in SCENARIOS:
            episode += 1
            name = "{:02d}_{}_{}".format(episode, scenario, rnd)
            log_path = os.path.join(LOG_DIR, name + ".out")
            try:
                started_at, text = run_once(scenario, script, log_path)
            except CollectError as first:
                print("discarded: {} -> retrying once".format(first), flush=True)
                time.sleep(PAUSE_SECONDS)
                try:
                    started_at, text = run_once(scenario, script, log_path)
                except CollectError as second:
                    print("STOP: {}".format(second), file=sys.stderr, flush=True)
                    return 1
            rel = os.path.join("data", "episodes", name + ".jsonl")
            path = os.path.join(ROOT, rel)
            with open(path, "w", encoding="utf-8") as f:
                f.write(text)
            requests, _ = parse_file(path)
            rows.append({
                "episode_id": "{:02d}".format(episode),
                "scenario": scenario,
                "label": label,
                "round": rnd,
                "file": rel,
                "started_at": started_at,
                "total_lines": text.count("\n"),
                "sa_requests": len(requests),
            })
            print("{} lines={} sa_requests={}".format(
                name, rows[-1]["total_lines"], rows[-1]["sa_requests"]), flush=True)
            time.sleep(PAUSE_SECONDS)

    with open(MANIFEST, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    print("wrote {} episodes and {}".format(len(rows), os.path.relpath(MANIFEST, ROOT)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
