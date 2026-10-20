"""Descriptive statistics per scenario, for explaining what separates benign
from attack runs. Reads data/ only (no cluster). Not used by any detector rule.

Usage (from the repo root): python3 evaluation/describe.py
"""

import csv
import json
import os
import sys
from collections import Counter, OrderedDict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from detector.parser import parse_file  # noqa: E402

MANIFEST = os.path.join(ROOT, "data", "manifest.csv")
RESULT = os.path.join(ROOT, "evaluation", "results", "03-describe.json")


def _range(values, ndigits=1):
    values = [v for v in values if v is not None]
    if not values:
        return None
    return {"min": round(min(values), ndigits), "max": round(max(values), ndigits),
            "mean": round(sum(values) / len(values), ndigits)}


def describe(manifest=MANIFEST):
    per = OrderedDict()
    with open(manifest, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    for row in rows:
        requests, _ = parse_file(os.path.join(ROOT, row["file"]))
        s = per.setdefault(row["scenario"], {
            "label": row["label"], "runs": 0, "source_ips": set(), "user_agents": set(),
            "requests_per_run": [], "requests_per_second": [], "duration_seconds": [],
            "shapes": Counter(), "forbidden_per_run": [], "named_per_run": []})
        s["runs"] += 1
        for r in requests:
            s["source_ips"].update(r["source_ips"])
            s["user_agents"].add(r["user_agent"])
            s["shapes"][" ".join([r["verb"], r["resource"]] +
                                 ([r["subresource"]] if r["subresource"] else []))] += 1
        times = [r["time"] for r in requests if r["time"]]
        span = (max(times) - min(times)).total_seconds() if len(times) >= 2 else None
        s["requests_per_run"].append(len(requests))
        s["duration_seconds"].append(span)
        # Undefined for a single request (no first-to-last interval).
        s["requests_per_second"].append(len(requests) / span if span else None)
        s["forbidden_per_run"].append(sum(1 for r in requests if r["code"] == 403))
        s["named_per_run"].append(sum(1 for r in requests if r["name"]))

    out = OrderedDict()
    for name, s in per.items():
        out[name] = OrderedDict([
            ("label", s["label"]),
            ("runs", s["runs"]),
            ("source_ips", sorted(s["source_ips"])),
            ("user_agents", sorted(s["user_agents"])),
            ("requests_per_run", sorted(set(s["requests_per_run"]))),
            ("duration_seconds", _range(s["duration_seconds"], 2)),
            ("requests_per_second", _range(s["requests_per_second"])),
            ("request_shapes", sorted(s["shapes"])),
            ("forbidden_per_run", sorted(set(s["forbidden_per_run"]))),
            ("named_per_run", sorted(set(s["named_per_run"]))),
        ])
    return out


def main():
    result = describe()
    os.makedirs(os.path.dirname(RESULT), exist_ok=True)
    with open(RESULT, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
        f.write("\n")
    print("| 시나리오 | 라벨 | IP | UA | 요청/회 | 초당 요청(평균) | 403/회 | 이름 지정/회 | 요청 모양 |")
    print("|---|---|---|---|---|---|---|---|---|")
    for name, s in result.items():
        rps = s["requests_per_second"]
        print("| {} | {} | {} | {} | {} | {} | {} | {} | {} |".format(
            name, s["label"], ", ".join(s["source_ips"]),
            ", ".join(ua.split(" ")[0] for ua in s["user_agents"]),
            "/".join(map(str, s["requests_per_run"])),
            rps["mean"] if rps else "-",
            "/".join(map(str, s["forbidden_per_run"])),
            "/".join(map(str, s["named_per_run"])),
            ", ".join(s["request_shapes"])))
    print("\n저장: {}".format(os.path.relpath(RESULT, ROOT)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
