"""CLI: python3 -m detector <file.jsonl> [--sa NAME] [--json]"""

import argparse
import json
import sys
from collections import Counter

from detector.parser import DEFAULT_SA, parse_file
from detector.rules import RULES, detect


def build_report(path, sa):
    requests, skipped = parse_file(path, sa)
    by_id = {r["audit_id"]: r for r in requests}
    alerts = detect(requests)
    rule_counts = Counter(a["rule"] for a in alerts)
    rows = []
    for a in alerts:
        req = by_id[a["audit_ids"][0]]
        rows.append({
            "time": a["time"].isoformat() if a["time"] else None,
            "rule": a["rule"],
            "severity": a["severity"],
            "verb": req["verb"],
            "resource": req["resource"],
            "subresource": req["subresource"],
            "name": req["name"],
            "code": req["code"],
            "reason": a["reason"],
            "audit_ids": a["audit_ids"],
        })
    return {
        "file": path,
        "sa": sa,
        "skipped_lines": skipped,
        "requests": len(requests),
        "alerts": rows,
        "alerts_by_rule": {rule_id: rule_counts.get(rule_id, 0) for rule_id, _ in RULES},
    }


def print_text(report):
    print("파일: {}".format(report["file"]))
    print("감시 SA: {}".format(report["sa"]))
    print("요청 수: {} (건너뛴 줄 {})".format(report["requests"], report["skipped_lines"]))
    print("알림 {}개".format(len(report["alerts"])))
    for a in report["alerts"]:
        print("  {}  {}  {:<6} {} {} {} {} code={}  {}".format(
            a["time"], a["rule"], a["severity"], a["verb"], a["resource"],
            a["subresource"] or "-", a["name"] or "-", a["code"], a["reason"]))
    print("규칙별 알림 수: " + ", ".join(
        "{}={}".format(k, v) for k, v in report["alerts_by_rule"].items()))


def main(argv=None):
    ap = argparse.ArgumentParser(prog="python3 -m detector")
    ap.add_argument("file", help="audit JSON Lines file")
    ap.add_argument("--sa", default=DEFAULT_SA, help="watched ServiceAccount username")
    ap.add_argument("--json", action="store_true", help="print JSON")
    args = ap.parse_args(argv)
    report = build_report(args.file, args.sa)
    if args.json:
        json.dump(report, sys.stdout, ensure_ascii=False, indent=2)
        print()
    else:
        print_text(report)
    return 0


if __name__ == "__main__":
    sys.exit(main())
