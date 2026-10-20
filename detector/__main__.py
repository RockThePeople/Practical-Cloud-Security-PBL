"""CLI: python3 -m detector <file.jsonl> [--sa NAME] [--mode base|u12|u123] [--json]"""

import argparse
import json
import sys
from collections import Counter

from detector.parser import DEFAULT_SA, parse_file
from detector.upgrade import MODES, RULE_IDS, run


def _iso(t):
    return t.isoformat() if t else None


def build_report(path, sa, mode="u123"):
    requests, skipped = parse_file(path, sa)
    by_id = {r["audit_id"]: r for r in requests}
    alerts, incidents = run(requests, mode)
    rule_counts = Counter(a["rule"] for a in alerts)
    rows = []
    for a in alerts:
        req = by_id[a["audit_ids"][-1]]
        rows.append({
            "time": _iso(a["time"]),
            "rule": a["rule"],
            "severity": a["severity"],
            "requests": len(a["audit_ids"]),
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
        "mode": mode,
        "skipped_lines": skipped,
        "requests": len(requests),
        "alerts": rows,
        "alerts_by_rule": {rule_id: rule_counts.get(rule_id, 0) for rule_id in RULE_IDS[mode]},
        "incidents": [{
            "start": _iso(inc["start"]),
            "end": _iso(inc["end"]),
            "severity": inc["severity"],
            "rules": inc["rules"],
            "alerts": len(inc["alerts"]),
            "requests": len(inc["audit_ids"]),
        } for inc in incidents],
    }


def print_text(report):
    print("파일: {}".format(report["file"]))
    print("감시 SA: {}".format(report["sa"]))
    print("모드: {}".format(report["mode"]))
    print("요청 수: {} (건너뛴 줄 {})".format(report["requests"], report["skipped_lines"]))
    print("알림 {}개".format(len(report["alerts"])))
    for a in report["alerts"]:
        print("  {}  {}  {:<6} 요청{:>3}  {} {} {} {} code={}  {}".format(
            a["time"], a["rule"], a["severity"], a["requests"], a["verb"], a["resource"],
            a["subresource"] or "-", a["name"] or "-", a["code"], a["reason"]))
    print("규칙별 알림 수: " + ", ".join(
        "{}={}".format(k, v) for k, v in report["alerts_by_rule"].items()))
    print("사건 {}개".format(len(report["incidents"])))
    for inc in report["incidents"]:
        print("  {} ~ {}  {:<6} 규칙 {}  알림 {}  요청 {}".format(
            inc["start"], inc["end"], inc["severity"], ",".join(inc["rules"]),
            inc["alerts"], inc["requests"]))


def main(argv=None):
    ap = argparse.ArgumentParser(prog="python3 -m detector")
    ap.add_argument("file", help="audit JSON Lines file")
    ap.add_argument("--sa", default=DEFAULT_SA, help="watched ServiceAccount username")
    ap.add_argument("--mode", choices=MODES, default="u123", help="detector (default u123)")
    ap.add_argument("--json", action="store_true", help="print JSON")
    args = ap.parse_args(argv)
    report = build_report(args.file, args.sa, args.mode)
    if args.json:
        json.dump(report, sys.stdout, ensure_ascii=False, indent=2)
        print()
    else:
        print_text(report)
    return 0


if __name__ == "__main__":
    sys.exit(main())
