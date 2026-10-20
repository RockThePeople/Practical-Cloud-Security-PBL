"""Evaluate the detectors on data/ (no cluster needed).

Usage (from the repo root): python3 evaluation/evaluate.py

Writes evaluation/results/01-baseline.json (stage 01, baseline only, same
layout as before) and evaluation/results/02-upgrade.json (stage 02: detectors
base / u12 / u123 on the original and counterfactual data).

Ground truth is per file: every watched-SA request in an attack episode is an
attack request, every request in a benign episode is benign. A request is
"flagged" when at least one alert of severity >= medium hits it. A run is
"detected" when it raises at least one alert of severity >= medium.

The counterfactual copies the events in memory and turns the watched SA's
403/forbid into 200/allow, to see what happens when least privilege is broken.
"""

import copy
import csv
import json
import os
import sys
from collections import Counter, OrderedDict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from detector.parser import DECISION_KEY, DEFAULT_SA, group_requests, read_events  # noqa: E402
from detector.rules import at_least  # noqa: E402
from detector.upgrade import MODES, RULE_IDS, run  # noqa: E402

MANIFEST = os.path.join(ROOT, "data", "manifest.csv")
RESULT = os.path.join(ROOT, "evaluation", "results", "01-baseline.json")
RESULT_02 = os.path.join(ROOT, "evaluation", "results", "02-upgrade.json")
SCENARIO_ORDER = ["normal", "normal_misconfig", "abnormal_1", "abnormal_2", "abnormal_3"]


def counterfactual(events, sa=DEFAULT_SA):
    """Return a copy where the watched SA's 403/forbid become 200/allow.

    Events of other users are passed through untouched; the input list and
    its events are never modified.
    """
    out = []
    for event in events:
        if event.get("user", {}).get("username") != sa:
            out.append(event)
            continue
        event = copy.deepcopy(event)
        status = event.get("responseStatus")
        if status and status.get("code") == 403:
            status["code"] = 200
        annotations = event.get("annotations")
        if annotations and annotations.get(DECISION_KEY) == "forbid":
            annotations[DECISION_KEY] = "allow"
        out.append(event)
    return out


def load_episodes(manifest=MANIFEST):
    episodes = []
    with open(manifest, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            with open(os.path.join(ROOT, row["file"]), encoding="utf-8") as ef:
                events, _ = read_events(ef)
            episodes.append({"id": row["episode_id"], "scenario": row["scenario"],
                             "label": row["label"], "events": events})
    return episodes


def _ratio(a, b):
    return round(a / b, 3) if b else None


def _request_key(req):
    resource = req["resource"]
    if req["subresource"]:
        resource += "/" + req["subresource"]
    return "{} {} {}".format(req["verb"], resource, req["code"])


def _new_scenario(rule_ids):
    return {"runs": 0, "requests": 0, "flagged_requests": 0,
            "alerts_by_rule": {r: 0 for r in rule_ids}, "alerts": 0}


def compute(episodes, transform=None, mode="base"):
    """Metrics for one detector mode. Only alerts of severity >= medium count."""
    rule_ids = RULE_IDS[mode]
    runs = Counter()
    per_scenario = OrderedDict((s, _new_scenario(rule_ids)) for s in SCENARIO_ORDER)
    fn = OrderedDict()
    fp_combos = OrderedDict()
    a3_incidents = 0
    tp = fp = fn_count = tn = 0

    for ep in episodes:
        events = transform(ep["events"]) if transform else ep["events"]
        requests = group_requests(events)
        alerts, incidents = run(requests, mode)
        counted = [a for a in alerts if at_least(a["severity"], "medium")]
        flagged_ids = {aid for a in counted for aid in a["audit_ids"]}
        is_attack = ep["label"] == "attack"

        sc = per_scenario.setdefault(ep["scenario"], _new_scenario(rule_ids))
        sc["runs"] += 1
        sc["requests"] += len(requests)
        sc["flagged_requests"] += len(flagged_ids)
        sc["alerts"] += len(alerts)
        for a in alerts:
            sc["alerts_by_rule"][a["rule"]] += 1
        if ep["scenario"] == "abnormal_3":
            a3_incidents += sum(1 for i in incidents if at_least(i["severity"], "medium"))

        runs[(ep["label"], "total")] += 1
        if counted:
            runs[(ep["label"], "alerted")] += 1

        for req in requests:
            flagged = req["audit_id"] in flagged_ids
            if is_attack and flagged:
                tp += 1
            elif is_attack:
                fn_count += 1
                fn.setdefault(ep["scenario"], Counter())[_request_key(req)] += 1
            elif flagged:
                fp += 1
                fp_combos.setdefault(ep["scenario"], Counter())[_request_key(req)] += 1
            else:
                tn += 1

    a3 = per_scenario.get("abnormal_3", {})
    a3_runs = a3.get("runs", 0)
    return {
        "run_level": {
            "attack_runs_detected": runs[("attack", "alerted")],
            "attack_runs": runs[("attack", "total")],
            "benign_runs_false_alarm": runs[("benign", "alerted")],
            "benign_runs": runs[("benign", "total")],
        },
        "request_level": {
            "TP": tp, "FP": fp, "FN": fn_count, "TN": tn,
            "precision": _ratio(tp, tp + fp),
            "recall": _ratio(tp, tp + fn_count),
        },
        "abnormal_3_per_run": {
            # alerts: every alert; incidents: incidents of severity >= medium.
            # For base, one alert = one incident and every alert is high.
            "alerts": _ratio(a3.get("alerts", 0), a3_runs),
            "incidents": _ratio(a3_incidents, a3_runs),
        },
        "per_scenario": per_scenario,
        "alerts_by_rule_total": {
            r: sum(s["alerts_by_rule"][r] for s in per_scenario.values()) for r in rule_ids},
        "missed_attack_requests": {s: dict(c) for s, c in fn.items()},
        "false_positive_requests": {s: dict(c) for s, c in fp_combos.items()},
    }


BASELINE_KEYS = ["run_level", "request_level", "abnormal_3_per_run", "per_scenario",
                 "alerts_by_rule_total", "missed_attack_requests"]


def baseline_view(m):
    """Stage 01 result layout (keeps 01-baseline.json unchanged)."""
    return {k: m[k] for k in BASELINE_KEYS}


def _flat(nested):
    return {"{} {}".format(s, key): n for s, combos in nested.items() for key, n in combos.items()}


def comparison_row(mode, data, m):
    r, q, a = m["run_level"], m["request_level"], m["abnormal_3_per_run"]
    return OrderedDict([
        ("detector", mode), ("data", data),
        ("attack_runs_detected", r["attack_runs_detected"]), ("attack_runs", r["attack_runs"]),
        ("benign_runs_false_alarm", r["benign_runs_false_alarm"]), ("benign_runs", r["benign_runs"]),
        ("TP", q["TP"]), ("FP", q["FP"]), ("FN", q["FN"]), ("TN", q["TN"]),
        ("precision", q["precision"]), ("recall", q["recall"]),
        ("abnormal_3_alerts_per_run", a["alerts"]),
        ("abnormal_3_incidents_per_run", a["incidents"]),
        ("alerts_by_rule_total", m["alerts_by_rule_total"]),
        ("fn", _flat(m["missed_attack_requests"])),
        ("fp", _flat(m["false_positive_requests"])),
    ])


def comparison_markdown(rows):
    lines = ["| 탐지기 | 데이터 | 공격 실행 탐지 | 정상 실행 오탐 | TP | FP | FN | TN "
             "| precision | recall | abnormal_3 1회당 알림 / 사건 |",
             "|---|---|---|---|---|---|---|---|---|---|---|"]
    for r in rows:
        lines.append("| {detector} | {data} | {attack_runs_detected}/{attack_runs} "
                     "| {benign_runs_false_alarm}/{benign_runs} | {TP} | {FP} | {FN} | {TN} "
                     "| {precision:.3f} | {recall:.3f} "
                     "| {abnormal_3_alerts_per_run} / {abnormal_3_incidents_per_run} |".format(**r))
    lines += ["", "행별 FN / FP (`시나리오 verb resource code` × 개수):", ""]
    for r in rows:
        fn = ", ".join("`{}` × {}".format(k, v) for k, v in r["fn"].items()) or "없음"
        fp = ", ".join("`{}` × {}".format(k, v) for k, v in r["fp"].items()) or "없음"
        lines.append("- {} / {}: FN {} | FP {}".format(r["detector"], r["data"], fn, fp))
    lines.append("")
    return "\n".join(lines)


def _write(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
        f.write("\n")


def main():
    episodes = load_episodes()

    # Stage 01: baseline, unchanged layout.
    baseline = baseline_view(compute(episodes, mode="base"))
    baseline["counterfactual"] = baseline_view(
        compute(episodes, transform=counterfactual, mode="base"))
    _write(RESULT, baseline)

    # Stage 02: 3 detectors x (original, counterfactual).
    rows = []
    for mode in MODES:
        for data, transform in (("original", None), ("counterfactual", counterfactual)):
            rows.append(comparison_row(mode, data, compute(episodes, transform, mode)))
    _write(RESULT_02, {"episodes": len(episodes), "rows": rows})

    print("# 단계 02 최종 비교표 (에피소드 {}개, medium 이상 알림만 탐지로 셈)\n".format(len(episodes)))
    print(comparison_markdown(rows))
    print("저장: {}, {}".format(os.path.relpath(RESULT, ROOT), os.path.relpath(RESULT_02, ROOT)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
