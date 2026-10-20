"""Evaluate the baseline detector on data/ (no cluster needed).

Usage (from the repo root): python3 evaluation/evaluate.py

Ground truth is per file: every watched-SA request in an attack episode is an
attack request, every request in a benign episode is benign. A request is
"flagged" when at least one alert of severity >= medium hits it. A run is
"detected" when it raises at least one alert.

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
from detector.rules import RULES, at_least, detect  # noqa: E402

MANIFEST = os.path.join(ROOT, "data", "manifest.csv")
RESULT = os.path.join(ROOT, "evaluation", "results", "01-baseline.json")
SCENARIO_ORDER = ["normal", "normal_misconfig", "abnormal_1", "abnormal_2", "abnormal_3"]
RULE_IDS = [rule_id for rule_id, _ in RULES]


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


def compute(episodes, transform=None):
    runs = Counter()
    per_scenario = OrderedDict(
        (s, {"runs": 0, "requests": 0, "flagged_requests": 0,
             "alerts_by_rule": {r: 0 for r in RULE_IDS}, "alerts": 0})
        for s in SCENARIO_ORDER)
    fn = OrderedDict()
    tp = fp = fn_count = tn = 0

    for ep in episodes:
        events = transform(ep["events"]) if transform else ep["events"]
        requests = group_requests(events)
        alerts = detect(requests)
        flagged_ids = {aid for a in alerts if at_least(a["severity"], "medium")
                       for aid in a["audit_ids"]}
        is_attack = ep["label"] == "attack"

        sc = per_scenario.setdefault(ep["scenario"], {
            "runs": 0, "requests": 0, "flagged_requests": 0,
            "alerts_by_rule": {r: 0 for r in RULE_IDS}, "alerts": 0})
        sc["runs"] += 1
        sc["requests"] += len(requests)
        sc["flagged_requests"] += len(flagged_ids)
        sc["alerts"] += len(alerts)
        for a in alerts:
            sc["alerts_by_rule"][a["rule"]] += 1

        runs[(ep["label"], "total")] += 1
        if alerts:
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
            "alerts": _ratio(a3.get("alerts", 0), a3_runs),
            # Baseline has no incident grouping: one alert = one incident.
            "incidents": _ratio(a3.get("alerts", 0), a3_runs),
        },
        "per_scenario": per_scenario,
        "alerts_by_rule_total": {
            r: sum(s["alerts_by_rule"][r] for s in per_scenario.values()) for r in RULE_IDS},
        "missed_attack_requests": {s: dict(c) for s, c in fn.items()},
    }


def markdown(title, m):
    lines = ["## " + title, ""]
    r = m["run_level"]
    lines += ["| 실행 단위 | 값 |", "|---|---|",
              "| 공격 실행 탐지 | {}/{} |".format(r["attack_runs_detected"], r["attack_runs"]),
              "| 정상 실행 오탐 | {}/{} |".format(r["benign_runs_false_alarm"], r["benign_runs"]), ""]
    q = m["request_level"]
    lines += ["| TP | FP | FN | TN | precision | recall |", "|---|---|---|---|---|---|",
              "| {TP} | {FP} | {FN} | {TN} | {precision} | {recall} |".format(**q), ""]
    a = m["abnormal_3_per_run"]
    lines += ["abnormal_3 1회당 평균 알림 {} / 사건 {}".format(a["alerts"], a["incidents"]), ""]
    lines += ["| 시나리오 | 실행 | 요청 | 표시한 요청 | " + " | ".join(RULE_IDS) + " |",
              "|---|---|---|---|" + "---|" * len(RULE_IDS)]
    for name, s in m["per_scenario"].items():
        lines.append("| {} | {} | {} | {} | {} |".format(
            name, s["runs"], s["requests"], s["flagged_requests"],
            " | ".join(str(s["alerts_by_rule"][rid]) for rid in RULE_IDS)))
    lines.append("| 합계 | | | | {} |".format(
        " | ".join(str(m["alerts_by_rule_total"][rid]) for rid in RULE_IDS)))
    lines += ["", "놓친 공격 요청(FN):"]
    if not m["missed_attack_requests"]:
        lines.append("- 없음")
    for name, combos in m["missed_attack_requests"].items():
        for key, n in combos.items():
            lines.append("- {}: `{}` × {}".format(name, key, n))
    lines.append("")
    return "\n".join(lines)


def main():
    episodes = load_episodes()
    result = compute(episodes)
    result["counterfactual"] = compute(episodes, transform=counterfactual)
    os.makedirs(os.path.dirname(RESULT), exist_ok=True)
    with open(RESULT, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
        f.write("\n")
    print("# 단계 01 기본 탐지 평가 (에피소드 {}개)\n".format(len(episodes)))
    print(markdown("기본 탐지", result))
    print(markdown("반사실 (감시 SA의 403→200, forbid→allow)", result["counterfactual"]))
    print("저장: {}".format(os.path.relpath(RESULT, ROOT)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
