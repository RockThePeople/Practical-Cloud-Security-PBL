"""Upgraded detectors u12 (upgrades 1, 2) and u123 (upgrades 1-3).

u12  = R1/R3 graded by request shape, R2 high, C1 enumeration window,
       C2 repeated named-get failures (low), C3 recon before exec,
       plus incident grouping.
u123 = u12 + A1 (outside the README allowlist, regardless of response code)
       and C1 triggered by unnamed list/watch outside the allowlist.

Window sizes and thresholds are fixed by the stage 02 instructions.
"""

from collections import OrderedDict
from datetime import timedelta

from detector import rules as base
from detector.common import (allowed, failed, is_exec, is_named_get, is_unnamed_list,
                             max_severity, shape_severity)

C1_WINDOW = timedelta(seconds=30)
C2_MIN_FAILURES = 3
C3_WINDOW = timedelta(seconds=10)
INCIDENT_GAP = timedelta(seconds=30)

MODES = ("base", "u12", "u123")
RULE_IDS = {
    "base": ["R1", "R2", "R3"],
    "u12": ["R1", "R2", "R3", "C1", "C2", "C3"],
    "u123": ["R1", "R2", "R3", "C1", "C2", "C3", "A1"],
}


def _alert(rule, severity, reason, reqs):
    times = [r["time"] for r in reqs if r.get("time")]
    return {
        "rule": rule,
        "severity": severity,
        "reason": reason,
        "audit_ids": [r["audit_id"] for r in reqs],
        "time": min(times) if times else None,
        "end": max(times) if times else None,
    }


def graded_single_rules(req):
    """R1 and R3 graded by shape, R2 always high."""
    alerts = []
    reason = base.r1_secret_access(req)
    if reason:
        alerts.append(_alert("R1", shape_severity(req), reason, [req]))
    reason = base.r2_workload_entry(req)
    if reason:
        alerts.append(_alert("R2", "high", reason, [req]))
    reason = base.r3_out_of_permission(req)
    if reason:
        alerts.append(_alert("R3", shape_severity(req), reason, [req]))
    return alerts


def a1_outside_allowlist(req):
    if allowed(req):
        return None
    if is_unnamed_list(req) or is_exec(req):
        severity = "high"
    elif is_named_get(req):
        severity = "low"
    else:
        severity = "medium"
    reason = "허용 목록 밖 요청: {} {} (code {})".format(
        req.get("verb"), base._target(req), req.get("code"))
    return _alert("A1", severity, reason, [req])


def c2_permission_check(requests):
    """Named get failing >= 3 times on the same target -> one low alert."""
    groups = OrderedDict()
    for req in requests:
        if is_named_get(req) and failed(req):
            groups.setdefault((req.get("resource"), req.get("name")), []).append(req)
    alerts = []
    for (resource, name), reqs in groups.items():
        if len(reqs) >= C2_MIN_FAILURES:
            reason = "권한 설정 확인 필요: {} {} 이름 지정 get이 {}회 거부됨".format(
                resource, name, len(reqs))
            alerts.append(_alert("C2", "low", reason, reqs))
    return alerts


def _c1_trigger(req, use_allowlist):
    if not is_unnamed_list(req):
        return False
    return failed(req) or (use_allowlist and not allowed(req))


def c1_enumeration(requests, use_allowlist):
    """Window [t-30s, t] with a trigger and >= 2 resources -> merged medium alert."""
    timed = [r for r in requests if r.get("time")]
    alerts = []
    current, current_end = None, None

    def flush():
        reqs = list(current.values())
        resources = sorted({r.get("resource") for r in reqs})
        reason = "열거 패턴: 30초 창 안에 {} list와 리소스 {}종({}) 조회".format(
            "거부/허용 목록 밖" if use_allowlist else "거부된",
            len(resources), ", ".join(resources))
        alerts.append(_alert("C1", "medium", reason, reqs))

    for req in timed:
        t = req["time"]
        start = t - C1_WINDOW
        window = [w for w in timed if start <= w["time"] <= t]
        if not any(_c1_trigger(w, use_allowlist) for w in window):
            continue
        if len({w.get("resource") for w in window}) < 2:
            continue
        if current is not None and start <= current_end:
            for w in window:
                current.setdefault(w["audit_id"], w)
            current_end = t
        else:
            if current is not None:
                flush()
            current = OrderedDict((w["audit_id"], w) for w in window)
            current_end = t
    if current is not None:
        flush()
    return alerts


def c3_recon_then_exec(requests):
    """exec-like request + pods get/list in the 10 s before it -> one high alert."""
    alerts = []
    for ex in requests:
        if not is_exec(ex) or not ex.get("time"):
            continue
        recon = [r for r in requests
                 if r is not ex and r.get("time")
                 and r.get("resource") == "pods" and not r.get("subresource")
                 and r.get("verb") in ("get", "list")
                 and ex["time"] - C3_WINDOW <= r["time"] <= ex["time"]]
        if recon:
            reason = "정찰 후 진입: pods 조회 {}건 직후 {} {}".format(
                len(recon), ex.get("verb"), base._target(ex))
            alerts.append(_alert("C3", "high", reason, recon + [ex]))
    return alerts


def group_incidents(alerts):
    """Merge alerts whose start is within 30 s of the current incident's end."""
    timed = sorted((a for a in alerts if a.get("time")), key=lambda a: a["time"])
    incidents = []
    for a in timed:
        if incidents and a["time"] <= incidents[-1]["end"] + INCIDENT_GAP:
            inc = incidents[-1]
            inc["alerts"].append(a)
            inc["end"] = max(inc["end"], a["end"])
        else:
            incidents.append({"start": a["time"], "end": a["end"], "alerts": [a]})
    incidents += [{"start": None, "end": None, "alerts": [a]}
                  for a in alerts if not a.get("time")]
    for inc in incidents:
        inc["severity"] = max_severity(a["severity"] for a in inc["alerts"])
        inc["rules"] = sorted({a["rule"] for a in inc["alerts"]})
        ids = OrderedDict()
        for a in inc["alerts"]:
            for aid in a["audit_ids"]:
                ids[aid] = True
        inc["audit_ids"] = list(ids)
    return incidents


def detect_upgraded(requests, use_allowlist):
    alerts = []
    for req in requests:
        alerts.extend(graded_single_rules(req))
        if use_allowlist:
            alert = a1_outside_allowlist(req)
            if alert:
                alerts.append(alert)
    alerts.extend(c1_enumeration(requests, use_allowlist))
    alerts.extend(c2_permission_check(requests))
    alerts.extend(c3_recon_then_exec(requests))
    return alerts


def run(requests, mode="u123"):
    """Return (alerts, incidents) for a detector mode."""
    if mode == "base":
        # Baseline: no grouping, one alert = one incident.
        alerts = base.detect(requests)
        incidents = [{"start": a["time"], "end": a["time"], "alerts": [a],
                      "severity": a["severity"], "rules": [a["rule"]],
                      "audit_ids": list(a["audit_ids"])} for a in alerts]
        return alerts, incidents
    if mode not in MODES:
        raise ValueError("unknown mode: {}".format(mode))
    alerts = detect_upgraded(requests, use_allowlist=(mode == "u123"))
    return alerts, group_incidents(alerts)
