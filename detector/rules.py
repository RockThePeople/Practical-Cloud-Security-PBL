"""Baseline rules R1-R3 from the README observation points.

Each request is checked against every rule independently, so one request can
raise several alerts. The baseline has no severity levels (every alert is
"high") and no incident grouping (one alert = one incident).
"""

EXEC_SUBRESOURCES = ("exec", "attach", "portforward")
SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2}


def _target(req):
    resource = req.get("resource") or "-"
    if req.get("subresource"):
        resource += "/" + req["subresource"]
    if req.get("name"):
        resource += " " + req["name"]
    return resource


def r1_secret_access(req):
    if req.get("resource") == "secrets":
        return "Secret 접근 시도: {} {} (code {})".format(
            req.get("verb"), _target(req), req.get("code"))
    return None


def r2_workload_entry(req):
    if req.get("resource") == "pods" and req.get("subresource") in EXEC_SUBRESOURCES:
        return "다른 workload 진입 시도: {} {} (code {})".format(
            req.get("verb"), _target(req), req.get("code"))
    return None


def r3_out_of_permission(req):
    if req.get("code") == 403 or req.get("decision") == "forbid":
        return "권한 밖 요청: {} {} (code {}, decision {})".format(
            req.get("verb"), _target(req), req.get("code"), req.get("decision"))
    return None


RULES = [
    ("R1", r1_secret_access),
    ("R2", r2_workload_entry),
    ("R3", r3_out_of_permission),
]


def evaluate_request(req):
    """Return the alerts raised by one request."""
    alerts = []
    for rule_id, check in RULES:
        reason = check(req)
        if reason:
            alerts.append({
                "rule": rule_id,
                "severity": "high",
                "reason": reason,
                "audit_ids": [req["audit_id"]],
                "time": req.get("time"),
            })
    return alerts


def detect(requests):
    """Return all alerts for a list of requests, in request order."""
    alerts = []
    for req in requests:
        alerts.extend(evaluate_request(req))
    return alerts


def at_least(severity, minimum):
    return SEVERITY_ORDER.get(severity, -1) >= SEVERITY_ORDER[minimum]
