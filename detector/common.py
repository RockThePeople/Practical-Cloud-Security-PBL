"""Definitions shared by the upgraded detectors (u12, u123)."""

from detector.rules import EXEC_SUBRESOURCES, SEVERITY_ORDER

# Allowlist = the permissions of Role pbl-crypto-platform-reader as written in
# category3/README.md ("Pods, Services, ConfigMaps의 get/list만 허용").
# Fixed from the README; never tuned from the collected data.
ALLOWED_RESOURCES = frozenset({"pods", "services", "configmaps"})
ALLOWED_VERBS = frozenset({"get", "list"})


def is_exec(req):
    return req.get("resource") == "pods" and req.get("subresource") in EXEC_SUBRESOURCES


def is_unnamed_list(req):
    return req.get("verb") in ("list", "watch") and not req.get("name")


def is_named_get(req):
    return req.get("verb") == "get" and bool(req.get("name"))


def failed(req):
    return req.get("code") == 403 or req.get("decision") == "forbid"


def allowed(req):
    return (req.get("resource") in ALLOWED_RESOURCES
            and req.get("verb") in ALLOWED_VERBS
            and not req.get("subresource"))


def shape_severity(req):
    """Severity from the request's shape alone."""
    if is_exec(req):
        return "high"
    if is_unnamed_list(req):
        return "medium"
    if is_named_get(req):
        return "low"
    return "medium"


def max_severity(severities):
    return max(severities, key=lambda s: SEVERITY_ORDER[s])
