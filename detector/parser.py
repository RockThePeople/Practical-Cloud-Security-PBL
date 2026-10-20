"""Parse kube-apiserver audit JSON Lines into one record per request.

Only lines from the watched ServiceAccount are kept. Lines with the same
auditID are grouped into a single request; the ResponseComplete line is the
representative line, or the last stage if ResponseComplete is missing.
"""

import json
from datetime import datetime, timezone

DEFAULT_SA = "system:serviceaccount:pbl-security:pbl-crypto-platform-app"
DECISION_KEY = "authorization.k8s.io/decision"


def parse_time(value):
    """Convert an audit timestamp such as 2026-10-20T04:46:00.123456Z."""
    if not value:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ"):
        try:
            return datetime.strptime(value, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def read_events(lines):
    """Decode JSON lines. Returns (events, number of skipped lines)."""
    events = []
    skipped = 0
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            skipped += 1
            continue
        if not isinstance(event, dict):
            skipped += 1
            continue
        events.append(event)
    return events, skipped


def group_requests(events, sa=DEFAULT_SA):
    """Group the watched SA's events by auditID into request dicts."""
    groups = {}
    for event in events:
        if event.get("user", {}).get("username") != sa:
            continue
        audit_id = event.get("auditID")
        if not audit_id:
            continue
        groups.setdefault(audit_id, []).append(event)

    requests = []
    for audit_id, group in groups.items():
        rep = group[-1]
        for event in group:
            if event.get("stage") == "ResponseComplete":
                rep = event
        obj = rep.get("objectRef") or {}
        requests.append({
            "audit_id": audit_id,
            "time": parse_time(rep.get("requestReceivedTimestamp")),
            "verb": rep.get("verb"),
            "resource": obj.get("resource"),
            "subresource": obj.get("subresource"),
            "namespace": obj.get("namespace"),
            "name": obj.get("name") or None,
            "code": (rep.get("responseStatus") or {}).get("code"),
            "decision": (rep.get("annotations") or {}).get(DECISION_KEY),
            "user_agent": rep.get("userAgent"),
            "source_ips": rep.get("sourceIPs") or [],
            "stages": [e.get("stage") for e in group],
        })

    epoch = datetime.min.replace(tzinfo=timezone.utc)
    requests.sort(key=lambda r: r["time"] or epoch)
    return requests


def parse_lines(lines, sa=DEFAULT_SA):
    """Return (requests, skipped line count) for an iterable of lines."""
    events, skipped = read_events(lines)
    return group_requests(events, sa), skipped


def parse_file(path, sa=DEFAULT_SA):
    """Return (requests, skipped line count) for an audit JSONL file."""
    with open(path, encoding="utf-8") as f:
        return parse_lines(f, sa)
