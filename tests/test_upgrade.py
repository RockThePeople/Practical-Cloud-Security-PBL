import json
import os
import unittest
from datetime import datetime, timedelta, timezone

from detector import rules
from detector.common import allowed, failed, shape_severity
from detector.parser import parse_file
from detector.upgrade import (a1_outside_allowlist, c1_enumeration, c2_permission_check,
                              c3_recon_then_exec, group_incidents, run)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
T0 = datetime(2026, 10, 20, 5, 0, 0, tzinfo=timezone.utc)
_seq = [0]


def req(verb="list", resource="pods", subresource=None, name=None, code=200,
        decision=None, at=0.0):
    _seq[0] += 1
    if decision is None:
        decision = "forbid" if code == 403 else "allow"
    return {"audit_id": "r{}".format(_seq[0]), "time": T0 + timedelta(seconds=at),
            "verb": verb, "resource": resource, "subresource": subresource,
            "namespace": "pbl-security", "name": name, "code": code, "decision": decision}


def rules_of(alerts):
    return sorted(a["rule"] for a in alerts)


class DefinitionsTest(unittest.TestCase):
    def test_shape_severity_four_cases(self):
        self.assertEqual(shape_severity(req("create", "pods", "exec", "backend-x")), "high")
        self.assertEqual(shape_severity(req("list", "secrets")), "medium")
        self.assertEqual(shape_severity(req("watch", "pods")), "medium")
        self.assertEqual(shape_severity(req("get", "secrets", name="app-tls")), "low")
        self.assertEqual(shape_severity(req("delete", "pods", name="db-x")), "medium")

    def test_failed(self):
        self.assertTrue(failed(req(code=403)))
        self.assertTrue(failed(req(code=None, decision="forbid")))
        self.assertFalse(failed(req(code=200)))

    def test_allowlist(self):
        self.assertTrue(allowed(req("list", "configmaps")))
        self.assertTrue(allowed(req("get", "pods", name="frontend-x")))
        self.assertFalse(allowed(req("list", "secrets")))
        self.assertFalse(allowed(req("watch", "pods")))
        self.assertFalse(allowed(req("get", "pods", "log", "frontend-x")))


class C2Test(unittest.TestCase):
    def test_three_failures_raise_one_low_alert(self):
        reqs = [req("get", "secrets", name="app-tls", code=403, at=i) for i in range(3)]
        alerts = c2_permission_check(reqs)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["severity"], "low")
        self.assertEqual(alerts[0]["audit_ids"], [r["audit_id"] for r in reqs])

    def test_two_failures_do_not(self):
        reqs = [req("get", "secrets", name="app-tls", code=403, at=i) for i in range(2)]
        self.assertEqual(c2_permission_check(reqs), [])

    def test_different_targets_are_counted_separately(self):
        reqs = [req("get", "secrets", name="a", code=403),
                req("get", "secrets", name="b", code=403),
                req("get", "secrets", name="a", code=403)]
        self.assertEqual(c2_permission_check(reqs), [])


class C1Test(unittest.TestCase):
    def test_failed_list_with_two_resources(self):
        reqs = [req("list", "pods", at=0), req("list", "secrets", code=403, at=1),
                req("list", "configmaps", at=2)]
        alerts = c1_enumeration(reqs, use_allowlist=False)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["severity"], "medium")
        self.assertEqual(sorted(alerts[0]["audit_ids"]), sorted(r["audit_id"] for r in reqs))

    def test_one_resource_only(self):
        reqs = [req("list", "secrets", code=403, at=0), req("list", "secrets", code=403, at=1)]
        self.assertEqual(c1_enumeration(reqs, use_allowlist=False), [])

    def test_named_get_failure_is_not_a_trigger(self):
        reqs = [req("list", "pods", at=0), req("get", "secrets", name="app-tls", code=403, at=1),
                req("list", "configmaps", at=2)]
        self.assertEqual(c1_enumeration(reqs, use_allowlist=False), [])
        self.assertEqual(c1_enumeration(reqs, use_allowlist=True), [])

    def test_allowed_secret_list_only_triggers_with_allowlist(self):
        reqs = [req("list", "pods", at=0), req("list", "secrets", code=200, at=1)]
        self.assertEqual(c1_enumeration(reqs, use_allowlist=False), [])
        self.assertEqual(len(c1_enumeration(reqs, use_allowlist=True)), 1)
        self.assertNotIn("C1", rules_of(run(reqs, "u12")[0]))
        self.assertIn("C1", rules_of(run(reqs, "u123")[0]))

    def test_overlapping_windows_merge_and_far_ones_split(self):
        burst = [req("list", "pods", at=0), req("list", "secrets", code=403, at=1),
                 req("list", "pods", at=20), req("list", "secrets", code=403, at=21)]
        self.assertEqual(len(c1_enumeration(burst, use_allowlist=False)), 1)
        far = burst[:2] + [req("list", "pods", at=100), req("list", "secrets", code=403, at=101)]
        self.assertEqual(len(c1_enumeration(far, use_allowlist=False)), 2)

    def test_request_outside_window_is_not_bound(self):
        old = req("list", "services", at=0)
        reqs = [old, req("list", "pods", at=40), req("list", "secrets", code=403, at=41)]
        alerts = c1_enumeration(reqs, use_allowlist=False)
        self.assertEqual(len(alerts), 1)
        self.assertNotIn(old["audit_id"], alerts[0]["audit_ids"])


class C3Test(unittest.TestCase):
    def test_recon_within_10s_is_bound(self):
        recon = req("list", "pods", at=0)
        ex = req("create", "pods", "exec", "backend-x", code=403, at=9)
        alerts = c3_recon_then_exec([recon, ex])
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["severity"], "high")
        self.assertEqual(alerts[0]["audit_ids"], [recon["audit_id"], ex["audit_id"]])

    def test_recon_older_than_10s_is_not_bound(self):
        recon = req("list", "pods", at=0)
        ex = req("create", "pods", "exec", "backend-x", code=403, at=10.5)
        self.assertEqual(c3_recon_then_exec([recon, ex]), [])

    def test_non_pods_reads_are_not_recon(self):
        ex = req("create", "pods", "exec", "backend-x", code=403, at=1)
        self.assertEqual(c3_recon_then_exec([req("list", "services", at=0), ex]), [])


class IncidentTest(unittest.TestCase):
    def _alert(self, at, severity="medium"):
        t = T0 + timedelta(seconds=at)
        return {"rule": "R1", "severity": severity, "reason": "x",
                "audit_ids": ["a{}".format(at)], "time": t, "end": t}

    def test_within_30s_is_one_incident(self):
        incidents = group_incidents([self._alert(0, "low"), self._alert(29, "high")])
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0]["severity"], "high")

    def test_over_30s_is_two_incidents(self):
        self.assertEqual(len(group_incidents([self._alert(0), self._alert(31)])), 2)

    def test_gap_is_measured_from_incident_end(self):
        self.assertEqual(len(group_incidents([self._alert(0), self._alert(25), self._alert(50)])), 1)


class A1Test(unittest.TestCase):
    def test_allowlisted_requests_are_silent(self):
        for r in (req("list", "pods"), req("get", "pods", name="frontend-x"),
                  req("list", "services"), req("list", "configmaps")):
            self.assertIsNone(a1_outside_allowlist(r))

    def test_outside_requests_are_graded(self):
        cases = [
            (req("list", "secrets"), "high"),
            (req("watch", "pods"), "high"),
            (req("create", "pods", "exec", "backend-x"), "high"),
            (req("get", "secrets", name="app-tls"), "low"),
            (req("delete", "pods", name="db-x"), "medium"),
        ]
        for r, severity in cases:
            alert = a1_outside_allowlist(r)
            self.assertEqual(alert["rule"], "A1")
            self.assertEqual(alert["severity"], severity, r)

    def test_a1_ignores_response_code(self):
        self.assertEqual(a1_outside_allowlist(req("list", "secrets", code=200))["severity"], "high")
        self.assertEqual(a1_outside_allowlist(req("list", "secrets", code=403))["severity"], "high")


class GradedRulesTest(unittest.TestCase):
    def test_u12_grades_r1_r3_by_shape(self):
        alerts, _ = run([req("get", "secrets", name="app-tls", code=403)], "u12")
        self.assertEqual({(a["rule"], a["severity"]) for a in alerts}, {("R1", "low"), ("R3", "low")})
        alerts, _ = run([req("list", "secrets", code=403)], "u12")
        self.assertEqual({(a["rule"], a["severity"]) for a in alerts},
                         {("R1", "medium"), ("R3", "medium")})

    def test_r2_stays_high(self):
        alerts, _ = run([req("create", "pods", "exec", "backend-x", code=403)], "u12")
        self.assertEqual({(a["rule"], a["severity"]) for a in alerts}, {("R2", "high"), ("R3", "high")})


class BaseModeTest(unittest.TestCase):
    def test_base_mode_equals_stage01_rules(self):
        for name in ("normal.log", "abnormal_1.log", "abnormal_2.log", "abnormal_3.log"):
            requests, _ = parse_file(os.path.join(ROOT, "category3", "logs", name))
            alerts, incidents = run(requests, "base")
            self.assertEqual(alerts, rules.detect(requests))
            self.assertEqual(len(incidents), len(alerts))

    def test_base_metrics_reproduce_01_baseline_json(self):
        from evaluation.evaluate import baseline_view, compute, counterfactual, load_episodes
        path = os.path.join(ROOT, "evaluation", "results", "01-baseline.json")
        if not os.path.exists(os.path.join(ROOT, "data", "manifest.csv")):
            self.skipTest("data/manifest.csv not present")
        with open(path, encoding="utf-8") as f:
            expected = json.load(f)
        episodes = load_episodes()
        got = baseline_view(compute(episodes, mode="base"))
        got["counterfactual"] = baseline_view(compute(episodes, counterfactual, mode="base"))
        self.assertEqual(json.loads(json.dumps(got)), expected)


if __name__ == "__main__":
    unittest.main()
