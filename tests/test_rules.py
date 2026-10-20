import unittest

from detector.rules import detect, evaluate_request


def req(verb="list", resource="pods", subresource=None, name=None, code=200, decision="allow"):
    return {"audit_id": "id-" + verb + resource, "time": None, "verb": verb,
            "resource": resource, "subresource": subresource, "namespace": "pbl-security",
            "name": name, "code": code, "decision": decision}


def rules_of(r):
    return sorted(a["rule"] for a in evaluate_request(r))


class RulesTest(unittest.TestCase):
    def test_normal_reads_raise_nothing(self):
        for r in (req(), req(resource="services"), req(resource="configmaps"),
                  req(verb="get", name="frontend-x")):
            self.assertEqual(rules_of(r), [])

    def test_r1_secret_access_even_when_allowed(self):
        self.assertEqual(rules_of(req(resource="secrets")), ["R1"])

    def test_secret_403_raises_r1_and_r3(self):
        alerts = evaluate_request(req(resource="secrets", code=403, decision="forbid"))
        self.assertEqual(sorted(a["rule"] for a in alerts), ["R1", "R3"])

    def test_r2_exec_attach_portforward(self):
        for sub in ("exec", "attach", "portforward"):
            self.assertEqual(rules_of(req(verb="create", subresource=sub, name="backend-x")), ["R2"])

    def test_r2_ignores_other_subresources(self):
        self.assertEqual(rules_of(req(verb="get", subresource="log", name="backend-x")), [])
        self.assertEqual(rules_of(req(resource="services", subresource="exec")), [])

    def test_r3_on_code_or_decision(self):
        self.assertEqual(rules_of(req(code=403, decision=None)), ["R3"])
        self.assertEqual(rules_of(req(code=None, decision="forbid")), ["R3"])
        self.assertEqual(rules_of(req(code=404)), [])

    def test_alert_fields_and_severity(self):
        r = req(verb="create", subresource="exec", name="backend-x", code=403, decision="forbid")
        alerts = detect([r, req()])
        self.assertEqual(len(alerts), 2)
        for a in alerts:
            self.assertEqual(set(a), {"rule", "severity", "reason", "audit_ids", "time"})
            self.assertEqual(a["severity"], "high")
            self.assertEqual(a["audit_ids"], [r["audit_id"]])
            self.assertTrue(a["reason"])


if __name__ == "__main__":
    unittest.main()
