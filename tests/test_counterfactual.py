import copy
import json
import os
import unittest

from detector.parser import DEFAULT_SA, group_requests
from evaluation.evaluate import counterfactual

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load(name):
    with open(os.path.join(ROOT, "category3", "logs", name), encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


class CounterfactualTest(unittest.TestCase):
    def setUp(self):
        sa_event = load("abnormal_1.log")[0]
        other = copy.deepcopy(sa_event)
        other["user"]["username"] = "system:serviceaccount:pbl-security:someone-else"
        other["auditID"] = "other-1"
        self.events = [sa_event, other]
        self.original = copy.deepcopy(self.events)

    def test_watched_sa_403_becomes_200_allow(self):
        req = group_requests(counterfactual(self.events))[0]
        self.assertEqual(req["code"], 200)
        self.assertEqual(req["decision"], "allow")

    def test_other_users_are_unchanged(self):
        out = counterfactual(self.events)
        self.assertEqual(out[1], self.original[1])
        self.assertEqual(out[1]["responseStatus"]["code"], 403)

    def test_input_is_not_modified(self):
        counterfactual(self.events)
        self.assertEqual(self.events, self.original)

    def test_allowed_requests_stay_the_same(self):
        events = load("normal.log")
        self.assertEqual(counterfactual(events, DEFAULT_SA), events)


if __name__ == "__main__":
    unittest.main()
