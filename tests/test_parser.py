import json
import os
import unittest

from detector.parser import DEFAULT_SA, parse_file, parse_lines

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOGS = os.path.join(ROOT, "category3", "logs")


def sample_lines(name):
    with open(os.path.join(LOGS, name), encoding="utf-8") as f:
        return [line for line in f if line.strip()]


def request_received(line):
    """Build the RequestReceived line that precedes a ResponseComplete line."""
    event = json.loads(line)
    event["stage"] = "RequestReceived"
    event.pop("responseStatus", None)
    event.pop("annotations", None)
    event.pop("stageTimestamp", None)
    return json.dumps(event)


class ParserTest(unittest.TestCase):
    def test_sample_normal(self):
        requests, skipped = parse_file(os.path.join(LOGS, "normal.log"))
        self.assertEqual(skipped, 0)
        self.assertEqual(len(requests), 4)
        self.assertEqual([r["code"] for r in requests], [200] * 4)
        get_pod = [r for r in requests if r["verb"] == "get"][0]
        self.assertEqual(get_pod["resource"], "pods")
        self.assertIsNotNone(get_pod["name"])
        self.assertTrue(all(r["name"] is None for r in requests if r["verb"] == "list"))

    def test_audit_id_grouping(self):
        line = sample_lines("abnormal_1.log")[0]
        requests, _ = parse_lines([request_received(line), line])
        self.assertEqual(len(requests), 1)
        req = requests[0]
        self.assertEqual(req["stages"], ["RequestReceived", "ResponseComplete"])
        # Representative line is ResponseComplete even though it is not first.
        self.assertEqual(req["code"], 403)
        self.assertEqual(req["decision"], "forbid")

    def test_grouping_without_response_complete_uses_last_stage(self):
        line = sample_lines("abnormal_1.log")[0]
        requests, _ = parse_lines([request_received(line)])
        self.assertEqual(requests[0]["stages"], ["RequestReceived"])
        self.assertIsNone(requests[0]["code"])

    def test_forbidden_secret_list(self):
        requests, _ = parse_file(os.path.join(LOGS, "abnormal_1.log"))
        self.assertEqual(len(requests), 1)
        req = requests[0]
        self.assertEqual((req["verb"], req["resource"]), ("list", "secrets"))
        self.assertEqual(req["code"], 403)
        self.assertEqual(req["decision"], "forbid")

    def test_exec_subresource(self):
        requests, _ = parse_file(os.path.join(LOGS, "abnormal_2.log"))
        req = requests[0]
        self.assertEqual((req["verb"], req["resource"], req["subresource"]),
                         ("create", "pods", "exec"))
        self.assertIsNotNone(req["name"])
        self.assertEqual(req["code"], 403)

    def test_abnormal_3_request_count(self):
        requests, _ = parse_file(os.path.join(LOGS, "abnormal_3.log"))
        self.assertEqual(len(requests), 18)
        self.assertEqual(sum(1 for r in requests if r["code"] == 403), 6)

    def test_invalid_json_lines_are_skipped(self):
        lines = ["{not json", "", "[1, 2]"] + sample_lines("normal.log")
        requests, skipped = parse_lines(lines)
        self.assertEqual(skipped, 2)
        self.assertEqual(len(requests), 4)

    def test_other_users_are_dropped(self):
        event = json.loads(sample_lines("normal.log")[0])
        event["user"]["username"] = "kubernetes-admin"
        requests, _ = parse_lines([json.dumps(event)])
        self.assertEqual(requests, [])
        requests, _ = parse_lines([json.dumps(event)], sa="kubernetes-admin")
        self.assertEqual(len(requests), 1)

    def test_time_is_datetime(self):
        requests, _ = parse_file(os.path.join(LOGS, "normal.log"))
        self.assertIsNotNone(requests[0]["time"].tzinfo)
        self.assertEqual(DEFAULT_SA, "system:serviceaccount:pbl-security:pbl-crypto-platform-app")


if __name__ == "__main__":
    unittest.main()
