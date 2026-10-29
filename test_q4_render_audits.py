"""Q4 Render audit wording regressions; all HTTP traffic and state are local."""
import asyncio
import copy
import importlib.util
import json
from pathlib import Path
import unittest

from fastapi import HTTPException

ROOT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("q4_render_base", ROOT.parent / "ga5-src/test_q11_first_pass.py")
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)


def audit_fixture(tag, cause, *, freeze=1, maximum=11, target=11):
    body = base.fixture(tag, cause)
    service = body["incident"]["service"]
    if cause == "database_connection_exhaustion":
        observations = [
            f"{service} spends most of its request time waiting for database connections; connection acquisition repeatedly times out.",
            f"No new application release, feature edit or failed TLS peer correlates with the database-pool backlog. Operating replicas=10; contract maximum={maximum}; change freeze={freeze}. Proposed target={target}.",
            "Policy: scaling to the proposed target requires a contract maximum at least that large and freeze=0; otherwise page the owner.",
        ]
    else:
        observations = [
            f"{service} has increasing request queues and all workers saturated as arrival rate rises.",
            f"A trial replica drains additional requests. There is no contemporaneous database wait, flag edit, release or upstream failure. Operating replicas=10; contract maximum={maximum}; change freeze={freeze}. Proposed target={target}.",
            "Policy: scaling to the proposed target requires a contract maximum at least that large and freeze=0; otherwise page the owner.",
        ]
    body["incident"]["transcript"] = "\n".join("[ev_%s%d] correlated sample: %s" % (tag, i, text)
                                                     for i, text in enumerate(observations))
    for tool in body["toolCatalog"]:
        if tool["name"] == "page_owner":
            tool["inputSchema"]["required"] = ["service", "severity"]
    return body


class RenderAuditTests(unittest.TestCase):
    setUp = base.FirstPassTests.setUp
    client = base.FirstPassTests.client
    create = base.FirstPassTests.create
    receipt = base.FirstPassTests.receipt
    workflow = base.FirstPassTests.workflow

    def plan(self, body):
        return self.q11.heuristic_decision(body["incident"], body["policy"], body["toolCatalog"])

    def test_database_acquisition_without_pool_word_is_supported(self):
        body = audit_fixture("dbwording", "database_connection_exhaustion")
        plan = self.plan(body)
        self.assertEqual(plan["rootCause"], "database_connection_exhaustion")
        self.assertEqual([step["toolName"] for step in plan["diagnostics"]], ["query_logs", "query_metrics"])
        self.assertEqual(plan["effect"]["toolName"], "page_owner")

    def test_arrival_rate_with_saturated_workers_is_supported(self):
        body = audit_fixture("trafficwording", "traffic_capacity_exhaustion")
        plan = self.plan(body)
        self.assertEqual(plan["rootCause"], "traffic_capacity_exhaustion")
        self.assertEqual([step["toolName"] for step in plan["diagnostics"]], ["query_metrics"])
        self.assertEqual(plan["effect"]["toolName"], "page_owner")

    def test_close_paraphrases_keep_the_same_causal_relations(self):
        cases = [
            ("database_connection_exhaustion", "connection acquisition repeatedly times out", "connection acquisition has repeatedly timed out"),
            ("database_connection_exhaustion", "connection acquisition repeatedly times out", "connection checkout repeatedly times out"),
            ("traffic_capacity_exhaustion", "workers saturated as arrival rate rises", "workers are saturated as arrival rate increases"),
        ]
        for index, (cause, old, new) in enumerate(cases):
            with self.subTest(cause=cause, phrase=new):
                body = audit_fixture("paraphrase%d" % index, cause)
                body["incident"]["transcript"] = body["incident"]["transcript"].replace(old, new)
                self.assertEqual(self.plan(body)["rootCause"], cause)

    def test_change_freeze_and_capacity_bounds_remain_authoritative(self):
        for cause in ("database_connection_exhaustion", "traffic_capacity_exhaustion"):
            for freeze, maximum, target, expected in ((1, 11, 11, "page_owner"),
                                                       (0, 11, 11, "scale_service"),
                                                       (0, 11, 12, "page_owner")):
                with self.subTest(cause=cause, freeze=freeze, maximum=maximum, target=target):
                    body = audit_fixture("bounds", cause, freeze=freeze, maximum=maximum, target=target)
                    plan = self.plan(body)
                    self.assertEqual(plan["effect"]["toolName"], expected)
                    if expected == "scale_service":
                        self.assertEqual(plan["effect"]["arguments"]["targetReplicas"], target)

    def test_negated_and_conflicting_evidence_still_fail_closed(self):
        db = audit_fixture("negative", "database_connection_exhaustion")
        traffic = audit_fixture("negative", "traffic_capacity_exhaustion")
        signal_db = self.q11._offline_observations(db["incident"])[0]
        signal_traffic = self.q11._offline_observations(traffic["incident"])[0]
        for signal in ([signal_db, signal_traffic],
                       [("ev_negative", "correlated sample: No database connections were affected; connection acquisition never timed out.")],
                       [("ev_negative", "correlated sample: Database connections are normal and connection acquisition never times out.")],
                       [("ev_negative", "correlated sample: Database connections stay healthy and connection acquisition never has timeouts.")],
                       [("ev_negative", "correlated sample: Request queues and workers saturated, but the arrival rate never rises.")],
                       [("ev_unknown", "A generic error occurred; no cause is established.")]):
            with self.subTest(signal=signal):
                with self.assertRaises(HTTPException) as caught:
                    self.q11._classify_failure(signal, list(base.CAUSE_LINES))
                self.assertEqual(caught.exception.status_code, 422)

    def test_other_service_cannot_supply_the_diagnosis(self):
        body = audit_fixture("scope", "database_connection_exhaustion")
        body["incident"]["transcript"] = body["incident"]["transcript"].replace(
            body["incident"]["service"], "svc_other")
        with self.assertRaises(HTTPException) as caught:
            self.plan(body)
        self.assertEqual(caught.exception.status_code, 422)

    def test_http_lifecycles_preserve_trace_receipts_and_replay(self):
        async def run():
            async with self.client() as client:
                for index, cause in enumerate(("database_connection_exhaustion", "traffic_capacity_exhaustion")):
                    body = audit_fixture("workflow%d" % index, cause)
                    first = await self.create(client, body)
                    self.assertEqual(first.status_code, 200, first.text)
                    self.assertTrue(all(dispatch["phase"] == "diagnostic" for dispatch in first.json()["dispatches"]))
                    self.assertEqual(first.json()["approvals"], [])
                    final = await self.workflow(client, body)
                    self.assertEqual(final["diagnosis"]["rootCause"], cause)
                    self.assertEqual(final["chosenEffect"], "page_owner")
                    self.assertEqual(len([item for item in final["actionLog"] if item["phase"] == "effect"]), 1)
        asyncio.run(run())

    def test_exact_captured_failures_complete_after_the_wording_fix(self):
        paths = list(ROOT.parent.glob("q4-protected-analysis-*/failed-*.json"))
        if not paths:
            self.skipTest("No local protected audit captures available")

        async def run():
            async with self.client() as client:
                for index, path in enumerate(paths):
                    saved = json.loads(path.read_text(encoding="utf-8"))
                    body = copy.deepcopy(saved["body"])
                    body["runId"] = "run_captured_audit_%d" % index
                    body["publicMarker"] = "public_captured_audit_%d" % index
                    body["sensitive"] = {"accessToken": "private_captured_audit_%d" % index}
                    final = await self.workflow(client, body)
                    self.assertIn(final["diagnosis"]["rootCause"],
                                  ("database_connection_exhaustion", "traffic_capacity_exhaustion"))
                    self.assertEqual(final["chosenEffect"], "page_owner")
        asyncio.run(run())


if __name__ == "__main__":
    unittest.main()
