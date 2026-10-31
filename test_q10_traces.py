"""Local-only tests for authenticated, durable invoice diagnostics."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import sys
import types
import unittest
from unittest.mock import patch

from fastapi import APIRouter, FastAPI
from httpx import ASGITransport, AsyncClient

ROOT = Path(__file__).resolve().parent


def module(name):
    spec = importlib.util.spec_from_file_location("trace_test_" + name, ROOT / (name + ".py"))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def package(pid="pkg-trace"):
    records = [
        "[R_SIGNED01] Signed commercial instrument INV-TEST-1 covers order PO-TEST-1, payee AC-111 and USD 123.45.",
        "[R_LEDGER01] Payment ledger: a disbursement for USD 123.45 to Example Supplier previously settled order PO-TEST-1. The currently submitted order is PO-TEST-1.",
        "[R_CONTROL1] Payment controls: do not pay a commercial order already discharged; a material order/invoice difference requires the exception process; an unverified bank change pauses payment. Otherwise follow the delegation limit.",
    ]
    return {"packageId": pid, "documents": [{"name": f"current-{i}.txt", "text": text} for i, text in enumerate(records)]}


class TraceTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.folder = tempfile.TemporaryDirectory(prefix="q10-trace-test-")
        self.q = module("q10")
        self.q.DB_PATH = str(Path(self.folder.name) / "tasks.db")
        self.q._TRACE_DB_PATH = str(Path(self.folder.name) / "traces.db")
        self.q._Q10_WIRE_KEY = "test-only-debug-secret"
        self.app = FastAPI()
        self.app.include_router(self.q.router)
        self.client = AsyncClient(transport=ASGITransport(app=self.app, raise_app_exceptions=False), base_url="http://test")
        self.headers = {"Authorization": "Bearer test-owner-credential", "A2A-Version": "1.0", "Content-Type": self.q.A2A_MEDIA_TYPE}
        self.admin = {"X-Debug-Key": self.q._Q10_WIRE_KEY}

    async def asyncTearDown(self):
        await self.client.aclose()
        if self.q._conn is not None:
            self.q._conn.close()
        if hasattr(self, "suite"):
            self.suite.close()
        self.folder.cleanup()

    def batch(self, message_id="msg-start", packages=None):
        return {"message": {"messageId": message_id, "role": "ROLE_USER", "parts": [{
            "mediaType": self.q.MODE_BATCH, "data": {"batchId": "batch-trace", "policyRevision": "test-v1",
                "packages": packages if packages is not None else [package()]}}]}}

    async def index(self, **params):
        response = await self.client.get("/debug/q10/traces", headers=self.admin, params=params)
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()

    async def detail(self, trace_id):
        response = await self.client.get(f"/debug/q10/traces/{trace_id}", headers=self.admin)
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()

    async def test_full_capture_redaction_replay_and_receipt_correlation(self):
        batch = self.batch(packages=[package("pkg-accepted"), package("pkg-rejected")])
        batch["configuration"] = {"token": "body-credential", "debugKey": "nested-debug-credential"}
        sent = await self.client.post("/a2a/message:send", headers=self.headers, json=batch)
        self.assertEqual(sent.status_code, 200, sent.text)
        task = sent.json()["task"]
        index = await self.index(taskId=task["id"])
        self.assertEqual(len(index["rows"]), 1)
        trace = await self.detail(index["rows"][0]["id"])
        self.assertEqual(trace["solverVersion"], self.q.SOLVER_VERSION)
        self.assertEqual(trace["request"]["receivedBytes"], len(sent.request.content))
        self.assertEqual(trace["request"]["sha256"], hashlib.sha256(sent.request.content).hexdigest())
        self.assertFalse(trace["request"]["truncated"])
        self.assertEqual(trace["request"]["body"]["configuration"]["token"], "[REDACTED]")
        self.assertEqual(trace["response"]["body"], sent.json())
        self.assertEqual(trace["taskId"], task["id"])
        self.assertEqual(trace["messageId"], "msg-start")
        self.assertEqual(trace["decisions"][0]["parser"], "distributed")
        self.assertEqual(trace["decisions"][0]["factProvenance"]["invoiceNumber"]["status"], "present_in_source")
        self.assertTrue(trace["decisions"][0]["relationships"][0]["sameOrder"])
        for secret in ("test-owner-credential", "body-credential", "nested-debug-credential", self.q._Q10_WIRE_KEY):
            self.assertNotIn(secret, json.dumps(trace))
        replay = await self.client.post("/a2a/message:send", headers=self.headers, json=batch)
        self.assertEqual(replay.json(), sent.json())
        latest = await self.index(taskId=task["id"])
        self.assertEqual((await self.detail(latest["rows"][0]["id"]))["decisions"], [])
        proposals = task["artifacts"][0]["parts"][0]["data"]["proposals"]
        results = [{"packageId": p["packageId"], "actionId": p["actionId"], "action": p["action"],
                    "outcome": "ACCEPTED" if i == 0 else "REJECTED", "receiptNonce": f"receipt-{i}"}
                   for i, p in enumerate(proposals)]
        continuation = {"message": {"messageId": "msg-results", "taskId": task["id"], "contextId": task["contextId"],
                        "role": "ROLE_USER", "parts": [{"mediaType": self.q.MODE_RESULTS,
                        "data": {"batchId": "batch-trace", "results": results}}]}}
        final = await self.client.post("/message:send", headers=self.headers, json=continuation)
        self.assertEqual(final.status_code, 200, final.text)
        executions = final.json()["task"]["artifacts"][-1]["parts"][0]["data"]["executions"]
        self.assertEqual([e["packageId"] for e in executions], ["pkg-accepted"])
        newest = await self.index(taskId=task["id"])
        result_trace = await self.detail(newest["rows"][0]["id"])
        self.assertEqual(result_trace["outcomes"], results)
        self.assertEqual(result_trace["taskId"], trace["taskId"])
        self.assertEqual(newest["captureFailures"], 0)

    async def test_authorization_and_outsider_request_are_isolated(self):
        for path in ("/debug/q10/traces", "/debug/q10/traces/1"):
            self.assertEqual((await self.client.get(path)).status_code, 403)
            self.assertEqual((await self.client.get(path, headers={"X-Debug-Key": "wrong"})).status_code, 403)
            self.assertEqual((await self.client.get(path, params={"key": self.q._Q10_WIRE_KEY})).status_code, 403)
        sent = await self.client.post("/message:send", headers=self.headers, json=self.batch())
        task_id = sent.json()["task"]["id"]
        outsider = dict(self.headers, Authorization="Bearer outsider")
        response = await self.client.get(f"/tasks/{task_id}", headers=outsider)
        self.assertEqual(response.status_code, 404)
        self.assertNotIn(task_id, response.text)
        rows = (await self.index(taskId=task_id))["rows"]
        self.assertEqual(rows[0]["status"], 404)
        self.assertEqual((await self.index(taskId="' OR 1=1 --"))["rows"], [])

    async def test_disabled_capture_does_not_create_a_trace_database(self):
        self.q._Q10_WIRE_KEY = ""
        response = await self.client.post("/message:send", headers=self.headers, json=self.batch())
        self.assertEqual(response.status_code, 200)
        self.assertFalse(Path(self.q._TRACE_DB_PATH).exists())
        self.assertEqual((await self.client.get("/debug/q10/traces", headers=self.admin)).status_code, 403)

    async def test_capture_storage_failure_does_not_fail_the_request(self):
        self.q._TRACE_DB_PATH = self.folder.name
        response = await self.client.post("/message:send", headers=self.headers, json=self.batch())
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(self.q._TRACE_FAILURES, 1)
        self.assertEqual(self.q._TRACE_LAST_ERROR, "OperationalError")
        task_id = response.json()["task"]["id"]
        self.assertEqual(self.q.load_task(task_id)[0]["state"], self.q.INPUT_REQUIRED)

    async def test_omitted_bodies_are_explicit_and_requests_still_work(self):
        self.q._TRACE_BODY_LIMIT = 64
        response = await self.client.post("/message:send", headers=self.headers, json=self.batch())
        self.assertEqual(response.status_code, 200)
        index = await self.index()
        trace = await self.detail(index["rows"][0]["id"])
        self.assertTrue(trace["request"]["truncated"])
        self.assertEqual(trace["request"]["omittedReason"], "body_size_limit")
        self.assertEqual(trace["request"]["storedBytes"], 0)
        self.assertEqual(trace["request"]["receivedBytes"], len(response.request.content))

    async def test_invalid_json_and_unhandled_error_are_captured(self):
        response = await self.client.post("/message:send", headers=self.headers, content=b'{"token":"broken-secret"')
        self.assertEqual(response.status_code, 400)
        index = await self.index()
        trace = await self.detail(index["rows"][0]["id"])
        self.assertEqual(trace["request"]["omittedReason"], "invalid_json")
        self.assertNotIn("broken-secret", json.dumps(trace))
        with patch.object(self.q, "decide", side_effect=RuntimeError("exception-secret")):
            failed = await self.client.post("/message:send", headers=self.headers, json=self.batch())
        self.assertEqual(failed.status_code, 500)
        newest = await self.index()
        error_trace = await self.detail(newest["rows"][0]["id"])
        self.assertEqual(error_trace["errorType"], "RuntimeError")
        self.assertNotIn("exception-secret", json.dumps(error_trace))

    async def test_retention_pagination_and_read_only_inspection(self):
        self.q._TRACE_ROW_LIMIT = 3
        for index in range(5):
            response = await self.client.post("/message:send", headers=self.headers, json=self.batch(f"msg-{index}"))
            self.assertEqual(response.status_code, 200)
        first = await self.index(limit=2)
        self.assertEqual(len(first["rows"]), 2)
        second = await self.index(limit=2, before=first["nextBefore"])
        self.assertEqual(len(second["rows"]), 1)
        self.assertIsNone(second["nextBefore"])
        self.assertEqual(len((await self.index())["rows"]), 3)
        self.assertEqual(self.q.db().execute("SELECT count(*) FROM q10_tasks").fetchone()[0], 5)
        self.assertEqual((await self.client.get("/debug/q10/traces/1", headers=self.admin)).status_code, 404)
        self.assertEqual((await self.client.get("/debug/q10/traces", headers=self.admin, params={"limit": "bad"})).status_code, 400)

    async def test_retention_bounds_serialized_payload_bytes(self):
        self.q._TRACE_STORAGE_LIMIT = 1800
        for index in range(6):
            self.q._trace_store({"received": index, "status": 200, "data": "x" * 700})
        rows = self.q._trace_rows(limit=100)
        self.assertLessEqual(sum(row["payload_bytes"] for row in rows), self.q._TRACE_STORAGE_LIMIT)
        self.assertEqual(len(rows), 2)

    async def test_oversized_event_keeps_bounded_metadata_instead_of_silently_exceeding_retention(self):
        self.q._TRACE_STORAGE_LIMIT = 1800
        self.q._trace_store({"received": 1, "status": 200, "data": "x" * 5000})
        rows = self.q._trace_rows(limit=10)
        self.assertEqual(len(rows), 1)
        self.assertLessEqual(rows[0]["payload_bytes"], 1800)
        detail = await self.detail(rows[0]["id"])
        self.assertEqual(detail["omittedReason"], "event_size_limit")
        self.assertGreater(detail["originalPayloadBytes"], 5000)

    async def test_main_middleware_preserves_body_and_redacts_debug_key(self):
        unrelated = {}
        for name in ("q8", "q9", "q11"):
            unrelated[name] = types.ModuleType(name)
            unrelated[name].router = APIRouter()
        with patch.dict(sys.modules, {**unrelated, "q10": self.q, "q10_variants": module("q10_variants")}):
            main = module("main")
        main._DEBUG_KEY = self.q._Q10_WIRE_KEY
        self.suite = main.Q2_SUITE
        async with AsyncClient(transport=ASGITransport(app=main.app), base_url="http://test") as client:
            sent = await client.post("/message:send", headers=self.headers, json=self.batch())
            self.assertEqual(sent.status_code, 200, sent.text)
            trace_index = await client.get("/debug/q10/traces", headers=self.admin)
            self.assertEqual(trace_index.status_code, 200)
            trace_id = trace_index.json()["rows"][0]["id"]
            detail = await client.get(f"/debug/q10/traces/{trace_id}", headers=self.admin)
            self.assertEqual(detail.json()["request"]["body"], self.batch())
            public = await client.get("/debug/logs/q10")
            self.assertNotIn(self.q._Q10_WIRE_KEY, public.text)
            self.assertNotIn("test-owner-credential", public.text)
            self.assertEqual((await client.get("/health")).json()["version"], "offline-v36-d")
            for index in range(5):
                main.LOGS_Q11.append({"timestamp": float(index + 1), "method": "POST",
                    "url": "http://test/v2/incidents", "headers": {"x-debug-key": "q11-secret"},
                    "body": json.dumps({"sensitive": {"accessToken": "private-q11"}, "index": index,
                                        "incident": {"transcript": "private incident transcript"},
                                        "dispatch": {"arguments": {"service": "svc-private"}}}),
                    "status_code": 200, "duration_ms": 1, "error": None, "response_body": "{}"})
            self.assertEqual((await client.get("/debug/logs/q11", params={"limit": 2})).status_code, 403)
            self.assertEqual((await client.get("/debug/logs/q11", params={"key": main._DEBUG_KEY})).status_code, 403)
            self.assertEqual((await client.get("/debug/logs/q11", headers={"X-Debug-Key": "wrong"})).status_code, 403)
            recent = await client.get("/debug/logs/q11", headers=self.admin, params={"limit": 2, "before": 6})
            self.assertEqual([json.loads(row["body"])["index"] for row in recent.json()], [3, 4])
            self.assertNotIn("q11-secret", recent.text)
            self.assertNotIn("private-q11", recent.text)
            self.assertIn("private incident transcript", recent.text)
            self.assertIn("svc-private", recent.text)
            older = await client.get("/debug/logs/q11", headers=self.admin, params={"limit": 2, "before": 4})
            self.assertEqual([json.loads(row["body"])["index"] for row in older.json()], [1, 2])
            public_all = await client.get("/debug/logs")
            self.assertNotIn("private incident transcript", public_all.text)
            self.assertNotIn("svc-private", public_all.text)
            self.assertNotIn("private-q11", public_all.text)

    async def test_trace_generation_cannot_change_decision(self):
        plain = self.q.decide(package())
        trace = {}
        self.assertEqual(self.q.decide(package(), trace=trace), plain)
        with patch.object(self.q, "_decision_trace", side_effect=ValueError("broken trace")):
            broken = {}
            self.assertEqual(self.q.decide(package(), trace=broken), plain)
        self.assertEqual(broken["traceError"], "ValueError")


if __name__ == "__main__":
    unittest.main()
