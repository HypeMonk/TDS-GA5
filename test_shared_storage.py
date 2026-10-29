"""Shared-database HTTP regressions using a caller-owned local PostgreSQL test server."""
import asyncio
import copy
from concurrent.futures import ThreadPoolExecutor
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import threading
import unittest
from urllib.parse import urlsplit
from unittest.mock import patch

from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import durable_store


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


invoice = module("shared_invoice_fixture", ROOT / "test_q10_evidence.py")
incident = module("shared_incident_fixture", ROOT.parent / "ga5-src/test_q11_first_pass.py")
HEADERS = {"Authorization": "Bearer local-shared-owner", "A2A-Version": "1.0",
           "Content-Type": "application/a2a+json"}


class ConfigurationTests(unittest.TestCase):
    def test_vercel_without_shared_database_fails_explicitly(self):
        with patch.dict(os.environ, {"VERCEL": "1"}, clear=True):
            self.assertFalse(durable_store.storage_status()["configured"])
            with self.assertRaises(sqlite3.OperationalError):
                durable_store.connect("/tmp/should-not-create.db")
            q = module("missing_store_q10", ROOT / "q10.py")
            app = FastAPI()
            app.include_router(q.router)
            response = SharedDatabaseTests.request(app, "GET", "/tasks", headers=HEADERS)
            self.assertEqual(response.status_code, 503)
            self.assertEqual(response.json()["error"]["code"], "STORAGE_UNAVAILABLE")
            self.assertEqual(response.headers["content-type"], "application/a2a+json")
            self.assertEqual(response.headers["cache-control"], "no-store")
            q4 = module("missing_store_q11", ROOT / "q11.py")
            app4 = FastAPI()
            app4.include_router(q4.router)
            response = SharedDatabaseTests.request(app4, "GET", "/v2/incidents/local-run")
            self.assertEqual(response.status_code, 503)

    def test_local_sqlite_still_works(self):
        with patch.dict(os.environ, {}, clear=True), tempfile.TemporaryDirectory() as folder:
            connection = durable_store.connect(str(Path(folder) / "state.db"))
            try:
                connection.execute("CREATE TABLE records(id TEXT PRIMARY KEY)")
                connection.execute("INSERT INTO records VALUES(?)", ("local-record",))
                connection.commit()
                self.assertEqual(connection.execute("SELECT id FROM records").fetchone()[0], "local-record")
            finally:
                connection.close()


@unittest.skipUnless(os.environ.get("SOLVER_TEST_DATABASE_URL"), "Set a local PostgreSQL test URL")
class SharedDatabaseTests(unittest.TestCase):
    def setUp(self):
        url = os.environ["SOLVER_TEST_DATABASE_URL"]
        parsed = urlsplit(url)
        if parsed.hostname not in ("127.0.0.1", "localhost") or parsed.path != "/ga5_local_test":
            raise RuntimeError("Tests require the disposable local ga5_local_test database")
        env = patch.dict(os.environ, {"SOLVER_DATABASE_URL": url, "VERCEL": "1", "DEBUG_KEY": "local-debug-key"})
        env.start()
        self.addCleanup(env.stop)
        self.temp = tempfile.TemporaryDirectory(prefix="shared-store-workers-")
        self.addCleanup(self.temp.cleanup)
        self.workers = []
        self.addCleanup(self.close)
        q, _ = self.worker("q10")
        q4, _ = self.worker("q11")
        q4._q11_state_connect().close()
        q.db().execute("TRUNCATE q10_msgs,q10_final,q10_tasks,q11_runs")

    def close(self):
        for q in self.workers:
            for attr in ("_conn", "_q11_wire_conn"):
                connection = getattr(q, attr, None)
                if connection is not None:
                    connection.close()

    def worker(self, name):
        q = module("shared_worker_%s_%d" % (name, len(self.workers)), ROOT / (name + ".py"))
        path = str(Path(self.temp.name) / ("instance_%d.db" % len(self.workers)))
        if name == "q10":
            q.DB_PATH = path
            q._TRACE_DB_PATH = path + ".traces"
            q._Q10_WIRE_KEY = ""
        else:
            q._Q11_WIRE_DB = path
            q._Q11_WIRE_KEY = ""
        self.workers.append(q)
        app = FastAPI()
        app.include_router(q.router)
        return q, app

    @staticmethod
    def request(app, method, path, body=None, headers=None):
        async def run():
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://local-shared") as client:
                return await client.request(method, path, json=body, headers=headers)
        return asyncio.run(run())

    def batch(self, q, identity="shared"):
        return {"message": {"messageId": "message-" + identity, "role": "ROLE_USER", "parts": [{
            "mediaType": q.MODE_BATCH, "data": {"batchId": "batch-" + identity,
            "packages": [invoice.invoice_package()]}}]}}

    def results(self, q, task, identity="receipt"):
        proposal = task["artifacts"][0]["parts"][0]["data"]["proposals"][0]
        return {"message": {"messageId": identity, "role": "ROLE_USER", "taskId": task["id"],
                "contextId": task["contextId"], "parts": [{"mediaType": q.MODE_RESULTS, "data": {
                    "batchId": task["metadata"]["batchId"], "results": [{
                        "packageId": proposal["packageId"], "actionId": proposal["actionId"],
                        "action": proposal["action"], "outcome": "ACCEPTED", "receiptNonce": "local-nonce"}]}}]}}

    def test_q2_new_worker_and_new_local_path_read_same_task(self):
        a, app_a = self.worker("q10")
        task = self.request(app_a, "POST", "/message:send", self.batch(a), HEADERS).json()["task"]
        a._conn.close()
        b, app_b = self.worker("q10")
        response = self.request(app_b, "GET", "/a2a/tasks/" + task["id"], headers=HEADERS)
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json(), task)
        self.assertFalse(Path(b.DB_PATH).exists())
        outsider = dict(HEADERS, Authorization="Bearer different-local-owner")
        self.assertEqual(self.request(app_b, "GET", "/tasks/" + task["id"], headers=outsider).status_code, 404)
        self.assertEqual(self.request(app_b, "GET", "/tasks", headers=outsider).json()["tasks"], [])

    def test_q2_twenty_concurrent_creates_are_one_complete_task(self):
        apps = [self.worker("q10")[1] for _ in range(20)]
        barrier = threading.Barrier(len(apps))
        body = self.batch(self.workers[0])
        def send(index, app):
            variant = copy.deepcopy(body)
            variant["configuration"] = {"returnImmediately": bool(index % 2)}
            barrier.wait(timeout=20)
            return self.request(app, "POST", "/message:send", variant, HEADERS)
        with ThreadPoolExecutor(max_workers=20) as pool:
            futures = [pool.submit(send, i, app) for i, app in enumerate(apps)]
            responses = [future.result(timeout=40) for future in futures]
        self.assertEqual(set(r.status_code for r in responses), {200})
        first = responses[0].json()["task"]
        self.assertTrue(all(r.json()["task"] == first for r in responses))
        self.assertEqual(first["state"], self.workers[0].INPUT_REQUIRED)
        self.assertEqual(len(self.request(apps[0], "GET", "/tasks", headers=HEADERS).json()["tasks"]), 1)

    def test_q2_twenty_cancel_receipt_races_have_exactly_one_winner(self):
        a, app_a = self.worker("q10")
        _, app_b = self.worker("q10")
        for i in range(20):
            task = self.request(app_a, "POST", "/message:send", self.batch(a, str(i)), HEADERS).json()["task"]
            barrier = threading.Barrier(2)
            def send(app, path, body=None):
                barrier.wait(timeout=10)
                return self.request(app, "POST", path, body, HEADERS)
            with ThreadPoolExecutor(max_workers=2) as pool:
                left = pool.submit(send, app_a, "/message:send", self.results(a, task, "receipt-" + str(i)))
                right = pool.submit(send, app_b, "/tasks/" + task["id"] + ":cancel")
                responses = [left.result(timeout=30), right.result(timeout=30)]
            self.assertEqual(sorted(r.status_code for r in responses), [200, 409])
            final = self.request(app_b, "GET", "/tasks/" + task["id"], headers=HEADERS).json()
            self.assertEqual(final, self.request(app_a, "GET", "/tasks/" + task["id"], headers=HEADERS).json())
            receipts = [p for art in final["artifacts"] for p in art["parts"] if p["mediaType"] == a.MODE_RECEIPTS]
            self.assertEqual(bool(receipts), final["state"] == a.COMPLETED)

    def test_q2_reconnect_reads_committed_task(self):
        a, app_a = self.worker("q10")
        task = self.request(app_a, "POST", "/message:send", self.batch(a), HEADERS).json()["task"]
        a._conn.close()
        response = self.request(app_a, "GET", "/tasks/" + task["id"], headers=HEADERS)
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json(), task)

    def test_q4_concurrent_creates_and_receipts_survive_new_workers(self):
        a, app_a = self.worker("q11")
        _, app_b = self.worker("q11")
        body = incident.fixture("shared-incident")
        barrier = threading.Barrier(2)
        def create(app):
            barrier.wait(timeout=10)
            return self.request(app, "POST", "/v2/incidents", body)
        with ThreadPoolExecutor(max_workers=2) as pool:
            l = pool.submit(create, app_a)
            r = pool.submit(create, app_b)
            responses = [l.result(timeout=30), r.result(timeout=30)]
        self.assertEqual([r.status_code for r in responses], [200, 200])
        self.assertEqual(responses[0].json(), responses[1].json())
        current = responses[0].json()
        for step in range(6):
            _, app = self.worker("q11")
            self.assertEqual(self.request(app, "GET", "/v2/incidents/" + body["runId"]).json(), current)
            if current["status"] in ("completed", "failed"):
                break
            payload = {"receiptId": "shared-receipt-%d" % step, "outcomes": []}
            for d in current["dispatches"]:
                item = {key: d[key] for key in ("actionId", "callId", "attempt")}
                item.update(status=200, resultClass="diagnosis_confirmed" if d["phase"] == "diagnostic" else "effect_applied", nonce="local-nonce")
                payload["outcomes"].append(item)
            response = self.request(app, "POST", "/v2/incidents/" + body["runId"] + "/receipts", payload)
            self.assertEqual(response.status_code, 200, response.text)
            current = response.json()
        self.assertEqual(current["status"], "completed")
        self.assertEqual(self.request(app_a, "POST", "/v2/incidents", body).json(), current)
        self.assertFalse(Path(a._Q11_WIRE_DB).exists())

    def test_diagnostic_rows_and_traces_are_shared_without_local_files(self):
        import request_diagnostics
        a, app_a = self.worker("q10")
        a._Q10_WIRE_KEY = "local-debug-key"
        task = self.request(app_a, "POST", "/message:send", self.batch(a), HEADERS).json()["task"]
        b, app_b = self.worker("q10")
        b._Q10_WIRE_KEY = "local-debug-key"
        trace_index = self.request(app_b, "GET", "/debug/q10/traces", headers={"X-Debug-Key": "local-debug-key"})
        self.assertEqual(trace_index.status_code, 200, trace_index.text)
        self.assertTrue(any(row["task_id"] == task["id"] for row in trace_index.json()["rows"]))
        request_diagnostics.record("q11", {"timestamp": 100, "method": "POST", "status_code": 200, "body": "{}"})
        self.assertTrue(any(row["timestamp"] == 100 for row in request_diagnostics.rows("q11")))
        self.assertFalse(Path(a._TRACE_DB_PATH).exists())

    def test_q4_receipt_compare_and_swap_prevents_lost_updates(self):
        a, app_a = self.worker("q11")
        _, app_b = self.worker("q11")
        body = incident.fixture("shared-cas", "deployment_regression")
        first = self.request(app_a, "POST", "/v2/incidents", body).json()
        receipts = []
        for i, d in enumerate(first["dispatches"]):
            outcome = {key: d[key] for key in ("actionId", "callId", "attempt")}
            outcome.update(status=200, resultClass="diagnosis_confirmed", nonce="cas-nonce-%d" % i)
            receipts.append({"receiptId": "cas-receipt-%d" % i, "outcomes": [outcome]})
        barrier = threading.Barrier(2)
        def send(app, payload):
            barrier.wait(timeout=10)
            return self.request(app, "POST", "/v2/incidents/" + body["runId"] + "/receipts", payload)
        with ThreadPoolExecutor(max_workers=2) as pool:
            l = pool.submit(send, app_a, receipts[0])
            r = pool.submit(send, app_b, receipts[1])
            responses = [l.result(timeout=30), r.result(timeout=30)]
        self.assertEqual([r.status_code for r in responses], [200, 200])
        current = self.request(app_b, "GET", "/v2/incidents/" + body["runId"]).json()
        self.assertEqual(len(current["approvals"]), 1)
        state = a._load_incident(body["runId"])
        self.assertEqual(len(state["receipts_seen"]), 2)


if __name__ == "__main__":
    unittest.main()
