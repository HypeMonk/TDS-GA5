"""Invoice protocol checks with independent workers sharing only their database."""
import asyncio
import copy
from concurrent.futures import ThreadPoolExecutor
import importlib.util
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

ROOT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("invoice_fixtures", ROOT / "test_q10_evidence.py")
fixtures = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixtures)
HEADERS = {"Authorization": "Bearer local-invoice-owner", "A2A-Version": "1.0",
           "Content-Type": "application/a2a+json"}


class InvoiceAtomicityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="q10-atomicity-")
        self.addCleanup(self.temp.cleanup)
        self.workers = []
        self.addCleanup(self.close_workers)

    def close_workers(self):
        for worker in self.workers:
            if worker._conn is not None:
                worker._conn.close()

    def worker(self, *, database="shared.db"):
        spec = importlib.util.spec_from_file_location("invoice_worker_%d" % len(self.workers), ROOT / "q10.py")
        worker = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(worker)
        worker.DB_PATH = str(Path(self.temp.name) / database)
        worker._Q10_WIRE_KEY = ""
        self.workers.append(worker)
        app = FastAPI()
        app.include_router(worker.router)
        return worker, app

    def batch(self, worker, identity="one"):
        return {"message": {"messageId": "message-" + identity, "role": "ROLE_USER",
                "parts": [{"mediaType": worker.MODE_BATCH, "data": {
                    "batchId": "batch-" + identity, "policyRevision": "local-v1",
                    "packages": [fixtures.invoice_package("settle_invoice")]}}]}}

    def results(self, worker, task, identity="receipt"):
        proposal = task["artifacts"][0]["parts"][0]["data"]["proposals"][0]
        return {"message": {"messageId": "message-" + identity, "role": "ROLE_USER",
                "taskId": task["id"], "contextId": task["contextId"],
                "parts": [{"mediaType": worker.MODE_RESULTS, "data": {
                    "batchId": task["metadata"]["batchId"], "results": [{
                        "packageId": proposal["packageId"], "actionId": proposal["actionId"],
                        "action": proposal["action"], "outcome": "ACCEPTED", "receiptNonce": "local-receipt"}]}}]}}

    def request(self, app, method, path, body=None):
        async def exercise():
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://invoice-test") as client:
                return await client.request(method, path, json=body, headers=HEADERS)
        return asyncio.run(exercise())

    def test_receipt_scope_and_outcome_validation_does_not_mutate(self):
        worker, app = self.worker()
        first = self.request(app, "POST", "/message:send", self.batch(worker)).json()["task"]
        for variant in ("context", "batch", "duplicate", "outcome", "missing_outcome", "action", "nonce"):
            with self.subTest(variant=variant):
                body = self.results(worker, first)
                data = body["message"]["parts"][0]["data"]
                result = data["results"][0]
                if variant == "context": body["message"]["contextId"] = "wrong-context"
                elif variant == "batch": data["batchId"] = "wrong-batch"
                elif variant == "duplicate": data["results"].append(copy.deepcopy(result))
                elif variant == "outcome": result["outcome"] = "EXECUTED"
                elif variant == "missing_outcome": result.pop("outcome")
                elif variant == "action": result.pop("action")
                else: result["receiptNonce"] = ""
                response = self.request(app, "POST", "/message:send", body)
                self.assertEqual(response.status_code, 400, response.text)
                self.assertEqual(self.request(app, "GET", "/tasks/" + first["id"]).json(), first)

    def test_concurrent_equivalent_creates_are_one_complete_task(self):
        a, app_a = self.worker()
        b, app_b = self.worker()
        for worker in (a, b): worker.db()
        barrier = threading.Barrier(2)
        def send(app, body):
            barrier.wait(timeout=10)
            return self.request(app, "POST", "/message:send", body)
        body = self.batch(a)
        other = copy.deepcopy(body)
        other["configuration"] = {"returnImmediately": True}
        with ThreadPoolExecutor(max_workers=2) as pool:
            left = pool.submit(send, app_a, body)
            right = pool.submit(send, app_b, other)
            responses = [left.result(timeout=20), right.result(timeout=20)]
        self.assertTrue(all(r.status_code == 200 for r in responses))
        tasks = [r.json()["task"] for r in responses]
        self.assertEqual(tasks[0], tasks[1])
        self.assertEqual(tasks[0]["state"], a.INPUT_REQUIRED)
        self.assertEqual(len(self.request(app_a, "GET", "/tasks").json()["tasks"]), 1)

    def test_message_conflict_is_checked_for_continuations_too(self):
        worker, app = self.worker()
        first_body = self.batch(worker)
        task = self.request(app, "POST", "/message:send", first_body).json()["task"]
        continuation = self.results(worker, task)
        continuation["message"]["messageId"] = first_body["message"]["messageId"]
        response = self.request(app, "POST", "/message:send", continuation)
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.json()["error"]["code"], "IDEMPOTENCY_CONFLICT")
        self.assertEqual(self.request(app, "GET", "/tasks/" + task["id"]).json(), task)

    def test_cancel_and_receipt_have_one_winner_across_workers(self):
        a, app_a = self.worker()
        b, app_b = self.worker()
        for worker in (a, b): worker.db()
        for index in range(12):
            task = self.request(app_a, "POST", "/message:send", self.batch(a, str(index))).json()["task"]
            barrier = threading.Barrier(2)
            def send(app, path, body=None):
                barrier.wait(timeout=10)
                return self.request(app, "POST", path, body)
            with ThreadPoolExecutor(max_workers=2) as pool:
                receipt = pool.submit(send, app_a, "/message:send", self.results(a, task, str(index)))
                cancel = pool.submit(send, app_b, "/tasks/" + task["id"] + ":cancel")
                responses = [receipt.result(timeout=20), cancel.result(timeout=20)]
            self.assertEqual(sorted(r.status_code for r in responses), [200, 409])
            final = self.request(app_a, "GET", "/tasks/" + task["id"]).json()
            self.assertEqual(final, self.request(app_b, "GET", "/tasks/" + task["id"]).json())
            receipts = [p for art in final["artifacts"] for p in art["parts"] if p["mediaType"] == a.MODE_RECEIPTS]
            self.assertEqual(bool(receipts), final["state"] == a.COMPLETED)

    def test_separate_instance_files_cannot_share_state(self):
        a, app_a = self.worker(database="instance-a.db")
        _b, app_b = self.worker(database="instance-b.db")
        task = self.request(app_a, "POST", "/message:send", self.batch(a)).json()["task"]
        self.assertEqual(self.request(app_b, "GET", "/tasks/" + task["id"]).status_code, 404)

    def test_rejected_results_complete_without_execution(self):
        worker, app = self.worker()
        task = self.request(app, "POST", "/message:send", self.batch(worker)).json()["task"]
        body = self.results(worker, task)
        body["message"]["parts"][0]["data"]["results"][0]["outcome"] = "REJECTED"
        response = self.request(app, "POST", "/message:send", body)
        self.assertEqual(response.status_code, 200, response.text)
        final = response.json()["task"]
        self.assertEqual(final["state"], worker.COMPLETED)
        self.assertEqual(final["artifacts"][-1]["parts"][0]["data"]["executions"], [])
        self.assertEqual(self.request(app, "POST", "/message:send", body).json()["task"], final)

    def test_new_message_id_on_terminal_replay_is_reserved(self):
        worker, app = self.worker()
        task = self.request(app, "POST", "/message:send", self.batch(worker)).json()["task"]
        receipt = self.results(worker, task)
        final = self.request(app, "POST", "/message:send", receipt).json()["task"]
        replay = copy.deepcopy(receipt)
        replay["message"]["messageId"] = "new-terminal-replay-id"
        self.assertEqual(self.request(app, "POST", "/message:send", replay).json()["task"], final)
        changed = copy.deepcopy(replay)
        changed["message"]["parts"][0]["data"]["results"][0]["outcome"] = "REJECTED"
        response = self.request(app, "POST", "/message:send", changed)
        self.assertEqual(response.status_code, 409, response.text)
        self.assertEqual(response.json()["error"]["code"], "IDEMPOTENCY_CONFLICT")

    def test_failed_planning_rolls_back_the_message_reservation(self):
        worker, app = self.worker()
        body = self.batch(worker)
        with patch.object(worker, "decide", side_effect=RuntimeError("local injected failure")):
            with self.assertRaises(RuntimeError): self.request(app, "POST", "/message:send", body)
        self.assertEqual(self.request(app, "GET", "/tasks").json()["tasks"], [])
        response = self.request(app, "POST", "/message:send", body)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["task"]["state"], worker.INPUT_REQUIRED)


if __name__ == "__main__":
    unittest.main()
