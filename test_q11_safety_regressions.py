"""Local Q4 fail-closed target, policy, telemetry, and creation regressions."""
import asyncio
import copy
from concurrent.futures import ThreadPoolExecutor
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

from fastapi import FastAPI, HTTPException
from httpx import ASGITransport, AsyncClient

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
spec = importlib.util.spec_from_file_location("q4_base", ROOT.parent / "ga5-src/test_q11_first_pass.py")
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)


class SafetyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="q4-safety-")
        self.addCleanup(self.temp.cleanup)
        clean_env = {key: value for key, value in os.environ.items()
                     if key not in ("SOLVER_DATABASE_URL", "POSTGRES_URL", "DATABASE_URL", "VERCEL")}
        env = patch.dict(os.environ, clean_env, clear=True)
        env.start()
        self.addCleanup(env.stop)
        self.modules = []
        self.addCleanup(self.close)
        self.q, self.app = self.worker()

    def close(self):
        for q in self.modules:
            if q._q11_wire_conn is not None:
                q._q11_wire_conn.close()

    def worker(self):
        spec = importlib.util.spec_from_file_location("q4_safety_" + str(len(self.modules)), ROOT / "q11.py")
        q = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(q)
        q._Q11_WIRE_DB = str(Path(self.temp.name) / "shared.db")
        q._Q11_WIRE_KEY = "test-debug-key"
        self.modules.append(q)
        app = FastAPI()
        app.include_router(q.router)
        return q, app

    def request(self, app, method, path, body=None, headers=None):
        async def run():
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://local-test") as client:
                return await client.request(method, path, json=body, headers=headers)
        return asyncio.run(run())

    def test_lone_broken_release_is_never_rollback_target(self):
        body = base.fixture("broken", "deployment_regression")
        body["incident"]["transcript"] = body["incident"]["transcript"].replace(
            "the previous healthy release r1-GOOD has no matching errors",
            "only the active release r2-BAD is listed and it is broken")
        decision = self.q.heuristic_decision(body["incident"], body["policy"], body["toolCatalog"])
        self.assertNotEqual(decision["effect"]["toolName"], "rollback_deployment")

    def test_destructive_only_catalog_never_fabricates_target(self):
        for name in ("rollback_deployment", "disable_feature"):
            with self.subTest(tool=name):
                self.assertIsNone(self.q._choose_effect("deployment_regression", [name], set(), None, None))

    def test_healthy_flag_preceding_causal_flag_is_not_selected(self):
        body = base.fixture("flags", "feature_flag_recursion")
        body["incident"]["transcript"] = body["incident"]["transcript"].replace(
            "feature flag flag_loop123 enables recursive evaluation",
            "flag_safe123 remains healthy with no recursion; feature flag flag_loop123 enables recursive evaluation")
        decision = self.q.heuristic_decision(body["incident"], body["policy"], body["toolCatalog"])
        self.assertEqual(decision["effect"]["arguments"]["flag"], "flag_loop123")

    def test_same_clause_healthy_and_bad_releases_are_not_tied(self):
        text = "release r1-GOOD is the previous healthy release, while release r2-BAD introduced malformed errors"
        self.assertEqual(self.q._parse_release(text), "r1-GOOD")
        self.assertIsNone(self.q._parse_release("r1-GOOD and r2-GOOD are both healthy releases"))

    def test_known_mutating_tool_cannot_be_a_diagnostic(self):
        body = base.fixture("diagnostic", "deployment_regression", effect=False)
        body["toolCatalog"] = [{"name": "rollback_deployment", "inputSchema": {"required": ["service", "release"]}}]
        with self.assertRaises(HTTPException) as exc:
            self.q.heuristic_decision(body["incident"], body["policy"], body["toolCatalog"])
        self.assertEqual(exc.exception.status_code, 422)

    def test_missing_prescribed_safe_effect_does_not_fall_through(self):
        body = base.fixture("runbook", "deployment_regression")
        body["incident"]["transcript"] += "\n[ev_rule] 2026-05-18T03:09:30Z correlated sample: The current runbook requires paging the service owner rather than deployment rollback."
        body["toolCatalog"] = [tool for tool in body["toolCatalog"] if tool["name"] != "page_owner"]
        with self.assertRaises(HTTPException) as exc:
            self.q.heuristic_decision(body["incident"], body["policy"], body["toolCatalog"])
        self.assertEqual(exc.exception.status_code, 422)

    def test_destructive_approval_cannot_be_removed_by_incomplete_policy(self):
        body = base.fixture("gate", "deployment_regression")
        body["policy"]["approvalRequiredFor"] = []
        decision = self.q.heuristic_decision(body["incident"], body["policy"], body["toolCatalog"])
        self.assertTrue(decision["effect"]["needs_approval"])

    def test_sensitive_tracestate_is_rejected_and_valid_context_is_preserved(self):
        body = base.fixture("trace")
        headers = {"traceparent": "00-" + "a" * 32 + "-" + "b" * 16 + "-01",
                   "tracestate": "vendor=" + body["sensitive"]["accessToken"]}
        response = self.request(self.app, "POST", "/v2/incidents", body, headers)
        self.assertEqual(response.status_code, 422)
        self.assertNotIn(body["sensitive"]["accessToken"], response.text + str(response.headers))
        body["runId"] += "-valid"
        headers["tracestate"] = "vendor=valid"
        response = self.request(self.app, "POST", "/v2/incidents", body, headers)
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.headers["tracestate"], "vendor=valid")

    def test_concurrent_creates_return_one_stored_winner(self):
        b, app_b = self.worker()
        self.q._q11_state_connect().close()
        b._q11_state_connect().close()
        body = base.fixture("create")
        barrier = threading.Barrier(2)
        def send(app):
            barrier.wait(timeout=10)
            return self.request(app, "POST", "/v2/incidents", body)
        with ThreadPoolExecutor(max_workers=2) as pool:
            a_future = pool.submit(send, self.app)
            b_future = pool.submit(send, app_b)
            responses = [a_future.result(timeout=20), b_future.result(timeout=20)]
        self.assertEqual([r.status_code for r in responses], [200, 200])
        self.assertEqual(responses[0].json(), responses[1].json())
        self.assertEqual(self.request(app_b, "GET", "/v2/incidents/" + body["runId"]).json(), responses[0].json())


if __name__ == "__main__":
    unittest.main()
