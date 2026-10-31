"""Fixed historical business outputs and concurrent Q2 endpoint isolation."""
import asyncio
import gzip
import hashlib
import importlib.util
import itertools
import json
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

from fastapi import FastAPI, APIRouter
from httpx import ASGITransport, AsyncClient

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
from q10_variants import BASELINE, REGISTRY, VariantSuite, load_instance


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


fixtures = load(ROOT / "test_q2_rationale_trial.py", "variant_fixtures")


def make_suite(folder):
    engine = load(ROOT / "q10.py", "suite_default")
    engine.DB_PATH = str(Path(folder) / "tasks.db")
    engine._TRACE_DB_PATH = str(Path(folder) / "traces.db")
    engine._Q10_WIRE_KEY = "local-only-debug-key"
    return VariantSuite(engine)


class PolicyTests(unittest.TestCase):
    def test_registry_is_complete_fixed_and_unique(self):
        self.assertEqual([c.id for c in REGISTRY], [f"v{i}" for i in range(1, 19)])
        self.assertEqual(len({c.digest for c in REGISTRY}), 18)
        self.assertEqual({(c.marker, c.rationale_style, c.vendor_binding) for c in REGISTRY},
                         set(itertools.product(("unknown", "not provided", ""),
                                               ("excerpts", "no-footer", "concise"), ("legacy", "current-order"))))

    def test_six_variants_match_independently_frozen_sources(self):
        reference = ROOT / "tests/fixtures/q2_history"
        manifest = json.loads((reference / "manifest.json").read_text())
        cases = []
        for action in fixtures.q10.ACTIONS:
            for currency in ("USD", "EUR", "INR", "JPY", "KWD"):
                ceiling = "199.00" if currency == "JPY" else "199.99"
                cases.append(fixtures.fixtures.invoice_package(action, ceiling=ceiling if action == "request_approval" else "250.00", currency=currency))
                cases.append(fixtures.complete_package(action, currency))
        cases += [fixtures.semantic_package(bank_location=location) for location in (None, 1, 2)]
        cases += [{"packageId": "unknown", "documents": [{"name": "unknown.txt", "text": "Unrecognized case."}]}]
        long = fixtures.fixtures.invoice_package()
        for doc in long["documents"]:
            doc["text"] = doc["text"].replace("PO-CURRENT", "PO-" + "X" * 800)
        cases.append(long)
        with tempfile.TemporaryDirectory() as folder:
            for config in REGISTRY[:6]:
                raw = gzip.decompress((reference / (config.id + ".py.gz")).read_bytes())
                self.assertEqual(hashlib.sha256(raw).hexdigest(), manifest[config.id]["sha256"])
                old = types.ModuleType("frozen_" + config.id)
                old.__file__ = str(reference / (config.id + ".py"))
                exec(compile(raw, old.__file__, "exec"), old.__dict__)
                new = load_instance(config, db_path=Path(folder) / (config.id + ".db"), trace_path=Path(folder) / (config.id + ".traces"))
                for index, case in enumerate(cases):
                    with self.subTest(variant=config.id, case=index):
                        self.assertEqual(new.decide(case), old.decide(case))
            baseline = load_instance(BASELINE, db_path=Path(folder) / "base.db", trace_path=Path(folder) / "base.traces")
            d = types.ModuleType("frozen_d")
            exec(gzip.decompress((reference / "v5.py.gz").read_bytes()), d.__dict__)
            for case in cases:
                self.assertEqual(baseline.decide(case), d.decide(case))

    def test_all_combinations_preserve_action_and_late_binding(self):
        with tempfile.TemporaryDirectory() as folder:
            suite = make_suite(folder)
            self.assertFalse(list(Path(folder).rglob("*.db")))
            for config in REGISTRY:
                engine = suite.instances[config.id]
                for action in engine.ACTIONS:
                    package = fixtures.fixtures.invoice_package(action, ceiling="199.99" if action == "request_approval" else "250.00")
                    output = engine.decide(package)
                    self.assertEqual(output["action"], action)
                    self.assertTrue(60 <= len(output["rationale"]) <= 1500)
                    self.assertEqual(output["evidenceRefs"], ["R_SOURCE0", "R_SOURCE1", "R_SOURCE2"])
                    for field in output["unresolvedFacts"]:
                        self.assertEqual(output["facts"][field], config.marker)
                if config.vendor_binding == "current-order":
                    package = fixtures.fixtures.invoice_package()
                    legacy_config = next(c for c in REGISTRY if c.marker == config.marker and c.rationale_style == config.rationale_style and c.vendor_binding == "legacy")
                    before = suite.instances[legacy_config.id].decide(package)
                    after = engine.decide(package)
                    self.assertEqual(after["rationale"], before["rationale"])
                    self.assertEqual(after["unresolvedFacts"], ["vendorName", "invoiceNumber"])
            suite.close()


class EndpointTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.suite = make_suite(self.folder.name)
        self.app = FastAPI()
        self.suite.register(self.app)
        self.client = AsyncClient(transport=ASGITransport(app=self.app, raise_app_exceptions=False), base_url="http://test")
        self.headers = {"Authorization": "Bearer local-owner", "A2A-Version": "1.0", "Content-Type": "application/a2a+json"}
        self.admin = {"X-Debug-Key": "local-only-debug-key"}

    async def asyncTearDown(self):
        await self.client.aclose()
        self.suite.close()
        self.folder.cleanup()

    def batch(self, message_id="same-message"):
        return {"message": {"messageId": message_id, "role": "ROLE_USER", "parts": [{
            "mediaType": fixtures.q10.MODE_BATCH, "data": {"batchId": "same-batch", "policyRevision": "local",
            "packages": [fixtures.fixtures.invoice_package()]}}]}}

    def continuation(self, task, action_id=None):
        prop = task["artifacts"][0]["parts"][0]["data"]["proposals"][0]
        return {"message": {"messageId": "same-result", "role": "ROLE_USER", "taskId": task["id"],
                "contextId": task["contextId"], "parts": [{"mediaType": fixtures.q10.MODE_RESULTS,
                "data": {"batchId": "same-batch", "results": [{"packageId": prop["packageId"],
                "actionId": action_id or prop["actionId"], "action": prop["action"],
                "outcome": "ACCEPTED", "receiptNonce": "local-nonce"}]}}]}}

    async def test_cards_all_aliases_and_lazy_storage(self):
        for config in REGISTRY:
            for base in config.bases:
                for filename in ("agent-card.json", "agent.json"):
                    response = await self.client.get(base + ".well-known/" + filename)
                    self.assertEqual(response.status_code, 200)
                    card = response.json()
                    self.assertEqual(card["url"], "https://test" + base)
                    self.assertEqual(card["provider"]["url"], card["url"])
                    self.assertEqual([i["url"] for i in card["supportedInterfaces"]], ["https://test" + b for b in config.bases])
                response = await self.client.get(base)
                self.assertEqual(response.json()["variantId"], config.id)
        self.assertFalse(Path(self.folder.name, "tasks.db.variants").exists())
        self.assertEqual((await self.client.get("/a2a/v19/.well-known/agent-card.json")).status_code, 404)
        for engine in self.suite.instances.values():
            self.assertIsNone(engine._conn)

    async def test_concurrent_variants_alias_replay_and_receipt_isolation(self):
        replies = await asyncio.gather(*(self.client.post(c.bases[0] + "message:send", json=self.batch(), headers=self.headers) for c in REGISTRY))
        self.assertTrue(all(r.status_code == 200 for r in replies), [r.text for r in replies])
        tasks = [r.json()["task"] for r in replies]
        self.assertEqual(len({t["id"] for t in tasks}), 18)
        for config, task in zip(REGISTRY, tasks):
            other = "v2" if config.id != "v2" else "v1"
            self.assertEqual((await self.client.get(f"/{other}/tasks/{task['id']}", headers=self.headers)).status_code, 404)
            replay = await self.client.post(config.bases[1] + "message:send", json=self.batch(), headers=self.headers)
            self.assertEqual(replay.json()["task"], task)
            outsider = dict(self.headers, Authorization="Bearer other-owner")
            self.assertEqual((await self.client.get(config.bases[0] + "tasks/" + task["id"], headers=outsider)).status_code, 404)
        first, second = tasks[:2]
        foreign = first["artifacts"][0]["parts"][0]["data"]["proposals"][0]["actionId"]
        rejected = await self.client.post("/v2/message:send", json=self.continuation(second, foreign), headers=self.headers)
        self.assertEqual(rejected.status_code, 400)
        self.assertEqual(rejected.json()["code"], "ACTION_ID_MISMATCH")
        self.assertEqual((await self.client.get("/v2/tasks/" + second["id"], headers=self.headers)).json(), second)
        for config, task in zip(REGISTRY, tasks):
            result = self.continuation(task)
            completed = await self.client.post(config.bases[0] + "message:send", json=result, headers=self.headers)
            self.assertEqual(completed.status_code, 200, completed.text)
            self.assertEqual(completed.json()["task"]["state"], fixtures.q10.COMPLETED)
            replay = await self.client.post(config.bases[1] + "message:send", json=result, headers=self.headers)
            self.assertEqual(replay.json(), completed.json())
            index = await self.client.get(f"/debug/q10/variants/{config.id}/traces", headers=self.admin)
            self.assertEqual(index.json()["variantId"], config.id)
            row = index.json()["rows"][0]
            detail = await self.client.get(f"/debug/q10/variants/{config.id}/traces/{row['id']}", headers=self.admin)
            self.assertEqual(detail.json()["variantId"], config.id)
            self.assertNotIn("local-owner", detail.text)
            self.assertEqual((await self.client.get(f"/debug/q10/variants/{config.id}/traces")).status_code, 403)
        self.suite.close()
        reopened = make_suite(self.folder.name)
        for config, task in zip(REGISTRY, tasks):
            self.assertEqual(reopened.instances[config.id].load_task(task["id"])[0]["state"], fixtures.q10.COMPLETED)
        reopened.close()

    async def test_variant_trace_limits_failures_cancellation_and_replay_conflicts(self):
        config = REGISTRY[5]
        engine = self.suite.instances[config.id]
        base = config.bases[0]
        self.assertEqual(engine._TRACE_STORAGE_LIMIT, 2 * 1024 * 1024)
        self.assertEqual(engine._TRACE_ROW_LIMIT, 100)
        self.assertEqual((await self.client.post(base + "message:send", headers=self.headers, content=b"bad-json")).status_code, 400)
        sent = await self.client.post(base + "message:send", headers=self.headers, json=self.batch())
        task = sent.json()["task"]
        changed = self.batch()
        changed["message"]["parts"][0]["data"]["packages"][0]["packageId"] = "changed-package"
        self.assertEqual((await self.client.post(base + "message:send", headers=self.headers, json=changed)).status_code, 409)
        cancel = await self.client.post(base + "tasks/" + task["id"] + ":cancel", headers=self.headers)
        self.assertEqual(cancel.status_code, 200)
        self.assertEqual((await self.client.post(base + "message:send", headers=self.headers, json=self.continuation(task))).status_code, 409)
        engine._TRACE_DB_PATH = self.folder.name
        healthy = await self.client.post(base + "message:send", headers=self.headers, json=self.batch("new-message"))
        self.assertEqual(healthy.status_code, 200)
        self.assertGreater(engine._TRACE_FAILURES, 0)
        self.assertEqual(self.suite.instances["v5"]._TRACE_FAILURES, 0)

    async def test_cancel_and_receipt_race_never_crosses_variants(self):
        replies = await asyncio.gather(*(self.client.post(f"/{v}/message:send", headers=self.headers,
                                       json=self.batch("race-message")) for v in ("v5", "v6")))
        for variant, reply in zip(("v5", "v6"), replies):
            task = reply.json()["task"]
            cancel, complete = await asyncio.gather(
                self.client.post(f"/{variant}/tasks/{task['id']}:cancel", headers=self.headers),
                self.client.post(f"/a2a/{variant}/message:send", headers=self.headers, json=self.continuation(task)))
            self.assertEqual(sorted((cancel.status_code, complete.status_code)), [200, 409])
            final = await self.client.get(f"/{variant}/tasks/{task['id']}", headers=self.headers)
            self.assertIn(final.json()["state"], (fixtures.q10.CANCELED, fixtures.q10.COMPLETED))
            other = "v5" if variant == "v6" else "v6"
            self.assertEqual((await self.client.post(f"/{other}/tasks/{task['id']}:cancel", headers=self.headers)).status_code, 404)

    async def test_main_logs_are_separated_and_diagnostic_reads_do_not_recurse(self):
        unrelated = {}
        for name in ("q8", "q9", "q11"):
            module = types.ModuleType(name)
            module.router = APIRouter()
            unrelated[name] = module
        engine = load(ROOT / "q10.py", "main_test_default")
        engine.DB_PATH = str(Path(self.folder.name) / "main.db")
        engine._TRACE_DB_PATH = str(Path(self.folder.name) / "main.traces")
        engine._Q10_WIRE_KEY = "local-only-debug-key"
        with patch.dict(sys.modules, {**unrelated, "q10": engine}):
            main = load(ROOT / "main.py", "main_variant_test")
        try:
            async with AsyncClient(transport=ASGITransport(app=main.app, raise_app_exceptions=False), base_url="http://test") as client:
                self.assertEqual((await client.get("/health")).json()["version"], "offline-v36-d")
                self.assertEqual((await client.post("/v6/message:send", headers=self.headers, json=self.batch())).status_code, 200)
                self.assertEqual(len(main.Q2_SUITE.logs["v6"]), 1)
                self.assertFalse(main.Q2_SUITE.logs["v5"])
                self.assertFalse(main.LOGS_Q10)
                logs = await client.get("/debug/q10/variants/v6/logs", headers=self.admin)
                self.assertEqual(logs.json()["rows"][0]["variantId"], "v6")
                self.assertNotIn("local-owner", logs.text)
                self.assertNotIn("body", logs.json()["rows"][0])
                self.assertEqual(len(main.Q2_SUITE.logs["v6"]), 1)
                with patch.object(main.Q2_SUITE.instances["v6"], "decide", side_effect=RuntimeError("private-error")):
                    failed = await client.post("/a2a/v6/message:send", headers=self.headers, json=self.batch("failing-message"))
                self.assertEqual(failed.status_code, 500)
                self.assertTrue(main.Q2_SUITE.logs["v6"][-1]["failed"])
                self.assertNotIn("private-error", json.dumps(list(main.Q2_SUITE.logs["v6"])))
                self.assertFalse(main.LOGS_Q10)
        finally:
            main.Q2_SUITE.close()

    async def test_logs_do_not_classify_mailroom_or_incidents_as_q2(self):
        self.assertIsNone(self.suite.variant_for_path("/v1/mailroom/actions"))
        self.assertIsNone(self.suite.variant_for_path("/v2/incidents"))
        self.assertIsNone(self.suite.variant_for_path("/debug/q10/variants/v1/traces"))
        self.assertEqual(self.suite.variant_for_path("/a2a/v10/message:send"), "v10")
        self.assertEqual((await self.client.get("/debug/q10/variants/v1/logs")).status_code, 403)
        self.assertEqual((await self.client.get("/debug/q10/variants/v1/wire", headers=self.admin)).status_code, 404)


if __name__ == "__main__":
    unittest.main()
