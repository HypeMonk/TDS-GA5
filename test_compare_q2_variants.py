"""Counterfactual outputs must not inherit another variant's receipt."""
import importlib.util
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
from q10_variants import CONFIGS
from test_q10_variants import fixtures

spec = importlib.util.spec_from_file_location("comparison_test", ROOT / "compare_q2_variants.py")
comparison = importlib.util.module_from_spec(spec)
spec.loader.exec_module(comparison)


class ComparisonTests(unittest.TestCase):
    def capture(self):
        config = CONFIGS["v6"]
        package = fixtures.fixtures.invoice_package()
        engine = fixtures.q10
        output = engine.decide(package)
        proposal = {"packageId": package["packageId"], "actionId": "act-local", **output}
        traces = [{"id": 1, "variantId": "v6", "taskId": "task-local", "status": 200,
                   "request": {"body": {"message": {"parts": [{"data": {"packages": [package]}}]}}},
                   "response": {"body": {"task": {"artifacts": [{"parts": [{"data": {"proposals": [proposal]}}]}]}}},
                   "decisions": [{"packageId": package["packageId"], "decision": output}]},
                  {"id": 2, "variantId": "v6", "taskId": "task-local", "status": 200,
                   "outcomes": [{"packageId": package["packageId"], "actionId": "act-local",
                                 "action": output["action"], "outcome": "ACCEPTED", "receiptNonce": "local-nonce"}]}]
        return {"variantId": "v6", "configDigest": config.digest, "completeListing": True}, traces

    def test_only_recorded_variant_can_have_a_verified_outcome(self):
        manifest, traces = self.capture()
        result = comparison.compare(manifest, traces)
        self.assertEqual(result["variantCount"], 18)
        self.assertEqual(result["packageCount"], 1)
        outputs = result["packages"][0]["variants"]
        self.assertEqual([o["variantId"] for o in outputs if o["graderOutcome"] == "ACCEPTED"], ["v6"])
        self.assertTrue(all(o["graderOutcome"] == "NOT_GRADED" for o in outputs if o["variantId"] != "v6"))
        self.assertFalse(result["graderInvoked"])

    def test_unknown_config_or_wrong_action_id_never_gets_a_grade(self):
        manifest, traces = self.capture()
        manifest["configDigest"] = "old-unverified-config"
        result = comparison.compare(manifest, traces)
        self.assertTrue(all(o["graderOutcome"] == "NOT_GRADED" for o in result["packages"][0]["variants"]))
        manifest["configDigest"] = CONFIGS["v6"].digest
        traces[1]["outcomes"][0]["actionId"] = "foreign-action"
        result = comparison.compare(manifest, traces)
        self.assertTrue(all(o["graderOutcome"] == "NOT_GRADED" for o in result["packages"][0]["variants"]))


if __name__ == "__main__":
    unittest.main()
