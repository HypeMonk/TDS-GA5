"""Tests for post-Check trace correlation and explicit uncertainty."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("analysis_test", ROOT / "analyze_q2_traces.py")
analyzer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(analyzer)


def decision(package_id, action, warnings=None):
    return {"packageId": package_id, "parser": "distributed", "parserAttempts": [{"parser": "distributed", "matched": True}],
            "decision": {"action": action, "facts": {"vendorName": "Example", "invoiceNumber": "unknown",
                         "amountMinor": 100, "currency": "USD"}, "evidenceRefs": ["R_ONE001", "R_TWO002", "R_THREE3"],
                         "rationale": "Action with evidence"},
            "warnings": warnings or [], "factProvenance": {"invoiceNumber": {"status": "unresolved"}},
            "relationships": [{"kind": "authority", "withinLimit": True}]}


class AnalysisTests(unittest.TestCase):
    def test_correlates_rejected_and_accepted_packages_without_inventing_expected_answers(self):
        manifest = {"captureFailures": 0, "completeListing": True, "missingRows": []}
        traces = [
            {"id": 1, "solverVersion": "offline-v20", "taskId": "task-a", "messageId": "start", "method": "POST",
             "path": "/message:send", "status": 200, "durationMs": 10, "request": {}, "response": {},
             "decisions": [decision("pkg-a", "settle_invoice", ["unresolved_invoiceNumber"]),
                           decision("pkg-b", "reject_duplicate")], "outcomes": []},
            {"id": 2, "solverVersion": "offline-v20", "taskId": "task-a", "messageId": "results", "method": "POST",
             "path": "/message:send", "status": 200, "durationMs": 5, "request": {}, "response": {}, "decisions": [],
             "outcomes": [{"packageId": "pkg-a", "actionId": "act-a", "action": "settle_invoice",
                           "outcome": "REJECTED", "receiptNonce": "nonce-a"},
                          {"packageId": "pkg-b", "actionId": "act-b", "action": "reject_duplicate",
                           "outcome": "ACCEPTED", "receiptNonce": "nonce-b"}]},
        ]
        result = analyzer.analyze(manifest, traces)
        self.assertEqual(result["outcomes"], {"ACCEPTED": 1, "REJECTED": 1})
        self.assertEqual(result["solverVersions"], ["offline-v20"])
        rejected = result["rejectedPackages"][0]
        self.assertEqual(rejected["packageId"], "pkg-a")
        self.assertEqual(rejected["action"], "settle_invoice")
        self.assertIn("unresolved_invoiceNumber", rejected["warnings"])
        self.assertFalse(rejected["hiddenExpectedAnswerKnown"])
        self.assertEqual(rejected["transportConsistency"]["issues"], [])
        self.assertIn("cannot reveal", result["interpretation"])

    def test_reports_capture_gaps_conflicts_and_transport_action_mismatch(self):
        manifest = {"captureFailures": 2, "completeListing": False, "missingRows": [9]}
        first = decision("pkg-a", "settle_invoice")
        second = decision("pkg-a", "request_approval")
        traces = [
            {"id": 1, "solverVersion": "v1", "taskId": "task-a", "status": 200,
             "request": {"truncated": True, "omittedReason": "body_size_limit"}, "response": {},
             "decisions": [first], "outcomes": []},
            {"id": 2, "solverVersion": "v2", "taskId": "task-a", "status": 200,
             "request": {}, "response": {"omittedReason": "invalid_json"}, "decisions": [second],
             "outcomes": [{"packageId": "pkg-a", "action": "settle_invoice", "outcome": "REJECTED"},
                          {"packageId": "pkg-no-decision", "action": "hold_invoice", "outcome": "REJECTED"}]},
        ]
        result = analyzer.analyze(manifest, traces)
        reasons = {issue["reason"] for issue in result["integrityIssues"]}
        self.assertTrue({"body_size_limit", "invalid_json", "conflicting_decision_trace",
                         "outcome_without_decision_trace"}.issubset(reasons))
        package = next(item for item in result["rejectedPackages"] if item["packageId"] == "pkg-a")
        self.assertEqual(package["transportConsistency"]["issues"], ["continuation_action_differs_from_trace"])
        self.assertEqual(result["solverVersions"], ["v1", "v2"])
        self.assertFalse(result["completeListing"])
        self.assertEqual(result["missingRows"], [9])

    def test_manifest_loader_rejects_missing_files(self):
        with tempfile.TemporaryDirectory(prefix="q2-analysis-test-") as folder:
            root = Path(folder)
            (root / "manifest.json").write_text(json.dumps({"files": ["trace-1.json"]}), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "missing"):
                analyzer.load_capture(root)

    def test_manifest_loader_round_trip(self):
        with tempfile.TemporaryDirectory(prefix="q2-analysis-roundtrip-") as folder:
            root = Path(folder)
            trace = {"id": 1, "taskId": "task-a", "decisions": [], "outcomes": []}
            (root / "trace-1.json").write_text(json.dumps(trace), encoding="utf-8")
            manifest = {"files": ["trace-1.json"], "captureFailures": 0}
            (root / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
            loaded_manifest, traces = analyzer.load_capture(root)
            self.assertEqual(loaded_manifest, manifest)
            self.assertEqual(traces, [trace])


if __name__ == "__main__":
    unittest.main()
