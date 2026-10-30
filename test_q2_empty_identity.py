"""Trial D changes only absent identity strings, preserving Trial C decisions."""
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("empty_identity_fixtures", ROOT / "test_q2_rationale_trial.py")
rationales = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rationales)
fixtures = rationales.fixtures
q10 = fixtures.q10


def baseline(package):
    with patch.object(q10, "MISSING_IDENTITY_MARKER", "unknown"):
        return q10.decide(package)


class EmptyIdentityTests(unittest.TestCase):
    def test_only_declared_missing_identities_change(self):
        self.assertEqual(q10.MISSING_IDENTITY_MARKER, "")
        for action in q10.ACTIONS:
            with self.subTest(action=action):
                package = fixtures.invoice_package(action, "199.99" if action == "request_approval" else "250.00")
                before, after = baseline(package), q10.decide(package)
                expected = json.loads(json.dumps(before))
                for field in before["unresolvedFacts"]:
                    self.assertEqual(expected["facts"][field], "unknown")
                    expected["facts"][field] = ""
                self.assertEqual(after, expected)

    def test_complete_identities_and_rationales_are_frozen(self):
        for action in q10.ACTIONS:
            with self.subTest(action=action):
                package = rationales.complete_package(action)
                before, after = baseline(package), q10.decide(package)
                self.assertFalse(after["unresolvedFacts"])
                self.assertEqual(after, before)

    def test_empty_fields_are_present_strings_not_null_or_omitted(self):
        for action, field in (("settle_invoice", "invoiceNumber"), ("hold_invoice", "vendorName")):
            with self.subTest(action=action):
                decision = q10.decide(fixtures.invoice_package(action))
                encoded = json.dumps(decision["facts"])
                decoded = json.loads(encoded)
                self.assertEqual(set(decoded), {"vendorName", "invoiceNumber", "amountMinor", "currency"})
                self.assertIsInstance(decoded[field], str)
                self.assertEqual(decoded[field], "")
                self.assertIn('"' + field + '": ""', encoded)
                self.assertEqual(type(decoded["amountMinor"]), int)

    def test_empty_value_is_not_located_in_every_source(self):
        for action, field in (("settle_invoice", "invoiceNumber"), ("hold_invoice", "vendorName")):
            with self.subTest(action=action):
                trace = {}
                decision = q10.decide(fixtures.invoice_package(action), trace)
                self.assertEqual(trace["decision"], decision)
                self.assertEqual(trace["factProvenance"][field], {"value": "", "status": "unresolved", "sources": []})
                self.assertIn("unresolved_" + field, trace["warnings"])

    def test_unsupported_fallback_is_not_relabelled(self):
        package = {"packageId": "pkg-unsupported", "documents": [{"name": "unknown.txt", "text": "Unrecognized commercial case."}]}
        before, after = baseline(package), q10.decide(package)
        self.assertNotIn("unresolvedFacts", after)
        self.assertEqual(after, before)
        self.assertEqual(after["facts"]["vendorName"], "unknown")

    def test_semantic_missing_invoice_uses_empty_without_other_changes(self):
        package = rationales.semantic_package(bank_location=1)
        trace = {}
        after = q10.decide(package, trace)
        before = baseline(package)
        self.assertEqual(trace["parser"], "semantic")
        self.assertEqual(after["facts"]["invoiceNumber"], "")
        before["facts"]["invoiceNumber"] = ""
        self.assertEqual(after, before)
        self.assertNotIn("Missing source fields:", after["rationale"])


if __name__ == "__main__":
    unittest.main()
