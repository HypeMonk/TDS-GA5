"""Trial B changes only explicit missing-identity markers, with v32 rationales."""
import importlib.util
import itertools
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("trial_q2_fixtures", ROOT / "test_q10_evidence.py")
fixtures = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixtures)
q10 = fixtures.q10


def baseline_decision(package):
    with patch.object(q10, "MISSING_IDENTITY_MARKER", "unknown"):
        return q10.decide(package)


def complete_package(action, currency="USD"):
    package = fixtures.invoice_package(action, "199.99" if action == "request_approval" else "250.00",
                                       currency=currency)
    if action in ("settle_invoice", "request_approval"):
        package["documents"].append({"name": "signed.txt", "text": (
            f"[R_SIGNED] Signed commercial instrument INV-CURRENT-1 covers order PO-CURRENT, "
            f"payee ExampleSupplier and {currency} 200.00.")})
    else:
        package["documents"][0]["text"] = package["documents"][0]["text"].replace(
            "payee AC-OLD", "payee ExampleSupplier")
    return package


def semantic_package(*, bank_location=None, bank_status="confirmed"):
    texts = [
        "Signed purchase order PO-ALT-2 totals USD 200.00; submitted invoice total is USD 200.00.",
        "Current ledger: payment of USD 200.00 to Example Industries settled PO-OLD-2. The currently submitted order is PO-ALT-2.",
        "Delegated settlement authority ceiling is USD 250.00.",
    ]
    if bank_location is not None:
        texts[bank_location] += f" The remittance account is AC-OLD; callback is {bank_status}."
    return {"packageId": "pkg-semantic-trial", "documents": [
        {"name": f"current-{i}.txt", "text": f"[R_SOURCE{i}] {text}"} for i, text in enumerate(texts)]}


class MissingIdentityTrialTests(unittest.TestCase):
    def assert_marker_only(self, baseline, trial):
        self.assertEqual(set(trial), set(baseline))
        self.assertEqual({key: value for key, value in trial.items() if key != "facts"},
                         {key: value for key, value in baseline.items() if key != "facts"})
        expected = dict(baseline["facts"])
        for field in baseline.get("unresolvedFacts", []):
            self.assertEqual(expected[field], "unknown")
            expected[field] = "not provided"
        self.assertEqual(trial["facts"], expected)

    def test_incomplete_decisions_change_only_missing_identity_fields(self):
        self.assertEqual(q10.MISSING_IDENTITY_MARKER, "not provided")
        for action in q10.ACTIONS:
            for currency in ("USD", "EUR", "INR", "JPY", "KWD"):
                with self.subTest(action=action, currency=currency):
                    ceiling = "199.00" if currency == "JPY" else "199.99"
                    package = fixtures.invoice_package(action, ceiling if action == "request_approval" else "250.00",
                                                       currency=currency)
                    baseline, trial = baseline_decision(package), q10.decide(package)
                    self.assertEqual(trial["action"], action)
                    self.assert_marker_only(baseline, trial)
                    for ref in trial["evidenceRefs"]:
                        self.assertEqual(trial["rationale"].count(ref + ': "'), 1)

    def test_complete_decisions_keep_all_fields_and_rationale(self):
        for action in q10.ACTIONS:
            for currency in ("USD", "EUR", "INR"):
                with self.subTest(action=action, currency=currency):
                    package = complete_package(action, currency)
                    baseline = baseline_decision(package)
                    self.assertFalse(baseline["unresolvedFacts"])
                    with patch.object(q10, "_incomplete_identity_rationale", side_effect=AssertionError("Trial A helper used")):
                        self.assertEqual(q10.decide(package), baseline)

    def test_baseline_quotations_are_restored_for_every_action(self):
        for action in q10.ACTIONS:
            with self.subTest(action=action):
                package = fixtures.invoice_package(action, "199.99" if action == "request_approval" else "250.00")
                decision = q10.decide(package)
                self.assertEqual(decision["rationale"], baseline_decision(package)["rationale"])
                for index, document in enumerate(package["documents"][:3]):
                    source = document["text"].split("] ", 1)[1]
                    self.assertEqual(fixtures.citation_text(decision["rationale"], f"R_SOURCE{index}"), source)
                self.assertNotIn("[R_SOURCE", decision["rationale"])

    def test_semantic_confirmation_remains_in_its_source_quotation(self):
        for location in (1, 2):
            with self.subTest(location=location):
                package = semantic_package(bank_location=location)
                trace = {}
                decision = q10.decide(package, trace)
                self.assertEqual(trace["parser"], "semantic")
                self.assertEqual(decision["action"], "settle_invoice")
                self.assertEqual(decision["facts"]["invoiceNumber"], "not provided")
                for index in range(3):
                    citation = fixtures.citation_text(decision["rationale"], f"R_SOURCE{index}")
                    self.assertEqual("callback is confirmed" in citation, index == location)
                self.assert_marker_only(baseline_decision(package), decision)

    def test_absent_or_pending_confirmation_is_not_invented(self):
        cases = [semantic_package()]
        cases += [semantic_package(bank_location=1, bank_status=status)
                  for status in ("not yet verified", "not confirmed", "not completed", "awaiting independent verification")]
        for package in cases:
            with self.subTest(text=package["documents"][1]["text"]):
                decision = q10.decide(package)
                self.assertNotIn("callback is confirmed.", decision["rationale"])
                self.assertNotIn("receiving entry confirms", decision["rationale"])
                self.assert_marker_only(baseline_decision(package), decision)

    def test_semantic_output_ignores_namespaces_and_document_order(self):
        package = semantic_package(bank_location=1)
        expected = q10.decide(package)
        for documents in itertools.permutations(package["documents"]):
            self.assertEqual(q10.decide(dict(package, documents=list(documents), packageId="pkg-renamed",
                                            receivedAt="2026-01-01T00:00:00Z")), expected)
        for index, document in enumerate(package["documents"]):
            document["text"] = document["text"].replace(f"R_SOURCE{index}", f"R_FRESH{index}")
        renamed = q10.decide(package)
        for field in ("action", "facts", "unresolvedFacts"):
            self.assertEqual(renamed[field], expected[field])
        self.assertEqual(renamed["evidenceRefs"], [f"R_FRESH{i}" for i in range(3)])
        self.assertNotIn("R_SOURCE", renamed["rationale"])
        self.assert_marker_only(baseline_decision(package), renamed)

    def test_long_rationale_keeps_baseline_length_and_source_prefixes(self):
        package = fixtures.invoice_package()
        for document in package["documents"]:
            document["text"] = document["text"].replace("PO-CURRENT", "PO-" + "X" * 800)
        baseline, trial = baseline_decision(package), q10.decide(package)
        self.assert_marker_only(baseline, trial)
        self.assertTrue(60 <= len(trial["rationale"]) <= 1500)
        for ref in trial["evidenceRefs"]:
            self.assertIn(ref + ': "', trial["rationale"])

    def test_trace_records_actual_marker_and_unresolved_provenance(self):
        for action, field in (("settle_invoice", "invoiceNumber"), ("hold_invoice", "vendorName")):
            with self.subTest(action=action):
                trace = {}
                decision = q10.decide(fixtures.invoice_package(action), trace)
                self.assertEqual(trace["decision"], decision)
                self.assertEqual(trace["factProvenance"][field],
                                 {"value": "not provided", "status": "unresolved", "sources": []})
                self.assertIn("unresolved_" + field, trace["warnings"])
                self.assertFalse(trace["hiddenGraderAcceptanceKnown"])

    def test_both_missing_identities_use_marker_without_changing_action(self):
        package = {"packageId": "pkg-both-missing", "documents": [
            {"name": "order.txt", "text": "[R_ORDER01] Signed purchase order PO-NONE-1 totals USD 200.00; submitted invoice total is USD 200.00."},
            {"name": "bank.txt", "text": "[R_BANK001] The account changed from AC-OLD to AC-NEW; callback is not yet verified."},
            {"name": "control.txt", "text": "[R_CONTROL] Remittance controls require payment to pause until independent verification completes."}]}
        decision = q10.decide(package)
        self.assertEqual(decision["action"], "hold_invoice")
        self.assertEqual(decision["unresolvedFacts"], ["vendorName", "invoiceNumber"])
        self.assert_marker_only(baseline_decision(package), decision)


if __name__ == "__main__":
    unittest.main()
