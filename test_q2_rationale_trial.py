"""Source-excerpt rationale regressions, independent of the missing-value marker."""
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
    helper = q10._relationship_rationale

    def with_footer(action, facts, current_order, evidence, details, sources):
        rationale = helper(action, facts, current_order, evidence, details, sources)
        missing = [field for field in ("vendorName", "invoiceNumber") if facts[field] == "unknown"]
        if missing:
            rationale += " Missing source fields: " + ", ".join(missing) + "; unknown is not an inferred identity."
        return rationale

    with patch.object(q10, "_relationship_rationale", with_footer):
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


class MissingIdentityFooterTests(unittest.TestCase):
    def assert_footer_only(self, baseline, trial):
        self.assertEqual(set(trial), set(baseline))
        self.assertEqual({key: value for key, value in trial.items() if key != "rationale"},
                         {key: value for key, value in baseline.items() if key != "rationale"})
        missing = baseline.get("unresolvedFacts", [])
        if missing:
            footer = " Missing source fields: " + ", ".join(missing) + "; unknown is not an inferred identity."
            self.assertTrue(baseline["rationale"].endswith(footer))
            self.assertEqual(trial["rationale"], baseline["rationale"][:-len(footer)])
            for field in missing:
                self.assertEqual(trial["facts"][field], q10.MISSING_IDENTITY_MARKER)
        else:
            self.assertEqual(trial, baseline)

    def test_incomplete_decisions_change_only_rationale_footer(self):
        for action in q10.ACTIONS:
            for currency in ("USD", "EUR", "INR", "JPY", "KWD"):
                with self.subTest(action=action, currency=currency):
                    ceiling = "199.00" if currency == "JPY" else "199.99"
                    package = fixtures.invoice_package(action, ceiling if action == "request_approval" else "250.00",
                                                       currency=currency)
                    baseline, trial = baseline_decision(package), q10.decide(package)
                    self.assertEqual(trial["action"], action)
                    self.assert_footer_only(baseline, trial)
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
                self.assert_footer_only(baseline_decision(package), decision)
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
                self.assertEqual(decision["facts"]["invoiceNumber"], q10.MISSING_IDENTITY_MARKER)
                for index in range(3):
                    citation = fixtures.citation_text(decision["rationale"], f"R_SOURCE{index}")
                    self.assertEqual("callback is confirmed" in citation, index == location)
                self.assert_footer_only(baseline_decision(package), decision)

    def test_absent_or_pending_confirmation_is_not_invented(self):
        cases = [semantic_package()]
        cases += [semantic_package(bank_location=1, bank_status=status)
                  for status in ("not yet verified", "not confirmed", "not completed", "awaiting independent verification")]
        for package in cases:
            with self.subTest(text=package["documents"][1]["text"]):
                decision = q10.decide(package)
                self.assertNotIn("callback is confirmed.", decision["rationale"])
                self.assertNotIn("receiving entry confirms", decision["rationale"])
                self.assert_footer_only(baseline_decision(package), decision)

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
        self.assert_footer_only(baseline_decision(package), renamed)

    def test_long_rationale_keeps_baseline_length_and_source_prefixes(self):
        package = fixtures.invoice_package()
        for document in package["documents"]:
            document["text"] = document["text"].replace("PO-CURRENT", "PO-" + "X" * 800)
        baseline, trial = baseline_decision(package), q10.decide(package)
        self.assert_footer_only(baseline, trial)
        self.assertTrue(60 <= len(trial["rationale"]) <= 1500)
        for ref in trial["evidenceRefs"]:
            self.assertIn(ref + ': "', trial["rationale"])

    def test_trace_records_unknown_and_unresolved_provenance(self):
        for action, field in (("settle_invoice", "invoiceNumber"), ("hold_invoice", "vendorName")):
            with self.subTest(action=action):
                trace = {}
                decision = q10.decide(fixtures.invoice_package(action), trace)
                self.assertEqual(trace["decision"], decision)
                self.assertEqual(trace["factProvenance"][field],
                                 {"value": q10.MISSING_IDENTITY_MARKER, "status": "unresolved", "sources": []})
                self.assertIn("unresolved_" + field, trace["warnings"])
                self.assertFalse(trace["hiddenGraderAcceptanceKnown"])

    def test_both_missing_identities_keep_unknown_without_changing_action(self):
        package = {"packageId": "pkg-both-missing", "documents": [
            {"name": "order.txt", "text": "[R_ORDER01] Signed purchase order PO-NONE-1 totals USD 200.00; submitted invoice total is USD 200.00."},
            {"name": "bank.txt", "text": "[R_BANK001] The account changed from AC-OLD to AC-NEW; callback is not yet verified."},
            {"name": "control.txt", "text": "[R_CONTROL] Remittance controls require payment to pause until independent verification completes."}]}
        decision = q10.decide(package)
        self.assertEqual(decision["action"], "hold_invoice")
        self.assertEqual(decision["unresolvedFacts"], ["vendorName", "invoiceNumber"])
        self.assert_footer_only(baseline_decision(package), decision)


    def test_footer_text_inside_a_source_quotation_is_preserved(self):
        facts = {"vendorName": "unknown", "invoiceNumber": "INV-TEST-1", "amountMinor": 20000, "currency": "USD"}
        refs = ["R_SOURCE0", "R_SOURCE1", "R_SOURCE2"]
        sources = {"R_SOURCE0": "Signed record. Missing source fields: vendorName; unknown is not an inferred identity.",
                   "R_SOURCE1": "Remittance changed; callback awaits verification.",
                   "R_SOURCE2": "Payment controls require a hold until verification completes."}
        rationale = q10._relationship_rationale("hold_invoice", facts, "PO-CURRENT", refs, {}, sources)
        for ref in refs:
            self.assertIn(f'{ref}: "{sources[ref]}".', rationale)
        self.assertTrue(rationale.endswith('R_SOURCE2: "' + sources["R_SOURCE2"] + '".'))
        self.assertEqual(rationale.count("Missing source fields:"), 1)


if __name__ == "__main__":
    unittest.main()
