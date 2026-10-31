"""Trial E isolates current-vendor authority from historical payment mentions."""
import importlib.util
import itertools
import json
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("vendor_binding_fixtures", ROOT / "test_q2_rationale_trial.py")
rationales = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rationales)
fixtures = rationales.fixtures
q10 = fixtures.q10


def trial_d_decision(package):
    with patch.object(q10, "_current_order_vendor", side_effect=lambda current, prior, *_:
                      current if current != "unknown" else prior):
        return q10.decide(package)


class VendorBindingTests(unittest.TestCase):
    def assert_vendor_only_change(self, package, parser):
        before = trial_d_decision(package)
        trace = {}
        after = q10.decide(package, trace)
        expected = json.loads(json.dumps(before))
        self.assertTrue(before["facts"]["vendorName"])
        expected["facts"]["vendorName"] = ""
        expected["unresolvedFacts"] = [field for field in ("vendorName", "invoiceNumber")
                                       if field == "vendorName" or field in before["unresolvedFacts"]]
        self.assertEqual(after, expected)
        self.assertEqual(trace["parser"], parser)
        self.assertEqual(trace["factProvenance"]["vendorName"],
                         {"value": "", "status": "unresolved", "sources": []})
        self.assertIn("unresolved_vendorName", trace["warnings"])
        return after

    def test_different_order_payment_does_not_name_current_vendor(self):
        for action, ceiling in (("settle_invoice", "250.00"), ("request_approval", "199.99")):
            for currency in ("USD", "EUR", "INR", "JPY", "KWD"):
                with self.subTest(action=action, currency=currency):
                    limit = "199.00" if currency == "JPY" and action == "request_approval" else ceiling
                    package = fixtures.invoice_package(action, ceiling=limit, currency=currency)
                    decision = self.assert_vendor_only_change(package, "distributed")
                    self.assertEqual(decision["action"], action)
                    self.assertEqual(decision["unresolvedFacts"], ["vendorName", "invoiceNumber"])

    def test_paraphrased_historical_payee_is_also_unresolved(self):
        for limit, action in (("250.00", "settle_invoice"), ("199.99", "request_approval")):
            package = rationales.semantic_package(bank_location=1)
            package["documents"][2]["text"] = package["documents"][2]["text"].replace("250.00", limit)
            decision = self.assert_vendor_only_change(package, "semantic")
            self.assertEqual(decision["action"], action)

    def test_present_invoice_id_does_not_authorize_a_historical_vendor(self):
        packages = [rationales.complete_package("settle_invoice"), rationales.semantic_package(bank_location=1)]
        packages[0]["documents"][-1]["text"] = packages[0]["documents"][-1]["text"].replace("ExampleSupplier", "AC-OLD")
        packages[1]["documents"][0]["text"] = (
            "[R_SOURCE0] Signed invoice record INV-CURRENT-1 for purchase order PO-ALT-2 states USD 200.00.")
        for parser, package in zip(("distributed", "semantic"), packages):
            with self.subTest(parser=parser):
                decision = self.assert_vendor_only_change(package, parser)
                self.assertEqual(decision["facts"]["invoiceNumber"], "INV-CURRENT-1")
                self.assertEqual(decision["unresolvedFacts"], ["vendorName"])

    def test_same_order_payment_retains_vendor(self):
        structured = fixtures.invoice_package("reject_duplicate")
        semantic = {"packageId": "pkg-same-order", "documents": [
            {"name": "invoice.txt", "text": "[R_INVOICE] Signed invoice record INV-CURRENT-1 for purchase order PO-CURRENT-1 states USD 200.00."},
            {"name": "ledger.txt", "text": "[R_LEDGER] Current ledger: payment of USD 200.00 to Example Industries settled PO-CURRENT-1. The currently submitted order is PO-CURRENT-1."},
            {"name": "policy.txt", "text": "[R_POLICY] Duplicate control prohibits a second payment for an already paid order."}]}
        for parser, package in (("distributed", structured), ("semantic", semantic)):
            with self.subTest(parser=parser):
                trace = {}
                decision = q10.decide(package, trace)
                self.assertEqual(trace["parser"], parser)
                self.assertEqual(decision, trial_d_decision(package))
                self.assertEqual(decision["action"], "reject_duplicate")
                self.assertTrue(decision["facts"]["vendorName"])
                self.assertFalse(decision["unresolvedFacts"])

    def test_explicit_current_vendor_wins_in_both_parsers(self):
        structured = rationales.complete_package("settle_invoice")
        semantic = rationales.semantic_package(bank_location=1)
        semantic["documents"][0]["text"] = (
            "[R_SOURCE0] Signed invoice record INV-CURRENT-1 for purchase order PO-ALT-2 "
            "names payee Current Supplier and USD 200.00.")
        for parser, package, vendor in (("distributed", structured, "ExampleSupplier"),
                                        ("semantic", semantic, "Current Supplier")):
            with self.subTest(parser=parser):
                trace = {}
                decision = q10.decide(package, trace)
                self.assertEqual(trace["parser"], parser)
                self.assertEqual(decision, trial_d_decision(package))
                self.assertEqual(decision["facts"]["vendorName"], vendor)
                self.assertFalse(decision["unresolvedFacts"])

    def test_no_ledger_does_not_change_existing_missing_identity(self):
        for action in ("hold_invoice", "open_exception"):
            package = fixtures.invoice_package(action)
            self.assertEqual(q10.decide(package), trial_d_decision(package))

    def test_unrelated_vendor_rename_changes_only_its_source_quote(self):
        for parser, package in (("distributed", fixtures.invoice_package()),
                                ("semantic", rationales.semantic_package(bank_location=1))):
            expected = q10.decide(package)
            for document in package["documents"]:
                document["text"] = document["text"].replace("Example Supplier", "Other Supplier").replace(
                    "Example Industries", "Other Industries")
            changed = self.assert_vendor_only_change(package, parser)
            for key in ("action", "facts", "evidenceRefs", "unresolvedFacts"):
                self.assertEqual(changed[key], expected[key])

    def test_identity_is_independent_of_document_order_and_package_id(self):
        package = fixtures.invoice_package()
        expected = q10.decide(package)
        for documents in itertools.permutations(package["documents"]):
            self.assertEqual(q10.decide(dict(package, documents=list(documents), packageId="pkg-other")), expected)
        for document in package["documents"]:
            document["text"] = document["text"].replace("R_SOURCE", "R_RENAMED")
        changed = q10.decide(package)
        self.assertEqual(changed["facts"], expected["facts"])
        self.assertEqual(changed["evidenceRefs"], [ref.replace("R_SOURCE", "R_RENAMED") for ref in expected["evidenceRefs"]])

    def test_long_citations_keep_trial_d_budget(self):
        package = fixtures.invoice_package()
        for document in package["documents"]:
            document["text"] = document["text"].replace("Example Supplier", "Example " + "Supplier " * 120)
        decision = self.assert_vendor_only_change(package, "distributed")
        self.assertTrue(60 <= len(decision["rationale"]) <= 1500)


if __name__ == "__main__":
    unittest.main()
