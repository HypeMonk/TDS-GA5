"""Invoice citation provenance, authority boundaries, and stable evidence selection."""
import importlib.util
import itertools
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("evidence_q10", ROOT / "q10.py")
q10 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(q10)

CONTROL = ("Payment controls: do not pay a commercial order already discharged; a material "
           "order/invoice difference requires the exception process; an unverified bank change "
           "pauses payment. Otherwise follow the delegation limit.")
BANK = ("Vendor master lists account AC-OLD. Remittance instructions now specify AC-OLD. "
        "The callback for this request is confirmed through the established vendor channel.")


def invoice_package(action="settle_invoice", ceiling="250.00", bank_with_ledger=False, currency="USD"):
    signed = f"Signed commercial instrument INV-TEST-1 covers order PO-CURRENT, payee AC-OLD and {currency} 200.00."
    order_total = "210.00" if action == "open_exception" else "200.00"
    order = (f"Order PO-CURRENT is signed for {currency} {order_total}. The receiving entry confirms the billed units; "
             f"submitted invoice total is {currency} 200.00. No corrected invoice exists.")
    paid_order = "PO-CURRENT" if action == "reject_duplicate" else "PO-EARLIER"
    ledger = (f"Payment ledger: a disbursement for {currency} 200.00 to Example Supplier previously settled "
              f"order {paid_order}. The currently submitted order is PO-CURRENT.")
    limit = (f"Approved autonomous payment ceiling for {currency} is {currency} {ceiling}. "
             "A named approver is required when the payable total is greater.")
    if action == "reject_duplicate":
        texts = [signed, ledger, CONTROL]
    elif action == "open_exception":
        texts = [signed + " The supplier has not resolved the valuation dispute.", order, CONTROL]
    elif action == "hold_invoice":
        bank = BANK.replace("now specify AC-OLD", "now specify AC-NEW").replace(
            "confirmed through the established vendor channel", "awaiting independent verification")
        texts = [signed, bank, CONTROL]
    elif bank_with_ledger:
        texts = [order, ledger + " " + BANK + " " + CONTROL, limit]
    else:
        texts = [order, ledger, BANK + " " + limit + " " + CONTROL]
    documents = [{"name": f"record-{i}.txt", "text": f"[R_SOURCE{i}] {text}"} for i, text in enumerate(texts)]
    documents.append({"name": "archive.txt", "text": "[R_DECOY00] Archive examples mention every available action but govern no live case."})
    return {"packageId": "pkg-evidence", "documents": documents}


class InvoiceEvidenceTests(unittest.TestCase):
    def assert_citations(self, package, decision):
        rationale = decision["rationale"]
        self.assertGreaterEqual(len(rationale), 60)
        self.assertLessEqual(len(rationale), 1500)
        self.assertIn("Action " + decision["action"], rationale)
        self.assertEqual(decision["evidenceRefs"], ["R_SOURCE0", "R_SOURCE1", "R_SOURCE2"])
        for doc in package["documents"][:3]:
            ref, text = doc["text"].split("] ", 1)
            ref = ref[1:]
            self.assertEqual(rationale.count(ref), 1)
            self.assertIn(f'{ref}: "{text}".', rationale)
        self.assertNotIn("R_DECOY00", rationale)

    def test_each_action_cites_actual_sources(self):
        for action in q10.ACTIONS:
            for currency in ("USD", "EUR", "INR"):
                with self.subTest(action=action, currency=currency):
                    package = invoice_package(action, "199.99" if action == "request_approval" else "250.00", currency=currency)
                    decision = q10.decide(package)
                    self.assertEqual(decision["action"], action)
                    self.assertEqual(decision["facts"]["amountMinor"], 20000)
                    self.assertEqual(decision["facts"]["currency"], currency)
                    self.assert_citations(package, decision)

    def test_bank_verification_stays_with_its_own_reference(self):
        package = invoice_package("request_approval", ceiling="199.99", bank_with_ledger=True)
        decision = q10.decide(package)
        self.assertEqual(decision["action"], "request_approval")
        self.assert_citations(package, decision)
        ceiling_citation = decision["rationale"].split('R_SOURCE2: "', 1)[1].split('".', 1)[0]
        self.assertNotIn("callback", ceiling_citation)
        self.assertNotIn("account", ceiling_citation)
        self.assertIn("above the 19999 minor-unit ceiling", decision["rationale"])

    def test_authority_boundary_includes_equality(self):
        for ceiling, expected in (("199.99", "request_approval"), ("200.00", "settle_invoice"), ("200.01", "settle_invoice")):
            with self.subTest(ceiling=ceiling):
                decision = q10.decide(invoice_package(ceiling=ceiling))
                self.assertEqual(decision["action"], expected)

    def test_absent_invoice_and_vendor_names_remain_explicit(self):
        cases = (("settle_invoice", "invoiceNumber", "PO-CURRENT"),
                 ("hold_invoice", "vendorName", "AC-OLD"),
                 ("open_exception", "vendorName", "AC-OLD"))
        for action, field, identifier in cases:
            with self.subTest(action=action):
                package = invoice_package(action)
                decision = q10.decide(package)
                self.assertEqual(decision["facts"][field], "unknown")
                self.assertEqual(decision["unresolvedFacts"], [field])
                self.assertIn(identifier, decision["rationale"])
                self.assert_citations(package, decision)

    def test_document_permutations_preserve_full_decision(self):
        for action in q10.ACTIONS:
            package = invoice_package(action, "199.99" if action == "request_approval" else "250.00")
            expected = q10.decide(package)
            for documents in itertools.permutations(package["documents"]):
                with self.subTest(action=action, names=[d["name"] for d in documents]):
                    self.assertEqual(q10.decide(dict(package, documents=list(documents))), expected)

    def test_reference_renaming_preserves_meaning(self):
        package = invoice_package()
        original = q10.decide(package)
        for index, doc in enumerate(package["documents"][:3]):
            doc["text"] = doc["text"].replace(f"R_SOURCE{index}", f"R_FRESH73{index}8")
        changed = q10.decide(package)
        self.assertEqual(changed["facts"], original["facts"])
        self.assertEqual(changed["action"], original["action"])
        self.assertEqual(changed["evidenceRefs"], [f"R_FRESH73{i}8" for i in range(3)])
        self.assertNotIn("R_SOURCE", changed["rationale"])

    def test_semantic_sources_do_not_invent_bank_confirmation(self):
        texts = [
            "Issued invoice record INV-ALT-2 for purchase order PO-ALT-2 states EUR 400.00.",
            "Current ledger: payment of EUR 400.00 to Example Industries settled PO-OLD-2. The currently submitted order is PO-ALT-2.",
            "Delegated settlement authority ceiling is EUR 500.00.",
        ]
        package = {"packageId": "pkg-paraphrase", "documents": [
            {"name": f"current-{i}.txt", "text": f"[R_SOURCE{i}] {text}"} for i, text in enumerate(texts)]}
        decision = q10.decide(package)
        self.assertEqual(decision["action"], "settle_invoice")
        self.assert_citations(package, decision)
        self.assertNotIn("remittance", decision["rationale"])
        self.assertNotIn("confirmed", decision["rationale"])

    def test_pending_verification_is_not_misread_as_confirmed(self):
        for status in ("not yet verified", "not confirmed", "not completed", "awaiting independent verification"):
            with self.subTest(status=status):
                parsed = q10._semantic_bank_record(
                    "The remittance account changed from AC-OLD to AC-NEW; callback is " + status + ".")
                self.assertEqual(parsed, (True, True, False))

    def test_semantic_hold_uses_explicit_payee_and_separate_control(self):
        texts = [
            "Signed invoice record INV-ALT-3 for purchase order PO-ALT-3 names payee Example Industries and INR 600.00.",
            "The remittance account changed from AC-OLD to AC-NEW; callback is not yet verified.",
            "Remittance controls require payment to pause until independent verification completes.",
        ]
        package = {"packageId": "pkg-payee", "documents": [
            {"name": f"current-{i}.txt", "text": f"[R_SOURCE{i}] {text}"} for i, text in enumerate(texts)]}
        package["documents"][0]["text"] += "\n\nThe month-end report groups documents by arrival time rather than by the date printed on the invoice."
        trace = {}
        decision = q10.decide(package, trace=trace)
        self.assertEqual(trace["parser"], "semantic")
        self.assertEqual(decision["action"], "hold_invoice")
        self.assertEqual(decision["facts"]["vendorName"], "Example Industries")
        self.assertEqual(decision["evidenceRefs"], ["R_SOURCE0", "R_SOURCE1", "R_SOURCE2"])
        package["documents"][0]["text"] = package["documents"][0]["text"].replace("Example Industries", "AC-OLD")
        self.assertEqual(q10.decide(package)["facts"]["vendorName"], "unknown")

    def test_invoice_reference_to_order_is_not_a_second_order_record(self):
        texts = [
            "Signed invoice record INV-ALT-9 for purchase order PO-ALT-9 states USD 200.00.",
            "Signed purchase order PO-ALT-9 totals USD 210.00; submitted invoice total is USD 200.00.",
            "Payment policy requires an exception while the invoice and order totals disagree.",
        ]
        package = {"packageId": "pkg-conflict", "documents": [
            {"name": f"current-{i}.txt", "text": f"[R_SOURCE{i}] {text}"} for i, text in enumerate(texts)]}
        trace = {}
        decision = q10.decide(package, trace=trace)
        self.assertEqual(trace["parser"], "semantic")
        self.assertEqual(decision["action"], "open_exception")
        self.assertEqual(decision["facts"]["amountMinor"], 20000)
        self.assertEqual(decision["evidenceRefs"], ["R_SOURCE0", "R_SOURCE1", "R_SOURCE2"])

    def test_long_excerpts_fit_contract_and_remain_source_prefixes(self):
        refs = [f"R_LONG_{i}" for i in range(3)]
        facts = {"invoiceNumber": "unknown", "vendorName": "Example Supplier", "amountMinor": 20000, "currency": "USD"}
        for lengths in ((8, 2000, 6000), (6000, 6000, 6000), (6000, 2000, 8)):
            with self.subTest(lengths=lengths):
                sources = {ref: (f"Source {i} record words " * length).strip() for i, (ref, length) in enumerate(zip(refs, lengths))}
                rationale = q10._relationship_rationale("settle_invoice", facts, "PO-CURRENT", refs,
                                                      {"paidOrder": "PO-EARLIER", "limitMinor": 25000}, sources)
                self.assertLessEqual(len(rationale), 1500)
                for ref in refs:
                    self.assertEqual(rationale.count(ref), 1)
                    excerpt = rationale.split(f'{ref}: "', 1)[1].split('".', 1)[0]
                    self.assertTrue(sources[ref].startswith(excerpt.removesuffix("...")))


if __name__ == "__main__":
    unittest.main()
