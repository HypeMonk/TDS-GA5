"""Q2-only regressions for the business failures observed on Render."""
import importlib.util
import itertools
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("render_q2_fixtures", ROOT / "test_q10_evidence.py")
fixtures = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixtures)
q10 = fixtures.q10


def decode(value):
    if isinstance(value, dict):
        return value
    try:
        return json.loads(value or "{}")
    except (ValueError, TypeError):
        return {}


def captured_proposals():
    seen = set()
    paths = list(ROOT.parent.glob("render-q2-business-*/q10-http.json"))
    paths += list(ROOT.parent.glob("q2-v31-review-*/q10-http.json"))
    for path in paths:
        sends, outcomes = {}, {}
        for row in json.loads(path.read_text(encoding="utf-8")):
            if row.get("status_code") != 200:
                continue
            body, response = decode(row.get("body")), decode(row.get("response_body"))
            message, task = body.get("message") or {}, response.get("task") or {}
            packages, results = [], []
            for part in message.get("parts") or []:
                data = part.get("data") or {}
                if isinstance(data, dict):
                    packages.extend(data.get("packages") or [])
                    results.extend(data.get("results") or [])
            if packages and task.get("id"):
                proposals = {p["packageId"]: p for art in task.get("artifacts", [])
                             for part in art.get("parts", []) for p in (part.get("data") or {}).get("proposals", [])}
                sends[task["id"]] = packages, proposals
            for result in results:
                outcomes[(message.get("taskId"), result["packageId"])] = result.get("outcome")
        for task, (packages, proposals) in sends.items():
            for package in packages:
                original = proposals.get(package["packageId"])
                outcome = outcomes.get((task, package["packageId"]))
                if not original or outcome not in ("ACCEPTED", "REJECTED"):
                    continue
                semantic = {field: original[field] for field in ("action", "facts", "evidenceRefs", "rationale")}
                identity = (q10.canonical(sorted(package["documents"], key=q10.canonical)),
                            q10.canonical(semantic), outcome)
                if identity not in seen:
                    seen.add(identity)
                    yield package, original, outcome


class RenderBusinessTests(unittest.TestCase):
    def assert_source_binding(self, package, decision):
        records = [(q10.BRACKET_REF.findall(paragraph), paragraph) for _, paragraph in q10._case_paragraphs(package)]
        selected = "\n".join(text for refs, text in records if set(refs) & set(decision["evidenceRefs"]))
        for field in ("invoiceNumber", "vendorName"):
            value = decision["facts"][field]
            if field in decision.get("unresolvedFacts", []):
                self.assertEqual(value, "not provided")
                self.assertIn("Missing source fields", decision["rationale"])
            else:
                self.assertIn(value, selected)
        self.assertEqual(len(set(decision["evidenceRefs"])), 3)
        self.assertTrue(60 <= len(decision["rationale"]) <= 1500)
        for ref in decision["evidenceRefs"]:
            self.assertEqual(decision["rationale"].count(ref), 1)
            self.assertEqual(decision["rationale"].count(ref + ': "'), 1)

    def test_current_order_is_not_substituted_for_a_missing_invoice(self):
        for action in ("settle_invoice", "request_approval"):
            for currency in ("USD", "EUR", "INR", "JPY", "KWD"):
                with self.subTest(action=action, currency=currency):
                    ceiling = ("199.00" if currency == "JPY" else "199.99") if action == "request_approval" else "250.00"
                    package = fixtures.invoice_package(action, ceiling=ceiling, currency=currency)
                    decision = q10.decide(package)
                    self.assertEqual(decision["action"], action)
                    self.assertEqual(decision["facts"]["invoiceNumber"], "not provided")
                    self.assertIn("PO-CURRENT", decision["rationale"])
                    self.assertNotEqual(decision["facts"]["invoiceNumber"], "PO-EARLIER")
                    self.assert_source_binding(package, decision)

    def test_signed_payee_account_is_not_a_vendor_name(self):
        for action in ("hold_invoice", "open_exception"):
            package = fixtures.invoice_package(action)
            decision = q10.decide(package)
            self.assertEqual(decision["action"], action)
            self.assertEqual(decision["facts"]["vendorName"], "not provided")
            self.assertIn("AC-OLD", decision["rationale"])
            self.assert_source_binding(package, decision)

    def test_reference_renaming_and_document_order_do_not_change_identity(self):
        package = fixtures.invoice_package("request_approval", ceiling="199.99", bank_with_ledger=True)
        for index, document in enumerate(package["documents"]):
            document["text"] = document["text"].replace("R_SOURCE%d" % index, "R_RENAMED%d" % index)
        expected = q10.decide(package)
        for documents in itertools.permutations(package["documents"]):
            actual = q10.decide(dict(package, documents=list(documents)))
            self.assertEqual(actual, expected)
            self.assert_source_binding(package, actual)

    def test_archive_identity_cannot_replace_current_identity(self):
        package = fixtures.invoice_package("hold_invoice")
        package["documents"][-1]["text"] = "[R_ARCHIVE] Archived supplier memo says invoice INV-DECOY-1 belongs to Decoy Vendor with account AC-NEW."
        actual = q10.decide(package)
        self.assertEqual(actual["facts"]["vendorName"], "not provided")
        self.assertEqual(actual["facts"]["invoiceNumber"], "INV-TEST-1")
        self.assertNotIn("R_ARCHIVE", actual["evidenceRefs"])

    def test_truly_absent_semantic_payee_is_not_invented(self):
        package = {"packageId": "pkg-no-payee", "documents": [
            {"name": "invoice.txt", "text": "[R_INVOICE] Signed invoice record INV-NONE-1 for purchase order PO-NONE-1 states INR 600.00."},
            {"name": "bank.txt", "text": "[R_BANKING] The account changed from AC-OLD to AC-NEW; callback is not yet verified."},
            {"name": "control.txt", "text": "[R_CONTROL] Remittance controls require payment to pause until independent verification completes."}]}
        decision = q10.decide(package)
        self.assertEqual(decision["action"], "hold_invoice")
        self.assertEqual(decision["facts"]["vendorName"], "not provided")
        self.assertEqual(decision["unresolvedFacts"], ["vendorName"])

    def test_explicit_human_payee_name_is_preserved(self):
        package = fixtures.invoice_package("hold_invoice")
        package["documents"][0]["text"] = package["documents"][0]["text"].replace("payee AC-OLD", "payee Northstar")
        decision = q10.decide(package)
        self.assertEqual(decision["facts"]["vendorName"], "Northstar")
        self.assertEqual(decision["unresolvedFacts"], [])
        self.assert_source_binding(package, decision)

    def test_current_signed_payee_wins_over_historical_ledger_vendor(self):
        package = fixtures.invoice_package("open_exception")
        package["documents"][0]["text"] = package["documents"][0]["text"].replace("payee AC-OLD", "payee Northstar")
        package["documents"].append({"name": "ledger.txt", "text": "[R_PREVIOUS] Payment ledger: a disbursement for USD 200.00 to Previous Supplier previously settled order PO-EARLIER. The currently submitted order is PO-CURRENT."})
        decision = q10.decide(package)
        self.assertEqual(decision["action"], "open_exception")
        self.assertEqual(decision["facts"]["vendorName"], "Northstar")
        self.assert_source_binding(package, decision)

    def test_current_semantic_invoice_vendor_wins_over_historical_payment(self):
        package = {"packageId": "pkg-current-vendor", "documents": [
            {"name": "invoice.txt", "text": "[R_CURRENT] Signed invoice record INV-CURRENT-1 for purchase order PO-CURRENT-1 names payee Northstar Labs and USD 200.00."},
            {"name": "ledger.txt", "text": "[R_PREVIOUS] Current ledger: payment of USD 200.00 to Previous Supplier settled PO-OLD-1. The currently submitted order is PO-CURRENT-1."},
            {"name": "authority.txt", "text": "[R_AUTHORITY] Delegated settlement authority ceiling is USD 500.00."}]}
        decision = q10.decide(package)
        self.assertEqual(decision["action"], "settle_invoice")
        self.assertEqual(decision["facts"]["vendorName"], "Northstar Labs")
        self.assert_source_binding(package, decision)

    def test_namespace_and_date_do_not_invent_an_invoice(self):
        package = fixtures.invoice_package("settle_invoice")
        for identity, date in (("pkg-alternate-123", "2025-01-01T08:30:00Z"),
                               ("pkg-alternate-987", "2026-12-01T08:30:00Z")):
            current = dict(package, packageId=identity, receivedAt=date)
            decision = q10.decide(current)
            self.assertEqual(decision["facts"]["invoiceNumber"], "not provided")
            self.assert_source_binding(current, decision)

    def test_render_capture_preserves_accepted_and_flags_missing_data(self):
        accepted = rejected = 0
        for package, original, outcome in captured_proposals():
            actual = q10.decide(package)
            with self.subTest(package=package["packageId"], outcome=outcome):
                if outcome == "ACCEPTED":
                    accepted += 1
                    for field in ("action", "facts", "evidenceRefs", "rationale"):
                        self.assertEqual(actual[field], original[field])
                else:
                    rejected += 1
                    self.assertEqual(actual["action"], original["action"])
                    self.assertEqual(actual["evidenceRefs"], original["evidenceRefs"])
                    for field, value in original["facts"].items():
                        if field not in actual.get("unresolvedFacts", []):
                            self.assertEqual(actual["facts"][field], value)
                    self.assertTrue(actual["unresolvedFacts"])
                    self.assert_source_binding(package, actual)
        if not accepted and not rejected:
            self.skipTest("No local Render capture available")
        self.assertGreater(accepted, 0)
        self.assertGreater(rejected, 0)
        print("Render replay: %d accepted proposals preserved; %d rejected cases retain explicit missing-data markers; no new grade verified" % (accepted, rejected))


if __name__ == "__main__":
    unittest.main()
