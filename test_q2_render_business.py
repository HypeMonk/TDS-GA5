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
    for path in ROOT.parent.glob("render-q2-business-*/q10-http.json"):
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
            self.assertNotEqual(decision["facts"][field], "unknown")
            self.assertIn(decision["facts"][field], selected)
        self.assertEqual(len(set(decision["evidenceRefs"])), 3)
        self.assertTrue(60 <= len(decision["rationale"]) <= 1500)
        for ref in decision["evidenceRefs"]:
            self.assertEqual(decision["rationale"].count(ref + ': "'), 1)

    def test_current_order_is_used_not_the_previously_paid_order(self):
        for action in ("settle_invoice", "request_approval"):
            for currency in ("USD", "EUR", "INR", "JPY", "KWD"):
                with self.subTest(action=action, currency=currency):
                    ceiling = ("199.00" if currency == "JPY" else "199.99") if action == "request_approval" else "250.00"
                    package = fixtures.invoice_package(action, ceiling=ceiling, currency=currency)
                    decision = q10.decide(package)
                    self.assertEqual(decision["action"], action)
                    self.assertEqual(decision["facts"]["invoiceNumber"], "PO-CURRENT")
                    self.assertNotEqual(decision["facts"]["invoiceNumber"], "PO-EARLIER")
                    self.assert_source_binding(package, decision)

    def test_signed_payee_is_used_not_unverified_new_account(self):
        for action in ("hold_invoice", "open_exception"):
            package = fixtures.invoice_package(action)
            decision = q10.decide(package)
            self.assertEqual(decision["action"], action)
            self.assertEqual(decision["facts"]["vendorName"], "AC-OLD")
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
        self.assertEqual(actual["facts"]["vendorName"], "AC-OLD")
        self.assertEqual(actual["facts"]["invoiceNumber"], "INV-TEST-1")
        self.assertNotIn("R_ARCHIVE", actual["evidenceRefs"])

    def test_truly_absent_semantic_payee_is_not_invented(self):
        package = {"packageId": "pkg-no-payee", "documents": [
            {"name": "invoice.txt", "text": "[R_INVOICE] Signed invoice record INV-NONE-1 for purchase order PO-NONE-1 states INR 600.00."},
            {"name": "bank.txt", "text": "[R_BANKING] The account changed from AC-OLD to AC-NEW; callback is not yet verified."},
            {"name": "control.txt", "text": "[R_CONTROL] Remittance controls require payment to pause until independent verification completes."}]}
        decision = q10.decide(package)
        self.assertEqual(decision["action"], "hold_invoice")
        self.assertEqual(decision["facts"]["vendorName"], "unknown")
        self.assertEqual(decision["unresolvedFacts"], ["vendorName"])

    def test_render_capture_preserves_accepted_and_changes_only_missing_identities(self):
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
                        if value != "unknown":
                            self.assertEqual(actual["facts"][field], value)
                    self.assert_source_binding(package, actual)
        if not accepted and not rejected:
            self.skipTest("No local Render capture available")
        self.assertGreater(accepted, 0)
        self.assertGreater(rejected, 0)
        print("Render replay: %d accepted proposals preserved; %d rejected identity cases changed without action/amount/reference changes" % (accepted, rejected))


if __name__ == "__main__":
    unittest.main()
