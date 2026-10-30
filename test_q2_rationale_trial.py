"""Trial A changes only unresolved-identity rationales, not business decisions."""
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
    with patch.object(q10, "_incomplete_identity_rationale", q10._relationship_rationale):
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


class RationaleTrialTests(unittest.TestCase):
    def test_incomplete_decisions_change_only_rationale(self):
        for action in q10.ACTIONS:
            for currency in ("USD", "EUR", "INR", "JPY", "KWD"):
                with self.subTest(action=action, currency=currency):
                    ceiling = "199.00" if currency == "JPY" else "199.99"
                    package = fixtures.invoice_package(action, ceiling if action == "request_approval" else "250.00",
                                                       currency=currency)
                    baseline, trial = baseline_decision(package), q10.decide(package)
                    self.assertEqual(trial["action"], action)
                    self.assertEqual(set(trial), set(baseline))
                    self.assertEqual({key: value for key, value in trial.items() if key != "rationale"},
                                     {key: value for key, value in baseline.items() if key != "rationale"})
                    if trial["unresolvedFacts"]:
                        self.assertNotEqual(trial["rationale"], baseline["rationale"])
                        self.assertNotIn(': "', trial["rationale"])
                        for ref in trial["evidenceRefs"]:
                            self.assertEqual(trial["rationale"].count("[" + ref + "]"), 1)
                    else:
                        self.assertEqual(trial, baseline)

    def test_complete_decisions_do_not_call_trial_helper(self):
        for action in q10.ACTIONS:
            for currency in ("USD", "EUR", "INR"):
                with self.subTest(action=action, currency=currency):
                    package = complete_package(action, currency)
                    baseline = baseline_decision(package)
                    self.assertFalse(baseline["unresolvedFacts"])
                    with patch.object(q10, "_incomplete_identity_rationale", side_effect=AssertionError("Complete case changed")):
                        self.assertEqual(q10.decide(package), baseline)
                    for ref in baseline["evidenceRefs"]:
                        self.assertIn(ref + ': "', baseline["rationale"])

    def test_claims_explain_each_controlling_role(self):
        expected = {
            "settle_invoice": ("different order PO-EARLIER", "within the 25000 minor-unit ceiling", "Autonomous settlement is permitted"),
            "request_approval": ("different order PO-EARLIER", "above the 19999 minor-unit ceiling", "A named approver is required"),
            "hold_invoice": ("changed remittance instructions", "verification still pending", "paused until verification completes"),
            "open_exception": ("controlling signed commercial records", "exception workflow", "unresolved discrepancy"),
        }
        for action, phrases in expected.items():
            with self.subTest(action=action):
                decision = q10.decide(fixtures.invoice_package(action, "199.99" if action == "request_approval" else "250.00"))
                first = fixtures.citation_text(decision["rationale"], "R_SOURCE0")
                second = fixtures.citation_text(decision["rationale"], "R_SOURCE1")
                third = fixtures.citation_text(decision["rationale"], "R_SOURCE2")
                self.assertIn("20000", first)
                self.assertIn("PO-CURRENT", first)
                self.assertIn(phrases[0], second)
                self.assertIn(phrases[1], second if action == "hold_invoice" else third)
                self.assertIn(phrases[2], third)
                if action in ("hold_invoice", "open_exception"):
                    self.assertIn("signed payee account AC-OLD", first)
                    self.assertEqual(decision["facts"]["vendorName"], "unknown")
                else:
                    self.assertIn("receiving entry confirms the billed units", first)

    def test_semantic_confirmation_is_bound_to_its_reference(self):
        for location in (1, 2):
            with self.subTest(location=location):
                package = semantic_package(bank_location=location)
                trace = {}
                decision = q10.decide(package, trace)
                self.assertEqual(trace["parser"], "semantic")
                self.assertEqual(decision["action"], "settle_invoice")
                self.assertEqual(decision["facts"]["invoiceNumber"], "unknown")
                for index in range(3):
                    claim = fixtures.citation_text(decision["rationale"], f"R_SOURCE{index}")
                    self.assertEqual("Remittance verification is confirmed" in claim, index == location)
                baseline = baseline_decision(package)
                self.assertEqual({key: value for key, value in decision.items() if key != "rationale"},
                                 {key: value for key, value in baseline.items() if key != "rationale"})

    def test_absent_or_pending_confirmation_is_not_invented(self):
        cases = [semantic_package()]
        cases += [semantic_package(bank_location=1, bank_status=status)
                  for status in ("not yet verified", "not confirmed", "not completed", "awaiting independent verification")]
        for package in cases:
            with self.subTest(text=package["documents"][1]["text"]):
                decision = q10.decide(package)
                self.assertNotIn("Remittance verification is confirmed", decision["rationale"])
                self.assertNotIn("receiving entry confirms", decision["rationale"])
                self.assertEqual(decision["action"], "settle_invoice")

    def test_semantic_claims_ignore_namespaces_and_document_order(self):
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
        self.assertIn("Remittance verification is confirmed", fixtures.citation_text(renamed["rationale"], "R_FRESH1"))

    def test_oversized_rationale_retains_source_excerpt_fallback(self):
        package = fixtures.invoice_package()
        for document in package["documents"]:
            document["text"] = document["text"].replace("PO-CURRENT", "PO-" + "X" * 800)
        baseline, trial = baseline_decision(package), q10.decide(package)
        self.assertEqual(trial, baseline)
        self.assertTrue(60 <= len(trial["rationale"]) <= 1500)
        for ref in trial["evidenceRefs"]:
            self.assertIn(ref + ': "', trial["rationale"])


if __name__ == "__main__":
    unittest.main()
