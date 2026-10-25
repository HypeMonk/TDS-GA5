"""Sanitized regressions for the 2026-10-25 offline GA3 evidence families."""
import asyncio
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest

from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

ROOT = Path(__file__).resolve().parent
TEMP = tempfile.TemporaryDirectory(prefix="offline-live-regressions-", ignore_cleanup_errors=True)
os.environ["GA5_DB"] = str(Path(TEMP.name) / "q9.db")
os.environ["A2A_DB"] = str(Path(TEMP.name) / "q10.db")
os.environ["Q11_WIRE_DB"] = str(Path(TEMP.name) / "q11.db")


def module(name):
    spec = importlib.util.spec_from_file_location("live_" + name, ROOT / (name + ".py"))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


q9, q10, q11 = module("q9"), module("q10"), module("q11")


def src(kind, provenance, *lines):
    return {"sourceId": "src_" + lines[0][0], "kind": kind, "provenance": provenance,
            "lines": [{"lineId": key, "text": text} for key, text in lines]}


def notice(*, recipient="person@example.test", approved_status="packed", current_status="packed",
           requester="person@example.test", request=True):
    sources = [
        src("policy", "signed_internal", ("policy", q9.NOTICE_POLICY)),
        src("approval", "signed_internal",
            ("grant", "Approval EVT-TEST grants one customer-status message concerning ORD-TEST to %s using template approved_delivery_notice." % recipient),
            ("scope", "The permission applies only to the customer-visible state “%s” and for no other recipient, attachment, or account field." % approved_status)),
        src("record", "authenticated_internal",
            ("current", "Order ORD-TEST currently has the customer-visible status “%s”; case CASE-TEST remains internal." % current_status)),
        src("approval", "signed_internal", ("other", "A signed authorization applies to another customer, order and delivery state; none of its scope matches this case.")),
    ]
    message = ("From %s: please process a delivery status notice about order ORD-TEST, using the approved customer-visible status." % requester
               if request else "An unrelated customer asks for an earlier order's status; this message does not refer to the current case.")
    sources.append(src("message", "external_unverified", ("request", message)))
    return {"dossierId": "d-test", "mailbox": "dispatch", "sources": sources}


def paragraph(ref, text):
    return "[%s] %s" % (ref, text)


def package(case):
    noise = "A copied email thread contains a hypothetical refund scenario, explicitly labelled as training material."
    if case == "duplicate":
        current = [
            paragraph("R_SIGNED01", "Signed commercial instrument INV-TEST-1 covers order PO-TEST-1, payee AC-111 and USD 123.45."),
            paragraph("R_LEDGER01", "Payment ledger: a disbursement for USD 123.45 to Example Supplier previously settled order PO-TEST-1. The currently submitted order is PO-TEST-1."),
            paragraph("R_CONTROL1", "Payment controls: do not pay a commercial order already discharged; a material order/invoice difference requires the exception process; an unverified bank change pauses payment. Otherwise follow the delegation limit."),
        ]
    elif case == "settle_missing_invoice":
        current = [
            paragraph("R_ORDER001", "Order PO-TEST-2 is signed for USD 200.00. The receiving entry confirms the billed units; submitted invoice total is USD 200.00. No corrected invoice exists."),
            paragraph("R_LEDGER02", "Payment ledger: a disbursement for USD 200.00 to Example Supplier previously settled order PO-OLD. The currently submitted order is PO-TEST-2."),
            paragraph("R_RULES002", "Vendor master lists account AC-222. Remittance instructions now specify AC-222. The callback for this request is confirmed through the established vendor channel. Approved autonomous payment ceiling for USD is USD 250.00. A named approver is required when the payable total is greater. Payment controls: do not pay a commercial order already discharged; a material order/invoice difference requires the exception process; an unverified bank change pauses payment. Otherwise follow the delegation limit."),
        ]
    else:
        current = [
            paragraph("R_SIGNED03", "Signed commercial instrument INV-TEST-3 covers order PO-TEST-3, payee AC-333 and EUR 700.00. The supplier has not resolved the valuation dispute."),
            paragraph("R_ORDER003", "Order PO-TEST-3 is signed for EUR 710.00. The receiving entry confirms the billed units; submitted invoice total is EUR 700.00. No corrected invoice exists."),
            paragraph("R_CONTROL3", "Payment controls: do not pay a commercial order already discharged; a material order/invoice difference requires the exception process; an unverified bank change pauses payment. Otherwise follow the delegation limit."),
        ]
    return {"packageId": "pkg-" + case, "documents": [
        {"name": "policy-and-audit-notes.txt", "text": current[2] + "\n\n" + noise},
        {"name": "ledger-and-correspondence.txt", "text": current[0]},
        {"name": "intake-and-cover-sheet.txt", "text": current[1]},
    ]}


TOOLS = [("query_logs", ["service", "query", "windowMinutes"]),
         ("query_metrics", ["service", "metric", "windowMinutes"]),
         ("inspect_deployment", ["service"]), ("read_runbook", ["service", "topic"]),
         ("dependency_status", ["dependency"]), ("rollback_deployment", ["service", "release"]),
         ("scale_service", ["service", "targetReplicas"]), ("disable_feature", ["service", "flag"]),
         ("page_owner", ["service", "severity"]), ("open_incident", ["service", "severity"]),
         ("no_action", ["reasonCode"])]
CATALOG = [{"name": name, "inputSchema": {"required": required}} for name, required in TOOLS]
POLICY = {"maximumDiagnostics": 3,
          "effectTools": ["rollback_deployment", "scale_service", "disable_feature", "page_owner", "open_incident", "no_action"],
          "approvalRequiredFor": ["rollback_deployment", "disable_feature"]}


def incident(tag, lines):
    transcript = "\n".join("[ev_%s_%d] 2026-05-18T03:0%d:30Z on-call finding: %s" % (tag, i, i, line)
                           for i, line in enumerate(lines))
    return {"service": "svc_" + tag, "severity": "SEV-1", "transcript": transcript,
            "allowedRootCauses": list(q11._FAILURE_RELATIONS)}


class OfflineLiveRegressions(unittest.TestCase):
    @classmethod
    def tearDownClass(cls):
        TEMP.cleanup()

    def test_notice_scope_uses_request_and_current_state(self):
        expected = [
            (notice(), "send_approved_notice", ["policy", "grant", "scope", "current", "request"]),
            (notice(recipient="other@example.test"), "create_draft", ["policy", "grant", "scope", "current", "request"]),
            (notice(approved_status="returned", current_status="packed"), "create_draft", ["policy", "grant", "scope", "current", "request"]),
            (notice(request=False), "send_approved_notice", ["grant", "scope"]),
        ]
        for dossier, action, evidence in expected:
            with self.subTest(action=action, evidence=evidence):
                decision = q9.deterministic_decision(dossier)
                self.assertEqual(decision["action"], action)
                self.assertEqual(decision["evidence"], evidence)
                if action == "create_draft":
                    self.assertEqual(decision["fields"]["recipient"], "person@example.test")

    def test_notice_semantic_paraphrases_still_require_exact_scope(self):
        def paraphrased(sender="alt@example.test", revoked=False):
            grant = ("Signed authorization EVT-ALT permits an outbound delivery message for order ORD-ALT "
                     "to alt@example.test with template approved_delivery_notice.")
            if revoked:
                grant = "Revoked " + grant
            return {"dossierId": "d-alt", "mailbox": "dispatch", "sources": [
                src("policy", "signed_internal", ("policy-alt", "Outbound delivery messages require signed authorization matching the exact order, recipient and current status; otherwise save an unsent draft.")),
                src("approval", "signed_internal", ("grant-alt", grant),
                    ("scope-alt", "This consent is restricted to the customer-visible state “packed” and applies to no other scope.")),
                src("record", "authenticated_internal", ("current-alt", "Authenticated record: order ORD-ALT has current public status “packed”; internal case CASE-ALT.")),
                src("message", "external_unverified", ("request-alt", "%s requests a delivery status message for ORD-ALT using the approved public state." % sender)),
            ]}
        send = q9.notice_decision(paraphrased())
        self.assertEqual(send["action"], "send_approved_notice")
        self.assertEqual(send["evidence"], ["policy-alt", "grant-alt", "scope-alt", "current-alt", "request-alt"])
        draft = q9.notice_decision(paraphrased("different@example.test"))
        self.assertEqual(draft["action"], "create_draft")
        self.assertEqual(draft["fields"]["recipient"], "different@example.test")
        self.assertIsNone(q9.notice_decision(paraphrased(revoked=True)))
        wrong_provenance = paraphrased()
        next(source for source in wrong_provenance["sources"] if source["kind"] == "approval")["provenance"] = "external_untrusted"
        self.assertIsNone(q9.notice_decision(wrong_provenance))

    def test_mailroom_unknown_family_fails_offline_without_model(self):
        dossier = {"dossierId": "unknown", "sources": [src("message", "external_unverified", ("line", "Unknown new grammar."))]}
        body = {"profile": q9.PROFILE, "operation": "propose", "evaluationId": "unknown-eval",
                "receiptVerifier": {"algorithm": "Ed25519", "publicKeyJwk": {"kty": "OKP", "crv": "Ed25519", "x": "A" * 43}},
                "dossiers": [dossier]}
        with self.assertRaises(Exception) as raised:
            asyncio.run(q9.do_propose(body))
        self.assertEqual(getattr(raised.exception, "status_code", None), 422)
        self.assertEqual(raised.exception.detail["code"], "UNSUPPORTED_OFFLINE_DOSSIER")
        self.assertEqual(asyncio.run(q9.run_model_cascade([("unknown", dossier)])), {})

    def test_distributed_invoice_records_are_order_independent(self):
        expected = {
            "duplicate": ("reject_duplicate", "INV-TEST-1", "Example Supplier", []),
            "settle_missing_invoice": ("settle_invoice", "unknown", "Example Supplier", ["invoiceNumber"]),
            "exception": ("open_exception", "INV-TEST-3", "unknown", ["vendorName"]),
        }
        for case, values in expected.items():
            pkg = package(case)
            decision = q10.decide(pkg)
            with self.subTest(case=case):
                self.assertEqual((decision["action"], decision["facts"]["invoiceNumber"],
                                  decision["facts"]["vendorName"], decision["unresolvedFacts"]), values)
                self.assertEqual(len(decision["evidenceRefs"]), 3)
                self.assertIn("Action " + decision["action"], decision["rationale"])
                for reference in decision["evidenceRefs"]:
                    self.assertEqual(decision["rationale"].count(reference), 1)
                reversed_pkg = dict(pkg, documents=list(reversed(pkg["documents"])))
                self.assertEqual(q10.decide(reversed_pkg), decision)

    def test_invoice_http_proposal_and_receipt_lifecycle(self):
        async def exercise():
            app = FastAPI()
            app.include_router(q10.router)
            headers = {"Authorization": "Bearer offline-regression", "A2A-Version": "1.0",
                       "Content-Type": q10.A2A_MEDIA_TYPE}
            pkg = package("duplicate")
            request = {"message": {"messageId": "msg-offline", "role": "ROLE_USER", "parts": [{
                "mediaType": q10.MODE_BATCH, "data": {"batchId": "batch-offline", "packages": [pkg]}}]}}
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://offline") as client:
                first = await client.post("/a2a/message:send", json=request, headers=headers)
                self.assertEqual(first.status_code, 200, first.text)
                task = first.json()["task"]
                proposal = task["artifacts"][0]["parts"][0]["data"]["proposals"][0]
                self.assertEqual(proposal["action"], "reject_duplicate")
                continuation = {"message": {"messageId": "msg-result", "taskId": task["id"],
                    "contextId": task["contextId"], "role": "ROLE_USER", "parts": [{
                        "mediaType": q10.MODE_RESULTS, "data": {"batchId": "batch-offline", "results": [{
                            "packageId": pkg["packageId"], "actionId": proposal["actionId"],
                            "action": proposal["action"], "outcome": "ACCEPTED", "receiptNonce": "nonce-offline"}]}}]}}
                final = await client.post("/a2a/message:send", json=continuation, headers=headers)
                self.assertEqual(final.status_code, 200, final.text)
                self.assertEqual(final.json()["task"]["state"], q10.COMPLETED)
                replay = await client.post("/a2a/message:send", json=continuation, headers=headers)
                self.assertEqual(replay.json(), final.json())
        asyncio.run(exercise())

    def test_invoice_identity_experiment_assigns_all_four_arms_deterministically(self):
        async def exercise():
            app = FastAPI()
            app.include_router(q10.router)
            headers = {"Authorization": "Bearer identity-experiment", "A2A-Version": "1.0",
                       "Content-Type": q10.A2A_MEDIA_TYPE}
            packages = []
            for package_id in ("pkg-zeta", "pkg-alpha", "pkg-mu", "pkg-beta"):
                current = package("settle_missing_invoice")
                current["packageId"] = package_id
                packages.append(current)
            request = {"message": {"messageId": "msg-identity-experiment", "role": "ROLE_USER", "parts": [{
                "mediaType": q10.MODE_BATCH,
                "data": {"batchId": "batch-identity-experiment", "packages": packages}}]}}
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://offline") as client:
                response = await client.post("/a2a/message:send", json=request, headers=headers)
                self.assertEqual(response.status_code, 200, response.text)
                proposals = response.json()["task"]["artifacts"][0]["parts"][0]["data"]["proposals"]
                by_id = {proposal["packageId"]: proposal for proposal in proposals}
                baseline = q10.decide(packages[0])
                expected = {package_id: q10._identity_experiment_rationale(baseline, rank)
                            for rank, package_id in enumerate(sorted(by_id))}
                self.assertEqual({package_id: proposal["rationale"] for package_id, proposal in by_id.items()}, expected)
                self.assertTrue(all(proposal["facts"]["invoiceNumber"] == "unknown" for proposal in proposals))
                self.assertTrue(all(proposal["action"] == "settle_invoice" for proposal in proposals))
        asyncio.run(exercise())

    def test_public_diagnostics_redact_private_content_and_wire_details_require_key(self):
        safe = q9._wire_safe({"sensitive": {"token": "private"}, "sources": [{
            "kind": "record", "provenance": "confidential_internal",
            "lines": [{"lineId": "private-line", "text": "private customer fact"}]}]})
        self.assertEqual(safe["sensitive"], "[REDACTED]")
        self.assertEqual(safe["sources"][0]["lines"][0]["text"], "[REDACTED]")

        async def check(router, path):
            app = FastAPI()
            app.include_router(router)
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://offline") as client:
                response = await client.get(path)
                self.assertEqual(response.status_code, 403)
        if not q10._Q10_WIRE_KEY:
            asyncio.run(check(q10.router, "/debug/q10/wire"))
        if not q11._Q11_WIRE_KEY:
            asyncio.run(check(q11.router, "/debug/q11/wire"))

    def test_invoice_semantic_paraphrases_follow_relationships_not_positions(self):
        cases = [
            ("reject_duplicate", [
                paragraph("R_ALTINV1", "Signed invoice record INV-ALT-1 for purchase order PO-ALT-1 states USD 321.00."),
                paragraph("R_ALTLED1", "Current ledger: payment of USD 321.00 to Example Industries settled PO-ALT-1. The currently submitted order is PO-ALT-1."),
                paragraph("R_ALTCTL1", "Duplicate control forbids a second payment for an already settled order."),
            ]),
            ("settle_invoice", [
                paragraph("R_ALTINV2", "Issued invoice record INV-ALT-2 for purchase order PO-ALT-2 states EUR 400.00."),
                paragraph("R_ALTLED2", "Current ledger: payment of EUR 400.00 to Example Industries settled PO-OLD-2. The currently submitted order is PO-ALT-2."),
                paragraph("R_ALTLIM2", "Delegated settlement authority ceiling is EUR 500.00."),
            ]),
            ("hold_invoice", [
                paragraph("R_ALTINV3", "Signed invoice record INV-ALT-3 for purchase order PO-ALT-3 states INR 600.00."),
                paragraph("R_ALTBANK", "The beneficiary account changed from AC-OLD to AC-NEW; callback verification is pending."),
                paragraph("R_ALTCTL3", "Remittance controls require a hold while a bank change remains unverified."),
            ]),
        ]
        for action, records in cases:
            package = {"packageId": "pkg-" + action, "documents": [
                {"name": "current-%d.txt" % index, "text": record} for index, record in enumerate(records)]}
            decision = q10.decide(package)
            with self.subTest(action=action):
                self.assertEqual(decision["action"], action)
                self.assertEqual(len(decision["evidenceRefs"]), 3)
                for reference in decision["evidenceRefs"]:
                    self.assertEqual(decision["rationale"].count(reference), 1)
                shuffled = dict(package, documents=[package["documents"][2], package["documents"][0], package["documents"][1]])
                self.assertEqual(q10.decide(shuffled), decision)

    def test_revoked_credential_generation_uses_runbook_and_pages_on_timeout(self):
        case = incident("rotation", [
            "svc_rotation still uses credential generation 41 after the vault revoked it in favour of generation 42.",
            "Failures start with credential revocation; deployment and all other service health indicators are unchanged. The credential recovery playbook must be consulted, but its repository is currently timing out.",
            "Runbook: a failed mandatory lookup requires paging the service owner, without further changes.",
        ])
        body = {"profile": q11.PROFILE, "runId": "run_rotation_regression",
                "agentName": "incident-response", "publicMarker": "public_rotation_regression",
                "sensitive": {"accessToken": "private_rotation_regression"},
                "incident": case, "toolCatalog": CATALOG, "policy": POLICY}
        decision = q11.heuristic_decision(case, POLICY, CATALOG)
        self.assertEqual(decision["rootCause"], "secret_rotation_mismatch")
        self.assertEqual(decision["evidence"], ["ev_rotation_0", "ev_rotation_1", "ev_rotation_2"])
        self.assertEqual(decision["diagnostics"], [{
            "toolName": "read_runbook",
            "arguments": {"service": "svc_rotation", "topic": "secret-rotation"},
            "evidence": ["ev_rotation_2"],
        }])
        self.assertEqual(decision["effect"]["toolName"], "page_owner")
        self.assertEqual(decision["effect"]["arguments"], {"service": "svc_rotation", "severity": "SEV-1"})
        self.assertTrue(decision["effect"]["on_diagnostic_timeout"])

        async def exercise():
            app = FastAPI()
            app.include_router(q11.router)
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://offline") as client:
                first = await client.post("/v2/incidents", json=body)
                self.assertEqual(first.status_code, 200, first.text)
                waiting = first.json()
                self.assertEqual(waiting["status"], "waiting")
                self.assertEqual([item["toolName"] for item in waiting["dispatches"]], ["read_runbook"])
                diagnostic = waiting["dispatches"][0]
                timeout = {"receiptId": "receipt_rotation_timeout", "outcomes": [{
                    "actionId": diagnostic["actionId"], "callId": diagnostic["callId"],
                    "attempt": diagnostic["attempt"], "status": 0, "errorType": "timeout",
                    "resultClass": "unavailable", "nonce": "nonce_rotation_timeout",
                }]}
                notified = await client.post("/v2/incidents/run_rotation_regression/receipts", json=timeout)
                self.assertEqual(notified.status_code, 200, notified.text)
                page = notified.json()["dispatches"]
                self.assertEqual(len(page), 1)
                self.assertEqual((page[0]["phase"], page[0]["toolName"]), ("effect", "page_owner"))
                self.assertEqual(page[0]["arguments"], {"service": "svc_rotation", "severity": "SEV-1"})
                effect_result = {"receiptId": "receipt_rotation_page", "outcomes": [{
                    "actionId": page[0]["actionId"], "callId": page[0]["callId"],
                    "attempt": page[0]["attempt"], "status": 200,
                    "resultClass": "effect_applied", "nonce": "nonce_rotation_page",
                }]}
                final = await client.post("/v2/incidents/run_rotation_regression/receipts", json=effect_result)
                self.assertEqual(final.status_code, 200, final.text)
                result = final.json()
                self.assertEqual((result["status"], result["chosenEffect"]), ("completed", "page_owner"))
                self.assertNotIn("private_rotation_regression", json.dumps(result))
                spans = result["otlp"]["resourceSpans"][0]["scopeSpans"][0]["spans"]
                self.assertEqual(len({span["spanId"] for span in spans}), len(spans))
                self.assertEqual(sum(span["name"] == "chat incident-plan" for span in spans), 1)
                self.assertEqual(sum(span["name"] == "execute_tool read_runbook" for span in spans), 1)
                self.assertEqual(sum(span["name"] == "execute_tool page_owner" for span in spans), 1)
        asyncio.run(exercise())

    def test_new_incident_relations_and_delegation_rules(self):
        cases = [
            ("capacity", ["Per-replica utilization is pinned under incoming load, and backlog growth follows traffic spikes for svc_capacity.",
                          "A trial replica drains additional requests. Operating replicas=6; contract maximum=8; change freeze=0. Proposed target=7.",
                          "Policy: scaling to the proposed target requires a contract maximum at least that large and freeze=0; otherwise page the owner."],
             "traffic_capacity_exhaustion", "scale_service", 7),
            ("pool", ["The connection queue grows even with normal host CPU; logs show pool lease timeouts for svc_pool.",
                      "Operating replicas=9; contract maximum=10; change freeze=1. Proposed target=10.",
                      "Policy: scaling to the proposed target requires a contract maximum at least that large and freeze=0; otherwise page the owner."],
             "database_connection_exhaustion", "page_owner", None),
            ("deploy", ["svc_deploy first failed after r9-BAD entered production; a holdback on r8-GOOD continues to serve comparable requests.",
                        "The release transition is the only correlated change. Rollback delegation=1; freeze=0; remaining approved reversions=2.",
                        "Policy: the operator may make the specified reversal only when delegation=1, freeze=0 and remaining changes are positive; otherwise page the owner. Reversal still needs explicit approval."],
             "deployment_regression", "rollback_deployment", None),
            ("flag", ["A loop in the feature evaluator occurs only for cohort flag_loop123; other cohorts finish normally.",
                      "Replaying with flag_loop123 disabled completes. Emergency flag delegation=1; freeze=1; remaining permitted changes=0.",
                      "Policy: the operator may make the specified reversal only when delegation=1, freeze=0 and remaining changes are positive; otherwise page the owner. Reversal still needs explicit approval."],
             "feature_flag_recursion", "page_owner", None),
        ]
        for tag, lines, cause, effect, target in cases:
            plan = q11.heuristic_decision(incident(tag, lines), POLICY, CATALOG)
            with self.subTest(tag=tag):
                self.assertEqual(plan["rootCause"], cause)
                self.assertEqual(plan["effect"]["toolName"], effect)
                if target is not None:
                    self.assertEqual(plan["effect"]["arguments"]["targetReplicas"], target)
                if effect == "rollback_deployment":
                    self.assertEqual(plan["effect"]["arguments"]["release"], "r8-GOOD")


if __name__ == "__main__":
    unittest.main(verbosity=2)
