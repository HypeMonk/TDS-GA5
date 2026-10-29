"""Replay recorded Q2 proposals without invoking the grader or inferring hidden answers."""
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import q10


def decoded(value):
    if isinstance(value, dict):
        return value
    try:
        return json.loads(value or "{}")
    except (ValueError, TypeError):
        return {}


def records():
    paths = list(ROOT.parent.glob("ga3-offline-live-*/q10-http.json"))
    paths += list(ROOT.parent.glob("postcheck-q2-*/q2.json"))
    seen = set()
    for path in paths:
        sends, outcomes = {}, {}
        for row in json.loads(path.read_text(encoding="utf-8-sig")):
            body, response = decoded(row.get("body")), decoded(row.get("response_body"))
            message, task = body.get("message") or {}, response.get("task") or {}
            packages, results = [], []
            for part in message.get("parts") or []:
                data = part.get("data") or {}
                if isinstance(data, dict):
                    packages.extend(data.get("packages") or [])
                    results.extend(data.get("results") or [])
            if packages and task.get("id"):
                proposals = {p["packageId"]: p for artifact in task.get("artifacts", [])
                             for part in artifact.get("parts", [])
                             for p in (part.get("data") or {}).get("proposals", [])}
                sends[task["id"]] = packages, proposals
            for result in results:
                outcomes[(message.get("taskId"), result["packageId"])] = result.get("outcome")
        for identity, (packages, proposals) in sends.items():
            for package in packages:
                pid = package["packageId"]
                if pid not in proposals:
                    continue
                outcome = outcomes.get((identity, pid))
                semantic = {field: proposals[pid].get(field)
                            for field in ("action", "facts", "evidenceRefs", "rationale")}
                key = (q10.canonical(sorted(package["documents"], key=q10.canonical)),
                       q10.canonical(semantic), outcome)
                if key not in seen:
                    seen.add(key)
                    yield package, proposals[pid], outcome


class CapturedInvoiceTests(unittest.TestCase):
    def test_recorded_accepted_actions_facts_and_citations_are_preserved(self):
        accepted = 0
        rejected = 0
        total = 0
        for package, original, outcome in records():
            total += 1
            new = q10.decide(package)
            self.assertTrue(60 <= len(new["rationale"]) <= 1500)
            self.assertEqual(len(set(new["evidenceRefs"])), 3)
            sources = "\n".join(d.get("text", "") for d in package["documents"])
            self.assertTrue(all("[" + ref + "]" in sources for ref in new["evidenceRefs"]))
            if outcome == "ACCEPTED":
                accepted += 1
                with self.subTest(package=package["packageId"]):
                    for field in ("action", "facts", "evidenceRefs"):
                        self.assertEqual(new[field], original[field])
            elif outcome == "REJECTED":
                rejected += 1
        if not total:
            self.skipTest("No local captured grader traffic available")
        self.assertGreater(accepted, 0)
        print("Recorded Q2 replay: %d accepted proposals preserved; %d prior rejections inspected" % (accepted, rejected))


if __name__ == "__main__":
    unittest.main()
