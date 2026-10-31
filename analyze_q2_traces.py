"""Correlate exported Q2 decisions with grader outcomes without calling the grader."""
import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path
import sys


def load_capture(folder):
    manifest_path = folder / "manifest.json"
    if not manifest_path.is_file():
        raise ValueError("manifest.json is missing")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    traces = []
    for name in manifest.get("files", []):
        path = folder / name
        if not path.is_file():
            raise ValueError(f"Manifest entry is missing: {name}")
        traces.append(json.loads(path.read_text(encoding="utf-8")))
    return manifest, traces


def analyze(manifest, traces):
    tasks = defaultdict(lambda: {"requests": [], "decisions": {}, "outcomes": {}, "versions": set(),
                                 "proposals": {}, "conflicts": set(), "configs": set()})
    integrity = []
    for trace in traces:
        variant = trace.get("variantId", manifest.get("variantId", "baseline"))
        trace_id = trace.get("id")
        task_id = trace.get("taskId") or f"unbound-trace-{trace_id}"
        task = tasks[(variant, task_id)]
        for side in ("request", "response"):
            capture = trace.get(side) or {}
            if capture.get("truncated") or capture.get("omittedReason"):
                integrity.append({"variantId": variant, "traceId": trace_id, "side": side,
                                  "reason": capture.get("omittedReason") or "truncated"})
        if trace.get("omittedReason"):
            integrity.append({"variantId": variant, "traceId": trace_id, "side": "event", "reason": trace["omittedReason"]})
        task["requests"].append({"traceId": trace_id, "method": trace.get("method"), "path": trace.get("path"),
                                 "status": trace.get("status"), "messageId": trace.get("messageId"),
                                 "durationMs": trace.get("durationMs")})
        if trace.get("solverVersion"):
            task["versions"].add(trace["solverVersion"])
        if trace.get("configDigest"):
            task["configs"].add(trace["configDigest"])
        if trace.get("status") != 200:
            continue
        response = (trace.get("response") or {}).get("body")
        envelope = response.get("task", response) if isinstance(response, dict) else {}
        for artifact in envelope.get("artifacts", []):
            for part in artifact.get("parts", []):
                data = part.get("data") or {}
                for proposal in data.get("proposals", []) if isinstance(data, dict) else []:
                    pid = proposal.get("packageId")
                    if pid in task["proposals"] and task["proposals"][pid] != proposal:
                        task["conflicts"].add(pid)
                        integrity.append({"variantId": variant, "taskId": task_id, "packageId": pid,
                                          "reason": "conflicting_persisted_proposal"})
                    task["proposals"][pid] = proposal
        for decision in trace.get("decisions") or []:
            pid = decision.get("packageId")
            if not pid:
                integrity.append({"traceId": trace_id, "reason": "missing_package_id"})
                continue
            existing = task["decisions"].get(pid)
            if existing is not None and existing != decision:
                task["conflicts"].add(pid)
                integrity.append({"variantId": variant, "taskId": task_id, "packageId": pid,
                                  "reason": "conflicting_decision_trace"})
            task["decisions"][pid] = decision
        for outcome in trace.get("outcomes") or []:
            pid = outcome.get("packageId")
            if not pid:
                integrity.append({"traceId": trace_id, "reason": "missing_package_id"})
                continue
            existing = task["outcomes"].get(pid)
            if existing is not None and existing != outcome:
                task["conflicts"].add(pid)
                integrity.append({"variantId": variant, "taskId": task_id, "packageId": pid,
                                  "reason": "conflicting_outcome_trace"})
            task["outcomes"][pid] = outcome

    output_tasks, totals, rejected = [], Counter(), []
    for (variant, task_id), task in sorted(tasks.items()):
        packages = []
        for pid in sorted(set(task["decisions"]) | set(task["outcomes"])):
            decision, receipt = task["decisions"].get(pid), task["outcomes"].get(pid)
            proposal = task["proposals"].get(pid)
            output = (decision or {}).get("decision") or {}
            issues = []
            if receipt:
                if receipt.get("action") != output.get("action"):
                    issues.append("continuation_action_differs_from_trace")
                if proposal and receipt.get("actionId") != proposal.get("actionId"):
                    issues.append("continuation_action_id_differs_from_proposal")
                if receipt.get("outcome") not in ("ACCEPTED", "REJECTED"):
                    issues.append("unknown_receipt_outcome")
                if receipt.get("outcome") == "ACCEPTED" and not receipt.get("receiptNonce"):
                    issues.append("accepted_receipt_nonce_unavailable")
                if not proposal:
                    issues.append("persisted_proposal_unavailable")
                if decision is None:
                    issues.append("outcome_without_decision_trace")
                if proposal and any(proposal.get(field) != output.get(field)
                                    for field in ("action", "facts", "evidenceRefs", "rationale")):
                    issues.append("decision_differs_from_persisted_proposal")
                if pid in task["conflicts"] or len(task["configs"]) > 1:
                    issues.append("conflicting_observations")
            bound = bool(receipt and proposal and decision and not issues)
            status = receipt.get("outcome") if bound else "UNVERIFIED_OUTCOME" if receipt else "NO_OUTCOME"
            totals[status] += 1
            for reason in issues:
                integrity.append({"variantId": variant, "taskId": task_id, "packageId": pid, "reason": reason})
            package = {"packageId": pid, "outcome": status, "recordedOutcome": receipt.get("outcome") if receipt else None,
                       "receiptBindingVerified": bound, "decisionTraceMissing": decision is None,
                       "parser": (decision or {}).get("parser"), "action": output.get("action"),
                       "facts": output.get("facts"), "evidenceRefs": output.get("evidenceRefs"),
                       "rationale": output.get("rationale"), "warnings": (decision or {}).get("warnings") or [],
                       "factProvenance": (decision or {}).get("factProvenance") or {},
                       "relationships": (decision or {}).get("relationships") or [],
                       "parserAttempts": (decision or {}).get("parserAttempts") or [],
                       "hiddenExpectedAnswerKnown": False}
            if receipt:
                package["transportConsistency"] = {"issues": issues, "actionId": receipt.get("actionId"),
                                                   "receiptNoncePresent": bool(receipt.get("receiptNonce"))}
            packages.append(package)
            if status == "REJECTED":
                rejected.append({"variantId": variant, "taskId": task_id, **package})
        output_tasks.append({"variantId": variant, "taskId": task_id, "solverVersions": sorted(task["versions"]),
                             "configDigests": sorted(task["configs"]), "requests": sorted(task["requests"], key=lambda row: row["traceId"] or 0), "packages": packages})
    return {"solverVersions": sorted({v for task in tasks.values() for v in task["versions"]}),
            "traceFiles": len(traces), "taskCount": len(tasks), "outcomes": dict(sorted(totals.items())),
            "captureFailures": manifest.get("captureFailures"), "completeListing": manifest.get("completeListing"),
            "missingRows": manifest.get("missingRows") or [], "integrityIssues": integrity,
            "rejectedPackages": rejected, "tasks": output_tasks,
            "interpretation": "REJECTED means a successful, proposal-bound continuation rejected this exact proposal; the trace cannot reveal which hidden expected field differed. Unbound observations remain unverified."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", type=Path, help="Directory created by capture_q2_traces.py")
    parser.add_argument("--output", type=Path, help="Optional JSON output path; defaults to stdout")
    args = parser.parse_args()
    try:
        manifest, traces = load_capture(args.capture)
        result = analyze(manifest, traces)
        encoded = json.dumps(result, ensure_ascii=False, indent=2)
        if args.output:
            if not args.output.parent.is_dir():
                raise ValueError("The output parent directory does not exist")
            args.output.write_text(encoded, encoding="utf-8")
            print(f"Saved analysis to {args.output}")
        else:
            print(encoded)
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        print(f"Analysis failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
