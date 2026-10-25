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
    tasks = defaultdict(lambda: {"requests": [], "decisions": {}, "outcomes": {}, "versions": set()})
    integrity = []
    for trace in traces:
        trace_id = trace.get("id")
        for side in ("request", "response"):
            capture = trace.get(side) or {}
            if capture.get("truncated") or capture.get("omittedReason"):
                integrity.append({"traceId": trace_id, "side": side,
                                  "reason": capture.get("omittedReason") or "truncated"})
        if trace.get("omittedReason"):
            integrity.append({"traceId": trace_id, "side": "event", "reason": trace["omittedReason"]})
        task_id = trace.get("taskId") or f"unbound-trace-{trace_id}"
        task = tasks[task_id]
        task["requests"].append({"traceId": trace_id, "method": trace.get("method"), "path": trace.get("path"),
                                 "status": trace.get("status"), "messageId": trace.get("messageId"),
                                 "durationMs": trace.get("durationMs")})
        if trace.get("solverVersion"):
            task["versions"].add(trace["solverVersion"])
        for decision in trace.get("decisions") or []:
            package_id = decision.get("packageId")
            if not package_id:
                integrity.append({"traceId": trace_id, "side": "decision", "reason": "missing_package_id"})
                continue
            existing = task["decisions"].get(package_id)
            if existing is not None and existing != decision:
                integrity.append({"traceId": trace_id, "side": "decision", "packageId": package_id,
                                  "reason": "conflicting_decision_trace"})
            task["decisions"][package_id] = decision
        for outcome in trace.get("outcomes") or []:
            package_id = outcome.get("packageId")
            if not package_id:
                integrity.append({"traceId": trace_id, "side": "outcome", "reason": "missing_package_id"})
                continue
            existing = task["outcomes"].get(package_id)
            if existing is not None and existing != outcome:
                integrity.append({"traceId": trace_id, "side": "outcome", "packageId": package_id,
                                  "reason": "conflicting_outcome_trace"})
            task["outcomes"][package_id] = outcome

    output_tasks, totals = [], Counter()
    rejected = []
    for task_id, task in sorted(tasks.items()):
        packages = []
        package_ids = sorted(set(task["decisions"]) | set(task["outcomes"]))
        for package_id in package_ids:
            decision = task["decisions"].get(package_id)
            outcome = task["outcomes"].get(package_id)
            status = outcome.get("outcome") if outcome else "NO_OUTCOME"
            totals[status] += 1
            if decision is None:
                integrity.append({"taskId": task_id, "packageId": package_id, "reason": "outcome_without_decision_trace"})
                package = {"packageId": package_id, "outcome": status, "decisionTraceMissing": True}
            else:
                proposal = decision.get("decision") or {}
                package = {"packageId": package_id, "outcome": status, "parser": decision.get("parser"),
                           "action": proposal.get("action"), "facts": proposal.get("facts"),
                           "evidenceRefs": proposal.get("evidenceRefs"), "rationale": proposal.get("rationale"),
                           "warnings": decision.get("warnings") or [],
                           "factProvenance": decision.get("factProvenance") or {},
                           "relationships": decision.get("relationships") or [],
                           "parserAttempts": decision.get("parserAttempts") or [],
                           "hiddenExpectedAnswerKnown": False}
                if outcome:
                    mismatches = []
                    if outcome.get("action") != proposal.get("action"):
                        mismatches.append("continuation_action_differs_from_trace")
                    package["transportConsistency"] = {"issues": mismatches,
                                                       "actionId": outcome.get("actionId"),
                                                       "receiptNoncePresent": bool(outcome.get("receiptNonce"))}
            packages.append(package)
            if status == "REJECTED":
                rejected.append({"taskId": task_id, **package})
        output_tasks.append({"taskId": task_id, "solverVersions": sorted(task["versions"]),
                             "requests": sorted(task["requests"], key=lambda item: item["traceId"] or 0),
                             "packages": packages})
    return {"solverVersions": sorted({version for task in tasks.values() for version in task["versions"]}),
            "traceFiles": len(traces), "taskCount": len(tasks), "outcomes": dict(sorted(totals.items())),
            "captureFailures": manifest.get("captureFailures"), "completeListing": manifest.get("completeListing"),
            "missingRows": manifest.get("missingRows") or [], "integrityIssues": integrity,
            "rejectedPackages": rejected, "tasks": output_tasks,
            "interpretation": ("REJECTED means the hidden grader rejected the exact proposal; the trace cannot reveal "
                               "which hidden expected field differed unless the grader supplied that detail.")}


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
