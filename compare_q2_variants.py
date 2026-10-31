"""Replay a protected Q2 capture through all fixed variants without network calls."""
import argparse
import importlib.util
import json
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parent


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


analyzer = load(ROOT / "analyze_q2_traces.py", "q2_variant_capture_analysis")
variants = load(ROOT / "q10_variants.py", "q2_variant_comparison_registry")


def compare(manifest, traces):
    analysis = analyzer.analyze(manifest, traces)
    observations = {(task["variantId"], task["taskId"], package["packageId"]): package
                    for task in analysis["tasks"] for package in task["packages"]}
    inputs, gaps = {}, list(analysis["integrityIssues"])
    for trace in traces:
        if trace.get("status") != 200:
            continue
        variant = trace.get("variantId", manifest.get("variantId", "baseline"))
        body = (trace.get("request") or {}).get("body")
        message = body.get("message") if isinstance(body, dict) else None
        for part in (message or {}).get("parts", []):
            data = part.get("data") or {}
            for package in data.get("packages", []) if isinstance(data, dict) else []:
                key = (variant, trace.get("taskId"), package.get("packageId"))
                inputs[key] = package
    rows = []
    with tempfile.TemporaryDirectory(prefix="q2-counterfactual-") as folder:
        engines = {config.id: variants.load_instance(config, db_path=Path(folder) / (config.id + ".db"),
                   trace_path=Path(folder) / (config.id + ".traces")) for config in (variants.BASELINE, *variants.REGISTRY)}
        for (original_variant, task_id, pid), package in sorted(inputs.items(), key=lambda row: tuple(str(v) for v in row[0])):
            baseline = engines["baseline"].decide(package)
            observation = observations.get((original_variant, task_id, pid))
            original_config = variants.CONFIGS.get(original_variant)
            captured_digest = manifest.get("configDigest")
            variants_out = []
            for config in variants.REGISTRY:
                engine = engines[config.id]
                output = engine.decide(package)
                differences = [field for field in ("action", "facts", "evidenceRefs", "rationale", "unresolvedFacts")
                               if output.get(field) != baseline.get(field)]
                exact_output = bool(observation and all(output.get(k) == observation.get(k)
                                    for k in ("action", "facts", "evidenceRefs", "rationale")))
                field_differences = {field: {"baseline": baseline.get(field), "variant": output.get(field)}
                                     for field in differences if field != "facts"}
                if "facts" in differences:
                    field_differences.update({"facts." + field: {"baseline": baseline["facts"].get(field),
                                             "variant": output["facts"].get(field)}
                                             for field in set(baseline["facts"]) | set(output["facts"])
                                             if baseline["facts"].get(field) != output["facts"].get(field)})
                config_matches = captured_digest == config.digest
                graded = bool(config.id == original_variant and config_matches and exact_output
                              and observation and observation.get("receiptBindingVerified"))
                variants_out.append({**config.public(), "decision": output, "changedFieldsFromTrialD": differences,
                                     "fieldDifferencesFromTrialD": field_differences,
                                     "sameBusinessOutputAsRecorded": exact_output,
                                     "graderOutcome": observation["outcome"] if graded else "NOT_GRADED",
                                     "receiptBindingVerified": graded})
            rows.append({"packageId": pid, "taskId": task_id, "recordedVariantId": original_variant,
                         "inputSha256": engines["baseline"].sha(engines["baseline"].canonical(package)),
                         "package": package, "recordedObservation": observation,
                         "recordedConfigKnown": bool(original_config and captured_digest == original_config.digest),
                         "baselineDecision": baseline, "variants": variants_out})
    return {"packages": rows, "packageCount": len(rows), "variantCount": len(variants.REGISTRY),
            "integrityIssues": gaps, "completeListing": manifest.get("completeListing"),
            "missingRows": manifest.get("missingRows", []), "graderInvoked": False,
            "interpretation": "Counterfactual outputs are NOT_GRADED. Only the original variant, matching configuration, exact business output and verified receipt binding can carry its recorded verdict."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        manifest, traces = analyzer.load_capture(args.capture)
        result = compare(manifest, traces)
        encoded = json.dumps(result, ensure_ascii=False, indent=2)
        if args.output:
            if args.output.exists():
                raise ValueError("Output already exists; choose a new file to preserve prior evidence.")
            args.output.write_text(encoded, encoding="utf-8")
            print(f"Compared {result['packageCount']} packages across 18 variants; saved {args.output}")
        else:
            print(encoded)
    except (OSError, ValueError) as exc:
        print(f"Comparison failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
