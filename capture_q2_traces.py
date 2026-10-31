"""Export protected invoice traces using GET requests only; never invoke grading."""
import argparse
import json
import os
import re
from pathlib import Path
import sys
import tempfile
from urllib.parse import urlsplit, urlunsplit

import httpx


def diagnostic_base(base):
    parts = urlsplit(base)
    if parts.scheme != "https" or not parts.netloc or parts.username or parts.password or parts.query or parts.fragment:
        raise ValueError("Use an HTTPS Q2 base URL without credentials, query parameters, or fragments.")
    origin = urlunsplit((parts.scheme, parts.netloc, "", "", ""))
    path = parts.path.rstrip("/")
    if path in ("", "/a2a"):
        return origin, "baseline", origin + "/debug/q10"
    match = re.fullmatch(r"/(?:a2a/)?(v(?:[1-9]|1[0-8]))", path)
    if not match:
        raise ValueError("Unknown Q2 variant base URL.")
    variant = match.group(1)
    return origin, variant, origin + "/debug/q10/variants/" + variant


def export(client, base, output_parent, *, task_id=None, maximum=500):
    origin, variant, diagnostics = diagnostic_base(base)
    if not output_parent.is_dir():
        raise ValueError("The output parent directory must already exist.")
    params = {"limit": 100}
    if task_id:
        params["taskId"] = task_id
    first = client.get(diagnostics + "/traces", params=params)
    first.raise_for_status()
    page = first.json()
    if page.get("variantId", "baseline") != variant:
        raise ValueError("Trace endpoint returned a different variant.")
    config_digest = page.get("configDigest")
    folder = Path(tempfile.mkdtemp(prefix="q2-traces-", dir=output_parent))
    manifest = {"origin": origin, "requestedBase": base, "diagnosticBase": diagnostics,
                "variantId": variant, "configDigest": page.get("configDigest"), "solverVersion": page.get("solverVersion"), "files": [], "missingRows": [],
                "captureFailures": page.get("captureFailures"), "lastCaptureError": page.get("lastCaptureError"),
                "bodyLimitBytes": page.get("bodyLimitBytes"), "retainedPayloadLimitBytes": page.get("retainedPayloadLimitBytes"),
                "rowLimit": page.get("rowLimit"), "maximum": maximum, "completeListing": False}
    seen = set()
    try:
        while True:
            for row in page["rows"]:
                row_id = int(row["id"])
                if row_id in seen or len(seen) >= maximum:
                    continue
                seen.add(row_id)
                detail = client.get(diagnostics + f"/traces/{row_id}")
                if detail.status_code == 404:
                    manifest["missingRows"].append(row_id)
                    continue
                detail.raise_for_status()
                data = detail.json()
                if data.get("variantId", "baseline") != variant or data.get("configDigest") != config_digest:
                    raise ValueError("Trace detail belongs to a different variant.")
                name = f"trace-{row_id}.json"
                (folder / name).write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
                manifest["files"].append(name)
            cursor = page.get("nextBefore")
            if cursor is None:
                manifest["completeListing"] = all(int(row["id"]) in seen for row in page["rows"])
                break
            if len(seen) >= maximum:
                break
            if "before" in params and int(cursor) >= int(params["before"]):
                raise ValueError("The trace cursor did not advance.")
            params["before"] = int(cursor)
            response = client.get(diagnostics + "/traces", params=params)
            response.raise_for_status()
            page = response.json()
            if page.get("variantId", "baseline") != variant or page.get("configDigest") != config_digest:
                raise ValueError("Trace page belongs to a different variant.")
    finally:
        (folder / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return folder, manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("base", help="HTTPS deployment URL")
    parser.add_argument("output_parent", type=Path, help="Existing directory; a new capture subdirectory is created")
    parser.add_argument("--task-id")
    parser.add_argument("--maximum", type=int, default=500)
    args = parser.parse_args()
    key = os.environ.get("DEBUG_KEY")
    if not key:
        parser.error("Set DEBUG_KEY in the environment to the deployment's diagnostic secret.")
    if not 1 <= args.maximum <= 5000:
        parser.error("--maximum must be between 1 and 5000")
    try:
        with httpx.Client(headers={"X-Debug-Key": key}, timeout=45, trust_env=False, follow_redirects=False) as client:
            folder, manifest = export(client, args.base, args.output_parent, task_id=args.task_id, maximum=args.maximum)
    except (httpx.HTTPError, ValueError, OSError) as exc:
        print(f"Export failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    print(f"Saved {len(manifest['files'])} traces to {folder}")
    print(f"Capture failures reported by server: {manifest['captureFailures']}")
    if manifest["missingRows"]:
        print(f"Rows evicted during export: {len(manifest['missingRows'])}")
    if not manifest["completeListing"]:
        print("Export stopped at its limit; the manifest marks the listing incomplete.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
