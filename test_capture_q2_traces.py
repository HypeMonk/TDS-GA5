"""The exporter reads diagnostics only, preserves pagination, and reports gaps."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

import httpx

ROOT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("capture_test", ROOT / "capture_q2_traces.py")
capture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(capture)


class ExportTests(unittest.TestCase):
    def test_paginated_export_uses_only_authenticated_gets(self):
        seen = []

        def respond(request):
            seen.append(request)
            self.assertEqual(request.method, "GET")
            self.assertEqual(request.headers["x-debug-key"], "test-export-secret")
            if request.url.path == "/debug/q10/traces":
                if request.url.params.get("before") == "2":
                    return httpx.Response(200, json={"rows": [{"id": 1}], "nextBefore": None})
                return httpx.Response(200, json={"solverVersion": "offline-v20", "captureFailures": 0,
                                              "rows": [{"id": 3}, {"id": 2}], "nextBefore": 2})
            row_id = int(request.url.path.rsplit("/", 1)[1])
            return httpx.Response(200, json={"id": row_id, "method": "POST", "status": 200})

        with tempfile.TemporaryDirectory(prefix="q2-export-test-") as parent:
            with httpx.Client(transport=httpx.MockTransport(respond), headers={"X-Debug-Key": "test-export-secret"}) as client:
                folder, manifest = capture.export(client, "https://example.test/a2a", Path(parent), task_id="task-test")
            self.assertEqual(len(manifest["files"]), 3)
            self.assertTrue(manifest["completeListing"])
            self.assertEqual(manifest["captureFailures"], 0)
            self.assertEqual(json.loads((folder / "trace-2.json").read_text())["id"], 2)
            self.assertNotIn("test-export-secret", (folder / "manifest.json").read_text())
            self.assertNotEqual(folder, Path(parent))
        self.assertTrue(all(request.url.path.startswith("/debug/q10/traces") for request in seen))
        self.assertEqual(seen[0].url.params["taskId"], "task-test")

    def test_export_limit_marks_partial_last_page_incomplete(self):
        def respond(request):
            if request.url.path == "/debug/q10/traces":
                return httpx.Response(200, json={"rows": [{"id": 3}, {"id": 2}, {"id": 1}], "nextBefore": None})
            return httpx.Response(200, json={"id": int(request.url.path.rsplit("/", 1)[1])})
        with tempfile.TemporaryDirectory(prefix="q2-export-limit-") as parent:
            with httpx.Client(transport=httpx.MockTransport(respond)) as client:
                _, manifest = capture.export(client, "https://example.test", Path(parent), maximum=1)
            self.assertEqual(len(manifest["files"]), 1)
            self.assertFalse(manifest["completeListing"])

    def test_eviction_is_recorded_in_manifest(self):
        def respond(request):
            if request.url.path == "/debug/q10/traces":
                return httpx.Response(200, json={"rows": [{"id": 1}], "nextBefore": None})
            return httpx.Response(404)
        with tempfile.TemporaryDirectory(prefix="q2-export-eviction-") as parent:
            with httpx.Client(transport=httpx.MockTransport(respond)) as client:
                _, manifest = capture.export(client, "https://example.test", Path(parent))
            self.assertEqual(manifest["missingRows"], [1])
            self.assertEqual(manifest["files"], [])

    def test_variant_aliases_select_separate_diagnostics(self):
        for base in ("https://example.test/v18/", "https://example.test/a2a/v18/"):
            seen = []
            def respond(request):
                seen.append(request.url.path)
                self.assertTrue(request.url.path.startswith("/debug/q10/variants/v18/traces"))
                if request.url.path.endswith("/traces"):
                    return httpx.Response(200, json={"variantId": "v18", "configDigest": "fixed", "rows": [{"id": 1}], "nextBefore": None})
                return httpx.Response(200, json={"variantId": "v18", "configDigest": "fixed", "id": 1})
            with tempfile.TemporaryDirectory() as parent, httpx.Client(transport=httpx.MockTransport(respond)) as client:
                _, manifest = capture.export(client, base, Path(parent))
                self.assertEqual(manifest["variantId"], "v18")
                self.assertEqual(manifest["configDigest"], "fixed")
                self.assertEqual(len(seen), 2)
        for base in ("https://example.test/v19", "https://example.test/v2/incidents", "https://example.test/a2a/v01"):
            with self.assertRaises(ValueError):
                capture.diagnostic_base(base)

    def test_invalid_origins_are_rejected_before_any_request(self):
        def unexpected(request):
            self.fail("An invalid origin caused a request")
        with tempfile.TemporaryDirectory(prefix="q2-export-origin-") as parent:
            with httpx.Client(transport=httpx.MockTransport(unexpected)) as client:
                for base in ("http://example.test", "https://user:secret@example.test", "https://example.test?key=secret"):
                    with self.subTest(base=base), self.assertRaises(ValueError):
                        capture.export(client, base, Path(parent))


if __name__ == "__main__":
    unittest.main()
