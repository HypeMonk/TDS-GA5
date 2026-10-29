"""Launch two real HTTP app instances against a disposable local PostgreSQL database."""
import os
from pathlib import Path
import socket
import subprocess
import sys
import sysconfig
import tempfile
import time
from urllib.parse import urlsplit

import httpx

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
from test_q10_evidence import invoice_package


def port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def main():
    url = os.environ.get("SOLVER_TEST_DATABASE_URL", "")
    parsed = urlsplit(url)
    if parsed.hostname not in ("127.0.0.1", "localhost") or parsed.path != "/ga5_local_test":
        raise RuntimeError("Use the disposable local ga5_local_test database")
    processes = []
    streams = []
    with tempfile.TemporaryDirectory(prefix="ga5-http-smoke-") as folder:
        try:
            origins = []
            for number in range(2):
                chosen = port()
                origins.append("http://127.0.0.1:%d" % chosen)
                env = dict(os.environ, SOLVER_DATABASE_URL=url, VERCEL="1", DEBUG_KEY="local-smoke-debug",
                           A2A_DB=str(Path(folder) / ("q2-instance-%d.db" % number)),
                           Q11_WIRE_DB=str(Path(folder) / ("q4-instance-%d.db" % number)),
                           GA5_DB=str(Path(folder) / ("q3-instance-%d.db" % number)), PYTHONIOENCODING="utf-8")
                env["PYTHONPATH"] = sysconfig.get_path("purelib")
                stream = open(Path(folder) / ("server-%d.log" % number), "w", encoding="utf-8")
                streams.append(stream)
                # Windows venv launchers spawn a second process, which would outlive terminate().
                executable = sys._base_executable if os.name == "nt" else sys.executable
                processes.append(subprocess.Popen([executable, "-B", "-m", "uvicorn", "main:app",
                    "--app-dir", str(ROOT), "--host", "127.0.0.1", "--port", str(chosen), "--lifespan", "off"],
                    cwd=ROOT, env=env, stdout=stream, stderr=subprocess.STDOUT))
            with httpx.Client(timeout=30, trust_env=False, follow_redirects=False) as client:
                for origin, process in zip(origins, processes):
                    deadline = time.monotonic() + 20
                    while True:
                        if process.poll() is not None:
                            raise RuntimeError("App process exited before readiness")
                        try:
                            ready = client.get(origin + "/health/ready")
                            if ready.status_code == 200:
                                assert ready.json()["storage"]["shared"]
                                break
                        except httpx.TransportError:
                            pass
                        if time.monotonic() > deadline:
                            raise RuntimeError("App did not become ready")
                        time.sleep(0.1)
                a, b = origins
                headers = {"Authorization": "Bearer local-http-smoke", "A2A-Version": "1.0",
                           "Content-Type": "application/a2a+json"}
                batch = {"message": {"messageId": "smoke-initial", "role": "ROLE_USER", "parts": [{
                    "mediaType": "application/vnd.ga5.invoice-claim-batch+json", "data": {
                        "batchId": "smoke-batch", "packages": [invoice_package()]}}]}}
                card = client.get(a + "/.well-known/agent-card.json")
                assert card.status_code == 200 and card.json()["protocolVersion"] == "1.0"
                sent = client.post(a + "/message:send", headers=headers, json=batch)
                assert sent.status_code == 200, sent.text
                task = sent.json()["task"]
                polled = client.get(b + "/a2a/tasks/" + task["id"], headers=headers)
                assert polled.status_code == 200 and polled.json() == task, polled.text
                p = task["artifacts"][0]["parts"][0]["data"]["proposals"][0]
                receipt = {"message": {"messageId": "smoke-receipt", "role": "ROLE_USER", "taskId": task["id"],
                    "contextId": task["contextId"], "parts": [{"mediaType": "application/vnd.ga5.invoice-action-results+json",
                    "data": {"batchId": task["metadata"]["batchId"], "results": [{
                        "packageId": p["packageId"], "actionId": p["actionId"], "action": p["action"],
                        "outcome": "ACCEPTED", "receiptNonce": "local-smoke-nonce"}]}}]}}
                finished = client.post(b + "/message:send", headers=headers, json=receipt)
                assert finished.status_code == 200, finished.text
                assert client.get(a + "/tasks/" + task["id"], headers=headers).json() == finished.json()["task"]
                assert client.post(a + "/tasks/" + task["id"] + ":cancel", headers=headers).status_code == 409
                print("Q2 real HTTP create/read/receipt across separate instances: PASS")

                incident = {"profile": "ga5-incident-agent/v2", "runId": "run-http-smoke", "agentName": "incident-response",
                    "publicMarker": "public-smoke", "sensitive": {"accessToken": "private-smoke-credential"},
                    "incident": {"incidentId": "inc-http-smoke", "service": "svc_smoke", "severity": "SEV-1",
                        "allowedRootCauses": ["traffic_capacity_exhaustion"], "transcript":
                        "[ev_one] correlated sample: queue depth and latency rise with traffic; every replica is saturated.\n"
                        "[ev_two] correlated sample: request saturation reproduces the latency curve across three probes.\n"
                        "[ev_three] correlated sample: current capacity is exactly 8 application replicas and each replica is saturated."},
                    "toolCatalog": [{"name": "query_metrics", "inputSchema": {"required": ["service", "metric", "windowMinutes"]}},
                                    {"name": "scale_service", "inputSchema": {"required": ["service", "targetReplicas"]}}],
                    "policy": {"maximumDiagnostics": 3, "effectTools": ["scale_service"], "approvalRequiredFor": [], "doNotExport": []}}
                created = client.post(a + "/v2/incidents", json=incident)
                assert created.status_code == 200, created.text
                current = created.json()
                for step in range(5):
                    origin = origins[step % 2]
                    read = client.get(origin + "/v2/incidents/" + incident["runId"])
                    assert read.status_code == 200 and read.json() == current, read.text
                    if current["status"] in ("completed", "failed"):
                        break
                    outcomes = []
                    for dispatch in current["dispatches"]:
                        outcome = {key: dispatch[key] for key in ("actionId", "callId", "attempt")}
                        outcome.update(status=200, resultClass="diagnosis_confirmed" if dispatch["phase"] == "diagnostic" else "effect_applied", nonce="local-effect-nonce")
                        outcomes.append(outcome)
                    response = client.post(origin + "/v2/incidents/" + incident["runId"] + "/receipts",
                        json={"receiptId": "smoke-receipt-%d" % step, "outcomes": outcomes})
                    assert response.status_code == 200, response.text
                    current = response.json()
                assert current["status"] == "completed"
                logs = client.get(b + "/debug/logs/q11", headers={"X-Debug-Key": "local-smoke-debug"})
                assert logs.status_code == 200 and logs.json(), logs.text
                assert "private-smoke-credential" not in logs.text
                assert client.get(b + "/debug/logs/q11").status_code == 403
                print("Q4 real HTTP lifecycle and protected shared diagnostics: PASS")
        finally:
            for process in processes:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
            for stream in streams:
                stream.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
