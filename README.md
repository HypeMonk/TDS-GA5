# TDS GA3/GA5 Offline Universal Solver

A single FastAPI deployment for the assignment endpoints. The Q2–Q4 agent paths are deterministic and provider-free: no OpenAI, AI Pipe, OpenRouter, or Google model client is imported or called.

## Offline decision model

- **Invoice/A2A:** extracts current commercial identities, amounts, order/payment relationships, authority ceilings, bank verification, and exactly three controlling references. It supports both the ordinary cover/ledger layout and distributed/paraphrased records independent of file order. When a distributed record omits a distinct invoice number or human-readable vendor, that field remains `unknown` rather than being invented. The evidence-backed action still follows the signed order/invoice, current ledger, verification state, and authority boundary.
- **Mailroom:** selects actions from source kind, provenance, current authenticated state, signed scope, exact request identity, and least privilege. Standing approvals and request-controlled notices are handled separately. Contradictory or unsupported evidence returns HTTP 422 without a model call.
- **Incident response:** classifies unique positive causal relations, validates catalog-bound arguments, evaluates bounded numeric/Boolean operating rules, enforces approval gates, and persists receipt-driven state and OTLP topology.

The solver is designed to generalize through entities and relationships rather than fixed generated IDs. Arbitrary natural-language input can still be ambiguous; those cases fail closed instead of being guessed.

## Render

The Dockerfile starts Uvicorn on Render's `$PORT`. Required environment variable:

- `STUDENT_EMAIL`: the registered assignment email.

Optional:

- `DEBUG_KEY`: a random secret enabling detailed Q10/Q11 wire access and Q2 request/decision tracing. Without it, the new trace recorder is disabled and its endpoints return 403.
- `Q10_TRACE_DB`: separate SQLite diagnostic database; defaults to the Q2 task database path with `.traces` appended.
- `GA5_DB`, `A2A_DB`, `Q11_WIRE_DB`: SQLite paths. Render's free filesystem is ephemeral, so redeployment clears state; exact replay is durable only within the running deployment.

No provider API key is required for Q2–Q4.

## Health and diagnostics

- `/health` — readiness and version (`offline-v21`)
- `/debug/q9` — redacted durable Q3 proposal records
- `/debug/q9/commitwire` — redacted Q3 receipt/outcome records
- `/debug/q10` — redacted recent Q2 HTTP records
- `/debug/q11` — redacted recent Q4 HTTP records
- `/debug/logs/q9`, `/debug/logs/q10` — equivalent request-log views
- `/debug/logs/q11?limit=25&before=TIMESTAMP` — bounded, cursorable Q4 request logs; omit `before` for the newest records
- `/debug/q10/wire?key=DEBUG_KEY`, `/debug/q11/wire?key=DEBUG_KEY` — protected durable indexes

Authorization/cookie headers, diagnostic keys, secret-shaped values, `sensitive` objects, and confidential/private source text are redacted from public diagnostics.

## Protected Q2 traces

Set `DEBUG_KEY` on the deployment before the next evaluation. These endpoints require an `X-Debug-Key` header containing that secret; they do not accept it in a query string:

- `GET /debug/q10/traces?limit=25` lists recent captures. Use `before=ID` for older rows and `taskId=...` to correlate a task's requests, replays, and result continuation.
- `GET /debug/q10/traces/ID` returns the detailed capture.

Captures include solver version, HTTP status and duration, request/response JSON, original byte counts and SHA-256 hashes, stored byte counts, explicit omission flags, hashed principal, and message/task/batch identifiers. Authorization and cookie values are never included. Invalid JSON is represented by its size and hash, not raw text. Each request or response body is limited to 2 MiB; larger bodies are omitted and marked, rather than silently clipped.

New decisions include parser-attempt results, facts and source-presence locations, controlling evidence text, order/payment relationships, bank verification, authority calculations, and unresolved-field warnings. Source presence is diagnostic evidence, not proof that a hidden grader accepts a fact. Replay requests refer to the original task and do not recompute its decisions. Continuations retain the actual grader outcomes without treating a rejected proposal as an execution.

The trace database is separate from task state. Retention is bounded by 500 rows and 32 MiB of serialized payloads. An individual event exceeding that budget is reduced to metadata and marked `event_size_limit`. Capture failures do not change protocol responses; the index reports `captureFailures` and `lastCaptureError`. Diagnostic reads do not create more traces. Export before redeploying: an ephemeral filesystem does not retain them across deployments.

To export after a Check, set `DEBUG_KEY` in the local terminal environment to the same secret, then run from this repository:

```powershell
python -I -B capture_q2_traces.py https://your-deployment.example ..
```

The exporter uses only GET requests to the protected diagnostic endpoints. It never calls Check, Save, or a grading endpoint. It creates a new `q2-traces-*` directory containing per-request JSON files and a manifest; gaps from retention and partial exports are reported. Use `--task-id TASK_ID` to export one task or `--maximum 100` to bound the export.

Correlate proposals with returned outcomes locally:

```powershell
python -I -B analyze_q2_traces.py ..\q2-traces-XXXX --output ..\q2-analysis.json
```

The analysis preserves each rejected proposal's parser, facts, evidence, rationale, provenance, and relationships. It checks transport consistency and capture completeness, but marks the hidden expected answer as unknown unless the grader actually supplied it.

## Verification

```powershell
python -I -B test_q10_evidence.py
python -I -B test_q10_traces.py
python -I -B test_capture_q2_traces.py
python -I -B test_analyze_q2_traces.py
python -I -B test_live_offline_regressions.py
```

Additional replay suites live in the adjacent `ga5-src` workspace. They verify signed receipts, stable accepted outputs, receipt conflict handling, invoice audit cases, incident retries/approvals/timeouts, trace topology, and persisted replay.
