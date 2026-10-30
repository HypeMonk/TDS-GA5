# TDS GA3/GA5 Offline Universal Solver

A single FastAPI deployment for the assignment endpoints. The Q2–Q4 agent paths are deterministic and provider-free: no OpenAI, AI Pipe, OpenRouter, or Google model client is imported or called.

## Offline decision model

- **Invoice/A2A:** extracts commercial names, invoice numbers, amounts, payment/order relationships, authority limits, bank verification, and exactly three controlling references. A purchase-order identifier is not an invoice number, and a bank-account identifier is not a vendor name. When the required name or invoice number is absent, Trial B returns the explicit marker `not provided` and records the unresolved field rather than inventing or substituting a different identity.
- **Mailroom:** selects actions from source kind, provenance, current authenticated state, signed scope, exact request identity, and least privilege. Standing approvals and request-controlled notices are handled separately. Contradictory or unsupported evidence returns HTTP 422 without a model call.
- **Incident response:** classifies unique positive causal relations, validates catalog-bound arguments, evaluates bounded numeric/Boolean operating rules, enforces approval gates, and persists receipt-driven state and OTLP topology.

The solver is designed to generalize through entities and relationships rather than fixed generated IDs. Arbitrary natural-language input can still be ambiguous; those cases fail closed instead of being guessed.

## Q2 source-identity candidate

The deployed `offline-v31` order/payee substitutions did not resolve the residual business deductions. A new retained capture contains nine rejected audit cases: five do not supply a distinct invoice number, and four do not supply a human-readable vendor name. No extra identity catalogue or mapping is present in those requests. The current public question does not document what value to return when either required identity is absent.

The `offline-v32` baseline removes the unsupported substitutions, prefers an explicit current-invoice payee name over a historical payment’s supplier name, and keeps the detailed source-bound rationale. This vendor-precedence correction is covered by distributed and paraphrased regression cases. It does not change actions, amounts, currencies, evidence selection, task lifecycle, SQLite storage, or Q3/Q4. `unknown` is an honest unresolved marker, not a proven full-score sentinel. This patch is for source correctness and is not claimed to restore 4/4.

The grading blocker needs clarification: should a missing identity be included in the audit input, or should an unresolved marker be accepted? Returning an order number or account number under a different field label is not evidence of the missing commercial fact. Keep new grader checks separate from local validation; do not infer a new score from a replay.

## Q2 controlled trials

Trial A (`offline-v33-a`) tested concise, bracket-cited rationale while preserving v32 facts. The retained feedback was still business 3.33/3.50; its captured missing-vendor hold and missing-invoice settlement proposals both remained rejected. This is not evidence that every possible rationale format was tested.

Trial B (`offline-v34-b`) restores the `offline-v32` source-quotation rationale and changes only genuinely unresolved `facts.invoiceNumber` or `facts.vendorName` from `unknown` to `not provided`. Existing names and invoice numbers, actions, amounts, currencies, evidence arrays, and unresolved-field lists remain unchanged. Conversion happens after rationale construction, so the rationale is byte-for-byte identical to v32, including its description of unknown identities. Diagnostic traces record the marker actually returned and still classify those fields as unresolved. This release does not combine Trial A's rationale changes with Trial B's marker change.

Use the isolated Q2 service from `fix/q2-source-identities`, not production `main`. A branch push can auto-deploy that test service if Render auto-deploy is enabled. Keep its root URL unchanged between trials, export the audit outcomes before another deployment, and evaluate acceptance of the previously failing audit shape rather than just the rounded score. Local tests and replay do not establish a new grader score; `not provided` is an experimental representation, not a known accepted sentinel.

## Q4 Render audit wording fix

`offline-v31` also extends two narrowly scoped causal relations: database connection acquisition/checkout timing out, and request queues with saturated workers as arrival rate rises. These cover the two protected audit inputs that returned `Incident failure is unsupported or ambiguous`. Negated timeout descriptions remain excluded, and a diagnosis still requires exactly one supported cause; the patch does not guess a cause or suppress valid errors.

Regression tests cover the original exported failures, close paraphrases, conflicting/negated evidence, service scope, and complete local receipt/trace/replay workflows. Scaling still follows the supplied freeze and capacity rules: the captured `freeze=1` cases choose `page_owner`, not `scale_service`. Q3 is untouched and no database or provider dependency is added.

## Render

The Dockerfile starts Uvicorn on Render's `$PORT`. Required environment variable:

- `STUDENT_EMAIL`: the registered assignment email.

Optional:

- `DEBUG_KEY`: a random secret enabling detailed Q10/Q11 wire access and Q2 request/decision tracing. Without it, the new trace recorder is disabled and its endpoints return 403.
- `Q10_TRACE_DB`: separate SQLite diagnostic database; defaults to the Q2 task database path with `.traces` appended.
- `GA5_DB`, `A2A_DB`, `Q11_WIRE_DB`: SQLite paths. Render's free filesystem is ephemeral, so redeployment clears state; exact replay is durable only within the running deployment.

No provider API key is required for Q2–Q4.

## Q2 submission URL

For a new deployment, prefer its root HTTPS URL with a trailing slash, for example `https://your-service.onrender.com/`. The same transport handlers are also served under `/a2a/`; that suffix is optional, not a requirement. The Agent Card advertises both interfaces.

Keep one base URL for a controlled test. A lower score on a separate Check does not establish that the prefix caused it: every Check/Save can use a new audit. If protocol marks remain full and feedback only reports business semantics, investigate the proposal rather than switching paths.

## Health and diagnostics

- `/health` — readiness and version (`offline-v34-b`)
- `/debug/q9` — redacted durable Q3 proposal records
- `/debug/q9/commitwire` — redacted Q3 receipt/outcome records
- `/debug/q10` — redacted recent Q2 HTTP records
- `/debug/q11` — redacted recent Q4 HTTP records
- `/debug/logs/q9` — equivalent Q3 request-log view
- `/debug/logs/q10?limit=25&before=TIMESTAMP` — bounded, cursorable Q2 request logs
- `/debug/logs/q11?limit=25&before=TIMESTAMP` — bounded, cursorable Q4 request logs requiring `X-Debug-Key: DEBUG_KEY`; query-string credentials are rejected
- `/debug/q10/wire?key=DEBUG_KEY`, `/debug/q11/wire?key=DEBUG_KEY` — protected durable indexes

Authorization/cookie headers, diagnostic keys, secret-shaped values, `sensitive` objects, and confidential/private source text are redacted from public diagnostics. Public aggregate logs also replace incident transcripts, prompts, tool arguments, and tool results; only the key-gated Q4 view retains those synthetic fields for debugging.

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
python -I -B test_q2_render_business.py
python -I -B test_q2_rationale_trial.py
python -I -B test_q4_render_audits.py
python -I -B test_q10_traces.py
python -I -B test_capture_q2_traces.py
python -I -B test_analyze_q2_traces.py
python -I -B test_live_offline_regressions.py
```

Additional replay suites live in the adjacent `ga5-src` workspace. They verify signed receipts, stable accepted outputs, receipt conflict handling, invoice audit cases, incident retries/approvals/timeouts, trace topology, and persisted replay.
