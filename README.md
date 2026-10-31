# TDS GA3/GA5 Offline Universal Solver

A single FastAPI deployment for the assignment endpoints. The Q2–Q4 agent paths are deterministic and provider-free: no OpenAI, AI Pipe, OpenRouter, or Google model client is imported or called.

## Offline decision model

- **Invoice/A2A:** extracts commercial names, invoice numbers, amounts, payment/order relationships, authority limits, bank verification, and exactly three controlling references. A purchase-order identifier is not an invoice number, and a bank-account identifier is not a vendor name. The root and `/a2a/` retain Trial D behavior. The experimental Q2 URLs select fixed identity-marker, rationale, and vendor-binding policies; none changes currency arithmetic, controlling actions, or evidence selection.
- **Mailroom:** selects actions from source kind, provenance, current authenticated state, signed scope, exact request identity, and least privilege. Standing approvals and request-controlled notices are handled separately. Contradictory or unsupported evidence returns HTTP 422 without a model call.
- **Incident response:** classifies unique positive causal relations, validates catalog-bound arguments, evaluates bounded numeric/Boolean operating rules, enforces approval gates, and persists receipt-driven state and OTLP topology.

The solver is designed to generalize through entities and relationships rather than fixed generated IDs. Arbitrary natural-language input can still be ambiguous; those cases fail closed instead of being guessed.

## Q2 source-identity candidate

The deployed `offline-v31` order/payee substitutions did not resolve the residual business deductions. A new retained capture contains nine rejected audit cases: five do not supply a distinct invoice number, and four do not supply a human-readable vendor name. No extra identity catalogue or mapping is present in those requests. The current public question does not document what value to return when either required identity is absent.

The `offline-v32` baseline removes the unsupported substitutions, prefers an explicit current-invoice payee name over a historical payment’s supplier name, and keeps the detailed source-bound rationale. This vendor-precedence correction is covered by distributed and paraphrased regression cases. It does not change actions, amounts, currencies, evidence selection, task lifecycle, SQLite storage, or Q3/Q4. `unknown` is an honest unresolved marker, not a proven full-score sentinel. This patch is for source correctness and is not claimed to restore 4/4.

The grading blocker needs clarification: should a missing identity be included in the audit input, or should an unresolved marker be accepted? Returning an order number or account number under a different field label is not evidence of the missing commercial fact. Keep new grader checks separate from local validation; do not infer a new score from a replay.

## Q2 controlled trials

Trial A (`offline-v33-a`) tested concise, bracket-cited rationale while preserving v32 facts. The retained feedback was still business 3.33/3.50; its captured missing-vendor hold and missing-invoice settlement proposals both remained rejected. This is not evidence that every possible rationale format was tested.

Trial B (`offline-v34-b`) tested `not provided` instead of `unknown`, retaining the exact v32 rationale. Its feedback remained partial (business 3.29/3.50); the captured missing-invoice approval and settlement cases and missing-vendor hold case were rejected. The different audit mix does not establish that the marker itself lowered the score.

Trial C (`offline-v35-c`) returns to v32's `unknown` facts and detailed source quotations, removing only the appended `Missing source fields: ...; unknown is not an inferred identity.` sentence from incomplete-case rationales. Actions, facts, currencies, amounts, evidence arrays, and unresolved-field lists are identical to v32. The original excerpt budget is retained, so removing the footer does not change the quoted evidence or its truncation. Source text that happens to contain the same phrase is not removed. Complete-identity proposals and diagnostic missing-field warnings are unchanged.

Trial D (`offline-v36-d`) preserves Trial C actions, evidence, rationale, amounts, currencies, and all populated identities. Only fields already recorded in `unresolvedFacts` change from the prose marker `unknown` to the empty string. The keys remain present and string-typed; they are not omitted or converted to null. Diagnostic traces retain unresolved provenance. This representation is experimental and not a verified grader convention.

Trial D's reported result remained 3.95/4, with business 3.33/3.50 and every non-business category full. Its saved capture has 61 unique accepted proposals and one rejected order-only settlement with an empty invoice number. It supplies no accepted incomplete-identity counterpart.

Trial E (`offline-v37-e`) is a local, ungraded candidate based on Trial D. In both structured and paraphrased record paths, a historical recipient from a different order no longer fills `vendorName` when the current invoice does not name a vendor. Same-order ledger identities and explicit current-invoice vendors remain unchanged. Actions, invoice numbers, amounts, currencies, evidence arrays, and rationale text are frozen; the vendor field and its unresolved provenance are the intended changes. Rationale generation retains the Trial D identity inputs for its original excerpt budget before the vendor-binding check is applied.

Local validation against frozen commit `89c097919b27b94ffb45dc03619c324cf1197ece` covered 2,111 inputs: 139 vendor-binding changes, with all 2,111 rationales unchanged. All 1,780 unique receipt-bound accepted variants retain Trial D's full output and their recorded action/fact/evidence values. Twenty-three old accepted rationale differences already existed in Trial D; this candidate does not introduce them. All 147 exercised tests and the real localhost HTTP proposal/trace/receipt/replay/isolation workflow passed. These checks establish isolation, not grader acceptance or 4/4. No Trial E deployment or scored attempt has been performed.

Use the isolated Q2 service from `fix/q2-source-identities`, not production `main`. A branch push can auto-deploy that test service if Render auto-deploy is enabled. Keep its root URL unchanged between trials, export the audit outcomes before another deployment, and evaluate acceptance of the previously failing audit shape rather than just the rounded score. Local tests and replay do not establish a new grader score.

## Parallel Q2 hypothesis suite

The local implementation exposes **18 fixed variants** on one service. The existing origin and `/a2a/` continue to use `offline-v36-d`. Variant aliases share state with their canonical URL, but never with another variant. Q3/Q4 routes are unchanged. This suite has not been deployed or graded yet.

Use `https://tds-ga3-q2-dz54.onrender.com/a2a/vN/` after the separately authorized branch deployment. `/vN/` is an equivalent alias. Do not submit the registry or diagnostic URL to the grader.

| ID | Missing identity string | Rationale | Vendor identity rule | Historical reference |
|---|---|---|---|---|
| v1 | `unknown` | Excerpts + footer | Legacy ledger fallback | v32 |
| v2 | `unknown` | Concise, bracket-cited incomplete cases | Legacy | Trial A |
| v3 | `not provided` | Excerpts + footer | Legacy | Trial B |
| v4 | `unknown` | Excerpts, no footer | Legacy | Trial C |
| v5 | Empty string | Excerpts, no footer | Legacy | Trial D |
| v6 | Empty string | Excerpts, no footer | Current-order binding | Local Trial E |
| v7 | `unknown` | Excerpts + footer | Current-order | New combination |
| v8 | `unknown` | Excerpts, no footer | Current-order | New combination |
| v9 | `unknown` | Concise incomplete cases | Current-order | New combination |
| v10 | `not provided` | Excerpts + footer | Current-order | New combination |
| v11 | `not provided` | Excerpts, no footer | Legacy | New combination |
| v12 | `not provided` | Excerpts, no footer | Current-order | New combination |
| v13 | `not provided` | Concise incomplete cases | Legacy | New combination |
| v14 | `not provided` | Concise incomplete cases | Current-order | New combination |
| v15 | Empty string | Excerpts + footer | Legacy | New combination |
| v16 | Empty string | Excerpts + footer | Current-order | New combination |
| v17 | Empty string | Concise incomplete cases | Legacy | New combination |
| v18 | Empty string | Concise incomplete cases | Current-order | New combination |

IDs and policy tuples are permanent. `GET /debug/q10/variants` returns their URLs, settings, reference labels, and immutable configuration digests. Experimental task/action IDs are namespaced by variant. The same principal, batch, and message submitted to two variants therefore cannot reuse another variant's task or receipt.

**Rendering order:** construct legacy parsed facts, render the selected historical rationale, optionally apply current-order vendor binding, recompute unresolved identities, then apply the missing-value string. Thus Trial E and new current-order combinations preserve the corresponding legacy rationale even when vendor binding newly marks a name unresolved. Concise selection and footer budgeting use pre-binding facts; a historical source quotation can still name the previous recipient. `no footer` retains the original v32 excerpt budget. Trial A uses its exact historical source checks and original-excerpt overflow fallback. Heuristic fallbacks are unchanged, not relabeled with experimental missing markers.

### Separate logs and exports

For v6 (replace the ID for another variant):

- `GET /debug/q10/variants/v6/logs?limit=25&before=TIMESTAMP` — independent metadata-only HTTP log ring.
- `GET /debug/q10/variants/v6/traces?limit=25&before=ID` — protected, durable full trace index.
- `GET /debug/q10/variants/v6/traces/ID` — exact redacted request, proposal, decision, and receipt observations.

All three require `X-Debug-Key`. Variant diagnostic reads do not log themselves. Full bodies are stored only in protected traces, not duplicated into public logs. The legacy unbounded wire recorder is disabled for experiments; root wire behavior is unchanged.

```powershell
python -I -B capture_q2_traces.py https://tds-ga3-q2-dz54.onrender.com/a2a/v6/ ..
python -I -B analyze_q2_traces.py ..\q2-traces-XXXX --output ..6-outcomes.json
python -I -B compare_q2_variants.py ..\q2-traces-XXXX --output ..\same-input-comparison.json
```

Set `DEBUG_KEY` in the terminal environment before export. The exporter uses only authenticated GET requests; either variant URL alias selects that variant's diagnostics. Its manifest preserves the requested base, variant/config identity, omissions, and capture gaps. Analysis counts only successful proposal-bound receipt observations; missing or conflicting bindings remain `UNVERIFIED_OUTCOME`.

The comparison runs every captured package through all 18 policies locally and reports field-level differences from Trial D. Only the originally checked variant with a matching config, exact business output, and verified receipt can retain its observed verdict. All counterfactual variants are **NOT_GRADED**, even if their output happens to match.

### Resource and Check limits

Each experiment has its own lazy task SQLite connection, trace database, and 100-entry metadata log ring. Protected trace retention is **100 rows / 2 MiB of serialized payload per variant**, totaling at most 36 MiB across experiments. Root traces retain their existing 500 rows / 32 MiB. Database pages, WAL files, and task state add storage beyond those payload limits. Large individual events may become metadata-only with explicit omission flags; export soon after each Check. Render's ephemeral filesystem still loses state on redeployment.

**One deployment does not mean one grader attempt.** Each URL needs its own Check, and different Checks may draw different audit cases. The ten Check/Save attempts per 24 hours still apply; reserve the final attempt for Save. Choose informative combinations rather than spending attempts on every historical variant. No live Check or Save is invoked by export, analysis, local comparison, or these tests.

### Local verification

The frozen v32/A/B/C/D and pre-refactor E references are test-only compressed fixtures, not copied deployed solvers. The retained-corpus comparison verified **2,111 inputs / 37,998 variant decisions** with no historical-equivalence or action/evidence discrepancy; it also checked 1,780 accepted variants. The actual localhost monolith completed all 18 discovery/proposal/receipt/alias/log workflows and recovered exact tasks and terminal receipt replays after process restart. These results do not establish new grader acceptance or 4/4.

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

- `/health` — baseline readiness and version (`offline-v36-d`)
- `/a2a/vN/health` or `/vN/health` — the selected experimental policy/version
- `/debug/q10/variants` — fixed Q2 policy registry and submission URLs
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
python -I -B test_q2_empty_identity.py
python -I -B test_q2_vendor_binding.py
python -I -B test_q10_variants.py
python -I -B test_compare_q2_variants.py
python -I -B test_q4_render_audits.py
python -I -B test_q10_traces.py
python -I -B test_capture_q2_traces.py
python -I -B test_analyze_q2_traces.py
python -I -B test_live_offline_regressions.py
```

Additional replay suites live in the adjacent `ga5-src` workspace. They verify signed receipts, stable accepted outputs, receipt conflict handling, invoice audit cases, incident retries/approvals/timeouts, trace topology, and persisted replay.
