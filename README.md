# TDS GA3/GA5 Offline Universal Solver

A single FastAPI deployment for the assignment endpoints. The Q2–Q4 agent paths are deterministic and provider-free: no OpenAI, AI Pipe, OpenRouter, or Google model client is imported or called.

## Offline decision model

- **Invoice/A2A:** extracts current commercial identities, amounts, order/payment relationships, authority ceilings, bank verification, and exactly three controlling references. It supports both the ordinary cover/ledger layout and distributed/paraphrased records independent of file order. When a distributed record omits a distinct invoice number, the signed current order identifier is returned as the only supplied commercial identity. A missing human-readable vendor remains explicit rather than being replaced by an account number, and the evidence-backed action still follows the current ledger, verification state, and authority boundary.
- **Mailroom:** selects actions from source kind, provenance, current authenticated state, signed scope, exact request identity, and least privilege. Standing approvals and request-controlled notices are handled separately. Contradictory or unsupported evidence returns HTTP 422 without a model call.
- **Incident response:** classifies unique positive causal relations, validates catalog-bound arguments, evaluates bounded numeric/Boolean operating rules, enforces approval gates, and persists receipt-driven state and OTLP topology.

The solver is designed to generalize through entities and relationships rather than fixed generated IDs. Arbitrary natural-language input can still be ambiguous; those cases fail closed instead of being guessed.

## Render

The Dockerfile starts Uvicorn on Render's `$PORT`. Required environment variable:

- `STUDENT_EMAIL`: the registered assignment email.

Optional:

- `DEBUG_KEY`: a random secret enabling detailed Q10/Q11 durable wire endpoints.
- `GA5_DB`, `A2A_DB`, `Q11_WIRE_DB`: SQLite paths. Render's free filesystem is ephemeral, so redeployment clears state; exact replay is durable only within the running deployment.

No provider API key is required for Q2–Q4.

## Health and diagnostics

- `/health` — readiness and version (`offline-v18`)
- `/debug/q9` — redacted durable Q3 proposal records
- `/debug/q9/commitwire` — redacted Q3 receipt/outcome records
- `/debug/q10` — redacted recent Q2 HTTP records
- `/debug/q11` — redacted recent Q4 HTTP records
- `/debug/logs/q9`, `/debug/logs/q10`, `/debug/logs/q11` — equivalent request-log views
- `/debug/q10/wire?key=DEBUG_KEY`, `/debug/q11/wire?key=DEBUG_KEY` — protected durable indexes

Authorization/cookie headers, secret-shaped values, `sensitive` objects, and confidential/private source text are redacted from public diagnostics.

## Verification

```powershell
python -I -B test_live_offline_regressions.py
```

Additional replay suites live in the adjacent `ga5-src` workspace. They verify signed receipts, stable accepted outputs, receipt conflict handling, invoice audit cases, incident retries/approvals/timeouts, trace topology, and persisted replay.
