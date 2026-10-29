# Vercel deployment

## What changed

Q2 and Q4 can now share one PostgreSQL database across Vercel function instances. Task creation and deduplication are transactional; receipt finalization and cancellation take the same database lock. Q4 creates runs once and uses compare-and-swap updates for receipts. Neither endpoint relies on an instance-local cache as its authoritative state.

**A Vercel deployment without a shared database is not ready.** `/tmp` SQLite files are local to individual instances. Increasing function duration, adding uptime pings, or repeatedly checking the grader does not make those files shared.

Q3's mailroom implementation is unchanged. This storage change applies only to Q2/Q4 and their diagnostics.

## Repair branch

The verified repair candidate is published on **`fix/q2-q4-vercel`**, leaving `main` unchanged until Neon is configured. After saving the Production environment variables below:

1. Open **Vercel → project → Settings → Environments → Production → Branch Tracking**.
2. Set the tracked branch to `fix/q2-q4-vercel` and save.
3. Open **Deployments → Create Deployment**, enter `fix/q2-q4-vercel`, and create the deployment.

This deploys the repair branch to the project's production domain. Redeploying an old `main` commit does not include these fixes. Alternatively, merge the repair branch into `main` after configuration and keep tracking `main`.

## Required setup

1. Create a PostgreSQL database, for example using Neon through Vercel's Storage/Marketplace integration or the Neon console. Select an available free plan if appropriate. Free-plan storage, compute, suspension, and connection limits still apply; there is no unlimited availability guarantee.
2. Obtain the PostgreSQL connection string. Prefer the provider's pooled connection string for serverless traffic; preserve its TLS parameters such as `sslmode=require`.
3. In **Vercel → project → Settings → Environment Variables**, set:

   | Variable | Value |
   |---|---|
   | `SOLVER_DATABASE_URL` | The full PostgreSQL connection string, including credentials and TLS parameters. |
   | `DEBUG_KEY` | A long random secret for protected diagnostics. |
   | `STUDENT_EMAIL` | Keep the registered assignment email already used by the app. |

   `POSTGRES_URL` and `DATABASE_URL` are accepted when `SOLVER_DATABASE_URL` is absent. All instances of a deployment must resolve to the same database. Do not leave an obsolete higher-priority URL configured.

4. Enable the variables for **Production**. Use a separate database/branch for Preview and Development rather than sharing production test state.
5. Deploy this repository with `main.py` as the detected FastAPI entrypoint. Leave Build/Output Directory overrides unset unless Vercel requires otherwise. Dependencies come from `requirements.txt`; `.python-version` selects **Python 3.12**; `vercel.json` gives the function a **60-second** platform limit and disables response caching. The grader still has its own shorter request and overall deadlines.
6. The app creates its Q2/Q4 and diagnostic tables automatically. Its database role must be allowed to create tables/indexes and read/write them. Never point a preview regression test at production.

No credentials are stored in the repository or sent to a browser. Environment variables must be saved through the account owner's Vercel settings. A Git push and deployment are separate actions from these local repairs.

## Confirm readiness before another Check

These are read-only checks and do not spend a grader attempt:

```powershell
curl.exe -fsS https://YOUR-DEPLOYMENT/health
curl.exe -fsS https://YOUR-DEPLOYMENT/health/ready
curl.exe -fsS https://YOUR-DEPLOYMENT/.well-known/agent-card.json
```

- `/health` must report `version: offline-v29-shared`, `storage.backend: postgresql`, and `storage.shared: true`.
- `/health/ready` must return HTTP 200 and `status: ready`. It actually connects to the configured database.
- The Agent Card must advertise the deployment's current HTTPS origin and protocol `1.0`.
- Submit the origin or its `/a2a` base for Q2; both route families are supported. Submit the origin for Q4. Do not use an authenticated Vercel preview URL that redirects the grader to a login page.
- Missing shared storage or an unavailable database returns an explicit **503**, not a successful creation backed by disposable local state. Retrying a failed state-changing request must reuse its original message/receipt ID; the app never blindly retries an ambiguous committed mutation.

The first deployment using PostgreSQL does **not** migrate tasks from old Vercel `/tmp` files. Export any accessible old diagnostics before redeployment. Do not switch the database while a grader run is in progress; new checks create their own task/run namespaces.

## Retrieve the logs

Q2 traces and Q2/Q4 HTTP diagnostics now use the shared database, so a different function instance can retrieve them. Q4 HTTP logs require the header below. Keep the key out of URLs and screenshots.

```powershell
# DEBUG_KEY must be set locally to the deployment's secret.
curl.exe -fsS -H "X-Debug-Key: $env:DEBUG_KEY" "https://YOUR-DEPLOYMENT/debug/logs/q11?limit=100"
curl.exe -fsS "https://YOUR-DEPLOYMENT/debug/logs/q10?limit=100"
python -I -B capture_q2_traces.py https://YOUR-DEPLOYMENT .. --maximum 100
```

The Q2 public view is redacted. The protected Q4 view retains synthetic incident/tool fields but redacts declared private literals and authentication material. HTTP logs retain at most 100 rows and 16 MiB per question; Q2 detailed traces retain at most 500 rows and 32 MiB. Export important evidence before it is evicted. Diagnostic failures never authorize a state change and can leave gaps; Q2's trace index reports capture failures for the responding process.

The older protected wire endpoints still support their legacy query-key form for compatibility. Prefer the header-gated HTTP logs and Q2 trace exporter for new investigations.

## Local validation

```powershell
python -I -B run_local_tests.py
```

The runner isolates test processes, removes deployment database credentials, supplies a test-only diagnostic key, and uses temporary files. It runs adjacent `ga5-src` replay suites when available. PostgreSQL tests are skipped unless a disposable local database is explicitly supplied.

To test real shared storage, create a **local** database named `ga5_local_test` and set `SOLVER_TEST_DATABASE_URL` to its localhost PostgreSQL URL, then run:

```powershell
python -I -B test_shared_storage.py
python -I -B smoke_shared_http.py
```

The PostgreSQL suite tests separate workers/local paths, 20 concurrent duplicate creates, 20 cancel/receipt races, rejected/malformed scope handling through the local suites, Q4 receipt compare-and-swap, and shared diagnostics. The smoke script launches two actual Uvicorn app instances and drives Q2/Q4 across them. It disables unrelated Q8 startup sandbox creation for this focused test and stops both servers afterward. These tests refuse non-local or differently named databases.

Passing local tests and preserving recorded accepted proposals are not a new grader score. Live deployment behavior still needs verification after the shared database and diagnostic key are configured.

References: [Vercel FastAPI](https://vercel.com/docs/frameworks/backend/fastapi), [Vercel Python version](https://vercel.com/docs/functions/runtimes/python/python-version), [Neon manual Vercel connection](https://neon.com/docs/guides/vercel-manual), [Neon plans](https://neon.com/pricing).
