"""Run each local regression suite in an isolated process without deployment credentials."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent
LOCAL = ["test_q10_evidence.py", "test_q2_capture_replay.py", "test_q10_atomicity.py", "test_q10_traces.py",
         "test_capture_q2_traces.py", "test_analyze_q2_traces.py",
         "test_live_offline_regressions.py", "test_q11_safety_regressions.py", "test_shared_storage.py"]
ADJACENT = ["test_q11_first_pass.py", "test_q11_save_audit.py", "test_q11_reliability.py"]


def main():
    files = [ROOT / name for name in LOCAL]
    files += [ROOT.parent / "ga5-src" / name for name in ADJACENT]
    failures = []
    missing = []
    with tempfile.TemporaryDirectory(prefix="ga5-regressions-") as folder:
        env = dict(os.environ)
        for key in ("SOLVER_DATABASE_URL", "POSTGRES_URL", "DATABASE_URL", "VERCEL", "SOLVER_TEST_DATABASE_URL"):
            env.pop(key, None)
        env.update(DEBUG_KEY="local-regression-debug-key", SOLVER_LOG_DB=str(Path(folder) / "logs.db"),
                   PYTHONIOENCODING="utf-8")
        for file in files:
            if not file.is_file():
                missing.append(str(file))
                continue
            print("\nRUN " + file.name, flush=True)
            code = ("import sys,runpy;sys.path.insert(0," + repr(str(ROOT)) + ");"
                    "sys.argv=[" + repr(str(file)) + "];runpy.run_path(sys.argv[0],run_name='__main__')")
            result = subprocess.run([sys.executable, "-I", "-B", "-c", code], env=env, cwd=ROOT)
            if result.returncode:
                failures.append(file.name)
    if missing:
        print("Adjacent suites unavailable: " + ", ".join(missing))
    if failures:
        print("FAILED: " + ", ".join(failures))
        return 1
    print("All available local suites passed. PostgreSQL tests need a separate local database run.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
