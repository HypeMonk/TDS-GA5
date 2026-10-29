"""Bounded Q2/Q4 request diagnostics shared across function instances."""
import json
import os
import sqlite3
import threading

from durable_store import connect, initialize, is_shared

_LOCK = threading.Lock()
SCHEMA = """CREATE TABLE IF NOT EXISTS solver_http_logs(
    id INTEGER PRIMARY KEY AUTOINCREMENT, question TEXT NOT NULL,
    received REAL NOT NULL, payload TEXT NOT NULL, payload_bytes INTEGER NOT NULL);
    CREATE INDEX IF NOT EXISTS solver_http_log_question ON solver_http_logs(question,id);"""
_FAILURES = 0


def _connection():
    connection = connect(os.environ.get("SOLVER_LOG_DB", "/tmp/ga5_http_logs.db"), timeout=1.0)
    initialize(connection, SCHEMA)
    connection.row_factory = sqlite3.Row
    return connection


def record(question, entry):
    global _FAILURES
    connection = None
    try:
        payload = json.dumps(entry, ensure_ascii=False)
        if len(payload.encode("utf-8")) > 2 * 1024 * 1024:
            reduced = {key: entry.get(key) for key in ("timestamp", "method", "status_code", "duration_ms")}
            reduced["omittedReason"] = "diagnostic_size_limit"
            payload = json.dumps(reduced)
        with _LOCK:
            connection = _connection()
            if is_shared():
                connection.execute("BEGIN")
                connection.execute("SELECT pg_advisory_xact_lock(710104)")
            else:
                connection.execute("BEGIN IMMEDIATE")
            size = len(payload.encode("utf-8"))
            connection.execute("INSERT INTO solver_http_logs(question,received,payload,payload_bytes) VALUES(?,?,?,?)",
                               (question, entry["timestamp"], payload, size))
            total = 0
            for index, (identity, size) in enumerate(connection.execute(
                    "SELECT id,payload_bytes FROM solver_http_logs WHERE question=? ORDER BY id DESC",
                    (question,)).fetchall()):
                total += size
                if index >= 100 or total > 16 * 1024 * 1024:
                    connection.execute("DELETE FROM solver_http_logs WHERE question=? AND id<=?",
                                       (question, identity))
                    break
            connection.commit()
    except Exception:
        _FAILURES += 1
    finally:
        if connection is not None:
            connection.close()


def rows(question, *, limit=25, before=None):
    connection = _connection()
    try:
        sql = "SELECT payload FROM solver_http_logs WHERE question=?"
        params = [question]
        if before is not None:
            sql += " AND received<?"
            params.append(before)
        sql += " ORDER BY id DESC LIMIT ?"
        params.append(max(1, min(limit, 100)))
        return [json.loads(row[0]) for row in connection.execute(sql, params).fetchall()][::-1]
    finally:
        connection.close()
