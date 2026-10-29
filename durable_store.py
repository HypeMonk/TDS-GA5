"""Shared PostgreSQL storage for Q2/Q4; SQLite remains the local-development backend."""
import os
import math
import sqlite3
import threading

_SCHEMA_READY = set()
_SCHEMA_LOCK = threading.Lock()


class Row:
    def __init__(self, names, values):
        self.names = names
        self.values = values

    def __getitem__(self, key):
        return self.values[key if isinstance(key, int) else self.names.index(key)]

    def __iter__(self):
        return iter(self.values)

    def keys(self):
        return self.names


class Cursor:
    def __init__(self, cursor):
        self.cursor = cursor
        self.rowcount = cursor.rowcount
        self.names = [column.name for column in cursor.description or []]

    def fetchone(self):
        values = self.cursor.fetchone()
        return None if values is None else Row(self.names, values)

    def fetchall(self):
        return [Row(self.names, values) for values in self.cursor.fetchall()]

    def __iter__(self):
        return iter(self.fetchall())


class PostgresConnection:
    # The callers use only static qmark SQL, not arbitrary SQL or user-supplied identifiers.
    def __init__(self, url, timeout):
        import psycopg
        self.driver = psycopg
        self.statement_timeout = max(250, min(15000, int(timeout * 1000)))
        self.lock_timeout = max(250, min(10000, int(timeout * 1000)))
        self.connection = None
        try:
            self.connection = psycopg.connect(url, autocommit=True,
                                              connect_timeout=max(1, min(10, math.ceil(timeout))),
                                              prepare_threshold=None)
            self.connection.execute("SET statement_timeout = %s" % self.statement_timeout)
            self.connection.execute("SET lock_timeout = %s" % self.lock_timeout)
        except psycopg.Error as exc:
            if self.connection is not None:
                self.connection.close()
            raise sqlite3.OperationalError("Shared database connection unavailable") from exc

    @property
    def closed(self):
        return self.connection.closed

    def execute(self, sql, params=()):
        try:
            if sql in ("BEGIN IMMEDIATE", "BEGIN"):
                self.connection.execute("BEGIN")
                self.connection.execute("SET LOCAL statement_timeout = %s" % self.statement_timeout)
                self.connection.execute("SET LOCAL lock_timeout = %s" % self.lock_timeout)
                if sql == "BEGIN":
                    return Cursor(self.connection.execute("SELECT 1"))
                # All Q2 transitions use the same transaction-scoped lock, including creates
                # whose task/message rows do not exist yet. It also works through PgBouncer.
                return Cursor(self.connection.execute("SELECT pg_advisory_xact_lock(710102)"))
            sql = sql.replace("INTEGER PRIMARY KEY AUTOINCREMENT", "BIGSERIAL PRIMARY KEY")
            sql = sql.replace(" REAL", " DOUBLE PRECISION")
            return Cursor(self.connection.execute(sql.replace("?", "%s"), params))
        except self.driver.IntegrityError as exc:
            raise sqlite3.IntegrityError("Shared database constraint conflict") from exc
        except self.driver.OperationalError as exc:
            self.connection.close()
            raise sqlite3.OperationalError("Shared database connection unavailable") from exc
        except self.driver.Error as exc:
            raise sqlite3.OperationalError("Shared database operation unavailable") from exc

    def executescript(self, sql):
        for statement in sql.split(";"):
            if statement.strip():
                self.execute(statement)

    def commit(self):
        self.execute("COMMIT")

    def rollback(self):
        self.execute("ROLLBACK")

    def close(self):
        self.connection.close()


def initialize(connection, schema):
    if not isinstance(connection, PostgresConnection):
        connection.executescript(schema)
        return
    key = (database_url(), schema)
    with _SCHEMA_LOCK:
        if key in _SCHEMA_READY:
            return
        try:
            connection.execute("BEGIN")
            connection.execute("SELECT pg_advisory_xact_lock(710100)")
            connection.executescript(schema)
            connection.commit()
        except Exception:
            try:
                connection.rollback()
            except sqlite3.Error:
                pass
            connection.close()
            raise
        _SCHEMA_READY.add(key)


def database_url():
    return (os.environ.get("SOLVER_DATABASE_URL") or os.environ.get("POSTGRES_URL")
            or os.environ.get("DATABASE_URL") or "")


def is_shared():
    return bool(database_url())


def storage_status():
    shared = is_shared()
    required = os.environ.get("VERCEL") == "1"
    return {"backend": "postgresql" if shared else "sqlite", "shared": shared,
            "configured": shared or not required,
            "requirement": "Shared PostgreSQL is required on Vercel" if required and not shared else None}


def connect(path, *, timeout=10.0):
    url = database_url()
    if url:
        if not url.startswith(("postgres://", "postgresql://")):
            raise sqlite3.OperationalError("Shared database URL must use PostgreSQL")
        return PostgresConnection(url, timeout)
    if os.environ.get("VERCEL") == "1":
        raise sqlite3.OperationalError("Set SOLVER_DATABASE_URL to shared PostgreSQL on Vercel")
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    connection = sqlite3.connect(path, timeout=timeout, check_same_thread=False)
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA busy_timeout=%d" % int(timeout * 1000))
    return connection
