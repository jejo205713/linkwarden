"""SQLite-backed incident report storage with JSONL fallback.

Schema:
    reports(
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp       TEXT     NOT NULL,
        name            TEXT,
        email           TEXT,
        phishing_url    TEXT,
        incident_date   TEXT,
        financial_loss  TEXT,
        details         TEXT,
        scan_result     TEXT,
        risk_level      TEXT,
        indicators      TEXT
    )

Why JSONL fallback: tests inject ``LINKWARDEN_REPORTS_FILE`` to capture writes
in a temp file. We honor that env var and skip the SQLite path entirely when
it's set, so existing tests stay green.
"""
from __future__ import annotations

import json
import os
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Optional


_DB_LOCK = threading.Lock()


def _data_dir() -> Path:
    return Path(os.path.dirname(__file__)).parent / "data"


def _db_path() -> Path:
    override = os.environ.get("LINKWARDEN_REPORTS_DB")
    if override:
        return Path(override)
    return _data_dir() / "reports.sqlite"


def _jsonl_path() -> Optional[Path]:
    override = os.environ.get("LINKWARDEN_REPORTS_FILE")
    return Path(override) if override else None


def _ensure_dir(p: Path) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)


def _connect() -> sqlite3.Connection:
    path = _db_path()
    _ensure_dir(path)
    conn = sqlite3.connect(str(path))
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS reports (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp       TEXT     NOT NULL,
            name            TEXT,
            email           TEXT,
            phishing_url    TEXT,
            incident_date   TEXT,
            financial_loss  TEXT,
            details         TEXT,
            scan_result     TEXT,
            risk_level      TEXT,
            indicators      TEXT
        )
        """
    )
    return conn


def save_report(payload: dict) -> dict:
    """Persist a report. Returns the stored record (with ``id`` and timestamp).

    If ``LINKWARDEN_REPORTS_FILE`` is set, JSONL mode is used (test path).
    Otherwise SQLite is used.
    """
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "name": payload.get("name", "Anonymous") or "Anonymous",
        "email": payload.get("email", "") or "",
        "phishing_url": payload.get("phishing_url", "") or "",
        "incident_date": payload.get("incident_date", "") or "",
        "financial_loss": payload.get("financial_loss", "None") or "None",
        "details": payload.get("details", "") or "",
        "scan_result": payload.get("scan_result", "") or "",
        "risk_level": payload.get("risk_level", "") or "",
        "indicators": json.dumps(payload.get("indicators", []), ensure_ascii=False),
    }

    jsonl = _jsonl_path()
    if jsonl is not None:
        _ensure_dir(jsonl)
        with jsonl.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")
        # Mirror the structure the SQLite path returns.
        record["id"] = None
        return record

    with _DB_LOCK:
        conn = _connect()
        try:
            cur = conn.execute(
                """
                INSERT INTO reports (
                    timestamp, name, email, phishing_url, incident_date,
                    financial_loss, details, scan_result, risk_level, indicators
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record["timestamp"],
                    record["name"],
                    record["email"],
                    record["phishing_url"],
                    record["incident_date"],
                    record["financial_loss"],
                    record["details"],
                    record["scan_result"],
                    record["risk_level"],
                    record["indicators"],
                ),
            )
            conn.commit()
            record["id"] = cur.lastrowid
        finally:
            conn.close()
    return record


def list_reports(limit: int = 100) -> list[dict]:
    """Return the most recent ``limit`` reports, newest first."""
    jsonl = _jsonl_path()
    if jsonl is not None:
        if not jsonl.exists():
            return []
        rows: list[dict] = []
        with jsonl.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        rows.reverse()
        return rows[:limit]

    with _DB_LOCK:
        conn = _connect()
        try:
            cur = conn.execute(
                """
                SELECT id, timestamp, name, email, phishing_url, incident_date,
                       financial_loss, details, scan_result, risk_level, indicators
                FROM reports
                ORDER BY id DESC
                LIMIT ?
                """,
                (max(1, min(int(limit), 1000)),),
            )
            cols = [d[0] for d in cur.description]
            out = [dict(zip(cols, row)) for row in cur.fetchall()]
        finally:
            conn.close()

    for r in out:
        try:
            r["indicators"] = json.loads(r["indicators"]) if r.get("indicators") else []
        except (json.JSONDecodeError, TypeError):
            r["indicators"] = []
    return out


def report_count() -> int:
    jsonl = _jsonl_path()
    if jsonl is not None:
        if not jsonl.exists():
            return 0
        with jsonl.open("r", encoding="utf-8") as fh:
            return sum(1 for line in fh if line.strip())

    with _DB_LOCK:
        conn = _connect()
        try:
            return conn.execute("SELECT COUNT(*) FROM reports").fetchone()[0]
        finally:
            conn.close()
