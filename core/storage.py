"""
DriftWatch — SQLite storage layer.
"""

import json
import logging
import sqlite3
import uuid
from datetime import datetime

logger = logging.getLogger("driftwatch.storage")


class ReportStorage:
    """Manages the SQLite database for saved drift reports."""

    def __init__(self, db_path: str = "./driftwatch.db"):
        self.db_path = db_path
        self._init_db()

    # ── Connection ─────────────────────────────────────────────────────────────

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._get_conn() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS reports (
                    id              TEXT PRIMARY KEY,
                    label           TEXT NOT NULL DEFAULT '',
                    total_rules     INTEGER NOT NULL DEFAULT 0,
                    never_fired     INTEGER NOT NULL DEFAULT 0,
                    overfiring      INTEGER NOT NULL DEFAULT 0,
                    healthy         INTEGER NOT NULL DEFAULT 0,
                    coverage_pct    REAL NOT NULL DEFAULT 0,
                    noise_score     REAL NOT NULL DEFAULT 0,
                    time_window_hours INTEGER NOT NULL DEFAULT 168,
                    event_count     INTEGER NOT NULL DEFAULT 0,
                    report_json     TEXT NOT NULL,
                    created_at      TEXT NOT NULL
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_reports_created
                ON reports (created_at)
            """)
            conn.commit()
        logger.info("Storage initialised: %s", self.db_path)

    # ── Write ──────────────────────────────────────────────────────────────────

    def save_report(self, report: dict) -> dict:
        """Persist a drift report. Generates a new ID; returns updated report."""
        report_id = str(uuid.uuid4())
        now       = datetime.utcnow().isoformat() + "Z"
        summary   = report.get("summary", {})

        with self._get_conn() as conn:
            conn.execute(
                """
                INSERT INTO reports
                    (id, label, total_rules, never_fired, overfiring, healthy,
                     coverage_pct, noise_score, time_window_hours, event_count,
                     report_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    report_id,
                    report.get("label", ""),
                    summary.get("total_rules", 0),
                    summary.get("never_fired_count", 0),
                    summary.get("overfiring_count", 0),
                    summary.get("healthy_count", 0),
                    summary.get("coverage_pct", 0.0),
                    summary.get("noise_score", 0.0),
                    report.get("time_window_hours", 168),
                    report.get("event_count", 0),
                    json.dumps(report),
                    now,
                ),
            )
            conn.commit()

        report["id"]         = report_id
        report["created_at"] = now
        logger.info("Saved report %s (%d rules)", report_id, summary.get("total_rules", 0))
        return report

    # ── Read ───────────────────────────────────────────────────────────────────

    def get_report(self, report_id: str) -> dict | None:
        with self._get_conn() as conn:
            row = conn.execute(
                "SELECT * FROM reports WHERE id = ?", (report_id,)
            ).fetchone()
        if row is None:
            return None
        data = json.loads(row["report_json"])
        data["id"]         = row["id"]
        data["created_at"] = row["created_at"]
        return data

    def list_reports(
        self,
        page: int = 1,
        per_page: int = 50,
        search: str = "",
    ) -> dict:
        conditions: list[str] = []
        params:     list      = []

        if search:
            conditions.append("LOWER(label) LIKE LOWER(?)")
            params.append(f"%{search}%")

        where  = ("WHERE " + " AND ".join(conditions)) if conditions else ""
        offset = (page - 1) * per_page

        with self._get_conn() as conn:
            total = conn.execute(
                f"SELECT COUNT(*) FROM reports {where}", params
            ).fetchone()[0]
            rows = conn.execute(
                f"""
                SELECT id, label, total_rules, never_fired, overfiring, healthy,
                       coverage_pct, noise_score, time_window_hours, event_count,
                       created_at
                FROM reports {where}
                ORDER BY created_at DESC
                LIMIT ? OFFSET ?
                """,
                params + [per_page, offset],
            ).fetchall()

        items = [dict(r) for r in rows]
        return {
            "items":    items,
            "total":    total,
            "page":     page,
            "per_page": per_page,
            "pages":    max(1, (total + per_page - 1) // per_page),
        }

    # ── Delete ─────────────────────────────────────────────────────────────────

    def delete_report(self, report_id: str) -> bool:
        with self._get_conn() as conn:
            cur = conn.execute("DELETE FROM reports WHERE id = ?", (report_id,))
            conn.commit()
        return cur.rowcount > 0

    def clear_all(self) -> int:
        with self._get_conn() as conn:
            cur = conn.execute("DELETE FROM reports")
            conn.commit()
        return cur.rowcount
