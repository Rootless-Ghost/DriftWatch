"""
DriftWatch — PostgreSQL storage layer.

Schema is managed externally via init-db/. Table expected: driftwatch_reports
"""

import json
import logging
import os
import uuid
from datetime import datetime

import psycopg2
import psycopg2.extras
from contextlib import contextmanager
from psycopg2.pool import ThreadedConnectionPool

logger = logging.getLogger("driftwatch.storage")


class ReportStorage:

    def __init__(self, db_path: str = "./driftwatch.db"):
        url = os.environ.get("DATABASE_URL") or db_path
        self._pool = ThreadedConnectionPool(minconn=1, maxconn=10, dsn=url)

    @contextmanager
    def _get_conn(self):
        conn = self._pool.getconn()
        try:
            yield conn
        except Exception:
            conn.rollback()
            raise
        finally:
            self._pool.putconn(conn)

    # ── Write ──────────────────────────────────────────────────────────────────

    def save_report(self, report: dict) -> dict:
        report_id = str(uuid.uuid4())
        now       = datetime.utcnow().isoformat() + "Z"
        summary   = report.get("summary", {})

        with self._get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO driftwatch_reports
                        (id, label, total_rules, never_fired, overfiring, healthy,
                         coverage_pct, noise_score, time_window_hours, event_count,
                         report_json, created_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
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
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    "SELECT * FROM driftwatch_reports WHERE id = %s", (report_id,)
                )
                row = cur.fetchone()
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
            conditions.append("LOWER(label) LIKE LOWER(%s)")
            params.append(f"%{search}%")

        where  = ("WHERE " + " AND ".join(conditions)) if conditions else ""
        offset = (page - 1) * per_page

        with self._get_conn() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(f"SELECT COUNT(*) FROM driftwatch_reports {where}", params)
                total = cur.fetchone()["count"]
                cur.execute(
                    f"""
                    SELECT id, label, total_rules, never_fired, overfiring, healthy,
                           coverage_pct, noise_score, time_window_hours, event_count,
                           created_at
                    FROM driftwatch_reports {where}
                    ORDER BY created_at DESC
                    LIMIT %s OFFSET %s
                    """,
                    params + [per_page, offset],
                )
                items = [dict(r) for r in cur.fetchall()]

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
            with conn.cursor() as cur:
                cur.execute(
                    "DELETE FROM driftwatch_reports WHERE id = %s", (report_id,)
                )
                deleted = cur.rowcount > 0
            conn.commit()
        return deleted

    def clear_all(self) -> int:
        with self._get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM driftwatch_reports")
                count = cur.rowcount
            conn.commit()
        return count
