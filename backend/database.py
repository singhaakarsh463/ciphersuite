"""SQLite persistence layer for TLSentinel assessments, history, and certificate monitoring."""
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

DB_DIR = Path(__file__).resolve().parent / "data"
DB_PATH = DB_DIR / "tlsentinel.db"


def get_db():
    DB_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    with conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS assessments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                created_at TEXT NOT NULL,
                overall_status TEXT NOT NULL,
                summary TEXT NOT NULL,
                details TEXT NOT NULL
            );
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                assessment_id INTEGER,
                created_at TEXT NOT NULL,
                severity TEXT NOT NULL,
                title TEXT NOT NULL,
                message TEXT NOT NULL,
                FOREIGN KEY (assessment_id) REFERENCES assessments (id) ON DELETE CASCADE
            );
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS monitored_domains (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL UNIQUE,
                port INTEGER NOT NULL DEFAULT 443,
                email TEXT,
                last_checked TEXT,
                status TEXT DEFAULT 'PENDING',
                days_left INTEGER DEFAULT 0,
                hours_left INTEGER DEFAULT 0,
                expiry_date TEXT,
                issuer TEXT,
                subject TEXT,
                alert_level TEXT DEFAULT 'NORMAL',
                enabled INTEGER DEFAULT 1,
                created_at TEXT NOT NULL
            );
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS monitoring_notifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain_id INTEGER,
                domain TEXT NOT NULL,
                created_at TEXT NOT NULL,
                alert_level TEXT NOT NULL,
                message TEXT NOT NULL,
                channel TEXT DEFAULT 'DASHBOARD',
                FOREIGN KEY (domain_id) REFERENCES monitored_domains (id) ON DELETE CASCADE
            );
        """)
    conn.close()


def save_assessment(target: str, overall_status: str, summary: Dict[str, Any], details: Dict[str, Any]) -> int:
    init_db()
    conn = get_db()
    now_iso = datetime.now(timezone.utc).isoformat(timespec="seconds")
    with conn:
        cur = conn.execute(
            "INSERT INTO assessments (target, created_at, overall_status, summary, details) VALUES (?, ?, ?, ?, ?)",
            (target, now_iso, overall_status, json.dumps(summary), json.dumps(details))
        )
        aid = cur.lastrowid
        # Extract and save active alerts if any
        for alert in summary.get("alerts", []):
            conn.execute(
                "INSERT INTO alerts (assessment_id, created_at, severity, title, message) VALUES (?, ?, ?, ?, ?)",
                (aid, now_iso, alert.get("severity", "INFO"), alert.get("title", ""), alert.get("message", ""))
            )
    conn.close()
    return aid


def get_history(limit: int = 30) -> List[Dict[str, Any]]:
    init_db()
    conn = get_db()
    cur = conn.execute(
        "SELECT id, target, created_at, overall_status, summary FROM assessments ORDER BY id DESC LIMIT ?",
        (limit,)
    )
    rows = cur.fetchall()
    conn.close()
    out = []
    for r in rows:
        try:
            summ = json.loads(r["summary"])
        except Exception:
            summ = {}
        out.append({
            "id": r["id"],
            "target": r["target"],
            "created_at": r["created_at"],
            "overall_status": r["overall_status"],
            "summary": summ
        })
    return out


def get_assessment(assessment_id: int) -> Optional[Dict[str, Any]]:
    init_db()
    conn = get_db()
    cur = conn.execute(
        "SELECT id, target, created_at, overall_status, summary, details FROM assessments WHERE id = ?",
        (assessment_id,)
    )
    row = cur.fetchone()
    conn.close()
    if not row:
        return None
    try:
        det = json.loads(row["details"])
    except Exception:
        det = {}
    det["id"] = row["id"]
    det["saved_target"] = row["target"]
    det["saved_at"] = row["created_at"]
    return det


def compare_assessments(base_id: int, target_id: int) -> Dict[str, Any]:
    base = get_assessment(base_id)
    target = get_assessment(target_id)
    if not base or not target:
        raise ValueError(f"One or both assessment IDs ({base_id}, {target_id}) not found")

    base_checks = {c["id"]: c for c in base.get("results", [])}
    target_checks = {c["id"]: c for c in target.get("results", [])}

    changes = []
    all_keys = sorted(set(base_checks.keys()) | set(target_checks.keys()))

    improved = 0
    regressed = 0
    unchanged = 0

    for k in all_keys:
        b = base_checks.get(k)
        t = target_checks.get(k)
        if b and t:
            old_st = b.get("status")
            new_st = t.get("status")
            name = t.get("name", b.get("name"))
            
            diff_type = "unchanged"
            if old_st != new_st:
                if old_st in ("REVIEW", "FAIL") and new_st == "PASS":
                    diff_type = "improved"
                    improved += 1
                elif old_st == "PASS" and new_st in ("REVIEW", "FAIL"):
                    diff_type = "regressed"
                    regressed += 1
                else:
                    diff_type = "changed"
            else:
                unchanged += 1

            changes.append({
                "id": k,
                "name": name,
                "diff_type": diff_type,
                "base_status": old_st,
                "target_status": new_st,
                "base_measured": b.get("measured"),
                "target_measured": t.get("measured"),
                "base_severity": b.get("severity", "INFO"),
                "target_severity": t.get("severity", "INFO"),
                "explanation": t.get("explanation")
            })

    b_cert = base.get("certificate") or {}
    t_cert = target.get("certificate") or {}
    cert_diff = {
        "fingerprint_changed": b_cert.get("fingerprint_sha256") != t_cert.get("fingerprint_sha256"),
        "serial_changed": b_cert.get("serial") != t_cert.get("serial"),
        "validity_changed": b_cert.get("not_after") != t_cert.get("not_after"),
        "base_expires": b_cert.get("not_after"),
        "target_expires": t_cert.get("not_after"),
        "base_key": f"{b_cert.get('key_type')} {b_cert.get('key_size')}",
        "target_key": f"{t_cert.get('key_type')} {t_cert.get('key_size')}",
    }

    # Include risk score comparison if present
    base_score = base.get("risk_score", {}).get("score")
    target_score = target.get("risk_score", {}).get("score")
    score_diff = None
    if base_score is not None and target_score is not None:
        score_diff = {
            "base_score": base_score,
            "target_score": target_score,
            "delta": target_score - base_score,
            "base_tier": base.get("risk_score", {}).get("tier"),
            "target_tier": target.get("risk_score", {}).get("tier")
        }

    return {
        "base": {"id": base_id, "created_at": base.get("saved_at"), "target": base.get("saved_target")},
        "target": {"id": target_id, "created_at": target.get("saved_at"), "target": target.get("saved_target")},
        "summary": {
            "improved": improved,
            "regressed": regressed,
            "unchanged": unchanged,
            "total": len(changes)
        },
        "checks": changes,
        "certificate_diff": cert_diff,
        "score_diff": score_diff
    }


# ===================================================================
# Certificate Expiry Monitoring Functions
# ===================================================================

def add_monitored_domain(domain: str, port: int = 443, email: Optional[str] = None) -> int:
    init_db()
    conn = get_db()
    clean_domain = domain.strip().lower()
    now_iso = datetime.now(timezone.utc).isoformat(timespec="seconds")
    with conn:
        # Check if already exists
        cur = conn.execute("SELECT id FROM monitored_domains WHERE domain = ?", (clean_domain,))
        existing = cur.fetchone()
        if existing:
            conn.execute(
                "UPDATE monitored_domains SET port = ?, email = ?, enabled = 1 WHERE id = ?",
                (port, email, existing["id"])
            )
            aid = existing["id"]
        else:
            cur = conn.execute(
                "INSERT INTO monitored_domains (domain, port, email, status, created_at) VALUES (?, ?, ?, 'PENDING', ?)",
                (clean_domain, port, email, now_iso)
            )
            aid = cur.lastrowid
    conn.close()
    return aid


def get_monitored_domains() -> List[Dict[str, Any]]:
    init_db()
    conn = get_db()
    cur = conn.execute("SELECT * FROM monitored_domains ORDER BY days_left ASC, id DESC")
    rows = cur.fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_monitored_domain(domain_id: int) -> Optional[Dict[str, Any]]:
    init_db()
    conn = get_db()
    cur = conn.execute("SELECT * FROM monitored_domains WHERE id = ?", (domain_id,))
    row = cur.fetchone()
    conn.close()
    return dict(row) if row else None


def update_monitored_domain(domain_id: int, last_checked: str, status: str, days_left: int, hours_left: int,
                            expiry_date: str, issuer: str, subject: str, alert_level: str):
    init_db()
    conn = get_db()
    with conn:
        conn.execute("""
            UPDATE monitored_domains
            SET last_checked = ?, status = ?, days_left = ?, hours_left = ?,
                expiry_date = ?, issuer = ?, subject = ?, alert_level = ?
            WHERE id = ?
        """, (last_checked, status, days_left, hours_left, expiry_date, issuer, subject, alert_level, domain_id))
    conn.close()


def delete_monitored_domain(domain_id: int) -> bool:
    init_db()
    conn = get_db()
    with conn:
        conn.execute("DELETE FROM monitored_domains WHERE id = ?", (domain_id,))
    conn.close()
    return True


def add_notification(domain_id: Optional[int], domain: str, alert_level: str, message: str, channel: str = "DASHBOARD"):
    init_db()
    conn = get_db()
    now_iso = datetime.now(timezone.utc).isoformat(timespec="seconds")
    with conn:
        conn.execute(
            "INSERT INTO monitoring_notifications (domain_id, domain, created_at, alert_level, message, channel) VALUES (?, ?, ?, ?, ?, ?)",
            (domain_id, domain, now_iso, alert_level, message, channel)
        )
    conn.close()


def get_notifications(limit: int = 50) -> List[Dict[str, Any]]:
    init_db()
    conn = get_db()
    cur = conn.execute("SELECT * FROM monitoring_notifications ORDER BY id DESC LIMIT ?", (limit,))
    rows = cur.fetchall()
    conn.close()
    return [dict(r) for r in rows]
