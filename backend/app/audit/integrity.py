"""
Audit Hash Chain Integrity Verification (real DDL, section 11.6 / ADR-10).

Re-links the ``audit.audit_logs`` chain from the database and verifies every
link: prev_hash[i] MUST equal row_hash[i-1], and the self hash is recomputed
with the same formula as ``AuditService._chain_hash_audit``.
"""

from __future__ import annotations

import hashlib
import json

from sqlalchemy import text


def _recompute_row_hash(prev_hash_ord, user_id, action, timestamp, ip_address,
                        mac_address, result, details) -> str:
    details_str = json.dumps(details, sort_keys=True, ensure_ascii=False) if details else "null"
    material = "|".join([
        prev_hash_ord or "GENESIS",
        str(user_id) if user_id else "None",
        action or "",
        timestamp.isoformat() if timestamp else "",
        str(ip_address) if ip_address else "",
        mac_address or "",
        result or "",
        details_str,
    ])
    return hashlib.sha256(material.encode()).hexdigest()


def _recompute_login_hash(prev_hash_ord, user_id, username, timestamp, ip_address,
                          mac_address, success, failure_reason) -> str:
    material = "|".join([
        prev_hash_ord or "GENESIS",
        str(user_id) if user_id else "None",
        username or "",
        timestamp.isoformat() if timestamp else "",
        str(ip_address) if ip_address else "",
        mac_address or "",
        "success" if success else "failure",
        failure_reason or "",
    ])
    return hashlib.sha256(material.encode()).hexdigest()


async def _verify_log_chain(conn, table: str) -> tuple[int, int]:
    """Verify one hash chain (audit_logs or login_audit_logs); returns (total, broken)."""
    broken = 0
    prev_row_hash: str | None = None
    total = 0
    if table == "audit.login_audit_logs":
        projection = ("id, user_id, timestamp, ip_address, mac_address,"
                      " prev_hash, row_hash, username, success, failure_reason")
    else:
        projection = ("id, user_id, timestamp, ip_address, mac_address,"
                      " prev_hash, row_hash, action, result, details")
    rows = (await conn.execute(text(f"""
        SELECT {projection}
          FROM {table}
         ORDER BY id
    """))).mappings().all()
    for row in rows:
        total += 1
        if row["prev_hash"] != prev_row_hash:
            broken += 1
        if table == "audit.login_audit_logs":
            recomputed = _recompute_login_hash(
                prev_row_hash, row["user_id"], row["username"], row["timestamp"],
                row["ip_address"], row["mac_address"], row["success"], row["failure_reason"],
            )
        else:
            recomputed = _recompute_row_hash(
                prev_row_hash, row["user_id"], row["action"], row["timestamp"],
                row["ip_address"], row["mac_address"], row["result"], row["details"],
            )
        if recomputed != row["row_hash"]:
            broken += 1
        prev_row_hash = row["row_hash"]
    return total, broken


async def verify_integrity(conn) -> dict:
    """Verify every hash chain (audit_logs + login_audit_logs)."""
    total = 0
    broken = 0
    for table in ("audit.audit_logs", "audit.login_audit_logs"):
        t, b = await _verify_log_chain(conn, table)
        total += t
        broken += b

    status = "integrity_ok" if broken == 0 else "integrity_broken"
    return {
        "status": status,
        "total_logs": total,
        "broken_links": broken,
        "total_links": max(total - 2, 0),
        "message": "Chain integrity verified" if broken == 0 else f"{broken} chain links broken",
    }


async def check_audit_integrity() -> dict:
    """Public entry point for GET /audit/integrity-check."""
    from app.core.database import engine

    async with engine.connect() as conn:
        result = await verify_integrity(conn)
    return result