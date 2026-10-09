"""
Database SQLite para armazenar scans
"""
import aiosqlite
import json
from pathlib import Path
from typing import Optional
from datetime import datetime
from .models import ScanStatus, ScanResult, Finding, Technology, SecurityHeaders, Severity

DATABASE_PATH = Path(__file__).parent.parent / "rootx.db"


async def init_db():
    """Inicializa o banco de dados"""
    async with aiosqlite.connect(DATABASE_PATH) as db:
        await db.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                url TEXT NOT NULL,
                scan_type TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                started_at TEXT NOT NULL,
                completed_at TEXT,
                duration_seconds REAL,
                findings_json TEXT,
                technologies_json TEXT,
                security_headers_json TEXT,
                score INTEGER DEFAULT 100,
                summary_json TEXT
            )
        """)
        await db.commit()


async def create_scan(scan_id: str, url: str, scan_type: str) -> dict:
    """Cria um novo scan no banco"""
    async with aiosqlite.connect(DATABASE_PATH) as db:
        await db.execute(
            """INSERT INTO scans (id, url, scan_type, status, started_at)
               VALUES (?, ?, ?, ?, ?)""",
            (scan_id, url, scan_type, ScanStatus.PENDING.value, datetime.utcnow().isoformat())
        )
        await db.commit()
    return {"id": scan_id, "url": url, "status": ScanStatus.PENDING.value}


async def update_scan_status(scan_id: str, status: ScanStatus):
    """Atualiza status do scan"""
    async with aiosqlite.connect(DATABASE_PATH) as db:
        if status == ScanStatus.RUNNING:
            await db.execute(
                "UPDATE scans SET status = ? WHERE id = ?",
                (status.value, scan_id)
            )
        elif status == ScanStatus.COMPLETED:
            await db.execute(
                "UPDATE scans SET status = ?, completed_at = ? WHERE id = ?",
                (status.value, datetime.utcnow().isoformat(), scan_id)
            )
        else:
            await db.execute(
                "UPDATE scans SET status = ? WHERE id = ?",
                (status.value, scan_id)
            )
        await db.commit()


async def save_scan_results(scan_id: str, result: ScanResult):
    """Salva os resultados do scan"""
    async with aiosqlite.connect(DATABASE_PATH) as db:
        await db.execute(
            """UPDATE scans SET
               status = ?,
               completed_at = ?,
               duration_seconds = ?,
               findings_json = ?,
               technologies_json = ?,
               security_headers_json = ?,
               score = ?,
               summary_json = ?
               WHERE id = ?""",
            (
                result.status.value,
                result.completed_at.isoformat() if result.completed_at else None,
                result.duration_seconds,
                json.dumps([f.dict() for f in result.findings]),
                json.dumps([t.dict() for t in result.technologies]),
                result.security_headers.model_dump_json(),
                result.score,
                json.dumps(result.summary),
                scan_id
            )
        )
        await db.commit()


async def get_scan(scan_id: str) -> Optional[dict]:
    """Busca um scan pelo ID"""
    async with aiosqlite.connect(DATABASE_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM scans WHERE id = ?", (scan_id,)
        ) as cursor:
            row = await cursor.fetchone()
            if row:
                return dict(row)
            return None


async def get_all_scans() -> list:
    """Lista todos os scans"""
    async with aiosqlite.connect(DATABASE_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM scans ORDER BY started_at DESC LIMIT 50"
        ) as cursor:
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]
