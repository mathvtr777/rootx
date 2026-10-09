"""
ROOTX - API Principal
"""
import asyncio
import uuid
import json
import traceback
from datetime import datetime
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .models import ScanRequest, ScanResponse, ScanStatus, ScanResult, Finding
from .database import init_db, create_scan, update_scan_status, save_scan_results, get_scan, get_all_scans
from .scanner import SecurityScanner

# Configuração
BASE_DIR = Path(__file__).parent.parent

app = FastAPI(
    title="ROOTX API",
    description="Scanner de Segurança Web",
    version="1.0.0"
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
async def startup():
    """Inicializa banco de dados"""
    await init_db()


@app.get("/api/health")
async def health():
    """Health check"""
    return {"status": "ok", "service": "ROOTX", "version": "1.0.0"}


@app.post("/api/scan")
async def create_scan_endpoint(request: ScanRequest):
    """Inicia um novo scan de segurança"""
    scan_id = str(uuid.uuid4())[:8]
    await create_scan(scan_id, str(request.url), request.scan_type.value)

    time_map = {"quick": 30, "full": 180, "aggressive": 600}
    estimated_time = time_map.get(request.scan_type.value, 60)

    return {
        "scan_id": scan_id,
        "status": "pending",
        "message": f"Scan iniciado. ID: {scan_id}",
        "estimated_time_seconds": estimated_time
    }


@app.get("/api/scan/{scan_id}")
async def get_scan_status(scan_id: str):
    """Verifica status de um scan"""
    scan = await get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan não encontrado")

    status = scan["status"]
    progress = 0 if status == "pending" else (50 if status == "running" else 100)

    return {
        "scan_id": scan_id,
        "status": status,
        "url": scan["url"],
        "progress": progress,
        "started_at": scan["started_at"]
    }


@app.post("/api/scan/{scan_id}/run")
async def run_scan(scan_id: str, background_tasks: BackgroundTasks):
    """Executa o scan"""
    scan = await get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan não encontrado")

    if scan["status"] not in ["pending", "failed"]:
        return {"message": "Scan já executado", "status": scan["status"]}

    await update_scan_status(scan_id, ScanStatus.RUNNING)
    background_tasks.add_task(execute_scan, scan_id, scan["url"], scan["scan_type"])

    return {"message": "Scan em execução", "status": "running"}


async def execute_scan(scan_id: str, url: str, scan_type: str):
    """Executa o scan completo"""
    print(f"[ROOTX] Iniciando scan {scan_id} para {url}")

    try:
        scanner = SecurityScanner()
        print(f"[ROOTX] Scanner criado")

        from .models import ScanType
        scan_type_enum = ScanType(scan_type)
        print(f"[ROOTX] Tipo de scan: {scan_type_enum}")

        result = await scanner.scan(url, scan_type_enum)
        print(f"[ROOTX] Scan concluído, achados: {len(result.findings)}")

        await scanner.close()

        result.scan_id = scan_id
        result.status = ScanStatus.COMPLETED
        result.completed_at = datetime.utcnow()

        await save_scan_results(scan_id, result)
        print(f"[ROOTX] Scan {scan_id} completo - Score: {result.score}")

    except Exception as e:
        print(f"[ROOTX] Erro no scan {scan_id}: {e}")
        traceback.print_exc()
        await update_scan_status(scan_id, ScanStatus.FAILED)


@app.get("/api/scan/{scan_id}/report")
async def get_scan_report(scan_id: str):
    """Retorna relatório do scan"""
    scan = await get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan não encontrado")

    if scan["status"] != "completed":
        raise HTTPException(
            status_code=400,
            detail=f"Scan ainda não completo. Status: {scan['status']}"
        )

    findings = json.loads(scan["findings_json"]) if scan["findings_json"] else []
    technologies = json.loads(scan["technologies_json"]) if scan["technologies_json"] else []
    security_headers = json.loads(scan["security_headers_json"]) if scan["security_headers_json"] else {}
    summary = json.loads(scan["summary_json"]) if scan["summary_json"] else {}
    summary["timestamp"] = scan["completed_at"]

    return {
        "report_url": scan["url"],
        "score": scan["score"],
        "classification": summary.get("classification"),
        "duration_seconds": scan["duration_seconds"] or 0,
        "summary": {
            "total_findings": len(findings),
            "severity_counts": summary.get("severity_counts", {}),
            "risk_level": summary.get("risk_level", "unknown")
        },
        "technologies": technologies,
        "security_headers": security_headers,
        "findings": findings,
        "recommendations": []
    }


@app.get("/api/scans")
async def list_scans():
    """Lista todos os scans"""
    scans = await get_all_scans()
    return {"scans": scans, "total": len(scans)}


@app.get("/api/debug")
async def debug():
    """Endpoint de debug"""
    try:
        # Tenta importar scanner
        from .scanner import SecurityScanner

        # Tenta criar scanner
        scanner = SecurityScanner()

        # Tenta fazer um scan simples
        async with scanner.client:
            response = await scanner.client.get("https://httpbin.org/html")

        return {
            "status": "ok",
            "scanner": "funcionando",
            "response_status": response.status_code
        }
    except Exception as e:
        return {
            "status": "error",
            "error": str(e),
            "traceback": traceback.format_exc()
        }


@app.get("/")
async def root():
    """Health check na raiz"""
    return {"message": "ROOTX API", "version": "1.0.0", "docs": "/docs"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
