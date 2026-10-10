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

from fastapi import FastAPI, HTTPException, BackgroundTasks, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response

from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from .models import ScanRequest, ScanResponse, ScanStatus, ScanResult, Finding
from .database import init_db, create_scan, update_scan_status, save_scan_results, get_scan, get_all_scans
from .scanner import SecurityScanner
from .pdf_generator import generate_pdf

# Configuração
BASE_DIR = Path(__file__).parent.parent

# Rate limiter: 5 scans por IP por hora
limiter = Limiter(key_func=get_remote_address, default_limits=["5/hour"])

app = FastAPI(
    title="ROOTX API",
    description="Scanner de Segurança Web",
    version="1.0.0"
)

# Rate limiter state
app.state.limiter = limiter


# Rate limit handler amigável (retorna JSON em vez de texto puro)
@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(
        status_code=429,
        content={
            "detail": "Limite de scans atingido. Você pode fazer no máximo 5 scans por hora. Aguarde e tente novamente.",
            "limit": str(exc.detail),
        }
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
@limiter.limit("5/hour")
async def create_scan_endpoint(request: Request, scan_request: ScanRequest):
    """Inicia um novo scan de segurança (limitado a 5/hora por IP)"""
    scan_id = str(uuid.uuid4())[:8]
    await create_scan(scan_id, str(scan_request.url), scan_request.scan_type.value)

    time_map = {"quick": 30, "full": 180, "aggressive": 600}
    estimated_time = time_map.get(scan_request.scan_type.value, 60)

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

    # Calcula progresso baseado em tempo decorrido vs tempo estimado
    progress = 0
    estimated_time_map = {"quick": 30, "full": 180, "aggressive": 600}
    estimated_time = estimated_time_map.get(scan["scan_type"], 60)

    if status == "pending":
        progress = 0
    elif status == "running":
        # Calcula % baseado no tempo decorrido desde started_at
        from datetime import datetime as dt
        started = dt.fromisoformat(scan["started_at"])
        elapsed = (dt.utcnow() - started).total_seconds()
        progress = min(95, int((elapsed / estimated_time) * 100))
    elif status == "completed":
        progress = 100
    elif status == "failed":
        progress = 0

    return {
        "scan_id": scan_id,
        "status": status,
        "url": scan["url"],
        "progress": progress,
        "started_at": scan["started_at"],
        "estimated_time_seconds": estimated_time
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


@app.get("/api/scan/{scan_id}/pdf")
async def get_scan_pdf(scan_id: str):
    """Gera e retorna o PDF do relatório"""
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

    scan_data = {
        "scan_id": scan_id,
        "url": scan["url"],
        "score": scan["score"],
        "classification": summary.get("classification"),
        "duration_seconds": scan["duration_seconds"] or 0,
        "summary": summary,
        "technologies": technologies,
        "security_headers": security_headers,
        "findings": findings,
    }

    try:
        pdf_bytes = generate_pdf(scan_data)
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Erro ao gerar PDF: {str(e)}")

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="nightfall-{scan_id}.pdf"'
        }
    )


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
