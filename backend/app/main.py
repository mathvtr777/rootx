"""
ROOTX - API Principal
"""
import asyncio
import uuid
import json
from datetime import datetime
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, BackgroundTasks, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from .models import ScanRequest, ScanResponse, ScanStatus, ScanResult, Finding
from .database import init_db, create_scan, update_scan_status, save_scan_results, get_scan, get_all_scans
from .scanner import SecurityScanner
from .analyzer import generate_markdown_report, generate_json_report

# Configuração
BASE_DIR = Path(__file__).parent.parent.parent
BACKEND_DIR = Path(__file__).parent.parent

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

# Estado
scanner_tasks = {}


@app.on_event("startup")
async def startup():
    """Inicializa banco de dados"""
    await init_db()


@app.get("/api/health")
async def health():
    """Health check"""
    return {"status": "ok", "service": "ROOTX", "version": "1.0.0"}


@app.post("/api/scan", response_model=ScanResponse)
async def create_scan_endpoint(request: ScanRequest):
    """
    Inicia um novo scan de segurança
    """
    # Gerar ID único
    scan_id = str(uuid.uuid4())[:8]

    # Criar registro no banco
    await create_scan(scan_id, str(request.url), request.scan_type.value)

    # Estimar tempo baseado no tipo
    time_map = {
        "quick": 30,
        "full": 180,
        "aggressive": 600
    }
    estimated_time = time_map.get(request.scan_type.value, 60)

    return ScanResponse(
        scan_id=scan_id,
        status=ScanStatus.PENDING,
        message=f"Scan iniciado. ID: {scan_id}",
        estimated_time_seconds=estimated_time
    )


@app.get("/api/scan/{scan_id}")
async def get_scan_status(scan_id: str):
    """
    Verifica status de um scan
    """
    scan = await get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan não encontrado")

    # Calcular progresso
    status = scan["status"]
    if status == "pending":
        progress = 0
    elif status == "running":
        progress = 50
    else:
        progress = 100

    return {
        "scan_id": scan_id,
        "status": status,
        "url": scan["url"],
        "progress": progress,
        "started_at": scan["started_at"]
    }


@app.post("/api/scan/{scan_id}/run")
async def run_scan(scan_id: str, background_tasks: BackgroundTasks):
    """
    Executa o scan (endpoint separado para evitar timeout)
    """
    scan = await get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan não encontrado")

    if scan["status"] not in ["pending", "failed"]:
        return {"message": "Scan já executado", "status": scan["status"]}

    # Atualizar status
    await update_scan_status(scan_id, ScanStatus.RUNNING)

    # Executar scan em background
    background_tasks.add_task(execute_scan, scan_id, scan["url"], scan["scan_type"])

    return {"message": "Scan em execução", "status": "running"}


async def execute_scan(scan_id: str, url: str, scan_type: str):
    """
    Executa o scan completo
    """
    try:
        scanner = SecurityScanner()

        # Mapear tipo de scan
        from .models import ScanType
        scan_type_enum = ScanType(scan_type)

        # Executar scan
        result = await scanner.scan(url, scan_type_enum)
        await scanner.close()

        # Atualizar result com ID e status
        result.scan_id = scan_id
        result.status = ScanStatus.COMPLETED
        result.completed_at = datetime.utcnow()

        # Salvar resultados
        await save_scan_results(scan_id, result)

        print(f"[ROOTX] Scan {scan_id} completo - Score: {result.score}")

    except Exception as e:
        print(f"[ROOTX] Erro no scan {scan_id}: {e}")
        await update_scan_status(scan_id, ScanStatus.FAILED)


@app.get("/api/scan/{scan_id}/report")
async def get_scan_report(scan_id: str, format: str = "json"):
    """
    Retorna relatório do scan
    """
    scan = await get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan não encontrado")

    if scan["status"] != "completed":
        raise HTTPException(
            status_code=400,
            detail=f"Scan ainda não completo. Status: {scan['status']}"
        )

    # Reconstruir objetos
    findings = json.loads(scan["findings_json"]) if scan["findings_json"] else []
    technologies = json.loads(scan["technologies_json"]) if scan["technologies_json"] else []
    security_headers = json.loads(scan["security_headers_json"]) if scan["security_headers_json"] else {}
    summary = json.loads(scan["summary_json"]) if scan["summary_json"] else {}

    summary["timestamp"] = scan["completed_at"]

    if format == "markdown":
        duration = scan["duration_seconds"] or 0
        report = generate_markdown_report(
            scan["url"],
            scan["score"],
            findings,
            summary,
            technologies,
            security_headers,
            duration
        )
        return HTMLResponse(content=report)

    return generate_json_report(
        scan["url"],
        scan["score"],
        findings,
        summary,
        technologies,
        security_headers,
        scan["duration_seconds"] or 0
    )


@app.get("/api/scans")
async def list_scans():
    """
    Lista todos os scans
    """
    scans = await get_all_scans()
    return {"scans": scans, "total": len(scans)}


# === FRONTEND ===

@app.get("/")
async def root():
    """Página principal"""
    return FileResponse(str(BASE_DIR / "frontend" / "index.html"))


@app.get("/scan")
async def scan_page():
    """Página de scan"""
    return FileResponse(str(BASE_DIR / "frontend" / "scan.html"))


@app.get("/report/{scan_id}")
async def report_page(scan_id: str):
    """Página de relatório"""
    return FileResponse(str(BASE_DIR / "frontend" / "report.html"))


# === STATIC FILES ===
# Servir arquivos estáticos seexistirem
static_dir = BASE_DIR / "frontend"
if static_dir.exists():
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
