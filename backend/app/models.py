"""
Modelos Pydantic para o ROOTX
"""
from pydantic import BaseModel, HttpUrl, Field
from typing import Optional, List
from datetime import datetime
from enum import Enum


class ScanType(str, Enum):
    QUICK = "quick"           # 30 segundos
    FULL = "full"             # 5 minutos
    AGGRESSIVE = "aggressive" # 15 minutos


class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class ScanRequest(BaseModel):
    url: HttpUrl = Field(..., description="URL para escanear")
    scan_type: ScanType = Field(default=ScanType.QUICK)


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Finding(BaseModel):
    name: str
    severity: Severity
    description: str
    location: str
    recommendation: str
    cve_id: Optional[str] = None
    cvss: Optional[float] = None


class Technology(BaseModel):
    name: str
    version: Optional[str] = None
    confidence: str = "high"


class SecurityHeaders(BaseModel):
    x_frame_options: bool = False
    x_content_type_options: bool = False
    strict_transport_security: bool = False
    content_security_policy: bool = False
    x_xss_protection: bool = False
    referrer_policy: bool = False
    permissions_policy: bool = False


class ScanResult(BaseModel):
    scan_id: str
    url: str
    status: ScanStatus
    started_at: datetime
    completed_at: Optional[datetime] = None
    duration_seconds: Optional[float] = None
    findings: List[Finding] = []
    technologies: List[Technology] = []
    security_headers: SecurityHeaders = SecurityHeaders()
    score: int = Field(ge=0, le=100, default=100)
    summary: dict = {}


class ScanResponse(BaseModel):
    scan_id: str
    status: ScanStatus
    message: str
    estimated_time_seconds: int


class ReportResponse(BaseModel):
    scan_id: str
    url: str
    score: int
    severity_counts: dict
    findings: List[Finding]
    summary: str
    recommendations: List[str]
