"""
Wrapper para o Nuclei Scanner
"""
import subprocess
import json
import re
from typing import List, Optional
from pathlib import Path

# Configuração
NUCLEI_PATH = "nuclei"
TEMPLATES_PATH = Path(__file__).parent.parent.parent / "nuclei-templates"

# Templates por severidade
TEMPLATE_CATEGORIES = {
    "critical": [
        "cves/2024/",
        "exposed-panels/",
        "exposures/",
        "vulnerabilities/",
    ],
    "high": [
        "security-misconfiguration/",
        "default-logins/",
        "subdomain-takeover/",
    ],
    "medium": [
        "technologies/",
        "miscellaneous/",
    ],
    "info": [
        "dns/",
        "helpers/",
    ]
}


def run_nuclei_scan(
    url: str,
    scan_type: str = "quick",
    timeout: int = 60
) -> List[dict]:
    """
    Executa scan com Nuclei

    Args:
        url: URL para escanear
        scan_type: quick, full, aggressive
        timeout: timeout em segundos

    Returns:
        Lista de vulnerabilidades encontradas
    """
    findings = []

    # Construir comandos baseado no tipo de scan
    if scan_type == "quick":
        # Só tecnologias e info
        templates = ["technologies/", "dns/"]
        rate_limit = 150
    elif scan_type == "full":
        # Tudo exceto aggressive
        templates = list(TEMPLATE_CATEGORIES.values())[:3]
        rate_limit = 100
    else:  # aggressive
        # Todos os templates
        templates = None  # usa default
        rate_limit = 50
        timeout = min(timeout * 2, 300)  # até 5 min

    # Montar comando
    cmd = [
        NUCLEI_PATH,
        "-u", url,
        "-json",  # Output JSON
        "-silent",
        "-rate-limit", str(rate_limit),
        "-timeout", str(timeout // 60),
        "-retries", "1",
    ]

    # Adicionar templates específicos se definidos
    if templates:
        templates_path = str(TEMPLATES_PATH)
        cmd.extend(["-t", f"{templates_path}/technologies/"])
        cmd.extend(["-t", f"{templates_path}/exposed-panels/"])
        cmd.extend(["-t", f"{templates_path}/exposures/config/"])

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout + 10,
            cwd=str(Path(__file__).parent.parent)
        )

        # Parsear output JSON do Nuclei
        for line in result.stdout.strip().split("\n"):
            if not line:
                continue
            try:
                finding = json.loads(line)
                findings.append(parse_nuclei_finding(finding))
            except json.JSONDecodeError:
                continue

    except subprocess.TimeoutExpired:
        pass  # Timeout é ok, retorna o que encontrou
    except FileNotFoundError:
        # Nuclei não instalado, retorna vazio
        return []
    except Exception as e:
        print(f"Erro no Nuclei: {e}")

    return findings


def parse_nuclei_finding(raw: dict) -> dict:
    """Converte output do Nuclei para formato ROOTX"""
    # Extrair severidade
    info = raw.get("info", {})
    severity = info.get("severity", "info")
    severity = severity.lower()

    # Mapear severidade
    severity_map = {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "low": "low",
        "info": "info",
        "unknown": "info"
    }
    severity = severity_map.get(severity, "info")

    # Extrair CVE se existir
    cve_id = None
    classification = info.get("classification", {})
    if "cve" in classification:
        cve_id = classification["cve"]
    elif "cve-id" in info:
        cve_id = info["cve-id"]

    # Extrair CVSS
    cvss = None
    if "cvss-metrics" in info:
        try:
            cvss = float(info["cvss-metrics"].split("/")[0])
        except:
            pass

    return {
        "name": info.get("name", "Vulnerabilidade"),
        "severity": severity,
        "description": info.get("description", "")[:500],
        "location": raw.get("matched-at", ""),
        "recommendation": generate_recommendation(info.get("name", ""), severity),
        "cve_id": cve_id,
        "cvss": cvss,
        "template": raw.get("template-id", ""),
        "extracted_results": raw.get("extracted-results", [])
    }


def generate_recommendation(vulnerability_name: str, severity: str) -> str:
    """Gera recomendação baseada no tipo de vulnerabilidade"""
    recommendations = {
        "critical": f"Atualize imediatamente. Esta vulnerabilidade pode comprometer todo o sistema.",
        "high": f"Revise a configuração e aplique correções de segurança o quanto antes.",
        "medium": f"Considere implementar melhores práticas de segurança.",
        "low": f"Melhoria opcional, mas recomendada para postura de segurança completa.",
        "info": f"Informação收集ada para documentação."
    }
    return recommendations.get(severity, "Revise e corrija conforme necessário.")


def check_nuclei_installed() -> bool:
    """Verifica se o Nuclei está instalado"""
    try:
        result = subprocess.run(
            [NUCLEI_PATH, "-version"],
            capture_output=True,
            text=True,
            timeout=5
        )
        return result.returncode == 0
    except:
        return False
