"""
Análise de resultados e geração de relatório
"""
from typing import List
from .models import Finding, Severity


def generate_markdown_report(
    url: str,
    score: int,
    findings: List[Finding],
    summary: dict,
    technologies: List[dict],
    security_headers: dict,
    duration_seconds: float
) -> str:
    """Gera relatório em Markdown"""

    severity_icons = {
        "critical": "🔴",
        "high": "🟠",
        "medium": "🟡",
        "low": "🔵",
        "info": "⚪"
    }

    severity_counts = summary.get("severity_counts", {})

    report = f"""# 🔒 ROOTX - Relatório de Segurança

## Informações Gerais

| Campo | Valor |
|-------|-------|
| **URL** | {url} |
| **Score** | {score}/100 |
| **Classificação** | {summary.get('classification', 'N/A')} |
| **Duração** | {duration_seconds:.1f}s |
| **Data** | {summary.get('timestamp', 'N/A')} |

---

## 📊 Resumo

### Distribuição de Vulnerabilidades

| Severidade | Quantidade |
|------------|------------|
| 🔴 Crítica | {severity_counts.get('critical', 0)} |
| 🟠 Alta | {severity_counts.get('high', 0)} |
| 🟡 Média | {severity_counts.get('medium', 0)} |
| 🔵 Baixa | {severity_counts.get('low', 0)} |
| ⚪ Info | {severity_counts.get('info', 0)} |

### Tecnologias Detectadas

"""

    if technologies:
        for tech in technologies:
            version = f" v{tech.get('version', '')}" if tech.get('version') else ""
            report += f"- **{tech.get('name', 'Unknown')}**{version}\n"
    else:
        report += "_Nenhuma tecnologia detectada_\n"

    report += f"\n---\n\n## 🔍 Headers de Segurança\n\n"

    header_checks = [
        ("X-Frame-Options", security_headers.get("x_frame_options")),
        ("X-Content-Type-Options", security_headers.get("x_content_type_options")),
        ("Strict-Transport-Security", security_headers.get("strict_transport_security")),
        ("Content-Security-Policy", security_headers.get("content_security_policy")),
        ("X-XSS-Protection", security_headers.get("x_xss_protection")),
        ("Referrer-Policy", security_headers.get("referrer_policy")),
        ("Permissions-Policy", security_headers.get("permissions_policy")),
    ]

    for header, present in header_checks:
        status = "✅" if present else "❌"
        report += f"| {status} | {header} |\n"

    report += f"\n---\n\n## ⚠️ Vulnerabilidades Encontradas\n\n"

    if not findings:
        report += "_🎉 Nenhuma vulnerabilidade encontrada!_\n\n"
    else:
        # Ordenar por severidade
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_findings = sorted(
            findings,
            key=lambda x: severity_order.get(x.get("severity", "info"), 5)
        )

        for i, finding in enumerate(sorted_findings, 1):
            severity = finding.get("severity", "info")
            icon = severity_icons.get(severity, "⚪")

            report += f"""### {icon} {i}. {finding.get('name', 'Vulnerabilidade Desconhecida')}

**Severidade:** {severity.upper()}
**Local:** `{finding.get('location', 'N/A')}`

{finding.get('description', 'Sem descrição')}

**Recomendação:** {finding.get('recommendation', 'Revise e corrija esta vulnerabilidade.')}

"""

            if finding.get("cve_id"):
                report += f"> 🏷️ **CVE:** {finding['cve_id']}"
                if finding.get("cvss"):
                    report += f" (CVSS: {finding['cvss']})"
                report += "\n"

            report += "---\n\n"

    report += f"""## 📋 Próximos Passos

1. **Imediato:** Corrija todas as vulnerabilidades críticas e altas
2. **Curto prazo:** Implemente os headers de segurança faltando
3. **Médio prazo:** Atualize tecnologias com vulnerabilidades conhecidas
4. **Contínuo:** Realize scans regulares para manter a segurança

---

_🔒 Gerado por ROOTX - Scanner de Segurança Web_
_Este relatório é apenas informativo e não substitui um pentest profissional._
"""

    return report


def generate_json_report(
    url: str,
    score: int,
    findings: List[Finding],
    summary: dict,
    technologies: List[dict],
    security_headers: dict,
    duration_seconds: float
) -> dict:
    """Gera relatório em JSON"""
    return {
        "report_url": url,
        "score": score,
        "classification": summary.get("classification"),
        "duration_seconds": duration_seconds,
        "summary": {
            "total_findings": len(findings),
            "severity_counts": summary.get("severity_counts", {}),
            "risk_level": summary.get("risk_level", "unknown")
        },
        "technologies": technologies,
        "security_headers": security_headers,
        "findings": findings,
        "recommendations": generate_recommendations_list(findings)
    }


def generate_recommendations_list(findings: List[Finding]) -> List[str]:
    """Extrai lista de recomendações únicas"""
    recommendations = []
    seen = set()

    for finding in findings:
        rec = finding.get("recommendation", "")
        # Pegar primeira frase
        first_sentence = rec.split(".")[0] if "." in rec else rec
        if first_sentence and first_sentence not in seen:
            seen.add(first_sentence)
            recommendations.append(first_sentence + ".")

    return recommendations


def calculate_risk_distribution(findings: List[Finding]) -> dict:
    """Calcula distribuição de risco"""
    total = len(findings)
    if total == 0:
        return {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = f.get("severity", "info")
        if sev in counts:
            counts[sev] += 1

    # Converter para porcentagem
    return {k: round((v / total) * 100, 1) for k, v in counts.items()}
