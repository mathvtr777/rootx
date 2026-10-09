"""
Motor de Scan - Orquestra todas as ferramentas
"""
import asyncio
import httpx
import re
from datetime import datetime
from typing import List, Optional
from .models import (
    Finding, Technology, SecurityHeaders, Severity,
    ScanResult, ScanType
)
from . import nuclei


class SecurityScanner:
    """Motor de scan de segurança"""

    # Headers de segurança importantes
    SECURITY_HEADERS = {
        "x-frame-options": ["DENY", "SAMEORIGIN"],
        "x-content-type-options": ["nosniff"],
        "strict-transport-security": None,  # só verifica se existe
        "content-security-policy": None,
        "x-xss-protection": None,
        "referrer-policy": None,
        "permissions-policy": None,
    }

    # Headers que revelam tecnologia
    TECH_HEADERS = {
        "server": None,
        "x-powered-by": None,
        "x-aspnet-version": None,
        "x-aspnetmvc-version": None,
    }

    # Padrões para detectar tecnologias
    TECH_PATTERNS = [
        (r"wp-content", "WordPress"),
        (r"wp-includes", "WordPress"),
        (r"_nuxt/", "Nuxt.js"),
        (r"__NEXT_DATA__", "Next.js"),
        (r"react", "React"),
        (r"gatsby", "Gatsby"),
        (r"vue", "Vue.js"),
        (r"angular", "Angular"),
        (r"laravel", "Laravel"),
        (r"django", "Django"),
        (r"flask", "Flask"),
        (r"express", "Express.js"),
        (r"node", "Node.js"),
        (r"php", "PHP"),
        (r"\.php", "PHP"),
        (r"jQuery", "jQuery"),
        (r"bootstrap", "Bootstrap"),
        (r"webpack", "Webpack"),
        (r"gtm-", "Google Tag Manager"),
        (r"shopify", "Shopify"),
        (r"woocommerce", "WooCommerce"),
    ]

    # Padrões para detectar secrets expostos
    SECRET_PATTERNS = [
        (r"(?i)api[_-]?key\s*[=:]\s*['\"]?[\w\-]{20,}", "API Key exposta"),
        (r"(?i)secret[_-]?key\s*[=:]\s*['\"]?[\w\-]{20,}", "Secret Key exposta"),
        (r"(?i)password\s*[=:]\s*['\"]?[^\s'\"]{8,}", "Password hardcoded"),
        (r"sk-[a-zA-Z0-9]{20,}", "Chave secreta (Stripe/OpenAI/etc)"),
        (r"AKIA[0-9A-Z]{16}", "AWS Access Key"),
        (r"(?i)bearer\s+[a-zA-Z0-9\-._~+/]+=*", "Bearer Token"),
        (r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----", "Chave privada exposta"),
    ]

    def __init__(self, timeout: int = 30):
        self.timeout = timeout
        self.client = httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=True,
            headers={
                "User-Agent": "ROOTX-Security-Scanner/1.0 (https://rootx.security)"
            }
        )

    async def close(self):
        """Fecha o cliente HTTP"""
        await self.client.aclose()

    async def scan(self, url: str, scan_type: ScanType = ScanType.QUICK) -> ScanResult:
        """
        Executa scan completo

        Args:
            url: URL para escanear
            scan_type: Tipo de scan

        Returns:
            ScanResult com todos os achados
        """
        start_time = datetime.utcnow()
        findings: List[Finding] = []
        technologies: List[Technology] = []

        try:
            # 1. Fazer request inicial
            response = await self.client.get(url)
            html_content = response.text
            headers = {k.lower(): v for k, v in response.headers.items()}
            final_url = str(response.url)

            # 2. Analisar headers de segurança
            security_headers = self._analyze_security_headers(headers)
            findings.extend(self._security_headers_findings(security_headers))

            # 3. Detectar tecnologias
            technologies = self._detect_technologies(html_content, headers)

            # 4. Procurar secrets expostos no HTML
            findings.extend(self._find_secrets(html_content, url))

            # 5. Verificar páginas comuns
            findings.extend(await self._check_common_issues(final_url))

            # 6. Rodar Nuclei (se instalado)
            if nuclei.check_nuclei_installed():
                timeout_map = {
                    ScanType.QUICK: 60,
                    ScanType.FULL: 180,
                    ScanType.AGGRESSIVE: 600
                }
                nuclei_findings = nuclei.run_nuclei_scan(
                    final_url,
                    scan_type.value,
                    timeout_map.get(scan_type, 60)
                )
                for nf in nuclei_findings:
                    findings.append(Finding(
                        name=nf["name"],
                        severity=Severity(nf["severity"]),
                        description=nf["description"],
                        location=nf["location"],
                        recommendation=nf["recommendation"],
                        cve_id=nf.get("cve_id"),
                        cvss=nf.get("cvss")
                    ))

        except httpx.TimeoutException:
            pass
        except Exception as e:
            print(f"Erro no scan: {e}")

        # Calcular score
        score = self._calculate_score(findings)

        # Calcular duração
        end_time = datetime.utcnow()
        duration = (end_time - start_time).total_seconds()

        return ScanResult(
            scan_id="",  # Será preenchido depois
            url=url,
            status=ScanResult.model_fields["status"].default,
            started_at=start_time,
            completed_at=end_time,
            duration_seconds=duration,
            findings=findings,
            technologies=technologies,
            security_headers=security_headers,
            score=score,
            summary=self._generate_summary(findings, score)
        )

    def _analyze_security_headers(self, headers: dict) -> SecurityHeaders:
        """Analisa headers de segurança"""
        return SecurityHeaders(
            x_frame_options=headers.get("x-frame-options", "").upper() in ["DENY", "SAMEORIGIN"],
            x_content_type_options=headers.get("x-content-type-options", "").lower() == "nosniff",
            strict_transport_security="strict-transport-security" in headers,
            content_security_policy="content-security-policy" in headers,
            x_xss_protection=headers.get("x-xss-protection", "").strip() != "",
            referrer_policy="referrer-policy" in headers,
            permissions_policy="permissions-policy" in headers,
        )

    def _security_headers_findings(self, headers: SecurityHeaders) -> List[Finding]:
        """Gera findings sobre headers faltando"""
        findings = []

        if not headers.x_frame_options:
            findings.append(Finding(
                name="X-Frame-Options Faltando",
                severity=Severity.MEDIUM,
                description="O header X-Frame-Options não está configurado. Isso permite que o site seja embedado em iframes, facilitando ataques de clickjacking.",
                location="HTTP Headers",
                recommendation="Adicione o header 'X-Frame-Options: DENY' ou 'X-Frame-Options: SAMEORIGIN' para prevenir clickjacking."
            ))

        if not headers.x_content_type_options:
            findings.append(Finding(
                name="X-Content-Type-Options Faltando",
                severity=Severity.LOW,
                description="O header X-Content-Type-Options não está configurado. Navegadores podem fazer MIME-type sniffing.",
                location="HTTP Headers",
                recommendation="Adicione o header 'X-Content-Type-Options: nosniff'."
            ))

        if not headers.strict_transport_security:
            findings.append(Finding(
                name="HSTS Não Configurado",
                severity=Severity.MEDIUM,
                description="Strict-Transport-Security não está habilitado. Conexões podem usar HTTP antes de redirecionar para HTTPS.",
                location="HTTP Headers",
                recommendation="Adicione o header 'Strict-Transport-Security: max-age=31536000; includeSubDomains'."
            ))

        if not headers.content_security_policy:
            findings.append(Finding(
                name="Content-Security-Policy Faltando",
                severity=Severity.MEDIUM,
                description="CSP não está definido. O site é mais vulnerável a XSS e injection attacks.",
                location="HTTP Headers",
                recommendation="Implemente uma Content-Security-Policy apropriada para seu site."
            ))

        return findings

    def _detect_technologies(self, html: str, headers: dict) -> List[Technology]:
        """Detecta tecnologias usadas no site"""
        technologies = []
        detected = set()

        # Checar headers
        for header_name, tech_name in self.TECH_HEADERS.items():
            if header_name in headers:
                value = headers[header_name]
                # Extrair versão se possível
                version_match = re.search(r"[\d]+\.[\d]+(?:\.[\d]+)?", value)
                version = version_match.group(0) if version_match else None
                tech = Technology(
                    name=value.split("/")[0] if "/" in value else value,
                    version=version,
                    confidence="high"
                )
                if tech.name.lower() not in [t.name.lower() for t in technologies]:
                    technologies.append(tech)

        # Checar padrões no HTML
        for pattern, tech_name in self.TECH_PATTERNS:
            if re.search(pattern, html, re.IGNORECASE) and tech_name not in detected:
                detected.add(tech_name)
                technologies.append(Technology(name=tech_name, confidence="high"))

        return technologies

    def _find_secrets(self, html: str, url: str) -> List[Finding]:
        """Procura secrets expostos no HTML"""
        findings = []

        for pattern, description in self.SECRET_PATTERNS:
            matches = re.finditer(pattern, html, re.IGNORECASE)
            for match in matches:
                findings.append(Finding(
                    name=f"Secret Exposto: {description}",
                    severity=Severity.CRITICAL,
                    description=f"Possível {description.lower()} encontrada no código fonte.",
                    location=f"{url} - HTML Source",
                    recommendation="Remova imediatamente credenciais hardcoded. Use variáveis de ambiente ou secrets managers.",
                    cve_id=None,
                    cvss=9.1
                ))

        return findings

    async def _check_common_issues(self, url: str) -> List[Finding]:
        """Verifica problemas comuns"""
        findings = []
        base_url = url.rstrip("/")

        common_paths = [
            ("/admin", "Painel Administrativo Exposto"),
            ("/wp-login.php", "Login WordPress Exposto"),
            ("/phpmyadmin", "phpMyAdmin Exposto"),
            ("/admin/login", "Login Admin Exposto"),
            ("/.env", "Arquivo .env Acessível"),
            ("/config.php", "Arquivo de Configuração Exposto"),
            ("/api/", "API Exposta"),
            ("/debug", "Modo Debug Ativado"),
            ("/swagger", "Swagger UI Exposto"),
            ("/swagger-ui", "Swagger UI Exposto"),
        ]

        tasks = []
        for path, name in common_paths:
            tasks.append(self._check_path(f"{base_url}{path}", name))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for result in results:
            if result:
                findings.append(result)

        return findings

    async def _check_path(self, url: str, name: str) -> Optional[Finding]:
        """Verifica se um path existe e está acessível"""
        try:
            response = await self.client.get(url, timeout=5)
            if response.status_code == 200:
                return Finding(
                    name=name,
                    severity=Severity.HIGH,
                    description=f"{name} encontrado em {url}.Isso pode ser explorado por atacantes.",
                    location=url,
                    recommendation="Restrinja o acesso a esta URL ou remova se não necessário."
                )
        except:
            pass
        return None

    def _calculate_score(self, findings: List[Finding]) -> int:
        """Calcula score de segurança (0-100)"""
        if not findings:
            return 100

        deductions = {
            Severity.CRITICAL: 25,
            Severity.HIGH: 15,
            Severity.MEDIUM: 8,
            Severity.LOW: 3,
            Severity.INFO: 1,
        }

        total_deduction = sum(deductions.get(f.severity, 1) for f in findings)
        score = max(0, 100 - total_deduction)

        return score

    def _generate_summary(self, findings: List[Finding], score: int) -> dict:
        """Gera sumário do scan"""
        severity_counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }

        for f in findings:
            severity_counts[f.severity.value] += 1

        # Classificação baseada no score
        if score >= 90:
            classification = "Excelente"
        elif score >= 70:
            classification = "Bom"
        elif score >= 50:
            classification = "Atenção"
        elif score >= 25:
            classification = "Crítico"
        else:
            classification = "Muito Crítico"

        return {
            "classification": classification,
            "severity_counts": severity_counts,
            "total_findings": len(findings),
            "risk_level": "high" if severity_counts["critical"] > 0 or severity_counts["high"] > 2 else "medium" if severity_counts["medium"] > 0 else "low"
        }
