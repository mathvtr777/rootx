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


class SecurityScanner:
    """Motor de scan de segurança"""

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
        (r"sk-[a-zA-Z0-9]{20,}", "Chave secreta (Stripe/OpenAI/etc)"),
        (r"AKIA[0-9A-Z]{16}", "AWS Access Key"),
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

        except httpx.TimeoutException:
            findings.append(Finding(
                name="Timeout na conexão",
                severity=Severity.MEDIUM,
                description=f"Não foi possível completar a requisição em {self.timeout} segundos.",
                location=url,
                recommendation="Verifique se o site está acessível."
            ))
        except Exception as e:
            findings.append(Finding(
                name="Erro no scan",
                severity=Severity.MEDIUM,
                description=f"Erro ao escanear: {str(e)}",
                location=url,
                recommendation="Verifique se a URL está correta e o site está acessível."
            ))

        # Calcular score
        score = self._calculate_score(findings)

        # Calcular duração
        end_time = datetime.utcnow()
        duration = (end_time - start_time).total_seconds()

        return ScanResult(
            scan_id="",
            url=url,
            status="completed",
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

        # Checar headers de servidor
        if "server" in headers:
            server = headers["server"]
            technologies.append(Technology(name=server, confidence="medium"))

        if "x-powered-by" in headers:
            tech = Technology(name=headers["x-powered-by"], confidence="high")
            if tech.name not in [t.name for t in technologies]:
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
                # Não reportar falsos positivos comuns
                matched = match.group(0)
                if "example" in matched.lower() or "your_" in matched.lower():
                    continue

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
            ("/debug", "Modo Debug Ativado"),
            ("/swagger", "Swagger UI Exposto"),
        ]

        for path, name in common_paths:
            try:
                resp = await self.client.get(f"{base_url}{path}", timeout=5)
                if resp.status_code == 200:
                    findings.append(Finding(
                        name=name,
                        severity=Severity.HIGH,
                        description=f"{name} encontrado em {base_url}{path}.",
                        location=f"{base_url}{path}",
                        recommendation="Restrinja o acesso a esta URL ou remova se não necessário."
                    ))
            except:
                pass

        return findings

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
        return max(0, 100 - total_deduction)

    def _generate_summary(self, findings: List[Finding], score: int) -> dict:
        """Gera sumário do scan"""
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

        for f in findings:
            severity_counts[f.severity.value] += 1

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
