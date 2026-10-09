"""
Motor de Scan - Orquestra todas as ferramentas
"""
import asyncio
import httpx
import re
from datetime import datetime
from typing import List
from .models import Finding, Technology, SecurityHeaders, Severity, ScanResult, ScanType
from .extended import ExtendedScanner


class SecurityScanner:
    """Motor de scan de segurança completo"""

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
        (r"stripe", "Stripe"),
        (r"razorpay", "Razorpay"),
        (r"firebase", "Firebase"),
        (r"supabase", "Supabase"),
    ]

    # Padrões para detectar secrets expostos
    SECRET_PATTERNS = [
        (r"(?i)api[_-]?key\s*[=:]\s*['\"]?[\w\-]{20,}", "API Key exposta"),
        (r"(?i)secret[_-]?key\s*[=:]\s*['\"]?[\w\-]{20,}", "Secret Key exposta"),
        (r"sk-[a-zA-Z0-9]{20,}", "Chave secreta (Stripe/OpenAI/etc)"),
        (r"AKIA[0-9A-Z]{16}", "AWS Access Key"),
        (r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----", "Chave privada exposta"),
        (r"ghp_[a-zA-Z0-9]{36}", "GitHub Personal Access Token"),
        (r"xox[baprs]-[a-zA-Z0-9]{10,}", "Slack Token"),
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
        self.extended = ExtendedScanner(timeout=10)

    async def close(self):
        """Fecha os clientes HTTP"""
        await self.client.aclose()
        await self.extended.close()

    async def scan(self, url: str, scan_type: ScanType = ScanType.QUICK) -> ScanResult:
        """
        Executa scan completo
        """
        start_time = datetime.utcnow()
        findings: List[Finding] = []
        technologies: List[Technology] = []

        try:
            # 1. Request inicial
            response = await self.client.get(url)
            html_content = response.text
            headers = {k.lower(): v for k, v in response.headers.items()}
            final_url = str(response.url)

            # 2. Análise de headers de segurança
            security_headers = self._analyze_security_headers(headers)
            findings.extend(self._security_headers_findings(security_headers))

            # 3. Detectar tecnologias
            technologies = self._detect_technologies(html_content, headers)

            # 4. Procurar secrets no HTML
            findings.extend(self._find_secrets(html_content, url))

            # 5. Verificações básicas
            findings.extend(await self._check_common_issues(final_url))

            # 6. Verificações estendidas (baseado no tipo de scan)
            if scan_type in [ScanType.FULL, ScanType.AGGRESSIVE]:
                findings.extend(await self.extended.check_subdomains(final_url))
                findings.extend(await self.extended.check_robots_sitemap(final_url))
                findings.extend(await self.extended.check_security_txt(final_url))
                findings.extend(await self.extended.check_cookie_security(final_url))
                findings.extend(await self.extended.check_graphql(final_url))
                findings.extend(await self.extended.check_cors(final_url))
                findings.extend(await self.extended.check_api_endpoints(final_url))
                findings.extend(await self.extended.check_missing_headers(final_url))
                findings.extend(await self.extended.check_cloud_metadata(final_url))

            if scan_type == ScanType.AGGRESSIVE:
                findings.extend(await self.extended.check_debug_mode(final_url))

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
                recommendation="Adicione o header 'X-Frame-Options: DENY' ou 'X-Frame-Options: SAMEORIGIN'."
            ))

        if not headers.x_content_type_options:
            findings.append(Finding(
                name="X-Content-Type-Options Faltando",
                severity=Severity.LOW,
                description="O header X-Content-Type-Options não está configurado.",
                location="HTTP Headers",
                recommendation="Adicione o header 'X-Content-Type-Options: nosniff'."
            ))

        if not headers.strict_transport_security:
            findings.append(Finding(
                name="HSTS Não Configurado",
                severity=Severity.MEDIUM,
                description="Strict-Transport-Security não está habilitado.",
                location="HTTP Headers",
                recommendation="Adicione o header 'Strict-Transport-Security: max-age=31536000; includeSubDomains'."
            ))

        if not headers.content_security_policy:
            findings.append(Finding(
                name="Content-Security-Policy Faltando",
                severity=Severity.MEDIUM,
                description="CSP não está definido. O site é mais vulnerável a XSS.",
                location="HTTP Headers",
                recommendation="Implemente uma Content-Security-Policy apropriada."
            ))

        return findings

    def _detect_technologies(self, html: str, headers: dict) -> List[Technology]:
        """Detecta tecnologias usadas"""
        technologies = []
        detected = set()

        # Headers de servidor
        if "server" in headers:
            technologies.append(Technology(name=headers["server"], confidence="medium"))

        if "x-powered-by" in headers:
            tech = Technology(name=headers["x-powered-by"], confidence="high")
            if tech.name not in [t.name for t in technologies]:
                technologies.append(tech)

        # Padrões no HTML
        for pattern, tech_name in self.TECH_PATTERNS:
            if re.search(pattern, html, re.IGNORECASE) and tech_name not in detected:
                detected.add(tech_name)
                technologies.append(Technology(name=tech_name, confidence="high"))

        return technologies

    def _find_secrets(self, html: str, url: str) -> List[Finding]:
        """Procura secrets expostos"""
        findings = []

        for pattern, description in self.SECRET_PATTERNS:
            matches = re.finditer(pattern, html, re.IGNORECASE)
            for match in matches:
                matched = match.group(0)
                if "example" in matched.lower() or "your_" in matched.lower():
                    continue

                findings.append(Finding(
                    name=f"Secret Exposto: {description}",
                    severity=Severity.CRITICAL,
                    description=f"Possível {description.lower()} encontrada no código fonte.",
                    location=f"{url} - HTML Source",
                    recommendation="Remova imediatamente credenciais hardcoded.",
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
            ("/console", "Console Exposto"),
            ("/backup", "Backup Exposto"),
            ("/.git", "Diretório .git Exposto"),
            ("/.hg", "Diretório .hg Exposto"),
            ("/server-status", "Apache Server Status Exposto"),
            ("/status", "Status Page Exposto"),
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
                        recommendation="Restrinja o acesso a esta URL."
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
