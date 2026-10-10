"""
Motor de Scan - Orquestra todas as ferramentas
"""
import asyncio
import httpx
import re
import time
from datetime import datetime
from typing import List, Optional
from .models import Finding, Technology, SecurityHeaders, Severity, ScanResult, ScanType
from .active_vuln_scanner import ActiveVulnScanner, FormDetector
from .credential_leak import CredentialLeakScanner, SecretScanner
from .ssl_analyzer import SSLAnalyzer
from .subdomain_enum import SubdomainEnumerator, DNSAnalyzer
from .port_scanner import PortScanner
from .waf_detector import WAFDetector
from .directory_enum import DirectoryEnumerator
from .crawler import WebCrawler


class SecurityScanner:
    """Motor de scan completo com 3 modos funcionais"""

    # Tempos estimados por modo (segundos)
    MODE_TIMES = {
        ScanType.QUICK: 30,
        ScanType.FULL: 180,
        ScanType.AGGRESSIVE: 600,
    }

    # Padrões para detectar tecnologias
    TECH_PATTERNS = [
        (r"wp-content|wp-includes", "WordPress"),
        (r"_nuxt/", "Nuxt.js"),
        (r"__NEXT_DATA__", "Next.js"),
        (r"gatsby", "Gatsby"),
        (r"VUE|vuejs|vue@", "Vue.js"),
        (r"angular", "Angular"),
        (r"react", "React"),
        (r"laravel|laravel_session", "Laravel"),
        (r"django", "Django"),
        (r"flask", "Flask"),
        (r"express", "Express.js"),
        (r"node", "Node.js"),
        (r"php|\.php", "PHP"),
        (r"jQuery", "jQuery"),
        (r"bootstrap", "Bootstrap"),
        (r"webpack", "Webpack"),
        (r"shopify", "Shopify"),
        (r"woocommerce", "WooCommerce"),
        (r"stripe", "Stripe"),
        (r"firebase", "Firebase"),
        (r"supabase", "Supabase"),
        (r"nextjs", "Next.js"),
    ]

    # Padrões para detectar secrets
    SECRET_PATTERNS = [
        (r"AKIA[0-9A-Z]{16}", "AWS Access Key"),
        (r"sk-[a-zA-Z0-9]{20,}", "Secret Key"),
        (r"ghp_[a-zA-Z0-9]{36}", "GitHub Token"),
        (r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----", "Private Key"),
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

        # Inicializa scanners
        self.active_scanner = ActiveVulnScanner(timeout=30)
        self.form_detector = FormDetector(timeout=30)
        self.credential_scanner = CredentialLeakScanner(timeout=60)
        self.secret_scanner = SecretScanner(timeout=60)
        self.ssl_analyzer = SSLAnalyzer(timeout=30)
        self.subdomain_enum = SubdomainEnumerator(timeout=60)
        self.dns_analyzer = DNSAnalyzer(timeout=30)
        self.port_scanner = PortScanner(timeout=2)
        self.waf_detector = WAFDetector(timeout=30)
        self.directory_enum = DirectoryEnumerator(timeout=60)
        self.crawler = WebCrawler(timeout=30, max_pages=20)

    async def close(self):
        """Fecha todos os clientes HTTP"""
        await self.client.aclose()
        await self.active_scanner.close()
        await self.form_detector.close()
        await self.credential_scanner.close()
        await self.secret_scanner.close()
        await self.ssl_analyzer.close()
        await self.subdomain_enum.close()
        await self.port_scanner.close()
        await self.waf_detector.close()
        await self.directory_enum.close()
        await self.crawler.close()

    async def scan(self, url: str, scan_type: ScanType = ScanType.QUICK) -> ScanResult:
        """
        Executa scan completo baseado no modo

        QUICK (30s): Recon + Enumeração básica
        FULL (3min): + Testes ativos (SQLi, XSS, RCE, LFI, SSTI, Login Bypass)
        AGGRESSIVE (10min): + Credential leaks + Full enum
        """
        start_time = time.time()
        findings: List[Finding] = []
        technologies: List[Technology] = []
        security_headers = SecurityHeaders()

        print(f"[ROOTX] Iniciando scan {scan_type.value} em {url}")

        try:
            # ==============================================
            # PHASE 1: DISCOVERY (todos os modos)
            # ==============================================
            print(f"[ROOTX] Phase 1: Discovery")
            response = await self.client.get(url, timeout=self.timeout)
            html_content = response.text
            headers = {k.lower(): v for k, v in response.headers.items()}
            final_url = str(response.url)

            # 1.1 SSL/TLS
            ssl_findings = await self.ssl_analyzer.analyze(url)
            findings.extend(ssl_findings)

            # 1.2 Headers de segurança
            security_headers = self._analyze_security_headers(headers)
            findings.extend(self._security_headers_findings(security_headers))

            # 1.3 Tecnologias
            technologies = self._detect_technologies(html_content, headers)

            # 1.4 Secrets no HTML
            findings.extend(await self._find_secrets(html_content, url))

            # 1.5 WAF Detection
            waf_findings = await self.waf_detector.detect(url, mode="quick")
            findings.extend(waf_findings)

            # 1.6 Missing headers
            findings.extend(self._check_info_leakage(headers))

            # ==============================================
            # PHASE 2: ENUMERATION (QUICK+)
            # ==============================================
            print(f"[ROOTX] Phase 2: Enumeration")

            # 2.1 Paths críticos expostos
            findings.extend(await self._check_common_paths(final_url))

            # 2.2 Directory enumeration
            if scan_type != ScanType.QUICK:
                mode = "full" if scan_type == ScanType.FULL else "aggressive"
                dir_findings = await self.directory_enum.enumerate(final_url, mode=mode)
                findings.extend(dir_findings)

            # 2.3 Crawling + forms
            crawl_results = await self.crawler.crawl(final_url)
            print(f"[ROOTX] Crawled {crawl_results['pages_crawled']} pages")

            # ==============================================
            # PHASE 3: DEEP ENUMERATION (FULL+)
            # ==============================================
            if scan_type in [ScanType.FULL, ScanType.AGGRESSIVE]:
                print(f"[ROOTX] Phase 3: Deep Enum")

                # 3.1 Subdomain enumeration
                sub_findings = await self.subdomain_enum.enumerate(final_url, mode="full")
                findings.extend(sub_findings)

                # 3.2 DNS Analysis
                dns_findings = await self.dns_analyzer.analyze(final_url)
                findings.extend(dns_findings)

                # 3.3 Port scanning (HTTP ports only)
                port_findings = await self.port_scanner.scan(final_url, mode="quick")
                findings.extend(port_findings)

                # 3.4 API endpoints
                api_findings = await self._find_api_endpoints(final_url, crawl_results)
                findings.extend(api_findings)

            # ==============================================
            # PHASE 4: ACTIVE VULNERABILITY TESTING (FULL+)
            # ==============================================
            if scan_type in [ScanType.FULL, ScanType.AGGRESSIVE]:
                print(f"[ROOTX] Phase 4: Active Testing")

                # Detecta forms
                forms = await self.form_detector.find_forms(final_url)

                # Testes ativos
                vuln_findings = await self.active_scanner.scan_all(final_url, forms)
                findings.extend(vuln_findings)

            # ==============================================
            # PHASE 5: CREDENTIAL LEAKS (AGGRESSIVE only)
            # ==============================================
            if scan_type == ScanType.AGGRESSIVE:
                print(f"[ROOTX] Phase 5: Credential Leaks")

                domain = urlparse(url).netloc
                if not domain.startswith('www.'):
                    domain = domain.split(':')[0]

                # Cred leaks
                leak_findings = await self.credential_scanner.scan_domain(domain)
                findings.extend(leak_findings)

                # Secrets em páginas crawladas
                for page_url in crawl_results.get('urls', [])[:10]:
                    try:
                        page_response = await self.client.get(page_url, timeout=10)
                        secrets = await self.secret_scanner.scan_content(
                            page_response.text, page_url
                        )
                        findings.extend(secrets)
                    except:
                        pass

                # Port scan mais agressivo
                aggressive_port_findings = await self.port_scanner.scan(final_url, mode="full")
                findings.extend(aggressive_port_findings)

            # Verifica se ainda tem tempo
            elapsed = time.time() - start_time
            print(f"[ROOTX] Elapsed: {elapsed:.1f}s")

        except httpx.TimeoutException:
            findings.append(Finding(
                name="Timeout na conexão",
                severity=Severity.MEDIUM,
                description=f"Timeout após {self.timeout}s",
                location=url,
                recommendation="Verifique se o site está acessível"
            ))
        except Exception as e:
            findings.append(Finding(
                name="Erro no scan",
                severity=Severity.MEDIUM,
                description=f"Erro: {str(e)}",
                location=url,
                recommendation="Verifique a URL e tente novamente"
            ))

        # Calcula score
        score = self._calculate_score(findings)

        # Duração
        end_time = time.time()
        duration = end_time - start_time

        print(f"[ROOTX] Scan concluído em {duration:.1f}s - {len(findings)} findings - Score: {score}")

        return ScanResult(
            scan_id="",
            url=url,
            status="completed",
            started_at=datetime.utcfromtimestamp(start_time),
            completed_at=datetime.utcfromtimestamp(end_time),
            duration_seconds=duration,
            findings=findings,
            technologies=technologies,
            security_headers=security_headers,
            score=score,
            summary=self._generate_summary(findings, score, scan_type)
        )

    # ==================== HELPERS ====================

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
                description="Clickjacking possível sem X-Frame-Options",
                location="HTTP Headers",
                recommendation="Adicione 'X-Frame-Options: DENY'"
            ))

        if not headers.x_content_type_options:
            findings.append(Finding(
                name="X-Content-Type-Options Faltando",
                severity=Severity.LOW,
                description="MIME sniffing pode ser explorado",
                location="HTTP Headers",
                recommendation="Adicione 'X-Content-Type-Options: nosniff'"
            ))

        if not headers.strict_transport_security:
            findings.append(Finding(
                name="HSTS Não Configurado",
                severity=Severity.MEDIUM,
                description="HTTP pode ser usado para ataques MITM",
                location="HTTP Headers",
                recommendation="Adicione HSTS com max-age de pelo menos 31536000"
            ))

        if not headers.content_security_policy:
            findings.append(Finding(
                name="Content-Security-Policy Faltando",
                severity=Severity.MEDIUM,
                description="CSP não definido - XSS mais fácil",
                location="HTTP Headers",
                recommendation="Implemente CSP restritiva"
            ))

        return findings

    def _detect_technologies(self, html: str, headers: dict) -> List[Technology]:
        """Detecta tecnologias"""
        technologies = []
        detected = set()

        if "server" in headers:
            technologies.append(Technology(name=headers["server"], confidence="medium"))

        if "x-powered-by" in headers:
            tech = Technology(name=headers["x-powered-by"], confidence="high")
            if tech.name not in [t.name for t in technologies]:
                technologies.append(tech)

        for pattern, tech_name in self.TECH_PATTERNS:
            if re.search(pattern, html, re.IGNORECASE) and tech_name not in detected:
                detected.add(tech_name)
                technologies.append(Technology(name=tech_name, confidence="high"))

        return technologies

    async def _find_secrets(self, html: str, url: str) -> List[Finding]:
        """Procura secrets expostos"""
        findings = []

        for pattern, description in self.SECRET_PATTERNS:
            matches = re.finditer(pattern, html, re.IGNORECASE)
            for match in matches:
                findings.append(Finding(
                    name=f"Secret Exposto: {description}",
                    severity=Severity.CRITICAL,
                    description=f"{description} encontrada no código",
                    location=f"{url} - HTML",
                    recommendation="Remova secrets hardcoded"
                ))

        return findings

    def _check_info_leakage(self, headers: dict) -> List[Finding]:
        """Verifica information disclosure"""
        findings = []

        leak_headers = {
            "x-powered-by": "X-Powered-By exposto",
            "server": "Server header exposto",
            "x-aspnet-version": "ASP.NET Version exposta",
            "x-generator": "X-Generator exposto",
        }

        for header, description in leak_headers.items():
            if header in headers:
                findings.append(Finding(
                    name=description,
                    severity=Severity.LOW,
                    description=f"Header {header}: {headers[header]}",
                    location="HTTP Headers",
                    recommendation=f"Oculte o header {header}"
                ))

        return findings

    async def _check_common_paths(self, url: str) -> List[Finding]:
        """Verifica paths críticos expostos"""
        findings = []
        base_url = url.rstrip("/")

        critical_paths = [
            "/.env", "/config.php", "/wp-config.php",
            "/admin", "/login", "/debug",
            "/.git/config", "/phpmyadmin",
            "/server-status", "/phpinfo.php",
        ]

        tasks = []
        for path in critical_paths:
            tasks.append(self._check_path(f"{base_url}{path}"))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        findings.extend([r for r in results if r])

        return findings

    async def _check_path(self, url: str) -> Optional[Finding]:
        """Verifica se um path existe"""
        try:
            resp = await self.client.get(url, timeout=5)
            if resp.status_code == 200:
                name = url.split("/")[-1] if url.split("/")[-1] else "path"
                return Finding(
                    name=f"Path Exposto: /{name}",
                    severity=Severity.HIGH,
                    description=f"URL {url} acessível publicamente",
                    location=url,
                    recommendation="Restrinja acesso ou remova"
                )
        except:
            pass
        return None

    async def _find_api_endpoints(self, base_url: str, crawl_results: dict) -> List[Finding]:
        """Encontra endpoints de API"""
        findings = []

        api_paths = [
            "/api", "/api/v1", "/api/v2",
            "/api/users", "/api/admin",
            "/graphql", "/api/graphql",
            "/swagger", "/api/docs",
        ]

        for path in api_paths:
            try:
                url = base_url.rstrip("/") + path
                resp = await self.client.get(url, timeout=5, follow_redirects=False)
                if resp.status_code == 200:
                    findings.append(Finding(
                        name="API Endpoint Exposto",
                        severity=Severity.INFO,
                        description=f"Endpoint {path} encontrado",
                        location=url,
                        recommendation="Verifique se deve ser público"
                    ))
            except:
                pass

        return findings

    def _calculate_score(self, findings: List[Finding]) -> int:
        """Calcula score 0-100"""
        if not findings:
            return 100

        deductions = {
            Severity.CRITICAL: 25,
            Severity.HIGH: 15,
            Severity.MEDIUM: 8,
            Severity.LOW: 3,
            Severity.INFO: 1,
        }

        total = sum(deductions.get(f.severity, 1) for f in findings)
        return max(0, 100 - total)

    def _generate_summary(self, findings: List[Finding], score: int, scan_type: ScanType) -> dict:
        """Gera sumário"""
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            counts[f.severity.value] += 1

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

        modes = {
            ScanType.QUICK: "Scan Essencial (30s)",
            ScanType.FULL: "Scan Profissional (3min)",
            ScanType.AGGRESSIVE: "Scan Completo (10min)",
        }

        return {
            "classification": classification,
            "severity_counts": counts,
            "total_findings": len(findings),
            "risk_level": "high" if counts["critical"] > 0 or counts["high"] > 2 else "medium" if counts["medium"] > 0 else "low",
            "scan_mode": scan_type.value,
            "scan_mode_description": modes.get(scan_type, ""),
        }


# Helper para parsing de URL
from urllib.parse import urlparse
