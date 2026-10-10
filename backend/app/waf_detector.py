"""
Detector de WAF e Firewall
Identifica Web Application Firewalls e sistemas de proteção
"""
import asyncio
import httpx
import re
from typing import List, Optional, Dict
from urllib.parse import urlparse
from .models import Finding, Severity


class WAFDetector:
    """Detector de Web Application Firewalls"""

    # Assinaturas de WAFs conhecidos
    WAF_SIGNATURES: Dict[str, Dict] = {
        # WAFs por header
        "x-sucuri-id": {"name": "Sucuri", "severity": Severity.INFO},
        "x-sucuri-cache": {"name": "Sucuri", "severity": Severity.INFO},
        "x-ithemes": {"name": "iThemes Security", "severity": Severity.INFO},
        "x-xxss-protection": {"name": "Custom XXS Protection", "severity": Severity.LOW},
        "x-RequestAnalyzer-Token": {"name": "Imunify360", "severity": Severity.INFO},

        # Cloud Providers / CDNs
        "cf-ray": {"name": "Cloudflare", "severity": Severity.INFO},
        "cf-cache-status": {"name": "Cloudflare", "severity": Severity.INFO},
        "cf-edge": {"name": "Cloudflare", "severity": Severity.INFO},
        "x-amz-cf-id": {"name": "CloudFront", "severity": Severity.INFO},
        "x-amz-cf-pop": {"name": "CloudFront", "severity": Severity.INFO},
        "x-edge-location": {"name": "CloudFront", "severity": Severity.INFO},
        "x-ec-custom-error": {"name": "AWS WAF", "severity": Severity.INFO},

        # Security Headers específicos de WAF
        "x-protected-by": {"name": "ModSecurity", "severity": Severity.INFO},
        "x-cdn": {"name": "CDN Security", "severity": Severity.INFO},
        "server": {
            "patterns": {
                "akamai": "Akamai",
                "cloudflare": "Cloudflare",
                "fastly": "Fastly",
                "incapsula": "Incapsula/Imperva",
                "bigip": "F5 BIG-IP",
                "fortiweb": "FortiWeb",
                "citrix": "Citrix NetScaler",
                "aws": "AWS WAF/CloudFront",
            }
        },

        # Cookies de WAF
        "cookie": {
            "patterns": {
                "__cfduid": "Cloudflare",
                "Cloudflare-session": "Cloudflare",
                "ARQ": "AWS WAF",
                "AWSALB": "AWS Application Load Balancer",
                "incap_ses": "Incapsula",
                "visid_incap": "Incapsula",
            }
        },
    }

    # Páginas de erro de WAFs
    WAF_ERROR_PAGES = [
        # Cloudflare
        (r"Cloudflare", "Error connecting to origin", "Cloudflare"),
        (r"cloudflare", "Ray ID:", "Cloudflare"),
        (r"Attention required! \| Cloudflare", "", "Cloudflare"),
        # AWS
        (r"403 ERROR", "The request could not be satisfied", "AWS WAF/CloudFront"),
        (r"403 Forbidden", "AWS WAF", "AWS WAF"),
        # Incapsula
        (r"Incapsula", "Incident ID:", "Incapsula/Imperva"),
        (r"incapsula", "_Incapsula_Resource", "Incapsula/Imperva"),
        # Sucuri
        (r"sucuri", "Website Firewall", "Sucuri"),
        # ModSecurity
        (r"mod_security", "ModSecurity", "ModSecurity"),
        (r"modsecurity", "ModSecurity", "ModSecurity"),
        # Wordfence
        (r"wordfence", "Wordfence", "Wordfence"),
        # StackPath
        (r"stackpath", "StackPath", "StackPath"),
        # Akamai
        (r"Reference #[0-9]+", "Akamai", "Akamai"),
    ]

    # Requests que ativam WAFs
    WAF_TRIGGERS = [
        "/?param=<script>alert(1)</script>",
        "/?param=1' OR '1'='1",
        "/?param=../../../etc/passwd",
        "/?param=<img src=x onerror=alert(1)>",
    ]

    def __init__(self, timeout: int = 30):
        self.timeout = timeout
        self.client = httpx.AsyncClient(timeout=timeout, follow_redirects=False)

    async def close(self):
        await self.client.aclose()

    async def detect(self, target: str, mode: str = "quick") -> List[Finding]:
        """
        Detecta WAF na URL alvo

        Args:
            target: URL para verificar
            mode: 'quick' (apenas headers) ou 'aggressive' (ativa WAF triggers)

        Returns:
            Lista de Findings
        """
        findings = []

        # Fase 1: Verificação passiva (headers e cookies)
        passive_findings = await self._passive_detection(target)
        findings.extend(passive_findings)

        # Fase 2: Verificação ativa (enviando payloads)
        if mode == "aggressive":
            active_findings = await self._active_detection(target)
            findings.extend(active_findings)

        return findings

    async def _passive_detection(self, target: str) -> List[Finding]:
        """Detecção passiva via headers"""
        findings = []

        try:
            response = await self.client.get(target, timeout=self.timeout)
            headers = {k.lower(): v for k, v in response.headers.items()}

            detected_wafs = set()

            # Verifica headers
            for header, signature in self.WAF_SIGNATURES.items():
                if header == "server" and "server" in headers:
                    server_value = headers["server"].lower()
                    if "patterns" in signature:
                        for pattern, waf_name in signature["patterns"].items():
                            if pattern.lower() in server_value:
                                detected_wafs.add(waf_name)
                elif header == "cookie" and "cookie" in headers:
                    cookie_value = headers["cookie"].lower()
                    if "patterns" in signature:
                        for pattern, waf_name in signature["patterns"].items():
                            if pattern.lower() in cookie_value:
                                detected_wafs.add(waf_name)
                elif header in headers:
                    detected_wafs.add(signature["name"])

            # Verifica cookies
            for cookie_name in response.cookies:
                for waf_name in ["Cloudflare", "Incapsula", "AWS WAF"]:
                    if waf_name.lower() in cookie_name.lower():
                        detected_wafs.add(waf_name)

            # Reporta WAFs detectados
            for waf_name in detected_wafs:
                findings.append(Finding(
                    name=f"WAF Detectado: {waf_name}",
                    severity=Severity.INFO,
                    description=f"Proteção {waf_name} foi identificada neste site",
                    location=target,
                    recommendation=f"O site está protegido por {waf_name}"
                ))

            # Verifica página de erro
            if response.status_code in [403, 406, 419, 429, 503]:
                content = response.text

                for pattern, context, waf_name in self.WAF_ERROR_PAGES:
                    if re.search(pattern, content, re.IGNORECASE):
                        if context and context not in content:
                            continue

                        findings.append(Finding(
                            name=f"Proteção WAF Detectada: {waf_name}",
                            severity=Severity.INFO,
                            description=f"Resposta de erro {response.status_code} parece ser de {waf_name}",
                            location=target,
                            recommendation=f"O site está protegido por {waf_name}"
                        ))
                        break

        except Exception:
            pass

        return findings

    async def _active_detection(self, target: str) -> List[Finding]:
        """Detecção ativa via triggers de WAF"""
        findings = []

        for trigger in self.WAF_TRIGGERS[:2]:  # Limita a 2 triggers
            try:
                trigger_url = target.rstrip('/') + trigger
                response = await self.client.get(trigger_url, timeout=10)

                # Verifica se foi bloqueado
                if response.status_code in [403, 406, 419, 429, 503]:
                    # Identifica qual WAF bloqueou
                    for pattern, context, waf_name in self.WAF_ERROR_PAGES:
                        if re.search(pattern, response.text, re.IGNORECASE):
                            findings.append(Finding(
                                name=f"WAF Bloqueou Requisição: {waf_name}",
                                severity=Severity.INFO,
                                description=f"Payload de teste foi bloqueado por {waf_name}",
                                location=trigger_url,
                                recommendation=f"O site está protegido por {waf_name} contra ataques XSS/SQLi"
                            ))
                            break
                    else:
                        findings.append(Finding(
                            name="WAF Bloqueou Requisição",
                            severity=Severity.INFO,
                            description=f"Requisição foi bloqueada com status {response.status_code}",
                            location=trigger_url,
                            recommendation="Um WAF está ativo e bloqueando requisições suspeitas"
                        ))

            except Exception:
                pass

        return findings


class WAFBypassChecker:
    """Verifica possíveis bypasses de WAF"""

    # Técnicas de bypass conhecidas
    BYPASS_TECHNIQUES = [
        ("case", "/?id=1 UnIoN SeLeCt"),
        ("comment", "/?id=1'/**/OR/**/'1'='1"),
        ("encoding", "/?id=1%27%20OR%20%271%27=%271"),
        ("nullbyte", "/?id=1%00' OR '1'='1"),
    ]

    def __init__(self, timeout: int = 30):
        self.timeout = timeout
        self.client = httpx.AsyncClient(timeout=timeout, follow_redirects=False)

    async def close(self):
        await self.client.aclose()

    async def check_bypasses(self, target: str) -> List[Finding]:
        """Verifica se WAF pode ser contornado"""
        findings = []

        for technique, payload in self.BYPASS_TECHNIQUES:
            try:
                test_url = target.rstrip('/') + payload
                response = await self.client.get(test_url, timeout=10)

                # Se não foi bloqueado, pode ser bypass
                if response.status_code == 200:
                    # Verifica se o payload foi executado
                    if "1" in response.text and "SELECT" not in response.text:
                        findings.append(Finding(
                            name=f"Possível WAF Bypass ({technique})",
                            severity=Severity.HIGH,
                            description=f"Técnica {technique} pode ter contornado o WAF",
                            location=test_url,
                            recommendation="Revise as regras do WAF para bloquear esta técnica"
                        ))

            except Exception:
                pass

        return findings
