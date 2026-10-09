"""
Ferramentas de verificação adicional
"""
import asyncio
import httpx
import re
import json
from typing import List, Optional
from datetime import datetime
from .models import Finding, Severity


class ExtendedScanner:
    """Scanner estendido com mais verificações"""

    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.client = httpx.AsyncClient(timeout=timeout, follow_redirects=True)

    async def close(self):
        await self.client.aclose()

    async def check_ssl(self, domain: str) -> List[Finding]:
        """Verifica configurações SSL/TLS"""
        findings = []
        return findings  # Simplificado por enquanto

    async def check_ports(self, host: str) -> List[Finding]:
        """Verifica portas comuns abertas"""
        findings = []
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 3389, 5432, 8080, 8443]
        return findings  # Simplificado por enquanto

    async def check_subdomains(self, domain: str) -> List[Finding]:
        """Verifica subdomínios comuns"""
        findings = []
        common_subs = [
            "www", "api", "admin", "blog", "shop", "cdn",
            "mail", "ftp", "ssh", "dev", "test", "staging",
            "demo", "vpn", "gitlab", "jenkins", "ci", "docs"
        ]

        base_domain = domain.replace("https://", "").replace("http://", "").split("/")[0]

        for sub in common_subs[:10]:  # Limita a 10 pra não demorar
            try:
                url = f"https://{sub}.{base_domain}"
                resp = await self.client.get(url, timeout=3, follow_redirects=False)
                if resp.status_code in [200, 301, 302, 303, 307, 308]:
                    findings.append(Finding(
                        name=f"Subdomínio Exposto: {sub}.{base_domain}",
                        severity=Severity.INFO,
                        description=f"Subdomínio {sub} está acessível publicamente.",
                        location=url,
                        recommendation="Verifique se este subdomínio deve ser público."
                    ))
            except:
                pass

        return findings

    async def check_robots_sitemap(self, url: str) -> List[Finding]:
        """Verifica robots.txt e sitemap.xml"""
        findings = []
        base_url = url.rstrip("/").replace("https://", "").replace("http://", "").split("/")[0]

        # Verifica robots.txt
        try:
            robots_url = f"https://{base_url}/robots.txt"
            resp = await self.client.get(robots_url, timeout=5)
            if resp.status_code == 200:
                content = resp.text.lower()

                # Verifica se admin está no robots
                if "disallow: /admin" not in content and "disallow: /wp-admin" not in content:
                    if await self.client.get(f"https://{base_url}/admin", timeout=3):
                        findings.append(Finding(
                            name="Admin não bloqueada no robots.txt",
                            severity=Severity.LOW,
                            description="A página /admin não está explicitamente bloqueada no robots.txt.",
                            location=robots_url,
                            recommendation="Considere adicionar 'Disallow: /admin' no robots.txt."
                        ))

                # Verifica se sitemap existe
                if "sitemap:" in content:
                    findings.append(Finding(
                        name="Sitemap referenciado",
                        severity=Severity.INFO,
                        description="O site possui sitemap.xml configurado no robots.txt.",
                        location=robots_url,
                        recommendation="Bom! Isso ajuda crawlers a indexar o site."
                    ))
        except:
            pass

        return findings

    async def check_security_txt(self, url: str) -> List[Finding]:
        """Verifica /.well-known/security.txt"""
        findings = []
        base_url = url.rstrip("/").replace("https://", "").replace("http://", "").split("/")[0]

        try:
            security_url = f"https://{base_url}/.well-known/security.txt"
            resp = await self.client.get(security_url, timeout=5)
            if resp.status_code == 200:
                findings.append(Finding(
                    name="security.txt encontrado",
                    severity=Severity.INFO,
                    description="O site possui um arquivo security.txt para reportar vulnerabilidades.",
                    location=security_url,
                    recommendation="Bom! Permite que pesquisadores reportem vulnerabilidades."
                ))
            else:
                findings.append(Finding(
                    name="security.txt não encontrado",
                    severity=Severity.LOW,
                    description="O site não possui um arquivo security.txt.",
                    location=f"https://{base_url}/.well-known/security.txt",
                    recommendation="Considere criar um security.txt para facilitar o reporte de vulnerabilidades."
                ))
        except:
            pass

        return findings

    async def check_cookie_security(self, url: str) -> List[Finding]:
        """Verifica segurança de cookies"""
        findings = []
        try:
            resp = await self.client.get(url, timeout=self.timeout)
            cookies = resp.cookies

            for cookie in cookies:
                cookie_info = cookies[cookie]

                # Verifica HttpOnly
                if hasattr(cookie_info, 'httponly') and not cookie_info.httponly:
                    findings.append(Finding(
                        name=f"Cookie sem HttpOnly: {cookie}",
                        severity=Severity.MEDIUM,
                        description=f"O cookie '{cookie}' não tem o flag HttpOnly, podendo ser acessado via JavaScript.",
                        location=f"{url} - Cookie: {cookie}",
                        recommendation=f"Adicione o flag 'HttpOnly' ao cookie '{cookie}'."
                    ))

                # Verifica Secure
                if hasattr(cookie_info, 'secure') and not cookie_info.secure:
                    findings.append(Finding(
                        name=f"Cookie sem Secure flag: {cookie}",
                        severity=Severity.MEDIUM,
                        description=f"O cookie '{cookie}' não tem o flag Secure, podendo ser enviado via HTTP.",
                        location=f"{url} - Cookie: {cookie}",
                        recommendation=f"Adicione o flag 'Secure' ao cookie '{cookie}' para forçar HTTPS."
                    ))

                # Verifica SameSite
                if hasattr(cookie_info, 'samesite'):
                    samesite = str(cookie_info.samesite).lower()
                    if samesite == "none":
                        findings.append(Finding(
                            name=f"Cookie com SameSite=None: {cookie}",
                            severity=Severity.LOW,
                            description=f"O cookie '{cookie}' tem SameSite=None, podendo ser enviado em contextos cross-site.",
                            location=f"{url} - Cookie: {cookie}",
                            recommendation="Verifique se este cookie realmente precisa ser enviado cross-site."
                        ))
        except:
            pass

        return findings

    async def check_graphql(self, url: str) -> List[Finding]:
        """Verifica se GraphQL está exposto"""
        findings = []
        base_url = url.rstrip("/")

        graphql_endpoints = ["/graphql", "/api/graphql", "/query", "/api/query"]

        for endpoint in graphql_endpoints:
            try:
                graphql_url = f"{base_url}{endpoint}"
                resp = await self.client.post(
                    graphql_url,
                    json={"query": "{__schema{types{name}}}"},
                    headers={"Content-Type": "application/json"},
                    timeout=5
                )
                if resp.status_code == 200 and "data" in resp.text:
                    findings.append(Finding(
                        name="GraphQL Introspection Exposta",
                        severity=Severity.HIGH,
                        description=f"GraphQL endpoint encontrado com introspection habilitada: {endpoint}",
                        location=graphql_url,
                        recommendation="Desabilite introspection em produção ou restrinja o acesso."
                    ))
                    break
            except:
                pass

        return findings

    async def check_cors(self, url: str) -> List[Finding]:
        """Verifica configurações CORS"""
        findings = []
        try:
            resp = await self.client.get(url, timeout=self.timeout)
            cors_origin = resp.headers.get("access-control-allow-origin", "")

            if cors_origin == "*":
                findings.append(Finding(
                    name="CORS permite todas as origens",
                    severity=Severity.MEDIUM,
                    description="O header Access-Control-Allow-Origin está configurado como '*', permitindo requisições de qualquer domínio.",
                    location=f"{url} - CORS Header",
                    recommendation="Restrinja CORS a domínios específicos que precisam acessar a API."
                ))
            elif cors_origin:
                findings.append(Finding(
                    name="CORS configurado",
                    severity=Severity.INFO,
                    description=f"CORS configurado para: {cors_origin}",
                    location=f"{url} - CORS Header",
                    recommendation="Verifique se esta configuração está correta."
                ))
        except:
            pass

        return findings

    async def check_api_endpoints(self, url: str) -> List[Finding]:
        """Verifica APIs comuns expostas"""
        findings = []
        base_url = url.rstrip("/").replace("https://", "").replace("http://", "").split("/")[0]

        api_paths = [
            ("/api", "API REST"),
            ("/api/v1", "API v1"),
            ("/api/v2", "API v2"),
            ("/api/users", "API de Usuários"),
            ("/api/admin", "API Admin"),
            ("/graphql", "GraphQL"),
            ("/api/health", "Health Check"),
            ("/api/status", "Status Endpoint"),
        ]

        for path, name in api_paths:
            try:
                resp = await self.client.get(f"https://{base_url}{path}", timeout=3, follow_redirects=False)
                if resp.status_code == 200:
                    findings.append(Finding(
                        name=f"{name} exposta",
                        severity=Severity.INFO,
                        description=f"Endpoint {path} está acessível publicamente.",
                        location=f"https://{base_url}{path}",
                        recommendation="Verifique se este endpoint deve ser público."
                    ))
            except:
                pass

        return findings

    async def check_missing_headers(self, url: str) -> List[Finding]:
        """Verifica headers importantes faltando"""
        findings = []

        important_headers = {
            "x-powered-by": ("X-Powered-By exposto", Severity.LOW, "Remova ou oculte o header X-Powered-By para não revelar a tecnologia."),
            "server": ("Server header exposto", Severity.LOW, "Considere ocultar o header Server para não revelar informações do servidor."),
            "x-aspnet-version": ("ASP.NET Version exposta", Severity.MEDIUM, "Remova o header X-AspNet-Version."),
            "x-generator": ("X-Generator exposto", Severity.LOW, "Remova o header X-Generator se possível."),
        }

        try:
            resp = await self.client.get(url, timeout=self.timeout)
            headers = {k.lower(): v for k, v in resp.headers.items()}

            for header, (name, severity, rec) in important_headers.items():
                if header in headers:
                    findings.append(Finding(
                        name=name,
                        severity=severity,
                        description=f"Header {header} exposto: {headers[header]}",
                        location=f"{url} - Header: {header}",
                        recommendation=rec
                    ))
        except:
            pass

        return findings

    async def check_dns_records(self, domain: str) -> List[Finding]:
        """Verifica registros DNS (simplificado)"""
        findings = []
        return findings  # Requer biblioteca DNS

    async def check_cloud_metadata(self, url: str) -> List[Finding]:
        """Verifica se metadados de cloud estão acessíveis"""
        findings = []
        base_url = url.rstrip("/").replace("https://", "").replace("http://", "").split("/")[0]

        # AWS metadata
        try:
            resp = await self.client.get(
                "http://169.254.169.254/latest/meta-data/",
                timeout=3,
                headers={"User-Agent": ""}
            )
            if resp.status_code == 200:
                findings.append(Finding(
                    name="AWS Metadata Exposto!",
                    severity=Severity.CRITICAL,
                    description="O endpoint de metadados AWS está acessível! Isso pode permitir acesso a credenciais.",
                    location="http://169.254.169.254/",
                    recommendation="Bloqueie imediatamente o acesso ao IP 169.254.169.254 nos grupos de segurança!"
                ))
        except:
            pass

        return findings

    async def check_debug_mode(self, url: str) -> List[Finding]:
        """Verifica se modo debug está ativo"""
        findings = []
        base_url = url.rstrip("/")

        debug_paths = [
            ("/debug", "Debug Mode"),
            ("/debug=true", "Debug Mode"),
            ("/?debug=true", "Debug Mode"),
            ("/env", "Environment Variables"),
            ("/.env", "Environment File"),
            ("/.env.local", "Environment Local"),
            ("/config", "Configuration"),
            ("/settings", "Settings"),
        ]

        for path, name in debug_paths:
            try:
                resp = await self.client.get(f"{base_url}{path}", timeout=3)
                if resp.status_code == 200:
                    content = resp.text.lower()
                    if "debug" in content or "password" in content or "secret" in content or "key" in content:
                        findings.append(Finding(
                            name=f"{name} pode estar exposto",
                            severity=Severity.HIGH,
                            description=f"Página {path} pode conter informações sensíveis.",
                            location=f"{base_url}{path}",
                            recommendation="Restrinja o acesso a páginas de debug e configuração."
                        ))
            except:
                pass

        return findings
