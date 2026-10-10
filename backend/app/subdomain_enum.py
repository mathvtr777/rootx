"""
Enumeração de subdomínios
Busca subdomínios comuns e ativos
"""
import asyncio
import dns.resolver
import httpx
import socket
from typing import List, Set
from urllib.parse import urlparse
from .models import Finding, Severity


class SubdomainEnumerator:
    """Enumera subdomínios de um domínio"""

    # Subdomínios comuns para testar
    COMMON_SUBDOMAINS = [
        # Comuns
        "www", "mail", "ftp", "admin", "blog", "shop", "store", "cdn",
        "api", "app", "mobile", "dev", "test", "staging", "demo", "vpn",
        # Infra
        "git", "gitlab", "github", "jenkins", "ci", "docs", "wiki",
        "support", "help", "status", "monitor", "metrics", "logging",
        # Cloud
        "aws", "s3", "cloudfront", "digitalocean", "azure", "gcp",
        "storage", "backup", "static", "assets", "images", "img",
        # Segurança
        "security", "auth", "oauth", "sso", "login", "portal",
        "dashboard", "console", "control", "manage", "admin",
        # Email
        "smtp", "pop", "imap", "webmail", "mx", "mx1", "mail2",
        # Outros
        "beta", "alpha", "old", "new", "pre", "post", "legacy",
        "db", "database", "mysql", "postgres", "redis", "mongo",
        "ns1", "ns2", "dns", "ns", "resolver",
    ]

    def __init__(self, timeout: int = 60):
        self.timeout = timeout
        self.client = httpx.AsyncClient(timeout=timeout, follow_redirects=False)
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 5
        self.resolver.lifetime = 10

    async def close(self):
        """Fecha recursos"""
        await self.client.aclose()

    async def enumerate(self, target: str, mode: str = "quick") -> List[Finding]:
        """
        Enumera subdomínios

        Args:
            target: URL ou domínio base
            mode: 'quick' (10 subs), 'full' (30 subs), 'aggressive' (todos)

        Returns:
            Lista de Findings
        """
        findings = []
        domain = self._extract_domain(target)

        if not domain:
            return findings

        # Determina quantos subdomínios testar
        if mode == "quick":
            subs_to_test = self.COMMON_SUBDOMAINS[:10]
        elif mode == "full":
            subs_to_test = self.COMMON_SUBDOMAINS[:30]
        else:  # aggressive
            subs_to_test = self.COMMON_SUBDOMAINS

        # Testa DNS resolution em paralelo
        tasks = [self._check_subdomain(sub, domain) for sub in subs_to_test]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for sub, is_resolved, url in results:
            if isinstance(url, Exception):
                continue

            if is_resolved:
                findings.append(Finding(
                    name=f"Subdomínio Exposto: {sub}.{domain}",
                    severity=Severity.INFO,
                    description=f"Subdomínio {sub} resolve para um IP",
                    location=url,
                    recommendation=f"Verifique se {sub}.{domain} deve ser público"
                ))

        # Testa HTTP para os que resolveram
        for sub, is_resolved, url in results:
            if isinstance(url, Exception):
                continue

            if is_resolved and url:
                http_check = await self._check_http_response(url)
                if http_check:
                    findings.append(http_check)

        return findings

    async def _check_subdomain(self, subdomain: str, domain: str) -> tuple:
        """Verifica se um subdomínio resolve"""
        full_domain = f"{subdomain}.{domain}"
        url = f"https://{full_domain}"

        try:
            # Tenta resolver DNS
            answers = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: self.resolver.resolve(full_domain, 'A')
            )

            if answers:
                return (subdomain, True, url)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            pass
        except Exception:
            pass

        return (subdomain, False, url)

    async def _check_http_response(self, url: str) -> Finding:
        """Verifica se há conteúdo HTTP interessante"""
        try:
            response = await self.client.get(url, timeout=10, follow_redirects=True)

            if response.status_code == 200:
                # Verifica conteúdo interessante
                content_lower = response.text.lower()

                interesting = {
                    "login": "Página de login exposta",
                    "admin": "Painel administrativo exposto",
                    "dashboard": "Dashboard exposto",
                    "console": "Console exposto",
                    "jenkins": "Jenkins exposto",
                    "swagger": "Swagger exposto",
                    "api": "API exposta",
                    "phpinfo": "PHPInfo exposto",
                    ".env": "Arquivo .env pode estar exposto",
                }

                for keyword, description in interesting.items():
                    if keyword in content_lower:
                        return Finding(
                            name=f"Conteúdo Sensível: {description}",
                            severity=Severity.HIGH,
                            description=f"Página em {url} pode conter informações sensíveis",
                            location=url,
                            recommendation=f"Restrinja o acesso a {url}"
                        )

        except Exception:
            pass

        return None

    def _extract_domain(self, target: str) -> str:
        """Extrai o domínio base de uma URL"""
        try:
            if not target.startswith(('http://', 'https://')):
                target = f"https://{target}"

            parsed = urlparse(target)
            domain = parsed.netloc

            # Remove porta se presente
            if ':' in domain:
                domain = domain.split(':')[0]

            # Remove www. inicial
            if domain.startswith('www.'):
                domain = domain[4:]

            # Para domínios com múltiplos pontos (sub.domain.com)
            parts = domain.split('.')
            if len(parts) >= 2:
                # Pega os dois últimos segmentos
                return '.'.join(parts[-2:])

            return domain

        except Exception:
            return ""


class DNSAnalyzer:
    """Analisa registros DNS de um domínio"""

    def __init__(self, timeout: int = 30):
        self.timeout = timeout
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 5
        self.resolver.lifetime = 10

    async def analyze(self, target: str) -> List[Finding]:
        """Analisa registros DNS"""
        findings = []
        domain = self._extract_domain(target)

        if not domain:
            return findings

        # Verifica registros SPF (proteção de email)
        spf = await self._check_spf(domain)
        if spf:
            findings.append(spf)

        # Verifica registros DMARC
        dmarc = await self._check_dmarc(domain)
        if dmarc:
            findings.append(dmarc)

        # Verifica DKIM
        dkim = await self._check_dkim(domain)
        if dkim:
            findings.append(dkim)

        # Verifica MX (servidores de email)
        mx = await self._check_mx(domain)
        if mx:
            findings.append(mx)

        return findings

    async def _check_spf(self, domain: str) -> Finding:
        """Verifica registro SPF"""
        try:
            answers = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: self.resolver.resolve(domain, 'TXT')
            )

            for rdata in answers:
                txt = str(rdata)
                if txt.startswith('v=spf1'):
                    # Analisa o SPF
                    if '~all' in txt:
                        return Finding(
                            name="SPF Permissivo",
                            severity=Severity.LOW,
                            description="SPF usa ~all (softfail), emails podem ser forjados",
                            location=f"{domain} TXT record",
                            recommendation="Considere usar -all (fail) para maior segurança"
                        )
                    return None  # SPF configurado corretamente

            # Sem SPF
            return Finding(
                name="SPF Não Configurado",
                severity=Severity.MEDIUM,
                description="Não há registro SPF configurado para o domínio",
                location=f"{domain}",
                recommendation="Configure um registro SPF para prevenir email spoofing"
            )

        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return Finding(
                name="SPF Não Configurado",
                severity=Severity.MEDIUM,
                description="Não há registro SPF configurado para o domínio",
                location=f"{domain}",
                recommendation="Configure um registro SPF para prevenir email spoofing"
            )
        except Exception:
            return None

    async def _check_dmarc(self, domain: str) -> Finding:
        """Verifica registro DMARC"""
        try:
            dmarc_domain = f"_dmarc.{domain}"
            answers = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: self.resolver.resolve(dmarc_domain, 'TXT')
            )

            for rdata in answers:
                txt = str(rdata)
                if txt.startswith('v=DMARC1'):
                    return None  # DMARC configurado

        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return Finding(
                name="DMARC Não Configurado",
                severity=Severity.MEDIUM,
                description="Não há registro DMARC configurado",
                location=f"_dmarc.{domain}",
                recommendation="Configure DMARC para proteger contra email spoofing"
            )
        except Exception:
            pass

        return None

    async def _check_dkim(self, domain: str) -> Finding:
        """Verifica registro DKIM"""
        # DKIM selectors variam, então apenas verificamos se existe algum
        common_selectors = ["default", "google", "mail", "dkim", "selector1", "selector2"]

        for selector in common_selectors:
            try:
                dkim_domain = f"{selector}._domainkey.{domain}"
                answers = await asyncio.get_event_loop().run_in_executor(
                    None,
                    lambda: self.resolver.resolve(dkim_domain, 'TXT')
                )

                for rdata in answers:
                    txt = str(rdata)
                    if txt.startswith('v=DKIM1'):
                        return None  # DKIM configurado

            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                continue
            except Exception:
                continue

        return Finding(
            name="DKIM Não Configurado",
            severity=Severity.INFO,
            description="Não foram encontrados registros DKIM públicos",
            location=f"{domain}",
            recommendation="Configure DKIM para assinar digitalmente seus emails"
        )

    async def _check_mx(self, domain: str) -> Finding:
        """Verifica servidores MX"""
        try:
            answers = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: self.resolver.resolve(domain, 'MX')
            )

            mx_servers = [str(rdata.exchange).rstrip('.') for rdata in answers]

            if not mx_servers:
                return Finding(
                    name="MX Não Configurado",
                    severity=Severity.INFO,
                    description="Não há servidores MX configurados",
                    location=domain,
                    recommendation="Configure servidores MX se você recebe emails"
                )

        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            pass
        except Exception:
            pass

        return None

    def _extract_domain(self, target: str) -> str:
        """Extrai domínio de URL"""
        from urllib.parse import urlparse

        try:
            if not target.startswith(('http://', 'https://')):
                target = f"https://{target}"

            parsed = urlparse(target)
            domain = parsed.netloc.split(':')[0]

            if domain.startswith('www.'):
                domain = domain[4:]

            parts = domain.split('.')
            if len(parts) >= 2:
                return '.'.join(parts[-2:])

            return domain

        except Exception:
            return ""
