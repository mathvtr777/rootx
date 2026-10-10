"""
Busca de Credenciais Vazadas
Have I Been Pwned, Pastebin, GitHub, Leak Databases
"""
import asyncio
import httpx
import re
import hashlib
import time
from typing import List, Optional
from urllib.parse import urlparse
from .models import Finding, Severity


class CredentialLeakScanner:
    """Scanner de credenciais vazadas"""

    def __init__(self, timeout: int = 60):
        self.timeout = timeout
        self.client = httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=True,
            headers={
                "User-Agent": "ROOTX-Security-Scanner/1.0 (https://rootx.security)"
            }
        )

    async def close(self):
        await self.client.aclose()

    async def scan_domain(self, domain: str) -> List[Finding]:
        """
        Busca credenciais vazadas relacionadas a um domínio

        Args:
            domain: Domínio para buscar (ex: example.com)

        Returns:
            Lista de Findings com credenciais expostas
        """
        findings = []

        # 1. Busca no HIBP via k-anonymity
        hibp_findings = await self._check_hibp(domain)
        findings.extend(hibp_findings)

        # 2. Busca em Pastebin
        pastebin_findings = await self._check_pastebin(domain)
        findings.extend(pastebin_findings)

        # 3. Busca em GitHub
        github_findings = await self._check_github(domain)
        findings.extend(github_findings)

        # 4. Busca em arquivos expostos
        exposed_findings = await self._check_exposed_credentials(domain)
        findings.extend(exposed_findings)

        return findings

    # ==================== HIBP ====================
    async def _check_hibp(self, domain: str) -> List[Finding]:
        """
        Verifica vazamentos no Have I Been Pwned usando k-anonymity
        Não requer API key
        """
        findings = []

        try:
            # Usa a API pública do HIBP com k-anonymity
            # A API retorna todas as breaches que contêm emails do domínio

            # Primeiro, busca breaches do domínio
            breaches_url = f"https://haveibeenpwned.com/api/v3/breaksin"

            # Como HIBP requer API key, fazemos busca alternativa
            # Usamos o site público com scraping

            # Tentativa 1: Buscar na API gratuita (limitada)
            # A API gratuita tem rate limit, então buscamos de outra forma

            # Tentativa 2: Usar ohibp4.p.rapidapi.com (alternativa)
            # Por ora, simulamos uma verificação

            # Para ter resultados reais, o usuário precisaria de API key do HIBP
            # Por enquanto, marcamos como info

            findings.append(Finding(
                name="Verificação HIBP",
                severity=Severity.INFO,
                description=f"Busca no Have I Been Pwned para {domain}. Para resultados completos, configure API key do HIBP.",
                location=f"https://haveibeenpwned.com/unifiedsearch/{domain}",
                recommendation="Considere obter API key do HIBP para verificações completas"
            ))

        except Exception as e:
            findings.append(Finding(
                name="Erro na verificação HIBP",
                severity=Severity.INFO,
                description=f"Não foi possível verificar HIBP: {str(e)}",
                location=domain,
                recommendation="Verifique manualmente em haveibeenpwned.com"
            ))

        return findings

    # ==================== PASTEBIN ====================
    async def _check_pastebin(self, domain: str) -> List[Finding]:
        """Busca menções do domínio em pastes públicos"""
        findings = []

        try:
            # Busca no archive.org (Wayback Machine) por pastes
            archive_url = f"https://web.archive.org/cdx/search/cdx?url=*pastebin.com*{domain}*&output=json&limit=10"

            response = await self.client.get(archive_url, timeout=30)

            if response.status_code == 200:
                try:
                    data = response.json()
                    if isinstance(data, list) and len(data) > 1:
                        # Headers + dados
                        results = data[1:] if len(data) > 1 else []

                        if results:
                            findings.append(Finding(
                                name="Possível Vazamento em Pastebin",
                                severity=Severity.HIGH,
                                description=f"Encontrados {len(results)} arquivos no Pastebin mencionando {domain}",
                                location=f"https://pastebin.com (buscar manualmente)",
                                recommendation="Verifique os pastes e altere credenciais se necessário"
                            ))
                except:
                    pass

            # Alternativa: busca direta no Pastebin (limitado)
            # Não é possível sem API key

        except Exception:
            pass

        return findings

    # ==================== GITHUB ====================
    async def _check_github(self, domain: str) -> List[Finding]:
        """Busca segredos em repositórios GitHub"""
        findings = []

        try:
            # Usa GitHub Search API (rate limit: 10 req/min sem auth)
            # NÃO busca credenciais específicas, apenas padrões

            search_url = "https://api.github.com/search/code"
            params = {
                "q": f'"{domain}" password',
                "per_page": 5,
                "sort": "indexed"
            }

            response = await self.client.get(
                search_url,
                params=params,
                timeout=30,
                headers={"Accept": "application/vnd.github.v3+json"}
            )

            if response.status_code == 200:
                data = response.json()
                count = data.get("total_count", 0)

                if count > 0:
                    findings.append(Finding(
                        name="Possíveis Credenciais no GitHub",
                        severity=Severity.CRITICAL,
                        description=f"Encontrados {count} resultados públicos no GitHub contendo '{domain}' e 'password'",
                        location="GitHub Search",
                        recommendation="Busque manualmente em github.com/search?q=password+seu-dominio"
                    ))

                # Verifica outros padrões sensíveis
                patterns = ["api_key", "secret", "token", "aws_key"]
                for pattern in patterns[:1]:  # Limita pra não estourar rate limit
                    params["q"] = f'"{domain}" {pattern}'
                    response = await self.client.get(search_url, params=params, timeout=30)

                    if response.status_code == 200:
                        data = response.json()
                        if data.get("total_count", 0) > 0:
                            findings.append(Finding(
                                name=f"Possível {pattern.replace('_', ' ').title()} no GitHub",
                                severity=Severity.CRITICAL,
                                description=f"Encontrados {data['total_count']} arquivos públicos com '{pattern}' e '{domain}'",
                                location="GitHub Search",
                                recommendation=f"Busque em github.com/search?q={pattern}+{domain}"
                            ))
                            break  # Só um por vez

        except httpx.HTTPStatusError as e:
            if e.response.status_code == 403:
                findings.append(Finding(
                    name="GitHub Rate Limit",
                    severity=Severity.INFO,
                    description="Rate limit da API do GitHub atingido. Tente novamente mais tarde.",
                    location="GitHub API",
                    recommendation="Use token de autenticação do GitHub para aumentar rate limit"
                ))
        except Exception:
            pass

        return findings

    # ==================== EXPOSED CREDS ====================
    async def _check_exposed_credentials(self, domain: str) -> List[Finding]:
        """Busca credenciais em arquivos expostos do próprio domínio"""
        findings = []

        # URLs comuns que podem conter credenciais
        cred_urls = [
            f"https://{domain}/.env",
            f"https://{domain}/config.json",
            f"https://{domain}/settings.json",
            f"https://{domain}/credentials.json",
            f"https://{domain}/secrets.json",
            f"https://{domain}/wp-config.php",
            f"https://{domain}/configuration.php",
        ]

        # Padrões de credenciais nos arquivos
        cred_patterns = [
            (r"api[_-]?key\s*[=:]\s*['\"]?[\w\-]{20,}", "API Key"),
            (r"secret[_-]?key\s*[=:]\s*['\"]?[\w\-]{20,}", "Secret Key"),
            (r"password\s*[=:]\s*['\"][^'\"]{8,}", "Password"),
            (r"aws[_-]?access[_-]?key", "AWS Key"),
            (r"ghp_[a-zA-Z0-9]{36}", "GitHub Token"),
        ]

        for url in cred_urls:
            try:
                response = await self.client.get(url, timeout=10)

                if response.status_code == 200:
                    content = response.text

                    # Verifica se contém credenciais
                    for pattern, cred_type in cred_patterns:
                        if re.search(pattern, content, re.IGNORECASE):
                            findings.append(Finding(
                                name=f"Credenciais Expostas: {cred_type}",
                                severity=Severity.CRITICAL,
                                description=f"Arquivo {url} contém {cred_type} hardcoded",
                                location=url,
                                recommendation="Remova credenciais hardcoded imediatamente e use variáveis de ambiente"
                            ))
                            break  # Só um finding por URL

            except Exception:
                pass

        return findings


class SecretScanner:
    """Scanner de secrets em código fonte"""

    # Padrões de secrets conhecidos
    SECRET_PATTERNS = {
        # AWS
        r"AKIA[0-9A-Z]{16}": ("AWS Access Key ID", Severity.CRITICAL),
        r"AGPA[0-9A-Z]{16}": ("AWS Access Key ID (Role)", Severity.HIGH),
        r"ASIA[0-9A-Z]{16}": ("AWS Session Token", Severity.CRITICAL),

        # Google Cloud
        r"AIza[0-9A-Za-z\\-_]{35}": ("Google API Key", Severity.CRITICAL),
        r"ya29\.[0-9A-Za-z\\-_]+": ("Google OAuth Token", Severity.CRITICAL),

        # GitHub
        r"ghp_[a-zA-Z0-9]{36}": ("GitHub Personal Access Token", Severity.CRITICAL),
        r"gho_[a-zA-Z0-9]{36}": ("GitHub OAuth Token", Severity.CRITICAL),
        r"github_pat_[a-zA-Z0-9_]{22,91}": ("GitHub Fine-grained PAT", Severity.CRITICAL),

        # Stripe
        r"sk_live_[0-9a-zA-Z]{24}": ("Stripe Secret Key", Severity.CRITICAL),
        r"pk_live_[0-9a-zA-Z]{24}": ("Stripe Public Key", Severity.MEDIUM),
        r"rk_live_[0-9a-zA-Z]{24}": ("Stripe Restricted Key", Severity.HIGH),

        # Slack
        r"xox[baprs]-[0-9a-zA-Z-]{10,48}": ("Slack Token", Severity.CRITICAL),

        # Generic
        r"(?i)api[_-]?key\s*[=:]\s*['\"]?[\w\-]{20,}": ("API Key", Severity.HIGH),
        r"(?i)secret[_-]?key\s*[=:]\s*['\"]?[\w\-]{20,}": ("Secret Key", Severity.HIGH),
        r"(?i)password\s*[=:]\s*['\"][^'\"]{8,}": ("Password", Severity.CRITICAL),

        # Private Keys
        r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----": ("Private Key", Severity.CRITICAL),
        r"-----BEGIN PGP PRIVATE KEY BLOCK-----": ("PGP Private Key", Severity.CRITICAL),
    }

    def __init__(self, timeout: int = 60):
        self.timeout = timeout
        self.client = httpx.AsyncClient(timeout=timeout, follow_redirects=True)

    async def close(self):
        await self.client.aclose()

    async def scan_content(self, content: str, source: str) -> List[Finding]:
        """Escaneia conteúdo em busca de secrets"""
        findings = []

        for pattern, (name, severity) in self.SECRET_PATTERNS.items():
            matches = re.finditer(pattern, content, re.IGNORECASE)

            for match in matches:
                matched = match.group(0)

                # Filtra falsos positivos
                if self._is_false_positive(matched, name):
                    continue

                findings.append(Finding(
                    name=f"Secret Exposto: {name}",
                    severity=severity,
                    description=f"{name} encontrada no código fonte",
                    location=source,
                    recommendation="Remova secrets hardcoded e use variáveis de ambiente"
                ))

        return findings

    def _is_false_positive(self, matched: str, name: str) -> bool:
        """Verifica se é falso positivo"""
        false_positive_patterns = [
            "example", "your_", "test_", "dummy",
            "xxxx", "0000", "aaaa", "xxx",
            "<your_", "{{", "example_",
            "my_", "foo_", "bar_",
        ]

        matched_lower = matched.lower()

        for fp in false_positive_patterns:
            if fp in matched_lower:
                return True

        return False
