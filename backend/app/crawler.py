"""
Crawler de páginas web
Extrai links e informações das páginas
"""
import asyncio
import httpx
import re
from typing import List, Set, Tuple
from urllib.parse import urljoin, urlparse, urlunparse
from .models import Finding, Severity


class WebCrawler:
    """Crawler básico para extrair links e informações"""

    def __init__(self, timeout: int = 30, max_pages: int = 20):
        self.timeout = timeout
        self.max_pages = max_pages
        self.client = httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=True,
            headers={
                "User-Agent": "ROOTX-Security-Scanner/1.0 (https://rootx.security)"
            }
        )
        self.visited: Set[str] = set()
        self.js_files: List[str] = []
        self.forms: List[Tuple[str, dict]] = []  # (url, form_info)

    async def close(self):
        """Fecha o cliente HTTP"""
        await self.client.aclose()

    async def crawl(self, start_url: str) -> dict:
        """
        Executa crawl a partir de uma URL

        Returns:
            dict com páginas visitadas, JS files, forms, etc
        """
        results = {
            "pages_crawled": 0,
            "urls": [],
            "js_files": [],
            "forms": [],
            "internal_links": [],
            "external_links": [],
        }

        await self._crawl_page(start_url, results)

        return results

    async def _crawl_page(self, url: str, results: dict) -> None:
        """Crawle uma única página"""
        if results["pages_crawled"] >= self.max_pages:
            return

        # Normaliza URL
        normalized = self._normalize_url(url)
        if not normalized or normalized in self.visited:
            return

        self.visited.add(normalized)
        results["pages_crawled"] += 1
        results["urls"].append(normalized)

        try:
            response = await self.client.get(url, timeout=self.timeout)
            html = response.text

            # Extrai JS files
            js_files = self._extract_js_files(html, url)
            for js in js_files:
                if js not in self.js_files:
                    self.js_files.append(js)
                    results["js_files"].append(js)

            # Extrai forms
            forms = self._extract_forms(html, url)
            for form in forms:
                results["forms"].append(form)

            # Extrai links
            links = self._extract_links(html, url)
            base_domain = urlparse(url).netloc

            for link in links:
                normalized_link = self._normalize_url(link)
                if not normalized_link:
                    continue

                link_domain = urlparse(normalized_link).netloc

                if link_domain == base_domain:
                    if normalized_link not in results["internal_links"]:
                        results["internal_links"].append(normalized_link)
                    # Continua crawl em links internos (com limite)
                    if results["pages_crawled"] < self.max_pages:
                        await self._crawl_page(normalized_link, results)
                else:
                    if normalized_link not in results["external_links"]:
                        results["external_links"].append(normalized_link)

        except Exception:
            pass

    def _normalize_url(self, url: str) -> str:
        """Normaliza URL para evitar duplicatas"""
        try:
            parsed = urlparse(url)

            # Remove fragments
            normalized = urlunparse((
                parsed.scheme,
                parsed.netloc,
                parsed.path.rstrip('/'),
                parsed.params,
                parsed.query,
                ''  # Sem fragment
            ))

            return normalized.lower()
        except Exception:
            return url

    def _extract_js_files(self, html: str, base_url: str) -> List[str]:
        """Extrai URLs de arquivos JS"""
        js_files = []

        # Padrões para scripts
        patterns = [
            r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']',
        ]

        for pattern in patterns:
            matches = re.finditer(pattern, html, re.IGNORECASE)
            for match in matches:
                src = match.group(1)
                full_url = urljoin(base_url, src)

                # Filtra CDNs conhecidos (geralmente não vulneráveis)
                cdn_domains = ['cdn.jsdelivr.net', 'cdnjs.cloudflare.com',
                               'unpkg.com', 'ajax.googleapis.com',
                               'stackpath.bootstrapcdn.com']
                if any(cdn in full_url for cdn in cdn_domains):
                    continue

                js_files.append(full_url)

        return js_files

    def _extract_forms(self, html: str, base_url: str) -> List[dict]:
        """Extrai informações de formulários"""
        forms = []

        # Encontrar todos os forms
        form_pattern = r'<form[^>]+>(.*?)</form>'
        for form_match in re.finditer(form_pattern, html, re.DOTALL | re.IGNORECASE):
            form_html = form_match.group(0)

            # Extrair action
            action_match = re.search(r'action=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
            action = action_match.group(1) if action_match else ""
            form_action = urljoin(base_url, action) if action else base_url

            # Extrair method
            method_match = re.search(r'method=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
            method = method_match.group(1).upper() if method_match else "GET"

            # Extrair inputs sensíveis
            sensitive_inputs = re.findall(
                r'<input[^>]*(?:type=["\']?(?:password|secret|token|key|credit|card|cvv)["\']?)[^>]*>',
                form_html,
                re.IGNORECASE
            )

            forms.append({
                "url": form_action,
                "method": method,
                "has_sensitive_fields": len(sensitive_inputs) > 0,
                "sensitive_fields": len(sensitive_inputs)
            })

        return forms

    def _extract_links(self, html: str, base_url: str) -> List[str]:
        """Extrai todos os links do HTML"""
        links = []

        # Padrões para links
        patterns = [
            r'<a[^>]+href=["\']([^"\']+)["\']',
            r'<link[^>]+href=["\']([^"\']+)["\']',
            r'<area[^>]+href=["\']([^"\']+)["\']',
        ]

        for pattern in patterns:
            matches = re.finditer(pattern, html, re.IGNORECASE)
            for match in matches:
                href = match.group(1)

                # Ignora âncoras, javascript e mailto
                if href.startswith(('#', 'javascript:', 'mailto:', 'tel:')):
                    continue

                full_url = urljoin(base_url, href)
                links.append(full_url)

        return links


class FormScanner:
    """Scanner para verificar vulnerabilidades em formulários"""

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

    async def check_forms(self, forms: List[dict]) -> List[Finding]:
        """Verifica vulnerabilidades em formulários"""
        findings = []

        for form in forms:
            # Verifica se há campos sensíveis sem HTTPS
            if form.get("has_sensitive_fields"):
                findings.append(Finding(
                    name="Formulário com Campos Sensíveis",
                    severity=Severity.INFO,
                    description=f"Formulário em {form['url']} contém {form['sensitive_fields']} campo(s) sensível(is)",
                    location=form["url"],
                    recommendation="Garanta que este formulário usa HTTPS e tem proteção CSRF"
                ))

            # Verifica forms em HTTP
            if form["url"].startswith("http://"):
                findings.append(Finding(
                    name="Formulário sobre HTTP",
                    severity=Severity.HIGH,
                    description=f"Formulário enviando dados sobre HTTP não seguro",
                    location=form["url"],
                    recommendation="Mude para HTTPS para proteger os dados"
                ))

        return findings
