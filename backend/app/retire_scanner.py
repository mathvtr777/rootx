"""
Wrapper para Retire.js
Detecta bibliotecas JavaScript vulneráveis
"""
import asyncio
import re
import subprocess
from typing import List, Optional
from pathlib import Path
from .models import Finding, Severity


class RetireScanner:
    """Wrapper para o Retire.js scanner"""

    def __init__(self, timeout: int = 60):
        self.timeout = timeout
        self.retire_path = "retire"  # Assume que está no PATH (npm global)

    async def scan_js_files(self, js_urls: List[str]) -> List[Finding]:
        """
        Escaneia arquivos JavaScript em busca de vulnerabilidades

        Args:
            js_urls: Lista de URLs de arquivos JS para escanear

        Returns:
            Lista de Findings
        """
        findings = []

        if not js_urls:
            return findings

        # agrupa URLs para não sobrecarregar
        for url in js_urls[:50]:  # Limita a 50 arquivos JS
            try:
                finding = await self._scan_single_js(url)
                if finding:
                    findings.append(finding)
            except Exception:
                continue

        return findings

    async def _scan_single_js(self, js_url: str) -> Optional[Finding]:
        """Escaneia um único arquivo JS"""
        try:
            # Usa retire via linha de comando
            cmd = [self.retire_path, "--path", js_url, "--outputformat", "json"]

            result = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await asyncio.wait_for(
                result.communicate(),
                timeout=self.timeout
            )

            # Parse resultado
            if stdout:
                return self._parse_retire_output(stdout.decode('utf-8'), js_url)

        except asyncio.TimeoutError:
            return Finding(
                name="Retire.js Timeout",
                severity=Severity.INFO,
                description=f"Timeout ao escanear {js_url}",
                location=js_url,
                recommendation="Arquivo pode ser muito grande"
            )
        except FileNotFoundError:
            # Retire.js não está instalado, retorna None
            return None
        except Exception:
            return None

        return None

    def _parse_retire_output(self, output: str, js_url: str) -> Optional[Finding]:
        """Parse output do Retire.js"""
        try:
            import json
            data = json.loads(output)

            if not data or len(data) == 0:
                return None

            results = data if isinstance(data, list) else [data]

            for result in results:
                # Pega a библиотека mais crítica encontrada
                results_list = result.get("results", [])
                if not results_list:
                    continue

                for lib_result in results_list:
                    component = lib_result.get("component", "unknown")
                    version = lib_result.get("version", "unknown")
                    vulnerabilities = lib_result.get("vulnerabilities", [])

                    if vulnerabilities:
                        # Pega a vulnerabilidade mais crítica
                        highest_severity = "low"
                        highest_cvss = 0.0

                        for vuln in vulnerabilities:
                            severity = vuln.get("severity", "low")
                            cvss = float(vuln.get("cvss", 0.0))

                            if severity == "high" or cvss > highest_cvss:
                                highest_severity = severity
                                highest_cvss = cvss

                        return Finding(
                            name=f"Biblioteca JS Vulnerável: {component}",
                            severity=self._map_severity(highest_severity),
                            description=f"Biblioteca {component} v{version} tem {len(vulnerabilities)} vulnerabilidade(s) conhecida(s)",
                            location=js_url,
                            recommendation=f"Atualize {component} para versão mais recente",
                            cve_id=vulnerabilities[0].get("identifiers", {}).get("CVE", [None])[0] if vulnerabilities else None,
                            cvss=highest_cvss if highest_cvss > 0 else None
                        )

        except Exception:
            pass

        return None

    def _map_severity(self, retire_severity: str) -> Severity:
        """Mapeia severidade do Retire.js para nosso modelo"""
        mapping = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
        }
        return mapping.get(retire_severity.lower(), Severity.INFO)

    def is_installed(self) -> bool:
        """Verifica se Retire.js está instalado"""
        try:
            result = subprocess.run(
                [self.retire_path, "--version"],
                capture_output=True,
                timeout=5
            )
            return result.returncode == 0
        except Exception:
            return False

    @staticmethod
    def extract_js_urls(html_content: str, base_url: str) -> List[str]:
        """Extrai URLs de arquivos JS do HTML"""
        js_urls = []

        # Padrões para encontrar scripts
        patterns = [
            r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']',
            r'<script[^>]+src=["\']([^"\']+\.min\.js[^"\']*)["\']',
        ]

        for pattern in patterns:
            matches = re.finditer(pattern, html_content, re.IGNORECASE)
            for match in matches:
                src = match.group(1)

                # Constrói URL completa se for relativa
                if src.startswith('//'):
                    js_urls.append('https:' + src)
                elif src.startswith('/'):
                    # Extrai domínio do base_url
                    from urllib.parse import urlparse
                    parsed = urlparse(base_url)
                    js_urls.append(f"{parsed.scheme}://{parsed.netloc}{src}")
                elif not src.startswith(('http://', 'https://')):
                    from urllib.parse import urljoin
                    js_urls.append(urljoin(base_url, src))
                else:
                    js_urls.append(src)

        # Remove duplicatas
        return list(set(js_urls))
