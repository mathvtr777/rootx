"""
Wrapper para Nuclei Scanner
Executa scans de vulnerabilidades baseados em templates
"""
import asyncio
import json
import subprocess
from typing import List, Optional
from pathlib import Path
from .models import Finding, Severity


class NucleiScanner:
    """Wrapper para o Nuclei scanner"""

    def __init__(self, timeout: int = 120):
        self.timeout = timeout
        self.nuclei_path = "nuclei"  # Assume que está no PATH
        self.templates_dir = Path.home() / ".nuclei" / "templates"

    async def scan(self, target: str, mode: str = "selected") -> List[Finding]:
        """
        Executa scan com Nuclei

        Args:
            target: URL para escanear
            mode: 'selected' (FULL) ou 'full' (AGGRESSIVE)

        Returns:
            Lista de Findings
        """
        findings = []

        try:
            # Determina quais templates usar baseado no modo
            if mode == "selected":
                # FULL mode: templates mais críticos e comuns
                tags = ["cve", "critical", "high", "web", "misconfiguration"]
            else:
                # AGGRESSIVE: todos os templates de vulnerabilidade
                tags = ["cve", "critical", "high", "medium", "web", "network", "misconfiguration"]

            # Constrói comando nuclei
            cmd = [
                self.nuclei_path,
                "-u", target,
                "-json",
                "-silent",
                "-timeout", "10",
                "-rate-limit", "150",  # Limita requisições por segundo
            ]

            # Adiciona tags para filtrar templates
            if mode == "selected":
                # Usa apenas templates de alta prioridade
                cmd.extend(["-tags", ",".join(tags[:4])])
            else:
                # Usa mais tags no modo aggressivo
                cmd.extend(["-tags", ",".join(tags)])

            # Executa nuclei
            result = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await asyncio.wait_for(
                result.communicate(),
                timeout=self.timeout
            )

            # Parse output JSON
            if stdout:
                for line in stdout.decode('utf-8').strip().split('\n'):
                    if line.strip():
                        try:
                            finding = self._parse_result(json.loads(line))
                            if finding:
                                findings.append(finding)
                        except json.JSONDecodeError:
                            continue

        except asyncio.TimeoutError:
            findings.append(Finding(
                name="Nuclei Timeout",
                severity=Severity.INFO,
                description=f"Nuclei scan excedeu timeout de {self.timeout}s",
                location=target,
                recommendation="Scan pode ter sido interrompido. Tente novamente."
            ))
        except FileNotFoundError:
            # Nuclei não está instalado
            findings.append(Finding(
                name="Nuclei Não Instalado",
                severity=Severity.INFO,
                description="Nuclei não está instalado ou não está no PATH",
                location=target,
                recommendation="Instale nuclei: https://github.com/projectdiscovery/nuclei"
            ))
        except Exception as e:
            findings.append(Finding(
                name="Erro no Nuclei",
                severity=Severity.INFO,
                description=f"Erro ao executar Nuclei: {str(e)}",
                location=target,
                recommendation="Verifique se Nuclei está instalado corretamente"
            ))

        return findings

    def _parse_result(self, result: dict) -> Optional[Finding]:
        """Parse um resultado do Nuclei para Finding"""
        try:
            info = result.get("info", {})

            # Determina severidade
            severity = self._map_severity(result.get("severity", "info"))

            # Extrai CVE se presente
            cve_id = None
            if "cve" in info:
                cve_id = f"CVE-{info['cve']}" if isinstance(info.get("cve"), int) else info.get("cve")

            # Extrai CVSS
            cvss = info.get("cvss", None)
            if isinstance(cvss, str):
                try:
                    cvss = float(cvss)
                except (ValueError, TypeError):
                    cvss = None

            return Finding(
                name=f"Vulnerabilidade Nuclei: {info.get('name', 'Desconhecida')}",
                severity=severity,
                description=info.get('description', result.get('matched-at', '')),
                location=result.get('matched-at', result.get('host', '')),
                recommendation=info.get('remediation', 'Aplique a correção recomendada'),
                cve_id=cve_id,
                cvss=cvss
            )
        except Exception:
            return None

    def _map_severity(self, nuclei_severity: str) -> Severity:
        """Mapeia severidade do Nuclei para nosso modelo"""
        mapping = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
            "info": Severity.INFO,
        }
        return mapping.get(nuclei_severity.lower(), Severity.INFO)

    def is_installed(self) -> bool:
        """Verifica se Nuclei está instalado"""
        try:
            result = subprocess.run(
                [self.nuclei_path, "-version"],
                capture_output=True,
                timeout=5
            )
            return result.returncode == 0
        except Exception:
            return False
