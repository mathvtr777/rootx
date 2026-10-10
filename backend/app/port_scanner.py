"""
Scanner de portas
Verifica portas comuns abertas
"""
import asyncio
import socket
from typing import List, Set
from urllib.parse import urlparse
from .models import Finding, Severity


class PortScanner:
    """Scanner de portas TCP"""

    # Portas comuns e seus serviços
    COMMON_PORTS = {
        21: ("FTP", Severity.HIGH, "FTP exposto pode permitir upload de arquivos maliciosos"),
        22: ("SSH", Severity.INFO, "SSH exposto pode ser alvo de brute force"),
        23: ("Telnet", Severity.HIGH, "Telnet não é seguro, dados em texto plano"),
        25: ("SMTP", Severity.INFO, "SMTP exposto"),
        53: ("DNS", Severity.MEDIUM, "DNS server exposto pode ser usado para amplificação"),
        80: ("HTTP", Severity.INFO, "HTTP exposto (considerar HTTPS)"),
        110: ("POP3", Severity.INFO, "POP3 exposto"),
        143: ("IMAP", Severity.INFO, "IMAP exposto"),
        443: ("HTTPS", Severity.INFO, "HTTPS normal"),
        445: ("SMB", Severity.HIGH, "SMB exposto é vulnerável a ataques"),
        465: ("SMTPS", Severity.INFO, "SMTPS exposto"),
        587: ("SMTP Submission", Severity.INFO, "SMTP submission exposto"),
        993: ("IMAPS", Severity.INFO, "IMAPS exposto"),
        995: ("POP3S", Severity.INFO, "POP3S exposto"),
        1433: ("MSSQL", Severity.HIGH, "Microsoft SQL Server exposto"),
        1521: ("Oracle", Severity.HIGH, "Oracle Database exposto"),
        3306: ("MySQL", Severity.HIGH, "MySQL exposto na rede pública"),
        3389: ("RDP", Severity.HIGH, "RDP exposto é vulnerável a ataques"),
        5432: ("PostgreSQL", Severity.HIGH, "PostgreSQL exposto na rede pública"),
        5900: ("VNC", Severity.HIGH, "VNC exposto é vulnerável"),
        6379: ("Redis", Severity.HIGH, "Redis exposto sem autenticação"),
        8080: ("HTTP Proxy", Severity.MEDIUM, "Proxy HTTP exposto"),
        8443: ("HTTPS Alt", Severity.INFO, "Porta HTTPS alternativa"),
        8888: ("HTTP Alt", Severity.INFO, "Porta HTTP alternativa"),
        9200: ("Elasticsearch", Severity.HIGH, "Elasticsearch exposto pode vazar dados"),
        27017: ("MongoDB", Severity.HIGH, "MongoDB exposto na rede pública"),
    }

    # Portas mais críticas para AGGRESSIVE mode
    AGGRESSIVE_PORTS = list(range(1, 1001))  # Top 1000

    def __init__(self, timeout: int = 2):
        self.timeout = timeout

    async def scan(self, target: str, mode: str = "quick") -> List[Finding]:
        """
        Escaneia portas em um alvo

        Args:
            target: URL ou hostname
            mode: 'quick' (20 portas), 'full' (50 portas), 'aggressive' (1000 portas)

        Returns:
            Lista de Findings
        """
        findings = []

        hostname = self._extract_hostname(target)
        if not hostname:
            return findings

        # Determina portas a escanear
        if mode == "quick":
            ports_to_scan = list(self.COMMON_PORTS.keys())[:20]
        elif mode == "full":
            ports_to_scan = list(self.COMMON_PORTS.keys())[:50]
        else:  # aggressive
            ports_to_scan = self.AGGRESSIVE_PORTS

        # Escaneia portas em paralelo
        tasks = [self._check_port(hostname, port) for port in ports_to_scan]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for port, is_open in results:
            if isinstance(port, Exception) or not is_open:
                continue

            if port in self.COMMON_PORTS:
                name, severity, description = self.COMMON_PORTS[port]
                findings.append(Finding(
                    name=f"Porta Aberta: {port} ({name})",
                    severity=severity,
                    description=description,
                    location=f"{hostname}:{port}",
                    recommendation=self._get_recommendation(name, port)
                ))

        return findings

    async def _check_port(self, hostname: str, port: int) -> tuple:
        """Verifica se uma porta está aberta"""
        try:
            # Tenta conexão TCP
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(hostname, port),
                timeout=self.timeout
            )
            writer.close()
            await writer.wait_closed()
            return (port, True)

        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return (port, False)
        except Exception:
            return (port, False)

    def _extract_hostname(self, target: str) -> str:
        """Extrai hostname de URL"""
        try:
            if not target.startswith(('http://', 'https://')):
                target = f"https://{target}"

            parsed = urlparse(target)
            hostname = parsed.netloc.split(':')[0]

            # Resolve para IP
            return hostname

        except Exception:
            return ""

    def _get_recommendation(self, service: str, port: int) -> str:
        """Retorna recomendação baseada no serviço"""
        recommendations = {
            "FTP": "Desabilite FTP e use SFTP para transferência de arquivos",
            "Telnet": "Substitua Telnet por SSH com autenticação por chave",
            "SSH": "Use SSH com autenticação por chave efail2ban para proteção",
            "SMB": "Restrinja acesso SMB ou desabilite se não necessário",
            "MySQL": "Bind a localhost ou restrinja acesso por IP",
            "PostgreSQL": "Configure pg_hba.conf para permitir apenas IPs autorizados",
            "MSSQL": "Habilite autenticação Windows e restrinja rede",
            "Redis": "Habilite autenticação e bind a localhost",
            "MongoDB": "Habilite autenticação e TLS",
            "RDP": "Habilite NLA e use VPN para acesso",
            "VNC": "Substitua por solução mais segura ou use VPN",
            "Elasticsearch": "Habilite X-Pack security e autenticação",
        }

        base = recommendations.get(service, "Restrinja o acesso a esta porta")

        return f"{base}. Considere usar firewall para filtrar acessos."


class ServiceDetector:
    """Detecta serviços expostos através de fingerprints"""

    # Headers que revelam serviços
    SERVICE_HEADERS = {
        "server": "Servidor web",
        "x-powered-by": "Tecnologia backend",
        "x-aspnet-version": "ASP.NET",
        "x-aspnetmvc-version": "ASP.NET MVC",
        "x-jenkins": "Jenkins",
        "x-genesis-app": "Genesis App",
    }

    # Banners comuns
    BANNER_PATTERNS = {
        b"SSH-": "SSH",
        b"FTP": "FTP",
        b"220": "FTP",
        b"SMTP": "SMTP",
        b"POP3": "POP3",
        b"IMAP": "IMAP",
        b"HTTP": "HTTP",
        b"<title>Jenkins</title>": "Jenkins",
        b"swagger-ui": "Swagger/OpenAPI",
        b"phpinfo": "PHPInfo",
        b"WordPress": "WordPress",
        b"Drupal": "Drupal",
        b"Joomla": "Joomla",
    }

    def __init__(self, timeout: int = 10):
        self.timeout = timeout

    async def detect(self, target: str) -> List[Finding]:
        """Detecta serviços expostos"""
        findings = []

        try:
            import httpx
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(target)
                headers = response.headers

                # Verifica headers informativos
                for header, service in self.SERVICE_HEADERS.items():
                    if header.lower() in headers:
                        value = headers[header.lower()]
                        findings.append(Finding(
                            name=f"Informação Exposta: {service}",
                            severity=Severity.LOW,
                            description=f"Header {header} revela: {value}",
                            location=target,
                            recommendation=f"Oculte o header {header} para não revelar informações"
                        ))

        except Exception:
            pass

        return findings
