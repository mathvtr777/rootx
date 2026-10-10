"""
Analisador de SSL/TLS
Verifica configurações de certificado e protocolo
"""
import asyncio
import ssl
import socket
import certifi
import json
from datetime import datetime, timezone
from typing import List, Optional, Tuple
from urllib.parse import urlparse
from .models import Finding, Severity


class SSLAnalyzer:
    """Analisador de configurações SSL/TLS"""

    def __init__(self, timeout: int = 30):
        self.timeout = timeout

    async def analyze(self, url: str) -> List[Finding]:
        """
        Analisa configuração SSL/TLS de um site

        Args:
            url: URL para analisar

        Returns:
            Lista de Findings
        """
        findings = []

        try:
            parsed = urlparse(url)
            host = parsed.netloc.split(':')[0] if parsed.netloc else None

            if not host:
                return findings

            # Determina porta
            port = 443
            if ':' in parsed.netloc:
                port = int(parsed.netloc.split(':')[1])

            # Realiza análise SSL
            cert_info = await self._get_certificate_info(host, port)

            if cert_info:
                findings.extend(self._check_certificate(cert_info, host))
                findings.extend(await self._check_ssl_config(host, port))

        except Exception as e:
            findings.append(Finding(
                name="Erro na análise SSL",
                severity=Severity.INFO,
                description=f"Não foi possível analisar SSL: {str(e)}",
                location=url,
                recommendation="Verifique se o site usa HTTPS"
            ))

        return findings

    async def _get_certificate_info(self, host: str, port: int) -> Optional[dict]:
        """Obtém informações do certificado SSL"""
        try:
            # Cria contexto SSL com verificação
            context = ssl.create_default_context(cafile=certifi.where())

            # Conecta
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=context),
                timeout=self.timeout
            )

            # Obtém certificado
            transport = writer.get_extra_info('ssl_object')
            if transport:
                cert = transport.getpeercert(binary_form=True)
                if cert:
                    return self._parse_certificate(cert, host)

            writer.close()
            await writer.wait_closed()

        except asyncio.TimeoutError:
            pass
        except Exception:
            pass

        return None

    def _parse_certificate(self, cert_der: bytes, host: str) -> dict:
        """Faz parse do certificado DER"""
        try:
            import cryptography.x509
            from cryptography.hazmat.backends import default_backend

            cert = cryptography.x509.load_der_x509_certificate(cert_der, default_backend())

            # Extrai informações
            subject = {}
            for attr in cert.subject:
                subject[attr.oid._name] = attr.value

            issuer = {}
            for attr in cert.issuer:
                issuer[attr.oid._name] = attr.value

            # Verifica SANs
            san_list = []
            try:
                san_ext = cert.extensions.get_extension_for_oid(
                    cryptography.x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
                )
                san_list = [name.value for name in san_ext.value]
            except Exception:
                pass

            return {
                "subject": subject,
                "issuer": issuer,
                "not_before": cert.not_valid_before_utc,
                "not_after": cert.not_valid_after_utc,
                "san": san_list,
                "host": host,
                "serial_number": cert.serial_number,
            }
        except Exception:
            return None

    def _check_certificate(self, cert_info: dict, host: str) -> List[Finding]:
        """Verifica problemas no certificado"""
        findings = []

        now = datetime.now(timezone.utc)

        # Certificado expirado
        if cert_info["not_after"] < now:
            days_expired = (now - cert_info["not_after"]).days
            findings.append(Finding(
                name="Certificado SSL Expirado",
                severity=Severity.CRITICAL,
                description=f"Certificado expirou há {days_expired} dias",
                location=f"https://{host}",
                recommendation="Renove o certificado SSL imediatamente"
            ))
        # Certificado prestes a expirar
        elif cert_info["not_after"] < now.replace(day=now.day + 30):
            days_left = (cert_info["not_after"] - now).days
            findings.append(Finding(
                name="Certificado SSL Prestes a Expirar",
                severity=Severity.MEDIUM,
                description=f"Certificado expira em {days_left} dias",
                location=f"https://{host}",
                recommendation=f"Renove o certificado em até {days_left} dias"
            ))

        # Emissor auto-assinado ou não confiável
        issuer_cn = cert_info["issuer"].get("commonName", "")
        if "self" in issuer_cn.lower() or issuer_cn == "":
            findings.append(Finding(
                name="Certificado Auto-Assinado",
                severity=Severity.MEDIUM,
                description="O certificado é auto-assinado e não é confiável por padrão",
                location=f"https://{host}",
                recommendation="Use um certificado de uma CA confiável (Let's Encrypt, etc)"
            ))

        # Hostname mismatch
        if host not in cert_info.get("san", []) and host != cert_info["subject"].get("commonName", ""):
            findings.append(Finding(
                name="Hostname Mismatch no Certificado",
                severity=Severity.HIGH,
                description=f"O certificado não é válido para {host}",
                location=f"https://{host}",
                recommendation="Gere um certificado válido para este domínio"
            ))

        # Verifica issuer
        issuer_org = cert_info["issuer"].get("organizationName", "")
        trusted_cas = ["Let's Encrypt", "DigiCert", "GoDaddy", "Comodo", "GlobalSign", "Symantec"]
        if issuer_org and not any(trusted in issuer_org for trusted in trusted_cas):
            findings.append(Finding(
                name="Emissor de Certificado Pouco Comum",
                severity=Severity.LOW,
                description=f"Certificado emitido por: {issuer_org}",
                location=f"https://{host}",
                recommendation="Verifique se o emissor é confiável"
            ))

        return findings

    async def _check_ssl_config(self, host: str, port: int) -> List[Finding]:
        """Verifica configurações SSL/TLS (protocolos, ciphers)"""
        findings = []

        try:
            # Tenta conectar com diferentes versões de TLS
            protocols = {
                "SSL v3": ssl.PROTOCOL_SSLv23,  # Usado para detectar SSLv3
                "TLS 1.0": None,
                "TLS 1.1": None,
                "TLS 1.2": ssl.TLSv12,
                "TLS 1.3": ssl.TLSv13,
            }

            # Verifica SSLv3 (muito inseguro)
            try:
                context_ssl3 = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
                context_ssl3.minimum_version = ssl.TLSVersion.SSLv3
                context_ssl3.maximum_version = ssl.TLSVersion.SSLv3

                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port, ssl=context_ssl3),
                    timeout=5
                )
                writer.close()
                findings.append(Finding(
                    name="SSLv3 Habilitado",
                    severity=Severity.CRITICAL,
                    description="SSLv3 está habilitado. Este protocolo é vulnerável ao POODLE.",
                    location=f"https://{host}",
                    recommendation="Desabilite SSLv3 imediatamente"
                ))
            except (ssl.SSLError, asyncio.TimeoutError, OSError):
                pass  # SSLv3 não está disponível, bom

            # Verifica TLS 1.0 e 1.1 (deprecados)
            for tls_version, name in [("TLS 1.0", "TLS1.0"), ("TLS 1.1", "TLS1.1")]:
                try:
                    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    context.minimum_version = ssl.TLSVersion.TLSv1
                    context.maximum_version = getattr(ssl.TLSVersion, name)

                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(host, port, ssl=context),
                        timeout=5
                    )
                    writer.close()

                    findings.append(Finding(
                        name=f"{tls_version} Habilitado",
                        severity=Severity.LOW,
                        description=f"{tls_version} está habilitado. Este protocolo é considerado obsoleto.",
                        location=f"https://{host}",
                        recommendation="Desabilite TLS 1.0 e 1.1, use apenas TLS 1.2+"
                    ))
                except (ssl.SSLError, asyncio.TimeoutError, OSError):
                    pass  # TLS específico não está disponível

        except Exception:
            pass

        return findings


class TLSScanner:
    """Scanner alternativo usando testssl.sh se disponível"""

    def __init__(self, timeout: int = 120):
        self.timeout = timeout
        self.testssl_path = "testssl.sh"  # ou caminho para o script

    async def quick_scan(self, host: str) -> List[Finding]:
        """Scan rápido de SSL usando testssl.sh"""
        findings = []

        try:
            import subprocess

            cmd = [self.testssl_path, "--jsonfile", "/tmp/testssl.json", host]

            result = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await asyncio.wait_for(
                result.communicate(),
                timeout=self.timeout
            )

            # Parse JSON output se existir
            try:
                with open("/tmp/testssl.json", "r") as f:
                    data = json.load(f)
                    findings.extend(self._parse_testssl_output(data, host))
            except Exception:
                pass

        except FileNotFoundError:
            # testssl.sh não está instalado, usa SSLAnalyzer
            pass
        except Exception:
            pass

        return findings

    def _parse_testssl_output(self, data: list, host: str) -> List[Finding]:
        """Parse output do testssl.sh"""
        findings = []

        # Implementar parsing conforme formato do testssl
        # ...

        return findings
