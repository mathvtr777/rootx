"""
Enumeração de diretórios e arquivos
Busca caminhos comuns e arquivos sensíveis
"""
import asyncio
import httpx
from typing import List, Set
from urllib.parse import urlparse, urljoin
from .models import Finding, Severity


class DirectoryEnumerator:
    """Enumera diretórios e arquivos em um site"""

    # Diretórios comuns
    COMMON_DIRS = [
        # Admin
        "admin", "administrator", "admin/login", "adminpanel", "webadmin",
        "manage", "management", "dashboard", "control", "cpanel",
        # Login/Auth
        "login", "signin", "auth", "authentication", "logout", "register",
        "signup", "account", "accounts", "user", "users", "profile",
        # API
        "api", "api/v1", "api/v2", "api/v3", "api-docs", "api/swagger",
        "rest", "graphql", "graphiql", "console",
        # Backup/Config
        "backup", "backups", "config", "configuration", "settings",
        ".env", ".env.local", ".env.production", "config.php", "settings.php",
        # Dev
        "dev", "development", "test", "testing", "stage", "staging",
        "demo", "sandbox", "debug", "debugger",
        # Git/SVN
        ".git", ".git/config", ".git/HEAD", ".svn", ".svn/entries",
        ".hg", ".bzr",
        # Docs
        "docs", "documentation", "wiki", "readme", "README.md",
        # Server Info
        "server-status", "server-info", "status", "health", "ping",
        # Database
        "phpmyadmin", "adminer", "pgadmin", "mysql", "mongo", "redis",
        # Upload
        "upload", "uploads", "files", "images", "media", "attachments",
        # Old/Vulnerable
        "old", "archive", "backup-old", "tmp", "temp", "cache",
        # Cloud
        ".well-known", ".well-known/security.txt",
        # CMS
        "wp-admin", "wp-login.php", "wp-content", "wp-includes",
        "administrator", "joomla", "drupal", "magento",
    ]

    # Arquivos sensíveis
    SENSITIVE_FILES = [
        # Config
        ".env", ".env.local", ".env.dev", ".env.production",
        "config.php", "configuration.php", "settings.php", "db.php",
        "wp-config.php", "configuration.yml", "config.yml",
        "application.yml", "application.properties", "web.config",
        # Logs
        "access.log", "error.log", "debug.log", "logs.txt",
        ".log", "logs/", "log.txt",
        # Backup
        "backup.sql", "database.sql", "dump.sql", "data.sql",
        "backup.zip", "backup.tar", "backup.tar.gz", "site.zip",
        # Database tools
        "phpmyadmin", "adminer.php", "pgadmin", "robomongo",
        # Info disclosure
        "phpinfo.php", "info.php", "test.php", "debug.php",
        "readme.html", "README.md", "LICENSE.md",
        "CHANGELOG.txt", "VERSION",
        # IDE
        ".vscode/settings.json", ".idea/workspace.xml",
        ".vs/slnx.sqlite",
        # Docker
        "Dockerfile", "docker-compose.yml", ".dockerignore",
        # Cloud
        "aws.yml", "credentials", ".netrc",
    ]

    def __init__(self, timeout: int = 60):
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

    async def enumerate(self, target: str, mode: str = "quick") -> List[Finding]:
        """
        Enumera diretórios e arquivos

        Args:
            target: URL base
            mode: 'quick' (30 items), 'full' (80 items), 'aggressive' (todos)

        Returns:
            Lista de Findings
        """
        findings = []

        parsed = urlparse(target)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        base_path = parsed.path.rstrip('/') if parsed.path else ""

        # Determina itens a testar
        if mode == "quick":
            dirs_to_test = self.COMMON_DIRS[:15]
            files_to_test = self.SENSITIVE_FILES[:15]
        elif mode == "full":
            dirs_to_test = self.COMMON_DIRS[:30]
            files_to_test = self.SENSITIVE_FILES[:30]
        else:  # aggressive
            dirs_to_test = self.COMMON_DIRS
            files_to_test = self.SENSITIVE_FILES

        # Testa diretórios
        dir_tasks = [
            self._check_path(f"{base_url}{base_path}/{path}")
            for path in dirs_to_test
        ]
        dir_results = await asyncio.gather(*dir_tasks, return_exceptions=True)

        for path, status, content in dir_results:
            if isinstance(path, Exception):
                continue

            if status in [200, 201, 204]:
                finding = self._analyze_path(path, status, content)
                if finding:
                    findings.append(finding)

        # Testa arquivos
        file_tasks = [
            self._check_path(f"{base_url}{base_path}/{file}")
            for file in files_to_test
        ]
        file_results = await asyncio.gather(*file_tasks, return_exceptions=True)

        for path, status, content in file_results:
            if isinstance(path, Exception):
                continue

            if status in [200, 201, 204]:
                finding = self._analyze_path(path, status, content)
                if finding:
                    findings.append(finding)

        return findings

    async def _check_path(self, url: str) -> tuple:
        """Verifica se um caminho existe"""
        try:
            response = await self.client.get(url, timeout=self.timeout)

            content = ""
            if response.status_code == 200:
                content = response.text[:5000]  # Limita conteúdo

            return (url, response.status_code, content)

        except Exception as e:
            return (url, 0, "")

    def _analyze_path(self, path: str, status: int, content: str) -> Finding:
        """Analisa um caminho encontrado e retorna Finding se relevante"""

        # Arquivos críticos
        critical_patterns = [
            (".env", "Arquivo .env Exposto", Severity.CRITICAL,
             "Arquivo .env pode conter credenciais e secrets"),
            (".git/config", "Git Config Exposto", Severity.HIGH,
             "Diretório .git exposto pode vazar código fonte"),
            (".git/HEAD", "Git Repository Exposto", Severity.HIGH,
             "Repositório Git exposto pode vazar código fonte"),
            ("wp-config.php", "WordPress Config Exposto", Severity.CRITICAL,
             "Arquivo de configuração do WordPress exposto"),
            ("config.php", "Config PHP Exposto", Severity.HIGH,
             "Arquivo de configuração PHP exposto"),
            ("phpinfo.php", "PHPInfo Exposto", Severity.HIGH,
             "PHPInfo revela informações detalhadas do servidor"),
            ("debug.php", "Debug PHP Exposto", Severity.HIGH,
             "Página de debug pode revelar informações sensíveis"),
            ("phpmyadmin", "phpMyAdmin Exposto", Severity.CRITICAL,
             "phpMyAdmin exposto pode permitir acesso ao banco"),
            ("backup.sql", "Backup SQL Exposto", Severity.CRITICAL,
             "Backup de banco de dados exposto publicamente"),
            ("dump.sql", "Dump SQL Exposto", Severity.CRITICAL,
             "Dump SQL exposto pode conter dados sensíveis"),
            (".log", "Log File Exposto", Severity.MEDIUM,
             "Arquivo de log pode conter informações sensíveis"),
            ("credentials", "Arquivo de Credenciais Exposto", Severity.CRITICAL,
             "Arquivo de credenciais encontrado"),
            ("id_rsa", "Chave SSH Privada Exposta", Severity.CRITICAL,
             "Chave SSH privada exposta! Acesso não autorizado possível"),
        ]

        for pattern, name, severity, description in critical_patterns:
            if pattern in path.lower():
                return Finding(
                    name=name,
                    severity=severity,
                    description=description,
                    location=path,
                    recommendation=self._get_recommendation(pattern)
                )

        # Admin/Login expostos
        admin_patterns = ["admin", "login", "signin", "dashboard", "manage"]
        for pattern in admin_patterns:
            if f"/{pattern}" in path.lower():
                return Finding(
                    name=f"Página Sensível Exposta: {pattern.title()}",
                    severity=Severity.MEDIUM,
                    description=f"URL {pattern} está acessível publicamente",
                    location=path,
                    recommendation=f"Verifique se {pattern} deve ter restrição de acesso"
                )

        # API expostas
        if "/api" in path.lower():
            return Finding(
                name="API Endpoint Exposta",
                severity=Severity.INFO,
                description="Endpoint de API está acessível",
                location=path,
                recommendation="Verifique se esta API deve ser pública"
            )

        return None

    def _get_recommendation(self, pattern: str) -> str:
        """Retorna recomendação baseada no padrão"""
        recommendations = {
            ".env": "Remova o arquivo .env do diretório web e use variáveis de ambiente",
            ".git": "Adicione .git ao .htaccess ou desabilite acesso no nginx",
            ".git/config": "Remova diretórios .git ou bloqueie acesso via web server",
            ".git/HEAD": "Remova diretórios .git ou bloqueie acesso via web server",
            "wp-config.php": "Mova wp-config.php para fora do web root",
            "config.php": "Mova arquivos de configuração para fora do web root",
            "phpinfo.php": "Remova phpinfo.php imediatamente",
            "debug.php": "Desabilite páginas de debug em produção",
            "phpmyadmin": "Restrinja acesso ao phpMyAdmin via IP ou VPN",
            "backup.sql": "Remova backups de banco de dados do servidor web",
            "dump.sql": "Remova dumps SQL do servidor web",
            ".log": "Configure logs fora do web root ou bloqueie acesso",
            "credentials": "Remova este arquivo imediatamente e altere credenciais",
            "id_rsa": "Revogue esta chave imediatamente se comprometeram",
        }

        return recommendations.get(pattern, "Restrinja acesso a este arquivo")


class PathTraversalChecker:
    """Verifica vulnerabilidades de Path Traversal"""

    PAYLOADS = [
        "../../../etc/passwd",
        "..%2F..%2F..%2Fetc%2Fpasswd",
        "....//....//....//etc/passwd",
        "..\\..\\..\\windows\\system32\\config\\sam",
    ]

    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.client = httpx.AsyncClient(timeout=timeout, follow_redirects=False)

    async def close(self):
        await self.client.aclose()

    async def check(self, target: str) -> List[Finding]:
        """Verifica vulnerabilidade de Path Traversal"""
        findings = []

        for payload in self.PAYLOADS:
            try:
                test_url = f"{target.rstrip('/')}?file={payload}"
                response = await self.client.get(test_url, timeout=self.timeout)

                # Verifica se vazou conteúdo sensível
                if "root:" in response.text or "[boot loader]" in response.text:
                    findings.append(Finding(
                        name="Possível Vulnerabilidade Path Traversal",
                        severity=Severity.CRITICAL,
                        description="Parâmetro pode ser vulnerável a path traversal",
                        location=test_url,
                        recommendation="Valide e sanitiza todos os inputs de arquivo"
                    ))
                    break

            except Exception:
                pass

        return findings
