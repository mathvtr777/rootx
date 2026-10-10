# ROOTX - Deploy Guide

## Ferramentas de Scan

O ROOTX utiliza ferramentas externas para scans profundos. **São opcionais mas recomendadas** para scans completos:

### Nuclei (Scanner de Vulnerabilidades)
```bash
# Instalar Go primeiro (https://go.dev/dl/)

# Instalar Nuclei
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Atualizar templates
nuclei -update-templates

# Verificar instalação
nuclei -version
```

### Retire.js (Bibliotecas JS Vulneráveis)
```bash
# Instalar Node.js primeiro (https://nodejs.org/)

# Instalar retire globalmente
npm install -g retire

# Verificar instalação
retire --version
```

### DNS Resolver
```bash
pip install dnspython certifi
```

---

## Deploy Rápido

### 1. Frontend (Vercel)

```bash
# Instalar Vercel CLI
npm i -g vercel

# Deploy
cd frontend
vercel

# Seguir as instruções (Login, Projeto, etc.)
```

**Ou pelo GitHub:**
1. Subir código no GitHub
2. Ir em vercel.com → New Project → Import do GitHub
3. Deploy automático

### 2. Backend (Railway)

1. Ir em railway.app
2. Login com GitHub
3. New Project → Deploy from GitHub repo
4. Selecionar o repositório `rootx`
5. Railway detecta Python automaticamente
6. Configurar:
   - Start Command: `uvicorn app.main:app --host 0.0.0.0 --port $PORT`
   - Variables: adicionar `PYTHON_VERSION = 3.11`
7. Deploy!

**Nota:** Para tools de scan profundas, considere usar um VPS próprio ou container Docker com as ferramentas instaladas.

### 3. Conectar Frontend + Backend

Após deploy do backend, pegar a URL (ex: `https://rootx-api.up.railway.app`)

No frontend em `scan.html` e `report.html`, alterar:
```javascript
const API_BASE = 'https://rootx-api.up.railway.app';
```

**Ou usar variáveis de ambiente na Vercel.**

---

## Docker (Completo com Tools)

Para ambiente completo com Nuclei e Retire.js:

```dockerfile
FROM python:3.11-slim

# Instalar Go para Nuclei
RUN apt-get update && apt-get install -y golang-go

# Instalar Node para Retire.js
RUN apt-get install -y nodejs npm

# Instalar Nuclei
RUN go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Instalar Retire.js
RUN npm install -g retire

# Copiar código
COPY . /app
WORKDIR /app
RUN pip install -r requirements.txt

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

---

## Modos de Scan

O ROOTX possui 3 modos de scan com escopo diferente:

| Modo | Tempo | Escopo |
|------|-------|--------|
| **Quick** | ~30s | Headers, tecnologias, secrets, paths críticos, SSL básico |
| **Full** | ~3min | + Nuclei, Retire.js, crawling, subdomínios, DNS |
| **Aggressive** | ~10min | + Enumeração, port scanning, WAF detection |

---

## Domínio Personalizado (futuro)

- Vercel: Settings → Domains → adicionar `rootx.security`
- Railway: Settings → Networking → gerar domínio customizado

---

## Checklist de Produção

- [x] Configurar `APP_ENV=production`
- [ ] Adicionar rate limiting no backend
- [ ] Configurar CORS para só aceitar seu domínio
- [ ] Adicionar logs/monitoring (Sentry)
- [ ] Configurar pagamento (Asaas/Stripe)
- [ ] Instalar Nuclei e Retire.js para scans completos
