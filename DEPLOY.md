# ROOTX - Deploy Guide

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

### 3. Conectar Frontend + Backend

Após deploy do backend, pegar a URL (ex: `https://rootx-api.up.railway.app`)

No frontend em `scan.html` e `report.html`, alterar:
```javascript
const API_BASE = 'https://rootx-api.up.railway.app';
```

**Ou usar variáveis de ambiente na Vercel.**

---

## Domínio Personalizado (futuro)

- Vercel: Settings → Domains → adicionar `rootx.security`
- Railway: Settings → Networking → gerar domínio customizado

---

## Checklist de Produção

- [ ] Configurar `APP_ENV=production`
- [ ] Adicionar rate limiting no backend
- [ ] Configurar CORS para só aceitar seu domínio
- [ ] Adicionar logs/monitoring (Sentry)
- [ ] Configurar pagamento (Asaas/Stripe)
