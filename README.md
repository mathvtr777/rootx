# ROOTX - Security Scanner SaaS

🎯 Scanner de vulnerabilidades para sites e webapps. Encontre falhas de segurança em segundos.

![ROOTX](https://img.shields.io/badge/ROOTX-Security-10b981?style=for-the-badge)

## Funcionalidades

- 🔍 Scan de vulnerabilidades automatizado
- 🔒 Análise de headers de segurança
- 🕵️ Detecção de secrets expostos
- 📦 Identificação de dependências vulnerables
- 📊 Relatório com score de segurança (0-100)
- 🤖 Recomendações powered by AI

## Tech Stack

- **Backend:** Python 3.11 / FastAPI
- **Scanner:** Nuclei, httpx, Retire.js
- **Frontend:** HTML5 + TailwindCSS
- **LLM:** Groq API (opcional)
- **Infra:** Railway + Vercel

## Quick Start

### Local

```bash
# Backend
cd backend
python -m venv venv
source venv/bin/activate  # ou venv\Scripts\activate no Windows
pip install -r requirements.txt
python -m app.main

# Acesse http://localhost:8000
```

### Docker

```bash
docker-compose up -d
```

## Deploy

Consulte [DEPLOY.md](DEPLOY.md) para instruções detalhadas.

```bash
# Frontend → Vercel
cd frontend && vercel deploy

# Backend → Railway
cd backend && railway up
```

## API

### POST /api/scan
Inicia um novo scan

```json
{
  "url": "https://exemplo.com",
  "scan_type": "quick|full|aggressive"
}
```

### GET /api/scan/{scan_id}
Verifica status do scan

### GET /api/scan/{scan_id}/report
Baixa relatório completo

## Uso

⚠️ **Importante:** Use apenas em sites que você tem autorização para testar.

## Licença

MIT
