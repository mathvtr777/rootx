FROM python:3.11-slim

WORKDIR /app

# Atualizar e instalar dependências do sistema
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Instalar Nuclei
RUN curl -sL https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_linux_amd64.zip | \
    zcat > /usr/local/bin/nuclei && \
    chmod +x /usr/local/bin/nuclei

# Instalar templates do Nuclei
RUN nuclei -update-templates

# Copiar requirements e instalar
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copiar código
COPY app/ ./app/

# Expor porta
EXPOSE 8000

# Comando
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
