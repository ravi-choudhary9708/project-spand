FROM python:3.11-slim

# Install system dependencies and scanning tools
RUN apt-get update && apt-get install -y \
    nmap \
    openssl \
    curl \
    wget \
    git \
    dnsutils \
    net-tools \
    iputils-ping \
    ca-certificates \
    unzip \
    bsdextrautils \
    procps \
    && rm -rf /var/lib/apt/lists/*

# Install testssl.sh
RUN curl -sL https://testssl.sh/testssl.sh -o /usr/local/bin/testssl.sh \
    && chmod +x /usr/local/bin/testssl.sh

# Install SSLyze via pip (included in requirements)
# Install subfinder
RUN wget -q https://github.com/projectdiscovery/subfinder/releases/download/v2.6.5/subfinder_2.6.5_linux_amd64.zip -O /tmp/subfinder.zip \
    && unzip /tmp/subfinder.zip -d /usr/local/bin/ \
    && chmod +x /usr/local/bin/subfinder \
    && rm /tmp/subfinder.zip

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Create scan results directory
RUN mkdir -p /app/scan_results

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
