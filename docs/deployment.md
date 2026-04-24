# Shrike Deployment Guide

This guide covers deploying Shrike in production using Docker Compose, Kubernetes, or as a systemd service. Every section is self-contained so you can skip to the method you need.

---

## Table of Contents

- [Docker Compose](#docker-compose)
- [Kubernetes](#kubernetes)
- [systemd Service](#systemd-service)
- [Environment Variables](#environment-variables)
- [TLS and Reverse Proxy](#tls-and-reverse-proxy)
- [Health Checks](#health-checks)

---

## Docker Compose

Docker Compose is the simplest way to run Shrike with all features (HTTP API, syslog, OTLP, destination routing). The repository ships with a `docker-compose.yml` at the project root.

### Quick Start

```bash
git clone https://github.com/overlabbed-com/shrike.git && cd shrike

# Optional: download ML models for classification and NER (pattern-only mode works without them)
./scripts/download_models.sh

# Start
docker compose up -d

# Verify
curl -s http://localhost:8080/health | python3 -m json.tool
```

### Production Configuration

Copy the compose file and tailor it for your environment. The minimal production setup requires setting destination credentials and an ingest API key.

```yaml
services:
  shrike:
    build: .
    # Or use a pre-built image:
    # image: ghcr.io/overlabbed-com/shrike:latest
    container_name: shrike
    restart: unless-stopped
    ports:
      - "8080:8080"   # HTTP API
      - "1514:1514"   # Syslog (TCP)
      - "1514:1514/udp" # Syslog (UDP)
      - "4317:4317"   # OTLP gRPC
      - "4318:4318"   # OTLP HTTP
    environment:
      - SHRIKE_DESTINATIONS=splunk_hec
      - SPLUNK_HEC_URL=https://splunk.example.com:8088
      - SPLUNK_HEC_TOKEN=${SPLUNK_HEC_TOKEN}
      - SHRIKE_SPLUNK_TLS_VERIFY=true
      - INGEST_API_KEY=${INGEST_API_KEY}
      - SHRIKE_WAL_DIR=/data/wal
      - SHRIKE_WAL_MAX_MB=2048
    volumes:
      - shrike-data:/data
    healthcheck:
      test: ["CMD", "curl", "-sf", "http://localhost:8080/health"]
      interval: 30s
      timeout: 5s
      start_period: 30s
      retries: 3
    logging:
      driver: json-file
      options:
        max-size: "50m"
        max-file: "3"

volumes:
  shrike-data:
```

Store secrets in a `.env` file next to `docker-compose.yml` or use your preferred secret manager (1Password Connect, HashiCorp Vault, Docker secrets). Never commit `.env` files.

### Multi-Destination Example

Shrike can fan out to multiple destinations simultaneously. Set `SHRIKE_DESTINATIONS` to a comma-separated list:

```yaml
environment:
  - SHRIKE_DESTINATIONS=splunk_hec,file_jsonl
  - SPLUNK_HEC_URL=https://splunk.example.com:8088
  - SPLUNK_HEC_TOKEN=${SPLUNK_HEC_TOKEN}
  - FILE_OUTPUT_DIR=/data/output
```

### Model-Only Mode (No ML)

If you do not need ML-based classification or NER, skip the model download. The container runs in pattern-only mode using 2,052 YAML patterns across 133 files. This also reduces the image size by approximately 830MB.

---

## Kubernetes

This section provides production-grade Kubernetes manifests with resource limits, health probes, and secret management.

### Namespace and ServiceAccount

```yaml
# k8s/namespace.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: shrike
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: shrike
  namespace: shrike
automountServiceAccountToken: false
```

### Secrets

```yaml
# k8s/secrets.yaml
apiVersion: v1
kind: Secret
metadata:
  name: shrike-secrets
  namespace: shrike
type: Opaque
stringData:
  splunk-hec-token: "your-splunk-hec-token"
  ingest-api-key: "your-ingest-api-key"
```

Generate a strong ingest key: `openssl rand -hex 32`.

### ConfigMap

```yaml
# k8s/configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: shrike-config
  namespace: shrike
data:
  SHRIKE_DESTINATIONS: "splunk_hec"
  SPLUNK_HEC_URL: "https://splunk.example.com:8088"
  SHRIKE_SPLUNK_TLS_VERIFY: "true"
  SHRIKE_WAL_DIR: "/data/wal"
  SHRIKE_WAL_MAX_MB: "2048"
  SHRIKE_HTTP_PORT: "8080"
```

### Deployment

```yaml
# k8s/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: shrike
  namespace: shrike
  labels:
    app: shrike
spec:
  replicas: 2
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxUnavailable: 0
      maxSurge: 1
  selector:
    matchLabels:
      app: shrike
  template:
    metadata:
      labels:
        app: shrike
    spec:
      serviceAccountName: shrike
      containers:
        - name: shrike
          image: ghcr.io/overlabbed-com/shrike:latest
          imagePullPolicy: Always
          ports:
            - name: http
              containerPort: 8080
              protocol: TCP
            - name: syslog-tcp
              containerPort: 1514
              protocol: TCP
            - name: syslog-udp
              containerPort: 1514
              protocol: UDP
            - name: otlp-grpc
              containerPort: 4317
              protocol: TCP
            - name: otlp-http
              containerPort: 4318
              protocol: TCP
          envFrom:
            - configMapRef:
                name: shrike-config
          env:
            - name: SPLUNK_HEC_TOKEN
              valueFrom:
                secretKeyRef:
                  name: shrike-secrets
                  key: splunk-hec-token
            - name: INGEST_API_KEY
              valueFrom:
                secretKeyRef:
                  name: shrike-secrets
                  key: ingest-api-key
          resources:
            requests:
              cpu: "500m"
              memory: "1Gi"
            limits:
              cpu: "2000m"
              memory: "4Gi"
          livenessProbe:
            httpGet:
              path: /health
              port: http
            initialDelaySeconds: 30
            periodSeconds: 30
            timeoutSeconds: 5
            failureThreshold: 3
          readinessProbe:
            httpGet:
              path: /ready
              port: http
            initialDelaySeconds: 10
            periodSeconds: 10
            timeoutSeconds: 3
            failureThreshold: 3
          volumeMounts:
            - name: data
              mountPath: /data
      volumes:
        - name: data
          emptyDir:
            sizeLimit: 5Gi
```

### Service

```yaml
# k8s/service.yaml
apiVersion: v1
kind: Service
metadata:
  name: shrike
  namespace: shrike
spec:
  selector:
    app: shrike
  ports:
    - name: http
      port: 8080
      targetPort: 8080
    - name: syslog-tcp
      port: 1514
      targetPort: 1514
    - name: syslog-udp
      port: 1514
      targetPort: 1514
      protocol: UDP
    - name: otlp-grpc
      port: 4317
      targetPort: 4317
    - name: otlp-http
      port: 4318
      targetPort: 4318
  type: ClusterIP
```

### Ingress (optional)

For external HTTP access behind an ingress controller:

```yaml
# k8s/ingress.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: shrike
  namespace: shrike
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
spec:
  ingressClassName: nginx
  tls:
    - hosts:
        - shrike.example.com
      secretName: shrike-tls
  rules:
    - host: shrike.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: shrike
                port:
                  name: http
```

### Persistent Storage

Replace the `emptyDir` volume with a `persistentVolumeClaim` if you need WAL and output data to survive pod restarts:

```yaml
# k8s/pvc.yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: shrike-data
  namespace: shrike
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 10Gi
```

Then reference it in the Deployment spec:

```yaml
volumes:
  - name: data
    persistentVolumeClaim:
      claimName: shrike-data
```

### Applying Everything

```bash
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/secrets.yaml
kubectl apply -f k8s/configmap.yaml
kubectl apply -f k8s/pvc.yaml
kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/service.yaml
kubectl apply -f k8s/ingress.yaml
```

---

## systemd Service

For bare-metal or VM deployment, run Shrike directly via systemd. This assumes you have installed Shrike with pip and downloaded ML models.

### Install Shrike

```bash
# Create a dedicated user
sudo useradd --system --no-create-home --shell /usr/sbin/nologin shrike

# Install dependencies
sudo apt-get install -y python3-pip python3-venv curl

# Create virtual environment
sudo python3 -m venv /opt/shrike/venv
sudo /opt/shrike/venv/pip install -e /path/to/shrike

# Create data directories
sudo mkdir -p /opt/shrike/data/wal /opt/shrike/data/output
sudo chown -R shrike:shrike /opt/shrike
```

### Unit File

```ini
# /etc/systemd/system/shrike.service
[Unit]
Description=Shrike Security Data Platform
Documentation=https://github.com/overlabbed-com/shrike
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=shrike
Group=shrike
WorkingDirectory=/opt/shrike
ExecStart=/opt/shrike/venv/bin/python -m shrike.runtime
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal

# Environment variables -- use environment.d for secrets
Environment=SHRIKE_HTTP_PORT=8080
Environment=SHRIKE_DESTINATIONS=splunk_hec
Environment=SHRIKE_WAL_DIR=/opt/shrike/data/wal
Environment=SHRIKE_WAL_MAX_MB=2048
Environment=FILE_OUTPUT_DIR=/opt/shrike/data/output
EnvironmentFile=/etc/shrike/secrets.env

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/shrike/data
PrivateTmp=true
MemoryDenyWriteExecute=true

# Health check via systemd
ExecStartPre=/bin/sh -c "curl -sf http://localhost:8080/health || true"

[Install]
WantedBy=multi-user.target
```

### Secrets File

Store sensitive values in a separate file owned by root:

```bash
sudo mkdir -p /etc/shrike
sudo tee /etc/shrike/secrets.env > /dev/null <<EOF
SPLUNK_HEC_URL=https://splunk.example.com:8088
SPLUNK_HEC_TOKEN=your-splunk-hec-token
INGEST_API_KEY=your-ingest-api-key
EOF

sudo chmod 600 /etc/shrike/secrets.env
sudo chown root:shrike /etc/shrike/secrets.env
```

### Enable and Start

```bash
sudo systemctl daemon-reload
sudo systemctl enable shrike
sudo systemctl start shrike

# Check status
sudo systemctl status shrike

# View logs
journalctl -u shrike -f
```

---

## Environment Variables

All configuration is loaded from environment variables. Shrike validates required fields at startup and exits with an error if mandatory values for configured destinations are missing.

### Core Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `SHRIKE_MODE` | `full` | Operating mode: `full` (server with all ingestion), `pipeline` (API only), `forwarder` (syslog/OTLP forwarding) |
| `SHRIKE_HTTP_PORT` | `8080` | Port for the HTTP API |
| `SHRIKE_SYSLOG_PORT` | `1514` | Port for syslog ingestion (TCP and UDP) |
| `SHRIKE_OTLP_GRPC_PORT` | `4317` | Port for OTLP gRPC ingestion |
| `SHRIKE_OTLP_HTTP_PORT` | `4318` | Port for OTLP HTTP ingestion |
| `SHRIKE_FORWARD_TO` | *(empty)* | Forwarding target URL (required when `SHRIKE_MODE=forwarder`) |
| `SHRIKE_DESTINATIONS` | `splunk_hec` | Comma-separated list of output destinations: `splunk_hec`, `file_jsonl`, `s3` |
| `SHRIKE_INGEST_API_KEY` | *(empty)* | Bearer token for `POST /v1/ingest`. If empty, the endpoint is open. |
| `SHRIKE_RATE_LIMIT_PER_CLIENT` | `100/minute` | Per-client rate limit for ingestion endpoints |

### Write-Ahead Log

| Variable | Default | Description |
|----------|---------|-------------|
| `SHRIKE_WAL_DIR` | `/data/wal` | Directory for write-ahead log files. Must be writable by the Shrike process. |
| `SHRIKE_WAL_MAX_MB` | `500` | Maximum WAL size in MB before rollover. |

### Splunk HEC Destination

Required when `splunk_hec` is in `SHRIKE_DESTINATIONS`.

| Variable | Default | Description |
|----------|---------|-------------|
| `SPLUNK_HEC_URL` | *(required)* | Full URL to the Splunk HEC endpoint, e.g. `https://splunk.example.com:8088` |
| `SPLUNK_HEC_TOKEN` | *(required)* | HEC authentication token |
| `SHRIKE_SPLUNK_TLS_VERIFY` | `true` | Set to `false` to skip TLS certificate verification (not recommended in production) |

### S3 / MinIO Destination

Required when `s3` is in `SHRIKE_DESTINATIONS`.

| Variable | Default | Description |
|----------|---------|-------------|
| `S3_ENDPOINT` | *(required)* | S3-compatible endpoint URL, e.g. `https://s3.amazonaws.com` or `http://minio.example.com:9000` |
| `S3_BUCKET` | *(required)* | Bucket name for OCSF event storage |
| `S3_ACCESS_KEY` | *(required)* | Access key for the S3-compatible service |
| `S3_SECRET_KEY` | *(required)* | Secret key for the S3-compatible service |
| `S3_FORMAT` | `parquet` | Output format: `parquet` (default) |

### File JSONL Destination

Used when `file_jsonl` is in `SHRIKE_DESTINATIONS`.

| Variable | Default | Description |
|----------|---------|-------------|
| `FILE_OUTPUT_DIR` | `/data/output` | Directory where JSONL files are written. Events are organized by OCSF category subdirectories (e.g., `iam/`, `network_activity/`). |

### ML Models

| Variable | Default | Description |
|----------|---------|-------------|
| `SHRIKE_CLASSIFIER_MODEL` | Auto-discovered | Path to the OCSF classifier model directory. Auto-discovers `models/ocsf-classifier/` in the project root. |
| `SHRIKE_NER_MODEL` | Auto-discovered | Path to the NER model directory. Auto-discovers `models/shrike-ner/` in the project root. |

### LLM Extraction (Optional)

Enables Tiers 2 and 3 of the extraction engine. Any OpenAI-compatible API works (Ollama, vLLM, LiteLLM, OpenAI).

| Variable | Default | Description |
|----------|---------|-------------|
| `SHRIKE_LLM_URL` | *(empty)* | Base URL for an OpenAI-compatible API, e.g. `http://localhost:11434/v1` |
| `SHRIKE_LLM_MODEL` | `shrike-extractor` | Model name to use for LLM extraction |
| `SHRIKE_LLM_API_KEY` | *(empty)* | API key for the LLM endpoint (if required) |

### Forwarder TLS

| Variable | Default | Description |
|----------|---------|-------------|
| `SHRIKE_FORWARDER_TLS_INSECURE` | `false` | Set to `true` to skip TLS verification when forwarding (not recommended) |

### Webhook (Optional)

| Variable | Default | Description |
|----------|---------|-------------|
| `WEBHOOK_URL` | *(empty)* | Webhook endpoint URL for event notifications |
| `WEBHOOK_AUTH_TOKEN` | *(empty)* | Bearer token for webhook authentication |

---

## TLS and Reverse Proxy

Shrike listens on plain HTTP on all ports. Terminate TLS at the reverse proxy layer and forward traffic to Shrike. This section shows examples for Caddy and Nginx.

### Caddy

Caddy handles TLS automatically via Let's Encrypt. Place this in your Caddyfile:

```caddyfile
shrike.example.com {
    # Automatic TLS via Let's Encrypt
    encode gzip

    # Restrict to internal network (optional)
    @internal not remote_ip private

    # API endpoints
    reverse_proxy shrike:8080 {
        health_uri /health
        health_interval 30s
    }

    # Optional: restrict ingest to authenticated clients
    @ingest path /v1/ingest
    authenticate @ingest
}
```

With IP allowlist instead of auth:

```caddyfile
shrike.example.com {
    encode gzip

    # Only allow log forwarders from known IPs
    @allowed remote_ip 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16
    respond @not_allowed 403 {
        @not_allowed not @allowed
    }

    reverse_proxy shrike:8080
}
```

### Nginx

```nginx
upstream shrike {
    server shrike:8080;
    keepalive 32;
}

server {
    listen 443 ssl http2;
    server_name shrike.example.com;

    ssl_certificate     /etc/ssl/certs/shrike.example.com.crt;
    ssl_certificate_key /etc/ssl/private/shrike.example.com.key;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;

    # Rate limiting zone
    limit_req_zone $binary_remote_addr zone=shrike:10m rate=200r/s;

    location / {
        limit_req zone=shrike burst=50 nodelay;

        proxy_pass http://shrike;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Health check endpoint (exclude from rate limiting)
        location /health {
            proxy_pass http://shrike;
            access_log off;
        }

        location /ready {
            proxy_pass http://shrike;
            access_log off;
        }
    }

    # Large request body for batch log ingestion (up to 50MB)
    client_max_body_size 50m;
}

# Redirect HTTP to HTTPS
server {
    listen 80;
    server_name shrike.example.com;
    return 301 https://$host$request_uri;
}
```

### Syslog Behind the Proxy

Reverse proxies typically handle TCP/HTTP, not raw syslog or OTLP. For syslog and OTLP ingestion, either:

1. **Expose ports directly** on the host (with firewall rules restricting source IPs)
2. **Use a TCP proxy** like HAProxy or Envoy for TLS termination on syslog/OTLP ports
3. **Route all ingestion through HTTP** (`POST /v1/ingest`) when possible

Example HAProxy config for syslog TLS termination:

```
frontend syslog_tls
    bind *:1514 ssl crt /etc/ssl/certs/shrike.pem
    default_backend shrike_syslog

backend shrike_syslog
    server shrike1 shrike:1514 check inter 10s fall 3 rise 2
```

---

## Health Checks

Shrike exposes two health endpoints on the HTTP port (default `8080`).

### GET /health

Returns the overall system health status, including destination connectivity and pipeline state.

**Response when fully operational:**

```json
{
  "status": "healthy",
  "pipeline": "active",
  "destinations": {
    "splunk_hec": {
      "healthy": true,
      "pending": 0,
      "disk_usage_mb": 12.45
    }
  }
}
```

**Response when a destination is degraded:**

```json
{
  "status": "degraded",
  "pipeline": "active",
  "destinations": {
    "splunk_hec": {
      "healthy": false,
      "pending": 1250,
      "disk_usage_mb": 487.32
    },
    "file_jsonl": {
      "healthy": true,
      "pending": 0,
      "disk_usage_mb": 5.12
    }
  }
}
```

**Response when running in pattern-only mode (no ML models):**

```json
{
  "status": "healthy",
  "pipeline": "passthrough",
  "destinations": {}
}
```

**HTTP status:** Always `200` (the `status` field indicates healthy vs. degraded).

**Use as a liveness probe.** The endpoint checks that the HTTP server is running and reports on destination workers.

### GET /ready

Returns whether the service can accept traffic. This is a lighter check than `/health` and verifies that required filesystem paths are accessible.

**Ready:**

```json
{
  "ready": true
}
```

**Not ready (HTTP 503):**

```json
{
  "ready": false,
  "reason": "WAL dir not accessible: /data/wal"
}
```

**Use as a readiness probe.** Kubernetes and Docker both support this pattern: send traffic only when `/ready` returns `200`.

### Probe Configuration Summary

| Probe Type | Endpoint | Method | Success Criteria |
|------------|----------|--------|-----------------|
| Liveness | `/health` | GET | HTTP 200 (server is running) |
| Readiness | `/ready` | GET | HTTP 200 with `{"ready": true}` |

Recommended probe intervals:

| Setting | Liveness | Readiness |
|---------|----------|-----------|
| Initial delay | 30s | 10s |
| Period | 30s | 10s |
| Timeout | 5s | 3s |
| Failure threshold | 3 | 3 |
| Success threshold | 1 | 1 |
