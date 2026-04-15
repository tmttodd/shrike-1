#!/bin/bash
# Shrike Deployment Script
# Deploys Shrike with fluent-bit for log ingestion

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=== Shrike Deployment ==="
echo "Directory: $SCRIPT_DIR"
echo ""

# Check prerequisites
echo "Checking prerequisites..."
command -v docker >/dev/null 2>&1 || { echo "❌ Docker not found"; exit 1; }
command -v docker compose >/dev/null 2>&1 || { echo "❌ Docker Compose not found"; exit 1; }

# Validate configuration files
echo "Validating configuration..."
python3 -c "import yaml; yaml.safe_load(open('docker-compose.yml'))" || { echo "❌ docker-compose.yml invalid"; exit 1; }
echo "✅ docker-compose.yml valid"

# Check fluent-bit config files exist
[ -f "fluent-bit/fluent-bit.conf" ] || { echo "❌ fluent-bit.conf missing"; exit 1; }
[ -f "fluent-bit/parsers.conf" ] || { echo "❌ parsers.conf missing"; exit 1; }
echo "✅ fluent-bit configs present"

# Build Shrike image
echo ""
echo "Building Shrike image..."
docker build -t shrike:latest . || { echo "❌ Build failed"; exit 1; }
echo "✅ Build successful"

# Check image size
IMAGE_SIZE=$(docker images shrike:latest --format "{{.Size}}")
echo "   Image size: $IMAGE_SIZE"

# Stop existing containers
echo ""
echo "Stopping existing containers..."
docker compose down --remove-orphans 2>/dev/null || true

# Start services
echo ""
echo "Starting services..."
docker compose up -d || { echo "❌ Failed to start services"; exit 1; }

# Wait for shrike to be healthy
echo ""
echo "Waiting for Shrike to be healthy..."
for i in {1..30}; do
    HEALTH=$(docker inspect shrike --format '{{.State.Health.Status}}' 2>/dev/null || echo "not-found")
    if [ "$HEALTH" = "healthy" ]; then
        echo "✅ Shrike is healthy"
        break
    fi
    if [ $i -eq 30 ]; then
        echo "❌ Shrike failed to become healthy"
        docker logs shrike --tail 50
        exit 1
    fi
    echo "   Waiting... ($i/30)"
    sleep 2
done

# Wait for fluent-bit to start
echo ""
echo "Waiting for fluent-bit to start..."
sleep 5
FB_STATUS=$(docker inspect fluent-bit --format '{{.State.Status}}' 2>/dev/null || echo "not-found")
if [ "$FB_STATUS" = "running" ]; then
    echo "✅ fluent-bit is running"
else
    echo "⚠️  fluent-bit status: $FB_STATUS"
    docker logs fluent-bit --tail 20
fi

# Run health checks
echo ""
echo "Running health checks..."

# 1. HTTP API health
HEALTH_CHECK=$(curl -s http://localhost:8080/health 2>/dev/null || echo '{"error":"failed"}')
if echo "$HEALTH_CHECK" | grep -q '"status":"healthy"'; then
    echo "✅ HTTP API health check passed"
else
    echo "❌ HTTP API health check failed: $HEALTH_CHECK"
fi

# 2. Test HTTP ingestion
echo ""
echo "Testing HTTP ingestion..."
INGEST_RESULT=$(curl -s -X POST http://localhost:8080/v1/ingest \
    -H "Content-Type: application/json" \
    -d '{"logs": ["e2e test message from deployment script"]}' 2>/dev/null || echo '{"error":"failed"}')
if echo "$INGEST_RESULT" | grep -q '"accepted"'; then
    echo "✅ HTTP ingestion test passed: $INGEST_RESULT"
else
    echo "❌ HTTP ingestion test failed: $INGEST_RESULT"
fi

# 3. Check WAL cursor
echo ""
echo "Checking WAL cursor..."
sleep 3
CURSOR=$(docker exec shrike cat /data/wal/splunk_hec.cursor 2>/dev/null || echo "not-found")
if [ "$CURSOR" != "not-found" ] && [ "$CURSOR" != "" ]; then
    echo "✅ WAL cursor: $CURSOR"
else
    echo "⚠️  WAL cursor not found or empty"
fi

# 4. Check fluent-bit logs
echo ""
echo "Checking fluent-bit logs..."
FB_LOGS=$(docker logs fluent-bit 2>&1 | tail -10)
if echo "$FB_LOGS" | grep -qi "error"; then
    echo "⚠️  fluent-bit has errors:"
    echo "$FB_LOGS" | grep -i error
else
    echo "✅ fluent-bit logs look clean"
fi

# Summary
echo ""
echo "=== Deployment Summary ==="
echo "Shrike image: $IMAGE_SIZE"
echo "Shrike status: $(docker inspect shrike --format '{{.State.Status}}' 2>/dev/null || echo 'unknown')"
echo "fluent-bit status: $FB_STATUS"
echo "HTTP API: $(curl -s -o /dev/null -w '%{http_code}' http://localhost:8080/health 2>/dev/null || echo 'unreachable')"
echo ""
echo "To view logs:"
echo "  docker compose logs -f shrike"
echo "  docker compose logs -f fluent-bit"
echo ""
echo "To test ingestion:"
echo "  curl -X POST http://localhost:8080/v1/ingest -H 'Content-Type: application/json' -d '{\"logs\": [\"test\"]}'"
echo ""
echo "✅ Deployment complete!"
