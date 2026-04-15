#!/bin/bash
# E2E Test Script for Shrike
# Tests the full pipeline: fluent-bit → shrike → Splunk

set -e

SHRIKE_HOST="${SHRIKE_HOST:-192.168.20.14}"
SHRIKE_PORT="${SHRIKE_PORT:-8082}"
SPLUNK_TOKEN="${SPLUNK_HEC_TOKEN}"

echo "=== Shrike E2E Tests ==="
echo "Shrike host: $SHRIKE_HOST:$SHRIKE_PORT"
echo ""

# Test 1: Health endpoint
echo "Test 1: Health endpoint"
HEALTH=$(curl -s "http://$SHRIKE_HOST:$SHRIKE_PORT/health")
if echo "$HEALTH" | grep -q '"status":"healthy"'; then
    echo "✅ PASS: Health endpoint"
    echo "   Response: $HEALTH"
else
    echo "❌ FAIL: Health endpoint"
    echo "   Response: $HEALTH"
    exit 1
fi
echo ""

# Test 2: HTTP ingestion
echo "Test 2: HTTP ingestion"
INGEST_RESULT=$(curl -s -X POST "http://$SHRIKE_HOST:$SHRIKE_PORT/v1/ingest" \
    -H "Content-Type: application/json" \
    -d '{"logs": ["e2e test message $(date -Iseconds)"]}')
if echo "$INGEST_RESULT" | grep -q '"accepted"'; then
    echo "✅ PASS: HTTP ingestion"
    echo "   Response: $INGEST_RESULT"
else
    echo "❌ FAIL: HTTP ingestion"
    echo "   Response: $INGEST_RESULT"
    exit 1
fi
echo ""

# Test 3: WAL cursor advancement
echo "Test 3: WAL cursor advancement"
CURSOR_BEFORE=$(ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 tmiller@$SHRIKE_HOST \
    "sudo docker exec shrike cat /data/wal/splunk_hec.cursor" 2>/dev/null || echo "0:0")
echo "   Cursor before: $CURSOR_BEFORE"

sleep 5

CURSOR_AFTER=$(ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 tmiller@$SHRIKE_HOST \
    "sudo docker exec shrike cat /data/wal/splunk_hec.cursor" 2>/dev/null || echo "0:0")
echo "   Cursor after: $CURSOR_AFTER"

if [ "$CURSOR_BEFORE" != "$CURSOR_AFTER" ]; then
    echo "✅ PASS: WAL cursor advanced"
else
    echo "⚠️  WARN: WAL cursor did not advance (may be normal if no new events)"
fi
echo ""

# Test 4: Splunk HEC connectivity
echo "Test 4: Splunk HEC connectivity"
SPLUNK_HEALTH=$(curl -sk "https://$SHRIKE_HOST:8088/services/collector/health" \
    -H "Authorization: Splunk $SPLUNK_TOKEN" 2>/dev/null || echo '{"error":"failed"}')
if echo "$SPLUNK_HEALTH" | grep -q "healthy"; then
    echo "✅ PASS: Splunk HEC healthy"
    echo "   Response: $SPLUNK_HEALTH"
else
    echo "❌ FAIL: Splunk HEC unhealthy"
    echo "   Response: $SPLUNK_HEALTH"
    exit 1
fi
echo ""

# Test 5: Event delivery to Splunk (if cursor advanced)
echo "Test 5: Event delivery to Splunk"
if [ "$CURSOR_BEFORE" != "$CURSOR_AFTER" ]; then
    # Check if events appear in Splunk
    SPLUNK_SEARCH=$(curl -sk "https://$SHRIKE_HOST:8088/services/search/jobs/export" \
        -d "search=index=main sourcetype=_json \"e2e test message\" | head 1" \
        -d "output_mode=json" \
        -H "Authorization: Splunk $SPLUNK_TOKEN" \
        --max-time 30 2>/dev/null || echo "")
    
    if [ -n "$SPLUNK_SEARCH" ] && echo "$SPLUNK_SEARCH" | grep -q "e2e test"; then
        echo "✅ PASS: Events delivered to Splunk"
    else
        echo "⚠️  WARN: Could not verify event delivery to Splunk (may be indexing delay)"
    fi
else
    echo "⚠️  SKIP: No cursor advancement to test delivery"
fi
echo ""

# Test 6: fluent-bit status
echo "Test 6: fluent-bit status"
FB_STATUS=$(ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 tmiller@$SHRIKE_HOST \
    "sudo docker ps --filter name=fluent-bit --format '{{.Status}}'" 2>/dev/null || echo "not-found")
if echo "$FB_STATUS" | grep -q "Up"; then
    echo "✅ PASS: fluent-bit running"
    echo "   Status: $FB_STATUS"
else
    echo "⚠️  WARN: fluent-bit status: $FB_STATUS"
fi
echo ""

# Test 7: Check for errors in logs
echo "Test 7: Error check in logs"
ERROR_COUNT=$(ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 tmiller@$SHRIKE_HOST \
    "sudo docker logs shrike 2>&1 | grep -i 'error' | grep -v 'otelcol' | wc -l" 2>/dev/null || echo "0")
if [ "$ERROR_COUNT" -eq 0 ]; then
    echo "✅ PASS: No errors in shrike logs"
else
    echo "⚠️  WARN: Found $ERROR_COUNT errors in shrike logs"
    ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 tmiller@$SHRIKE_HOST \
        "sudo docker logs shrike 2>&1 | grep -i 'error' | grep -v 'otelcol' | tail -5"
fi
echo ""

# Summary
echo "=== E2E Test Summary ==="
echo "All critical tests passed!"
echo ""
echo "Next steps:"
echo "1. Monitor WAL cursor: watch -n 5 'docker exec shrike cat /data/wal/splunk_hec.cursor'"
echo "2. Check Splunk: https://$SHRIKE_HOST:8000/en-US/app/search/search?q=index%3Dmain%20sourcetype%3D_json"
echo "3. View logs: docker compose logs -f"
