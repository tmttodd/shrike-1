#!/bin/bash
# Create OCSF-aligned Splunk indexes
# Run on Splunk server or via REST API
#
# Usage:
#   ./scripts/create_splunk_indexes.sh https://your-splunk:8089 admin
#
# Or via docker exec:
#   docker exec splunk bash -c '/opt/splunk/bin/splunk add index ocsf-authentication -auth admin:password'

SPLUNK_URL="${1:-https://localhost:8089}"
SPLUNK_USER="${2:-admin}"

echo "Creating OCSF indexes on $SPLUNK_URL"
echo "Enter Splunk password:"
read -s SPLUNK_PASS

INDEXES=(
    # System Activity
    ocsf-file-activity ocsf-kernel-extension ocsf-kernel-activity
    ocsf-memory-activity ocsf-module-activity ocsf-scheduled-job
    ocsf-process-activity ocsf-log-activity
    # Findings
    ocsf-security-finding ocsf-vulnerability-finding ocsf-compliance-finding
    ocsf-detection-finding ocsf-incident-finding ocsf-data-security-finding
    # IAM
    ocsf-account-change ocsf-authentication ocsf-authorize-session
    ocsf-group-management ocsf-user-access-management ocsf-entity-management
    # Network
    ocsf-network-activity ocsf-http-activity ocsf-dns-activity
    ocsf-dhcp-activity ocsf-rdp-activity ocsf-smb-activity
    ocsf-ssh-activity ocsf-ftp-activity ocsf-email-activity
    ocsf-file-hosting ocsf-vpn-activity ocsf-email-url ocsf-inventory-info
    # Discovery
    ocsf-device-inventory ocsf-compliance-check ocsf-directory-service
    ocsf-config-state ocsf-device-config-state
    # Application
    ocsf-web-resources ocsf-application-lifecycle ocsf-api-activity
    ocsf-file-hosting-activity ocsf-scan-activity ocsf-module-activity-app
    # Fallbacks
    ocsf-system ocsf-findings ocsf-iam ocsf-network ocsf-discovery
    ocsf-application ocsf-raw
)

for INDEX in "${INDEXES[@]}"; do
    echo -n "  Creating $INDEX... "
    RESULT=$(curl -sk -u "$SPLUNK_USER:$SPLUNK_PASS" \
        "$SPLUNK_URL/servicesNS/admin/search/data/indexes" \
        -d "name=$INDEX&datatype=event&maxDataSizeMB=10240&frozenTimePeriodInSecs=7776000" \
        -o /dev/null -w "%{http_code}" 2>/dev/null)
    if [ "$RESULT" = "201" ]; then
        echo "created"
    elif [ "$RESULT" = "409" ]; then
        echo "exists"
    else
        echo "HTTP $RESULT"
    fi
done

echo ""
echo "Done. ${#INDEXES[@]} indexes processed."
echo ""
echo "To verify: curl -sk -u $SPLUNK_USER:pass '$SPLUNK_URL/servicesNS/admin/search/data/indexes?search=ocsf&output_mode=json' | jq '.entry[].name'"
