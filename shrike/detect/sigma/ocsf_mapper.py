"""Maps Sigma logsource specifications to OCSF field queries."""

from __future__ import annotations

from typing import Any


# Sigma logsource category → OCSF class_uid mapping
CATEGORY_TO_CLASS: dict[str, int] = {
    "process_creation": 1007,      # Process Activity
    "network_connection": 4001,    # Network Activity
    "dns_query": 4003,             # DNS Activity
    "file_create": 7003,           # System Activity (file)
    "registry_add": 7001,          # Configuration Change
    "registry_set": 7001,          # Configuration Change
    "registry_delete": 7001,       # Configuration Change
    "user_account": 3001,          # Account Management
    "authentication": 3002,        # Authentication
    "logon": 3002,                 # Authentication
    "privilege": 3005,             # Privilege Use
    "file_delete": 7003,           # System Activity
    "ps_script": 1007,             # Process Activity (PowerShell)
    "pipe_created": 1007,          # Process Activity
    "wmi_event": 1007,             # Process Activity
    "sysmon": 1001,                # System Activity
    "security": 3002,              # Authentication/Authorization
    "system": 1001,                # System Activity
}

# Sigma service → OCSF hints
SERVICE_TO_HINT: dict[str, str] = {
    "sysmon": "sysmon",
    "windows_defender": "microsoft_defender",
    "active_directory": "active_directory",
    "linux_audit": "auditd",
    "iptables": "firewall",
}


class OCSFFieldMapper:
    """Maps Sigma field names to OCSF field paths.

    Sigma rules use generic field names (e.g., "Image", "ParentImage").
    This mapper translates them to OCSF paths (e.g., "process.file.path").
    """

    # Windows-specific field mappings (most common Sigma use case)
    WINDOWS_FIELD_MAP: dict[str, str] = {
        # Process fields
        "Image": "process.file.path",
        "ProcessName": "process.name",
        "ProductName": "process.product.name",
        "Description": "process.description",
        "Company": "process.company.name",
        "OriginalFileName": "process.file.name",
        "CommandLine": "process.cmd_line",
        "CurrentDirectory": "process.current_directory",
        "User": "user.name",
        "SubjectUserName": "actor.user.name",
        "SubjectDomainName": "actor.user.domain",
        "ParentImage": "process.parent_process.file.path",
        "ParentProcessName": "process.parent_process.name",
        "ParentCommandLine": "process.parent_process.cmd_line",
        "ParentUser": "actor.user.name",
        "ProcessId": "process.pid",
        "ParentProcessId": "process.parent_process.pid",
        "Hashes": "process.file.hash",
        "Signature": "process.file.signature",
        "Signed": "process.file.signed",

        # Network fields
        "DestinationIp": "dst_endpoint.ip",
        "DestinationPort": "dst_endpoint.port",
        "SourceIp": "src_endpoint.ip",
        "SourcePort": "src_endpoint.port",
        "Protocol": "connection_info.protocol_name",
        "Hostname": "device.hostname",
        "Ip": "src_endpoint.ip",
        "Port": "src_endpoint.port",

        # DNS fields
        "Query": "query.hostname",
        "QueryName": "query.hostname",
        "QueryType": "query.type",
        "Response": "answers",

        # File fields
        "TargetFilename": "file.path",
        "CreationUtcTime": "file.created_time",
        "FileSize": "file.size",

        # Registry fields
        "Key": "registry.key.path",
        "Value": "registry.value.name",
        "Data": "registry.value.data",

        # Authentication fields
        "TargetUserName": "user.name",
        "TargetDomainName": "user.domain",
        "TargetLogonId": "user.session.uid",
        "IpAddress": "src_endpoint.ip",
        "IpPort": "src_endpoint.port",
        "AuthenticationPackageName": "auth_protocol",
        "Process": "process.name",
    }

    # Generic field mappings (cross-platform)
    GENERIC_FIELD_MAP: dict[str, str] = {
        "user": "user.name",
        "username": "user.name",
        "userName": "user.name",
        "client_ip": "src_endpoint.ip",
        "client_ip": "src_endpoint.ip",
        "server_ip": "dst_endpoint.ip",
        "server_ip": "dst_endpoint.ip",
        "src_ip": "src_endpoint.ip",
        "dst_ip": "dst_endpoint.ip",
        "source_ip": "src_endpoint.ip",
        "destination_ip": "dst_endpoint.ip",
        "src_port": "src_endpoint.port",
        "dst_port": "dst_endpoint.port",
        "source_port": "src_endpoint.port",
        "destination_port": "dst_endpoint.port",
        "hostname": "device.hostname",
        "host": "device.hostname",
        "path": "file.path",
        "filename": "file.name",
        "command": "process.cmd_line",
        "cmd": "process.cmd_line",
        "pid": "process.pid",
        "ppid": "process.parent_process.pid",
        "name": "process.name",
        "hash": "file.hash",
        "md5": "file.hash.md5",
        "sha1": "file.hash.sha1",
        "sha256": "file.hash.sha256",
    }

    def __init__(self):
        """Initialize field mapper."""
        # Combine maps, with Windows taking precedence
        self._field_map = {**self.GENERIC_FIELD_MAP, **self.WINDOWS_FIELD_MAP}

    def map_field(self, sigma_field: str) -> str | None:
        """Map a Sigma field name to OCSF path.

        Args:
            sigma_field: Sigma field name (e.g., "Image", "CommandLine").

        Returns:
            OCSF field path (e.g., "process.file.path") or None if no mapping.
        """
        # Try exact match first
        if sigma_field in self._field_map:
            return self._field_map[sigma_field]

        # Try case-insensitive match
        sigma_lower = sigma_field.lower()
        for key, value in self._field_map.items():
            if key.lower() == sigma_lower:
                return value

        # No mapping found
        return None

    def map_fields(self, sigma_fields: list[str]) -> list[tuple[str, str]]:
        """Map multiple Sigma fields to OCSF paths.

        Args:
            sigma_fields: List of Sigma field names.

        Returns:
            List of (ocsf_path, sigma_field) tuples for successfully mapped fields.
        """
        mappings = []
        for field in sigma_fields:
            ocsf_path = self.map_field(field)
            if ocsf_path:
                mappings.append((ocsf_path, field))
        return mappings

    def get_class_uid_for_logsource(
        self, category: str | None, service: str | None = None
    ) -> int | None:
        """Get OCSF class_uid for a Sigma logsource.

        Args:
            category: Sigma logsource category.
            service: Sigma logsource service.

        Returns:
            OCSF class_uid or None if no mapping.
        """
        if category:
            return CATEGORY_TO_CLASS.get(category.lower())
        return None
