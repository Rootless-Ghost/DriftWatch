"""
DriftWatch — Sigma field → ECS-lite field mappings.

Maps the flat Windows/Sysmon field names used in Sigma rules
to the dot-notation paths used in LogNorm ECS-lite output.

Resolution order when matching:
  1. Exact field name in flat event  (e.g. "CommandLine")
  2. ECS-lite path lookup            (e.g. "process.command_line")
  3. Alias / legacy field names
"""

# ── Primary mapping ────────────────────────────────────────────────────────────
# key   = Sigma field name (case-sensitive as written in rules)
# value = list of ECS-lite dot-paths to check, in priority order

FIELD_MAPPINGS: dict[str, list[str]] = {

    # ── Process fields ─────────────────────────────────────────────────────────
    "CommandLine":        ["process.command_line", "process.args"],
    "OriginalFileName":   ["process.pe.original_file_name"],
    "Image":              ["process.executable", "process.name"],
    "ProcessName":        ["process.name", "process.executable"],
    "ParentImage":        ["process.parent.executable", "process.parent.name"],
    "ParentCommandLine":  ["process.parent.command_line"],
    "ParentProcessName":  ["process.parent.name"],
    "ProcessId":          ["process.pid"],
    "ParentProcessId":    ["process.parent.pid"],
    "User":               ["user.name", "user.full_name"],
    "SubjectUserName":    ["user.name"],
    "TargetUserName":     ["user.target.name", "user.name"],
    "SubjectUserSid":     ["user.id"],
    "Company":            ["process.pe.company"],
    "Description":        ["process.pe.description"],
    "FileVersion":        ["process.pe.file_version"],
    "Hashes":             ["process.hash.md5", "process.hash.sha256", "process.hash.sha1"],
    "md5":                ["process.hash.md5"],
    "sha1":               ["process.hash.sha1"],
    "sha256":             ["process.hash.sha256"],
    "Imphash":            ["process.hash.imphash"],
    "IntegrityLevel":     ["process.integrity_level"],

    # ── Windows Event Log ──────────────────────────────────────────────────────
    "EventID":            ["event.code", "event.id", "winlog.event_id"],
    "Channel":            ["log.file.path", "winlog.channel"],
    "Provider_Name":      ["event.provider"],
    "Computer":           ["host.name", "agent.name"],
    "SubjectLogonId":     ["winlog.logon.id"],
    "TargetLogonId":      ["winlog.target_logon_id"],
    "LogonType":          ["winlog.logon.type"],
    "IpAddress":          ["source.ip", "network.forwarded_ip"],
    "WorkstationName":    ["source.domain", "host.name"],
    "TokenElevationType": ["winlog.token_elevation_type"],
    "AccountName":        ["user.name"],
    "AccountDomain":      ["user.domain"],

    # ── Registry ───────────────────────────────────────────────────────────────
    "TargetObject":       ["registry.path", "registry.key"],
    "Details":            ["registry.data.strings", "registry.value"],
    "EventType":          ["event.action", "event.type"],
    "NewName":            ["registry.path"],

    # ── Network ────────────────────────────────────────────────────────────────
    "DestinationHostname":["network.destination.domain", "destination.domain", "dns.question.name"],
    "DestinationIp":      ["destination.ip", "network.destination.ip"],
    "DestinationPort":    ["destination.port", "network.destination.port"],
    "SourceIp":           ["source.ip", "network.source.ip"],
    "SourcePort":         ["source.port", "network.source.port"],
    "Protocol":           ["network.transport", "network.protocol"],
    "Initiated":          ["network.direction"],
    "QueryName":          ["dns.question.name"],
    "QueryResults":       ["dns.answers.data"],
    "Image_Network":      ["process.executable"],

    # ── File ───────────────────────────────────────────────────────────────────
    "TargetFilename":     ["file.path", "file.name"],
    "Filename":           ["file.name", "file.path"],
    "CreationUtcTime":    ["file.created"],
    "PreviousCreationUtcTime": ["file.mtime"],

    # ── PowerShell ─────────────────────────────────────────────────────────────
    "ScriptBlockText":    ["powershell.script_block_text", "message"],
    "Payload":            ["powershell.script_block_text", "message"],
    "Path":               ["file.path", "process.executable"],
    "MessageNumber":      ["event.sequence"],

    # ── WMI ───────────────────────────────────────────────────────────────────
    "Operation":          ["event.action"],
    "Consumer":           ["wmi.consumer.name", "wmi.consumer.destination"],
    "Filter":             ["wmi.filter.name"],
    "Name":               ["process.name", "service.name"],
    "Query":              ["wmi.query"],

    # ── Service / task ─────────────────────────────────────────────────────────
    "ServiceName":        ["service.name", "winlog.event_data.ServiceName"],
    "ServiceFileName":    ["service.executable", "winlog.event_data.ServiceFileName"],
    "StartType":          ["service.type"],
    "TaskName":           ["task.name", "winlog.event_data.TaskName"],
    "TaskContent":        ["winlog.event_data.TaskContent"],

    # ── Generic / catch-all ────────────────────────────────────────────────────
    "message":            ["message", "log.original"],
    "Message":            ["message", "log.original"],
    "ObjectType":         ["object.type"],
    "ObjectName":         ["object.name", "file.path"],
    "ShareName":          ["network.share.name", "winlog.event_data.ShareName"],
    "RelativeTargetName": ["file.name", "winlog.event_data.RelativeTargetName"],
    "cs-uri-stem":        ["url.path"],
    "cs-uri-query":       ["url.query"],
    "c-ip":               ["source.ip"],
    "sc-status":          ["http.response.status_code"],
    "cs-method":          ["http.request.method"],
    "cs-useragent":       ["user_agent.original"],
    "ParentUser":         ["user.name"],
    "GrantedAccess":      ["winlog.event_data.GrantedAccess"],
    "CallTrace":          ["winlog.event_data.CallTrace"],
    "SourceImage":        ["process.executable"],
    "TargetImage":        ["winlog.event_data.TargetImage"],
    "StartAddress":       ["winlog.event_data.StartAddress"],
    "StartModule":        ["winlog.event_data.StartModule"],
    "StartFunction":      ["winlog.event_data.StartFunction"],
    "ImageLoaded":        ["dll.path", "winlog.event_data.ImageLoaded"],
    "Signed":             ["dll.code_signature.signed", "winlog.event_data.Signed"],
    "Signature":          ["dll.code_signature.subject_name"],
    "SignatureStatus":    ["dll.code_signature.status"],
}

# ── Reverse lookup: ECS path → list of Sigma field names ──────────────────────
_ECS_TO_SIGMA: dict[str, list[str]] = {}
for _sigma_field, _ecs_paths in FIELD_MAPPINGS.items():
    for _path in _ecs_paths:
        _ECS_TO_SIGMA.setdefault(_path, []).append(_sigma_field)


def get_ecs_paths(sigma_field: str) -> list[str]:
    """Return all ECS-lite paths for a given Sigma field name."""
    return FIELD_MAPPINGS.get(sigma_field, [])


def get_sigma_fields(ecs_path: str) -> list[str]:
    """Return all Sigma field names that map to a given ECS path."""
    return _ECS_TO_SIGMA.get(ecs_path, [])
