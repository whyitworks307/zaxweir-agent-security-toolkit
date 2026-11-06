class ToolkitError(Exception):
    """Base error. Every ToolkitError is treated as a denial (fail closed)."""

class ConfigError(ToolkitError):
    pass

class AccessDenied(PermissionError):
    pass

class ApprovalError(ToolkitError):
    pass

class AuditError(ToolkitError):
    pass

class AuditBusy(AuditError):
    pass
