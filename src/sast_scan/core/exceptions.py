class SastScanError(Exception):
    """Base exception for scanner orchestration failures."""


class WorkspaceError(SastScanError):
    """Raised when a scan target cannot be prepared safely."""


class ScannerExecutionError(SastScanError):
    """Raised when an external scanner cannot be executed."""
