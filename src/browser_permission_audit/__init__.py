"""Offline Chromium extension permission auditing."""
from .core import AuditReport, Finding, ManifestError, audit_manifest, audit_path, load_manifest

__all__ = ["AuditReport", "Finding", "ManifestError", "audit_manifest", "audit_path", "load_manifest"]
__version__ = "1.0.0"
