from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

RISK_WEIGHTS = {
    "debugger": 35, "nativeMessaging": 35, "proxy": 30, "webRequestBlocking": 25,
    "cookies": 20, "history": 20, "management": 20, "downloads": 15,
    "clipboardRead": 15, "clipboardWrite": 8, "geolocation": 15, "tabs": 10,
    "webRequest": 10, "bookmarks": 10, "notifications": 4, "storage": 2,
    "activeTab": 2, "scripting": 8,
}
BROAD_HOSTS = {"<all_urls>", "*://*/*", "http://*/*", "https://*/*"}

@dataclass(frozen=True)
class Finding:
    severity: str
    code: str
    message: str
    permission: str | None = None

@dataclass(frozen=True)
class AuditReport:
    manifest_version: int | None
    name: str
    permissions: tuple[str, ...]
    host_permissions: tuple[str, ...]
    findings: tuple[Finding, ...]
    score: int
    risk: str

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["permissions"] = list(self.permissions)
        data["host_permissions"] = list(self.host_permissions)
        data["findings"] = [asdict(f) for f in self.findings]
        return data

class ManifestError(ValueError):
    pass

def load_manifest(path: str | Path) -> dict[str, Any]:
    p = Path(path)
    if p.is_dir():
        p = p / "manifest.json"
    if not p.is_file():
        raise ManifestError(f"Manifest not found: {p}")
    if p.stat().st_size > 2_000_000:
        raise ManifestError("Manifest is unexpectedly large (>2 MB)")
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ManifestError(f"Cannot read valid UTF-8 JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ManifestError("Manifest root must be a JSON object")
    return data

def _strings(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or any(not isinstance(x, str) for x in value):
        raise ManifestError("Permission fields must be arrays of strings")
    return tuple(dict.fromkeys(value))

def _is_host_pattern(value: str) -> bool:
    return value == "<all_urls>" or "://" in value

def audit_manifest(data: dict[str, Any]) -> AuditReport:
    version = data.get("manifest_version")
    if version is not None and (not isinstance(version, int) or isinstance(version, bool)):
        raise ManifestError("manifest_version must be an integer")
    name = data.get("name", "Unnamed extension")
    if not isinstance(name, str):
        raise ManifestError("name must be a string")

    raw_permissions = _strings(data.get("permissions"))
    optional_permissions = _strings(data.get("optional_permissions"))
    host_permissions = list(_strings(data.get("host_permissions")))
    host_permissions += list(_strings(data.get("optional_host_permissions")))

    # Manifest V2 commonly places host patterns in permissions.
    api_permissions = []
    for perm in raw_permissions + optional_permissions:
        (host_permissions if _is_host_pattern(perm) else api_permissions).append(perm)
    api_permissions = list(dict.fromkeys(api_permissions))
    host_permissions = list(dict.fromkeys(host_permissions))

    findings: list[Finding] = []
    score = 0
    for perm in api_permissions:
        weight = RISK_WEIGHTS.get(perm, 5)
        score += weight
        if weight >= 25:
            severity = "high"
        elif weight >= 10:
            severity = "medium"
        else:
            severity = "low"
        findings.append(Finding(severity, "api-permission", f"Requests {perm!r} browser capability.", perm))

    for host in host_permissions:
        broad = host in BROAD_HOSTS or host.startswith("*://*.") or host.startswith("https://*.")
        if broad:
            score += 30
            findings.append(Finding("high", "broad-host-access", "Can access a very broad set of web origins.", host))
        else:
            score += 8
            findings.append(Finding("medium", "host-access", "Can access matching web origins.", host))

    if version == 2:
        score += 8
        findings.append(Finding("medium", "manifest-v2", "Manifest V2 is legacy; review migration and browser support."))

    csp = data.get("content_security_policy")
    if isinstance(csp, str) and "unsafe-eval" in csp:
        score += 25
        findings.append(Finding("high", "unsafe-eval", "Content Security Policy contains unsafe-eval."))

    score = min(score, 100)
    risk = "critical" if score >= 75 else "high" if score >= 50 else "moderate" if score >= 25 else "low"
    order = {"high": 0, "medium": 1, "low": 2}
    findings.sort(key=lambda f: (order[f.severity], f.code, f.permission or ""))
    return AuditReport(version, name, tuple(api_permissions), tuple(host_permissions), tuple(findings), score, risk)

def audit_path(path: str | Path) -> AuditReport:
    return audit_manifest(load_manifest(path))
