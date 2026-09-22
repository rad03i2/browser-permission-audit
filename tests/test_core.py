import json
import pytest
from browser_permission_audit import ManifestError, audit_manifest, audit_path


def test_low_risk_manifest():
    r = audit_manifest({"manifest_version": 3, "name": "Notes", "permissions": ["storage", "activeTab"]})
    assert r.risk == "low"
    assert r.score == 4
    assert r.permissions == ("storage", "activeTab")


def test_broad_host_and_debugger_are_high_risk():
    r = audit_manifest({"manifest_version": 3, "name": "Tool", "permissions": ["debugger"], "host_permissions": ["<all_urls>"]})
    assert r.score == 65
    assert r.risk == "high"
    assert {f.code for f in r.findings} == {"api-permission", "broad-host-access"}


def test_v2_host_permissions_are_separated():
    r = audit_manifest({"manifest_version": 2, "name": "Legacy", "permissions": ["tabs", "https://example.com/*"]})
    assert r.permissions == ("tabs",)
    assert r.host_permissions == ("https://example.com/*",)
    assert any(f.code == "manifest-v2" for f in r.findings)


def test_duplicates_are_removed():
    r = audit_manifest({"manifest_version": 3, "name": "X", "permissions": ["storage", "storage"]})
    assert r.permissions == ("storage",)
    assert r.score == 2


def test_invalid_permission_shape_rejected():
    with pytest.raises(ManifestError):
        audit_manifest({"permissions": "tabs"})


def test_directory_load(tmp_path):
    (tmp_path / "manifest.json").write_text(json.dumps({"manifest_version": 3, "name": "Local"}), encoding="utf-8")
    assert audit_path(tmp_path).name == "Local"


def test_unsafe_eval_is_flagged():
    r = audit_manifest({"manifest_version": 2, "name": "X", "content_security_policy": "script-src 'self' 'unsafe-eval'"})
    assert any(f.code == "unsafe-eval" for f in r.findings)
