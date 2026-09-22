import json
from browser_permission_audit.cli import main


def write_manifest(tmp_path, data):
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def test_json_output(tmp_path, capsys):
    path = write_manifest(tmp_path, {"manifest_version": 3, "name": "Safe", "permissions": ["storage"]})
    assert main([str(path), "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["name"] == "Safe"
    assert payload["risk"] == "low"


def test_fail_on_threshold(tmp_path):
    path = write_manifest(tmp_path, {"manifest_version": 3, "name": "Wide", "host_permissions": ["<all_urls>"]})
    assert main([str(path), "--fail-on", "moderate"]) == 2


def test_missing_manifest_is_error(tmp_path, capsys):
    assert main([str(tmp_path / "missing.json")]) == 1
    assert "Manifest not found" in capsys.readouterr().err
