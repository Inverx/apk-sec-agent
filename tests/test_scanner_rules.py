"""Static scan rule tests over the synthetic sample workspace."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from backend.services.pipeline import do_decompile, do_scan


@pytest.fixture(scope="module")
def scanned(tmp_path_factory, sample_apk):
    workspace: Path = tmp_path_factory.mktemp("scanws") / "ws"
    do_decompile(sample_apk, workspace)
    return do_scan(workspace)


def _rule_ids(scanned):
    return {f["rule_id"] for f in scanned["findings"]}


def test_all_six_categories_present(scanned):
    categories = set(scanned["summary"]["by_category"])
    assert categories == {"manifest", "network", "secrets", "crypto", "packer", "webview"}


def test_manifest_rules(scanned):
    ids = _rule_ids(scanned)
    assert "MANIFEST-001" in ids  # debuggable
    assert "MANIFEST-002" in ids  # allowBackup
    assert "MANIFEST-003" in ids  # exported without permission
    exported = scanned["manifest"]["exported_components"]
    names = {c["name"].rsplit(".", 1)[-1] for c in exported}
    assert "SettingsActivity" in names and "PushReceiver" in names
    assert "MainActivity" not in names or True  # launcher may be exported; must not be flagged
    flagged = {f["title"] for f in scanned["findings"] if f["rule_id"] == "MANIFEST-003"}
    assert not any("MainActivity" in t for t in flagged), "launcher activity must not be flagged"


def test_network_rules(scanned):
    ids = _rule_ids(scanned)
    assert "NETWORK-001" in ids  # cleartext manifest flag
    assert "NETWORK-002" in ids  # http:// URLs
    assert "NETWORK-003" in ids  # trust-all manager
    critical = [f for f in scanned["findings"] if f["severity"] == "CRITICAL"]
    assert any(f["rule_id"] == "NETWORK-003" for f in critical)
    http_hits = [f for f in scanned["findings"] if f["rule_id"] == "NETWORK-002"]
    assert all(f["line"] > 0 for f in http_hits)


def test_secrets_rules(scanned):
    ids = _rule_ids(scanned)
    assert "SECRETS-001" in ids  # AK/SK
    assert "SECRETS-002" in ids  # JWT secret
    assert "SECRETS-004" in ids  # high entropy
    jwt = next(f for f in scanned["findings"] if f["rule_id"] == "SECRETS-002")
    assert jwt["cwe"] == "CWE-798"
    assert "JWT_SECRET" in jwt["snippet"]


def test_crypto_rules(scanned):
    ids = _rule_ids(scanned)
    assert "CRYPTO-001" in ids  # ECB (implicit + explicit)
    assert "CRYPTO-002" in ids  # fixed IV
    assert "CRYPTO-003" in ids  # MD5
    assert "CRYPTO-004" in ids  # literal SecretKeySpec
    ecb = [f for f in scanned["findings"] if f["rule_id"] == "CRYPTO-001"]
    assert len(ecb) >= 1  # Cipher.getInstance("AES") implicit ECB in CryptoUtil
    assert any("未指定模式" in f["title"] for f in ecb)
    md5 = next(f for f in scanned["findings"] if f["rule_id"] == "CRYPTO-003")
    assert md5["cwe"] == "CWE-327"


def test_packer_rule(scanned):
    packer = [f for f in scanned["findings"] if f["rule_id"] == "PACKER-001"]
    assert len(packer) == 1
    assert "360加固" in packer[0]["title"]
    assert any("libjiagu.so" in ev for ev in [packer[0]["snippet"]])


def test_webview_rule(scanned):
    webview = [f for f in scanned["findings"] if f["rule_id"] == "WEBVIEW-001"]
    assert len(webview) == 1
    assert webview[0]["cwe"] == "CWE-749"
    assert webview[0]["line"] >= 20  # addJavascriptInterface location in MainActivity


def test_finding_fields_complete(scanned):
    for f in scanned["findings"]:
        assert f["id"].startswith("F-")
        assert f["severity"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
        assert f["cwe"].startswith("CWE-")
        assert f["file"]
        assert f["line"] >= 1
        assert f["suggestion"]
        assert "title" in f and "description" in f


def test_findings_sorted_by_severity(scanned):
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    levels = [order[f["severity"]] for f in scanned["findings"]]
    assert levels == sorted(levels)
