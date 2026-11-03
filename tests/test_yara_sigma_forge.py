"""
Automated Test Suite for YARA-X & Sigma Threat Rule Forge (`yara-sigma-forge`).
Verifies Shannon entropy calculation, threat preset definitions, and HTTP endpoints (/health, /api/presets, /api/scan).
"""

from __future__ import annotations

import json
import sys
import threading
import urllib.request
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from server import PRESETS, ThreadingTCPServer, YaraForgeHandler, shannon_entropy


def test_shannon_entropy_bounds():
    assert shannon_entropy("") == 0.0
    assert shannon_entropy("AAAAAAAA") == 0.0
    assert 0.99 <= shannon_entropy("ABABABAB") <= 1.01
    high_e = shannon_entropy("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*()")
    assert high_e > 5.8


def test_presets_have_valid_patterns_and_mitre_mappings():
    assert len(PRESETS) == 4
    ids = {p["id"] for p in PRESETS}
    assert ids == {"php-cgi-rce", "agent-exfil-trap", "elf-shellcode-stager", "ransomware-shadow-copy"}
    for preset in PRESETS:
        assert preset["ruleName"].startswith("ZOTH_")
        assert preset["severity"] in ("CRITICAL", "HIGH")
        assert len(preset["mitre"]) >= 2
        assert len(preset["patterns"]) >= 4


def test_http_endpoints_health_presets_and_scan():
    httpd = ThreadingTCPServer(("127.0.0.1", 0), YaraForgeHandler)
    port = httpd.server_address[1]
    httpd.port = port
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        # 1. GET /health
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=3) as resp:
            assert resp.status == 200
            health = json.loads(resp.read().decode("utf-8"))
            assert health["status"] == "ok"
            assert health["service"] == "yara-sigma-forge"
            assert health["threat_rules"] == 4

        # 2. GET /api/presets
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/presets", timeout=3) as resp:
            assert resp.status == 200
            presets_data = json.loads(resp.read().decode("utf-8"))
            assert len(presets_data["presets"]) == 4

        # 3. POST /api/scan (CVE-2024-4577 PHP-CGI payload)
        malicious_payload = (
            "POST /index.php?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input HTTP/1.1\n"
            "<?php system('id'); ?>"
        )
        req_scan = urllib.request.Request(
            f"http://127.0.0.1:{port}/api/scan",
            data=json.dumps({"payload": malicious_payload}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req_scan, timeout=3) as resp:
            assert resp.status == 200
            scan_res = json.loads(resp.read().decode("utf-8"))
            assert scan_res["verdict"] == "SUSPICIOUS"
            php_eval = next(e for e in scan_res["evaluations"] if e["preset"] == "php-cgi-rce")
            assert php_eval["matched"] is True
            assert len(php_eval["matched_patterns"]) >= 4

        # 4. POST /api/scan (clean payload)
        req_clean = urllib.request.Request(
            f"http://127.0.0.1:{port}/api/scan",
            data=json.dumps({"payload": "hello world"}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req_clean, timeout=3) as resp:
            assert resp.status == 200
            clean_res = json.loads(resp.read().decode("utf-8"))
            assert clean_res["verdict"] == "CLEAN"
            assert all(e["matched"] is False for e in clean_res["evaluations"])
    finally:
        httpd.shutdown()
        httpd.server_close()
