#!/usr/bin/env python3
"""
YARA-X & Sigma Threat Rule Forge Server (Port :8133)
Engineered by 1nc0gn30 (@1nc0gn30) • NullAI Platform
"""

import argparse
import http.server
import json
import math
import os
import re
import socketserver
import urllib.parse

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PUBLIC_DIR = os.path.join(SCRIPT_DIR, "public")

PRESETS = [
    {
        "id": "php-cgi-rce",
        "label": "PHP-CGI FastCGI RCE (CVE-2024-4577)",
        "ruleName": "ZOTH_PHP_CGI_Arg_Injection_RCE",
        "severity": "CRITICAL",
        "mitre": ["T1190 (Exploit Public-Facing App)", "T1059.004 (Unix Shell)"],
        "patterns": [
            {"id": "$soft_hyphen", "type": "ascii", "value": "%ADd"},
            {"id": "$allow_url", "type": "ascii", "value": "allow_url_include"},
            {"id": "$auto_prepend", "type": "ascii", "value": "auto_prepend_file"},
            {"id": "$php_input", "type": "ascii", "value": "php://input"},
            {"id": "$shell_exec", "type": "regex", "value": r"(system|passthru|shell_exec|popen)\s*\("},
        ],
        "minMatches": 2,
    },
    {
        "id": "agent-exfil-trap",
        "label": "AI Agent Prompt-to-Shell Credential Exfil",
        "ruleName": "ZOTH_Agent_MCP_Credential_Exfil",
        "severity": "HIGH",
        "mitre": ["T1552.001 (Credentials in Files)", "T1048 (Exfiltration Over Alt Protocol)"],
        "patterns": [
            {"id": "$env_file", "type": "ascii", "value": ".env"},
            {"id": "$ssh_key", "type": "ascii", "value": "id_ed25519"},
            {"id": "$curl_pipe", "type": "regex", "value": r"curl\s+-[a-zA-Z]*\s+https?://"},
            {"id": "$base64_exfil", "type": "ascii", "value": "base64 -w0"},
        ],
        "minMatches": 2,
    },
    {
        "id": "elf-shellcode-stager",
        "label": "ELF64 Memfd Reflective Stager",
        "ruleName": "ZOTH_ELF64_Memfd_Reflective_Loader",
        "severity": "CRITICAL",
        "mitre": ["T1620 (Reflective Code Loading)", "T1027 (Obfuscated Files)"],
        "patterns": [
            {"id": "$elf_magic", "type": "ascii", "value": r"\x7fELF"},
            {"id": "$memfd", "type": "ascii", "value": "memfd_create"},
            {"id": "$execveat", "type": "ascii", "value": "fexecve"},
            {"id": "$proc_self", "type": "ascii", "value": "/proc/self/fd/"},
        ],
        "minMatches": 2,
    },
    {
        "id": "ransomware-shadow-copy",
        "label": "Windows Shadow Copy Deletion (Ransomware Trigger)",
        "ruleName": "ZOTH_Ransomware_Vssadmin_Delete_Shadows",
        "severity": "CRITICAL",
        "mitre": ["T1490 (Inhibit System Recovery)", "T1059.001 (PowerShell)"],
        "patterns": [
            {"id": "$vssadmin", "type": "ascii", "value": "vssadmin delete shadows /all /quiet"},
            {"id": "$wmic_shadow", "type": "ascii", "value": "shadowcopy delete"},
            {"id": "$bcdedit_rec", "type": "ascii", "value": "bcdedit /set {default} recoveryenabled No"},
            {"id": "$wbadmin_del", "type": "ascii", "value": "wbadmin delete catalog -quiet"},
        ],
        "minMatches": 1,
    },
]


def shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    freq = {}
    for ch in data:
        freq[ch] = freq.get(ch, 0) + 1
    entropy = 0.0
    length = len(data)
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


class YaraForgeHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=PUBLIC_DIR, **kwargs)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path in ("/health", "/api/health"):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(
                json.dumps(
                    {
                        "status": "ok",
                        "service": "yara-sigma-forge",
                        "version": "3.3.0",
                        "port": getattr(self.server, "port", 8133),
                        "mode": "standalone-sovereign",
                        "threat_rules": len(PRESETS),
                    }
                ).encode("utf-8")
            )
            return

        if path == "/api/status":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(
                json.dumps(
                    {
                        "status": "online",
                        "service": "yara-sigma-forge",
                        "presets": [p["id"] for p in PRESETS],
                        "free_open_access": True,
                    }
                ).encode("utf-8")
            )
            return

        if path == "/api/presets":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps({"presets": PRESETS}).encode("utf-8"))
            return

        return super().do_GET()

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/api/scan":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode("utf-8")
            try:
                data = json.loads(body)
                payload = data.get("payload", "")
            except Exception:
                payload = body

            entropy = shannon_entropy(payload)
            results = []
            for preset in PRESETS:
                matched_patterns = []
                for p in preset["patterns"]:
                    if p["type"] == "ascii" and p["value"] in payload:
                        matched_patterns.append(p["id"])
                    elif p["type"] == "regex":
                        if re.search(p["value"], payload):
                            matched_patterns.append(p["id"])
                results.append(
                    {
                        "preset": preset["id"],
                        "ruleName": preset["ruleName"],
                        "matched": len(matched_patterns) >= preset["minMatches"],
                        "matched_patterns": matched_patterns,
                        "total_patterns": len(preset["patterns"]),
                    }
                )

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(
                json.dumps(
                    {
                        "entropy": round(entropy, 2),
                        "bytes": len(payload.encode("utf-8")),
                        "verdict": "SUSPICIOUS" if entropy > 5.5 or any(r["matched"] for r in results) else "CLEAN",
                        "evaluations": results,
                    }
                ).encode("utf-8")
            )
            return

        self.send_response(404)
        self.end_headers()


class ThreadingTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True


def main():
    parser = argparse.ArgumentParser(description="YARA-X & Sigma Threat Rule Forge Daemon")
    parser.add_argument("--port", type=int, default=8133, help="Port to bind (default: 8133)")
    args = parser.parse_args()

    server = ThreadingTCPServer(("127.0.0.1", args.port), YaraForgeHandler)
    server.port = args.port
    print(f"⚡ YARA-X & Sigma Forge running on http://127.0.0.1:{args.port} (serving {PUBLIC_DIR})")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping YARA-X Forge...")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
