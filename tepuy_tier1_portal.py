#!/usr/bin/env python3
# Copyright (c) 2026 Wanadi Tactical LLC. All rights reserved.
# SPDX-License-Identifier: LicenseRef-Wanadi-Source-Available-Eval-1.0
# Source-available for internal CISO security audit & evaluation only (see LICENSE.txt).
# Commercial resale, MSSP/third-party service delivery, and derivative products prohibited.
"""
WANADI TACTICAL LLC — Tepuy Core™ Air-Gap Bridge (Tier 1 Client Verification Portal)
====================================================================================
100% Python Standard Library local loopback HTTP portal (`127.0.0.1:8787`) exclusively
for customer-side Ed25519 signature verification and local identity rehydration.
Zero signing keys. Zero external dependencies. Zero external CDNs.
"""

from __future__ import annotations

import argparse
import html
import http.server
import json
import socketserver
import sqlite3
import tempfile
import threading
import urllib.request
from pathlib import Path
from typing import Any, Dict

import tepuy_airgap_bridge as bridge
from tepuy_brand import IDENTITY_CSS, identity_header

MAX_BODY_BYTES = 2 * 1024 * 1024  # 2 MiB safety cap


def request_document(payload: Dict[str, Any], field: str) -> Dict[str, Any]:
    text_field = f"{field}_json"
    if text_field in payload:
        text = payload[text_field]
        if field in payload or not isinstance(text, str):
            raise ValueError(f"Invalid {field} input")
        payload = {field: json.loads(text.lstrip("\ufeff"))}
    document = payload.get(field)
    if not isinstance(document, dict):
        raise ValueError(f"Missing or invalid {field} document")
    return document


def _build_portal_html(pub_key_hex: str) -> str:
    pk_esc = html.escape(pub_key_hex, quote=True)
    return f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Tepuy Core™ Air-Gap Bridge | Verificador Local · Wanadi Tactical</title>
<style>
  :root {{
    --bg:#02070D; --panel:#0A1420; --border:#14283D; --cyan:#00F2FE;
    --teal:#00D9DA; --text:#F4F7FB; --muted:#8FA8C2; --err:#FF3B5C;
  }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; padding:26px; background:var(--bg); color:var(--text);
         font-family:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif; }}
  .wrap {{ max-width:1120px; margin:0 auto; }}
  .top {{ border-bottom:1px solid var(--border); padding-bottom:16px; margin-bottom:20px; }}
  h1 {{ margin:4px 0 0; font-size:22px; }}
  .pill {{ padding:5px 12px; border-radius:999px; border:1px solid var(--teal); color:var(--teal);
          font-size:12px; background:rgba(0,217,218,0.08); display:inline-block; }}
  .panel {{ background:var(--panel); border:1px solid var(--border); border-radius:10px; padding:18px; margin-bottom:18px; }}
  label {{ display:block; font-size:12px; color:var(--muted); margin:10px 0 6px; }}
  textarea, input[type=text] {{
    width:100%; background:#030A12; color:var(--text); border:1px solid var(--border);
    border-radius:8px; padding:10px; font-family:ui-monospace,Consolas,monospace; font-size:12px;
  }}
  textarea {{ min-height:100px; resize:vertical; }}
  .row {{ display:flex; gap:10px; flex-wrap:wrap; margin-top:12px; align-items:center; }}
  button.btn {{ background:var(--cyan); color:#02070D; border:none; border-radius:8px; padding:10px 18px;
               font-weight:700; cursor:pointer; font-size:13px; }}
  button.btn.sec {{ background:transparent; color:var(--teal); border:1px solid var(--teal); }}
  pre {{ background:#030A12; border:1px solid var(--border); border-radius:8px; padding:12px;
        overflow:auto; max-height:360px; font-size:12px; color:#CFE2F5; }}
  .err {{ color:var(--err); font-size:13px; margin-top:8px; }}
  code {{ color:var(--cyan); font-size:12px; }}
{IDENTITY_CSS}
body {{ margin:0; padding:clamp(16px, 5vw, 64px); min-height:100vh;
  background:radial-gradient(ellipse at 92% 0%, #111436 0, transparent 56%), var(--wt-ink); }}
.top {{ display:block; padding:0 0 24px; border-color:var(--wt-line); }}
.top h1 {{ font-size:clamp(30px, 5vw, 60px); letter-spacing:-.05em; line-height:1.04; }}
.intro {{ color:var(--wt-muted); max-width:62ch; margin:14px 0; }}
.pill {{ color:var(--wt-teal); border-color:var(--wt-line); }}
.panel {{ background:var(--wt-navy); border-color:var(--wt-line); padding:clamp(16px, 3vw, 30px); }}
button.btn {{ background:var(--wt-teal); }} button.btn.sec {{ color:var(--wt-teal); border-color:var(--wt-teal); }}
h2 {{ margin:0; font-size:1.35rem; }} .err:empty {{ display:none; }}
.verify-files {{ display:grid; grid-template-columns:repeat(3,minmax(0,1fr)); gap:14px; }}
.file-slot {{ background:#07101c; border:1px solid var(--wt-line); border-radius:8px; padding:12px; min-width:0; }}
.file-slot label {{ margin:0 0 9px; color:var(--wt-white); }}
.file-slot input {{ max-width:100%; color:var(--wt-muted); }}
.file-slot input::file-selector-button {{ padding:7px 10px; background:var(--wt-blue); color:var(--wt-white); border:1px solid var(--wt-line); border-radius:4px; }}
details {{ margin-top:12px; }} summary {{ cursor:pointer; color:var(--wt-muted); font-size:.84rem; }}
@media (max-width:760px) {{ .verify-files {{ grid-template-columns:1fr; }} }}
</style>
</head>
<body>
<div class="wrap">
  <header class="top">
    {identity_header()}
    <span class="brand-kicker">Verificador Local · Tier 1</span>
    <h1>Air-Gap Bridge</h1>
    <p class="intro">Valide criptográficamente el dictamen firmado por Wanadi Tactical y reconstruya las identidades reales dentro de su perímetro.</p>
    <div class="pill">Clave Pública Wanadi Ed25519 <code>{pk_esc[:16]}…</code></div>
  </header>

  <div id="tab-rehydrate" class="panel">
    <h2>Verificar y reconstruir localmente</h2>
    <p class="intro">Cargue el informe firmado (<code>tepuy_report_raw_signed.json</code>), su mapa privado (<code>local_map.json</code>) y el manifiesto original (<code>tepuy_topology_manifest.json</code>).</p>
    <div class="verify-files">
      <div class="file-slot">
        <label for="signedFile">Informe firmado por Wanadi</label>
        <input id="signedFile" type="file" accept=".json" onchange="loadFileInto(this, 'signedInput')">
        <details><summary>Pegar JSON</summary><textarea id="signedInput" aria-label="JSON del informe firmado"></textarea></details>
      </div>
      <div class="file-slot">
        <label for="localMapFile">Mapa privado (local_map.json)</label>
        <input id="localMapFile" type="file" accept=".json" onchange="loadFileInto(this, 'localMapInput')">
        <details><summary>Pegar JSON</summary><textarea id="localMapInput" aria-label="JSON del mapa privado"></textarea></details>
      </div>
      <div class="file-slot">
        <label for="expectedManifestFile">Manifiesto original</label>
        <input id="expectedManifestFile" type="file" accept=".json" onchange="loadFileInto(this, 'expectedManifestInput')">
        <details><summary>Pegar JSON</summary><textarea id="expectedManifestInput" aria-label="JSON del manifiesto original"></textarea></details>
      </div>
    </div>
    <details><summary>Ver clave pública instalada</summary>
      <input type="text" aria-label="Clave pública Ed25519" value="{pk_esc}" readonly>
    </details>
    <div class="row">
      <button class="btn" onclick="runRehydrate()">Verificar y reconstruir</button>
      <button class="btn sec" onclick="openRehydratedHtml()">Abrir informe HTML</button>
      <button class="btn sec" onclick="downloadVerifiedHtml()">Guardar informe</button>
    </div>
    <div id="rehydrateErr" class="err" role="alert"></div>
    <pre id="rehydrateOutput" aria-live="polite">// Esperando verificación...</pre>
  </div>
</div>

<script>
let lastHtmlReport = "";
function loadFileInto(input, targetId) {{
  const f = input.files[0]; if (!f) return;
  const r = new FileReader();
  r.onload = () => {{ document.getElementById(targetId).value = r.result; }};
  r.readAsText(f);
}}
async function runRehydrate() {{
  const errEl = document.getElementById('rehydrateErr'); errEl.textContent = '';
  try {{
    const signed_report_json = document.getElementById('signedInput').value;
    const local_map_json = document.getElementById('localMapInput').value;
    const expected_manifest_json = document.getElementById('expectedManifestInput').value;
    const res = await fetch('/api/rehydrate', {{
      method: 'POST', headers: {{'Content-Type': 'application/json'}},
      body: JSON.stringify({{signed_report_json, local_map_json, expected_manifest_json}})
    }});
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Error');
    lastHtmlReport = data.html_report || '';
    document.getElementById('rehydrateOutput').textContent = JSON.stringify(data.rehydrated_report, null, 2);
  }} catch (e) {{ errEl.textContent = e.message; }}
}}
function openRehydratedHtml() {{
  if (!lastHtmlReport) return;
  const blob = new Blob([lastHtmlReport], {{type: 'text/html;charset=utf-8'}});
  window.open(URL.createObjectURL(blob), '_blank', 'noopener');
}}
function downloadVerifiedHtml() {{
  if (!lastHtmlReport) return;
  const url = URL.createObjectURL(new Blob([lastHtmlReport], {{type:'text/html;charset=utf-8'}}));
  const a = document.createElement('a');
  a.href = url; a.download = 'tepuy_informe_tier1.html'; a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}}
</script>
</body>
</html>"""


class PortalState:
    def __init__(self, trusted_key: bytes, state_path: Path) -> None:
        self.trusted_key = trusted_key
        self.state_path = state_path
        self.pub_key_hex = trusted_key.hex()


class TepuyClientPortalHandler(http.server.BaseHTTPRequestHandler):
    portal_state: PortalState

    def _allow_local(self, post: bool = False) -> bool:
        host = f"127.0.0.1:{self.server.server_address[1]}"
        allowed = self.headers.get("Host") == host
        if post:
            allowed = allowed and self.headers.get("Origin") == f"http://{host}"
            allowed = allowed and self.headers.get_content_type() == "application/json"
        if not allowed:
            self._send_json(403, {"error": "Use the configured loopback portal"})
        return allowed

    def setup(self) -> None:
        self.request.settimeout(10)
        super().setup()

    def log_message(self, format: str, *args: Any) -> None:
        pass

    def _send_json(self, code: int, payload: Dict[str, Any]) -> None:
        body = json.dumps(payload, indent=2, ensure_ascii=True).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _read_json_body(self) -> Dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0 or length > MAX_BODY_BYTES:
            raise ValueError(f"Invalid Content-Length (must be 1..{MAX_BODY_BYTES} bytes)")
        raw = self.rfile.read(length)
        data = json.loads(raw.decode("utf-8"))
        if not isinstance(data, dict):
            raise ValueError("JSON body must be an object")
        return data

    def do_GET(self) -> None:
        if not self._allow_local():
            return
        if self.path == "/health":
            self._send_json(200, {
                "status": "OK",
                "service": "Tepuy Core Air-Gap Bridge Client Verification Portal",
                "pub_key_hex": self.portal_state.pub_key_hex,
                "role": "verify",
            })
            return
        if self.path in ("/", "/index.html"):
            body = _build_portal_html(self.portal_state.pub_key_hex).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Cache-Control", "no-store")
            self.send_header(
                "Content-Security-Policy",
                "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; "
                "img-src data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
            )
            self.end_headers()
            self.wfile.write(body)
            return
        self._send_json(404, {"error": "Not found"})

    def do_POST(self) -> None:
        if not self._allow_local(post=True):
            return
        try:
            payload = self._read_json_body()
            if self.path == "/api/rehydrate":
                if "pub_key_hex" in payload:
                    raise ValueError("The verification key comes from the local configuration")
                signed_report = request_document(payload, "signed_report")
                local_map = request_document(payload, "local_map")
                expected_manifest = request_document(payload, "expected_manifest")
                rehydrated, html_report = bridge.verify_once(
                    signed_report, local_map, self.portal_state.trusted_key,
                    expected_manifest, self.portal_state.state_path,
                )
                self._send_json(200, {
                    "rehydrated_report": rehydrated,
                    "html_report": html_report,
                })
                return
            self._send_json(404, {"error": "Not found"})
        except (ValueError, KeyError, TypeError, bridge.SecurityError) as exc:
            self._send_json(400, {"error": str(exc)})
        except (OSError, sqlite3.Error):
            self._send_json(503, {"error": "Local verification state is unavailable"})


def create_server(port: int, state: PortalState) -> socketserver.TCPServer:
    class BoundHandler(TepuyClientPortalHandler):
        portal_state = state

    class LoopbackServer(socketserver.TCPServer):
        allow_reuse_address = True

    return LoopbackServer(("127.0.0.1", port), BoundHandler)


def run_self_test() -> None:
    import urllib.error
    from contextlib import contextmanager

    @contextmanager
    def running(state):
        with create_server(0, state) as server:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                yield f"http://127.0.0.1:{server.server_address[1]}"
            finally:
                server.shutdown()
                thread.join()

    def request(base, path, data, status=200):
        req = urllib.request.Request(
            base + path, data=json.dumps(data).encode("utf-8"),
            headers={"Content-Type": "application/json", "Origin": base},
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as result:
                assert result.status == status
                return json.load(result)
        except urllib.error.HTTPError as exc:
            with exc:
                assert exc.code == status, exc
                return json.load(exc)

    pk = bytes.fromhex(bridge._STATIC_TEST_PUBKEY_HEX)
    signed_text = json.dumps(bridge._STATIC_TEST_SIGNED_REPORT)
    tampered = json.loads(signed_text)
    tampered["report_body"]["sps_global_score"] = 99.0
    payload = {
        "signed_report_json": signed_text,
        "local_map_json": json.dumps(bridge._STATIC_TEST_LOCAL_MAP),
        "expected_manifest_json": json.dumps(bridge._STATIC_TEST_MANIFEST),
    }
    with tempfile.TemporaryDirectory() as directory:
        state_path = Path(directory) / "state.sqlite3"
        with running(PortalState(pk, state_path)) as base:
            request(base, "/api/nonexistent", {}, status=404)
            request(base, "/api/rehydrate", {**payload, "pub_key_hex": pk.hex()}, status=400)
            rejected = request(base, "/api/rehydrate", {
                **payload, "signed_report_json": json.dumps(tampered),
            }, status=400)
            assert "ED25519_VERIFICATION_FAILED" in rejected["error"]
            verified = request(base, "/api/rehydrate", payload)
            assert verified["rehydrated_report"]["verified_ed25519"]
        with running(PortalState(pk, state_path)) as base:
            assert "already used" in request(base, "/api/rehydrate", payload, status=400)["error"]
    print("Client Portal self-test PASS (key pinning, manifest binding, tamper rejection, durable anti-replay)")


def main() -> int:
    parser = argparse.ArgumentParser(description="Tepuy Core Tier 1 Client Verification Portal")
    parser.add_argument("--port", type=int, default=8787)
    parser.add_argument("--pub-key-file", type=Path, help="Provisioned Wanadi Tactical Ed25519 public key (.pub)")
    parser.add_argument("--state-db", type=Path, default=bridge.private_state_dir() / "verified.sqlite3")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        run_self_test()
        return 0
    if args.pub_key_file is None:
        parser.error("Provide --pub-key-file <wanadi_tier1.pub>")

    state = PortalState(bridge.read_hex_key(args.pub_key_file), args.state_db)
    with create_server(args.port, state) as httpd:
        print(f"[*] Tepuy Core Tier 1 Client Verifier at http://127.0.0.1:{httpd.server_address[1]}", flush=True)
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
