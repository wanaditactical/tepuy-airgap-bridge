# Wanadi Tactical | Tepuy Core™ Air-Gap Bridge (Kit de Cliente · Tier 1)

![Tepuy Core™](tepuy-core.png)

## Guía Operativa y Acta de Aceptación para el CISO

**Tepuy Core™ Air-Gap Bridge (Tier 1)** ejecuta una inspección local estrictamente pasiva y en modo solo-lectura tanto en **Linux** como en **Windows / Windows Server**, usando **únicamente la biblioteca estándar de Python (`Python 3.10+`)**, sin instalar agentes, sin dependencias externas (`pip`) y sin subprocesos.

* **Aislamiento de red verificable (`collect` vs. portal opcional):** El colector (`collect`) bloquea toda creación de sockets y resolución DNS en tiempo de ejecución (`sys.addaudithook` + namespace `CLONE_NEWNET` en Linux cuando el kernel lo habilita), generando **cero tráfico de red**. De forma independiente y opcional, el portal visual de verificación (`tepuy_tier1_portal.py`) abre únicamente un listener HTTP local en **`127.0.0.1:8787` (solo *loopback*)**, sin aceptar conexiones remotas ni generar tráfico externo.
* **Cobertura pasiva Linux y Windows Server:** En Linux inspecciona puertos TCP (`/proc/net/tcp*`), paquetes `dpkg`, `ASLR`, volúmenes `LUKS` (`/sys/block`), módulos EDR (`/proc/modules`) y configuración `SSH` (`sshd_config`). En Windows / Windows Server inspecciona puertos TCP vía API nativa (`iphlpapi.dll`), perfiles de **Windows Firewall**, servicio **EDR / Windows Defender**, **BitLocker (`BitLockerStatus`)**, **RDP con NLA (`UserAuthentication`)**, **SMBv1**, `ASLR`, compilación OS (`Build.UBR`) y software de servidor en Registro (`winreg`).
* **Privacidad perimetral:** Su estación conserva en todo momento el mapa real de hostnames e IPs (`local_map.json`). Únicamente cruza hacia **Wanadi Tactical LLC** un manifiesto JSON en texto plano (~1 KB, `tepuy_topology_manifest.json`) filtrado por lista blanca estricta y seudonimizado con `HMAC-SHA256`, auditable visualmente antes de salir.
* **Deber de cuidado (Cero hallazgos retenidos):** El dictamen firmado por Wanadi Tactical (`tepuy_report_raw_signed.json`) entrega el **100 % de los hallazgos observados** en el alcance pasivo Tier 1 junto con el **Score SPS v2.0 renormalizado** en 6 dominios (los dominios no observables pasivamente se marcan `N/A`, nunca `100`).
* **Custodia separada de la clave pública (`wanadi_tier1.pub`):** Por diseño de seguridad, **la clave pública `wanadi_tier1.pub` NO se incluye dentro de este ZIP** (si viajara junto al kit o al reporte, un atacante que interceptara el paquete podría sustituir ambos). Wanadi Tactical entrega `wanadi_tier1.pub` por un **canal autenticado independiente** antes de iniciar la verificación. Tanto la CLI como el portal local aceptan `wanadi_tier1.pub` en formato **PEM estándar de OpenSSL (`-----BEGIN PUBLIC KEY-----`)** o en hexadecimal de 64 caracteres.
* **Fingerprint oficial verificado PROD (`wanadi_tier1.pub`):**
  * **SHA-256 (DER):** `7ffe5c91b815b6dfd21d0866351d4191c0b9780cd7ef5ccb87712ee0d9d44880`
  * **Signer Key ID (en dictamen):** `caf80fe2c43d7d82`
  * Compruebe en su equipo que `openssl pkey -pubin -in wanadi_tier1.pub -outform DER | sha256sum` coincida exactamente con este fingerprint antes de verificar un informe.
* **Rotación y respuesta ante compromiso de clave:** Si una clave institucional rotara o sufriera compromiso, Wanadi Tactical publicará de inmediato el aviso de revocación en **`https://wanaditactical.com/seguridad`**, emitirá una nueva clave con su nuevo *fingerprint* `SHA-256` y conservará el registro histórico de *fingerprints* para re-verificar dictámenes anteriores.
* **Licencia *Source-Available* de Evaluación Interna (Sin NDA previo — ver `LICENSE.txt`):** *Copyright © 2026 Wanadi Tactical LLC. Todos los derechos reservados.* Se autoriza gratuitamente la lectura íntegra del código, su auditoría de seguridad y su ejecución interna sobre sistemas propios del evaluador sin requerir NDA previo; queda prohibida su reventa comercial, uso por terceros/MSSPs, redistribución modificada o uso no autorizado de las marcas **Wanadi Tactical™** y **Tepuy Core™**.

---

## 1. Verificar el ancla del ZIP (fuera de banda) y la integridad interna

### Paso A — Verificar el SHA-512 del paquete `.zip` contra canal separado
Antes de descomprimir, compare el `SHA-512` de `WANADI_TEPUY_AIRGAP_BRIDGE_TIER1_CLIENT_KIT.zip` con el ancla publicada en **`https://wanaditactical.com/seguridad`** o recibida por correo institucional separado desde `jparisca@wanaditactical.com`:

**Linux / macOS:**
```sh
sha512sum WANADI_TEPUY_AIRGAP_BRIDGE_TIER1_CLIENT_KIT.zip
```

**Windows PowerShell:**
```powershell
(Get-FileHash -Algorithm SHA512 .\WANADI_TEPUY_AIRGAP_BRIDGE_TIER1_CLIENT_KIT.zip).Hash.ToLower()
```

### Paso B — Verificar los 7 archivos internos y ejecutar auto-pruebas (`7/7`)

**Linux:**
```sh
sha512sum -c TIER1_DELIVERABLE_SHA512.sha512
python3 tepuy_airgap_bridge.py test
python3 tepuy_tier1_portal.py --self-test
```

**Windows PowerShell:**
```powershell
Get-Content .\TIER1_DELIVERABLE_SHA512.sha512 | ForEach-Object {
    $expected, $relativePath = $_ -split '\s{2,}', 2
    $actual = (Get-FileHash -Algorithm SHA512 -LiteralPath $relativePath -ErrorAction Stop).Hash.ToLower()
    if ($actual -ne $expected.ToLower()) { throw "SHA-512 incorrecto: $relativePath" }
    "OK: $relativePath"
}
py -3 .\tepuy_airgap_bridge.py test
py -3 .\tepuy_tier1_portal.py --self-test
```

---

## 2. Recolectar y exportar el manifiesto seudonimizado

Ejecute `collect` en el servidor o estación autorizada a evaluar:

**Linux:**
```sh
python3 tepuy_airgap_bridge.py collect --out-dir ./export
```

**Windows PowerShell:**
```powershell
py -3 .\tepuy_airgap_bridge.py collect --out-dir .\export
```

1. El comando activa el bloqueo de sockets (`sys.addaudithook` + `CLONE_NEWNET` en Linux cuando aplica) e imprime las rutas exactas generadas (incluido el identificador `<DESAFIO>`).
2. **Revise visualmente `export/tepuy_topology_manifest.json`** (confirmará que solo contiene alias `NODE-XX-...`, puertos de lista blanca, señales booleanas y versiones permitidas) y **envíe únicamente ese archivo (~1 KB)** a su contacto en Wanadi Tactical LLC.
3. El mapa sensible `local_map.json` queda resguardado localmente y **jamás debe salir de su red**:
   * **Linux:** `~/.tepuy-airgap/<DESAFIO>/local_map.json`
   * **Windows:** `%USERPROFILE%\.tepuy-airgap\<DESAFIO>\local_map.json`

---

## 3. Verificar la firma de Wanadi Tactical y reconstruir el informe localmente

Una vez recibido `tepuy_report_raw_signed.json` de parte de Wanadi Tactical LLC (y contando con `wanadi_tier1.pub` recibida por canal autenticado separado):

### Opción A — Por línea de comandos (CLI)

**Linux** (sustituya `<DESAFIO>` por el nonce impreso durante `collect`):
```sh
python3 tepuy_airgap_bridge.py rehydrate \
  --signed-report ./tepuy_report_raw_signed.json \
  --manifest ./export/tepuy_topology_manifest.json \
  --local-map ~/.tepuy-airgap/<DESAFIO>/local_map.json \
  --pub-key-file ./wanadi_tier1.pub
```

**Windows PowerShell:**
```powershell
py -3 .\tepuy_airgap_bridge.py rehydrate `
  --signed-report .\tepuy_report_raw_signed.json `
  --manifest .\export\tepuy_topology_manifest.json `
  --local-map "$env:USERPROFILE\.tepuy-airgap\<DESAFIO>\local_map.json" `
  --pub-key-file .\wanadi_tier1.pub
```

El informe reconstruido en HTML5 (100 % offline, CSP `default-src 'none'`) y JSON queda guardado localmente en:
* **Linux:** `~/.tepuy-airgap/reports/<DESAFIO>/`
* **Windows:** `%USERPROFILE%\.tepuy-airgap\reports\<DESAFIO>\`

Para re-exportar un informe ya verificado desde la base SQLite local:
* **Linux:** `python3 tepuy_airgap_bridge.py recover --challenge <DESAFIO>`
* **Windows:** `py -3 .\tepuy_airgap_bridge.py recover --challenge <DESAFIO>`

### Opción B — Mediante Portal Local Loopback (`127.0.0.1:8787`, sin tráfico externo)

* **Linux:** `python3 tepuy_tier1_portal.py --pub-key-file ./wanadi_tier1.pub`
* **Windows:** `py -3 .\tepuy_tier1_portal.py --pub-key-file .\wanadi_tier1.pub`

Abra `http://127.0.0.1:8787` en su navegador local, cargue los tres JSON (`tepuy_report_raw_signed.json`, `local_map.json` y `tepuy_topology_manifest.json`) y descargue el informe HTML verificado.

---

## 4. Alcance del Tier 1 y Acta de Aceptación Ejecutiva (20 minutos)

| Prueba | Criterio de aceptación | Evidencia en poder del cliente |
| :--- | :--- | :--- |
| **Ancla externa del ZIP** | El `SHA-512` del `.zip` coincide con el publicado fuera de banda en `wanaditactical.com/seguridad` | Salida de `sha512sum` / `Get-FileHash` |
| **Integridad interna** | Los 7 archivos coinciden con `TIER1_DELIVERABLE_SHA512.sha512` y pruebas `7/7` pasan | Verificación `SHA-512` y suite `test` en verde |
| **Salida controlada** | Solo cruza `tepuy_topology_manifest.json` (~1 KB); `local_map.json` permanece en su red | Manifiesto auditado en texto plano |
| **Autenticidad (canal separado)** | Firma `Ed25519` válida contra `wanadi_tier1.pub` entregada por canal separado; cualquier alteración falla | Informe verificado localmente |
| **Protección Anti-Replay** | Un segundo intento con el mismo `<DESAFIO>` es rechazado aún tras reiniciar | Registro en `verified.sqlite3` |

### Límites explícitos del Tier 1 y siguiente escalón opcional
Por diseño, el colector pasivo Tier 1 **no ejecuta** análisis forense de memoria RAM viva (*Volatility 3*), rutas de privilegio en Active Directory (*BloodHound*), inspección pasiva OT/ICS sobre capturas PCAP, catálogo completo de 1.786 CVEs CISA KEV, síntesis de reglas YARA/SOAR ni firma poscuántica **SHA-512 + Ed25519 + ML-DSA-65 (NIST FIPS 204)**.

Cierre la evaluación con una **sesión ejecutiva de 20 minutos** bajo NDA junto a Wanadi Tactical LLC (`jparisca@wanaditactical.com` · `https://wanaditactical.com`). Si la criticidad de los hallazgos justifica una inspección profunda en campo con **Tepuy Core™ v3.0 Enterprise** (unidad M.2 en modo misión sin salida a internet), el **100 % del PoV táctico de 72 h (USD 2 500)** se acredita a la **Auditoría Express de USD 6 500** dentro de los **45 días** siguientes *(no aplicable a licencias Sentinel OS Pro, implementaciones Sovereign ni auditorías Enterprise)*.

---
*Copyright © 2026 Wanadi Tactical LLC (Delaware, USA). Todos los derechos reservados. Distribuido bajo Licencia Source-Available de Evaluación Interna (`LICENSE.txt`). Wanadi Tactical™ y Tepuy Core™ son marcas de Wanadi Tactical LLC.*
