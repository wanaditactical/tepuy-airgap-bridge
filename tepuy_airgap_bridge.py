#!/usr/bin/env python3
# Copyright (c) 2026 Wanadi Tactical LLC. All rights reserved.
# SPDX-License-Identifier: LicenseRef-Wanadi-Source-Available-Eval-1.0
# Source-available for internal CISO security audit & evaluation only (see LICENSE.txt).
# Commercial resale, MSSP/third-party service delivery, and derivative products prohibited.
"""
WANADI TACTICAL LLC - TEPUY CORE(TM) AIR-GAP BRIDGE (TIER 1 CLIENT KIT)
=======================================================================
100% Python Standard Library (Zero external dependencies: no pip, no OpenSSL CLI).
Compatible with Python 3.10 - 3.14+ on Linux (production) and Windows (verification/probe).

Client-Side Roles Only (Analyst SPS v2.0 Signing Engine stays in Wanadi Tactical custody):
  1. `collect`: Passive read-only host inventory + strict allowlist sanitizer + HMAC-SHA256
     pseudonymizer (`local_map.json` stays strictly inside customer perimeter; only ~1 KB
     plaintext `tepuy_topology_manifest.json` is exported to Wanadi Tactical).
  2. `rehydrate`: RFC 8032 Ed25519 signature verifier + `manifest_sha256` binding check +
     SQLite durable anti-replay + XSS-safe offline HTML/JSON local identity rehydrator.
  3. `recover`: Re-exports a previously verified report from local SQLite state.
  4. `test`: Runs client-side cryptographic, isolation, sanitization, and anti-replay tests.

Axiom: DECLARED != EXERCISED != VERIFIED != EVIDENCED
Doctrina: "The Internet assumes connectivity. Wanadi assumes failure."
"""

from __future__ import annotations

import argparse
import base64
import datetime
import hashlib
import hmac
import html
import json
import os
import platform
import re
import secrets
import socket
import sqlite3
import tempfile
from contextlib import closing
import sys
import unittest
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from tepuy_brand import IDENTITY_CSS, identity_header


# =====================================================================
# 1. HARDENED NETWORK KILL-SWITCH (KERNEL NETNS + CPYTHON AUDIT HOOK)
# =====================================================================

class NetworkIsolationError(RuntimeError):
    """Raised whenever any code attempts socket creation, DNS resolution, or connect."""


_AIRGAP_HOOK_INSTALLED = False


def _airgap_audit_hook(event: str, _args: Tuple[Any, ...]) -> None:
    blocked_prefixes = (
        "socket.__new__",
        "socket.connect",
        "socket.bind",
        "socket.sendto",
        "socket.sendmsg",
        "socket.getaddrinfo",
        "socket.getnameinfo",
        "urllib.Request",
        "http.client.connect",
        "ftplib.",
        "smtplib.",
    )
    if event.startswith(blocked_prefixes):
        raise NetworkIsolationError(
            f"TEPUY_AIRGAP_VIOLATION: CPython audit hook blocked network operation '{event}'."
        )


def enforce_airgap_runtime() -> Dict[str, str]:
    """
    Applies layered runtime network isolation:
      1. Linux CLONE_NEWNET network namespace if permitted (handles EPERM cleanly on
         CIS-hardened kernels where unprivileged_userns_clone=0).
      2. Process-wide irreversible `sys.addaudithook` blocking C-level `_socket` ops.
      3. High-level `socket` wrapper defense-in-depth.
    """
    global _AIRGAP_HOOK_INSTALLED
    status = {
        "kernel_netns": "UNSUPPORTED_OS",
        "audit_hook": "ACTIVE" if _AIRGAP_HOOK_INSTALLED else "PENDING",
        "runtime_socket_guard": "ACTIVE_SOCKET_BLOCKED",
    }

    if hasattr(os, "unshare") and hasattr(os, "CLONE_NEWNET"):
        try:
            os.unshare(os.CLONE_NEWNET)
            status["kernel_netns"] = "ISOLATED_CLONE_NEWNET"
        except PermissionError:
            status["kernel_netns"] = "SKIPPED_EPERM_CIS_HARDENED"
        except OSError as exc:
            status["kernel_netns"] = f"SKIPPED_OSERROR_{exc.errno}"

    if not _AIRGAP_HOOK_INSTALLED:
        sys.addaudithook(_airgap_audit_hook)
        _AIRGAP_HOOK_INSTALLED = True
        status["audit_hook"] = "ACTIVE_IRREVERSIBLE_CPYTHON_HOOK"

    def _blocked_socket(*_args: Any, **_kwargs: Any) -> None:
        raise NetworkIsolationError(
            "TEPUY_AIRGAP_VIOLATION: Python socket API is blocked."
        )

    for attr in (
        "socket",
        "create_connection",
        "create_server",
        "getaddrinfo",
        "getnameinfo",
        "socketpair",
        "fromfd",
    ):
        if hasattr(socket, attr):
            setattr(socket, attr, _blocked_socket)

    return status


# =====================================================================
# 2. PURE-PYTHON RFC 8032 Ed25519 (ZERO EXTERNAL DEPENDENCIES)
# =====================================================================

_Q = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _Q - 2, _Q)) % _Q
_I = pow(2, (_Q - 1) // 4, _Q)

Point = Tuple[int, int, int, int]  # Extended Twisted Edwards (X, Y, Z, T)


def _ed_add(p: Point, q: Point) -> Point:
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q
    a = ((y1 - x1) * (y2 - x2)) % _Q
    b = ((y1 + x1) * (y2 + x2)) % _Q
    c = (2 * t1 * t2 * _D) % _Q
    d = (2 * z1 * z2) % _Q
    e = (b - a) % _Q
    f = (d - c) % _Q
    g = (d + c) % _Q
    h = (b + a) % _Q
    return (e * f) % _Q, (g * h) % _Q, (f * g) % _Q, (e * h) % _Q


def _ed_scalarmult(p: Point, e: int) -> Point:
    res: Point = (0, 1, 1, 0)
    cur = p
    while e > 0:
        if e & 1:
            res = _ed_add(res, cur)
        cur = _ed_add(cur, cur)
        e >>= 1
    return res


def _xrecover(y: int) -> int:
    xx = (y * y - 1) * pow(_D * y * y + 1, _Q - 2, _Q) % _Q
    x = pow(xx, (_Q + 3) // 8, _Q)
    if (x * x - xx) % _Q != 0:
        x = (x * _I) % _Q
    if x % 2 != 0:
        x = _Q - x
    return x


_BY = (4 * pow(5, _Q - 2, _Q)) % _Q
_BX = _xrecover(_BY)
_BASE: Point = (_BX, _BY, 1, (_BX * _BY) % _Q)


def _encode_point(p: Point) -> bytes:
    x, y, z, _ = p
    zi = pow(z, _Q - 2, _Q)
    x = (x * zi) % _Q
    y = (y * zi) % _Q
    val = y | ((x & 1) << 255)
    return val.to_bytes(32, "little")


def _decode_point(b: bytes) -> Point:
    if len(b) != 32:
        raise ValueError("Invalid Ed25519 point length")
    unpacked = int.from_bytes(b, "little")
    sign = (unpacked >> 255) & 1
    y = unpacked & ((1 << 255) - 1)
    if y >= _Q:
        raise ValueError("Point y-coordinate out of field bounds")
    x = _xrecover(y)
    if (x * x * (_D * y * y + 1) - (y * y - 1)) % _Q != 0:
        raise ValueError("Point is not on curve Ed25519")
    if x == 0 and sign == 1:
        raise ValueError("Invalid x=0 with negative sign bit")
    if (x & 1) != sign:
        x = _Q - x
    return (x, y, 1, (x * y) % _Q)


def ed25519_verify(msg: bytes, sig: bytes, pk: bytes) -> bool:
    if len(sig) != 64 or len(pk) != 32:
        return False
    try:
        r_point = _decode_point(sig[:32])
        a_point = _decode_point(pk)
    except ValueError:
        return False
    s = int.from_bytes(sig[32:], "little")
    identity = bytes([1]) + bytes(31)
    if s >= _L or pk == identity:
        return False
    if _encode_point(_ed_scalarmult(a_point, _L)) != identity:
        return False
    k = int.from_bytes(hashlib.sha512(sig[:32] + pk + msg).digest(), "little") % _L
    lhs = _ed_scalarmult(_BASE, s)
    rhs = _ed_add(r_point, _ed_scalarmult(a_point, k))
    return _encode_point(lhs) == _encode_point(rhs)


def canonical_json_bytes(payload: Dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def sha256_canonical(payload: Dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


# =====================================================================
# 3. PASSIVE READ-ONLY HOST COLLECTOR & ALLOWLIST SANITIZER (STAGE 1/2)
# =====================================================================

ALLOWED_DISTRO_PACKAGES = frozenset({
    "openssh-server",
    "openssl",
    "sudo",
    "linux-image",
    "nginx",
    "postgresql",
    "docker-ce",
    "systemd",
    "glibc",
    "libc6",
    "polkit",
    "policykit-1",
    "xz-utils",
    "liblzma5",
    "apache2",
    "curl",
    "libcurl4",
})

ALLOWED_PORTS = frozenset({21, 22, 23, 80, 443, 445, 2375, 2376, 3389, 5432, 6443, 8080})
SAFE_VERSION_RE = re.compile(r"^(?:\d+:)?[0-9][0-9A-Za-z.\-+~]{0,47}$")


def _strip_package_epoch(version: str) -> str:
    """Strips Debian/RPM epoch (e.g. `1:9.2p1-2+deb12u2` -> `9.2p1-2+deb12u2`)."""
    return re.sub(r"^\d+:", "", version.strip())


def _parse_proc_net_tcp_listening(path: Path) -> List[int]:
    ports: set[int] = set()
    if not path.is_file():
        return []
    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()[1:]
        for line in lines:
            parts = line.split()
            if len(parts) >= 4 and parts[3] == "0A":  # TCP_LISTEN
                _, hex_port = parts[1].split(":")
                port = int(hex_port, 16)
                if port in ALLOWED_PORTS:
                    ports.add(port)
    except OSError:
        raise
    return sorted(ports)


def _read_dpkg_allowlist(status_path: Path) -> Dict[str, str]:
    pkgs: Dict[str, str] = {}
    if not status_path.is_file():
        return pkgs
    try:
        current_pkg: Optional[str] = None
        current_status_ok = False
        for line in status_path.read_text(encoding="utf-8", errors="ignore").splitlines():
            if not line.strip():
                current_pkg = None
                current_status_ok = False
                continue
            if line.startswith("Package: "):
                pkg_name = line.split(": ", 1)[1].strip()
                current_pkg = pkg_name if pkg_name in ALLOWED_DISTRO_PACKAGES else None
            elif line.startswith("Status: "):
                current_status_ok = "install ok installed" in line
            elif line.startswith("Version: ") and current_pkg and current_status_ok:
                ver = line.split(": ", 1)[1].strip()
                if SAFE_VERSION_RE.fullmatch(ver):
                    pkg_alias_map = {
                        "libc6": "glibc",
                        "policykit-1": "polkit",
                        "liblzma5": "xz-utils",
                        "libcurl4": "curl",
                    }
                    canonical_pkg = pkg_alias_map.get(current_pkg, current_pkg)
                    pkgs[canonical_pkg] = ver
    except OSError:
        pass
    return pkgs


def linux_listener_snapshot() -> Optional[List[int]]:
    try:
        if not Path("/proc/net/tcp").is_file():
            return None
        return sorted(set(_parse_proc_net_tcp_listening(Path("/proc/net/tcp"))) |
                      set(_parse_proc_net_tcp_listening(Path("/proc/net/tcp6"))))
    except (OSError, ValueError):
        return None


def linux_package_profile() -> str:
    try:
        fields = dict(line.split("=", 1) for line in Path("/etc/os-release").read_text().splitlines()
                      if "=" in line and not line.startswith("#"))
    except OSError:
        return "unknown"
    release = (fields.get("ID", "").strip('"'), fields.get("VERSION_ID", "").strip('"'))
    return {("ubuntu", "22.04"): "ubuntu-22.04", ("ubuntu", "24.04"): "ubuntu-24.04"}.get(release, "unknown")


def collect_local_host_inventory(
    airgap_status: Dict[str, str], listeners: Optional[List[int]] = None
) -> Dict[str, Any]:
    """
    OS-agnostic passive read-only collector dispatcher (0 sockets, 0 subprocesses).
    Adapts Linux (/proc, /sys, /etc, dpkg) and Windows (ctypes iphlpapi + winreg HKLM)
    into the 7-field canonical control schema.
    """
    hostname = platform.node() or "local-host"
    sys_name = platform.system().lower()

    if sys_name == "linux":
        return _collect_linux_passive_inventory(hostname, airgap_status, listeners)
    if sys_name == "windows":
        return _collect_windows_passive_inventory(hostname, airgap_status)

    return {
        "telemetry_mode": "READ_ONLY_OTHER_LOCAL_SUMMARY",
        "nodes": [
            {
                "hostname": hostname,
                "ip": "127.0.0.1",
                "subnet": "local-workstation",
                "os_family": "other",
                "os_build": None,
                "packages": {},
                "open_ports": None,
                "controls": {
                    "firewall_active": None,
                    "disk_encryption_active": None,
                    "edr_present": None,
                    "remote_admin_hardened": None,
                    "legacy_protocols_disabled": None,
                    "aslr_enabled": None,
                    "airgap_enforced": True if airgap_status.get("kernel_netns") == "ISOLATED_CLONE_NEWNET" else None,
                },
            }
        ],
    }


def _collect_linux_passive_inventory(
    hostname: str, airgap_status: Dict[str, str], listeners: Optional[List[int]] = None
) -> Dict[str, Any]:
    pkgs = _read_dpkg_allowlist(Path("/var/lib/dpkg/status"))

    aslr_enabled: Optional[bool] = None
    try:
        value = Path("/proc/sys/kernel/randomize_va_space").read_text(encoding="utf-8").strip()
        if value in {"0", "1", "2"}:
            aslr_enabled = (value == "2")
    except OSError:
        pass

    # Disk encryption (LUKS via sysfs dm/uuid)
    disk_encryption_active: Optional[bool] = None
    try:
        sys_block = Path("/sys/block")
        if sys_block.is_dir():
            dm_uuids = []
            for blk in sys_block.iterdir():
                uuid_file = blk / "dm" / "uuid"
                if uuid_file.is_file():
                    dm_uuids.append(uuid_file.read_text(encoding="utf-8", errors="ignore").strip())
            if dm_uuids:
                disk_encryption_active = any(u.startswith("CRYPT-LUKS") for u in dm_uuids)
    except OSError:
        disk_encryption_active = None

    # EDR / Security kernel modules (/proc/modules)
    edr_present: Optional[bool] = None
    try:
        mods_path = Path("/proc/modules")
        if mods_path.is_file():
            mods_txt = mods_path.read_text(encoding="utf-8", errors="ignore").lower()
            edr_markers = ("falcon_lsm", "sentinel", "CarbonBlack", "cbd", "sophos", "cyprotect", "eset_rtp")
            if any(m.lower() in mods_txt for m in edr_markers):
                edr_present = True
    except OSError:
        pass

    # Remote admin hardening (/etc/ssh/sshd_config)
    ssh_root_login: Optional[bool] = None
    ssh_password_auth: Optional[bool] = None
    try:
        sshd_cfg = Path("/etc/ssh/sshd_config")
        if sshd_cfg.is_file():
            for raw_line in sshd_cfg.read_text(encoding="utf-8", errors="ignore").splitlines():
                line = raw_line.split("#", 1)[0].strip()
                if not line:
                    continue
                parts = line.split()
                if len(parts) >= 2:
                    k_low, v_low = parts[0].lower(), parts[1].lower()
                    if k_low == "permitrootlogin" and ssh_root_login is None:
                        if v_low == "yes":
                            ssh_root_login = True
                        elif v_low in ("no", "prohibit-password", "without-password", "forced-commands-only"):
                            ssh_root_login = False
                    elif k_low == "passwordauthentication" and ssh_password_auth is None:
                        if v_low in ("yes", "no"):
                            ssh_password_auth = (v_low == "yes")
    except OSError:
        pass

    remote_admin_hardened: Optional[bool] = None
    if listeners is not None and 22 not in listeners:
        remote_admin_hardened = True
    elif ssh_root_login is True or ssh_password_auth is True:
        remote_admin_hardened = False
    elif ssh_root_login is False and ssh_password_auth is False:
        remote_admin_hardened = True

    legacy_protocols_disabled: Optional[bool] = None
    if listeners is not None:
        legacy_protocols_disabled = (23 not in listeners and 2375 not in listeners)

    return {
        "telemetry_mode": "LIVE_LINUX_READONLY_PROBE",
        "nodes": [
            {
                "hostname": hostname,
                "ip": "127.0.0.1",
                "subnet": "local-host-only",
                "os_family": "linux",
                "os_build": None,
                "packages": pkgs,
                "open_ports": listeners,
                "package_profile": linux_package_profile(),
                "controls": {
                    "firewall_active": None,
                    "disk_encryption_active": disk_encryption_active,
                    "edr_present": edr_present,
                    "remote_admin_hardened": remote_admin_hardened,
                    "legacy_protocols_disabled": legacy_protocols_disabled,
                    "aslr_enabled": aslr_enabled,
                    "airgap_enforced": True if airgap_status.get("kernel_netns") == "ISOLATED_CLONE_NEWNET" else None,
                },
            }
        ],
    }


def windows_listener_snapshot() -> Optional[List[int]]:
    # GetExtendedTcpTable reads Windows' listener table without opening a socket.
    import ctypes
    import struct
    from ctypes import wintypes

    try:
        query = ctypes.WinDLL("iphlpapi.dll", winmode=0x800).GetExtendedTcpTable
    except (AttributeError, OSError):
        return None
    query.argtypes = (
        ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD), wintypes.BOOL,
        wintypes.ULONG, ctypes.c_int, wintypes.ULONG,
    )
    query.restype = wintypes.DWORD
    ports = set()
    for family, row_bytes, port_offset in ((2, 24, 8), (23, 56, 20)):
        size = wintypes.DWORD()
        status = query(None, ctypes.byref(size), False, family, 3, 0)
        for _ in range(3):
            if status != 122 or not 4 <= size.value <= 16 * 1024 * 1024:
                return None
            data = ctypes.create_string_buffer(size.value)
            status = query(data, ctypes.byref(size), False, family, 3, 0)
            if status == 0:
                break
        else:
            return None
        count = struct.unpack_from("<I", data)[0]
        if 4 + count * row_bytes > len(data):
            return None
        for index in range(count):
            offset = 4 + index * row_bytes + port_offset
            port = struct.unpack_from(">H", data, offset)[0]
            if port in ALLOWED_PORTS:
                ports.add(port)
    return sorted(ports)


def _collect_windows_passive_inventory(hostname: str, airgap_status: Dict[str, Any]) -> Dict[str, Any]:
    """
    100% stdlib Windows / Windows Server adapter (`ctypes` + `winreg`, 0 sockets, 0 subprocesses).
    Populates the canonical OS-agnostic control schema + `os_build` (`Build.UBR`).
    """
    firewall_active: Optional[bool] = None
    disk_encryption_active: Optional[bool] = None
    edr_present: Optional[bool] = None
    remote_admin_hardened: Optional[bool] = None
    legacy_protocols_disabled: Optional[bool] = None
    aslr_enabled: Optional[bool] = None
    os_build: Optional[str] = None
    pkgs: Dict[str, str] = {}
    ports = windows_listener_snapshot()

    try:
        import winreg

        def read_val(hive: int, subkey: str, value_name: str) -> Any:
            try:
                with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ) as k:
                    val, _ = winreg.QueryValueEx(k, value_name)
                    return val
            except OSError:
                return None

        def read_dword(hive: int, subkey: str, value_name: str) -> Optional[int]:
            val = read_val(hive, subkey, value_name)
            try:
                return int(val) if val is not None else None
            except (ValueError, TypeError):
                return None

        # 1. OS Build + UBR (e.g. "20348.2762" or "26200.9974")
        cv_key = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
        build_num = read_val(winreg.HKEY_LOCAL_MACHINE, cv_key, "CurrentBuildNumber")
        ubr_num = read_dword(winreg.HKEY_LOCAL_MACHINE, cv_key, "UBR")
        build_int: Optional[int] = None
        if build_num is not None and str(build_num).strip().isdigit():
            build_int = int(str(build_num).strip())
            os_build = f"{build_int}.{ubr_num if ubr_num is not None else 0}"

        # 2. Firewall across Domain, Standard, and Public profiles
        fw_base = r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy"
        fw_vals = [
            read_dword(winreg.HKEY_LOCAL_MACHINE, fw_base + "\\" + prof, "EnableFirewall")
            for prof in ("DomainProfile", "StandardProfile", "PublicProfile")
        ]
        fw_known = [v for v in fw_vals if v is not None]
        if fw_known:
            firewall_active = all(v != 0 for v in fw_known)

        # 3. Defender + Real-Time Monitoring / Enterprise EDR services
        edr_services = (
            "WinDefend", "Sense", "CSAgent", "SentinelAgent", "CylanceSvc",
            "Sophos MCS Agent", "ds_agent", "ekrn", "CarbonBlack", "CbDefense",
        )
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services", 0, winreg.KEY_READ):
                found_edr = False
                for svc in edr_services:
                    start_type = read_dword(
                        winreg.HKEY_LOCAL_MACHINE,
                        "SYSTEM\\CurrentControlSet\\Services\\" + svc,
                        "Start",
                    )
                    if start_type in (0, 1, 2):
                        if svc == "WinDefend":
                            anti_spy = read_dword(
                                winreg.HKEY_LOCAL_MACHINE,
                                r"SOFTWARE\Policies\Microsoft\Windows Defender",
                                "DisableAntiSpyware",
                            )
                            rt_pol = read_dword(
                                winreg.HKEY_LOCAL_MACHINE,
                                r"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection",
                                "DisableRealtimeMonitoring",
                            )
                            rt_local = read_dword(
                                winreg.HKEY_LOCAL_MACHINE,
                                r"SOFTWARE\Microsoft\Windows Defender\Real-Time Protection",
                                "DisableRealtimeMonitoring",
                            )
                            if anti_spy == 1 or rt_pol == 1 or rt_local == 1:
                                continue
                        found_edr = True
                        break
                edr_present = found_edr
        except OSError:
            edr_present = None

        # 4. BitLocker OS boot volume protection via kernel BitLockerStatus (0 subprocesses)
        bl_boot = read_dword(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\BitLockerStatus",
            "BootStatus",
        )
        if bl_boot in (0, 1):
            disk_encryption_active = (bl_boot == 1)

        # 5. Remote Admin Hardened (RDP disabled OR NLA UserAuthentication == 1)
        deny_ts = read_dword(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\Terminal Server",
            "fDenyTSConnections",
        )
        if deny_ts == 1:
            remote_admin_hardened = True
        elif deny_ts == 0:
            nla = read_dword(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp",
                "UserAuthentication",
            )
            if nla is not None:
                remote_admin_hardened = (nla != 0)

        # 6. Legacy Protocols Disabled (SMBv1 disabled/absent AND Telnet 23 not listening)
        smb1_disabled: Optional[bool] = None
        smb1_param = read_dword(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
            "SMB1",
        )
        if smb1_param is not None:
            smb1_disabled = (smb1_param == 0)
        else:
            mrx_smb10 = read_dword(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Services\mrxsmb10",
                "Start",
            )
            if mrx_smb10 is not None:
                smb1_disabled = (mrx_smb10 == 4)
            else:
                try:
                    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\LanmanServer", 0, winreg.KEY_READ):
                        try:
                            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\mrxsmb10", 0, winreg.KEY_READ):
                                pass
                        except FileNotFoundError:
                            smb1_disabled = True
                except OSError:
                    pass

        if smb1_disabled is False or (ports is not None and 23 in ports):
            legacy_protocols_disabled = False
        elif smb1_disabled is True and (ports is None or 23 not in ports):
            legacy_protocols_disabled = True

        # 7. Kernel ASLR (MoveImages != 0; on Windows 8.1+ build >= 9600 default NT kernel ASLR is active unless MoveImages == 0)
        move_images = read_dword(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management",
            "MoveImages",
        )
        if move_images is not None:
            aslr_enabled = (move_images != 0)
        elif build_int is not None and build_int >= 9600:
            aslr_enabled = True

        # 8. Allowlisted server software from Uninstall registry hives
        app_map = {
            "openssh": "openssh-server",
            "openssl": "openssl",
            "curl": "curl",
            "postgresql": "postgresql",
            "nginx": "nginx",
            "apache": "apache2",
            "docker": "docker-ce",
        }
        uninstall_roots = (
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        )
        for root_path in uninstall_roots:
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, root_path, 0, winreg.KEY_READ) as root_key:
                    subcount = winreg.QueryInfoKey(root_key)[0]
                    for idx in range(subcount):
                        try:
                            subname = winreg.EnumKey(root_key, idx)
                            with winreg.OpenKey(root_key, subname, 0, winreg.KEY_READ) as app_key:
                                disp_name, _ = winreg.QueryValueEx(app_key, "DisplayName")
                                disp_ver, _ = winreg.QueryValueEx(app_key, "DisplayVersion")
                                name_low = str(disp_name).lower()
                                ver_str = str(disp_ver).strip()
                                if not SAFE_VERSION_RE.fullmatch(ver_str):
                                    continue
                                for needle, pkg_canon in app_map.items():
                                    if needle in name_low and pkg_canon in ALLOWED_DISTRO_PACKAGES:
                                        pkgs.setdefault(pkg_canon, ver_str)
                        except OSError:
                            continue
            except OSError:
                continue
    except (ImportError, OSError, TypeError, ValueError):
        pass

    return {
        "telemetry_mode": "READ_ONLY_WINDOWS_REGISTRY_PASSIVE",
        "nodes": [
            {
                "hostname": hostname,
                "ip": "127.0.0.1",
                "subnet": "local-workstation",
                "os_family": "windows",
                "os_build": os_build,
                "packages": pkgs,
                "open_ports": ports,
                "controls": {
                    "firewall_active": firewall_active,
                    "disk_encryption_active": disk_encryption_active,
                    "edr_present": edr_present,
                    "remote_admin_hardened": remote_admin_hardened,
                    "legacy_protocols_disabled": legacy_protocols_disabled,
                    "aslr_enabled": aslr_enabled,
                    "airgap_enforced": True if airgap_status.get("kernel_netns") == "ISOLATED_CLONE_NEWNET" else None,
                },
            }
        ],
    }


# Canonical OS-Agnostic Control Schema (7 neutral controls)
CONTROL_FIELDS = frozenset({
    "firewall_active",
    "disk_encryption_active",
    "edr_present",
    "remote_admin_hardened",
    "legacy_protocols_disabled",
    "aslr_enabled",
    "airgap_enforced",
})
LIVE_MODES = frozenset({
    "LIVE_LINUX_READONLY_PROBE", "READ_ONLY_WINDOWS_REGISTRY_PASSIVE", "READ_ONLY_OTHER_LOCAL_SUMMARY",
})
TELEMETRY_MODES = LIVE_MODES | {"SYNTHETIC_DEMO_FIXTURE_NOT_LIVE_SCAN", "FIXTURE_OR_PROBE"}
PACKAGE_PROFILES = ("unknown", "ubuntu-22.04", "ubuntu-24.04")
SAFE_OS_BUILD_RE = re.compile(r"^\d{4,6}\.\d{1,6}$")


def _normalize_controls_to_canonical(raw_ctrl: Dict[str, Any], os_fam: str, ports: Optional[List[int]]) -> Dict[str, Optional[bool]]:
    """
    Maps OS-specific or legacy fixture keys cleanly into the 7 canonical OS-agnostic controls.
    """
    def b(key: str) -> Optional[bool]:
        v = raw_ctrl.get(key)
        return v if type(v) is bool else None

    disk_enc = b("disk_encryption_active")
    if disk_enc is None:
        disk_enc = b("luks_encrypted")

    remote_hard = b("remote_admin_hardened")
    if remote_hard is None:
        if os_fam == "windows":
            remote_hard = b("rdp_nla_enforced")
        else:
            ssh_root = b("ssh_root_login")
            ssh_pass = b("ssh_password_auth")
            if ssh_root is True or ssh_pass is True:
                remote_hard = False
            elif ssh_root is False and ssh_pass is False:
                remote_hard = True

    legacy_off = b("legacy_protocols_disabled")
    if legacy_off is None:
        smb1_off = b("smbv1_disabled")
        if smb1_off is not None:
            legacy_off = smb1_off

    return {
        "firewall_active": b("firewall_active"),
        "disk_encryption_active": disk_enc,
        "edr_present": b("edr_present"),
        "remote_admin_hardened": remote_hard,
        "legacy_protocols_disabled": legacy_off,
        "aslr_enabled": b("aslr_enabled"),
        "airgap_enforced": b("airgap_enforced"),
    }


def sanitize_and_pseudonymize(
    raw_inventory: Dict[str, Any], secret_salt: bytes
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    if len(secret_salt) < 16:
        raise ValueError("secret_salt must be at least 16 bytes")

    nodes_manifest: List[Dict[str, Any]] = []
    pseudo_to_real: Dict[str, Dict[str, str]] = {}

    for idx, node in enumerate(raw_inventory.get("nodes", []), start=1):
        real_hostname = str(node.get("hostname", f"unknown-{idx}"))
        real_ip = str(node.get("ip", "0.0.0.0"))
        real_subnet = str(node.get("subnet", "0.0.0.0/0"))

        node_digest = hmac.new(
            secret_salt, f"{real_hostname}|{real_ip}".encode("utf-8"), hashlib.sha256
        ).hexdigest()[:8].upper()
        sub_digest = hmac.new(
            secret_salt, real_subnet.encode("utf-8"), hashlib.sha256
        ).hexdigest()[:6].upper()

        node_alias = f"NODE-{idx:02d}-{node_digest}"
        subnet_alias = f"SUBNET-{sub_digest}"

        pseudo_to_real[node_alias] = {
            "hostname": real_hostname,
            "ip": real_ip,
            "subnet_alias": subnet_alias,
            "real_subnet": real_subnet,
        }

        clean_packages: Dict[str, str] = {}
        for pkg_name, pkg_ver in node.get("packages", {}).items():
            ver_str = str(pkg_ver).strip()
            if pkg_name in ALLOWED_DISTRO_PACKAGES and SAFE_VERSION_RE.fullmatch(ver_str):
                clean_packages[pkg_name] = ver_str

        ports = node.get("open_ports")
        clean_ports = None if ports is None else sorted({p for p in ports if type(p) is int and p in ALLOWED_PORTS})
        os_fam = str(node.get("os_family", "other")).lower()
        os_fam = os_fam if os_fam in ("linux", "windows") else "other"

        controls = node.get("controls", {})
        clean_controls = _normalize_controls_to_canonical(controls if isinstance(controls, dict) else {}, os_fam, clean_ports)
        profile = node.get("package_profile", "unknown")

        raw_build = node.get("os_build")
        clean_build = str(raw_build).strip() if isinstance(raw_build, str) and SAFE_OS_BUILD_RE.fullmatch(str(raw_build).strip()) else None

        node_entry: Dict[str, Any] = {
            "node_id": node_alias,
            "subnet_id": subnet_alias,
            "os_family": os_fam,
            "packages": clean_packages,
            "package_profile": profile if profile in PACKAGE_PROFILES else "unknown",
            "open_ports": clean_ports,
            "controls": clean_controls,
        }
        if clean_build is not None:
            node_entry["os_build"] = clean_build
        nodes_manifest.append(node_entry)

    challenge_nonce = secrets.token_hex(16)
    mode = raw_inventory.get("telemetry_mode")
    manifest = {
        "schema_version": "tepuy.manifest.v2",
        "sanitization_mode": "STRICT_ALLOWLIST_PSEUDONYMIZED",
        "telemetry_mode": mode if isinstance(mode, str) and mode in TELEMETRY_MODES else "FIXTURE_OR_PROBE",
        "client_challenge_nonce": challenge_nonce,
        "nodes": nodes_manifest,
    }
    local_map = {
        "schema_version": "tepuy.local_map.v2",
        "warning": "SENSITIVE_NEVER_EXPORT_OUTSIDE_PERIMETER",
        "client_challenge_nonce": challenge_nonce,
        "consumed_challenges": [],
        "mappings": pseudo_to_real,
    }
    return manifest, local_map


def validate_manifest(manifest: Dict[str, Any]) -> None:
    allowed = {"schema_version", "sanitization_mode", "telemetry_mode", "client_challenge_nonce", "nodes"}
    if not isinstance(manifest, dict) or set(manifest) != allowed or manifest.get("schema_version") != "tepuy.manifest.v2":
        raise ValueError("Unsupported or unexpected manifest fields")
    if manifest["sanitization_mode"] != "STRICT_ALLOWLIST_PSEUDONYMIZED":
        raise ValueError("Unexpected sanitization mode")
    mode, nonce, nodes = (manifest[key] for key in ("telemetry_mode", "client_challenge_nonce", "nodes"))
    if not isinstance(mode, str) or mode not in TELEMETRY_MODES:
        raise ValueError("Unsupported telemetry mode")
    if not isinstance(nonce, str) or not re.fullmatch(r"[0-9a-f]{32,64}", nonce):
        raise ValueError("Invalid client challenge")
    if not isinstance(nodes, list) or not 1 <= len(nodes) <= 1000:
        raise ValueError("Manifest must contain 1 to 1000 nodes")
    node_ids = set()
    required = {"node_id", "subnet_id", "os_family", "packages", "open_ports", "controls"}
    optional = {"package_profile", "os_build"}
    for node in nodes:
        if not isinstance(node, dict) or not required <= set(node) <= (required | optional):
            raise ValueError("Unexpected node fields")
        if not isinstance(node["node_id"], str) or not re.fullmatch(r"NODE-[0-9]{2,4}-[A-F0-9]{8}", node["node_id"]):
            raise ValueError("Invalid node alias")
        if not isinstance(node["subnet_id"], str) or not re.fullmatch(r"SUBNET-[A-F0-9]{6}", node["subnet_id"]):
            raise ValueError("Invalid subnet alias")
        if node["node_id"] in node_ids or node["os_family"] not in ("linux", "windows", "other"):
            raise ValueError("Duplicate alias or invalid OS")
        node_ids.add(node["node_id"])
        if node.get("package_profile", "unknown") not in PACKAGE_PROFILES:
            raise ValueError("Invalid package profile")
        if "os_build" in node and node["os_build"] is not None:
            if not isinstance(node["os_build"], str) or not SAFE_OS_BUILD_RE.fullmatch(node["os_build"]):
                raise ValueError("Invalid os_build format")
        packages, ports, controls = node["packages"], node["open_ports"], node["controls"]
        if not isinstance(packages, dict) or any(
            name not in ALLOWED_DISTRO_PACKAGES or not isinstance(version, str) or not SAFE_VERSION_RE.fullmatch(version)
            for name, version in packages.items()
        ):
            raise ValueError("Invalid package inventory")
        if ports is not None and (not isinstance(ports, list) or any(
            type(port) is not int or port not in ALLOWED_PORTS for port in ports
        )):
            raise ValueError("Invalid listener inventory")
        if not isinstance(controls, dict) or any(
            name not in CONTROL_FIELDS or (value is not None and type(value) is not bool)
            for name, value in controls.items()
        ):
            raise ValueError("Invalid control inventory")




# =====================================================================
# 5. CRYPTOGRAPHIC VERIFIER & ANTI-INJECTION LOCAL REHYDRATOR
# =====================================================================

SAFE_ID_RE = re.compile(r"^[A-Z0-9_\-]{3,40}$")


class SecurityError(Exception):
    """Raised on Ed25519 mismatch, manifest replay mismatch, or schema injection."""


def verify_and_rehydrate_locally(
    signed_report: Dict[str, Any],
    local_map: Dict[str, Any],
    trusted_public_key: bytes,
    expected_manifest: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    if not isinstance(signed_report, dict):
        raise SecurityError("SCHEMA_VIOLATION: Envelope must be JSON object")
    if "report_body" not in signed_report or "signature_ed25519_hex" not in signed_report:
        raise ValueError("Malformed signed report envelope")

    report_body = signed_report["report_body"]
    if not isinstance(report_body, dict) or report_body.get("schema_version") != "tepuy.report.raw.v2":
        raise SecurityError("SCHEMA_VIOLATION: Invalid or unsupported report_body schema_version")

    try:
        sig_hex = str(signed_report["signature_ed25519_hex"])
        sig_bytes = bytes.fromhex(sig_hex)
    except ValueError as exc:
        raise SecurityError("SIGNATURE_MALFORMED: Invalid hex encoding") from exc

    if not ed25519_verify(canonical_json_bytes(report_body), sig_bytes, trusted_public_key):
        raise SecurityError("ED25519_VERIFICATION_FAILED: Report integrity compromised")

    if not isinstance(expected_manifest, dict):
        raise SecurityError("Original manifest is required")
    validate_manifest(expected_manifest)
    if report_body.get("manifest_sha256") != sha256_canonical(expected_manifest):
        raise SecurityError("Signed report SHA-256 does not match the original manifest")
    if report_body.get("client_challenge_nonce") != expected_manifest["client_challenge_nonce"]:
        raise SecurityError("Signed challenge does not match the original manifest")

    if not isinstance(local_map, dict) or local_map.get("schema_version") != "tepuy.local_map.v2":
        raise SecurityError("Invalid local map")
    expected_challenge = str(local_map.get("client_challenge_nonce", "")).strip()
    report_challenge = str(report_body.get("client_challenge_nonce", "")).strip()
    if not expected_challenge or report_challenge != expected_challenge:
        raise SecurityError("ANTI_REPLAY_VIOLATION: Signed report client_challenge_nonce mismatch")
    consumed_challenges = local_map.setdefault("consumed_challenges", [])
    if not isinstance(consumed_challenges, list):
        raise SecurityError("SCHEMA_VIOLATION: local_map.consumed_challenges must be list")
    if expected_challenge in consumed_challenges:
        raise SecurityError("ANTI_REPLAY_VIOLATION: client_challenge_nonce already consumed (one-time challenge)")

    sps_score = float(report_body["sps_global_score"])
    if not (0.0 <= sps_score <= 100.0):
        raise SecurityError("SCHEMA_VIOLATION: SPS global score out of [0, 100] bounds")

    raw_findings = report_body.get("tier1_included_findings")
    if not isinstance(raw_findings, list):
        raise SecurityError("SCHEMA_VIOLATION: Invalid Tier 1 findings list")

    mappings = local_map.get("mappings")
    if not isinstance(mappings, dict) or set(mappings) != {node["node_id"] for node in expected_manifest["nodes"]}:
        raise SecurityError("Local map does not match manifest aliases")
    rehydrated_findings: List[Dict[str, Any]] = []

    for item in raw_findings:
        if not isinstance(item, dict):
            raise SecurityError("SCHEMA_VIOLATION: Finding entry must be object")
        node_alias = str(item.get("node_id", ""))
        rule_id = str(item.get("rule_id", ""))
        domain_id = str(item.get("domain_id", ""))
        if not SAFE_ID_RE.match(node_alias) or not SAFE_ID_RE.match(rule_id) or not SAFE_ID_RE.match(domain_id):
            raise SecurityError("SCHEMA_VIOLATION: Illegal identifier characters in finding")
        if node_alias not in mappings:
            raise SecurityError(f"UNMAPPED_ALIAS: '{node_alias}' does not exist in local_map.json")

        real_info = mappings[node_alias]
        rehydrated_findings.append({
            "node_alias": node_alias,
            "real_hostname": html.escape(str(real_info["hostname"]), quote=True),
            "real_ip": html.escape(str(real_info["ip"]), quote=True),
            "domain_id": html.escape(domain_id, quote=True),
            "rule_id": html.escape(rule_id, quote=True),
            "severity": html.escape(str(item.get("severity", "UNKNOWN")), quote=True),
            "penalty": int(item.get("penalty", 0)),
            "title": html.escape(str(item.get("title", "")), quote=True),
            "remediation_preview": html.escape(str(item.get("remediation_preview", "")), quote=True),
            "observation": html.escape(str(item.get("observation", "Consultar el manifiesto original.")), quote=True),
        })

    consumed_challenges.append(expected_challenge)

    return {
        "verified_ed25519": True,
        "manifest_sha256_verified": expected_manifest is not None,
        "challenge_nonce_consumed": True,
        "telemetry_mode": report_body.get("telemetry_mode", "FIXTURE_OR_PROBE"),
        "coverage": report_body.get("coverage"),
        "manifest_sha256": str(report_body["manifest_sha256"]),
        "client_challenge_nonce": report_challenge,
        "audit_timestamp_utc": html.escape(str(report_body["audit_timestamp_utc"]), quote=True),
        "sps_global_score": sps_score,
        "risk_tier": html.escape(str(report_body["risk_tier"]), quote=True),
        "risk_color_hex": html.escape(str(report_body["risk_color_hex"]), quote=True),
        "remediation_sla_days": int(report_body["remediation_sla_days"]),
        "domain_breakdown": report_body["domain_breakdown"],
        "total_findings_detected": int(report_body["total_findings_detected"]),
        "tier2_locked_findings_count": int(report_body["tier2_locked_findings_count"]),
        "rehydrated_findings": rehydrated_findings,
        "commercial_upsell_gate": html.escape(str(report_body["commercial_upsell_gate"]), quote=True),
    }


def private_state_dir() -> Path:
    return Path.home() / ".tepuy-airgap"


def verify_once(
    signed: Dict[str, Any], local_map: Dict[str, Any], key: bytes,
    manifest: Dict[str, Any], state_path: Path,
) -> Tuple[Dict[str, Any], str]:
    consumed = local_map.get("consumed_challenges", [])
    if not isinstance(consumed, list):
        raise SecurityError("Invalid consumed challenges")
    report = verify_and_rehydrate_locally(
        signed, {**local_map, "consumed_challenges": consumed.copy()}, key, expected_manifest=manifest,
    )
    rendered = render_rehydrated_html_report(report)
    state_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(state_path, os.O_WRONLY | os.O_CREAT, 0o600)
    os.close(fd)
    with closing(sqlite3.connect(state_path, timeout=10)) as db, db:
        db.execute("CREATE TABLE IF NOT EXISTS consumed (nonce TEXT PRIMARY KEY, report_json TEXT NOT NULL)")
        try:
            db.execute("INSERT INTO consumed VALUES (?, ?)",
                       (manifest["client_challenge_nonce"], json.dumps(report, ensure_ascii=True)))
        except sqlite3.IntegrityError as exc:
            raise SecurityError("Client challenge already used") from exc
    return report, rendered


def _write_text_secure(path: Path, content: str, restricted: bool = False) -> None:
    path.parent.mkdir(mode=0o700 if restricted else 0o755, parents=True, exist_ok=True)
    stream = tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent, delete=False)
    temporary_path = Path(stream.name)
    try:
        with stream:
            stream.write(content)
        temporary_path.replace(path)
    finally:
        temporary_path.unlink(missing_ok=True)


def _write_json_secure(path: Path, data: Dict[str, Any], restricted: bool = False) -> None:
    _write_text_secure(path, json.dumps(data, indent=2, ensure_ascii=False) + "\n", restricted)


_ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")


def read_hex_key(path: Path) -> bytes:
    """Reads a 32-byte Ed25519 key from either 64-char hex or OpenSSL SPKI PEM (`-----BEGIN PUBLIC KEY-----`)."""
    raw = path.read_text(encoding="ascii").strip()
    if "-----BEGIN PUBLIC KEY-----" in raw:
        b64_lines = [
            line.strip() for line in raw.splitlines()
            if line.strip() and not line.strip().startswith("-----")
        ]
        der = base64.b64decode("".join(b64_lines), validate=True)
        if len(der) != len(_ED25519_SPKI_PREFIX) + 32 or not der.startswith(_ED25519_SPKI_PREFIX):
            raise ValueError("PEM public key must be a valid Ed25519 SubjectPublicKeyInfo")
        return der[len(_ED25519_SPKI_PREFIX):]
    key = bytes.fromhex(raw)
    if len(key) != 32:
        raise ValueError("Ed25519 key must contain exactly 32 bytes")
    return key


# =====================================================================
# 6. OFFLINE HTML REPORT RENDERER (HONEST N/A DOMAIN DISPLAY)
# =====================================================================

def render_rehydrated_html_report(rehydrated_report: Dict[str, Any]) -> str:
    e = lambda val: html.escape(html.unescape(str(val)), quote=True)

    sps_score = float(rehydrated_report.get("sps_global_score", 0.0))
    risk_tier = e(rehydrated_report.get("risk_tier", "UNKNOWN"))
    audit_ts = e(rehydrated_report.get("audit_timestamp_utc", "N/A"))
    sla_days = int(rehydrated_report.get("remediation_sla_days", 0))
    manifest_hash = e(rehydrated_report.get("manifest_sha256", "N/A"))
    total_findings = int(rehydrated_report.get("total_findings_detected", 0))
    ed_ok = bool(rehydrated_report.get("verified_ed25519", False))
    sha_ok = bool(rehydrated_report.get("manifest_sha256_verified", False))
    verif_status = "ED25519 + SHA-256 VERIFIED" if (ed_ok and sha_ok) else ("ED25519 VERIFIED" if ed_ok else "UNVERIFIED")

    partial = risk_tier == "PARTIAL_COVERAGE"
    tier_label = {
        "PARTIAL_COVERAGE": "Cobertura parcial", "HARDENED": "Reforzado",
        "GOOD": "Favorable", "MODERATE_RISK": "Riesgo moderado",
        "HIGH_RISK": "Riesgo alto", "CRITICAL": "Riesgo crítico",
    }.get(risk_tier, risk_tier)
    synthetic = rehydrated_report.get("telemetry_mode") not in LIVE_MODES
    score_color = "#FFB969" if partial else ("#00D9A5" if sps_score >= 80 else ("#FFB969" if sps_score >= 55 else "#FF6474"))

    domain_rows = []
    raw_breakdown = rehydrated_report.get("domain_breakdown", [])
    for info in raw_breakdown:
        dom_id = e(info.get("id", ""))
        dom_name = e(info.get("name", dom_id))
        dom_weight = int(round(float(info.get("weight", 0.0)) * 100))
        raw_sc = info.get("score")
        if raw_sc is None:
            domain_rows.append(
                f"<tr>"
                f"<td><code>{dom_id}</code></td>"
                f"<td>{dom_name}</td>"
                f"<td>{dom_weight}%</td>"
                f"<td><span style='font-size:12px;color:#8FA8C2;'>No evaluado en alcance pasivo Tier 1 (requiere PoV M.2)</span></td>"
                f"<td class='num' style='color:#8FA8C2;'>N/A</td>"
                f"</tr>"
            )
        else:
            dom_score = float(raw_sc)
            bar_color = "#00D9DA" if dom_score >= 75 else ("#FF9F1C" if dom_score >= 45 else "#FF3B5C")
            domain_rows.append(
                f"<tr>"
                f"<td><code>{dom_id}</code></td>"
                f"<td>{dom_name}</td>"
                f"<td>{dom_weight}%</td>"
                f"<td><div class='bar-bg'><div class='bar-fill' style='width:{max(0, min(100, dom_score)):.1f}%;background:{bar_color};'></div></div></td>"
                f"<td class='num'>{dom_score:.1f} / 100</td>"
                f"</tr>"
            )

    coverage = rehydrated_report.get("coverage") or {}
    builds_info = ", ".join(coverage.get("os_builds") or [])
    build_segment = f" · OS Build: {builds_info}" if builds_info else ""
    coverage_note = (
        f"Telemetría: {rehydrated_report.get('telemetry_mode', 'desconocida')}{build_segment} · "
        f"Dominios evaluados: {coverage.get('evaluated_domains', '—')}/{coverage.get('total_domains', 6)} "
        f"(peso medido {int(round(float(coverage.get('evaluated_weight_ratio', 0.0)) * 100))}%) · "
        f"Controles canónicos observados: {coverage.get('control_observations', '—')}/{coverage.get('control_slots', '—')}. "
        "Los dominios no medibles pasivamente se marcan N/A y se excluyen del denominador (nunca reciben 100 puntos artificiales)."
    )

    finding_cards = []
    for idx, f in enumerate(rehydrated_report.get("rehydrated_findings", []), start=1):
        sev = str(f.get("severity", "MEDIUM")).upper()
        sev_cls = "crit" if sev == "CRITICAL" else ("high" if sev == "HIGH" else "med")
        finding_cards.append(
            f"<div class='finding {sev_cls}'>"
            f"<div class='f-head'>"
            f"<span class='badge {sev_cls}'>{e(sev)}</span>"
            f"<span class='rule'>{e(f.get('rule_id', ''))} &middot; {e(f.get('domain_id', ''))}</span>"
            f"<span class='penalty'>-{int(f.get('penalty', 0))} pts</span>"
            f"</div>"
            f"<h3>#{idx}: {e(f.get('title', ''))}</h3>"
            f"<div class='meta'>"
            f"<span><strong>Host:</strong> <code>{e(f.get('real_hostname', 'UNMAPPED'))}</code> ({e(f.get('real_ip', ''))})</span>"
            f"<span><strong>Alias:</strong> <code>{e(f.get('node_alias', ''))}</code></span>"
            f"</div>"
            f"<p class='rem'><strong>Evidencia observada:</strong> {e(f.get('observation', 'Consultar el manifiesto.'))}</p>"
            f"<p class='rem'><strong>Próxima acción:</strong> {e(f.get('remediation_preview', ''))}</p>"
            f"</div>"
        )

    return f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src data:; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>Tepuy Core™ · Informe Tier 1 | Wanadi Tactical</title>
<style>
  :root {{
    --bg:#02070D; --panel:#0A1420; --border:#14283D; --cyan:#00F2FE;
    --teal:#00D9DA; --text:#F4F7FB; --muted:#8FA8C2;
    --crit:#FF3B5C; --high:#FF9F1C; --med:#FFD166;
  }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; padding:28px; background:var(--bg); color:var(--text);
         font-family:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif; line-height:1.5; }}
  .wrap {{ max-width:1040px; margin:0 auto; }}
  .header {{ display:flex; justify-content:space-between; align-items:flex-start; gap:20px;
            border-bottom:1px solid var(--border); padding-bottom:18px; margin-bottom:22px; flex-wrap:wrap; }}
  h1 {{ margin:6px 0 4px; font-size:24px; color:var(--text); }}
  .sub {{ color:var(--muted); font-size:13px; }}
  .pill {{ display:inline-block; padding:5px 11px; border:1px solid var(--teal); color:var(--teal);
          border-radius:999px; font-size:12px; font-weight:600; background:rgba(0,217,218,0.08); }}
  .grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(220px,1fr)); gap:14px; margin-bottom:22px; }}
  .card {{ background:var(--panel); border:1px solid var(--border); border-radius:10px; padding:16px; }}
  .card .lbl {{ font-size:11px; text-transform:uppercase; letter-spacing:1.2px; color:var(--muted); }}
  .card .val {{ font-size:28px; font-weight:800; margin-top:6px; }}
  .panel {{ background:var(--panel); border:1px solid var(--border); border-radius:10px; padding:18px; margin-bottom:20px; }}
  .panel h2 {{ margin:0 0 14px; font-size:16px; color:var(--cyan); letter-spacing:0.6px; text-transform:uppercase; }}
  table {{ width:100%; border-collapse:collapse; font-size:13px; }}
  th, td {{ padding:10px 8px; border-bottom:1px solid var(--border); text-align:left; }}
  th {{ color:var(--muted); font-weight:600; font-size:11px; text-transform:uppercase; }}
  td.num {{ text-align:right; font-variant-numeric:tabular-nums; font-weight:700; }}
  .bar-bg {{ width:100%; min-width:140px; height:8px; background:#050D17; border-radius:99px; overflow:hidden; }}
  .bar-fill {{ height:100%; border-radius:99px; }}
  .finding {{ border:1px solid var(--border); border-left:4px solid var(--cyan); border-radius:8px;
             padding:14px; margin-bottom:12px; background:#07101B; }}
  .finding.crit {{ border-left-color:var(--crit); }}
  .finding.high {{ border-left-color:var(--high); }}
  .finding.med {{ border-left-color:var(--med); }}
  .f-head {{ display:flex; align-items:center; gap:10px; font-size:12px; margin-bottom:6px; flex-wrap:wrap; }}
  .badge {{ padding:2px 8px; border-radius:4px; font-weight:700; font-size:11px; color:#02070D; }}
  .badge.crit {{ background:var(--crit); }} .badge.high {{ background:var(--high); }} .badge.med {{ background:var(--med); }}
  .rule {{ color:var(--muted); }}
  .penalty {{ margin-left:auto; color:var(--crit); font-weight:700; }}
  .finding h3 {{ margin:4px 0 10px; font-size:15px; }}
  .meta {{ display:flex; flex-wrap:wrap; gap:14px; font-size:12px; color:var(--muted); margin-bottom:8px; }}
  .rem {{ margin:0; font-size:13px; color:#CFE2F5; }}
  code {{ background:#030A12; padding:2px 6px; border-radius:4px; color:var(--cyan); font-size:12px; }}
  .cta {{ border:1px solid var(--cyan); background:linear-gradient(135deg,#071625,#040C16);
         border-radius:10px; padding:18px; margin-bottom:20px; }}
  .crypto {{ font-size:11px; color:var(--muted); word-break:break-all; }}
{IDENTITY_CSS}
body {{ margin:0; padding:clamp(16px,5vw,56px); background:var(--wt-ink); }}
.wrap {{ max-width:1050px; margin:0 auto; }}
.header h1 {{ font-size:clamp(29px,5vw,56px); line-height:1.04; letter-spacing:-.043em; margin:.2em 0; }}
.panel, .card {{ background:var(--wt-navy); border-color:var(--wt-line); }}
.cta {{ background:var(--wt-navy); border:1px solid var(--wt-line); border-left:3px solid var(--wt-violet); }}
.summary-note {{ color:var(--wt-muted); max-width:72ch; line-height:1.6; }}
.report-actions {{ margin:0; padding-left:1.25rem; line-height:1.65; }}
.report-actions li + li {{ margin-top:.35rem; }}
.crypto code {{ overflow-wrap:anywhere; }}
@media print {{
  body {{ background:#fff; color:#061421; padding:0; }}
  .panel, .card, .cta, .finding {{ background:white; color:#061421; border-color:#678090; break-inside:avoid; }}
  .summary-note, .sub, .lbl, .meta, .num, .rem, .pill, .panel th, .panel td, code {{ color:#17344a !important; }}
  .brand-lockup {{ width:max-content; padding:5px 12px; background:#02070D; print-color-adjust:exact; }}
}}
</style>
</head>
<body>
<div class="wrap">
  <div class="header">
    <div>
      {identity_header()}
      <span class="brand-kicker">Informe confidencial · Tier 1{' · Datos de prueba' if synthetic else ''}</span>
      <h1>Diagnóstico de postura</h1>
      <p class="summary-note">Tepuy Core™ Air-Gap Bridge · Esquema Canónico Linux &amp; Windows Server</p>
      <div class="sub">Fecha UTC: <code>{audit_ts}</code> &middot; Plazo sugerido: <code>{f'{sla_days} días' if sla_days else 'Sin establecer'}</code></div>
    </div>
    <span class="pill">{verif_status}</span>
  </div>

  <div class="grid">
    <div class="card"><div class="lbl">SPS v2.0 {'indicativo' if partial else 'renormalizado'}</div><div class="val" style="color:{score_color};">{'N/A' if partial and coverage.get('evaluated_domains', 0) == 0 else f'{sps_score:.2f} / 100'}</div></div>
    <div class="card"><div class="lbl">Interpretación</div><div class="val" style="font-size:20px;">{tier_label}</div></div>
    <div class="card"><div class="lbl">Hallazgos entregados</div><div class="val">{total_findings}</div></div>
  </div>

  <div class="panel">
    <h2>Hallazgos observados (100 % entregados · Cero recortes)</h2>
    {"".join(finding_cards) if finding_cards else "<p>Los controles evaluados en este nodo se encuentran activos/endurecidos. Revise la tabla de cobertura inferior para ver qué dominios quedaron N/A fuera del alcance pasivo.</p>"}
  </div>

  <div class="panel">
    <h2>Cobertura y desglose SPS v2.0</h2>
    <p class="summary-note">{e(coverage_note)}</p>
    <table>
      <thead><tr><th>ID</th><th>Dominio</th><th>Peso</th><th>Estado</th><th style="text-align:right;">SPS</th></tr></thead>
      <tbody>{"".join(domain_rows)}</tbody>
    </table>
  </div>

  <div class="cta">
    <h2>Decisión para el CISO</h2>
    <ol class="report-actions">
      <li>Este informe entrega el 100 % de los hallazgos detectados ({total_findings}) dentro del alcance pasivo Tier 1, sin ocultar vulnerabilidades.</li>
      <li>Los dominios marcados como <code>N/A</code> no fueron evaluados por diseño pasivo (sin agente ni volcado de memoria) y jamás reciben puntaje artificial de 100/100.</li>
      <li>Para inspección profunda con Tepuy Core™ v3.0 Enterprise (12 motores M.2 offline: RAM viva con Volatility 3, Active Directory BloodHound, OT/ICS pasivo, 1.786 CVEs CISA KEV, reglas YARA/SOAR y firma poscuántica ML-DSA-65 FIPS 204), coordine el PoV táctico de 72 h (USD 2 500, 100 % acreditable a la Auditoría Express de USD 6 500 en 45 días).</li>
    </ol>
    <p class="summary-note">Contacto ejecutivo (sesión de 20 min bajo NDA): <strong>jparisca@wanaditactical.com</strong> · <strong>wanaditactical.com</strong>.</p>
  </div>

  <div class="panel crypto">
    <h2>Integridad y trazabilidad</h2>
    <div><strong>Manifest SHA-256:</strong> <code>{manifest_hash}</code></div>
    <div style="margin-top:6px;"><strong>Ed25519 Verified:</strong> <code>{ed_ok}</code> &middot; <strong>Anti-Replay Nonce Consumed:</strong> <code>{bool(rehydrated_report.get("challenge_nonce_consumed", False))}</code></div>
    <div style="margin-top:8px;"><em>"The Internet assumes connectivity. Wanadi assumes failure." — Copyright &copy; 2026 Wanadi Tactical LLC &middot; Uso exclusivo de evaluaci&oacute;n interna (ver LICENSE.txt) &middot; Generado sin conexi&oacute;n.</em></div>
  </div>
</div>
</body>
</html>"""



# =====================================================================
# 7. CLIENT-SIDE VERIFICATION & ISOLATION UNITTEST SUITE
# =====================================================================

_STATIC_TEST_PUBKEY_HEX = "659d09dfc22c7804c6686876e413d55010d51b5703e296b1c9a0289160a10384"
_STATIC_TEST_MANIFEST = json.loads("{\"client_challenge_nonce\": \"0319b28dc7f33aedfd3365255a5a3013\", \"nodes\": [{\"controls\": {\"airgap_enforced\": null, \"aslr_enabled\": null, \"disk_encryption_active\": null, \"edr_present\": null, \"firewall_active\": false, \"legacy_protocols_disabled\": null, \"remote_admin_hardened\": false}, \"node_id\": \"NODE-01-3D3AE8AF\", \"open_ports\": [22, 2375], \"os_family\": \"linux\", \"package_profile\": \"unknown\", \"packages\": {\"openssh-server\": \"1:9.2p1-2+deb12u2\"}, \"subnet_id\": \"SUBNET-456940\"}], \"sanitization_mode\": \"STRICT_ALLOWLIST_PSEUDONYMIZED\", \"schema_version\": \"tepuy.manifest.v2\", \"telemetry_mode\": \"SYNTHETIC_DEMO_FIXTURE_NOT_LIVE_SCAN\"}")
_STATIC_TEST_LOCAL_MAP = json.loads("{\"client_challenge_nonce\": \"0319b28dc7f33aedfd3365255a5a3013\", \"consumed_challenges\": [], \"mappings\": {\"NODE-01-3D3AE8AF\": {\"hostname\": \"srv-test-<script>alert(1)</script>.cliente.local\", \"ip\": \"192.0.2.55\", \"real_subnet\": \"192.0.2.0/24\", \"subnet_alias\": \"SUBNET-456940\"}}, \"schema_version\": \"tepuy.local_map.v2\", \"warning\": \"SENSITIVE_NEVER_EXPORT_OUTSIDE_PERIMETER\"}")
_STATIC_TEST_SIGNED_REPORT = json.loads("{\"report_body\": {\"audit_timestamp_utc\": \"2026-11-24T00:00:00Z\", \"client_challenge_nonce\": \"0319b28dc7f33aedfd3365255a5a3013\", \"commercial_upsell_gate\": \"Deber de cuidado: este informe incluye el 100 % de los hallazgos detectados en el alcance pasivo Tier 1, sin ocultar vulnerabilidades. Los dominios no observables sin inspecci\\u00f3n profunda se marcan expl\\u00edcitamente como N/A (nunca como 100/100). La forensia de memoria RAM viva (Volatility 3), Active Directory (BloodHound), OT/ICS pasivo, cat\\u00e1logo completo de 1.786 CVEs CISA KEV, reglas YARA/SOAR y firma poscu\\u00e1ntica ML-DSA-65 (NIST FIPS 204) corresponden al PoV t\\u00e1ctico de 72 h (USD 2 500, 100 % acreditable a la Auditor\\u00eda Express de USD 6 500 dentro de 45 d\\u00edas).\", \"coverage\": {\"control_observations\": 2, \"control_slots\": 7, \"evaluated_domains\": 3, \"evaluated_weight_ratio\": 0.55, \"listener_snapshots\": 1, \"nodes\": 1, \"observed_packages\": 1, \"os_builds\": [], \"total_domains\": 6, \"vendor_checked_packages\": 0}, \"dom03_scope_note\": \"Tier 1 pasivo: los dominios no medibles sin agente/M.2 se reportan como N/A (nunca 100).\", \"domain_breakdown\": [{\"evaluated\": false, \"id\": \"DOM-01\", \"name\": \"Seguridad de Endpoint (EDR / Defender)\", \"score\": null, \"weight\": 0.2, \"weighted_contribution\": null}, {\"evaluated\": true, \"id\": \"DOM-02\", \"name\": \"Exposici\\u00f3n de Red y Protocolos\", \"score\": 25.0, \"weight\": 0.1, \"weighted_contribution\": 2.5}, {\"evaluated\": false, \"id\": \"DOM-03\", \"name\": \"An\\u00e1lisis Malware / IOC y Aislamiento\", \"score\": null, \"weight\": 0.1, \"weighted_contribution\": null}, {\"evaluated\": false, \"id\": \"DOM-04\", \"name\": \"Endurecimiento y Cifrado de Disco\", \"score\": null, \"weight\": 0.15, \"weighted_contribution\": null}, {\"evaluated\": true, \"id\": \"DOM-05\", \"name\": \"Identidad y Acceso Remoto\", \"score\": 45.0, \"weight\": 0.25, \"weighted_contribution\": 11.25}, {\"evaluated\": true, \"id\": \"DOM-06\", \"name\": \"Postura de Parches y CVEs (KEV)\", \"score\": 55.0, \"weight\": 0.2, \"weighted_contribution\": 11.0}], \"engine\": \"TEPUY_SPS_v2.0_OS_AWARE_DETERMINISTIC\", \"manifest_sha256\": \"688a3b300704918fc5a4f2a354086d3ceef101c9051e1d6697df2cea0a1bcca3\", \"nonce\": \"1c3a62cc38869f15\", \"remediation_sla_days\": 0, \"risk_color_hex\": \"#FF9F1C\", \"risk_tier\": \"PARTIAL_COVERAGE\", \"schema_version\": \"tepuy.report.raw.v2\", \"signer_key_id\": \"659d09dfc22c7804\", \"sps_global_score\": 45.0, \"telemetry_mode\": \"SYNTHETIC_DEMO_FIXTURE_NOT_LIVE_SCAN\", \"tier1_included_findings\": [{\"domain_id\": \"DOM-05\", \"node_id\": \"NODE-01-3D3AE8AF\", \"observation\": \"Escucha TCP local: 22\", \"penalty\": 55, \"remediation_preview\": \"Establecer PermitRootLogin no y PasswordAuthentication no en sshd_config, usando llaves Ed25519.\", \"rule_id\": \"TEPUY-IAM-SSH-ROOT\", \"severity\": \"CRITICAL\", \"title\": \"Acceso administrativo SSH sin endurecimiento (PermitRootLogin o PasswordAuthentication activos)\"}, {\"domain_id\": \"DOM-02\", \"node_id\": \"NODE-01-3D3AE8AF\", \"observation\": \"Escucha TCP local: 2375\", \"penalty\": 50, \"remediation_preview\": \"Confirmar el proceso propietario del puerto 2375, cerrar exposici\\u00f3n sin TLS y exigir certificados mutuos.\", \"rule_id\": \"TEPUY-NET-DOCKER-2375\", \"severity\": \"CRITICAL\", \"title\": \"Escucha TCP/2375 observada (API Docker sin TLS o servicio no verificado)\"}, {\"domain_id\": \"DOM-06\", \"node_id\": \"NODE-01-3D3AE8AF\", \"observation\": \"Paquete openssh-server \\u00b7 versi\\u00f3n observada 1:9.2p1-2+deb12u2 \\u00b7 perfil unknown\", \"penalty\": 45, \"remediation_preview\": \"Actualizar openssh-server >= 9.8p1 o aplicar contenci\\u00f3n perimetral Tepuy Core\\u2122.\", \"rule_id\": \"KEV-CVE-2024-6387\", \"severity\": \"CRITICAL\", \"title\": \"RegreSSHion RCE no autenticado en OpenSSH (CVE-2024-6387)\"}, {\"domain_id\": \"DOM-02\", \"node_id\": \"NODE-01-3D3AE8AF\", \"observation\": \"Se\\u00f1al pasiva firewall_active = false en manifiesto.\", \"penalty\": 25, \"remediation_preview\": \"Aplicar pol\\u00edtica default-deny de entrada en nftables/iptables.\", \"rule_id\": \"TEPUY-NET-FW-OFF\", \"severity\": \"HIGH\", \"title\": \"Filtro local de paquetes (nftables / iptables) inactivo\"}], \"tier2_locked_findings_count\": 0, \"total_findings_detected\": 4}, \"signature_ed25519_hex\": \"5aeccf011fdd86aa7a4c283d8632afcf3e58add3407a06a14212ed83f675fe2e56aacf34990657775e202f121c0435314050aef4076faea0d6f53079956f020d\"}")


class TestTepuyClientBridge(unittest.TestCase):
    def test_01_rfc8032_official_vectors_verify(self) -> None:
        """Verifies pure-Python Ed25519 verifier against Official IETF RFC 8032 Vectors 1, 2, and 3."""
        vectors = [
            (
                "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
                "",
                "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
                "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
            ),
            (
                "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
                "72",
                "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
                "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
            ),
            (
                "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
                "af82",
                "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac"
                "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
            ),
        ]
        for pk_h, msg_h, sig_h in vectors:
            pk = bytes.fromhex(pk_h)
            msg = bytes.fromhex(msg_h)
            sig = bytes.fromhex(sig_h)
            self.assertTrue(ed25519_verify(msg, sig, pk))
            self.assertFalse(ed25519_verify(msg + b"\x00", sig, pk))

    def test_02_strict_allowlist_strips_proprietary_leaks(self) -> None:
        raw_fixture = {
            "nodes": [
                {
                    "hostname": "prd-core-banking-db01.cliente-demo.internal",
                    "ip": "198.51.100.99",
                    "subnet": "198.51.100.0/24",
                    "os_family": "linux",
                    "packages": {
                        "openssh-server": "1:9.2p1-2+deb12u2",
                        "cliente-demo-core-tx-engine": "4.12.0-proprietary",
                    },
                    "open_ports": [22, 5432, 31337],
                    "tls_cert_cn": "swift-gw.cliente-demo.internal",
                    "controls": {"firewall_active": False},
                }
            ]
        }
        manifest, local_map = sanitize_and_pseudonymize(raw_fixture, secrets.token_bytes(32))
        m_str = json.dumps(manifest)
        self.assertNotIn("cliente-demo", m_str)
        self.assertNotIn("198.51.100.99", m_str)
        self.assertNotIn("swift", m_str)
        self.assertNotIn("31337", m_str)
        self.assertIn("openssh-server", m_str)
        self.assertIn("198.51.100.99", json.dumps(local_map))

    def test_03_signed_report_verify_xss_escape_and_tamper_rejection(self) -> None:
        pk = bytes.fromhex(_STATIC_TEST_PUBKEY_HEX)
        manifest = json.loads(json.dumps(_STATIC_TEST_MANIFEST))
        local_map = json.loads(json.dumps(_STATIC_TEST_LOCAL_MAP))
        signed = json.loads(json.dumps(_STATIC_TEST_SIGNED_REPORT))

        res = verify_and_rehydrate_locally(signed, local_map, pk, expected_manifest=manifest)
        self.assertTrue(res["verified_ed25519"])
        self.assertTrue(res["manifest_sha256_verified"])
        self.assertNotIn("<script>", json.dumps(res))
        html_out = render_rehydrated_html_report(res)
        self.assertNotIn("<script>alert(1)", html_out)
        self.assertNotIn("https://", html_out)
        self.assertNotIn("http://", html_out)

        with self.assertRaises(SecurityError):
            verify_and_rehydrate_locally(signed, local_map, pk, expected_manifest=manifest)

        tampered = json.loads(json.dumps(_STATIC_TEST_SIGNED_REPORT))
        tampered["report_body"]["sps_global_score"] = 99.0
        fresh_map = json.loads(json.dumps(_STATIC_TEST_LOCAL_MAP))
        with self.assertRaises(SecurityError):
            verify_and_rehydrate_locally(tampered, fresh_map, pk, expected_manifest=manifest)

    def test_04_durable_sqlite_replay_protection(self) -> None:
        pk = bytes.fromhex(_STATIC_TEST_PUBKEY_HEX)
        manifest = json.loads(json.dumps(_STATIC_TEST_MANIFEST))
        local_map = json.loads(json.dumps(_STATIC_TEST_LOCAL_MAP))
        signed = json.loads(json.dumps(_STATIC_TEST_SIGNED_REPORT))
        with tempfile.TemporaryDirectory() as directory:
            db_path = Path(directory) / "verified.sqlite3"
            verify_once(signed, local_map, pk, manifest, db_path)
            with self.assertRaises(SecurityError):
                verify_once(signed, local_map, pk, manifest, db_path)

    def test_05_runtime_socket_and_audithook_killswitch(self) -> None:
        import _socket
        status = enforce_airgap_runtime()
        self.assertEqual(status["audit_hook"], "ACTIVE_IRREVERSIBLE_CPYTHON_HOOK")
        with self.assertRaises(NetworkIsolationError):
            socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        with self.assertRaises(NetworkIsolationError):
            _socket.socket(_socket.AF_INET, socket.SOCK_STREAM)

    def test_06_passive_local_collector_under_airgap_hook(self) -> None:
        isolation = enforce_airgap_runtime()
        inv = collect_local_host_inventory(isolation)
        manifest, local_map = sanitize_and_pseudonymize(inv, secrets.token_bytes(32))
        validate_manifest(manifest)
        self.assertEqual(len(local_map["mappings"]), len(manifest["nodes"]))

    def test_07_read_pem_and_hex_public_keys(self) -> None:
        raw_pk = bytes.fromhex(_STATIC_TEST_PUBKEY_HEX)
        b64 = base64.b64encode(_ED25519_SPKI_PREFIX + raw_pk).decode("ascii")
        pem = f"-----BEGIN PUBLIC KEY-----\n{b64}\n-----END PUBLIC KEY-----\n"
        with tempfile.TemporaryDirectory() as directory:
            hex_p = Path(directory) / "pub.hex"
            pem_p = Path(directory) / "pub.pem"
            hex_p.write_text(raw_pk.hex() + "\n", encoding="ascii")
            pem_p.write_text(pem, encoding="ascii")
            self.assertEqual(read_hex_key(hex_p), raw_pk)
            self.assertEqual(read_hex_key(pem_p), raw_pk)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Wanadi Tactical - Tepuy Core Air-Gap Bridge (Tier 1 Client Collector & Verifier)"
    )
    parser.add_argument(
        "command",
        nargs="?",
        default="test",
        choices=("test", "collect", "rehydrate", "recover"),
        help="Run passive host collection, verify/rehydrate a Wanadi-signed report, or run self-tests",
    )
    parser.add_argument("--out-dir", default="./export", help="Export directory for sanitized manifest")
    parser.add_argument("--signed-report", help="Path to Wanadi-signed tepuy_report_raw_signed.json (for rehydrate)")
    parser.add_argument("--local-map", help="Path to private local_map.json (for rehydrate)")
    parser.add_argument("--manifest", help="Path to original tepuy_topology_manifest.json (for rehydrate)")
    parser.add_argument("--pub-key-file", type=Path, help="Provisioned Wanadi Tactical Ed25519 public key (.pub)")
    parser.add_argument("--private-dir", type=Path, default=private_state_dir())
    parser.add_argument("--challenge", help="Recover a previously verified report by challenge nonce")
    parser.add_argument("--state-db", type=Path, default=private_state_dir() / "verified.sqlite3")
    args = parser.parse_args()

    if args.command in ("rehydrate", "recover"):
        if args.command == "rehydrate":
            if not (args.signed_report and args.local_map and args.pub_key_file and args.manifest):
                parser.error("rehydrate requires --signed-report, --local-map, --manifest and --pub-key-file")
            signed = json.loads(Path(args.signed_report).read_text(encoding="utf-8"))
            local_map = json.loads(Path(args.local_map).read_text(encoding="utf-8"))
            manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
            final_report, rendered = verify_once(
                signed, local_map, read_hex_key(args.pub_key_file), manifest, args.state_db
            )
        else:
            if not args.challenge or not args.state_db.is_file():
                parser.error("recover requires an existing --state-db and --challenge")
            with closing(sqlite3.connect(args.state_db)) as db:
                row = db.execute("SELECT report_json FROM consumed WHERE nonce = ?", (args.challenge,)).fetchone()
            if row is None:
                parser.error("Challenge has no verified report")
            final_report = json.loads(row[0])
            rendered = render_rehydrated_html_report(final_report)
        challenge = final_report.get("client_challenge_nonce") or (
            manifest["client_challenge_nonce"] if args.command == "rehydrate" else args.challenge
        )
        if not re.fullmatch(r"[0-9a-f]{32,64}", challenge):
            parser.error("Invalid report challenge")
        out_path = args.private_dir / "reports" / challenge
        _write_json_secure(out_path / "tepuy_final_rehydrated_report.json", final_report, restricted=True)
        _write_text_secure(out_path / "tepuy_final_rehydrated_report.html", rendered, restricted=True)
        print(json.dumps({"verified_ed25519": True, "output_path": str(out_path.resolve())}))
        return 0

    if args.command == "collect":
        export_dir, private_dir = Path(args.out_dir).resolve(), args.private_dir.resolve()
        if export_dir == private_dir or export_dir in private_dir.parents or private_dir in export_dir.parents:
            parser.error("Export and private directories must be disjoint")
        if export_dir.is_dir() and any(item.name != "tepuy_topology_manifest.json" for item in export_dir.iterdir()):
            parser.error("Choose an export directory containing only the manifest")
        snapshot = linux_listener_snapshot() if platform.system() == "Linux" else None
        isolation = enforce_airgap_runtime()
        inv = collect_local_host_inventory(isolation, snapshot)
        manifest, local_map = sanitize_and_pseudonymize(inv, secrets.token_bytes(32))
        map_path = private_dir / manifest["client_challenge_nonce"] / "local_map.json"
        _write_json_secure(map_path, local_map, restricted=True)
        _write_json_secure(export_dir / "tepuy_topology_manifest.json", manifest)
        print(json.dumps({
            "isolation": isolation,
            "telemetry_mode": manifest["telemetry_mode"],
            "export": str(export_dir / "tepuy_topology_manifest.json"),
            "private_map": str(map_path),
        }, indent=2))
        return 0

    print("[*] Running Tepuy Core Air-Gap Bridge Client Verification Suite (Stdlib Unittest)...")
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(TestTepuyClientBridge)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
