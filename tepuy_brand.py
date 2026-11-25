# Copyright (c) 2026 Wanadi Tactical LLC. All rights reserved.
# SPDX-License-Identifier: LicenseRef-Wanadi-Source-Available-Eval-1.0
# Wanadi Tactical™ and Tepuy Core™ logos and marks are proprietary (see LICENSE.txt).
"""Shared offline visual identity for the Tier 1 portal and report."""
import base64
from functools import lru_cache
from pathlib import Path


@lru_cache(maxsize=2)
def _logo(filename: str) -> str:
    png = Path(__file__).with_name(filename).read_bytes()
    return "data:image/png;base64," + base64.b64encode(png).decode("ascii")


def identity_header() -> str:
    return (
        '<div class="brand-lockup">'
        f'<img class="wanadi-mark" src="{_logo("wanadi-tactical.png")}" alt="Wanadi Tactical" width="60" height="60">'
        '<span class="brand-divider" aria-hidden="true"></span>'
        '<span class="tepuy-mark">'
        f'<img src="{_logo("tepuy-core.png")}" alt="Tepuy Core" width="210" height="140">'
        '</span></div>'
    )


IDENTITY_CSS = """
:root { --wt-ink:#02070D; --wt-navy:#061421; --wt-blue:#0A2540;
  --wt-teal:#00D9A5; --wt-cyan:#00A6FF; --wt-violet:#BA8AF4;
  --wt-muted:#A9B7C2; --wt-white:#F4F7FB; --wt-line:#234057; }
body { font-family: Inter, system-ui, "Segoe UI", sans-serif; color:var(--wt-white); }
.brand-lockup { display:flex; gap:20px; align-items:center; max-width:100%; min-height:70px; }
.wanadi-mark { display:block; width:60px; height:60px; object-fit:contain; }
.brand-divider { align-self:stretch; width:1px; background:var(--wt-line); }
.tepuy-mark { display:grid; place-items:center; width:174px; max-width:64vw; height:66px;
  overflow:hidden; background:#000; }
.tepuy-mark img { display:block; width:230px; max-width:none; height:auto; margin:-45px -28px; }
.brand-kicker { display:block; color:var(--wt-teal); font-size:.75rem; font-weight:700;
  letter-spacing:.13em; text-transform:uppercase; margin:18px 0 10px; }
:focus-visible { outline:2px solid var(--wt-teal); outline-offset:4px; }
@media(max-width:520px) { .brand-lockup { gap:12px; } .wanadi-mark { width:50px; height:50px; } }
"""
