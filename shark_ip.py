#!/usr/bin/env python3
"""
shark_ip.py — Passive IP enrichment CLI for OSINT / cyber-reconnaissance.

Like a shark sensing a single drop of blood in the ocean, Shark_IP surfaces
every piece of legally obtainable information about one IP address among
billions — by querying several open sources in a strictly PASSIVE, read-only
fashion (no scanning, no probing of the target). Every module degrades
gracefully: a missing API key or a failing source is skipped with a notice,
never a crash.

Sources:
  - ip-api.com       : geolocation, ASN, ISP/org, hosting/proxy/mobile flags  (no key)
  - Tor exit list    : is the IP a known Tor exit node                         (no key)
  - AbuseIPDB        : abuse confidence score, reports, categories             (key)
  - VirusTotal v3    : passive DNS resolutions, community reputation votes     (key)
  - Censys v2        : open ports, services/software, TLS cert SANs            (key id+secret)
  - vpnapi.io        : VPN / proxy / Tor / relay detection                     (key)
  - IKWYD            : P2P / torrent activity history   (key, OPTIONAL, sensitive)

Usage:
  python shark_ip.py 8.8.8.8
  python shark_ip.py 1.1.1.1 --json
  python shark_ip.py 9.9.9.9 --timeout 15

Legal note: this tool only reads public, third-party data about an IP. It does
NOT touch the target host. An IP address — especially combined with activity
history — is personal data under EU law (CJEU, Breyer). Use only against
targets you are authorized to investigate. See the README for full terms.
"""

from __future__ import annotations

import argparse
import ipaddress
import json as _json
import os
import sys
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

import requests
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:  # dotenv is optional; env vars may be set another way
    pass

console = Console()

DEFAULT_TIMEOUT = 10
USER_AGENT = "ip_profiler/1.0 (passive OSINT reconnaissance)"
TOR_EXIT_LIST_URL = "https://check.torproject.org/torbulkexitlist"


# --------------------------------------------------------------------------- #
# Result container
# --------------------------------------------------------------------------- #
@dataclass
class ModuleResult:
    """Normalized output of one source module."""
    name: str
    ok: bool = False
    skipped: bool = False
    reason: str = ""                     # why it was skipped / failed
    data: dict[str, Any] = field(default_factory=dict)


def _session(timeout: int) -> requests.Session:
    s = requests.Session()
    s.headers.update({"User-Agent": USER_AGENT, "Accept": "application/json"})
    s.request = _with_timeout(s.request, timeout)  # type: ignore[method-assign]
    return s


def _with_timeout(func: Callable, timeout: int) -> Callable:
    def wrapper(method, url, **kwargs):
        kwargs.setdefault("timeout", timeout)
        return func(method, url, **kwargs)
    return wrapper


def _env(*keys: str) -> Optional[str]:
    """Return the first non-empty env var among keys, else None."""
    for k in keys:
        v = os.getenv(k)
        if v and v.strip():
            return v.strip()
    return None


# --------------------------------------------------------------------------- #
# Source modules — one function per source, each returns a ModuleResult
# --------------------------------------------------------------------------- #
def mod_ipapi(ip: str, s: requests.Session) -> ModuleResult:
    """Geolocation + ASN via ip-api.com (free, no key, HTTP only on free tier)."""
    r = ModuleResult("ip-api.com")
    fields = ("status,message,country,countryCode,region,regionName,city,zip,"
              "lat,lon,timezone,currency,isp,org,as,asname,mobile,proxy,hosting")
    url = f"http://ip-api.com/json/{ip}?fields={fields}"
    try:
        resp = s.get(url)
        resp.raise_for_status()
        payload = resp.json()
        if payload.get("status") != "success":
            r.reason = payload.get("message", "lookup failed")
            return r
        r.ok = True
        r.data = payload
    except requests.RequestException as e:
        r.reason = f"request error: {e.__class__.__name__}"
    except ValueError:
        r.reason = "invalid JSON in response"
    return r


def mod_tor(ip: str, s: requests.Session) -> ModuleResult:
    """Check the official Tor bulk exit list (no key)."""
    r = ModuleResult("Tor exit list")
    try:
        resp = s.get(TOR_EXIT_LIST_URL, headers={"Accept": "text/plain"})
        resp.raise_for_status()
        # The list is one IP per line; exact-match against lines.
        exits = {line.strip() for line in resp.text.splitlines() if line.strip()}
        r.ok = True
        r.data = {"is_tor_exit": ip in exits, "list_size": len(exits)}
    except requests.RequestException as e:
        r.reason = f"request error: {e.__class__.__name__}"
    return r


def mod_abuseipdb(ip: str, s: requests.Session) -> ModuleResult:
    """Cyber-reputation via AbuseIPDB (needs ABUSEIPDB_API_KEY)."""
    r = ModuleResult("AbuseIPDB")
    key = _env("ABUSEIPDB_API_KEY", "ABUSEIPDB_KEY")
    if not key:
        r.skipped = True
        r.reason = "ABUSEIPDB_API_KEY not set"
        return r
    url = "https://api.abuseipdb.com/api/v2/check"
    try:
        resp = s.get(
            url,
            headers={"Key": key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""},
        )
        resp.raise_for_status()
        d = resp.json().get("data", {})
        r.ok = True
        r.data = {
            "abuse_score": d.get("abuseConfidenceScore"),
            "total_reports": d.get("totalReports"),
            "last_reported": d.get("lastReportedAt"),
            "country": d.get("countryCode"),
            "isp": d.get("isp"),
            "usage_type": d.get("usageType"),
            "is_whitelisted": d.get("isWhitelisted"),
            "domain": d.get("domain"),
        }
    except requests.RequestException as e:
        r.reason = f"request error: {e.__class__.__name__}"
    except ValueError:
        r.reason = "invalid JSON in response"
    return r


def mod_virustotal(ip: str, s: requests.Session) -> ModuleResult:
    """Passive DNS + community votes via VirusTotal v3 (needs VT_API_KEY)."""
    r = ModuleResult("VirusTotal")
    key = _env("VT_API_KEY", "VIRUSTOTAL_API_KEY")
    if not key:
        r.skipped = True
        r.reason = "VT_API_KEY not set"
        return r
    base = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    try:
        resp = s.get(base, headers={"x-apikey": key})
        resp.raise_for_status()
        attr = resp.json().get("data", {}).get("attributes", {})
        stats = attr.get("last_analysis_stats", {}) or {}
        votes = attr.get("total_votes", {}) or {}

        # Passive DNS: most recent resolutions (separate endpoint, best-effort).
        resolutions: list[str] = []
        try:
            rr = s.get(base + "/resolutions",
                       headers={"x-apikey": key},
                       params={"limit": 20})
            if rr.ok:
                for item in rr.json().get("data", []):
                    host = item.get("attributes", {}).get("host_name")
                    if host:
                        resolutions.append(host)
        except requests.RequestException:
            pass  # resolutions are a bonus; don't fail the whole module

        r.ok = True
        r.data = {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "votes_harmless": votes.get("harmless", 0),
            "votes_malicious": votes.get("malicious", 0),
            "reputation": attr.get("reputation"),
            "as_owner": attr.get("as_owner"),
            "resolutions": resolutions,
        }
    except requests.RequestException as e:
        r.reason = f"request error: {e.__class__.__name__}"
    except ValueError:
        r.reason = "invalid JSON in response"
    return r


def mod_censys(ip: str, s: requests.Session) -> ModuleResult:
    """
    Infrastructure via the Censys Platform API (v3).

    Auth: a single Personal Access Token (starts with `censys_`), sent as a
    Bearer token. Read from CENSYS_API_TOKEN, with CENSYS_API_SECRET accepted as
    a fallback for older configs. An optional CENSYS_ORG_ID (paid orgs) is sent
    as X-Organization-ID.

    The old ID+secret Basic-auth API (search.censys.io/api/v2) is deprecated.
    """
    r = ModuleResult("Censys")
    token = _env("CENSYS_API_TOKEN", "CENSYS_PAT", "CENSYS_API_SECRET")
    org = _env("CENSYS_ORG_ID", "CENSYS_ORGANIZATION_ID")
    if not token:
        r.skipped = True
        r.reason = "CENSYS_API_TOKEN not set"
        return r

    url = f"https://api.platform.censys.io/v3/global/asset/host/{ip}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.censys.api.v3.host.v1+json",
    }
    params = {}
    if org:
        params["organization_id"] = org
    try:
        resp = s.get(url, headers=headers, params=params)
        if resp.status_code == 404:
            r.ok = True
            r.data = {"ports": [], "services": [], "sans": [], "note": "no host record"}
            return r
        if resp.status_code in (401, 403):
            r.reason = (f"auth/permission error (HTTP {resp.status_code}) — "
                        "check the token, or your Censys tier/API-Access role")
            return r
        resp.raise_for_status()

        # Platform schema nests the host under result (sometimes result.resource).
        result = resp.json().get("result", {}) or {}
        host = result.get("resource") if isinstance(result.get("resource"), dict) else result
        services = host.get("services", []) or []

        ports, svc_rows, sans = [], [], set()
        for svc in services:
            port = svc.get("port")
            proto = (svc.get("protocol") or svc.get("service_name")
                     or svc.get("extended_service_name")
                     or svc.get("transport_protocol"))
            if port:
                ports.append(port)
            software = ""
            for sw in svc.get("software", []) or []:
                product = sw.get("product", "") or sw.get("uniform_resource_identifier", "")
                version = sw.get("version", "")
                software = " ".join(x for x in (product, version) if x)
                if software:
                    break
            svc_rows.append({"port": port, "protocol": proto, "software": software})
            # Certificate names (SANs) — try the Platform locations, then legacy.
            cert = svc.get("cert") or svc.get("certificate") or {}
            if isinstance(cert, dict):
                for n in cert.get("names", []) or []:
                    sans.add(n)
            tls = svc.get("tls", {}) or {}
            leaf = (tls.get("certificates", {}) or {}).get("leaf_data", {}) if tls else {}
            for n in (leaf.get("names", []) or []):
                sans.add(n)

        as_info = host.get("autonomous_system", {}) or {}
        r.ok = True
        r.data = {
            "ports": sorted(set(ports)),
            "services": svc_rows,
            "sans": sorted(n for n in sans if n),
            "asn": as_info.get("asn"),
            "as_name": as_info.get("name"),
        }
    except requests.RequestException as e:
        r.reason = f"request error: {e.__class__.__name__}"
    except ValueError:
        r.reason = "invalid JSON in response"
    return r


def mod_vpnapi(ip: str, s: requests.Session) -> ModuleResult:
    """VPN/proxy/Tor detection via vpnapi.io (needs VPNAPI_KEY)."""
    r = ModuleResult("vpnapi.io")
    key = _env("VPNAPI_KEY", "VPNAPI_IO_KEY")
    if not key:
        r.skipped = True
        r.reason = "VPNAPI_KEY not set"
        return r
    url = f"https://vpnapi.io/api/{ip}"
    try:
        resp = s.get(url, params={"key": key})
        resp.raise_for_status()
        sec = resp.json().get("security", {}) or {}
        r.ok = True
        r.data = {
            "vpn": sec.get("vpn"),
            "proxy": sec.get("proxy"),
            "tor": sec.get("tor"),
            "relay": sec.get("relay"),
        }
    except requests.RequestException as e:
        r.reason = f"request error: {e.__class__.__name__}"
    except ValueError:
        r.reason = "invalid JSON in response"
    return r


def mod_torrent(ip: str, s: requests.Session) -> ModuleResult:
    """
    Optional P2P activity history via iknowwhatyoudownload (IKWYD).

    Needs IKWYD_API_KEY. Disabled by default: with no key, the module is
    skipped and never runs. Returns torrent contents historically observed in
    public P2P swarms for this IP.

    NOTE (read the README): an IP address combined with activity history is
    personal data under EU law (CJEU, Breyer, C-582/14), whether or not it is
    tied to a name. Enable this module only against targets you are authorized
    to investigate, and with a lawful basis.
    """
    r = ModuleResult("Torrent history (IKWYD)")
    key = _env("IKWYD_API_KEY", "IKNOWWHATYOUDOWNLOAD_API_KEY")
    if not key:
        r.skipped = True
        r.reason = "IKWYD_API_KEY not set (optional module, off by default)"
        return r
    # IKWYD exposes a history endpoint keyed by API key + target IP.
    url = "https://api.iknowwhatyoudownload.com/api/v1/history/peer"
    try:
        resp = s.get(url, params={"key": key, "ip": ip})
        resp.raise_for_status()
        payload = resp.json()
        contents = payload.get("contents", []) if isinstance(payload, dict) else []
        rows = []
        for c in contents[:25]:
            rows.append({
                "name": c.get("torrent", {}).get("name") or c.get("name"),
                "category": c.get("category") or c.get("torrent", {}).get("category"),
                "first_seen": c.get("startDate"),
                "last_seen": c.get("endDate"),
            })
        r.ok = True
        r.data = {"count": len(contents), "contents": rows}
    except requests.RequestException as e:
        r.reason = f"request error: {e.__class__.__name__}"
    except ValueError:
        r.reason = "invalid JSON in response"
    return r


MODULES: list[Callable[[str, requests.Session], ModuleResult]] = [
    mod_ipapi,
    mod_tor,
    mod_abuseipdb,
    mod_virustotal,
    mod_censys,
    mod_vpnapi,
    mod_torrent,
]


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #
def _kv_table(title: str, rows: list[tuple[str, Any]], style: str) -> Table:
    t = Table(box=box.SIMPLE_HEAD, title=title, title_style=f"bold {style}",
              show_header=False, expand=True, pad_edge=False)
    t.add_column("Field", style="dim", no_wrap=True, ratio=1)
    t.add_column("Value", ratio=3)
    for k, v in rows:
        if v is None or v == "" or v == []:
            v = "[dim]—[/dim]"
        t.add_row(k, str(v))
    return t


def _flag(value: Any) -> str:
    if value is True:
        return "[bold red]yes[/bold red]"
    if value is False:
        return "[green]no[/green]"
    return "[dim]unknown[/dim]"


def render(ip: str, results: dict[str, ModuleResult]) -> None:
    console.print()
    console.print(Panel.fit(f"[bold]Passive IP profile[/bold]   [cyan]{ip}[/cyan]",
                            border_style="cyan"))

    # ---- Geolocation -----------------------------------------------------
    g = results.get("ip-api.com")
    if g and g.ok:
        d = g.data
        loc = ", ".join(x for x in (d.get("city"), d.get("regionName"),
                                    d.get("country")) if x)
        rows = [
            ("Location", loc),
            ("Coordinates", f'{d.get("lat")}, {d.get("lon")}'),
            ("Postal / ZIP", d.get("zip")),
            ("Timezone", d.get("timezone")),
        ]
        console.print(_kv_table("Geolocation", rows, "green"))

    # ---- Infrastructure --------------------------------------------------
    infra_rows: list[tuple[str, Any]] = []
    if g and g.ok:
        d = g.data
        infra_rows += [
            ("ASN", d.get("as")),
            ("AS name", d.get("asname")),
            ("ISP", d.get("isp")),
            ("Organization", d.get("org")),
            ("Hosting / DC", _flag(d.get("hosting"))),
            ("Mobile network", _flag(d.get("mobile"))),
        ]
    cen = results.get("Censys")
    if cen and cen.ok:
        ports = cen.data.get("ports", [])
        infra_rows.append(("Open ports (Censys)",
                           ", ".join(map(str, ports)) if ports else "none seen"))
    if infra_rows:
        console.print(_kv_table("Infrastructure", infra_rows, "blue"))

    # Censys services detail as its own table
    if cen and cen.ok and cen.data.get("services"):
        st = Table(box=box.SIMPLE_HEAD, title="Services & software (Censys)",
                   title_style="bold blue", expand=True)
        st.add_column("Port", style="cyan", no_wrap=True)
        st.add_column("Protocol")
        st.add_column("Software / banner")
        for svc in cen.data["services"]:
            st.add_row(str(svc.get("port") or "—"),
                       str(svc.get("protocol") or "—"),
                       svc.get("software") or "[dim]—[/dim]")
        console.print(st)

    # ---- Linked domains (Censys SANs + VT passive DNS) -------------------
    linked: list[str] = []
    if cen and cen.ok:
        linked += [f"{n}  [dim](TLS cert)[/dim]" for n in cen.data.get("sans", [])]
    vt = results.get("VirusTotal")
    if vt and vt.ok:
        linked += [f"{h}  [dim](passive DNS)[/dim]" for h in vt.data.get("resolutions", [])]
    if linked:
        panel_body = "\n".join(f"• {x}" for x in linked[:40])
        console.print(Panel(panel_body, title="Linked domain names",
                            border_style="blue", title_align="left"))

    # ---- Reputation / activity ------------------------------------------
    rep_rows: list[tuple[str, Any]] = []
    ab = results.get("AbuseIPDB")
    if ab and ab.ok:
        score = ab.data.get("abuse_score")
        score_disp = f"{score}/100"
        if isinstance(score, int):
            if score >= 50:
                score_disp = f"[bold red]{score}/100[/bold red]"
            elif score >= 10:
                score_disp = f"[yellow]{score}/100[/yellow]"
            else:
                score_disp = f"[green]{score}/100[/green]"
        rep_rows += [
            ("Abuse confidence", score_disp),
            ("Total reports (90d)", ab.data.get("total_reports")),
            ("Last reported", ab.data.get("last_reported")),
            ("Usage type", ab.data.get("usage_type")),
        ]
    if vt and vt.ok:
        rep_rows += [
            ("VT malicious detections", vt.data.get("malicious")),
            ("VT community votes (mal/harm)",
             f'{vt.data.get("votes_malicious")} / {vt.data.get("votes_harmless")}'),
            ("VT reputation", vt.data.get("reputation")),
        ]
    tor_hist = results.get("Torrent history (IKWYD)")
    if tor_hist and tor_hist.ok:
        rep_rows.append(("P2P contents observed (IKWYD)", tor_hist.data.get("count")))
    if rep_rows:
        console.print(_kv_table("Reputation & activity", rep_rows, "yellow"))

    # ---- P2P activity history (optional, sensitive) ----------------------
    if tor_hist and tor_hist.ok and tor_hist.data.get("contents"):
        ht = Table(box=box.SIMPLE_HEAD,
                   title="P2P activity history (IKWYD) — sensitive, see README",
                   title_style="bold magenta", expand=True)
        ht.add_column("Content", overflow="fold")
        ht.add_column("Category", no_wrap=True)
        ht.add_column("First seen", no_wrap=True)
        ht.add_column("Last seen", no_wrap=True)
        for c in tor_hist.data["contents"]:
            ht.add_row(str(c.get("name") or "—"),
                       str(c.get("category") or "—"),
                       str(c.get("first_seen") or "—"),
                       str(c.get("last_seen") or "—"))
        console.print(ht)

    # ---- Risk / network type --------------------------------------------
    risk_rows: list[tuple[str, Any]] = []
    tor = results.get("Tor exit list")
    if tor and tor.ok:
        risk_rows.append(("Tor exit node", _flag(tor.data.get("is_tor_exit"))))
    vp = results.get("vpnapi.io")
    if vp and vp.ok:
        risk_rows += [
            ("VPN", _flag(vp.data.get("vpn"))),
            ("Proxy", _flag(vp.data.get("proxy"))),
            ("Tor (vpnapi)", _flag(vp.data.get("tor"))),
            ("Relay", _flag(vp.data.get("relay"))),
        ]
    if g and g.ok:
        risk_rows.append(("Anonymizer flag (ip-api proxy)", _flag(g.data.get("proxy"))))
    if risk_rows:
        console.print(_kv_table("Risk & network type", risk_rows, "red"))

    # ---- Skipped / failed notices ---------------------------------------
    notes = []
    for res in results.values():
        if res.skipped:
            notes.append(f"[dim]⃠ {res.name}: skipped — {res.reason}[/dim]")
        elif not res.ok:
            notes.append(f"[yellow]⚠ {res.name}: {res.reason or 'no data'}[/yellow]")
    if notes:
        console.print(Panel("\n".join(notes), title="Modules not run",
                            border_style="dim", title_align="left"))
    console.print()


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #
def validate_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


# Keys offered by the interactive setup, with a short human label each.
_SETUP_KEYS: list[tuple[str, str]] = [
    ("ABUSEIPDB_API_KEY", "AbuseIPDB — abuse score (free)"),
    ("VT_API_KEY", "VirusTotal — passive DNS & reputation (free)"),
    ("CENSYS_API_TOKEN", "Censys — Personal Access Token, starts with 'censys_' (free)"),
    ("CENSYS_ORG_ID", "Censys — Organization ID (optional, paid orgs only)"),
    ("VPNAPI_KEY", "vpnapi.io — VPN/proxy/Tor detection (free)"),
    ("IKWYD_API_KEY", "IKWYD — P2P history (optional, sensitive)"),
]


def _env_path() -> str:
    """The .env living next to this script."""
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")


def _read_env_file(path: str) -> dict[str, str]:
    values: dict[str, str] = {}
    if not os.path.exists(path):
        return values
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, _, v = line.partition("=")
                values[k.strip()] = v.strip()
    except OSError:
        pass
    return values


def run_setup() -> int:
    """Interactively collect API keys and write them to .env (local only)."""
    path = _env_path()
    existing = _read_env_file(path)

    console.print(Panel.fit(
        "[bold]Shark_IP — API key setup[/bold]\n"
        "Keys are saved locally to [cyan].env[/cyan] (git-ignored, never pushed).\n"
        "Press [bold]Enter[/bold] to keep the current value or skip a key you don't have.",
        border_style="cyan"))

    for key, label in _SETUP_KEYS:
        current = existing.get(key, "")
        if current:
            shown = current[:4] + "…" + current[-2:] if len(current) > 6 else "set"
            prompt = f"{label}\n  {key} [dim](current: {shown})[/dim]: "
        else:
            prompt = f"{label}\n  {key} [dim](empty)[/dim]: "
        console.print(prompt, end="")
        try:
            entered = input().strip()
        except (EOFError, KeyboardInterrupt):
            console.print("\n[dim]setup cancelled[/dim]")
            return 130
        if entered:
            existing[key] = entered

    # Write back every known key, preserving a tidy, commented layout.
    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("# Shark_IP API keys — local only, never commit this file.\n")
            for key, label in _SETUP_KEYS:
                fh.write(f"# {label}\n{key}={existing.get(key, '')}\n")
        os.chmod(path, 0o600)  # best-effort: readable only by you (POSIX)
    except OSError as e:
        console.print(f"[bold red]Could not write {path}: {e}[/bold red]")
        return 1

    filled = sum(1 for k, _ in _SETUP_KEYS if existing.get(k))
    console.print(f"\n[green]✓ Saved {filled} key(s) to[/green] [cyan]{path}[/cyan]")
    console.print("[dim]Run a scan, e.g.:  python shark_ip.py 8.8.8.8[/dim]")
    return 0


def run(ip: str, timeout: int) -> dict[str, ModuleResult]:
    s = _session(timeout)
    results: dict[str, ModuleResult] = {}
    for module in MODULES:
        try:
            res = module(ip, s)
        except Exception as e:  # last-resort guard: one module never kills the run
            res = ModuleResult(getattr(module, "__name__", "module"))
            res.reason = f"unexpected error: {e.__class__.__name__}"
        results[res.name] = res
    return results


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="shark_ip.py",
        description="Shark_IP — passive IP enrichment for OSINT / cyber-reconnaissance.",
        epilog="Examples:\n"
               "  python shark_ip.py 8.8.8.8\n"
               "  python shark_ip.py 1.1.1.1 --json\n"
               "  python shark_ip.py --setup        (enter/update your API keys)",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("ip", nargs="?", help="target IPv4 or IPv6 address")
    parser.add_argument("--setup", action="store_true",
                        help="interactively enter your API keys and save them to .env")
    parser.add_argument("--json", action="store_true",
                        help="emit raw JSON instead of the rich console view")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT,
                        help=f"per-request timeout in seconds (default {DEFAULT_TIMEOUT})")
    args = parser.parse_args()

    if args.setup:
        return run_setup()

    if not args.ip:
        parser.print_help()
        return 0

    if not validate_ip(args.ip):
        console.print(f"[bold red]Error:[/bold red] '{args.ip}' is not a valid IP address.")
        return 2

    results = run(args.ip, args.timeout)

    if args.json:
        out = {name: {"ok": r.ok, "skipped": r.skipped,
                      "reason": r.reason, "data": r.data}
               for name, r in results.items()}
        print(_json.dumps({"ip": args.ip, "sources": out}, indent=2, default=str))
    else:
        render(args.ip, results)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        console.print("\n[dim]interrupted[/dim]")
        sys.exit(130)
