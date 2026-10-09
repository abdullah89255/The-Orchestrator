#!/usr/bin/env python3
"""
Recon Orchestrator — chains safe phases, stops before exploitation.
Only run against authorized targets with a signed RoE.

Pipeline:
  Phase 1: Passive recon    (crt.sh, DNS, subfinder/amass if installed)
  Phase 2: [CONFIRM] Active scan (nmap, nuclei if installed)
  Phase 3: Normalize -> unified asset inventory
  Phase 4: Flag candidates (no exploitation)
  Phase 5: Report skeleton (Markdown + JSON)
"""

import argparse
import json
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from urllib.request import urlopen, Request
from urllib.error import URLError


# ---------- Data model ----------

@dataclass
class Asset:
    host: str
    ip: str | None = None
    ports: list = field(default_factory=list)      # [{port, service, version}]
    tech: list = field(default_factory=list)       # detected technologies
    endpoints: list = field(default_factory=list)  # discovered URLs
    flags: list = field(default_factory=list)      # human-review candidates
    source: list = field(default_factory=list)     # which phase found it


@dataclass
class Engagement:
    target: str
    started: str
    authorized_by: str
    assets: dict = field(default_factory=dict)     # host -> Asset

    def get(self, host: str) -> Asset:
        if host not in self.assets:
            self.assets[host] = Asset(host=host)
        return self.assets[host]


# ---------- Phase 1: Passive recon ----------

def crt_sh_subdomains(domain: str) -> set[str]:
    """Certificate Transparency lookup — fully passive."""
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        req = Request(url, headers={"User-Agent": "recon-orchestrator/1.0"})
        with urlopen(req, timeout=20) as r:
            data = json.loads(r.read().decode())
        names = set()
        for entry in data:
            for name in entry.get("name_value", "").split("\n"):
                name = name.strip().lstrip("*.")
                if name and domain in name:
                    names.add(name)
        return names
    except (URLError, json.JSONDecodeError, TimeoutError) as e:
        print(f"  [!] crt.sh failed: {e}")
        return set()


def run_subfinder(domain: str) -> set[str]:
    if not shutil.which("subfinder"):
        return set()
    try:
        out = subprocess.run(
            ["subfinder", "-d", domain, "-silent"],
            capture_output=True, text=True, timeout=300,
        )
        return {l.strip() for l in out.stdout.splitlines() if l.strip()}
    except subprocess.TimeoutExpired:
        print("  [!] subfinder timed out")
        return set()


def phase1_passive(eng: Engagement, domain: str):
    print("\n[Phase 1] Passive reconnaissance")
    subs = set()
    for name, fn in [("crt.sh", crt_sh_subdomains), ("subfinder", run_subfinder)]:
        print(f"  → {name}")
        found = fn(domain)
        print(f"    {len(found)} subdomains")
        subs |= found

    for s in sorted(subs):
        a = eng.get(s)
        a.source.append("passive")
    print(f"  [+] {len(subs)} unique hosts discovered")
    return subs


# ---------- Phase 2: Active scan (gated) ----------

def confirm(prompt: str) -> bool:
    print(f"\n⚠️  {prompt}")
    return input("    Type 'I HAVE WRITTEN AUTHORIZATION' to continue: ").strip() \
        == "I HAVE WRITTEN AUTHORIZATION"


def run_nmap(hosts: list[str], top_ports: int = 1000) -> dict:
    """Returns {host: [{port, service, version}]}"""
    if not shutil.which("nmap"):
        print("  [!] nmap not found — skipping active scan")
        return {}

    targets_file = Path("/tmp/recon_targets.txt")
    targets_file.write_text("\n".join(hosts))
    cmd = [
        "nmap", "-sT", "-sV", "--top-ports", str(top_ports),
        "--open", "-oX", "-", "-iL", str(targets_file),
    ]
    print(f"  → nmap {' '.join(cmd[:5])} ... (this can take a while)")
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
    except subprocess.TimeoutExpired:
        print("  [!] nmap timed out")
        return {}

    import xml.etree.ElementTree as ET
    results = {}
    try:
        root = ET.fromstring(out.stdout)
    except ET.ParseError:
        return {}

    for host_el in root.findall("host"):
        addr = host_el.find("address")
        if addr is None:
            continue
        host_ip = addr.get("addr")
        ports = []
        for port_el in host_el.findall("./ports/port"):
            state = port_el.find("state")
            if state is None or state.get("state") != "open":
                continue
            svc = port_el.find("service")
            ports.append({
                "port": int(port_el.get("portid")),
                "service": svc.get("name") if svc is not None else "unknown",
                "version": (svc.get("product", "") + " " + svc.get("version", "")).strip()
                           if svc is not None else "",
            })
        results[host_ip] = ports
    return results


def run_nuclei(targets: list[str], severity: str = "medium,high,critical") -> list[dict]:
    """Non-destructive template scan. Returns findings."""
    if not shutil.which("nuclei"):
        print("  [!] nuclei not found — skipping template scan")
        return []

    targets_file = Path("/tmp/recon_urls.txt")
    urls = [t if t.startswith("http") else f"https://{t}" for t in targets]
    targets_file.write_text("\n".join(urls))
    cmd = [
        "nuclei", "-l", str(targets_file),
        "-severity", severity,
        "-jsonl", "-silent",
        "-no-interactsh",  # keep it fully self-contained, no OOB callbacks
    ]
    print(f"  → nuclei (severity: {severity})")
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
    except subprocess.TimeoutExpired:
        print("  [!] nuclei timed out")
        return []

    findings = []
    for line in out.stdout.splitlines():
        try:
            findings.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return findings


def phase2_active(eng: Engagement, hosts: list[str]):
    print("\n[Phase 2] Active scanning")
    if not confirm(f"About to actively scan {len(hosts)} hosts. "
                   "Confirm you have authorization."):
        print("  [✗] Not confirmed — stopping before active phase.")
        return

    # Resolve IPs
    import socket
    for h in hosts:
        try:
            eng.get(h).ip = socket.gethostbyname(h)
        except socket.gaierror:
            pass

    scan = run_nmap(hosts)
    # nmap keys by IP; map back to hostnames
    ip_to_host = {a.ip: h for h, a in eng.assets.items() if a.ip}
    for ip, ports in scan.items():
        host = ip_to_host.get(ip, ip)
        eng.get(host).ports = ports
        eng.get(host).source.append("nmap")
        print(f"  [+] {host} ({ip}): {len(ports)} open ports")

    print("\n  → nuclei template scan")
    findings = run_nuclei(hosts)
    for f in findings:
        matched = f.get("matched-at") or f.get("host", "")
        for h in eng.assets:
            if h in matched:
                eng.get(h).flags.append({
                    "type": "template",
                    "template": f.get("template-id"),
                    "severity": f.get("info", {}).get("severity"),
                    "matched": matched,
                    "needs_review": True,
                })
                break
    print(f"  [+] {len(findings)} template findings (all flagged for review)")


# ---------- Phase 3: Normalize & enrich ----------

INTERESTING = {
    "http": ["admin", "api", "dev", "staging", "test", "internal", "jenkins",
             "grafana", "gitlab", "jira", "vpn", "portal", "backup"],
}

def phase3_normalize(eng: Engagement):
    print("\n[Phase 3] Normalization & candidate flagging")
    for host, asset in eng.assets.items():
        lh = host.lower()
        # Hostname heuristics
        for kw in INTERESTING["http"]:
            if kw in lh:
                asset.flags.append({
                    "type": "interesting_name",
                    "reason": f"hostname contains '{kw}'",
                    "needs_review": True,
                })
                break
        # Port heuristics
        sensitive = {21, 23, 445, 3306, 3389, 5432, 5900, 6379, 9200, 27017}
        for p in asset.ports:
            if p["port"] in sensitive:
                asset.flags.append({
                    "type": "sensitive_service",
                    "reason": f"port {p['port']} ({p['service']}) exposed",
                    "needs_review": True,
                })
    n_flags = sum(len(a.flags) for a in eng.assets.values())
    print(f"  [+] {n_flags} candidates flagged for manual review")


# ---------- Phase 4: STOP ----------

def phase4_stop(eng: Engagement):
    print("\n[Phase 4] ═══ HARD STOP ═══")
    print("  Exploitation is intentionally NOT automated.")
    print("  Reasons:")
    print("    • Destructive risk to production systems")
    print("    • Most bug bounty programs ban automated exploitation")
    print("    • Context (auth, business logic, state) can't be guessed")
    print("    • A human must validate each candidate below before proceeding")
    print("\n  → Review the flagged candidates in the report, then test manually.")


# ---------- Phase 5: Report ----------

def phase5_report(eng: Engagement, out_dir: Path):
    print("\n[Phase 5] Report generation")
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")

    json_path = out_dir / f"recon-{eng.target}-{stamp}.json"
    json_path.write_text(json.dumps(asdict(eng), indent=2))
    print(f"  [+] {json_path}")

    md = [f"# Recon Report — {eng.target}", ""]
    md.append(f"- **Started:** {eng.started}")
    md.append(f"- **Authorized by:** {eng.authorized_by}")
    md.append(f"- **Hosts discovered:** {len(eng.assets)}")
    md.append("")

    md.append("## Candidates for Manual Review")
    md.append("")
    md.append("> These are *hypotheses*, not findings. Validate manually.")
    md.append("")
    for host, a in sorted(eng.assets.items()):
        if a.flags:
            md.append(f"### `{host}`")
            if a.ip:
                md.append(f"IP: `{a.ip}`")
            md.append("")
            md.append("| Type | Reason |")
            md.append("|---|---|")
            for f in a.flags:
                md.append(f"| {f['type']} | {f.get('reason') or f.get('template','')} |")
            md.append("")

    md.append("## Full Asset Inventory")
    md.append("")
    for host, a in sorted(eng.assets.items()):
        md.append(f"### `{host}`")
        if a.ip:
            md.append(f"- IP: `{a.ip}`")
        if a.source:
            md.append(f"- Discovered via: {', '.join(sorted(set(a.source)))}")
        if a.ports:
            md.append("- Open ports:")
            for p in a.ports:
                md.append(f"  - `{p['port']}` {p['service']} {p['version']}".rstrip())
        md.append("")

    md.append("---")
    md.append("*Generated by recon-orchestrator. Exploitation not performed.*")

    md_path = out_dir / f"recon-{eng.target}-{stamp}.md"
    md_path.write_text("\n".join(md))
    print(f"  [+] {md_path}")


# ---------- Main ----------

def main():
    ap = argparse.ArgumentParser(description="Recon orchestrator with hard stops.")
    ap.add_argument("target", help="Root domain, e.g. example.com")
    ap.add_argument("--authorized-by", required=True,
                    help="Name on the signed authorization / RoE")
    ap.add_argument("--out", default="./recon-out")
    ap.add_argument("--skip-active", action="store_true",
                    help="Passive only")
    args = ap.parse_args()

    eng = Engagement(
        target=args.target,
        started=datetime.now().isoformat(timespec="seconds"),
        authorized_by=args.authorized_by,
    )

    print(f"═══ Recon orchestrator — {args.target} ═══")
    print(f"Authorized by: {args.authorized_by}")

    hosts = phase1_passive(eng, args.target)
    if not hosts:
        hosts = {args.target}
        eng.get(args.target).source.append("passive")

    if not args.skip_active:
        phase2_active(eng, sorted(hosts))
    else:
        print("\n[Phase 2] Skipped (--skip-active)")

    phase3_normalize(eng)
    phase4_stop(eng)
    phase5_report(eng, Path(args.out))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted")
        sys.exit(130)
