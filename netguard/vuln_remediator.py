"""Real Nmap XML Parser, Pandas Zone-Risk Scorer, Visual Risk Matrix, and Excel SME Tracker."""

from __future__ import annotations

import shutil
import subprocess
import xml.etree.ElementTree as ET
from collections import Counter
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, List, Tuple

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import openpyxl
from openpyxl.styles import Alignment, Font, PatternFill
import pandas as pd


ZONE_META: Dict[str, Tuple[str, str, float]] = {
    "10.50.": ("Offshore-OT-ROV", "OT Field Operations", 1.5),
    "10.10.1.": ("Corp-AD-Core", "AD Infrastructure Team", 1.4),
    "172.16.": ("DMZ-Remote-Access", "Network Security Team", 1.3),
    "10.20.": ("Corp-Workstations", "Windows Endpoint Ops", 1.0),
    "127.0.": ("Localhost-Lab", "SOC Engineering Lab", 1.0),
}

CVE_SIGNATURES: Dict[Tuple[int, str], Dict[str, object]] = {
    (445, "microsoft-ds"): {
        "cve": "CVE-2020-0796 / SMBv3-Hardening",
        "base_cvss": 9.3,
        "remediation": "Disable SMBv1 via GPO, restrict TCP/445 at Cisco ASA, deploy KB patches.",
    },
    (3389, "ms-wbt-server"): {
        "cve": "CVE-2019-0708 / RDP-Exposed",
        "base_cvss": 8.8,
        "remediation": "Mandate BeyondTrust/Bomgar jump gate MFA and block direct TCP/3389.",
    },
    (23, "telnet"): {
        "cve": "CWE-319 Cleartext-Telnet",
        "base_cvss": 8.1,
        "remediation": "Disable Telnet ('transport input ssh'), enforce SSHv2 + CyberArk.",
    },
    (21, "ftp"): {
        "cve": "CWE-319 Cleartext-FTP",
        "base_cvss": 7.4,
        "remediation": "Decommission vsftpd/FTP and migrate automated transfers to SFTP.",
    },
    (161, "snmp"): {
        "cve": "CVE-2002-0012 / SNMPv2c-Default",
        "base_cvss": 6.5,
        "remediation": "Upgrade switch polling to SNMPv3 AuthPriv (AES-128 + SHA-256) with ACL.",
    },
    (443, "https"): {
        "cve": "TLS-Hygiene-Check",
        "base_cvss": 3.7,
        "remediation": "Verify TLS 1.2/1.3 cipher suite and X.509 internal CA renewal schedule.",
    },
}


@dataclass
class VulnerabilityTask:
    ticket_id: str
    host_ip: str
    hostname: str
    zone: str
    port: int
    service: str
    product: str
    cve_or_cwe: str
    base_cvss: float
    adjusted_risk_score: float
    priority: str
    triage_status: str
    assigned_sme: str
    sla_window: str
    remediation_action: str


def run_live_nmap_xml(target: str, output_xml: Path) -> bool:
    """Invoke native Nmap or WSL Ubuntu Nmap with -sV -oX against an authorized target."""
    if shutil.which("nmap"):
        cmd = ["nmap", "-sV", "-Pn", "--top-ports", "20", "-oX", str(output_xml), target]
    elif shutil.which("wsl"):
        posix = "/" + str(output_xml.resolve()).replace(":\\", "/").replace("\\", "/")
        wsl_out = f"/mnt/{posix[1].lower()}{posix[2:]}"
        cmd = ["wsl", "-d", "Ubuntu-24.04", "--", "nmap", "-sV", "-Pn", "--top-ports", "20", "-oX", wsl_out, target]
    else:
        return False
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
    return proc.returncode == 0 and output_xml.exists()


def _classify_zone(ip: str) -> Tuple[str, str, float]:
    for prefix, meta in ZONE_META.items():
        if ip.startswith(prefix):
            return meta
    return ("Internal-General", "IT Operations", 1.0)


def _priority_and_sla(score: float) -> Tuple[str, str]:
    if score >= 9.0:
        return ("CRITICAL", "24 Hours")
    if score >= 7.0:
        return ("HIGH", "7 Days")
    if score >= 4.0:
        return ("MEDIUM", "14 Days")
    return ("LOW", "30 Days")


def parse_nmap_xml_and_triage(xml_path: str | Path) -> Dict[str, object]:
    """Parse real Nmap XML output (-oX) into SME remediation tasks scored by zone sensitivity."""
    tree = ET.parse(xml_path)
    root = tree.getroot()
    scanner_ver = root.attrib.get("version", "unknown")
    tasks: List[VulnerabilityTask] = []
    t_num = 100

    for host in root.findall("host"):
        addr_el = host.find("address[@addrtype='ipv4']")
        if addr_el is None:
            continue
        ip = addr_el.attrib["addr"]
        hn_el = host.find("hostnames/hostname")
        hostname = hn_el.attrib["name"] if hn_el is not None else ip
        zone, sme, mult = _classify_zone(ip)

        ports_el = host.find("ports")
        if ports_el is None:
            continue
        for port_el in ports_el.findall("port"):
            state_el = port_el.find("state")
            if state_el is None or state_el.attrib.get("state") != "open":
                continue
            port_num = int(port_el.attrib["portid"])
            svc_el = port_el.find("service")
            svc_name = svc_el.attrib.get("name", "unknown") if svc_el is not None else "unknown"
            product = " ".join(
                p for p in [
                    svc_el.attrib.get("product", "") if svc_el is not None else "",
                    svc_el.attrib.get("version", "") if svc_el is not None else "",
                ] if p
            ) or svc_name

            sig = CVE_SIGNATURES.get((port_num, svc_name), {
                "cve": f"SERVICE-AUDIT-{port_num}",
                "base_cvss": 3.1,
                "remediation": f"Review firewall allowlist necessity for {svc_name} on TCP/{port_num}.",
            })
            t_num += 1
            base_cvss = float(sig["base_cvss"])
            adj = round(min(10.0, base_cvss * mult), 1)
            prio, sla = _priority_and_sla(adj)
            triage_status = "TRUE POSITIVE - ACTION REQUIRED" if adj >= 4.0 else "INFORMATIONAL - VERIFY BASELINE"

            tasks.append(
                VulnerabilityTask(
                    ticket_id=f"VULN-{t_num}",
                    host_ip=ip,
                    hostname=hostname,
                    zone=zone,
                    port=port_num,
                    service=svc_name,
                    product=product,
                    cve_or_cwe=str(sig["cve"]),
                    base_cvss=base_cvss,
                    adjusted_risk_score=adj,
                    priority=prio,
                    triage_status=triage_status,
                    assigned_sme=sme,
                    sla_window=sla,
                    remediation_action=str(sig["remediation"]),
                )
            )

    tasks.sort(key=lambda t: t.adjusted_risk_score, reverse=True)
    counts = Counter(t.priority for t in tasks)
    return {
        "scan_source": Path(xml_path).name,
        "nmap_version": scanner_ver,
        "total_actionable_findings": len(tasks),
        "priority_counts": dict(counts),
        "tasks": [asdict(t) for t in tasks],
    }


def export_remediation_artifacts(triage_result: Dict[str, object], output_xlsx: Path, output_chart: Path | None = None) -> Path:
    """Export SME Excel remediation workbook + optional Matplotlib risk distribution chart."""
    output_xlsx.parent.mkdir(parents=True, exist_ok=True)
    df = pd.DataFrame(triage_result["tasks"])

    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "SME Remediation Queue"
    headers = [
        "Ticket ID", "Host IP", "Hostname", "Network Zone", "Port",
        "Service", "Product", "CVE / CWE", "Base CVSS", "Risk Score",
        "Priority", "Triage Status", "Assigned SME", "SLA", "Remediation Plan",
    ]
    ws.append(headers)
    hfill = PatternFill(start_color="0B2545", end_color="0B2545", fill_type="solid")
    hfont = Font(color="FFFFFF", bold=True)
    for col_i in range(1, len(headers) + 1):
        c = ws.cell(row=1, column=col_i)
        c.fill = hfill
        c.font = hfont
        c.alignment = Alignment(horizontal="center")

    sev_fills = {
        "CRITICAL": PatternFill(start_color="FDE2E1", end_color="FDE2E1", fill_type="solid"),
        "HIGH": PatternFill(start_color="FFF3CD", end_color="FFF3CD", fill_type="solid"),
        "MEDIUM": PatternFill(start_color="E7F1FF", end_color="E7F1FF", fill_type="solid"),
        "LOW": PatternFill(start_color="E9F7EF", end_color="E9F7EF", fill_type="solid"),
    }

    for task in triage_result["tasks"]:
        ws.append([
            task["ticket_id"], task["host_ip"], task["hostname"], task["zone"],
            task["port"], task["service"], task["product"], task["cve_or_cwe"],
            task["base_cvss"], task["adjusted_risk_score"], task["priority"],
            task["triage_status"], task["assigned_sme"], task["sla_window"],
            task["remediation_action"],
        ])
        fill = sev_fills.get(task["priority"])
        if fill:
            cell = ws.cell(row=ws.max_row, column=11)
            cell.fill = fill
            cell.font = Font(bold=True)

    for col in ws.columns:
        max_len = max(len(str(c.value or "")) for c in col)
        ws.column_dimensions[col[0].column_letter].width = min(max_len + 4, 48)

    ws_sum = wb.create_sheet("SME SLA Summary")
    ws_sum.append(["Metric", "Count"])
    ws_sum.append(["Scan Source", triage_result["scan_source"]])
    ws_sum.append(["Total Actionable Findings", triage_result["total_actionable_findings"]])
    if not df.empty:
        for sme, cnt in df.groupby("assigned_sme").size().items():
            ws_sum.append([f"Owner: {sme}", int(cnt)])
    wb.save(output_xlsx)

    if output_chart is not None and not df.empty:
        fig, ax = plt.subplots(figsize=(7.5, 4.0))
        by_zone = df.groupby(["zone", "priority"]).size().unstack(fill_value=0)
        by_zone.plot(kind="bar", stacked=True, ax=ax, color={"CRITICAL": "#DC2626", "HIGH": "#F59E0B", "MEDIUM": "#2563EB", "LOW": "#10B981"})
        ax.set_title("Actionable Vulnerabilities by Network Zone & Severity")
        ax.set_ylabel("Open Findings")
        plt.xticks(rotation=15)
        plt.tight_layout()
        plt.savefig(output_chart, dpi=150)
        plt.close(fig)

    return output_xlsx
