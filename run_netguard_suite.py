"""End-to-end NetGuard Orchestrator: tshark/PCAP, Nmap XML, Cisco YAML->IOS/ASA, X.509 Cryptography Audit."""

from __future__ import annotations

import json
from pathlib import Path

from datasets.generate_fixtures import build_all
from netguard.cisco_hardening_gen import generate_cisco_hardening_config
from netguard.pcap_analyzer import PcapAnomalyDetector
from netguard.pki_tls_auditor import audit_pki_directory
from netguard.vuln_remediator import (
    export_remediation_artifacts,
    parse_nmap_xml_and_triage,
    run_live_nmap_xml,
)


ROOT = Path(__file__).resolve().parent


def main() -> None:
    reports_dir = ROOT / "reports"
    reports_dir.mkdir(exist_ok=True)
    build_all()

    # 1. Packet Analysis (tshark Wireshark CLI when present, else libpcap fallback)
    pcap_res = PcapAnomalyDetector(authorized_dhcp_servers=["10.10.1.10"]).analyze(
        ROOT / "datasets" / "corp_ot_capture.pcap"
    )

    # 2. Live Localhost Nmap verification + Enterprise OT/AD/DMZ Nmap XML Triage
    live_xml = reports_dir / "nmap_localhost_live.xml"
    live_nmap_ran = run_live_nmap_xml("127.0.0.1", live_xml)

    vuln_res = parse_nmap_xml_and_triage(ROOT / "datasets" / "nmap_scan_sample.xml")
    xlsx_path = export_remediation_artifacts(
        vuln_res,
        reports_dir / "Vulnerability_Remediation_Tracker.xlsx",
        reports_dir / "vuln_risk_matrix.png",
    )

    # 3. Cisco Switch + ASA Firewall + BeyondTrust/Bomgar Hardening Config
    cisco_res = generate_cisco_hardening_config(
        ROOT / "datasets" / "network_segmentation_policy.yml",
        reports_dir / "cisco_ot_hardening.cfg",
    )

    # 4. Real X.509 PEM PKI Cryptography Audit
    pki_res = audit_pki_directory(ROOT / "datasets" / "pki_certs")
    (reports_dir / "pki_audit_report.json").write_text(json.dumps(pki_res, indent=2), encoding="utf-8")

    summary = {
        "pcap_analysis": pcap_res,
        "live_localhost_nmap_executed": live_nmap_ran,
        "vulnerability_triage": vuln_res,
        "cisco_hardening": {
            "config_path": cisco_res["config_path"],
            "line_count": cisco_res["line_count"],
            "cis_controls_verified": f"{cisco_res['cis_controls_verified']}/{cisco_res['cis_controls_total']}",
        },
        "pki_audit": pki_res,
    }
    (reports_dir / "netguard_full_audit.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")

    print(
        f"PCAP Audit [{pcap_res['dissector_backend']}]: {pcap_res['total_packets_parsed']} packets -> "
        f"{pcap_res['alert_count']} alerts ({pcap_res['severity_breakdown']})"
    )
    print(
        f"Vulnerability Triage [live_nmap={live_nmap_ran}]: {vuln_res['total_actionable_findings']} findings -> "
        f"{xlsx_path.name} ({vuln_res['priority_counts']})"
    )
    print(
        f"Cisco Hardening: {cisco_res['line_count']} lines generated, "
        f"{cisco_res['cis_controls_verified']}/{cisco_res['cis_controls_total']} CIS controls verified"
    )
    print(
        f"X.509 PKI Audit (cryptography): {pki_res['compliant_count']}/{pki_res['total_certificates']} compliant PEMs"
    )


if __name__ == "__main__":
    main()
