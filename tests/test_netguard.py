"""Unit & integration tests covering tshark/PCAP dissection, Nmap XML triage, Cisco CIS config, X.509 PEMs, and FastAPI."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from api.netguard_api import app
from datasets.generate_fixtures import build_all
from netguard.cisco_hardening_gen import generate_cisco_hardening_config
from netguard.pcap_analyzer import PcapAnomalyDetector
from netguard.pki_tls_auditor import audit_pki_directory
from netguard.vuln_remediator import export_remediation_artifacts, parse_nmap_xml_and_triage


ROOT = Path(__file__).resolve().parent.parent


class TestNetGuardPlatform(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        build_all()

    def test_pcap_analyzer_detects_all_attacks_both_backends(self) -> None:
        detector = PcapAnomalyDetector(authorized_dhcp_servers=["10.10.1.10"])
        res = detector.analyze(ROOT / "datasets" / "corp_ot_capture.pcap", prefer_tshark=True)
        self.assertEqual(res["total_packets_parsed"], 19)
        self.assertSetEqual(
            {a["rule_id"] for a in res["alerts"]},
            {"PCAP-SYN-001", "PCAP-DNS-002", "PCAP-DHCP-003", "PCAP-CRED-004"},
        )

    def test_nmap_xml_triage_and_excel_plus_png(self) -> None:
        res = parse_nmap_xml_and_triage(ROOT / "datasets" / "nmap_scan_sample.xml")
        self.assertEqual(res["total_actionable_findings"], 7)
        with tempfile.TemporaryDirectory() as td:
            xlsx = Path(td) / "tracker.xlsx"
            png = Path(td) / "risk.png"
            export_remediation_artifacts(res, xlsx, png)
            self.assertTrue(xlsx.exists() and xlsx.stat().st_size > 3000)
            self.assertTrue(png.exists() and png.stat().st_size > 5000)

    def test_cisco_yaml_hardening_and_cis_verification(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            res = generate_cisco_hardening_config(
                ROOT / "datasets" / "network_segmentation_policy.yml",
                Path(td) / "hardening.cfg",
            )
            self.assertEqual(res["missing_controls"], [])
            self.assertEqual(res["cis_controls_verified"], res["cis_controls_total"])

    def test_real_x509_pem_cryptography_audit(self) -> None:
        res = audit_pki_directory(ROOT / "datasets" / "pki_certs")
        self.assertEqual(res["total_certificates"], 4)
        self.assertEqual(res["compliant_count"], 2)
        self.assertEqual(res["non_compliant_count"], 2)
        by_file = {r["pem_file"]: r for r in res["results"]}
        self.assertIn("EXPIRING_SOON", ",".join(by_file["03_cyberark_pvwa_expiring.pem"]["findings"]))
        weak_str = ",".join(by_file["04_legacy_rov_weak_1024.pem"]["findings"])
        self.assertIn("UNTRUSTED_SELF_SIGNED_LEAF", weak_str)
        self.assertIn("WEAK_RSA_KEY (1024-bit)", weak_str)
        self.assertIn("MISSING_SAN_EXTENSION", weak_str)
        self.assertIn("EXPIRED", weak_str)

    def test_fastapi_endpoints(self) -> None:
        client = TestClient(app)
        resp = client.get("/health")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["status"], "healthy")


if __name__ == "__main__":
    unittest.main()
