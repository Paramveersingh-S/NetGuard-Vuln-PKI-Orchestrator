# NetGuard-Vuln-PKI-Orchestrator

Production-grade **Packet Inspection (`tshark`/libpcap), Nmap Vulnerability Triage, Cisco IOS/ASA & Bomgar Hardening, and Cryptography X.509 PKI Hygiene Platform**.

## Real Tech Stack

| Domain | Real Tool / Library | Capability |
| :--- | :--- | :--- |
| **Packet Dissection** | **Wireshark `tshark`** + `libpcap` (`netguard/pcap_analyzer.py`) | Detects **TCP SYN Floods**, **DNS Tunneling** (Shannon entropy), **Rogue DHCP (UDP 67->68)**, and **Cleartext Creds**. |
| **Vulnerability Triage** | **Nmap 7.94 `-oX`** + **Pandas** + **OpenPyXL** + **Matplotlib** | Parses real Nmap XML, applies zone multipliers (`Offshore-OT-ROV`, `Corp-AD`), exports Excel tracker + PNG chart. |
| **Network Hardening** | **PyYAML** + **Cisco IOS / ASA ACL** (`netguard/cisco_hardening_gen.py`) | Compiles VLAN segmentation, DHCP Snooping, DAI, 802.1X NAC, Port Security & **Bomgar** Jump ACLs + CIS audit. |
| **X.509 PKI Hygiene** | **`cryptography.x509`** + `ssl` (`netguard/pki_tls_auditor.py`) | Validates real RSA/ECDSA X.509 PEM certs for expiry (`<=30d`), SHA-1 deprecation, `<2048-bit` keys, SANs & self-signed leaves. |
| **REST Microservice** | **FastAPI** (`api/netguard_api.py`) | Exposes `/health` and `/api/v1/audit-summary` for automated pipeline ingestion. |

## Quick Start & Verification

```bash
pip install -r requirements.txt
python run_netguard_suite.py
python -m unittest discover -s tests -v
uvicorn api.netguard_api:app --reload
```

### Verified Run Output

```text
PCAP Audit [tshark-wsl]: 19 packets -> 4 alerts ({'HIGH': 2, 'CRITICAL': 2})
Vulnerability Triage [live_nmap=True]: 7 findings -> Vulnerability_Remediation_Tracker.xlsx ({'CRITICAL': 5, 'HIGH': 1, 'MEDIUM': 1})
Cisco Hardening: 63 lines generated, 8/8 CIS controls verified
X.509 PKI Audit (cryptography): 2/4 compliant PEMs
```

Ran `python -m unittest discover -s tests -v`: **5/5 tests OK**.
