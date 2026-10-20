# Solution Design Document — NetGuard Vulnerability, Cisco Hardening & PKI Orchestrator

## 1. Real Security Toolchain Integration
- **Wireshark `tshark` + Python `libpcap` Dissector (`pcap_analyzer.py`)**: Dissects real `.pcap` captures via `tshark -T fields` (or portable libpcap fallback) to flag TCP SYN floods, Shannon-entropy DNS tunneling, Rogue DHCP servers, and cleartext credentials.
- **Nmap XML (`-oX`) & Pandas Risk Engine (`vuln_remediator.py`)**: Invokes real Nmap scans (`run_live_nmap_xml`) and parses service/version/port trees into SME remediation queues exported as styled OpenPyXL workbooks + Matplotlib charts.
- **YAML-to-Cisco IOS / ASA Hardening (`cisco_hardening_gen.py`)**: Compiles segmentation YAML into Cisco Catalyst L2 controls (`ip dhcp snooping`, `ip arp inspection`, `dot1x`, `port-security`) and ASA firewall ACLs isolating IT/OT and BeyondTrust/Bomgar jump hosts.
- **Cryptography X.509 PEM Auditor (`pki_tls_auditor.py`)**: Uses `cryptography.x509` to validate actual DER/PEM certificate chains, RSA/ECDSA key sizes, SHA-1 deprecation, BasicConstraints, SAN extensions, and expiry windows.
