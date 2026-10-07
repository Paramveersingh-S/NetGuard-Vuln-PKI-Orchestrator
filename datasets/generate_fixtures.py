"""Generate real X.509 PEM certs (via `cryptography`), libpcap captures, Nmap XML, and Cisco YAML policy."""

from __future__ import annotations

import datetime as dt
import socket
import struct
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import yaml


BASE = Path(__file__).resolve().parent


def _eth_ip_tcp(src_ip: str, dst_ip: str, sport: int, dport: int, flags: int, payload: bytes = b"") -> bytes:
    eth = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00"
    tcp_hdr = struct.pack("!HHIIHHHH", sport, dport, 1000, 0, (5 << 12) | flags, 64240, 0, 0) + payload
    total_len = 20 + len(tcp_hdr)
    ip_hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total_len, 1234, 0x4000, 64, 6, 0, socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
    return eth + ip_hdr + tcp_hdr


def _eth_ip_udp(src_ip: str, dst_ip: str, sport: int, dport: int, payload: bytes) -> bytes:
    eth = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00"
    udp_hdr = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    total_len = 20 + len(udp_hdr)
    ip_hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total_len, 2345, 0x4000, 64, 17, 0, socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
    return eth + ip_hdr + udp_hdr


def _dns_query_bytes(domain: str) -> bytes:
    hdr = struct.pack("!HHHHHH", 0xABCD, 0x0100, 1, 0, 0, 0)
    qname = b"".join(bytes([len(lbl)]) + lbl.encode("ascii") for lbl in domain.split(".")) + b"\x00"
    return hdr + qname + struct.pack("!HH", 1, 1)


def build_sample_pcap(path: Path) -> None:
    global_hdr = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    frames = [
        _eth_ip_tcp("10.20.5.14", "10.10.1.25", 51400, 443, 0x02),
        _eth_ip_tcp("10.10.1.25", "10.20.5.14", 443, 51400, 0x12),
        _eth_ip_tcp("10.20.5.14", "10.10.1.25", 51400, 443, 0x10),
        _eth_ip_udp("10.20.5.14", "10.10.1.10", 53001, 53, _dns_query_bytes("ad-dc01.corp.internal")),
        _eth_ip_udp("10.20.5.88", "8.8.8.8", 54112, 53, _dns_query_bytes("a9f8k3m2z7x1q4w8e5r6t9y2u3i4o5p6.exfil.badc2.net")),
        _eth_ip_udp("10.20.5.250", "255.255.255.255", 67, 68, b"\x02\x01\x06\x00" + b"\x00" * 240),
        _eth_ip_tcp("10.20.5.42", "10.50.10.20", 49811, 80, 0x18, b"GET /rov HTTP/1.1\r\nHost: ot\r\nAuthorization: Basic YWRtaW46U3Vic2VhMTIz\r\n\r\n"),
    ]
    for i in range(12):
        frames.append(_eth_ip_tcp("10.20.99.77", "10.50.10.15", 40000 + i, 502, 0x02))

    chunks = [global_hdr]
    for idx, frame in enumerate(frames):
        chunks.append(struct.pack("<IIII", 1792800000, idx * 1000, len(frame), len(frame)))
        chunks.append(frame)
    path.write_bytes(b"".join(chunks))


def build_real_x509_lab_certs(cert_dir: Path) -> None:
    """Create genuine cryptographically signed X.509 PEM certificates for PKI hygiene auditing."""
    cert_dir.mkdir(parents=True, exist_ok=True)
    ref = dt.datetime(2026, 10, 1, tzinfo=dt.timezone.utc)

    # 1. Corporate Root CA (RSA 4096, SHA-256)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Oceaneering-Lab-RootCA")])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(ref - dt.timedelta(days=30))
        .not_valid_after(ref + dt.timedelta(days=1825))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    (cert_dir / "01_corp_root_ca.pem").write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))

    # 2. Compliant Splunk Web Leaf Cert (RSA 2048, SHA-256, SAN present, 365d valid)
    k1 = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    c1 = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "splunk-soc.corp.internal")]))
        .issuer_name(ca_name)
        .public_key(k1.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(ref)
        .not_valid_after(ref + dt.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("splunk-soc.corp.internal")]), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    (cert_dir / "02_splunk_web_valid.pem").write_bytes(c1.public_bytes(serialization.Encoding.PEM))

    # 3. Expiring Soon CyberArk PVWA Cert (< 30 days from Oct 24 ref)
    k2 = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    c2 = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "cyberark-pvwa.corp.internal")]))
        .issuer_name(ca_name)
        .public_key(k2.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(ref - dt.timedelta(days=330))
        .not_valid_after(dt.datetime(2026, 11, 5, tzinfo=dt.timezone.utc))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("cyberark-pvwa.corp.internal")]), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    (cert_dir / "03_cyberark_pvwa_expiring.pem").write_bytes(c2.public_bytes(serialization.Encoding.PEM))

    # 4. Non-compliant Legacy ROV Telemetry Cert (Expired + Weak RSA 1024 + Self-Signed Leaf + No SAN)
    k3 = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    n3 = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "rov-legacy.ot.internal")])
    c3 = (
        x509.CertificateBuilder()
        .subject_name(n3)
        .issuer_name(n3)
        .public_key(k3.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(dt.datetime(2024, 1, 1, tzinfo=dt.timezone.utc))
        .not_valid_after(dt.datetime(2026, 9, 15, tzinfo=dt.timezone.utc))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(k3, hashes.SHA256())
    )
    (cert_dir / "04_legacy_rov_weak_1024.pem").write_bytes(c3.public_bytes(serialization.Encoding.PEM))


def build_all() -> None:
    build_sample_pcap(BASE / "corp_ot_capture.pcap")
    build_real_x509_lab_certs(BASE / "pki_certs")

    nmap_xml = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" version="7.94SVN" args="nmap -sV -Pn -oX nmap_scan_sample.xml 10.0.0.0/8">
  <host>
    <address addr="10.50.10.15" addrtype="ipv4"/>
    <hostnames><hostname name="rov-telemetry-plc01.ot.internal" type="PTR"/></hostnames>
    <ports>
      <port protocol="tcp" portid="23"><state state="open"/><service name="telnet" product="Cisco IOS telnetd" version="15.2"/></port>
      <port protocol="tcp" portid="445"><state state="open"/><service name="microsoft-ds" product="Windows Embedded SMB" version="2.1"/></port>
    </ports>
  </host>
  <host>
    <address addr="10.10.1.5" addrtype="ipv4"/>
    <hostnames><hostname name="ad-dc01.corp.internal" type="PTR"/></hostnames>
    <ports>
      <port protocol="tcp" portid="445"><state state="open"/><service name="microsoft-ds" product="Windows Server AD" version="2022"/></port>
      <port protocol="tcp" portid="3389"><state state="open"/><service name="ms-wbt-server" product="Microsoft Terminal Services"/></port>
      <port protocol="tcp" portid="443"><state state="open"/><service name="https" product="ADFS Web Proxy"/></port>
    </ports>
  </host>
  <host>
    <address addr="172.16.4.12" addrtype="ipv4"/>
    <hostnames><hostname name="bomgar-dmz-gw01.corp.internal" type="PTR"/></hostnames>
    <ports>
      <port protocol="tcp" portid="161"><state state="open"/><service name="snmp" product="Net-SNMP" version="5.7"/></port>
      <port protocol="tcp" portid="21"><state state="open"/><service name="ftp" product="vsftpd" version="3.0.2"/></port>
    </ports>
  </host>
</nmaprun>
"""
    (BASE / "nmap_scan_sample.xml").write_text(nmap_xml, encoding="utf-8")

    policy = {
        "site_name": "Chandigarh-Offshore-SOC-Lab",
        "switch_trusted_uplink": "GigabitEthernet1/0/48",
        "corp_workstation_subnet": "10.20.0.0 255.255.0.0",
        "ad_core_subnet": "10.10.1.0 255.255.255.0",
        "ot_rov_subnet": "10.50.10.0 255.255.255.0",
        "pam_jump_subnet": "10.99.0.0 255.255.255.0",
        "bomgar_external_relay_ip": "198.51.100.44",
        "vlans": [
            {"id": 10, "name": "CORP_WORKSTATIONS"},
            {"id": 20, "name": "OFFSHORE_OT_ROV"},
            {"id": 99, "name": "MGMT_PAM_BOMGAR"},
            {"id": 999, "name": "BLACKHOLE_UNUSED"},
        ],
    }
    (BASE / "network_segmentation_policy.yml").write_text(yaml.safe_dump(policy, sort_keys=False), encoding="utf-8")


if __name__ == "__main__":
    build_all()
    print("Generated NetGuard real X.509 PEM certs, PCAP, Nmap XML, and Cisco YAML policy cleanly.")
