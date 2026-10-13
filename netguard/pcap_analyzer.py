"""Hybrid tshark (Wireshark CLI) + pure-Python libpcap Packet Dissector and Anomaly Detector."""

from __future__ import annotations

import math
import re
import shutil
import socket
import struct
import subprocess
from collections import Counter, defaultdict
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, List, Optional, Tuple


PCAP_MAGIC_LE = 0xA1B2C3D4
PCAP_MAGIC_BE = 0xD4C3B2A1


@dataclass
class PacketSummary:
    index: int
    src_ip: str
    dst_ip: str
    protocol: str
    src_port: Optional[int]
    dst_port: Optional[int]
    tcp_flags: int
    dns_qname: Optional[str]
    payload: bytes


@dataclass
class NetworkAlert:
    rule_id: str
    severity: str
    category: str
    src_ip: str
    dst_ip: str
    evidence: str
    mitre_technique: str
    recommended_control: str


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _parse_dns_qname(udp_payload: bytes) -> Optional[str]:
    if len(udp_payload) < 13:
        return None
    qdcount = struct.unpack("!H", udp_payload[4:6])[0]
    if qdcount < 1:
        return None
    idx = 12
    labels: List[str] = []
    while idx < len(udp_payload):
        ln = udp_payload[idx]
        idx += 1
        if ln == 0:
            break
        if ln > 63 or idx + ln > len(udp_payload):
            return None
        labels.append(udp_payload[idx : idx + ln].decode("ascii", errors="replace"))
        idx += ln
    return ".".join(labels) if labels else None


def _dissect_with_tshark(pcap_path: Path) -> Optional[Tuple[str, List[PacketSummary]]]:
    """Use native tshark or WSL Ubuntu tshark when available to dissect frames identically to Wireshark."""
    fields = [
        "-T", "fields",
        "-e", "frame.number",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "ip.proto",
        "-e", "tcp.srcport",
        "-e", "tcp.dstport",
        "-e", "tcp.flags",
        "-e", "udp.srcport",
        "-e", "udp.dstport",
        "-e", "dns.qry.name",
        "-e", "http.authorization",
    ]
    cmd = None
    backend = "tshark-native"
    if shutil.which("tshark"):
        cmd = ["tshark", "-r", str(pcap_path)] + fields
    elif shutil.which("wsl"):
        posix = "/" + str(pcap_path.resolve()).replace(":\\", "/").replace("\\", "/")
        drive = posix[1].lower()
        wsl_path = f"/mnt/{drive}{posix[2:]}"
        cmd = ["wsl", "-d", "Ubuntu-24.04", "--", "tshark", "-r", wsl_path] + fields
        backend = "tshark-wsl"

    if cmd is None:
        return None

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=8)
        if proc.returncode != 0 or not proc.stdout.strip():
            return None
        packets: List[PacketSummary] = []
        for line in proc.stdout.splitlines():
            cols = line.split("\t")
            while len(cols) < 11:
                cols.append("")
            num, src_ip, dst_ip, ip_proto, tcp_sp, tcp_dp, tcp_fl, udp_sp, udp_dp, dns_q, http_auth = cols[:11]
            if not src_ip or not dst_ip:
                continue
            proto = "TCP" if ip_proto == "6" else ("UDP" if ip_proto == "17" else f"IP-{ip_proto}")
            sport = int(tcp_sp or udp_sp) if (tcp_sp or udp_sp) else None
            dport = int(tcp_dp or udp_dp) if (tcp_dp or udp_dp) else None
            flags = int(tcp_fl, 16) if tcp_fl.startswith("0x") else (int(tcp_fl) if tcp_fl.isdigit() else 0)
            payload = f"Authorization: {http_auth}".encode("utf-8") if http_auth else b""
            packets.append(
                PacketSummary(
                    index=int(num),
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    protocol=proto,
                    src_port=sport,
                    dst_port=dport,
                    tcp_flags=flags,
                    dns_qname=dns_q or None,
                    payload=payload,
                )
            )
        return backend, packets
    except Exception:
        return None


def read_pcap_python_fallback(pcap_path: str | Path) -> List[PacketSummary]:
    """Pure-Python libpcap fallback dissector for CI/portable execution without Wireshark."""
    raw = Path(pcap_path).read_bytes()
    if len(raw) < 24:
        raise ValueError("Invalid PCAP file")
    magic_le = struct.unpack("<I", raw[:4])[0]
    endian = "<" if magic_le == PCAP_MAGIC_LE else (">" if magic_le == PCAP_MAGIC_BE else "")
    if not endian:
        raise ValueError(f"Unsupported PCAP magic number: 0x{magic_le:08x}")

    offset = 24
    packets: List[PacketSummary] = []
    idx = 0
    while offset + 16 <= len(raw):
        _ts, _us, incl_len, _orig = struct.unpack(endian + "IIII", raw[offset : offset + 16])
        offset += 16
        frame = raw[offset : offset + incl_len]
        offset += incl_len
        idx += 1
        if len(frame) < 34 or struct.unpack("!H", frame[12:14])[0] != 0x0800:
            continue
        ihl = (frame[14] & 0x0F) * 4
        proto_num = frame[14 + 9]
        src_ip = socket.inet_ntoa(frame[14 + 12 : 14 + 16])
        dst_ip = socket.inet_ntoa(frame[14 + 16 : 14 + 20])
        l4 = 14 + ihl
        sport = dport = None
        flags = 0
        dns_q = None
        payload = b""
        pname = f"IP-{proto_num}"
        if proto_num == 6 and len(frame) >= l4 + 20:
            pname = "TCP"
            sport, dport = struct.unpack("!HH", frame[l4 : l4 + 4])
            doff = ((frame[l4 + 12] >> 4) & 0x0F) * 4
            flags = frame[l4 + 13]
            payload = frame[l4 + doff :]
        elif proto_num == 17 and len(frame) >= l4 + 8:
            pname = "UDP"
            sport, dport = struct.unpack("!HH", frame[l4 : l4 + 4])
            payload = frame[l4 + 8 :]
            if dport == 53:
                dns_q = _parse_dns_qname(payload)
        packets.append(PacketSummary(idx, src_ip, dst_ip, pname, sport, dport, flags, dns_q, payload))
    return packets


class PcapAnomalyDetector:
    """Detect SYN floods, high-entropy DNS tunneling, Rogue DHCP offers, and HTTP credential leaks."""

    CRED_RE = re.compile(rb"(Authorization:\s*Basic\s+[A-Za-z0-9+/=]+|password=[^&\s]{3,})", re.IGNORECASE)

    def __init__(
        self,
        authorized_dhcp_servers: Optional[List[str]] = None,
        syn_burst_threshold: int = 8,
        dns_entropy_threshold: float = 3.55,
    ) -> None:
        self.authorized_dhcp_servers = set(authorized_dhcp_servers or ["10.10.1.10"])
        self.syn_burst_threshold = syn_burst_threshold
        self.dns_entropy_threshold = dns_entropy_threshold

    def analyze(self, pcap_path: str | Path, prefer_tshark: bool = True) -> Dict[str, object]:
        p = Path(pcap_path)
        dissector = "python-libpcap"
        packets: List[PacketSummary] = []

        if prefer_tshark:
            tshark_res = _dissect_with_tshark(p)
            if tshark_res is not None:
                dissector, packets = tshark_res

        if not packets:
            packets = read_pcap_python_fallback(p)

        alerts: List[NetworkAlert] = []
        syn_counter: Dict[Tuple[str, str, int], int] = defaultdict(int)
        ack_seen: set[Tuple[str, str]] = set()
        flagged_dns: set[Tuple[str, str]] = set()

        for pkt in packets:
            if pkt.protocol == "TCP" and pkt.dst_port is not None:
                is_syn = bool(pkt.tcp_flags & 0x02)
                is_ack = bool(pkt.tcp_flags & 0x10)
                if is_syn and not is_ack:
                    syn_counter[(pkt.src_ip, pkt.dst_ip, pkt.dst_port)] += 1
                elif is_ack:
                    ack_seen.add((pkt.src_ip, pkt.dst_ip))

                if pkt.payload and (pkt.dst_port in (80, 8080) or pkt.src_port in (80, 8080)):
                    m = self.CRED_RE.search(pkt.payload)
                    if m:
                        alerts.append(
                            NetworkAlert(
                                rule_id="PCAP-CRED-004",
                                severity="HIGH",
                                category="Cleartext Credential Exposure",
                                src_ip=pkt.src_ip,
                                dst_ip=pkt.dst_ip,
                                evidence=f"Frame #{pkt.index} TCP/{pkt.dst_port} matched '{m.group(0).decode(errors='replace')[:44]}'",
                                mitre_technique="T1040 Network Sniffing",
                                recommended_control="Enforce TLS 1.2+ HTTPS and block legacy HTTP basic auth.",
                            )
                        )

            if pkt.protocol == "UDP" and pkt.dst_port == 53 and pkt.dns_qname:
                sub = pkt.dns_qname.split(".")[0]
                ent = shannon_entropy(sub)
                if (len(sub) >= 24 and ent >= self.dns_entropy_threshold) or len(pkt.dns_qname) > 55:
                    if (pkt.src_ip, pkt.dns_qname) not in flagged_dns:
                        flagged_dns.add((pkt.src_ip, pkt.dns_qname))
                        alerts.append(
                            NetworkAlert(
                                rule_id="PCAP-DNS-002",
                                severity="HIGH",
                                category="Suspected DNS Tunneling / Exfiltration",
                                src_ip=pkt.src_ip,
                                dst_ip=pkt.dst_ip,
                                evidence=f"QNAME='{pkt.dns_qname[:60]}' (entropy={ent:.2f}, sub_len={len(sub)})",
                                mitre_technique="T1071.004 DNS C2 / Exfiltration",
                                recommended_control="Block high-entropy external DNS resolvers at perimeter firewall.",
                            )
                        )

            if pkt.protocol == "UDP" and pkt.src_port == 67 and pkt.dst_port == 68:
                if pkt.src_ip not in self.authorized_dhcp_servers:
                    alerts.append(
                        NetworkAlert(
                            rule_id="PCAP-DHCP-003",
                            severity="CRITICAL",
                            category="Rogue DHCP Server Offer Detected",
                            src_ip=pkt.src_ip,
                            dst_ip=pkt.dst_ip,
                            evidence=f"Unauthorized DHCP server {pkt.src_ip} responded on UDP 67->68",
                            mitre_technique="T1557 Adversary-in-the-Middle",
                            recommended_control="Enable Cisco 'ip dhcp snooping' and trust only core uplink trunk.",
                        )
                    )

        for (src_ip, dst_ip, dport), cnt in syn_counter.items():
            if cnt >= self.syn_burst_threshold and (src_ip, dst_ip) not in ack_seen:
                alerts.append(
                    NetworkAlert(
                        rule_id="PCAP-SYN-001",
                        severity="CRITICAL",
                        category="TCP SYN Flood / Half-Open Exhaustion",
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        evidence=f"{cnt} unacknowledged SYN packets targeting {dst_ip}:{dport}",
                        mitre_technique="T1498 Network Denial of Service",
                        recommended_control="Enable Cisco ASA SYN-cookie protection & switchport storm-control.",
                    )
                )

        return {
            "pcap_file": str(p.name),
            "dissector_backend": dissector,
            "total_packets_parsed": len(packets),
            "alert_count": len(alerts),
            "severity_breakdown": dict(Counter(a.severity for a in alerts)),
            "alerts": [asdict(a) for a in alerts],
        }
