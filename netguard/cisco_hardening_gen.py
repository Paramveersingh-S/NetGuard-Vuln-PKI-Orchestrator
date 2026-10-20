"""YAML-driven Cisco Catalyst 2960-X IOS & ASA Firewall + Bomgar Hardening Generator & CIS Verifier."""

from __future__ import annotations

from pathlib import Path
from typing import Dict, List

import yaml


REQUIRED_CIS_CONTROLS = [
    "ip dhcp snooping",
    "ip arp inspection vlan",
    "dot1x pae authenticator",
    "switchport port-security",
    "ip ssh version 2",
    "transport input ssh",
    "access-list CORP-TO-OT-IN extended deny tcp",
    "access-list PAM-JUMP-OUT extended permit tcp",
]


def generate_cisco_hardening_config(policy_yml_path: str | Path, output_cfg_path: str | Path) -> Dict[str, object]:
    """Compile YAML segmentation policy into Cisco IOS/ASA ACL config and verify CIS controls."""
    policy = yaml.safe_load(Path(policy_yml_path).read_text(encoding="utf-8"))
    vlans = policy["vlans"]
    bomgar_relay = policy["bomgar_external_relay_ip"]
    ad_subnet = policy["ad_core_subnet"]
    ot_subnet = policy["ot_rov_subnet"]
    corp_subnet = policy["corp_workstation_subnet"]
    jump_subnet = policy["pam_jump_subnet"]
    uplink = policy["switch_trusted_uplink"]

    lines: List[str] = [
        "! ==========================================================================",
        f"! NetGuard Automated Cisco Hardening Baseline ({policy['site_name']})",
        "! Platforms: Cisco Catalyst 2960-X IOS + Cisco ASA 5516-X",
        "! ==========================================================================",
        "!",
    ]
    for v in vlans:
        lines.extend([f"vlan {v['id']}", f" name {v['name']}"])

    lines.extend([
        "!",
        "! --- Layer 2 Anti-Spoofing (DHCP Snooping + Dynamic ARP Inspection) ---",
        "ip dhcp snooping",
        "ip dhcp snooping vlan 10,20",
        "no ip dhcp snooping information option",
        "ip arp inspection vlan 10,20",
        "ip arp inspection validate src-mac dst-mac ip",
        "!",
        f"interface {uplink}",
        " description UPLINK-TO-CORE-AD-DHCP",
        " switchport mode trunk",
        " ip dhcp snooping trust",
        " ip arp inspection trust",
        "!",
        "! --- 802.1X NAC + Port Security ---",
        "aaa new-model",
        "dot1x system-auth-control",
        "interface range GigabitEthernet1/0/1 - 24",
        " switchport mode access",
        " switchport access vlan 10",
        " switchport port-security",
        " switchport port-security maximum 2",
        " switchport port-security violation restrict",
        " ip dhcp snooping limit rate 15",
        " authentication port-control auto",
        " dot1x pae authenticator",
        " spanning-tree portfast",
        " spanning-tree bpduguard enable",
        "!",
        "! --- Management Plane Hardening ---",
        "ip ssh version 2",
        "line vty 0 4",
        " transport input ssh",
        " access-class VTY-MGMT-ACL in",
        "!",
        "! --- Cisco ASA Firewall Policy (IT/OT Segmentation & BeyondTrust/Bomgar) ---",
        f"access-list CORP-TO-OT-IN extended deny tcp {corp_subnet} any eq 445",
        f"access-list CORP-TO-OT-IN extended deny tcp {corp_subnet} any eq 3389",
        f"access-list CORP-TO-OT-IN extended deny tcp {corp_subnet} {ot_subnet} eq 23",
        f"access-list CORP-TO-OT-IN extended permit tcp {jump_subnet} {ot_subnet} eq 22",
        f"access-list CORP-TO-OT-IN extended permit tcp {corp_subnet} {ad_subnet} eq 636",
        f"access-list CORP-TO-OT-IN extended deny ip {corp_subnet} {ot_subnet} log",
        "!",
        f"access-list PAM-JUMP-OUT extended permit tcp {jump_subnet} host {bomgar_relay} eq 443",
        f"access-list PAM-JUMP-OUT extended deny ip {jump_subnet} any log",
        "!",
        "access-group CORP-TO-OT-IN in interface CORP_VLAN10",
        "access-group PAM-JUMP-OUT in interface PAM_JUMP_VLAN99",
        "!",
        "end",
    ])

    rendered = "\n".join(lines) + "\n"
    out = Path(output_cfg_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(rendered, encoding="utf-8")

    missing = [ctrl for ctrl in REQUIRED_CIS_CONTROLS if ctrl not in rendered]
    return {
        "config_path": str(out.name),
        "line_count": len(lines),
        "cis_controls_verified": len(REQUIRED_CIS_CONTROLS) - len(missing),
        "cis_controls_total": len(REQUIRED_CIS_CONTROLS),
        "missing_controls": missing,
        "config_text": rendered,
    }
