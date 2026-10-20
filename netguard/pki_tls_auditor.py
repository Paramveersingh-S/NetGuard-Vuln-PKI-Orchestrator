"""Real X.509 Cryptography PKI Chain & TLS Certificate Hygiene Auditor."""

from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa


@dataclass
class X509AuditResult:
    pem_file: str
    common_name: str
    issuer_cn: str
    signature_hash: str
    key_algorithm: str
    key_bits: int
    days_remaining: int
    is_self_signed: bool
    san_dns_names: List[str]
    status: str
    findings: List[str]


def audit_pem_certificate(pem_path: str | Path, reference_date: datetime | None = None) -> X509AuditResult:
    """Parse an actual X.509 PEM certificate using `cryptography.x509` and audit against PKI standards."""
    p = Path(pem_path)
    cert = x509.load_pem_x509_certificate(p.read_bytes())
    ref = reference_date or datetime(2026, 10, 24, tzinfo=timezone.utc)

    cn_attrs = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    cn = cn_attrs[0].value if cn_attrs else "UNKNOWN"
    iss_attrs = cert.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    issuer_cn = iss_attrs[0].value if iss_attrs else "UNKNOWN"

    hash_name = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "unknown"
    pub = cert.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        key_alg = "RSA"
        key_bits = pub.key_size
    elif isinstance(pub, ec.EllipticCurvePublicKey):
        key_alg = f"ECDSA-{pub.curve.name}"
        key_bits = pub.key_size
    else:
        key_alg = type(pub).__name__
        key_bits = 0

    days_rem = (cert.not_valid_after_utc - ref).days
    is_self_signed = cert.subject == cert.issuer

    san_names: List[str] = []
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        san_names = san.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        pass

    is_ca = False
    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        is_ca = bc.value.ca
    except x509.ExtensionNotFound:
        pass

    issues: List[str] = []
    if days_rem <= 0:
        issues.append(f"EXPIRED ({abs(days_rem)}d overdue)")
    elif days_rem <= 30:
        issues.append(f"EXPIRING_SOON ({days_rem}d left)")

    if hash_name.lower() in ("sha1", "md5"):
        issues.append(f"WEAK_SIGNATURE_HASH ({hash_name.upper()})")

    if key_alg == "RSA" and key_bits < 2048:
        issues.append(f"WEAK_RSA_KEY ({key_bits}-bit)")

    if is_self_signed and not is_ca:
        issues.append("UNTRUSTED_SELF_SIGNED_LEAF")

    if not is_ca and not san_names:
        issues.append("MISSING_SAN_EXTENSION")

    return X509AuditResult(
        pem_file=p.name,
        common_name=cn,
        issuer_cn=issuer_cn,
        signature_hash=hash_name.upper(),
        key_algorithm=key_alg,
        key_bits=key_bits,
        days_remaining=days_rem,
        is_self_signed=is_self_signed,
        san_dns_names=san_names,
        status="NON_COMPLIANT" if issues else "COMPLIANT",
        findings=issues,
    )


def audit_pki_directory(cert_dir: str | Path, reference_date: datetime | None = None) -> Dict[str, object]:
    """Audit all PEM certificates inside a directory."""
    pems = sorted(Path(cert_dir).glob("*.pem"))
    results = [audit_pem_certificate(p, reference_date=reference_date) for p in pems]
    compliant = sum(1 for r in results if r.status == "COMPLIANT")
    return {
        "total_certificates": len(results),
        "compliant_count": compliant,
        "non_compliant_count": len(results) - compliant,
        "results": [asdict(r) for r in results],
    }


def probe_live_tls_endpoint(host: str, port: int = 443, timeout_sec: float = 2.0) -> Dict[str, object]:
    """Live TLS handshake inspector using Python stdlib `ssl`."""
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout_sec) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cipher = ssock.cipher()
                return {
                    "host": host,
                    "port": port,
                    "reachable": True,
                    "tls_version": ssock.version(),
                    "cipher_suite": cipher[0] if cipher else None,
                    "cipher_bits": cipher[2] if cipher else None,
                }
    except Exception as exc:
        return {"host": host, "port": port, "reachable": False, "error": str(exc)}
