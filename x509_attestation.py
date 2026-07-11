"""Persistent X.509 material for mdoc signing.

Standalone execution:
    python x509_attestation.py

This creates a fresh Root CA and a fresh EC P-256 Document Signer,
then stores their private keys and certificates on disk.

Library usage:
    import x509_attestation

The module only loads existing material. It never silently regenerates keys
when imported, because doing so would invalidate the trust chain.
"""
from __future__ import annotations

import base64
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Tuple, Union

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import NameOID


MODULE_DIR = Path(__file__).resolve().parent
MATERIAL_DIR = Path(
    os.getenv("X509_ATTESTATION_DIR", MODULE_DIR / "x509_material")
).expanduser().resolve()

ROOT_KEY_FILE = MATERIAL_DIR / "root_ca_key.pem"
ROOT_CERT_FILE = MATERIAL_DIR / "root_ca_cert.pem"
SIGNER_KEY_FILE = MATERIAL_DIR / "document_signer_key.pem"
SIGNER_CERT_FILE = MATERIAL_DIR / "document_signer_cert.pem"
CHAIN_FILE = MATERIAL_DIR / "document_signer_chain.pem"

REQUIRED_FILES = (
    ROOT_KEY_FILE,
    ROOT_CERT_FILE,
    SIGNER_KEY_FILE,
    SIGNER_CERT_FILE,
)


def alg(key: Union[str, Dict]) -> str:
    key = json.loads(key) if isinstance(key, str) else key
    kty = key.get("kty")
    crv = key.get("crv", "")

    if kty == "EC":
        if crv in ("secp256k1", "P-256K"):
            return "ES256K"
        if crv == "P-256":
            return "ES256"
        if crv == "P-384":
            return "ES384"
        if crv == "P-521":
            return "ES512"
        raise ValueError(f"Unsupported EC curve: {crv}")
    if kty == "RSA":
        return "RS256"
    if kty == "OKP":
        return "EdDSA"
    raise ValueError(f"Unsupported key type: {kty}")


def _b64url_uint(value: int, size: int | None = None) -> str:
    if size is None:
        size = max(1, (value.bit_length() + 7) // 8)
    raw = value.to_bytes(size, "big")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _private_key_to_jwk(private_key) -> Dict:
    if isinstance(private_key, rsa.RSAPrivateKey):
        numbers = private_key.private_numbers()
        public = numbers.public_numbers
        return {
            "kty": "RSA",
            "n": _b64url_uint(public.n),
            "e": _b64url_uint(public.e),
            "d": _b64url_uint(numbers.d),
            "p": _b64url_uint(numbers.p),
            "q": _b64url_uint(numbers.q),
            "dp": _b64url_uint(numbers.dmp1),
            "dq": _b64url_uint(numbers.dmq1),
            "qi": _b64url_uint(numbers.iqmp),
        }
    if isinstance(private_key, ec.EllipticCurvePrivateKey):
        numbers = private_key.private_numbers()
        public = numbers.public_numbers
        if not isinstance(private_key.curve, ec.SECP256R1):
            raise ValueError("Only EC P-256 is supported for the signer JWK")
        return {
            "kty": "EC",
            "crv": "P-256",
            "x": _b64url_uint(public.x, 32),
            "y": _b64url_uint(public.y, 32),
            "d": _b64url_uint(numbers.private_value, 32),
        }
    raise ValueError("Unsupported private key type")


def _write_private_key(path: Path, private_key) -> None:
    data = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    path.write_bytes(data)
    try:
        path.chmod(0o600)
    except OSError:
        pass


def _write_certificate(path: Path, certificate: x509.Certificate) -> None:
    path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))


def create_and_store_certificates(*, overwrite: bool = True) -> Tuple[Path, Path]:
    """Create and persist a new Root CA and EC P-256 Document Signer."""
    MATERIAL_DIR.mkdir(parents=True, exist_ok=True)

    existing = [path for path in REQUIRED_FILES if path.exists()]
    if existing and not overwrite:
        raise FileExistsError(
            "X.509 material already exists: " + ", ".join(str(p) for p in existing)
        )

    root_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    signer_key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(timezone.utc)

    root_subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "FR"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Paris"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Web3 Digital Wallet Trust Anchor"),
        x509.NameAttribute(NameOID.COMMON_NAME, "talao.io Root CA"),
    ])

    root_cert = (
        x509.CertificateBuilder()
        .subject_name(root_subject)
        .issuer_name(root_subject)
        .public_key(root_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=None,
                decipher_only=None,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(root_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("talao.io")]),
            critical=False,
        )
        .sign(root_key, hashes.SHA256())
    )

    signer_subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "FR"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Paris"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Web3 Digital Wallet"),
        x509.NameAttribute(NameOID.COMMON_NAME, "talao.co Document Signer"),
    ])

    signer_cert = (
        x509.CertificateBuilder()
        .subject_name(signer_subject)
        .issuer_name(root_subject)
        .public_key(signer_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=825))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=None,
                decipher_only=None,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([x509.ObjectIdentifier("1.0.18013.5.1.2")]),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(signer_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("talao.co"),
                x509.UniformResourceIdentifier("https://talao.co"),
            ]),
            critical=False,
        )
        .sign(root_key, hashes.SHA256())
    )

    _write_private_key(ROOT_KEY_FILE, root_key)
    _write_certificate(ROOT_CERT_FILE, root_cert)
    _write_private_key(SIGNER_KEY_FILE, signer_key)
    _write_certificate(SIGNER_CERT_FILE, signer_cert)
    CHAIN_FILE.write_bytes(
        signer_cert.public_bytes(serialization.Encoding.PEM)
        + root_cert.public_bytes(serialization.Encoding.PEM)
    )

    verify_stored_material()
    return SIGNER_CERT_FILE, ROOT_CERT_FILE


def _require_stored_material() -> None:
    missing = [str(path) for path in REQUIRED_FILES if not path.is_file()]
    if missing:
        raise FileNotFoundError(
            "Missing X.509 material: "
            + ", ".join(missing)
            + ". Run `python x509_attestation.py` once to generate it."
        )


def load_stored_material() -> Tuple[Dict, Dict, x509.Certificate, x509.Certificate]:
    """Load persisted JWK private keys and X.509 certificates."""
    _require_stored_material()
    root_key = serialization.load_pem_private_key(ROOT_KEY_FILE.read_bytes(), password=None)
    signer_key = serialization.load_pem_private_key(SIGNER_KEY_FILE.read_bytes(), password=None)
    root_cert = x509.load_pem_x509_certificate(ROOT_CERT_FILE.read_bytes())
    signer_cert = x509.load_pem_x509_certificate(SIGNER_CERT_FILE.read_bytes())
    return (
        _private_key_to_jwk(root_key),
        _private_key_to_jwk(signer_key),
        root_cert,
        signer_cert,
    )


def verify_stored_material() -> None:
    root_jwk, signer_jwk, root_cert, signer_cert = load_stored_material()

    root_private = serialization.load_pem_private_key(ROOT_KEY_FILE.read_bytes(), password=None)
    signer_private = serialization.load_pem_private_key(SIGNER_KEY_FILE.read_bytes(), password=None)

    if root_private.public_key().public_numbers() != root_cert.public_key().public_numbers():
        raise ValueError("Root private key does not match Root certificate")
    if signer_private.public_key().public_numbers() != signer_cert.public_key().public_numbers():
        raise ValueError("Signer private key does not match signer certificate")

    root_cert.public_key().verify(
        signer_cert.signature,
        signer_cert.tbs_certificate_bytes,
        padding.PKCS1v15(),
        signer_cert.signature_hash_algorithm,
    )

    # Ensure exported JWKs are usable and not accidentally public-only.
    if "d" not in signer_jwk or not root_jwk.get("d"):
        raise ValueError("Stored private keys could not be exported as private JWKs")


def generate_x509_san_dns() -> List[str]:
    """Load the existing x5chain as base64(DER): signer first, then root."""
    _require_stored_material()
    signer_cert = x509.load_pem_x509_certificate(SIGNER_CERT_FILE.read_bytes())
    root_cert = x509.load_pem_x509_certificate(ROOT_CERT_FILE.read_bytes())
    return [
        base64.b64encode(signer_cert.public_bytes(serialization.Encoding.DER)).decode("ascii"),
       # base64.b64encode(root_cert.public_bytes(serialization.Encoding.DER)).decode("ascii"),
    ]


def build_x509_san_dns() -> List[str]:
    """Backward-compatible alias used by existing issuer code."""
    return generate_x509_san_dns()


def verify_trust_chain(base64_chain: List[str]) -> None:
    if len(base64_chain) < 2:
        raise ValueError("The certificate chain must contain signer and root certificates")

    leaf_cert = x509.load_der_x509_certificate(base64.b64decode(base64_chain[0]))
    issuer_cert = x509.load_der_x509_certificate(base64.b64decode(base64_chain[1]))
    issuer_public_key = issuer_cert.public_key()

    try:
        if isinstance(issuer_public_key, rsa.RSAPublicKey):
            issuer_public_key.verify(
                leaf_cert.signature,
                leaf_cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                leaf_cert.signature_hash_algorithm,
            )
        elif isinstance(issuer_public_key, ec.EllipticCurvePublicKey):
            issuer_public_key.verify(
                leaf_cert.signature,
                leaf_cert.tbs_certificate_bytes,
                ec.ECDSA(leaf_cert.signature_hash_algorithm),
            )
        else:
            raise ValueError("Unsupported issuer public key type")
    except InvalidSignature as exc:
        raise ValueError("Invalid signer/root certificate chain") from exc


def build_verifier_attestation(client_id: str) -> str:
    # Optional dependency, only required for verifier attestation JWTs.
    from jwcrypto import jwk, jwt

    rsa_or_ec_key = jwk.JWK(**SIGNER_KEY)
    public_key = rsa_or_ec_key.export(private_key=False, as_dict=True)
    public_key.pop("kid", None)

    header = {
        "typ": "verifier-attestation+jwt",
        "alg": alg(SIGNER_KEY),
        "x5c": generate_x509_san_dns(),
    }
    payload = {
        "iss": "did:web:talao.co",
        "sub": client_id or "did:web:talao.co",
        "cnf": {"jwk": public_key},
        "exp": int(datetime.now(timezone.utc).timestamp()) + 1000,
    }

    token = jwt.JWT(header=header, claims=payload, algs=[alg(SIGNER_KEY)])
    token.make_signed_token(rsa_or_ec_key)
    return token.serialize()


# Importing the module loads existing material only; it never generates it.
# During standalone execution, generation must happen before the first load.
if __name__ != "__main__":
    TRUST_ANCHOR_KEY, SIGNER_KEY, ROOT_CERTIFICATE, SIGNER_CERTIFICATE = load_stored_material()
else:
    TRUST_ANCHOR_KEY = {}
    SIGNER_KEY = {}
    ROOT_CERTIFICATE = None
    SIGNER_CERTIFICATE = None


if __name__ == "__main__":
    signer_path, root_path = create_and_store_certificates(overwrite=True)
    # Refresh globals for the checks performed in this process.
    TRUST_ANCHOR_KEY, SIGNER_KEY, ROOT_CERTIFICATE, SIGNER_CERTIFICATE = load_stored_material()
    chain = generate_x509_san_dns()
    verify_trust_chain(chain)
    print("New X.509 material created successfully:")
    print(f"  Root certificate:   {root_path}")
    print(f"  Signer certificate: {signer_path}")
    print(f"  Full chain:         {CHAIN_FILE}")
    print(f"  Private keys:       {ROOT_KEY_FILE}, {SIGNER_KEY_FILE}")
