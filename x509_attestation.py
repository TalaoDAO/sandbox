from datetime import datetime, timedelta
import json
import base64
from typing import Tuple, List, Union, Dict

from jwcrypto import jwk, jwt
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend


# Load keys from a JSON file
with open('keys.json') as f:
    keys = json.load(f)

TRUST_ANCHOR_KEY: Dict = keys['issuer_key']  # Root CA
SIGNER_KEY: Dict = keys['RSA_key']  # Leaf signer


def alg(key: Union[str, Dict]) -> str:
    """Determine JWT algorithm based on key type."""
    key = json.loads(key) if isinstance(key, str) else key
    kty = key.get('kty')
    crv = key.get('crv', '')

    if kty == 'EC':
        if crv in ['secp256k1', 'P-256K']:
            return 'ES256K'
        elif crv == 'P-256':
            return 'ES256'
        elif crv == 'P-384':
            return 'ES384'
        elif crv == 'P-521':
            return 'ES512'
        raise ValueError("Unsupported EC curve")
    elif kty == 'RSA':
        return 'RS256'
    elif kty == 'OKP':
        return 'EdDSA'
    else:
        raise ValueError("Unsupported key type")


def convert_jwk_to_pem(key: Dict) -> bytes:
    """Convert JWK to PEM format."""
    return jwk.JWK(**key).export_to_pem(private_key=True, password=None)


def generate_certificates(trust_anchor_key: Dict, signer_key: Dict) -> Tuple[bytes, bytes]:
    """
    Generate X.509 certificates for the trust anchor and signer.
    Returns:
        Tuple of DER-encoded (signer_cert, trust_anchor_cert)
    """
    # Load private keys from PEM
    trust_anchor_pem = convert_jwk_to_pem(trust_anchor_key)
    signer_pem = convert_jwk_to_pem(signer_key)
    trust_anchor = serialization.load_pem_private_key(trust_anchor_pem, password=None)
    signer = serialization.load_pem_private_key(signer_pem, password=None)

    now = datetime.now()

    # Trust anchor certificate (self-signed)
    trust_subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "FR"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Paris"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Web3 Digital Wallet Trust Anchor"),
        x509.NameAttribute(NameOID.COMMON_NAME, "talao.io"),
    ])
    san = x509.SubjectAlternativeName([x509.DNSName("talao.io")])
    trust_cert = (
        x509.CertificateBuilder()
        .subject_name(trust_subject)
        .issuer_name(trust_subject)
        .public_key(trust_anchor.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), False)
        .add_extension(san, False)
        .sign(trust_anchor, hashes.SHA256(), default_backend())
    )

    # Signer certificate (issued by trust anchor)
    signer_subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "FR"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Paris"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Web3 Digital Wallet"),
        x509.NameAttribute(NameOID.COMMON_NAME, "talao.co"),
    ])
    san = x509.SubjectAlternativeName([
        x509.DNSName("talao.co"),
        x509.UniformResourceIdentifier("https://talao.co")
])
    signer_cert = (
        x509.CertificateBuilder()
        .subject_name(signer_subject)
        .issuer_name(trust_subject)
        .public_key(signer.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), False)
        .add_extension(san, False)
        .sign(trust_anchor, hashes.SHA256(), default_backend())
    )

    return signer_cert.public_bytes(serialization.Encoding.DER), trust_cert.public_bytes(serialization.Encoding.DER)


def generate_x509_san_dns(hostname: str = "talao.co") -> List[str]:
    """Generate base64-encoded DER certificates for use in x5c header."""
    signer_der, trust_anchor_der = generate_certificates(TRUST_ANCHOR_KEY, SIGNER_KEY)
    return [base64.b64encode(signer_der).decode(), base64.b64encode(trust_anchor_der).decode()]


def build_x509_san_dns():
    """this function is called by oidc4vc.py"""
    return ['MIICqTCCAlCgAwIBAgIUY7+k67+93hDrG9Ewa0oesv3oXUAwCgYIKoZIzj0EAwIwWzELMAkGA1UEBhMCRlIxDjAMBgNVBAcMBVBhcmlzMSkwJwYDVQQKDCBXZWIzIERpZ2l0YWwgV2FsbGV0IFRydXN0IEFuY2hvcjERMA8GA1UEAwwIdGFsYW8uaW8wHhcNMjUwNjI2MTMzOTE4WhcNMzUwNjI0MTMzOTE4WjBOMQswCQYDVQQGEwJGUjEOMAwGA1UEBwwFUGFyaXMxHDAaBgNVBAoME1dlYjMgRGlnaXRhbCBXYWxsZXQxETAPBgNVBAMMCHRhbGFvLmNvMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApPocyKreTAn3YrmGyPYXHklYqUiSSQirGACwJSYYs+ksfw4brtA3SZCmA2sdAO8a2DXfqADwFgVSxJFtJ3GkHLV2ZvOIOnZCX6MF6NIWHB9c64ydrYNJbEy72oyG/+v+sE6rb0x+D+uJe9DFYIURzisyBlNA7imsiZPQniOjPLv0BUgED0vdO5HijFe7XbpVhoU+2oTkHHQ4CadmBZhelCczACkXpOU7mwcImGj9h1//PsyT5VBLi/92+93NimZjechPaaTYEU2u0rfnfVW5eGDYNAynO4Q2bhpFPRTXWZ5Lhnhnq7M76T6DGA3GeAu/MOzB0l4dxpFMJ6wHnekdkQIDAQABozQwMjAJBgNVHRMEAjAAMCUGA1UdEQQeMByCCHRhbGFvLmNvhhBodHRwczovL3RhbGFvLmNvMAoGCCqGSM49BAMCA0cAMEQCICQBel1IVa96TaESOzqtDzuhkkURzCTw/LinOqMEpk9XAiArAjlrDYOVeOtIzR/kbpqmAkeiLo+bgIU4c+fc9V0QMQ==', 'MIIB4DCCAYagAwIBAgIUUY5MikywTKPGMkRDyZI5F2ZUbsYwCgYIKoZIzj0EAwIwWzELMAkGA1UEBhMCRlIxDjAMBgNVBAcMBVBhcmlzMSkwJwYDVQQKDCBXZWIzIERpZ2l0YWwgV2FsbGV0IFRydXN0IEFuY2hvcjERMA8GA1UEAwwIdGFsYW8uaW8wHhcNMjUwNjI2MTMzOTE4WhcNMzUwNjI0MTMzOTE4WjBbMQswCQYDVQQGEwJGUjEOMAwGA1UEBwwFUGFyaXMxKTAnBgNVBAoMIFdlYjMgRGlnaXRhbCBXYWxsZXQgVHJ1c3QgQW5jaG9yMREwDwYDVQQDDAh0YWxhby5pbzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABDQdcpTL3lePzz2LcfSmBI6EtVlgPKjd90iWr/aKVk2jUtOG2jR3NHadMMJ7wdYEq5/nHJHVfcy7QPt/OBHhBrGjKDAmMA8GA1UdEwQIMAYBAf8CAQAwEwYDVR0RBAwwCoIIdGFsYW8uaW8wCgYIKoZIzj0EAwIDSAAwRQIgdDl2rrQiyfKOZiezHm3f8d5aY2xXnGupw2KNSKMrCcACIQDX7rcwrPPYYE2SwstC/c0bjP0K/XEvdhvnirTknTZR7w==']


def build_verifier_attestation(client_id: str) -> str:
    """Generate a JWT attestation including the public key (cnf)."""
    rsa_key = jwk.JWK(**SIGNER_KEY)
    public_key = rsa_key.export(private_key=False, as_dict=True)
    public_key.pop('kid', None)

    header = {
        'typ': "verifier-attestation+jwt",
        'alg': alg(SIGNER_KEY),
    }
    payload = {
        'iss': "did:web:talao.co",
        'sub': client_id or "did:web:talao.co",
        'cnf': {"jwk": public_key},
        'exp': datetime.timestamp(datetime.now()) + 1000,
    }

    token = jwt.JWT(header=header, claims=payload, algs=[alg(SIGNER_KEY)])
    token.make_signed_token(rsa_key)
    return token.serialize()


if __name__ == '__main__':
    print(generate_x509_san_dns())
    


"""
ssl_certificate /etc/letsencrypt/live/app.talao.co/fullchain.pem; # managed by Certbot
    ssl_certificate_key /etc/letsencrypt/live/app.talao.co/privkey.pem; # managed by Certbot
    include /etc/letsencrypt/options-ssl-nginx.conf; # managed by Certbot
    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem; # managed by Certbot



"""