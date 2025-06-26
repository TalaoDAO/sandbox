from datetime import datetime, timedelta
import json
import base64
from typing import Tuple, List, Union, Dict

from jwcrypto import jwk, jwt
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.exceptions import InvalidSignature


# Load keys from a JSON file
with open('keys.json') as f:
    keys = json.load(f)

TRUST_ANCHOR_KEY: Dict = keys['RSA_key']  # Root CA
SIGNER_KEY: Dict = keys['issuer_key']  # Leaf signer


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



def verify_trust_chain(base64_chain: List[str]) -> None:
    certs = [
        x509.load_der_x509_certificate(base64.b64decode(cert), default_backend())
        for cert in base64_chain
    ]
    leaf_cert, issuer_cert = certs[0], certs[1]

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
            raise ValueError("Unsupported public key type")

        print("✅ Leaf certificate is correctly signed by the issuer.")
    except InvalidSignature:
        print("❌ Invalid signature: the chain is broken.")
    except Exception as e:
        print(f"⚠️ Verification failed: {e}")
        
        
def generate_certificates( signer_key: Dict, trust_anchor_key: Dict) -> Tuple[bytes, bytes]:
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
    trust_san = x509.SubjectAlternativeName([x509.DNSName("talao.io")])
    trust_cert = (
        x509.CertificateBuilder()
        .subject_name(trust_subject)
        .issuer_name(trust_subject)
        .public_key(trust_anchor.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), False)
        .add_extension(trust_san, False)
        .sign(trust_anchor, hashes.SHA256(), default_backend())
    )

    # Signer certificate (issued by trust anchor)
    signer_subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "FR"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Paris"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Web3 Digital Wallet"),
        x509.NameAttribute(NameOID.COMMON_NAME, "talao.co"),
    ])
    signer_san = x509.SubjectAlternativeName([
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
        .add_extension(signer_san, False)
        .sign(trust_anchor, hashes.SHA256(), default_backend())
    )

    return signer_cert.public_bytes(serialization.Encoding.DER), trust_cert.public_bytes(serialization.Encoding.DER)


def generate_x509_san_dns() -> List[str]:
    """Generate base64-encoded DER certificates for use in x5c header."""
    signer_der, trust_anchor_der = generate_certificates(SIGNER_KEY, TRUST_ANCHOR_KEY)
    return [base64.b64encode(signer_der).decode(), base64.b64encode(trust_anchor_der).decode()]


def build_x509_san_dns():
    """this function is called by oidc4vc.py"""
    return ['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']


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
    cert_chain = generate_x509_san_dns()
    verify_trust_chain(cert_chain)
    
    cert_chain = build_x509_san_dns()
    verify_trust_chain(cert_chain)



"""
ssl_certificate /etc/letsencrypt/live/app.talao.co/fullchain.pem; # managed by Certbot
    ssl_certificate_key /etc/letsencrypt/live/app.talao.co/privkey.pem; # managed by Certbot
    include /etc/letsencrypt/options-ssl-nginx.conf; # managed by Certbot
    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem; # managed by Certbot



"""