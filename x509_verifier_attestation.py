from datetime import datetime, timedelta
import json
from jwcrypto import jwk, jwt
import base64
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization


def alg(key):
    key = json.loads(key) if isinstance(key, str) else key
    if key['kty'] == 'EC':
        if key['crv'] in ['secp256k1', 'P-256K']:
            key['crv'] = 'secp256k1'
            return 'ES256K' 
        elif key['crv'] == 'P-256':
            return 'ES256'
        elif key['crv'] == 'P-384':
            return 'ES384'
        elif key['crv'] == 'P-521':
            return 'ES512'
        else:
            raise Exception("Curve not supported")
    elif key['kty'] == 'RSA':
        return 'RS256'
    elif key['kty'] == 'OKP':
        return 'EdDSA'
    else:
        raise Exception("Key type not supported")
    

def generate_selfsigned_cert(hostname, key=None):
    """Generates self signed certificate for a hostname, and optional IP addresses.""" 
    if not key:
        keys = json.load(open('keys.json')) 
        rsa_jwk = keys['RSA_key']
        rsa_key = jwk.JWK(**rsa_jwk)
        # export in PEM format
        pem_key = rsa_key.export_to_pem(private_key=True, password=None)
        # Load PEM key
        key = serialization.load_pem_private_key(pem_key, password=None)

    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, hostname)
    ])
 
    # best practice seem to be to include the hostname in the SAN, which *SHOULD* mean COMMON_NAME is ignored.    
    alt_names = [x509.DNSName(hostname)]
    
    san = x509.SubjectAlternativeName(alt_names)
    
    # path_len=0 means this cert can only sign itself, not other certs.
    basic_contraints = x509.BasicConstraints(ca=True, path_length=0)
    now = datetime.now()
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1000)
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=10*365))
        .add_extension(basic_contraints, False)
        .add_extension(san, False)
        .sign(key, hashes.SHA256(), default_backend())
    )
    return cert.public_bytes(encoding=serialization.Encoding.DER)


def build_x509_san_dns():
    hostname = "talao.co"
    a = generate_selfsigned_cert(hostname)
    return [base64.b64encode(a).decode()]

def build_verifier_attestation(client_id) -> str:
    """
    OIDC4VP
    """
    keys = json.load(open('keys.json')) 
    rsa_jwk = keys['RSA_key']
    rsa_key = jwk.JWK(**rsa_jwk)
    public_key = rsa_key.export(private_key=False, as_dict=True)
    if public_key.get('kid'): del public_key['kid']
    header = {
        'typ': "verifier-attestation+jwt",
        'alg': alg(rsa_key),
    }
    payload = {
        'iss': "did:web:talao.co",
        'sub': client_id,
        "cnf": {
            "jwk": public_key
        },
        'exp': datetime.timestamp(datetime.now()) + 1000,
    }
    token = jwt.JWT(header=header, claims=payload, algs=[alg(rsa_key)])
    token.make_signed_token(rsa_key)
    return token.serialize()