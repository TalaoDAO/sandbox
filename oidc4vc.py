import requests
from jwcrypto import jwk, jwt
import base58  # type: ignore
import json
from datetime import datetime, timezone
import logging
import hashlib
from random import randbytes
import x509_attestation
import copy
logging.basicConfig(level=logging.INFO)
import base64
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, padding
from typing import Any, Dict

"""
https://ec.europa.eu/digital-building-blocks/wikis/display/EBSIDOC/EBSI+DID+Method
VC/VP https://ec.europa.eu/digital-building-blocks/wikis/display/EBSIDOC/E-signing+and+e-sealing+Verifiable+Credentials+and+Verifiable+Presentations
DIDS method https://ec.europa.eu/digital-building-blocks/wikis/display/EBSIDOC/EBSI+DID+Method
supported signature: https://ec.europa.eu/digital-building-blocks/wikis/display/EBSIDOC/E-signing+and+e-sealing+Verifiable+Credentials+and+Verifiable+Presentations

"""


RESOLVER_LIST = [
    'https://unires:test@unires.talao.co/1.0/identifiers/',
    'https://dev.uniresolver.io/1.0/identifiers/',
    'https://resolver.cheqd.net/1.0/identifiers/'
]

def generate_key(curve):
    """
alg value https://www.rfc-editor.org/rfc/rfc7518#page-6

+--------------+-------------------------------+--------------------+
| "alg" Param  | Digital Signature or MAC      | Implementation     |
| Value        | Algorithm                     | Requirements       |
+--------------+-------------------------------+--------------------+
| RS256        | RSASSA-PKCS1-v1_5 using       | Recommended        |
|              | SHA-256                       |                    |
| RS384        | RSASSA-PKCS1-v1_5 using       | Optional           |
|              | SHA-384                       |                    |
| RS512        | RSASSA-PKCS1-v1_5 using       | Optional           |
|              | SHA-512                       |                    |
| ES256        | ECDSA using P-256 and SHA-256 | Recommended+       |
| ES384        | ECDSA using P-384 and SHA-384 | Optional           |
| ES512        | ECDSA using P-521 and SHA-512 | Optional           |
+--------------+-------------------------------+--------------------+
    """

    if curve in ['P-256', 'P-384', 'P-521', 'secp256k1']:
        key = jwk.JWK.generate(kty='EC', crv=curve)
    elif curve == 'RSA':
        key = jwk.JWK.generate(kty='RSA', size=2048)
    else:
        raise Exception("Curve not supported")
    return json.loads(key.export(private_key=True))

def alg(key) -> str:
    """
    Return the JOSE 'alg' for a given JWK.
    Accepts:
      - dict JWK
      - JSON string containing a JWK
      - jwcrypto.jwk.JWK instance
    """
    # Normalize input type
    if hasattr(key, "export") and callable(getattr(key, "export")):
        # jwcrypto.jwk.JWK -> dict
        key_dict = key.export(as_dict=True)
    elif isinstance(key, str):
        key_dict = json.loads(key)
    elif isinstance(key, dict):
        key_dict = key
    else:
        raise TypeError(f"Unsupported key type: {type(key).__name__}")

    kty = key_dict.get("kty")
    if not kty:
        raise ValueError("Missing 'kty' in JWK")

    if kty == "EC":
        crv = key_dict.get("crv")
        if not crv:
            raise ValueError("Missing 'crv' in EC JWK")

        # Normalize common aliases without mutating input
        crv_norm = {
            "P-256K": "secp256k1",
            "secp256k1": "secp256k1",
            "P-256": "P-256",
            "P-384": "P-384",
            "P-521": "P-521",
        }.get(crv)

        if crv_norm == "secp256k1":
            return "ES256K"
        if crv_norm == "P-256":
            return "ES256"
        if crv_norm == "P-384":
            return "ES384"
        if crv_norm == "P-521":
            return "ES512"

        raise ValueError(f"Unsupported EC curve: {crv}")

    if kty == "RSA":
        return "RS256"

    if kty == "OKP":
        crv = key_dict.get("crv")
        if not crv:
            raise ValueError("Missing 'crv' in OKP JWK")
        if crv == "Ed25519":
            return "EdDSA"
        raise ValueError(f"Unsupported OKP curve for EdDSA: {crv}")

    raise ValueError(f"Unsupported JWK kty: {kty}")


def generate_wallet_did_ebsiv3(key):
    # json string, remove space, alphabetical ordered
    if isinstance(key, str):
        key = json.loads(key)
    if key["kty"] == "EC":
        jwk = {
            "crv": key["crv"],  # seckp256k1 or P-256 
            "kty": "EC",
            "x": key["x"],
            "y": key["y"]
        }
    elif key["kty"] == "OKP":
        jwk = {
            "crv": "Ed25519",  # pub_key["crv"], # Ed25519
            "kty": "OKP",
            "x": key["x"]
        }
    else:
        logging.error("Curve not supported")
        return
    data = json.dumps(jwk, separators=(",", ":"), sort_keys=True).encode("utf-8")
    prefix = b'\xd1\xd6\x03'
    return "did:key:z" + base58.b58encode(prefix + data).decode()


def pub_key(key):
    key = json.loads(key) if isinstance(key, str) else key
    Key = jwk.JWK(**key) 
    return Key.export_public(as_dict=True)
    

def sign_jwt_vc(vc, kid, issuer_key, nonce, iss, jti, sub):
    """
    For issuer
    https://jwcrypto.readthedocs.io/en/latest/jwk.html
    https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims

    """
    issuer_key = json.loads(issuer_key) if isinstance(issuer_key, str) else issuer_key
    vc = json.loads(vc) if isinstance(vc, str) else vc
    signer_key = jwk.JWK(**issuer_key) 
    header = {
        'typ': 'JWT',
        'kid': kid,
        'alg': alg(issuer_key)
    }
    
    now = int(datetime.now(timezone.utc).timestamp())

    payload = {
        'iss': iss,
        'nonce': nonce,
        'iat': now,
        'nbf': now,
        'exp': now + 365*24*60*60, 
        'jti': jti
    }
    if sub:
        payload['sub'] = sub
    payload['vc'] = vc
    token = jwt.JWT(header=header, claims=payload, algs=[alg(issuer_key)])
    token.make_signed_token(signer_key)
    a = jwt.JWT.from_jose_token(token.serialize())
    verif_key = jwk.JWK(**issuer_key)
    a.validate(verif_key)
    logging.info("payload VC = %s", json.dumps(payload, indent=4))
    return token.serialize()


def sign_jwt_vp(vc, audience, holder_vm, holder_did, nonce, vp_id, holder_key):
    """
    For Wallet
    Build and sign verifiable presentation as vp_token
    Ascii is by default in the json string 
    """
    holder_key = json.loads(holder_key) if isinstance(holder_key, str) else holder_key
    signer_key = jwk.JWK(**holder_key) 
    header = {
        "typ": "JWT",
        "alg": alg(holder_key),
        "kid": holder_vm,
        "jwk": pub_key(holder_key),
    }
    now = int(datetime.now(timezone.utc).timestamp())
    payload = {
        #  "iat": iat,
        "jti": vp_id,
        "nbf": now,
        "aud": audience,
        "exp": now + 1000,
        "sub": holder_did,
        "iss": holder_did,
        "vp": {
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "id": vp_id,
            "type": ["VerifiablePresentation"],
            "holder": holder_did,
            "verifiableCredential": [vc]
        },
        "nonce": nonce
    }
    token = jwt.JWT(header=header, claims=payload, algs=[alg(holder_key)])
    token.make_signed_token(signer_key)
    return token.serialize()


def salt():
    return base64.urlsafe_b64encode(randbytes(16)).decode().replace("=", "")


def hash(text):
    m = hashlib.sha256()
    m.update(text.encode())
    return base64.urlsafe_b64encode(m.digest()).decode().replace("=", "")


def sd(data):
    unsecured = copy.deepcopy(data)
    payload = {'_sd': []}
    disclosed_claims = ['status', 'status_list', 'idx', 'uri', 'vct', 'iat', 'nbf', 'aud', 'iss', 'exp', '_sd_alg', 'cnf', 'vct#integrity']
    _disclosure = ""
    disclosure_list = unsecured.get("disclosure", [])
    for claim in [attribute for attribute in unsecured.keys()]:
        if claim == "disclosure":
            pass
        # for undisclosed attribute
        elif isinstance(unsecured[claim], (str, bool, int)) or claim in ["status", "status_list"]:
            if claim in disclosure_list or claim in disclosed_claims :
                payload[claim] = unsecured[claim]
            else:
                contents = json.dumps([salt(), claim, unsecured[claim]])
                disclosure = base64.urlsafe_b64encode(contents.encode()).decode().replace("=", "")
                if disclosure:
                    _disclosure += "~" + disclosure
                payload['_sd'].append(hash(disclosure))
        # for nested json
        elif isinstance(unsecured[claim], dict):
            if claim in disclosure_list or claim in disclosed_claims:
                payload[claim], disclosure = sd(unsecured[claim])
                if disclosure:
                    _disclosure += "~" + disclosure
            else:
                nested_content, nested_disclosure = sd(unsecured[claim])
                contents = json.dumps([salt(), claim, nested_content])
                if nested_disclosure:
                    _disclosure += "~" + nested_disclosure
                disclosure = base64.urlsafe_b64encode(contents.encode()).decode().replace("=", "")
                if disclosure:
                    _disclosure += "~" + disclosure
                payload['_sd'].append(hash(disclosure))
        # for list
        elif isinstance(unsecured[claim], list):  # list
            if claim in disclosure_list or claim in disclosed_claims:
                payload[claim] = unsecured[claim]
            else:
                nb = len(unsecured[claim])
                payload.update({claim: []})
                for index in range(0, nb):
                    if isinstance(unsecured[claim][index], dict):
                        nested_disclosure_list = unsecured[claim][index].get("disclosure", [])
                        if not nested_disclosure_list:
                            logging.warning("disclosure is missing for %s", claim)
                    else:
                        nested_disclosure_list = []
                for index in range(0, nb):
                    if isinstance(unsecured[claim][index], dict):
                        pass  # TODO
                    elif unsecured[claim][index] in nested_disclosure_list:
                        payload[claim].append(unsecured[claim][index])
                    else:
                        contents = json.dumps([salt(), unsecured[claim][index]])
                        nested_disclosure = base64.urlsafe_b64encode(contents.encode()).decode().replace("=", "")
                        if nested_disclosure:
                            _disclosure += "~" + nested_disclosure
                        payload[claim].append({"...": hash(nested_disclosure)})
        else:
            logging.warning("type not supported")
    if payload.get('_sd'):
        # add 1 fake digest
        contents = json.dumps([salt(), "decoy", "decoy"])
        disclosure = base64.urlsafe_b64encode(contents.encode()).decode().replace("=", "")
        payload['_sd'].append(hash(disclosure))
    else:
        payload.pop("_sd", None)
    _disclosure = _disclosure.replace("~~", "~")
    return payload, _disclosure


def sign_sd_jwt(unsecured, issuer_key, issuer, subject_key, wallet_did, wallet_identifier, kid, duration=365*24*60*60, x5c=False, draft=13):
    issuer_key = json.loads(issuer_key) if isinstance(issuer_key, str) else issuer_key
    if x5c:
        with open('keys.json') as f:
            keys = json.load(f)
        issuer_key = keys['issuer_key']
        issuer = "https://talao.co" 

    subject_key = json.loads(subject_key) if isinstance(subject_key, str) else subject_key
    now = int(datetime.now(timezone.utc).timestamp())
    payload = {
        'iss': issuer,
        'iat': now,
        'exp': now + duration,
        "_sd_alg": "sha-256",
    }
    
    if wallet_identifier == "jwk_thumbprint" or "jwk_thumbprint" in wallet_identifier:
        payload['cnf'] = {"jwk": subject_key}
    else:
        payload['cnf'] = {"kid": wallet_did}
    
    # Calculate selective disclosure 
    if unsecured and "all" in unsecured.get("disclosure", []):
        _payload = unsecured
        _payload.pop("disclosure")
        _disclosure = ""
    else:
        _payload, _disclosure = sd(unsecured)
    
    # update payload with selective disclosure
    payload.update(_payload)
    if not payload.get("_sd"):
        logging.info("no _sd present")
        payload.pop("_sd_alg", None)
    logging.info("sd-jwt payload = %s", json.dumps(payload, indent=4))
    
    signer_key = jwk.JWK(**issuer_key)
    
    # build header
    header = { 'alg': alg(issuer_key)}
    if draft >= 15:
        header['typ'] = "dc+sd-jwt"
    else:
        header['typ'] = "vc+sd-jwt"
    if x5c:
        logging.info("x509 certificates are added")
        header['x5c'] = x509_attestation.build_x509_san_dns()
    else:
        header['kid'] = kid
    
    # clean subject key jwk
    if subject_key:
        subject_key.pop('use', None)
        subject_key.pop('alg', None)
    
    if unsecured.get('status'): 
        payload['status'] = unsecured['status']
    token = jwt.JWT(header=header, claims=payload, algs=[alg(issuer_key)])
    token.make_signed_token(signer_key)
    sd_token = token.serialize() + _disclosure + "~"
    return sd_token


def build_pre_authorized_code(key, wallet_did, issuer_did, issuer_vm, nonce):
    key = json.loads(key) if isinstance(key, str) else key
    key = jwk.JWK(**key) 
    header = {
        "typ": "JWT",
        "alg": alg(key),
        "kid": issuer_vm,
    }
    now = int(datetime.now(timezone.utc).timestamp())
    payload = {
        "iat": now,
        "client_id": wallet_did,
        "aud": issuer_did,
        "exp": now + 1000,
        "sub": wallet_did,
        "iss": issuer_did,
        "nonce": nonce
    }
    token = jwt.JWT(header=header, claims=payload, algs=[alg(key)])
    token.make_signed_token(key)
    return token.serialize()




def _multibase_base58btc_decode(mb: str) -> bytes:
    # did:key uses multibase; base58btc is indicated by leading "z"
    if not mb or mb[0] != "z":
        raise ValueError("Unsupported multibase (expected base58btc starting with 'z').")
    return base58.b58decode(mb[1:])


def _varint_decode(buf: bytes, offset: int = 0):
    """
    Unsigned varint decode (multicodec prefixes are varints).
    Returns (value, new_offset).
    """
    value = 0
    shift = 0
    i = offset
    while True:
        if i >= len(buf):
            raise ValueError("Truncated varint")
        b = buf[i]
        i += 1
        value |= (b & 0x7F) << shift
        if (b & 0x80) == 0:
            return value, i
        shift += 7
        if shift > 63:
            raise ValueError("Varint too long")


def _ec_point_to_jwk(curve: str, pub_bytes: bytes):
    """
    pub_bytes is a SEC1-encoded point (did:key spec uses compressed points for p256/secp256k1).
    """
    if curve == "P-256":
        pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pub_bytes)
        size = 32
    elif curve == "secp256k1":
        pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), pub_bytes)
        size = 32
    else:
        raise ValueError(f"Unsupported EC curve: {curve}")

    nums = pub.public_numbers()
    return {
        "kty": "EC",
        "crv": curve,
        "x": _b64url(nums.x.to_bytes(size, "big")),
        "y": _b64url(nums.y.to_bytes(size, "big")),
    }


def _validate_supported_jwk(jwk):
    """
    Enforce: only Ed25519, P-256, secp256k1 public keys.
    """
    if not isinstance(jwk, dict):
        raise ValueError("Invalid JWK: not an object")

    kty = jwk.get("kty")
    crv = jwk.get("crv")

    if kty == "OKP":
        if crv != "Ed25519":
            raise ValueError(f"Unsupported OKP curve: {crv}")
        if "x" not in jwk:
            raise ValueError("Invalid Ed25519 JWK: missing 'x'")
        return {"kty": "OKP", "crv": "Ed25519", "x": jwk["x"]}

    if kty == "EC":
        if crv not in ("P-256", "secp256k1"):
            raise ValueError(f"Unsupported EC curve: {crv}")
        if "x" not in jwk or "y" not in jwk:
            raise ValueError("Invalid EC JWK: missing 'x'/'y'")
        return {"kty": "EC", "crv": crv, "x": jwk["x"], "y": jwk["y"]}

    raise ValueError(f"Unsupported JWK kty: {kty}")



def resolve_did_key(did_or_kid: str):
    """
    Resolve did:key locally for:
        - Ed25519 (multicodec 0xED)
        - P-256   (multicodec 0x1200)
        - secp256k1 (multicodec 0xE7)
        - EBSI did:key profile: jwk_jcs-pub (multicodec 0xEB51)
    """
    if not did_or_kid.startswith("did:key:"):
        raise ValueError("Not a did:key identifier")

    did = did_or_kid.split("#", 1)[0]
    mb = did[len("did:key:") :]
    return public_key_multibase_to_jwk(mb)



def public_key_multibase_to_jwk(mb):
    decoded = _multibase_base58btc_decode(mb)
    multicodec_value, off = _varint_decode(decoded, 0)
    raw = decoded[off:]
    jwk: Dict[str, Any]

    # Standard did:key types
    if multicodec_value == 0xED:  # ed25519-pub
        if len(raw) != 32:
            raise ValueError(f"invalidPublicKeyLength: Ed25519 expected 32, got {len(raw)}")
        jwk = {"kty": "OKP", "crv": "Ed25519", "x": _b64url(raw)}

    elif multicodec_value == 0x1200:  # p256-pub (compressed point, 33 bytes)
        if len(raw) != 33:
            raise ValueError(f"invalidPublicKeyLength: P-256 expected 33, got {len(raw)}")
        jwk = _ec_point_to_jwk("P-256", raw)

    elif multicodec_value == 0xE7:  # secp256k1-pub (compressed point, 33 bytes)
        if len(raw) != 33:
            raise ValueError(f"invalidPublicKeyLength: secp256k1 expected 33, got {len(raw)}")
        jwk = _ec_point_to_jwk("secp256k1", raw)

    # EBSI Natural Person did:key profile:
    # multicodec public-key-type "jwk_jcs-pub" (0xEB51), raw bytes are a JCS-canonicalized public JWK JSON
    elif multicodec_value == 0xEB51:
        try:
            jwk_json = raw.decode("utf-8")
            parsed = json.loads(jwk_json)
        except Exception as e:
            raise ValueError("Invalid jwk_jcs-pub payload (expected UTF-8 JSON JWK).") from e

        jwk = _validate_supported_jwk(parsed)

    else:
        raise ValueError(f"Unsupported multicodec: 0x{multicodec_value:x}")
    return jwk



def base58_to_jwk(base58_key: str):
    key_bytes = base58.b58decode(base58_key)
    x_b64url = base64.urlsafe_b64encode(key_bytes).decode().rstrip("=")
    jwk = {
        "kty": "OKP",  # Type de clé pour Ed25519
        "crv": "Ed25519",
        "x": x_b64url
    }
    return jwk

def base58_to_jwk_secp256k1(base58_key: str):
    key_bytes = base58.b58decode(base58_key)
    pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), key_bytes)
    nums = pub.public_numbers()
    return {
        "kty": "EC",
        "crv": "secp256k1",
        "x": _b64url(nums.x.to_bytes(32, "big")),
        "y": _b64url(nums.y.to_bytes(32, "big")),
    }


def resolve_did(vm) -> dict:
    """Return public key in jwk format from Verification Method"""
    logging.info('vm = %s', vm)
    jwk = None
    did_document = None
    try:
        if not vm.startswith("did:"):
            logging.error("Not a verificationMethod  %s", vm)
            return
        did = vm.split('#')[0]
    except Exception as e:
        logging.error("This verification method is not supported  %s", vm + " " + str(e))
        return 
    if did.startswith("did:key"):
        return resolve_did_key(vm)
    
    elif did.startswith("did:jwk"):
        key = did.split(':')[2]
        key += "=" * ((4 - len(key) % 4) % 4)
        try:
            return json.loads(base64.urlsafe_b64decode(key))
        except Exception:
            logging.warning("did:jwk is not formated correctly")
            return
    else:
        for res in RESOLVER_LIST:
            url = res + did
            try:
                r = requests.get(url, timeout=10)
                if not r.ok:
                    continue
                body = r.json()
            except Exception:
                continue
            did_document = body.get("didDocument")
            if not did_document:
                logging.warning("DID Document not found for resolver = %s", res)
            else:
                break
    if not did_document:
        logging.warning("DID Document not found")
        return
    logging.info("resolver used = %s", res)
    try:
        vm_list = did_document['verificationMethod']
    except Exception:
        logging.warning("No DID Document or verification method")
        return
    for verificationMethod in vm_list:
        if verificationMethod['id'] == vm: # or (('#' + vm.split('#')[1]) == verificationMethod['id']) :
            if verificationMethod.get('publicKeyJwk'):
                jwk = verificationMethod['publicKeyJwk']
                break
            elif verificationMethod.get('publicKeyBase58'):
                if verificationMethod["type"] in ["Ed25519VerificationKey2020","Ed25519VerificationKey2018"]:
                    jwk = base58_to_jwk(verificationMethod['publicKeyBase58'])
                    break
                else:
                    jwk = base58_to_jwk_secp256k1(verificationMethod['publicKeyBase58'])
                    break
            elif verificationMethod.get("publicKeyMultibase"):
                jwk = public_key_multibase_to_jwk(verificationMethod["publicKeyMultibase"])
                break
            else:
                logging.warning("Unsupported verification method.")
                return
    return jwk


def verif_token(token: str):
    header = get_header_from_token(token)
    if x5c_list := header.get('x5c'):
        try:
            cert_der = base64.b64decode(x5c_list[0])
            cert = x509.load_der_x509_certificate(cert_der)
            public_key = cert.public_key()
            issuer_key = jwk.JWK.from_pyca(public_key)
        except Exception as e:
            raise ValueError(f"Invalid x5c certificate or public key extraction failed: {e}")

    elif header.get('jwk'):
        try:
            jwk_data = header['jwk']
            if isinstance(jwk_data, str):
                jwk_data = json.loads(jwk_data)
            issuer_key = jwk.JWK(**jwk_data)
        except Exception as e:
            raise ValueError(f"Invalid 'jwk' in header: {e}")

    elif header.get('kid'):
        dict_key = resolve_did(header['kid'])
        if not dict_key or not isinstance(dict_key, dict):
            raise ValueError(f"Unable to resolve public key from kid: {header['kid']}")
        try:
            issuer_key = jwk.JWK(**dict_key)
        except Exception as e:
            raise ValueError(f"Invalid public key structure from DID: {e}")

    else:
        raise ValueError("Header missing key info: expected 'x5c', 'jwk', or 'kid'")

    try:
        parsed_jwt = jwt.JWT.from_jose_token(token)
        parsed_jwt.validate(issuer_key)
    except Exception as e:
        raise ValueError(f"JWT signature validation failed: {e}")

    return True  # if no exceptions, verification succeeded



def get_payload_from_token(token) -> dict:
    payload = token.split('.')[1]
    payload += "=" * ((4 - len(payload) % 4) % 4)  # solve the padding issue of the base64 python lib
    try:
        return json.loads(base64.urlsafe_b64decode(payload).decode())
    except Exception as e:
        raise ValueError(f"Invalid token payload: {e}")


def get_header_from_token(token):
    header = token.split('.')[0]
    header += "=" * ((4 - len(header) % 4) % 4)  # solve the padding issue of the base64 python lib
    try:
        return json.loads(base64.urlsafe_b64decode(header).decode())
    except Exception as e:
        raise ValueError(f"Invalid token header: {e}")


def build_proof_of_key_ownership(key, kid, aud, signer_did, nonce, jwk_include=False):
    key = json.loads(key) if isinstance(key, str) else key
    signer_key = jwk.JWK(**key)
    header = {
        'typ': 'openid4vci-proof+jwt',
        'alg': alg(key),
    }
    if jwk_include:
        header['jwk'] = signer_key.export(private_key=False, as_dict=True)
    else:
        header['kid'] = kid
    now = int(datetime.now(timezone.utc).timestamp())
    payload = {
        'iss': signer_did,  # client id of the clent making the credential request
        'nonce': nonce,
        'iat': now,
        'aud': aud  # Credential Issuer URL
    }
    token = jwt.JWT(header=header, claims=payload, algs=[alg(key)])
    token.make_signed_token(signer_key)
    return token.serialize()

def thumbprint(key):
    key = json.loads(key) if isinstance(key, str) else key
    if key.get('crv') == 'P-256K':
        key['crv'] = 'secp256k1'
    signer_key = jwk.JWK(**key)
    return signer_key.thumbprint()


def verification_method(did, key):  # = kid
    key = json.loads(key) if isinstance(key, str) else key
    signer_key = jwk.JWK(**key)
    thumb_print = signer_key.thumbprint()
    return did + '#' + thumb_print



def did_resolve_lp(did):
    """
    for legal person  did:ebsi and did:web
    API v3   Get DID document with EBSI API
    https://api-pilot.ebsi.eu/docs/apis/did-registry/latest#/operations/get-did-registry-v3-identifier
    """
    url = 'https://unires:test@unires.talao.co/1.0/identifiers/' + did
    try:
        r = requests.get(url, timeout=10)
        logging.info('Access to Talao Universal Resolver')
    except Exception:
        logging.error('cannot access to Talao Universal Resolver API')
        url = 'https://dev.uniresolver.io/1.0/identifiers/' + did
        try:
            r = requests.get(url, timeout=5)
            logging.info('Access to Public Universal Resolver')
        except Exception:
            logging.warning('fails to access to both universal resolver')
            return "{'error': 'cannot access to Universal Resolver'}"
    logging.info("DID'did:key:z2dmzD81cgPx8Vki7JbuuMmFYrWPgYoytykUZ3eyqht1j9KbsEYvdrjxMjQ4tpnje9BDBTzuNDP3knn6qLZErzd4bJ5go2CChoPjd5GAH3zpFJP5fuwSk66U5Pq6EhF4nKnHzDnznEP8fX99nZGgwbAh1o7Gj1X52Tdhf7U4KTk66xsA5r#z2dmzD81cgPx8Vki7JbuuMmFYrWPgYoytykUZ3eyqht1j9KbsEYvdrjxMjQ4tpnje9BDBTzuNDP3knn6qLZErzd4bJ5go2CChoPjd5GAH3zpFJP5fuwSk66U5Pq6EhF4nKnHzDnznEP8fX99nZGgwbAh1o7Gj1X52Tdhf7U4KTk66xsA5r' Document = %s", r.json())
    return r.json().get('didDocument')


def get_issuer_registry_data(did):
    """
    API v3
    https://api-pilot.ebsi.eu/docs/apis/trusted-issuers-registry/latest#/operations/get-trusted-issuers-registry-v3-issuers-issuer
    """
    try:
        url = 'https://api-pilot.ebsi.eu/trusted-issuers-registry/v3/issuers/' + did
        r = requests.get(url, timeout=10)
    except Exception:
        logging.error('cannot access API')
        return
    if 399 < r.status_code < 500:
        logging.warning('return API code = %s', r.status_code)
        return
    try:
        body = r.json()['attributes'][0]['body']
        return base64.urlsafe_b64decode(body).decode()
    except Exception:
        logging.error('registry data in invalid format')
        return


def load_cert_from_b64(b64_der):
    der = base64.b64decode(b64_der)
    return x509.load_der_x509_certificate(der)


def verify_signature(cert, issuer_cert):
    pubkey = issuer_cert.public_key()
    try:
        if isinstance(pubkey, rsa.RSAPublicKey):
            pubkey.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm
            )
        elif isinstance(pubkey, ec.EllipticCurvePublicKey):
            pubkey.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                ec.ECDSA(cert.signature_hash_algorithm)
            )
        elif isinstance(pubkey, ed25519.Ed25519PublicKey):
            pubkey.verify(
                cert.signature,
                cert.tbs_certificate_bytes
            )
        else:
            return f"Error: Unsupported public key type: {type(pubkey)}"
        return None  # success
    except InvalidSignature:
        return "Error: Signature verification failed."
    except Exception as e:
        return f"Error: Verification failed with exception: {e}"


def verify_x5c_chain(x5c_list):
    """
    Verifies a certificate chain from the x5c header field of a JWT.
    
    Checks:
      1. Each certificate is signed by the next one in the list.
      2. Each certificate is valid at the current time.
    
    Args:
        x5c_list (List[str]): List of base64-encoded DER certificates (leaf to root).
    
    Returns:
        str: Info or error message.
    """
    if not x5c_list or len(x5c_list) < 2:
        return "Error: Insufficient certificate chain."

    try:
        certs = [load_cert_from_b64(b64cert) for b64cert in x5c_list]
    except Exception as e:
        return f"Error loading certificates: {e}"

    now = datetime.now(timezone.utc)


    for i, cert in enumerate(certs):
        if now < cert.not_valid_before_utc or now > cert.not_valid_after_utc:
            return (
                f"Error: Certificate {i} is not valid at current time:\n"
                f" - Not before: {cert.not_valid_before_utc}\n"
                f" - Not after : {cert.not_valid_after_utc}"
            )
        else:
            logging.info(f"Certificate {i} is within validity period.")

    for i in range(len(certs) - 1):
        cert = certs[i]
        issuer_cert = certs[i + 1]
        result = verify_signature(cert, issuer_cert)
        if result:
            return f"Error: Certificate {i} verification failed: {result}"
        else:
            logging.info(f"Certificate {i} is signed by certificate {i+1}.")

    return "Info: Certificate chain and validity periods are all OK."



def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def base64url_decode(input_str):
    padding = '=' * (4 - (len(input_str) % 4))
    return base64.urlsafe_b64decode(input_str + padding)


def decode_sd_jwt(sd_jwt_str):
    parts = sd_jwt_str.split("~")
    jwt_header_payload_signature = parts[0]
    disclosures = parts[1:-1]  # skip the last detached JWS if present

    # Decode JWT payload
    jwt_parts = jwt_header_payload_signature.split(".")
    payload_b64 = jwt_parts[1]
    payload_json = json.loads(base64url_decode(payload_b64).decode("utf-8"))

    # Print or collect disclosures
    revealed = {}
    for disclosure_b64 in disclosures:
        try:
            decoded = base64url_decode(disclosure_b64).decode("utf-8")
            disclosure = json.loads(decoded)
            salt, claim_name, claim_value = disclosure
            revealed[claim_name] = claim_value
        except Exception as e:
            print("Invalid disclosure:", disclosure_b64)
            print(e)

    return  revealed



    

# MAIN entry point for test
if __name__ == '__main__':
    # info release
 
    did_list = [
    "did:key:z2dmzD81cgPx8Vki7JbuuMmFYrWPgYoytykUZ3eyqht1j9KbsEYvdrjxMjQ4tpnje9BDBTzuNDP3knn6qLZErzd4bJ5go2CChoPjd5GAH3zpFJP5fuwSk66U5Pq6EhF4nKnHzDnznEP8fX99nZGgwbAh1o7Gj1X52Tdhf7U4KTk66xsA5r",
    "did:key:z6Mkf5rGMoatrSj1f4CyvuHBeXJELe9RPdzo2PKGNCKVtZxP",
    "did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme",
    "did:key:zQ3shtxV1FrJfhqE1dvxYRcCknWNjHc3c5X1y3ZSoPDi2aur2",
    "did:key:zQ3shZc2QzApp2oymGvQbzP8eKheVshBHbU4ZYjeXqwSKEn6N",
    "did:key:zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv"
    ]
  
    for did in did_list:
        print(resolve_did_key(did))
   