import requests
from jwcrypto import jwk, jwt
import base64
import base58
import json
from datetime import datetime
import logging
import math
import hashlib
from random import randbytes
import x509_attestation
logging.basicConfig(level=logging.INFO)

"""
https://ec.europa.eu/digital-building-blocks/wikis/display/EBSIDOC/EBSI+DID+Method
VC/VP https://ec.europa.eu/digital-building-blocks/wikis/display/EBSIDOC/E-signing+and+e-sealing+Verifiable+Credentials+and+Verifiable+Presentations
DIDS method https://ec.europa.eu/digital-building-blocks/wikis/display/EBSIDOC/EBSI+DID+Method
supported signature: https://ec.europa.eu/digital-building-blocks/wikis/display/EBSIDOC/E-signing+and+e-sealing+Verifiable+Credentials+and+Verifiable+Presentations

"""


#issuer_did = 'did:jwk:' + base64.urlsafe_b64encode(json.dumps(issuer_public_key).replace(" ", "").encode()).decode()



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


def resolve_wallet_did_ebsi_v3(did) -> str:
    a = did.split('did:key:z')[1]
    b = base58.b58decode(a.encode())
    try:
        return b.split(b'\xd1\xd6\x03')[1].decode()
    except Exception:
        return


def generate_wallet_did_ebsiv3(key):
    # json string, remove space, alphabetical ordered 
    if isinstance(key, str):
        key = json.loads(pub_key)
    if key["kty"] == "EC":
        jwk = {
            "crv": key["crv"], # seckp256k1 or P-256 
            "kty": "EC",
            "x": key["x"],
            "y": key["y"]
        }
    elif key["kty"] == "OKP":
        jwk = {
            "crv": "Ed25519", # pub_key["crv"], # Ed25519
            "kty": "OKP",
            "x": key["x"]
        }
    else:
        logging.error("Curve not supported")
        return
    data = json.dumps(jwk).replace(" ", "").encode()
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
        'typ':'JWT',
        'kid': kid,
        'alg': alg(issuer_key)
    }

    payload = {
        'iss': iss,
        'nonce': nonce,
        'iat': math.floor(datetime.timestamp(datetime.now())),
        'nbf': math.floor(datetime.timestamp(datetime.now())),
        'exp': math.floor(datetime.timestamp(datetime.now())) + 365*24*60*60, 
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
        "typ":"JWT",
        "alg": alg(holder_key),
        "kid": holder_vm,
        "jwk": pub_key(holder_key),
    }
    iat = round(datetime.timestamp(datetime.now()))
    payload = {
        "iat": iat,
        "jti": vp_id,
        "nbf": iat,
        "aud": audience,
        "exp": iat + 1000,
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


def sign_sd_jwt(unsecured, issuer_key, issuer, subject_key, duration=365*24*60*60, x5c=False):
    """
    https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-01.html
    GAIN POC https://gist.github.com/javereec/48007399d9876d71f523145da307a7a3
    HAIP : https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-sd-jwt-vc-1_0-00.html
    """
    issuer_key = json.loads(issuer_key) if isinstance(issuer_key, str) else issuer_key
    subject_key = json.loads(subject_key) if isinstance(subject_key, str) else subject_key
    payload = {
        'iss': issuer,
        'iat': math.ceil(datetime.timestamp(datetime.now())),
        'exp': math.ceil(datetime.timestamp(datetime.now())) + duration,
        "_sd_alg": "sha-256",
        "cnf": {
            "jwk": subject_key
        },
    }
    payload['_sd'] = []
    _disclosure = ""
    disclosure_list = unsecured.get("disclosure", [])
    if not disclosure_list:
        logging.warning("disclosure is missing in sd-jwt")
    for claim in [attribute for attribute in unsecured.keys()]:
        if claim == "disclosure":
            pass
        # for attribute to disclose
        elif claim in disclosure_list:
            payload[claim] = unsecured[claim]
        # for undisclosed attribute
        elif isinstance(unsecured[claim], str) or  isinstance(unsecured[claim], bool) :
            contents = json.dumps([salt(), claim, unsecured[claim]])
            disclosure = base64.urlsafe_b64encode(contents.encode()).decode().replace("=", "")
            _disclosure += "~" + disclosure 
            payload['_sd'].append(hash(disclosure))
        # for nested json
        elif isinstance(unsecured[claim], dict):
            payload.update({claim: {'_sd': []}})
            nested_disclosure_list = unsecured[claim].get("disclosure", [])
            if not nested_disclosure_list:
                logging.warning("disclosure is missing for %s", claim)
            for nested_claim in [attribute for attribute in unsecured[claim].keys()]:
                if nested_claim == 'disclosure':
                    pass
                elif nested_claim in nested_disclosure_list:
                    payload[claim][nested_claim] = unsecured[claim][nested_claim]
                else:
                    nested_contents = json.dumps([salt(), nested_claim, unsecured[claim][nested_claim]])
                    nested_disclosure = base64.urlsafe_b64encode(nested_contents.encode()).decode().replace("=", "")
                    _disclosure += "~" + nested_disclosure 
                    payload[claim]['_sd'].append(hash(nested_disclosure))
            if not payload[claim]['_sd']: del payload[claim]['_sd']
        # for list
        elif isinstance(unsecured[claim], list): # list
            nb = len(unsecured[claim])
            payload.update({claim: []})
            for index in range(0, nb):
                if isinstance(unsecured[claim][index], dict):
                    nested_disclosure_list = unsecured[claim][index].get("disclosure", [])
                    if not nested_disclosure_list:
                        logging.warning("disclosure is missing for %s", claim)
                else:
                    nested_disclosure_list = []
            for index in range(0,nb):
                if isinstance(unsecured[claim][index], dict):
                    pass
                elif unsecured[claim][index] in nested_disclosure_list:
                    payload[claim].append(unsecured[claim][index])
                else:
                    contents = json.dumps([salt(), unsecured[claim][index]])
                    nested_disclosure = base64.urlsafe_b64encode(contents.encode()).decode().replace("=", "")
                    _disclosure += "~" + nested_disclosure 
                    payload[claim].append({"..." : hash(nested_disclosure)})
        else:
            logging.warning("type not supported")
    logging.info("sd-jwt payload = %s", payload)
    signer_key = jwk.JWK(**issuer_key)
    kid = issuer_key.get('kid') if issuer_key.get('kid') else signer_key.thumbprint()
    header = {
        'typ': "vc+sd-jwt",
        'alg': alg(issuer_key)
    }
    if x5c:
        header['x5c'] = x509_attestation.build_x509_san_dns(hostname=issuer)
    else:
        header['kid'] = kid
    try:
        if subject_key.get("use"): del subject_key['use']
    except:
        logging.error("error, subject_key = none")
    if unsecured.get('status'): payload['status'] = unsecured['status']
    token = jwt.JWT(header=header, claims=payload, algs=[alg(issuer_key)])
    token.make_signed_token(signer_key)
    return token.serialize() + _disclosure + "~"


def build_pre_authorized_code(key, wallet_did, issuer_did, issuer_vm, nonce):
    key = json.loads(key) if isinstance(key, str) else key
    key = jwk.JWK(**key) 
    header = {
        "typ":"JWT",
        "alg": alg(key),
        "kid": issuer_vm,
    }
    payload = {
        "iat": round(datetime.timestamp(datetime.now())),
        "client_id": wallet_did,
        "aud": issuer_did,
        "exp": round(datetime.timestamp(datetime.now())) + 1000,
        "sub": wallet_did,
        "iss": issuer_did,
        "nonce": nonce
    }
    token = jwt.JWT(header=header, claims=payload, algs=[alg(key)])
    token.make_signed_token(key)
    return token.serialize()


def resolve_did(vm) -> dict:
    logging.info('vm = %s', vm)
    did = vm.split('#')[0]
    # try did for ebsi v3
    try:
        jwk = resolve_wallet_did_ebsi_v3(did)
    except Exception:
        jwk = None
    if jwk:
        logging.info('wallet jwk EBSI-V3= %s', jwk)
        return json.loads(jwk)
    elif did.split(':')[1] == "jwk":
        key = did.split(':')[2]
        key += "=" * ((4 - len(key) % 4) % 4)
        return json.loads(base64.urlsafe_b64decode(key))
    elif did.split(':')[1] == "web":
        logging.info("did:web")
        did_document = resolve_did_web(did)
        for verificationMethod in did_document:
            if vm == verificationMethod['id'] or '#' + vm.split('#')[1] == verificationMethod['id']:
                jwk = verificationMethod.get('publicKeyJwk')
                logging.info('wallet jwk = %s', jwk)
                return jwk
    else:
        url = 'https://unires:test@unires.talao.co/1.0/identifiers/' + did
        try:
            r = requests.get(url, timeout=5)
            logging.info('Access to Talao Universal Resolver')
        except Exception:
            logging.error('cannot access to Talao Universal Resolver for %s', vm)
            url = 'https://dev.uniresolver.io/1.0/identifiers/' + did
            try:
                r = requests.get(url, timeout=5)
                logging.info('Access to Public Universal Resolver')
            except Exception:
                logging.warning('fails to access to both universal resolver')
                return
        did_document = r.json()
        for verificationMethod in did_document['didDocument']['verificationMethod']:
            if vm == verificationMethod['id'] or '#' + vm.split('#')[1] == verificationMethod['id']:
                jwk = verificationMethod.get('publicKeyJwk')
                if not jwk:
                    publicKeyBase58 = verificationMethod.get('publicKeyBase58')
                    logging.info('wallet publiccKeyBase48 = %s', publicKeyBase58)
                    return publicKeyBase58
                else:  
                    logging.info('wallet jwk = %s', jwk)
                    return jwk


def verif_token(token, nonce, aud=None):
    """
    For issuer 
    raise exception if problem
    https://jwcrypto.readthedocs.io/en/latest/jwt.html#jwcrypto.jwt.JWT.validate
    """
    header = get_header_from_token(token)
    payload = get_payload_from_token(token)
    if nonce and payload.get('nonce') != nonce:
        raise Exception("nonce is incorrect")
    if aud and payload.get('aud') != aud:
        raise Exception("aud is incorrect")
    if header.get('jwk'):
        if isinstance(header['jwk'], str):
            header['jwk'] = json.loads(header['jwk'])
        dict_key = header['jwk']
    elif header.get('kid'):
        dict_key = resolve_did(header['kid'])
        if not dict_key:
            raise Exception("Cannot get public key with kid")
    elif payload.get('sub_jwk'):
        dict_key = payload['sub_jwk']
    else:
        raise Exception("Cannot resolve public key")
    a = jwt.JWT.from_jose_token(token)
    issuer_key = jwk.JWK(**dict_key)
    a.validate(issuer_key)
    return True


def get_payload_from_token(token) -> dict:
    payload = token.split('.')[1]
    payload += "=" * ((4 - len(payload) % 4) % 4) # solve the padding issue of the base64 python lib
    return json.loads(base64.urlsafe_b64decode(payload).decode())


def get_header_from_token(token):
    header = token.split('.')[0]
    header += "=" * ((4 - len(header) % 4) % 4) # solve the padding issue of the base64 python lib
    return json.loads(base64.urlsafe_b64decode(header).decode())


def build_proof_of_key_ownership(key, kid, aud, signer_did, nonce, jwk=False):
    key = json.loads(key) if isinstance(key, str) else key
    signer_key = jwk.JWK(**key) 
    header = {
        'typ': 'openid4vci-proof+jwt',
        'alg': alg(key),
    }
    if jwk:
        header['jwk'] = signer_key.export(private_key=False, as_dict=True)
    else:
        header['kid'] = kid
    payload = {
        'iss': signer_did,  # client id of the clent making the credential request
        'nonce': nonce,
        'iat': datetime.timestamp(datetime.now()),
        'aud': aud  # Credential Issuer URL
    }  
    token = jwt.JWT(header=header, claims=payload, algs=[alg(key)])
    token.make_signed_token(signer_key)
    return token.serialize()


def thumbprint(key):
    key = json.loads(key) if isinstance(key, str) else key
    if key['crv'] == 'P-256K':
        key['crv'] = 'secp256k1'
    signer_key = jwk.JWK(**key) 
    a = signer_key.thumbprint()
    a  += "=" * ((4 - len(a) % 4) % 4) 
    return base64.urlsafe_b64decode(a).hex()


def thumbprint_str(key):
    key = json.loads(key) if isinstance(key, str) else key
    if key['crv'] == 'P-256K':
        key['crv'] = 'secp256k1'
    signer_key = jwk.JWK(**key) 
    return signer_key.thumbprint()
    

def verification_method(did, key):  # = kid
    key = json.loads(key) if isinstance(key, str) else key
    signer_key = jwk.JWK(**key) 
    thumb_print = signer_key.thumbprint()
    return did + '#' + thumb_print


def resolve_did_web(did) -> str:
    """
    get DID document for the did:web
    """
    if did.split(':')[1] != 'web':
        return
    url = 'https://' + did.split(':')[2] 
    i = 3
    try:
        while did.split(':')[i]:
            url = url + '/' +  did.split(':')[i]
            i += 1
    except Exception:
        pass
    url = url + '/did.json'
    r = requests.get(url)
    if 399 < r.status_code < 500:
        logging.warning('return API code = %s', r.status_code)
        return "{'error': 'did:web not found on server'}"
    return r.json()


def did_resolve_lp(did):
    #for legal person  did:ebsi and did:web
    #API v3   Get DID document with EBSI API
    #https://api-pilot.ebsi.eu/docs/apis/did-registry/latest#/operations/get-did-registry-v3-identifier
    if did.split(':')[1] == 'ebsi':
        url = 'https://api-pilot.ebsi.eu/did-registry/v3/identifiers/' + did
        try:
            r = requests.get(url)
        except Exception:
            logging.error('cannot access to EBSI API')
            return "{'error': 'cannot access to EBSI registry'}"
        logging.info("DID Document = %s", r.json())
        return r.json()
    else:
        url = 'https://unires:test@unires.talao.co/1.0/identifiers/' + did
    try:
        r = requests.get(url, timeout=10)
        logging.info('Access to Talao Universal Resolver')
    except Exception:
        logging.error('cannot access to Talao Universal Resolver API')
        return "{'error': 'cannot access to Talao Universal Resolver API'}"
    logging.info("DID Document = %s", r.json())
    return r.json().get('didDocument')


def get_issuer_registry_data(did):
    """
    API v3
    https://api-pilot.ebsi.eu/docs/apis/trusted-issuers-registry/latest#/operations/get-trusted-issuers-registry-v3-issuers-issuer
    """
    try:
        url = 'https://api-pilot.ebsi.eu/trusted-issuers-registry/v3/issuers/' + did
        r = requests.get(url) 
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
