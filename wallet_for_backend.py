import base64
import requests
from jwcrypto import jwk, jwt
from datetime import datetime
import uuid
import sys
import json
import copy
import math


wallet_private_key = {
    "kty": "EC",
    "d": "d_PpSCGQWWgUc1t4iLLH8bKYlYfc9Zy_M7TsfOAcbg8",
    "crv": "P-256",
    "x": "ngy44T1vxAT6Di4nr-UaM9K3Tlnz9pkoksDokKFkmNc",
    "y": "QCRfOKlSM31GTkb4JHx3nXB4G_jSPMsbdjzlkT_UpPc",
    "alg": "ES256",
}
wallet_pub_key = copy.copy(wallet_private_key)
del wallet_pub_key['d']


# TO BE DEFINED
wallet_provider = 'https://preprod-wallet-provider.talao.co'
login = "guest@Test3-1"
password = "guest"

def get_payload_from_token(token) -> dict:
    """
    For verifier
    check the signature and return None if failed
    """
    payload = token.split('.')[1]
    payload += "=" * ((4 - len(payload) % 4) % 4) # solve the padding issue of the base64 python lib
    return json.loads(base64.urlsafe_b64decode(payload).decode())


def thumbprint(key):
    signer_key = jwk.JWK(**key) 
    return signer_key.thumbprint()


kid = iss = thumbprint(wallet_pub_key)

def sign_jwt(iss, kid, issuer_key, nonce, payload, typ, aud=None):
    signer_key = jwk.JWK(**issuer_key) 
    header = {
        'typ':typ,
        'kid': kid,
        'alg': 'ES256'
    }
    data = {
        'iss': iss,
        'nonce': nonce,
        'iat': datetime.timestamp(datetime.now().replace(second=0, microsecond=0)),
        "exp": datetime.timestamp(datetime.now().replace(second=0, microsecond=0)) + 60,
        'jti': str(uuid.uuid1()),
    }
    data.update(payload)
    if aud: data['aud'] = aud
    token = jwt.JWT(header=header, claims=data, algs=['ES256'])
    token.make_signed_token(signer_key)
    return token.serialize()


nonce_endpoint = wallet_provider + '/nonce'
token_endpoint = wallet_provider + '/token'
configuration_endpoint = wallet_provider + '/configuration'
update_endpoint = wallet_provider + '/update'
sign_endpoint = wallet_provider + '/sign'


def get_wallet_attestation():
    # nonce request
    try:
        nonce = requests.get(nonce_endpoint).json()['nonce']
    except Exception:
        print('Wallet provider portal is not available')
        sys.exit()

    # wallet attestation request with assertion
    typ = "wiar+jwt"
    payload = {"cnf": {"jwk" : wallet_pub_key}}
    aud = "https://wallet-provider.talao.co"
    assertion = sign_jwt(iss, kid, wallet_private_key, nonce, payload, typ, aud=aud)
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    data = {
        "grant_type" : 'urn:ietf:params:oauth:grant-type:jwt-bearer',
        "assertion" : assertion,
    }
    resp = requests.post(token_endpoint, headers=headers, data = data)
    wallet_attestation = resp.content.decode()
    wallet_attestation_json = get_payload_from_token(resp.content.decode())

    print("wallet attestation json type = ", type(wallet_attestation_json))
    f = open("wallet_attestation.json", 'w')
    f.write(json.dumps(wallet_attestation_json))
    f.close()

    g = open("wallet_attestation.txt", 'w')
    g.write(wallet_attestation)
    g.close()
    return


def get_wallet_configuration():
    f = open("wallet_attestation.txt")
    wallet_attestation = f.read()
    # wallet configuration request with assertion and login:password as basic auth
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    data = {
        "grant_type" : 'urn:ietf:params:oauth:grant-type:jwt-bearer',
        "assertion" : wallet_attestation,
    }
    resp = requests.post(configuration_endpoint, auth=(login, password), headers=headers, data=data)
    if resp.status_code > 299:
        sys.exit()
    payload = get_payload_from_token(resp.content.decode())
    
    print("type wallet configuration = ", type(payload))
    f = open("wallet_configuration.json", 'w')
    f.write(json.dumps(payload))
    f.close()
    return


get_wallet_attestation()
get_wallet_configuration()

"""
# wallet sign request with assertion and login:password
headers = {
    'Content-Type': 'application/x-www-form-urlencoded'
}
header = {
    "typ": "JWT"
}
payload = {
    'iss': "iss_test",
    'nonce': nonce,
    'iat': math.floor(datetime.timestamp(datetime.now())),
}
data = {
    "grant_type": 'urn:ietf:params:oauth:grant-type:jwt-bearer',
    "assertion": wallet_attestation,
    "digest": "lkjmlkjmlkjmlkjkjl",
}

resp = requests.post(sign_endpoint, headers=headers, data=data)
if resp.status_code > 299:
    sys.exit()
print("\n digest signed = ", resp.content.decode())

"""



"""
# wallet update request with assertion and login:password
headers = {
    'Content-Type': 'application/x-www-form-urlencoded'
}
data = {
    "grant_type" : 'urn:ietf:params:oauth:grant-type:jwt-bearer',
    "assertion": wallet_attestation,
}
resp = requests.post(update_endpoint, auth=(login, password), headers=headers, data=data)

print(" ")
print("wallet update = ", resp.content.decode())

"""