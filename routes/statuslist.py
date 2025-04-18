
import base64
import zlib  # https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-02.html
import gzip
from datetime import datetime
from oidc4vc import alg, get_payload_from_token  # type: ignore
import json
from jwcrypto import jwk, jwt  # type: ignore
import logging
logging.basicConfig(level=logging.INFO)
from flask import render_template, request, redirect, Response, jsonify
import copy
import random

ISSUER_KEY = json.dumps(json.load(open('keys.json', 'r'))['talao_Ed25519_private_key'])
#  ISSUER_VM = 'did:web:app.altme.io:issuer#key-1'
#  ISSUER_DID = 'did:web:app.altme.io:issuer'


def init_app(app, red, mode):
    app.add_url_rule('/sandbox/issuer/statuslist',  view_func=issuer_statuslist, methods=['GET', 'POST'], defaults={"mode": mode})
    app.add_url_rule('/issuer/statuslist',  view_func=issuer_statuslist, methods=['GET', 'POST'], defaults={"mode": mode})

    app.add_url_rule('/sandbox/issuer/statuslist/<list_id>', view_func=issuer_status_list, methods=['GET'])
    app.add_url_rule('/issuer/statuslist/<list_id>', view_func=issuer_status_list, methods=['GET'])

    app.add_url_rule('/sandbox/issuer/statuslist/api', view_func=issuer_status_list_api, methods=['POST'],  defaults={"mode": mode})

    app.add_url_rule('/sandbox/issuer/bitstringstatuslist',  view_func=issuer_bitstringstatuslist, methods=['GET', 'POST'], defaults={"mode": mode})
    app.add_url_rule('/sandbox/issuer/bitstringstatuslist/<list_id>', view_func=issuer_bitstring_status_list, methods=['GET'])

    app.add_url_rule('/sandbox/issuer/statuslist/jwks', view_func=issuer_statuslist_jwks, methods=['GET'])
    app.add_url_rule('/issuer/statuslist/jwks', view_func=issuer_statuslist_jwks, methods=['GET'])

    app.add_url_rule('/sandbox/issuer/statuslist/.well-known/openid-configuration', view_func=issuer_statuslist_openid, methods=['GET'], defaults={"mode": mode})
    app.add_url_rule('/issuer/statuslist/.well-known/openid-configuration', view_func=issuer_statuslist_openid, methods=['GET'], defaults={"mode": mode})
 
    app.add_url_rule('/sandbox/issuer/statuslist/.well-known/oauth-authorization-server', view_func=issuer_statuslist_openid, methods=['GET'], defaults={"mode": mode})
    app.add_url_rule('/issuer/statuslist/.well-known/oauth-authorization-server', view_func=issuer_statuslist_openid, methods=['GET'], defaults={"mode": mode})

    return


def thumbprint(key):
    signer_key = jwk.JWK(**key)
    return signer_key.thumbprint()


# jwks endpoint
def issuer_statuslist_jwks():
    pub_key = copy.copy(json.loads(ISSUER_KEY))
    del pub_key['d']
    pub_key['kid'] = pub_key.get('kid') if pub_key.get('kid') else thumbprint(pub_key)
    return jsonify({'keys': [pub_key]})


def issuer_statuslist_openid(mode):
    pub_key = copy.copy(json.loads(ISSUER_KEY))
    del pub_key['d']
    pub_key['kid'] = pub_key.get('kid') if pub_key.get('kid') else thumbprint(pub_key)
    jwks = {'keys': [pub_key]}
    choice_bool = random.choice([True, False])
    if choice_bool:
        config = {
            'issuer': mode.server + 'issuer/statuslist',
            "jwks_uri": mode.server + "issuer/statuslist/jwks"
        }
    else:
        config = {
            'issuer': mode.server + 'issuer/statuslist',
            "jwks": jwks
        }
    logging.info("status list config = %s", config)
    return jsonify(config)


def issuer_status_list(list_id):
    """
    GET for IETF status list
    """
    try:
        list_id = str(list_id)
        listname = "statuslist_ietf_" + list_id + ".txt"
        f = open(listname, "r")
        status_list_token = f.read()
        headers = {
            'Cache-Control': 'no-store',
            'Content-Type': 'application/statuslist+jwt'
        }
        logging.info("status list token = %s", status_list_token)
        return Response(status_list_token, headers=headers)
    except Exception:
        return jsonify("status list token not found"), 400


def issuer_bitstring_status_list(list_id):
    """
    GET for W3C bitstring status list
    """
    logging.info("request headers for bitstring statuslist = %s", list_id)
    try:
        list_id = str(list_id)
        listname = "statuslist_w3c_bitstring_" + list_id + ".txt"
        f = open(listname, "r")
        status_list_token = f.read()
        headers = {
            'Cache-Control': 'no-store',
            'Content-Type': 'application/json'
        }
        return Response(status_list_token, headers=headers)
    except Exception:
        return jsonify("bitstring status list token not found"), 400


def issuer_statuslist(mode):
    """
    UX to revoke sd-jwt with  ietf statuslist
    """
    if request.method == 'GET':
        return render_template("statuslist.html")
    else:
        index = request.form['index']
        if request.form["button"] == "active":
            update_status_list_token_file(1, int(index), False, mode)
            logging.info("active index = %s", index)
        else:
            update_status_list_token_file(1, int(index), True, mode)
            logging.info("revoke index = %s", index)
        return redirect("/issuer/statuslist")


def issuer_bitstringstatuslist(mode):
    """
    UX to revoke vc_jwt_json with w3c bitstring statuslist
    """
    if request.method == 'GET':
        return render_template("bitstringstatuslist.html")
    else:
        index = request.form['index']
        if request.form["button"] == "active":
            update_status_list_bitstring_file(1, int(index), False, mode)
            logging.info("active index = %s", index)
        else:
            update_status_list_bitstring_file(1, int(index), True, mode)
            logging.info("revoke index = %s", index)
        return redirect("/sandbox/issuer/bitstringstatuslist")


def sign_status_list_token(lst, list_id, mode):  # for sd-jwt
    """
    https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-05.html#name-status-list-token
    """
    key = json.loads(ISSUER_KEY) if isinstance(ISSUER_KEY, str) else ISSUER_KEY
    key = jwk.JWK(**key)
    kid = key.get('kid') if key.get('kid') else key.thumbprint()
    header = {
        "typ": "statuslist+jwt",
        "alg": alg(key),
        "kid": kid,
    }
    payload = {
        "iat": round(datetime.timestamp(datetime.now())),
        "status_list": {
            "bits": 1,
            "lst": lst
        },
        "sub": mode.server + "issuer/statuslist/" + list_id,
        #  "exp": round(datetime.timestamp(datetime.now())) + 365*24*60*60,
        "iss": mode.server + "issuer/statuslist",
        "ttl": 86400  # 1 day
    }
    token = jwt.JWT(header=header, claims=payload, algs=[alg(key)])
    token.make_signed_token(key)
    return token.serialize()


def sign_status_list_bitstring_credential(lst, list_id, mode):  # for sd-jwt
    key = json.loads(ISSUER_KEY) if isinstance(ISSUER_KEY, str) else ISSUER_KEY
    key = jwk.JWK(**key)
    kid = key.get('kid') if key.get('kid') else key.thumbprint()
    header = {
        "typ": "statuslist+json",
        "alg": alg(key),
        "kid":  kid,
    }
    payload = {
        "iat": round(datetime.timestamp(datetime.now())),
        "jti": mode.server + "sandbox/issuer/bitstringstatuslist/" + list_id,
        "vc": {
            "@context": [
                "https://www.w3.org/ns/credentials/v2"
            ],
            "id": mode.server + "sandbox/issuer/bitstringstatuslist/" + list_id,
            "type": ["VerifiableCredential", "BitstringStatusListCredential"],
            "issuer": mode.server + "sandbox/issuer/statuslist",
            "validFrom":  datetime.now().replace(microsecond=0).isoformat() + "Z",
            "credentialSubject": {
                "id": mode.server + "sandbox/issuer/bitstringstatuslist/" + list_id + "#list",
                "type": "BitstringStatusList",
                "statusPurpose": "revocation",
                "encodedList": lst
            }
        },
        "sub": mode.server + "sandbox/issuer/bitstringstatuslist/" + list_id,
        "exp": round(datetime.timestamp(datetime.now())) + 365*24*60*60,
        "iss": mode.server + "sandbox/issuer/statuslist",
    }
    token = jwt.JWT(header=header, claims=payload, algs=[alg(key)])
    token.make_signed_token(key)
    return token.serialize()


def set_bit(v, index, x):
    """Set the index:th bit of v to 1 if x is truthy, else to 0, and return the new value."""
    mask = 1 << index   # Compute mask, an integer with just bit 'index' set.
    v &= ~mask          # Clear the bit indicated by the mask (if x is False)
    if x:
        v |= mask         # If x was True, set the bit indicated by the mask.
    return v


def set_status_list_frame(frame, index, status, standard):
    frame = bytearray(frame)
    index_byte = int(index/8)
    index_bit = index % 8
    if standard == "w3c_bitstring":
        index_bit = 7 - index_bit
    elif standard == "ietf":
        pass
    else:
        logging.error("wrong standard")
    actual_byte = frame[index_byte]
    new_byte = set_bit(actual_byte, index_bit, status)
    frame[index_byte] = new_byte
    return frame


def issuer_status_list_api(mode):
    """
    @status = "suspended" to suspend or revoke
    curl -d "status=false" -d "index=1000" -H "Content-Type: application/x-www-form-urlencoded"  -H "X-Api-Key: 123456" -X POST http://192.168.0.20:3000/sandbox/issuer/statuslist/api
    curl -d "status=suspended" -d "index=5320" -H "Content-Type: application/x-www-form-urlencoded"  -H "X-Api-Key: 123456" -X POST https://talao.co/sandbox/issuer/statuslist/api

    """
    try:
        key = request.headers.get('X-Api-Key')
        if key != "123456":
            payload = {
                'error': 'access_denied',
                'error_description': "incorrect API KEY",
            }
            headers = {'Cache-Control': 'no-store', 'Content-Type': 'application/json'}
            return {'response': json.dumps(payload), 'status': 401, 'headers': headers}
        index = int(request.form.get('index'))
        status = request.form.get('status')
    except Exception:
        payload = {
                'error': 'invalid_request',
                'error_description': "Bad Request",
            }
        headers = {'Cache-Control': 'no-store', 'Content-Type': 'application/json'}
        return {'response': json.dumps(payload), 'status': 400, 'headers': headers}

    if status in ["suspended", "revoked"]:
        status = True
        logging.info("index %s is suspended", index)
    else:
        status = False
        logging.info("index %s is activated", index)
    if not update_status_list_token_file("1", index, status, mode):
        payload = {
                'error': 'server_error',
                'error_description': "Status list saving error",
            }
        headers = {'Cache-Control': 'no-store', 'Content-Type': 'application/json'}
        return {'response': json.dumps(payload), 'status': 500, 'headers': headers}
    return 'ok', 200



def update_status_list_token_file(list_id, index, status, mode):
    """
    status = True (bool) -> revoke
    standard ! ietf
    """
    try:
        list_id = str(list_id)
        listname = "statuslist_ietf_" + list_id + ".txt"
        f = open(listname, "r")
        status_list_token = f.read() 
        lst = get_payload_from_token(status_list_token)['status_list']['lst']
        lst += "=" * ((4 - len(lst) % 4) % 4)
        lst = base64.urlsafe_b64decode(lst)
        old_frame = zlib.decompress(lst)
        logging.info("Existing frame loaded")
    except Exception:
        old_frame = bytearray(12500)
        logging.info("New empty frame created")
    new_frame = set_status_list_frame(old_frame, index, status, "ietf")
    new_lst = generate_ietf_lst(new_frame)
    status_list_token = sign_status_list_token(new_lst, list_id, mode)
    try:
        f = open("statuslist_ietf_" + list_id + ".txt", "w")
        f.write(status_list_token)
        f.close()
        logging.info("Success to store statuslist token file")
        return True
    except Exception:
        logging.error("Failed to store ietf statuslist file")
    return


def update_status_list_bitstring_file(list_id, index, status, mode):
    """
    status = false (1)
    standard ! w3c_bitstring
    """
    try:
        list_id = str(list_id)
        listname = "statuslist_w3c_bitstring_" + list_id + ".txt"
        f = open(listname, "r")
        status_list_token = f.read()
        lst = get_payload_from_token(status_list_token)['vc']['credentialSubject']["encodedList"]
        lst += "=" * ((4 - len(lst) % 4) % 4)
        lst = base64.urlsafe_b64decode(lst)
        old_frame = gzip.decompress(lst)
        logging.info("Existing frame loaded")
    except Exception:
        old_frame = bytearray(16384)
        logging.info("New empty frame created")
    new_frame = set_status_list_frame(old_frame, index, status, "w3c_bitstring")
    new_lst = generate_w3c_bitstring_lst(new_frame)
    status_list_token = sign_status_list_bitstring_credential(new_lst, list_id,  mode)
    try:
        f = open("statuslist_w3c_bitstring_" + list_id + ".txt", "w")
        f.write(status_list_token)
        f.close()
        logging.info("Success to store bitstring statuslist token file")
        return True
    except Exception:
        logging.info("Failed to store bitstring statuslist file")
    return


def generate_ietf_lst(frame):
    compressed = zlib.compress(frame, level=9)
    c = base64.urlsafe_b64encode(compressed)
    return c.decode().replace("=", "")


def generate_w3c_bitstring_lst(frame):
    compressed = gzip.compress(frame, compresslevel=9)
    c = base64.urlsafe_b64encode(compressed)
    return c.decode().replace("=", "")
