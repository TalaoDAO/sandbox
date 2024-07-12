
import base64
import zlib # https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-02.html
import gzip # 
from datetime import datetime
from oidc4vc import alg, get_payload_from_token
import json
from jwcrypto import jwk, jwt
import logging
logging.basicConfig(level=logging.INFO)
from flask import render_template, request, redirect, Response, jsonify
import copy

ISSUER_KEY = json.dumps(json.load(open('keys.json', 'r'))['talao_Ed25519_private_key'])
#ISSUER_VM = 'did:web:app.altme.io:issuer#key-1'
#ISSUER_DID = 'did:web:app.altme.io:issuer'


def init_app(app, red, mode):
    app.add_url_rule('/sandbox/issuer/statuslist',  view_func=issuer_statuslist, methods=['GET', 'POST'], defaults={"mode":mode})
    app.add_url_rule('/sandbox/issuer/statuslist/<list_id>', view_func=issuer_status_list, methods=['GET'])

    app.add_url_rule('/sandbox/issuer/statuslist/api', view_func=issuer_status_list_api, methods=['POST'],  defaults={"mode":mode})


    app.add_url_rule('/sandbox/issuer/bitstringstatuslist',  view_func=issuer_bitstringstatuslist, methods=['GET', 'POST'], defaults={"mode":mode})
    app.add_url_rule('/sandbox/issuer/bitstringstatuslist/<list_id>', view_func=issuer_bitstring_status_list, methods=['GET'])

    app.add_url_rule('/sandbox/issuer/statuslist/jwks', view_func=issuer_statuslist_jwks, methods=['GET'])
    app.add_url_rule('/sandbox/issuer/statuslist/.well-known/openid-configuration', view_func=issuer_statuslist_openid, methods=['GET'], defaults={"mode":mode})

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
    config = {
        'issuer': mode.server + 'sandbox/issuer/statuslist',
        "jwks_uri": mode.server + "sandbox/issuer/statuslist/jwks"
    }
    return jsonify(config)


def issuer_status_list(list_id):
    """
    GET for IETF status list
    """
    logging.info("request headers for ietf statuslist = %s", request.headers['Accept'])
    try:
        list_id = str(list_id)
        listname = "statuslist_ietf_" + list_id + ".txt"
        f = open(listname, "r")
        status_list_token = f.read() 
        headers = {
            'Cache-Control': 'no-store',
            'Content-Type': 'application/statuslist+jwt'
        }
        return Response(status_list_token, headers=headers)
    except Exception:
        return jsonify("status list token not found"), 400
    

def issuer_bitstring_status_list(list_id):
    """
    GET for W3C bitstring status list
    """
    logging.info("request headers for bitstring statuslist = %s", request.headers['Accept'])
    try:
        list_id = str(list_id)
        listname = "statuslist_w3c_bitstring_" + list_id + ".txt"
        f = open(listname, "r")
        status_list_token = f.read()
        headers = {
            'Cache-Control': 'no-store',
            'Content-Type': 'application/statuslist+jwt'
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
        return redirect("/sandbox/issuer/statuslist")


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
    key = json.loads(ISSUER_KEY) if isinstance(ISSUER_KEY, str) else ISSUER_KEY
    key = jwk.JWK(**key) 
    kid = key.get('kid') if key.get('kid') else key.thumbprint()
    header = {
        "typ":"statuslist+jwt",
        "alg": alg(key),
        "kid": kid,
    }
    payload = {
        "iat": round(datetime.timestamp(datetime.now())),
        "status_list": {
            "bits": 1,
            "lst": lst
        },
        "sub": mode.server + "sandbox/issuer/statuslist/" + list_id,
        "exp": round(datetime.timestamp(datetime.now())) + 365*24*60*60,
        "iss": mode.server + "sandbox/issuer/statuslist",
    }
    token = jwt.JWT(header=header, claims=payload, algs=[alg(key)])
    token.make_signed_token(key)
    return token.serialize()


def sign_status_list_bitstring_credential(lst, list_id, mode):  # for sd-jwt   
    key = json.loads(ISSUER_KEY) if isinstance(ISSUER_KEY, str) else ISSUER_KEY
    key = jwk.JWK(**key) 
    kid = key.get('kid') if key.get('kid') else key.thumbprint()
    header = {
        "typ":"statuslist+json",
        "alg": alg(key),
        "kid":  kid,
    }
    payload = {
        "iat": round(datetime.timestamp(datetime.now())),
        "jti": mode.server + "sandbox/issuer/bitstringstatuslist/" + list_id,
        "vc" : {
            "@context": [
                "https://www.w3.org/ns/credentials/v2"
            ],
            "id": mode.server + "sandbox/issuer/bitstringstatuslist/" + list_id,
            "type": ["VerifiableCredential", "BitstringStatusListCredential"],
            "issuer": mode.server + "/sandbox/issuer/statuslist",
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
    status = false to suspend
    curl -d "status=false" -d "index=1000" -H "Content-Type: application/x-www-form-urlencoded"  -H "Authorization: Bearer token" -X POST http://192.168.1.156:3000/sandbox/issuer/statuslist/api

    """
    try:
        bearer = request.headers.get('Authorization').split()[1]
        if bearer != "token":
            payload = {
                'error': 'Unauthorized',
                'error_description': "incorrect token",
            }
            headers = {'Cache-Control': 'no-store', 'Content-Type': 'application/json'}
            return {'response': json.dumps(payload), 'status': 404, 'headers': headers}
        index = int(request.form.get('index'))
        status = request.form.get('status')
    except Exception:
        payload = {
                'error': 'invalid_request',
                'error_description': "invalid",
            }
        headers = {'Cache-Control': 'no-store', 'Content-Type': 'application/json'}
        return {'response': json.dumps(payload), 'status': status, 'headers': headers}

    print ("index = ", index, type(index), " status =", status, type(status))
    update_status_list_token_file("1", index, status, mode)
    return "ok", 200



def update_status_list_token_file(list_id, index, status, mode):
    """
    status = false (1)
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
        logging.info("Failed to store ietf statuslist file")
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


