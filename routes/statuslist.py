
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


ISSUER_KEY = json.dumps(json.load(open('keys.json', 'r'))['talao_Ed25519_private_key'])
ISSUER_VM = 'did:web:app.altme.io:issuer#key-1'
ISSUER_DID = 'did:web:app.altme.io:issuer'


def init_app(app, red, mode):
    app.add_url_rule('/sandbox/issuer/statuslist',  view_func=issuer_statuslist, methods=['GET', 'POST'], defaults={"mode":mode})
    app.add_url_rule('/sandbox/issuer/statuslist/<list_id>', view_func=issuer_status_list, methods=['GET'])
    return


def issuer_status_list(list_id):
    print ("request headers for statuslist = ", request.headers)

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
    except:
        return jsonify("status list token not found"), 400


def issuer_statuslist(mode):
    if request.method == 'GET':
        return render_template ("statuslist.html")
    else:
        index = request.form['index']
        if request.form["button"] == "active":
            update_status_list_token_file(1, int(index), True, 'ietf', mode)
            logging.info("active index = %s", index)
        else:
            update_status_list_token_file(1, int(index), False, 'ietf', mode)
            logging.info("revoke index = %s", index)
        return redirect ("/sandbox/issuer/statuslist")


def sign_status_list_token(lst, mode):  # for sd-jwt   
    key = json.loads(ISSUER_KEY) if isinstance(ISSUER_KEY, str) else ISSUER_KEY
    key = jwk.JWK(**key) 
    header = {
        "typ":"statuslist+jwt",
        "alg": alg(key),
        "kid": ISSUER_VM,
    }
    payload = {
        "iat": round(datetime.timestamp(datetime.now())),
        "status_list": {
            "bits": 1,
            "lst": lst
        },
        "sub": mode.server + "sandbox/issuer/statuslist/1",
        "exp": round(datetime.timestamp(datetime.now())) + 365*24*60*60,
        "iss": ISSUER_DID,
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
    if standard == "w3c":
        index_bit = 7 - index_bit
    actual_byte = frame[index_byte]
    new_byte = set_bit(actual_byte, index_bit, status)
    frame[index_byte] = new_byte
    return frame


def update_status_list_token_file(list_id, index, status, standard, mode):
    """
    status = false (1)
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
    except:
        old_frame = bytearray(12500)
        logging.info("New empty frame created")
    new_frame = set_status_list_frame(old_frame, index, status, standard)
    new_lst = generate_ietf_lst(new_frame)
    status_list_token = sign_status_list_token(new_lst, mode)
    try :
        f = open("statuslist_ietf_1.txt", "w")
        f.write(status_list_token)
        f.close()
        logging.info("Success to store statuslist token file")
        return True
    except:
       logging.info("Failed to store statuslist file")
       return


def generate_ietf_lst(frame):
    compressed = zlib.compress(frame, level=9)
    c = base64.urlsafe_b64encode(compressed)
    return c.decode().replace("=", "")

"""
def generate_w3c_lst(frame):
    compressed = gzip.compress(frame, level=9)
    c = base64.urlsafe_b64encode(compressed)
    return c.decode().replace("=", "")
"""

