from flask import Flask, redirect, jsonify, request, session
import base64
from datetime import datetime, timedelta
import json
import uuid
import requests
import didkit
from random import randrange

key_wallet =  {"crv":"secp256k1",
        "d":"lbuGEjEsYQ205boyekj8qdCwB2Uv7L2FwHUNleJj_Z0",
        "kty":"EC",
        "x":"AARiMrLNsRka9wMEoSgMnM7BwPug4x9IqLDwHVU-1A4",
        "y":"vKMstC3TEN3rVW32COQX002btnU70v6P73PMGcUoZQs",
    "alg" : 'ES256K'}
    

key = json.dumps(key_wallet)
issuer_did = didkit.key_to_did("key", key)
issuer_vm = issuer_did  + "#key-1"

def init_app(app,red, mode) :
    app.add_url_rule('/sandbox/issuer/ebsiv2',  view_func=issuer_ebsiv2, methods = ['GET'], defaults={'mode' : mode})

    app.add_url_rule('/sandbox/issuer/hedera',  view_func=issuer_hedera, methods = ['GET'], defaults={'mode' : mode}) # Test 3
    app.add_url_rule('/sandbox/issuer/hedera_2',  view_func=issuer_hedera_2, methods = ['GET'], defaults={'mode' : mode}) # test GreencyPher
    app.add_url_rule('/sandbox/issuer/hedera_30',  view_func=issuer_hedera_3, methods = ['GET'], defaults={'mode' : mode}) # test 9

    app.add_url_rule('/sandbox/issuer/gaia-x',  view_func=issuer_gaiax, methods = ['GET'], defaults={'mode' : mode})

    app.add_url_rule('/sandbox/issuer/default',  view_func=issuer_default, methods = ['GET'], defaults={'mode' : mode})
    app.add_url_rule('/sandbox/issuer/default_2',  view_func=issuer_default_2, methods = ['GET'], defaults={'mode' : mode, 'red' : red}) # test 5
    app.add_url_rule('/sandbox/issuer/default_2/deferred',  view_func=issuer_default_2_deferred, methods = ['GET', 'POST'], defaults={'mode' : mode, 'red' : 'red'}) # test 5

    app.add_url_rule('/sandbox/issuer/default_3',  view_func=issuer_default_3, methods = ['GET'], defaults={'mode' : mode}) # test 6

    app.add_url_rule('/sandbox/issuer/ebsiv3',  view_func=issuer_ebsiv3, methods = ['GET'], defaults={'mode' : mode}) # test 10
    app.add_url_rule('/sandbox/issuer/ebsiv31',  view_func=issuer_ebsiv31, methods = ['GET'], defaults={'mode' : mode}) # test 8

    app.add_url_rule('/sandbox/issuer/wallet_link',  view_func=issuer_wallet_link, methods = ['GET'], defaults={'mode' : mode}) # test 8

    app.add_url_rule('/sandbox/issuer/callback',  view_func=issuer_callback, methods = ['GET'])


def issuer_callback():
    return jsonify("Great ! request = " + json.dumps(request.args))


def issuer_wallet_link(mode) :
    if mode.myenv == 'aws' :
        api_endpoint = "https://talao.co/sandbox/ebsi/issuer/api/tdiwmpyhzc"
        client_secret = "5972a3b8-45c3-11ee-93f5-0a1628958560"
    else : 
        api_endpoint = mode.server + "sandbox/ebsi/issuer/api/raamxepqex"
        client_secret = "5381c36b-45c2-11ee-ac39-9db132f0e4a1"
    vc = 'EthereumAssociatedAddress'
    with open('./verifiable_credentials/' + vc + '.jsonld', 'r') as f :
        credential = json.loads(f.read())
    credential['id'] = "urn:uuid:" + str(uuid.uuid4())
    credential['issuanceDate'] = datetime.now().replace(microsecond=0).isoformat() + "Z"
    credential['expirationDate'] =  (datetime.now().replace(microsecond=0) + timedelta(days= 365)).isoformat() + "Z"
    
    headers = {
        'Content-Type': 'application/json',
        'Authorization' : 'Bearer ' + client_secret
    }
    data = { 
        "vc" : {vc : credential}, 
        "issuer_state" : str(uuid.uuid1()),
        "credential_type" : vc,
        "pre-authorized_code" : True,
        "callback" : mode.server + 'sandbox/issuer/callback', # to replace with application call back endpoint
        }
    resp = requests.post(api_endpoint, headers=headers, json = data)
    try :
        qrcode =  resp.json()['redirect_uri']
    except :
        return jsonify("No qr code")
    return redirect(qrcode) 


def issuer_ebsiv2(mode):
    if mode.myenv == 'aws' :
        api_endpoint = "https://talao.co/sandbox/ebsi/issuer/api/zxhaokccsi"
        client_secret = "0e2e27b3-28a9-11ee-825b-9db9eb02bfb8"
    else : 
        api_endpoint = mode.server + "sandbox/ebsi/issuer/api/zxhaokccsi"
        client_secret = "0e2e27b3-28a9-11ee-825b-9db9eb02bfb8"
   
    vc = 'VerifiableDiploma'
    with open('./verifiable_credentials/' + vc + '.jsonld', 'r') as f :
        credential = json.loads(f.read())
    credential['id'] = "urn:uuid:" + str(uuid.uuid4())
    credential['issuanceDate'] = datetime.now().replace(microsecond=0).isoformat() + "Z"
    credential['issued'] = datetime.now().replace(microsecond=0).isoformat() + "Z"
    credential['validFrom'] =  (datetime.now().replace(microsecond=0) + timedelta(days= 365)).isoformat() + "Z"
    credential['expirationDate'] =  (datetime.now().replace(microsecond=0) + timedelta(days= 365)).isoformat() + "Z"
    
    headers = {
        'Content-Type': 'application/json',
        'Authorization' : 'Bearer ' + client_secret
    }
    data = { 
        "vc" : {vc : credential}, 
        "issuer_state" : str(uuid.uuid1()),
        "credential_type" : vc,
        "pre-authorized_code" : True,
        "callback" : mode.server + 'sandbox/issuer/callback',
        }
    resp = requests.post(api_endpoint, headers=headers, json = data)
    try :
        qrcode =  resp.json()['redirect_uri']
    except :
        return jsonify("No qr code")
    return redirect(qrcode) 
  


# Test 8
def issuer_ebsiv31(mode):
    if mode.myenv == 'aws' :
        api_endpoint = "https://talao.co/sandbox/ebsi/issuer/api/zarbjrqrzj"
        client_secret = "c755ade2-3b5a-11ee-b7f1-0a1628958560"
    else : 
        api_endpoint = mode.server + "sandbox/ebsi/issuer/api/nfwvbyacnw"
        client_secret = "4f64b6f5-3adf-11ee-a601-b33f6ebca22b"
    
    offer = ['VerifiableDiploma']
    headers = {
        'Content-Type': 'application/json',
        'Authorization' : 'Bearer ' + client_secret
    }
   
    data = { 
        "vc" : build_credential_offered(offer), 
        "issuer_state" : str(uuid.uuid1()),
        "credential_type" : offer,
        "pre-authorized_code" : True,
        "callback" : mode.server + 'sandbox/issuer/callback',
        "user_pin_required" : False,
        }
    resp = requests.post(api_endpoint, headers=headers, json = data)
    try :
        qrcode =  resp.json()['redirect_uri']
    except :
        return jsonify("No qr code")
    return redirect(qrcode) 
   

# Test 10
def issuer_ebsiv3(mode):
    if mode.myenv == 'aws' :
        api_endpoint = "https://talao.co/sandbox/ebsi/issuer/api/pcbrwbvrsi"
        client_secret = "0f4103ef-42c3-11ee-9015-0a1628958560"
    else : 
        api_endpoint = mode.server + "sandbox/ebsi/issuer/api/kwcdgsspng"
        client_secret = "6f1dd8a5-42c3-11ee-b096-b5bae73ba948"
    
    offer = ['VerifiableDiploma']
    headers = {
        'Content-Type': 'application/json',
        'Authorization' : 'Bearer ' + client_secret
    }
   
    data = { 
        "vc" : build_credential_offered(offer), 
        "issuer_state" : str(uuid.uuid1()),
        "credential_type" : offer,
        "pre-authorized_code" : False,
        "callback" : mode.server + 'sandbox/issuer/callback',
        "user_pin_required" : False
        }
    
    resp = requests.post(api_endpoint, headers=headers, json = data)
    try :
        qrcode =  resp.json()['redirect_uri']
    except :
        return jsonify("No qr code")
    return redirect(qrcode) 
  

# test 9
def issuer_hedera_3(mode):
    if mode.myenv == 'aws' :
        api_endpoint = "https://talao.co/sandbox/ebsi/issuer/api/vgxxsuvrhv"
        client_secret = "e566cbcb-3b5e-11ee-89bb-0a1628958560"
    else : 
        api_endpoint = mode.server + "sandbox/ebsi/issuer/api/beguvsaeox"
        client_secret = "72155eb7-3b5b-11ee-a601-b33f6ebca22b"
    
    offer = ['EmailPass']
    headers = {
        'Content-Type': 'application/json',
        'Authorization' : 'Bearer ' + client_secret
    }
    data = { 
        "vc" : build_credential_offered(offer), 
        "issuer_state" : str(uuid.uuid1()),
        "credential_type" : offer,
        "pre-authorized_code" : True,
        "callback" : mode.server + 'sandbox/issuer/callback',
        "user_pin_required" : True,
        "user_pin" : "100000"
        }
    resp = requests.post(api_endpoint, headers=headers, json = data)
    try :
        qrcode =  resp.json()['redirect_uri']
    except :
        return jsonify("No qr code")
    return redirect(qrcode) 
   
    
# test 2 authorization code flow on DEFAULT
def issuer_default(mode):
    if mode.myenv == 'aws' :
        api_endpoint = "https://talao.co/sandbox/ebsi/issuer/api/npwsshblrm"
        client_secret = "731dc86d-2abb-11ee-825b-9db9eb02bfb8"
    else :       
        api_endpoint = mode.server + "sandbox/ebsi/issuer/api/npwsshblrm"
        client_secret = "731dc86d-2abb-11ee-825b-9db9eb02bfb8"

    offer = ["VerifiableId"]

    headers = {
        'Content-Type': 'application/json',
        'Authorization' : 'Bearer ' + client_secret
    }
    data = { 
        "vc" : build_credential_offered(offer), 
        "issuer_state" : str(uuid.uuid1()),
        "pre-authorized_code" : False,
        "credential_type" : offer,
        "callback" : mode.server + 'sandbox/issuer/callback',
        }
    resp = requests.post(api_endpoint, headers=headers, json = data)
    try :
        qrcode = resp.json()['redirect_uri']
    except :
        return jsonify("No qr code")
    return redirect(qrcode) 
 

# test 5 part 2
def issuer_default_2_deferred(red, mode): # VC is sent after delay
    if mode.myenv == 'aws' :
        api_endpoint = "https://talao.co/sandbox/ebsi/issuer/api/wzxtwpltvn"
        client_secret = "731dc86d-2abb-11ee-825b-9db9eb02bfb8"
    else :       
        api_endpoint = mode.server + "sandbox/ebsi/issuer/api/omjqeppxps"
        client_secret = "731dc86d-2abb-11ee-825b-9db9eb02bfb8"

    offer = ["EmailPass"]

    headers = {
        'Content-Type': 'application/json',
        'Authorization' : 'Bearer ' + client_secret
    }
    issuer_state = request.form['issuer_state']
    data = { 
        "deferred_vc" : build_credential_offered(offer), 
        "issuer_state" : issuer_state,
        "pre-authorized_code" : True,
        "credential_type" : offer,
        }
    resp = requests.post(api_endpoint, headers=headers, json = data)
    print(resp.status_code)
    return redirect('/sandbox/issuer/oidc/test')


# Test 5 part 1
def issuer_default_2(red, mode): # Test 5 deferred no VC sent
    if mode.myenv == 'aws' :
        api_endpoint = "https://talao.co/sandbox/ebsi/issuer/api/wzxtwpltvn"
        client_secret = "731dc86d-2abb-11ee-825b-9db9eb02bfb8"
    else :       
        api_endpoint = mode.server + "sandbox/ebsi/issuer/api/omjqeppxps"
        client_secret = "731dc86d-2abb-11ee-825b-9db9eb02bfb8"

    offer = ["EmailPass"]

    headers = {
        'Content-Type': 'application/json',
        'Authorization' : 'Bearer ' + client_secret
    }
    issuer_state = str(randrange(100))
    data = { 
        "vc" : {"EmailPass" : {}}, # no VC for deferred
        "issuer_state" : issuer_state,
        "pre-authorized_code" : True,
        "credential_type" : offer,
        "callback" : mode.server + 'sandbox/issuer/callback',
        }
    resp = requests.post(api_endpoint, headers=headers, json = data)
    try :
        qrcode =  resp.json()['redirect_uri']
    except :
        return jsonify("No qr code")
    return redirect(qrcode +'?issuer_state=' + issuer_state) 
    


def issuer_default_3(mode): # Test 6 
    if mode.myenv == 'aws' :
        api_endpoint = "https://talao.co/sandbox/ebsi/issuer/api/cejjvswuep"
        client_secret = "731dc86d-2abb-11ee-825b-9db9eb02bfb8"
    else :       
        api_endpoint = mode.server + "sandbox/ebsi/issuer/api/ooroomolyd"
        client_secret = "f5fa78af-3aa9-11ee-a601-b33f6ebca22b"

    offer = ["VerifiableId", "PhoneProof"]

    headers = {
        'Content-Type': 'application/json',
        'Authorization' : 'Bearer ' + client_secret
    }
    data = { 
        "vc" : build_credential_offered(offer), 
        "issuer_state" : str(uuid.uuid1()),
        "credential_type" : offer,
        "pre-authorized_code" : True,
        "callback" : mode.server + 'sandbox/issuer/callback',
        }
    resp = requests.post(api_endpoint, headers=headers, json = data)
    try :
        qrcode =  resp.json()['redirect_uri']
    except :
        return jsonify("No qr code")
    return redirect(qrcode) 
  

def issuer_gaiax(mode):
    if mode.myenv == 'aws' :
        api_endpoint = "https://talao.co/sandbox/ebsi/issuer/api/mfyttabosy"
        client_secret = "c0ab5d96-3113-11ee-a3e3-0a1628958560"
    else  :
        api_endpoint = mode.server + "sandbox/ebsi/issuer/api/cqmygbreop"
        client_secret = "a71f33f9-3100-11ee-825b-9db9eb02bfb8"

    offer = ["EmployeeCredential"]
    headers = {
        'Content-Type': 'application/json',
        'Authorization' : 'Bearer ' + client_secret
    }
    data = { 
        "vc" : build_credential_offered(offer), 
        "issuer_state" : str(uuid.uuid1()),
        "credential_type" : offer,
        "pre-authorized_code" : True,
        "callback" : mode.server + 'sandbox/issuer/callback',
        }
    resp = requests.post(api_endpoint, headers=headers, json = data)
    try :
        qrcode =  resp.json()['redirect_uri']
    except :
        return jsonify("No qr code")
    return redirect(qrcode) 
   

# Test 3, multiple VC
def issuer_hedera(mode):
    if mode.myenv == 'aws' :
        api_endpoint = "https://talao.co/sandbox/ebsi/issuer/api/nkpbjplfbi"
        client_secret = "ed055e57-3113-11ee-a280-0a1628958560"
    
    else :
        api_endpoint = mode.server + "sandbox/ebsi/issuer/api/uxzjfrjptk"
        client_secret = "2675ebcf-2fc1-11ee-825b-9db9eb02bfb8"

    offer = ["GreencypherPass", "CetProject"]
    headers = {
        'Content-Type': 'application/json',
        'Authorization' : 'Bearer ' + client_secret
    }
    # "vc" : OPTIONAL -> { "EmployeeCredendial" : {}, ....}, json object, VC as a json-ld not signed { "EmployeeCredendial" : { "identifier1" : {} },  ....}
    data = {  
        "vc" : [  
            {
                "type" : "CetProject",
                "types" : ["VerifiableCredentials", "CetProject"],
                "list" : [ 
                    {
                        "identifier" : "Forest_project_1345",
                        "value" : build_credential("CetProject")
                    },
                    {
                        "identifier" : "Kenyan_see_protection_28",
                        "value" : build_credential("CetProject")
                    },
                     {
                        "identifier" : "Forest_project_245",
                        "value" : build_credential("CetProject")
                    },
                     {
                        "identifier" : "Kenyan_see_protection_2",
                        "value" : build_credential("CetProject")
                    }
                    ]
            },
            {
                "type" : "GreencyphaerPass",
                "types" : ["VerifiableCredentials", "GreencypherPass"],
                "list" : [
                    {
                        "identifier" : "identifier_38",
                        "value" : build_credential("GreencypherPass")
                    }
                ]
            }
        ],
        "issuer_state" : str(uuid.uuid1()),
        "credential_type" : offer,
        "pre-authorized_code" : True,
        "callback" : mode.server + 'sandbox/issuer/callback',
    }
    resp = requests.post(api_endpoint, headers=headers, json = data)
    try :
        qrcode =  resp.json()['redirect_uri']
    except :
        return jsonify("No qr code")
    return redirect(qrcode) 
   
   
# test 7 GreenCypher with GreencypherPass and projects
def issuer_hedera_2(mode):
    if mode.myenv == 'aws' :
        api_endpoint = "https://talao.co/sandbox/ebsi/issuer/api/gxstfttnum"
        client_secret = "ed055e57-3113-11ee-a280-0a1628958560"
    
    else :
        api_endpoint = mode.server + "sandbox/ebsi/issuer/api/fixmtbwkfr"
        client_secret = "2675ebcf-2fc1-11ee-825b-9db9eb02bfb8"

    offer = ['GreencypherPass']
    headers = {
        'Content-Type': 'application/json',
        'Authorization' : 'Bearer ' + client_secret
    }
    data = { 
        "vc" : build_credential_offered(offer), 
        "issuer_state" : str(uuid.uuid1()),
        "credential_type" : offer,
        "pre-authorized_code" : True,
        "callback" : mode.server + '/sandbox/issuer/callback',
        }
    resp = requests.post(api_endpoint, headers=headers, json = data)
    try :
        qrcode =  resp.json()['redirect_uri']
    except :
        return jsonify("No qr code")
    return redirect(qrcode) 
  

def build_credential_offered(offer) :
    credential_offered = dict()
    if isinstance(offer, str) :
        offer = [offer]
    for vc in offer :
        try :
            with open('./verifiable_credentials/' + vc + '.jsonld', 'r') as f :
                credential = json.loads(f.read())
        except :
            return
        credential['id'] = "urn:uuid:" + str(uuid.uuid4())
        credential['issuanceDate'] = datetime.now().replace(microsecond=0).isoformat() + "Z"
        credential['issued'] = datetime.now().replace(microsecond=0).isoformat() + "Z"
        credential['validFrom'] =  (datetime.now().replace(microsecond=0) + timedelta(days= 365)).isoformat() + "Z"
        credential['expirationDate'] =  (datetime.now().replace(microsecond=0) + timedelta(days= 365)).isoformat() + "Z"
        credential_offered[vc] = credential
    return credential_offered


def build_credential(vc) :
    try :
        with open('./verifiable_credentials/' + vc + '.jsonld', 'r') as f :
            credential = json.loads(f.read())
    except :
        return
    credential['id'] = "urn:uuid:" + str(uuid.uuid4())
    credential['issuanceDate'] = datetime.now().replace(microsecond=0).isoformat() + "Z"
    credential['issued'] = datetime.now().replace(microsecond=0).isoformat() + "Z"
    credential['validFrom'] =  (datetime.now().replace(microsecond=0) + timedelta(days= 365)).isoformat() + "Z"
    credential['expirationDate'] =  (datetime.now().replace(microsecond=0) + timedelta(days= 365)).isoformat() + "Z"
    return credential
