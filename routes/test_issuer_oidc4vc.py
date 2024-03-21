from flask import redirect, jsonify, request, render_template, send_file
from datetime import datetime, timedelta
import json
import uuid
import requests
from random import randrange
import db_api


def init_app(app,red, mode):
    app.add_url_rule('/sandbox/issuer/test_1',  view_func=test_1, methods=['GET'], defaults={'mode': mode})
    app.add_url_rule('/sandbox/issuer/test_2',  view_func=test_2, methods=['GET'], defaults={'mode': mode})
    app.add_url_rule('/sandbox/issuer/test_3',  view_func=test_3, methods=['GET'], defaults={'mode': mode}) 
    app.add_url_rule('/sandbox/issuer/test_4',  view_func=test_4, methods=['GET'], defaults={'mode': mode}) 
    app.add_url_rule('/sandbox/issuer/test_5',  view_func=test_5, methods=['GET'], defaults={'mode': mode}) 
    app.add_url_rule('/sandbox/issuer/test_6_1',  view_func=test_6_1, methods=['GET', 'POST'], defaults={'mode': mode, 'red': 'red'})
    app.add_url_rule('/sandbox/issuer/test_6_2',  view_func=test_6_2, methods=['GET', 'POST'], defaults={'mode': mode, 'red': 'red'})
    app.add_url_rule('/sandbox/issuer/test_7',  view_func=test_7, methods=['GET'], defaults={'mode': mode}) 
    app.add_url_rule('/sandbox/issuer/test_8',  view_func=test_8, methods=['GET'], defaults={'mode': mode})
    app.add_url_rule('/sandbox/issuer/test_9',  view_func=test_9, methods=['GET'], defaults={'mode': mode})
    app.add_url_rule('/sandbox/issuer/test_10',  view_func=test_10, methods=['GET'], defaults={'mode': mode})
    app.add_url_rule('/sandbox/issuer/test_11',  view_func=test_11, methods=['GET'], defaults={'mode': mode})
    app.add_url_rule('/sandbox/issuer/test_12',  view_func=test_12, methods=['GET'], defaults={'mode': mode})
    app.add_url_rule('/sandbox/issuer/test_13',  view_func=test_13, methods=['GET'], defaults={'mode': mode})

    app.add_url_rule('/sandbox/issuer/callback',  view_func=issuer_callback, methods=['GET'])
    # test
    app.add_url_rule('/issuer/oidc/test',  view_func=issuer_oidc_test, methods=['GET', 'POST'], defaults={"mode": mode})
    app.add_url_rule('/sandbox/issuer/oidc/test',  view_func=issuer_oidc_test, methods=['GET', 'POST'], defaults={"mode": mode})

    app.add_url_rule('/sandbox/image',  view_func=get_image, methods=['GET'])

    return


def get_image():
    filename = 'picture.jpg'
    return send_file(filename, mimetype='image/jpeg')


def issuer_oidc_test(mode):
    if mode.myenv == 'aws':
        issuer_id_test_1 = "zxhaokccsi"
        issuer_id_test_2 = "sobosgdtgd"
        issuer_id_test_3 = "cejjvswuep"
        issuer_id_test_4 = "tdiwmpyhzc"
        issuer_id_test_5 = "zarbjrqrzj"
        issuer_id_test_6 = "wzxtwpltvn"
        issuer_id_test_7 = "mfyttabosy"
        issuer_id_test_8 = "npwsshblrm"
        issuer_id_test_9 = "pexkhrzlmj"
        issuer_id_test_10 = "grlvzckofy"
        issuer_id_test_11 = "pcbrwbvrsi"
        issuer_id_test_12 = "hrngdrpura"
        issuer_id_test_13 = "eyulcaatwc"
    else:
        issuer_id_test_1 = "zxhaokccsi"
        issuer_id_test_2 = "mjdgqkkmcf"
        issuer_id_test_3 = "ooroomolyd"
        issuer_id_test_4 = "raamxepqex"
        issuer_id_test_5 = "nfwvbyacnw"
        issuer_id_test_6 = "omjqeppxps"
        issuer_id_test_7 = "cqmygbreop"
        issuer_id_test_8 = "npwsshblrm"
        issuer_id_test_9 = "beguvsaeox"
        issuer_id_test_10 = "kivrsduinn"
        issuer_id_test_11 = "kwcdgsspng"
        issuer_id_test_12 = "wixtxxvbxw"
        issuer_id_test_13 = "ywmtotgmsi"

    title_test_1 = json.loads(db_api.read_oidc4vc_issuer(issuer_id_test_1))["page_title"]
    subtitle_test_1 = json.loads(db_api.read_oidc4vc_issuer(issuer_id_test_1))["page_subtitle"]
    title_test_2 = json.loads(db_api.read_oidc4vc_issuer(issuer_id_test_2))["page_title"]
    subtitle_test_2 = json.loads(db_api.read_oidc4vc_issuer(issuer_id_test_2))["page_subtitle"]
    title_test_3 = json.loads(db_api.read_oidc4vc_issuer(issuer_id_test_3))["page_title"]
    subtitle_test_3 = json.loads(db_api.read_oidc4vc_issuer(issuer_id_test_3))["page_subtitle"]
    title_test_4 = json.loads(db_api.read_oidc4vc_issuer(issuer_id_test_4))["page_title"]
    subtitle_test_4 = json.loads(db_api.read_oidc4vc_issuer(issuer_id_test_4))["page_subtitle"]
    title_test_5 = json.loads(db_api.read_oidc4vc_issuer(issuer_id_test_5))["page_title"]
    subtitle_test_5 = json.loads(db_api.read_oidc4vc_issuer(issuer_id_test_5))["page_subtitle"]
    title_test_6 = json.loads(db_api.read_oidc4vc_issuer(issuer_id_test_6))["page_title"]
    subtitle_test_6 = json.loads(db_api.read_oidc4vc_issuer(issuer_id_test_6))["page_subtitle"]
    title_test_7 = json.loads(db_api.read_oidc4vc_issuer(issuer_id_test_7))["page_title"]
    subtitle_test_7 = json.loads(db_api.read_oidc4vc_issuer(issuer_id_test_7))["page_subtitle"]
    title_test_8 = json.loads(db_api.read_oidc4vc_issuer(issuer_id_test_8))["page_title"]
    subtitle_test_8 = json.loads(db_api.read_oidc4vc_issuer(issuer_id_test_8))["page_subtitle"]
    title_test_9 = json.loads(db_api.read_oidc4vc_issuer(issuer_id_test_9))["page_title"]
    subtitle_test_9 = json.loads(db_api.read_oidc4vc_issuer(issuer_id_test_9))["page_subtitle"]
    title_test_10 = json.loads(db_api.read_oidc4vc_issuer(issuer_id_test_10))["page_title"]
    subtitle_test_10 = json.loads(db_api.read_oidc4vc_issuer(issuer_id_test_10))["page_subtitle"]
    title_test_11 = json.loads(db_api.read_oidc4vc_issuer(issuer_id_test_11))["page_title"]
    subtitle_test_11 = json.loads(db_api.read_oidc4vc_issuer(issuer_id_test_11))["page_subtitle"]
    title_test_12 = json.loads(db_api.read_oidc4vc_issuer(issuer_id_test_12))["page_title"]
    subtitle_test_12 = json.loads(db_api.read_oidc4vc_issuer(issuer_id_test_12))["page_subtitle"]
    title_test_13 = json.loads(db_api.read_oidc4vc_issuer(issuer_id_test_13))["page_title"]
    subtitle_test_13 = json.loads(db_api.read_oidc4vc_issuer(issuer_id_test_13))["page_subtitle"]

    return render_template(
        'issuer_oidc/wallet_issuer_test.html',
        title_test_1=title_test_1,
        subtitle_test_1=subtitle_test_1,
        title_test_2=title_test_2,
        subtitle_test_2=subtitle_test_2,
        title_test_3=title_test_3,
        subtitle_test_3=subtitle_test_3,
        title_test_4=title_test_4,
        subtitle_test_4=subtitle_test_4,
        title_test_5=title_test_5,
        subtitle_test_5=subtitle_test_5,
        title_test_6=title_test_6,
        subtitle_test_6=subtitle_test_6,
        title_test_7=title_test_7,
        subtitle_test_7=subtitle_test_7,
        title_test_8=title_test_8,
        subtitle_test_8=subtitle_test_8,
        title_test_9=title_test_9,
        subtitle_test_9=subtitle_test_9,
        title_test_10=title_test_10,
        subtitle_test_10=subtitle_test_10,
        title_test_11=title_test_11,
        subtitle_test_11=subtitle_test_11,
        title_test_12=title_test_12,
        subtitle_test_12=subtitle_test_12,
        title_test_13=title_test_13,
        subtitle_test_13=subtitle_test_13
    )


def issuer_callback():
    return jsonify(f"Great ! request = {json.dumps(request.args)}")


def test_1(mode):
    api_endpoint = mode.server + "sandbox/oidc4vc/issuer/api"
    if mode.myenv == 'aws':
        issuer_id = "zxhaokccsi"
        client_secret = "0e2e27b3-28a9-11ee-825b-9db9eb02bfb8"
    else: 
        issuer_id = "zxhaokccsi"
        client_secret = "0e2e27b3-28a9-11ee-825b-9db9eb02bfb8"

    vc = 'VerifiableDiploma'
    with open('./verifiable_credentials/' + vc + '.jsonld', 'r') as f:
        credential = json.loads(f.read())
    credential['id'] = "urn:uuid:" + str(uuid.uuid4())
    credential['issuanceDate'] = datetime.now().replace(microsecond=0).isoformat() + "Z"
    credential['issued'] = datetime.now().replace(microsecond=0).isoformat() + "Z"
    credential['validFrom'] =  (datetime.now().replace(microsecond=0) + timedelta(days= 365)).isoformat() + "Z"
    credential['expirationDate'] =  (datetime.now().replace(microsecond=0) + timedelta(days= 365)).isoformat() + "Z"
    
    headers = {
        'Content-Type': 'application/json',
        'X-API-KEY': client_secret
    }
    data = { 
        "issuer_id": issuer_id,
        "vc": {vc: credential}, 
        "issuer_state": str(uuid.uuid1()),
        "credential_type": vc,
        "pre-authorized_code": True,
        "callback": mode.server + 'sandbox/issuer/callback',
        }
    resp = requests.post(api_endpoint, headers=headers, json = data)
    try:
        qrcode = resp.json()['redirect_uri']
    except Exception:
        return jsonify("No qr code")
    return redirect(qrcode)


def test_2(mode):
    api_endpoint = mode.server + "sandbox/oidc4vc/issuer/api"
    if mode.myenv == 'aws':
        issuer_id = "sobosgdtgd"
        client_secret = "9904f8ee-61f2-11ee-8e05-0a1628958560"
    else:
        issuer_id = "mjdgqkkmcf"
        client_secret = "36f779d3-61f2-11ee-864a-532486291c32"
    vc = 'EmailPass'
    with open('./verifiable_credentials/' + vc + '.jsonld', 'r') as f:
        credential = json.loads(f.read())
    credential['id'] = "urn:uuid:" + str(uuid.uuid4())
    credential['issuanceDate'] = datetime.now().replace(microsecond=0).isoformat() + "Z"
    credential['expirationDate'] = (datetime.now().replace(microsecond=0) + timedelta(days= 365)).isoformat() + "Z"
    
    headers = {
        'Content-Type': 'application/json',
        'X-API-KEY': client_secret
    }
    data = { 
        "issuer_id": issuer_id,
        "vc": {vc: credential}, 
        "issuer_state": str(uuid.uuid1()),
        "credential_type": vc,
        "pre-authorized_code": True,
        "user_pin_required": True,
        "user_pin": "4444",
        "callback": mode.server + 'sandbox/issuer/callback', # to replace with application call back endpoint
    }
    resp = requests.post(api_endpoint, headers=headers, json=data)
    try:
        qrcode = resp.json()['redirect_uri']
    except Exception:
        return jsonify("No qr code")
    return redirect(qrcode) 


def test_3(mode):
    api_endpoint = mode.server + "sandbox/oidc4vc/issuer/api"
    if mode.myenv == 'aws':
        issuer_id = "cejjvswuep"
        client_secret = "731dc86d-2abb-11ee-825b-9db9eb02bfb8"
    else:       
        issuer_id = "ooroomolyd"
        client_secret = "f5fa78af-3aa9-11ee-a601-b33f6ebca22b"

    offer = ["VerifiableId", "EmailPass", "Over18"]

    headers = {
        'Content-Type': 'application/json',
        'X-API-KEY': client_secret
    }
    data = { 
        "issuer_id": issuer_id,
        "vc": build_credential_offered(offer), 
        "issuer_state": str(uuid.uuid1()),
        "credential_type": offer,
        "pre-authorized_code": True,
        "callback": mode.server + 'sandbox/issuer/callback',
        }
    resp = requests.post(api_endpoint, headers=headers, json = data)
    try:
        qrcode = resp.json()['redirect_uri']
    except Exception:
        return jsonify("No qr code")
    return redirect(qrcode) 


def test_4(mode):
    api_endpoint = mode.server + "sandbox/oidc4vc/issuer/api"
    if mode.myenv == 'aws':
        issuer_id = "tdiwmpyhzc"
        client_secret = "5972a3b8-45c3-11ee-93f5-0a1628958560"
    else: 
        issuer_id = "raamxepqex"
        client_secret = "5381c36b-45c2-11ee-ac39-9db132f0e4a1"
    
    with open('./verifiable_credentials/IdentityCredential.json', 'r') as f:
        credential_verifiableid = json.loads(f.read())
    with open('./verifiable_credentials/EudiPid.json', 'r') as f:
        credential_eudipid = json.loads(f.read())
        
    headers = {
        'Content-Type': 'application/json',
        'X-API-KEY': client_secret
    }
    data = { 
        "issuer_id": issuer_id,
        "vc": {
            'IdentityCredential': credential_verifiableid,
            'EudiPid': credential_eudipid
        }, 
        "issuer_state": str(uuid.uuid1()),
        "credential_type": ['IdentityCredential', 'EudiPid'],
        "pre-authorized_code": True,
        "user_pin_required": False,
        "callback": mode.server + 'sandbox/issuer/callback', # to replace with application call back endpoint
    }
    resp = requests.post(api_endpoint, headers=headers, json=data)
    try:
        qrcode = resp.json()['redirect_uri']
    except Exception:
        return jsonify("No qr code")
    return redirect(qrcode)


def test_5(mode):
    api_endpoint = mode.server + "sandbox/oidc4vc/issuer/api"
    if mode.myenv == 'aws':
        issuer_id = "zarbjrqrzj"
        client_secret = "c755ade2-3b5a-11ee-b7f1-0a1628958560"
    else: 
        issuer_id = "nfwvbyacnw"
        client_secret = "4f64b6f5-3adf-11ee-a601-b33f6ebca22b"
    
    headers = {
        'Content-Type': 'application/json',
        'X-API-KEY': client_secret
    }

    offer = ['VerifiableId']

    data = { 
        "issuer_id": issuer_id,
        "vc": build_credential_offered(offer), 
        "issuer_state": str(uuid.uuid1()),
        "pre-authorized_code": True,
        "credential_type": ['VerifiableId'],
        "callback": mode.server + 'sandbox/issuer/callback',
        "user_pin_required": True,
        "user_pin": "4444",
        }

    resp = requests.post(api_endpoint, headers=headers, json = data)
    try:
        qrcode =  resp.json()['redirect_uri']
    except Exception:
        return jsonify("No qr code")
    return redirect(qrcode)


def test_6_2(red, mode): # VC is sent after delay
    api_endpoint = mode.server + "sandbox/oidc4vc/issuer/api"
    if mode.myenv == 'aws':
        issuer_id = "wzxtwpltvn"
        client_secret = "731dc86d-2abb-11ee-825b-9db9eb02bfb8"
    else:
        issuer_id = "omjqeppxps"
        client_secret = "731dc86d-2abb-11ee-825b-9db9eb02bfb8"

    offer = ["EmailPass"]

    headers = {
        'Content-Type': 'application/json',
        'X-API-KEY': client_secret
    }
    issuer_state = request.form['issuer_state']
    data = { 
        "issuer_id": issuer_id,
        "deferred_vc": build_credential_offered(offer), 
        "issuer_state": issuer_state,
        "pre-authorized_code": True,
        "credential_type": offer,
        }
    requests.post(api_endpoint, headers=headers, json = data)
    return redirect('/issuer/oidc/test')


def test_6_1(red, mode):
    api_endpoint = mode.server + "sandbox/oidc4vc/issuer/api"
    if mode.myenv == 'aws':
        issuer_id = "wzxtwpltvn"
        client_secret = "731dc86d-2abb-11ee-825b-9db9eb02bfb8"
    else:       
        issuer_id = "omjqeppxps"
        client_secret = "731dc86d-2abb-11ee-825b-9db9eb02bfb8"

    offer = ["EmailPass"]

    headers = {
        'Content-Type': 'application/json',
        'X-API-KEY': client_secret
    }
    issuer_state = str(randrange(100))
    data = { 
        "issuer_id": issuer_id,
        "vc": {"EmailPass": {}}, # no VC for deferred
        "issuer_state": issuer_state,
        "pre-authorized_code": True,
        "credential_type": offer,
        "callback": mode.server + 'sandbox/issuer/callback',
        }
    resp = requests.post(api_endpoint, headers=headers, json = data)
    try:
        qrcode =  resp.json()['redirect_uri']
    except Exception:
        return jsonify("No qr code")
    return redirect(qrcode + '?issuer_state=' + issuer_state)


def test_7(mode):
    api_endpoint = mode.server + "sandbox/oidc4vc/issuer/api"
    if mode.myenv == 'aws':
        issuer_id = "mfyttabosy"
        client_secret = "c0ab5d96-3113-11ee-a3e3-0a1628958560"
    else:
        issuer_id = "cqmygbreop"
        client_secret = "a71f33f9-3100-11ee-825b-9db9eb02bfb8"

    offer = ["EmailPass", "VerifiableId", "Over18", "DBCGuest"]
    headers = {
        'Content-Type': 'application/json',
        'X-API-KEY': client_secret
    }
    data = { 
        "issuer_id": issuer_id,
        "vc": build_credential_offered(offer), 
        "issuer_state": str(uuid.uuid1()),
        "credential_type": offer,
        "pre-authorized_code": False,
        "callback": mode.server + 'sandbox/issuer/callback',
        }
    resp = requests.post(api_endpoint, headers=headers, json=data)
    try:
        qrcode = resp.json()['redirect_uri']
    except Exception:
        return jsonify("No qr code")
    return redirect(qrcode) 


def test_8(mode):
    api_endpoint = mode.server + "sandbox/oidc4vc/issuer/api"
    if mode.myenv == 'aws':
        issuer_id = "npwsshblrm"
        client_secret = "731dc86d-2abb-11ee-825b-9db9eb02bfb8"
    else:       
        issuer_id = "npwsshblrm"
        client_secret = "731dc86d-2abb-11ee-825b-9db9eb02bfb8"

    headers = {
        'Content-Type': 'application/json',
        'X-API-KEY': client_secret
    }
    with open('./verifiable_credentials/IdentityCredential.json', 'r') as f:
        credential = json.loads(f.read())
    data = { 
        "issuer_id": issuer_id,
        "vc": {"IdentityCredential" : credential}, 
        "issuer_state": str(uuid.uuid1()),
        "pre-authorized_code": True,
        "credential_type": ['IdentityCredential'],
        "callback": mode.server + 'sandbox/issuer/callback',
        }
    resp = requests.post(api_endpoint, headers=headers, json = data)
    try:
        qrcode = resp.json()['redirect_uri']
    except Exception:
        return jsonify("No qr code")
    return redirect(qrcode) 


def test_9(mode): # 
    api_endpoint = mode.server + "sandbox/oidc4vc/issuer/api"
    if mode.myenv == 'aws':
        issuer_id = "pexkhrzlmj"
        client_secret = "7f888504-6ab4-11ee-938e-0a1628958560"
    else:       
        issuer_id = "beguvsaeox"
        client_secret = "72155eb7-3b5b-11ee-a601-b33f6ebca22b"
    headers = {
        'Content-Type': 'application/json',
        'X-API-KEY': client_secret
    }
   
    with open('./verifiable_credentials/IdentityCredential.json', 'r') as f:
        credential = json.loads(f.read())
    data = { 
        "issuer_id": issuer_id,
        "vc": {"IdentityCredential" : credential}, 
        "issuer_state": str(uuid.uuid1()),
        "pre-authorized_code": False,
        "credential_type": ['IdentityCredential'],
        "callback": mode.server + 'sandbox/issuer/callback',
        }
    resp = requests.post(api_endpoint, headers=headers, json=data)
    try:
        qrcode = resp.json()['redirect_uri']
    except Exception:
        return jsonify("No qr code")
    return redirect(qrcode) 


def test_10(mode):
    api_endpoint = mode.server + "sandbox/oidc4vc/issuer/api"
    if mode.myenv == 'aws':
        issuer_id = "grlvzckofy"
        client_secret = "731dc86d-2abb-11ee-825b-9db9eb02bfb8"
    else:       
        issuer_id = "kivrsduinn"
        client_secret = "f5fa78af-3aa9-11ee-a601-b33f6ebca22b"

    offer = ["VerifiableId", "EmailPass", "DBCGuest"]

    headers = {
        'Content-Type': 'application/json',
        'X-API-KEY': client_secret
    }
    data = { 
        "issuer_id": issuer_id,
        "vc": build_credential_offered(offer), 
        "issuer_state": str(uuid.uuid1()),
        "credential_type": offer,
        "pre-authorized_code": True,
        "callback": mode.server + 'sandbox/issuer/callback',
        }
    resp = requests.post(api_endpoint, headers=headers, json = data)
    try:
        qrcode =  resp.json()['redirect_uri']
    except Exception:
        return jsonify("No qr code")
    return redirect(qrcode) 


def test_11(mode):
    api_endpoint = mode.server + "sandbox/oidc4vc/issuer/api"
    if mode.myenv == 'aws':
        issuer_id = "pcbrwbvrsi"
        client_secret = "0f4103ef-42c3-11ee-9015-0a1628958560"
    else: 
        issuer_id = "kwcdgsspng"
        client_secret = "6f1dd8a5-42c3-11ee-b096-b5bae73ba948"
    
    offer = ['VerifiableDiploma']
    headers = {
        'Content-Type': 'application/json',
        'X-API-KEY': client_secret
    }

    data = { 
        "issuer_id" : issuer_id,
        "vc": build_credential_offered(offer), 
        "issuer_state": str(uuid.uuid1()),
        "credential_type": offer,
        "pre-authorized_code": False,
        "callback": mode.server + 'sandbox/issuer/callback',
        "user_pin_required": False
        }
    
    resp = requests.post(api_endpoint, headers=headers, json = data)
    try:
        qrcode = resp.json()['redirect_uri']
    except Exception:
        return jsonify("No qr code")
    return redirect(qrcode) 


def test_12(mode):
    api_endpoint = mode.server + "sandbox/oidc4vc/issuer/api"
    if mode.myenv == 'aws':
        issuer_id = "hrngdrpura"
        client_secret = "1c290181-de11-11ee-9fb4-0a1628958560"
    else:
        issuer_id = "wixtxxvbxw"
        client_secret = "4fc17d17-934b-11ee-b456-699f8f5cf9a0"

    headers = {
        'Content-Type': 'application/json',
        'X-API-KEY': client_secret
    }
    with open('./verifiable_credentials/IdentityCredential.json', 'r') as f:
        credential1 = json.loads(f.read())
    with open('./verifiable_credentials/EudiPid.json', 'r') as f:
        credential2 = json.loads(f.read())
    
    data = { 
        "issuer_id": issuer_id,
        "vc": {
            "IdentityCredential" : credential1,
            "EudiPid": credential2
        }, 
        "issuer_state": str(uuid.uuid1()),
        "pre-authorized_code": False,
        "credential_type": ['IdentityCredential', 'EudiPid'],
        "callback": mode.server + 'sandbox/issuer/callback',
    }
    resp = requests.post(api_endpoint, headers=headers, json=data)
    try:
        qrcode = resp.json()['redirect_uri']
    except Exception:
        return jsonify("No qr code")
    return redirect(qrcode) 


def test_13(mode):
    api_endpoint = mode.server + "sandbox/oidc4vc/issuer/api"
    if mode.myenv == 'aws':
        issuer_id = "eyulcaatwc"
        client_secret = "ab4dfa8b-dedc-11ee-a098-0a1628958560"
    else:
        issuer_id = "ywmtotgmsi"
        client_secret = "970220c3-dedc-11ee-9a92-15b06d6def59"

    headers = {
        'Content-Type': 'application/json',
        'X-API-KEY': client_secret
    }
    with open('./verifiable_credentials/IdentityCredential.json', 'r') as f:
        credential1 = json.loads(f.read())
    with open('./verifiable_credentials/EudiPid.json', 'r') as f:
        credential2 = json.loads(f.read())
    data = { 
        "issuer_id": issuer_id,
        "vc": {
            "IdentityCredential": credential1,
            "EudiPid": credential2}, 
        "issuer_state": str(uuid.uuid1()),
        "pre-authorized_code": True,
        "credential_type": ['IdentityCredential', 'EudiPid'],
        "user_pin_required": True,
        "user_pin": "4444",
        "callback": mode.server + 'sandbox/issuer/callback',
        }
    resp = requests.post(api_endpoint, headers=headers, json=data)
    try:
        qrcode = resp.json()['redirect_uri']
    except Exception:
        return jsonify("No qr code")
    return redirect(qrcode) 


def build_credential_offered(offer):
    credential_offered = dict()
    if isinstance(offer, str):
        offer = [offer]
    for vc in offer:
        try:
            with open('./verifiable_credentials/' + vc + '.jsonld', 'r') as f:
                credential = json.loads(f.read())
        except Exception:
            return
        credential['id'] = "urn:uuid:" + str(uuid.uuid4())
        credential['issuanceDate'] = datetime.now().replace(microsecond=0).isoformat() + "Z"
        credential['issued'] = datetime.now().replace(microsecond=0).isoformat() + "Z"
        credential['validFrom'] =  (datetime.now().replace(microsecond=0) + timedelta(days= 365)).isoformat() + "Z"
        credential['expirationDate'] =  (datetime.now().replace(microsecond=0) + timedelta(days= 365)).isoformat() + "Z"
        credential_offered[vc] = credential
    return credential_offered


def build_credential(vc):
    try:
        with open('./verifiable_credentials/' + vc + '.jsonld', 'r') as f:
            credential = json.loads(f.read())
    except Exception:
        return
    credential['id'] = "urn:uuid:" + str(uuid.uuid4())
    credential['issuanceDate'] = datetime.now().replace(microsecond=0).isoformat() + "Z"
    credential['issued'] = datetime.now().replace(microsecond=0).isoformat() + "Z"
    credential['validFrom'] =  (datetime.now().replace(microsecond=0) + timedelta(days= 365)).isoformat() + "Z"
    credential['expirationDate'] =  (datetime.now().replace(microsecond=0) + timedelta(days= 365)).isoformat() + "Z"
    return credential
