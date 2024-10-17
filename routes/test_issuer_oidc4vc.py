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
    app.add_url_rule('/sandbox/issuer/test_14',  view_func=test_14, methods=['GET'], defaults={'mode': mode})
    app.add_url_rule('/sandbox/issuer/test_15',  view_func=test_15, methods=['GET'], defaults={'mode': mode})
    app.add_url_rule('/sandbox/issuer/test_16',  view_func=test_16, methods=['GET'], defaults={'mode': mode})
    app.add_url_rule('/sandbox/issuer/test_17',  view_func=test_17, methods=['GET'], defaults={'mode': mode})
    
    # badges
    app.add_url_rule('/sandbox/issuer/test_18',  view_func=test_18, methods=['GET'], defaults={'mode': mode})
    app.add_url_rule('/sandbox/issuer/test_19',  view_func=test_19, methods=['GET'], defaults={'mode': mode})
    app.add_url_rule('/sandbox/issuer/test_20',  view_func=test_20, methods=['GET'], defaults={'mode': mode})
    app.add_url_rule('/sandbox/issuer/test_21',  view_func=test_21, methods=['GET'], defaults={'mode': mode})

    app.add_url_rule('/sandbox/issuer/callback',  view_func=issuer_callback, methods=['GET'])
    # test
    app.add_url_rule('/issuer/oidc/test',  view_func=issuer_oidc_test, methods=['GET', 'POST'], defaults={"mode": mode})
    app.add_url_rule('/sandbox/issuer/oidc/test',  view_func=issuer_oidc_test, methods=['GET', 'POST'], defaults={"mode": mode})

    app.add_url_rule('/sandbox/image',  view_func=get_image, methods=['GET'])

    app.add_url_rule('/sandbox/issuer/webhook',  view_func=webhook, methods=['POST'])
    return

    

def issuer_test(test, mode, secret=False):
    if mode.myenv == 'aws':
        issuer = [
            ["zxhaokccsi", "0e2e27b3-28a9-11ee-825b-9db9eb02bfb8"],
            ["sobosgdtgd", "9904f8ee-61f2-11ee-8e05-0a1628958560"],
            ["cejjvswuep", "731dc86d-2abb-11ee-825b-9db9eb02bfb8"],
            ["tdiwmpyhzc", "5972a3b8-45c3-11ee-93f5-0a1628958560"],
            ["zarbjrqrzj", "c755ade2-3b5a-11ee-b7f1-0a1628958560"],# 5
            ["wzxtwpltvn", "731dc86d-2abb-11ee-825b-9db9eb02bfb8"],
            ["mfyttabosy", "c0ab5d96-3113-11ee-a3e3-0a1628958560"],
            ["npwsshblrm", "731dc86d-2abb-11ee-825b-9db9eb02bfb8"],
            ["pexkhrzlmj", "7f888504-6ab4-11ee-938e-0a1628958560"],
            ["grlvzckofy", "731dc86d-2abb-11ee-825b-9db9eb02bfb8"], #10
            ["pcbrwbvrsi", "0f4103ef-42c3-11ee-9015-0a1628958560"],
            ["hrngdrpura", "1c290181-de11-11ee-9fb4-0a1628958560"],
            ["eyulcaatwc", "ab4dfa8b-dedc-11ee-a098-0a1628958560"],
            ["kucdqzidbs", "0e2e27b3-28a9-11ee-825b-9db9eb02bfb8"], 
            ["jfzmmdaedq", "7f888504-6ab4-11ee-938e-0a1628958560"], #15
            ["gssmaqetje", "7f888504-6ab4-11ee-938e-0a1628958560"],
            ["uwbcbtilws", "7f888504-6ab4-11ee-938e-0a1628958560"],
            ["hmvwdgszax", "731dc86d-2abb-11ee-825b-9db9eb02bfb8"],
            ["saxupyiiqd", "731dc86d-2abb-11ee-825b-9db9eb02bfb8"],
            ["palmwvyrpz", "731dc86d-2abb-11ee-825b-9db9eb02bfb8"],#20
            ["aminiifbnh", "731dc86d-2abb-11ee-825b-9db9eb02bfb8"]
        ]
    else:
        issuer = [
            ["zxhaokccsi", "0e2e27b3-28a9-11ee-825b-9db9eb02bfb8"],
            ["mjdgqkkmcf", "36f779d3-61f2-11ee-864a-532486291c32"],
            ["ooroomolyd", "f5fa78af-3aa9-11ee-a601-b33f6ebca22b"],
            ["raamxepqex", "5381c36b-45c2-11ee-ac39-9db132f0e4a1"],
            ["nfwvbyacnw", "4f64b6f5-3adf-11ee-a601-b33f6ebca22b"], #5
            ["omjqeppxps", "731dc86d-2abb-11ee-825b-9db9eb02bfb8"],
            ["cqmygbreop", "a71f33f9-3100-11ee-825b-9db9eb02bfb8"],
            ["npwsshblrm", "731dc86d-2abb-11ee-825b-9db9eb02bfb8"],
            ["beguvsaeox", "72155eb7-3b5b-11ee-a601-b33f6ebca22b"],
            ["kivrsduinn", "f5fa78af-3aa9-11ee-a601-b33f6ebca22b"], #10
            ["kwcdgsspng", "6f1dd8a5-42c3-11ee-b096-b5bae73ba948"],
            ["wixtxxvbxw", "4fc17d17-934b-11ee-b456-699f8f5cf9a0"],
            ["ywmtotgmsi", "970220c3-dedc-11ee-9a92-15b06d6def59"],
            ["azjkjzlfku", "0e2e27b3-28a9-11ee-825b-9db9eb02bfb8"],
            ["znyvjvylrh", "72155eb7-3b5b-11ee-a601-b33f6ebca22b"],#15
            ["lxvmyjevie", "72155eb7-3b5b-11ee-a601-b33f6ebca22b"],
            ["xjktmrjcae", "72155eb7-3b5b-11ee-a601-b33f6ebca22b"],
            ["vokyfraqyj", "731dc86d-2abb-11ee-825b-9db9eb02bfb8"],
            ["jamrcaqppf", "731dc86d-2abb-11ee-825b-9db9eb02bfb8"],
            ["swzqynzppm", "731dc86d-2abb-11ee-825b-9db9eb02bfb8"], #20
            ["sztgmnihqs", "731dc86d-2abb-11ee-825b-9db9eb02bfb8"]
        ]
    if isinstance(test, str): test == int(test)
    return issuer[test - 1][int(secret)]
  

def get_image():
    filename = 'picture.jpg'
    return send_file(filename, mimetype='image/jpeg')


# display the test page for OIDC4VCI
def issuer_oidc_test(mode):
    my_test = dict()
    for test in range(1, 22):
        issuer_data = json.loads(db_api.read_oidc4vc_issuer(issuer_test(test, mode)))
        my_test.update(
            {
                "title_test_" + str(test) : issuer_data['page_title'],
                "subtitle_test_" + str(test): issuer_data['page_subtitle']
            }
        )
    return render_template('issuer_oidc/wallet_issuer_test.html', **my_test)


def issuer_callback():
    return jsonify(f"Great ! request = {json.dumps(request.args)}")


def test_1(mode):
    api_endpoint = mode.server + "sandbox/oidc4vc/issuer/api"
    issuer_id = issuer_test(1, mode)
    client_secret = issuer_test(1, mode, secret=True)

    vc = 'VerifiableDiploma2'
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
    issuer_id = issuer_test(2, mode)
    client_secret = issuer_test(2, mode, secret = True)

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
    issuer_id = issuer_test(3, mode)
    client_secret = issuer_test(3, mode, secret = True)

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
    resp = requests.post(api_endpoint, headers=headers, json=data)
    try:
        qrcode = resp.json()['redirect_uri']
    except Exception:
        return jsonify("No qr code")
    return redirect(qrcode) 


def test_4(mode):
    api_endpoint = mode.server + "sandbox/oidc4vc/issuer/api"
    issuer_id = issuer_test(4, mode)
    client_secret = issuer_test(4, mode, secret = True)

    offer = ["PhoneProof", "EmailPass", "VerifiableId", "Over18", "DBCGuest", "TestCredential"]
    headers = {
        'Content-Type': 'application/json',
        'X-API-KEY': client_secret
    }
    data = { 
        "issuer_id": issuer_id,
        "vc": build_credential_offered(offer), 
        "issuer_state": "test4",
        "credential_type": offer,
        "pre-authorized_code": True,
        "callback": mode.server + 'sandbox/issuer/callback',
        }
    
    resp = requests.post(api_endpoint, headers=headers, json=data)
    try:
        qrcode_uri = resp.json()['redirect_uri']
        qrcode_value = resp.json()['qrcode_value']
    except Exception:
        return jsonify("No qr code")
    print("qrcode value = ", qrcode_value)
    return redirect(qrcode_uri)


def test_5(mode):
    api_endpoint = mode.server + "sandbox/oidc4vc/issuer/api"
    issuer_id = issuer_test(5, mode)
    client_secret = issuer_test(5, mode, secret = True)
    
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
        "user_pin_required": False,
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
    issuer_id = issuer_test(6, mode)
    client_secret = issuer_test(6, mode, secret = True)
   
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
    issuer_id = issuer_test(6, mode)
    client_secret = issuer_test(6, mode, secret = True)

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
    issuer_id = issuer_test(7, mode)
    client_secret = issuer_test(7, mode, secret = True)

    offer = ["EmailPass", "PhoneProof"]
    headers = {
        'Content-Type': 'application/json',
        'X-API-KEY': client_secret
    }
    data = { 
        "issuer_id": issuer_id,
        "vc": build_credential_offered(offer), 
        "issuer_state": "test7",
        "credential_type": offer,
        "pre-authorized_code": True,
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
    issuer_id = issuer_test(8, mode)
    client_secret = issuer_test(8, mode, secret = True)

    headers = {
        'Content-Type': 'application/json',
        'X-API-KEY': client_secret
    }
    with open('./verifiable_credentials/EmployeeBadge.json', 'r') as f:
        employee_badge = json.loads(f.read())
        
    data = { 
        "issuer_id": issuer_id,
        "vc": {
            "EmployeeBadge": employee_badge, 
        },
        "issuer_state": "pid",
        "pre-authorized_code": False,
        "webhook": mode.server + "sandbox/issuer/webhook",
        "credential_type": ['EmployeeBadge'],
        "callback": mode.server + 'sandbox/issuer/callback',
        }
    resp = requests.post(api_endpoint, headers=headers, json = data)
    try:
        # 2 solutions possibles 
        qrcode_value = resp.json()['qrcode_value'] # valeur du QR code a afficher
        redirect_uri = resp.json()['redirect_uri'] # redirect vers la page d un QR code sur sandbox
    except Exception:
        return jsonify("No qr code")
    return redirect(redirect_uri) 


def test_9(mode): # 
    api_endpoint = mode.server + "sandbox/oidc4vc/issuer/api"
    issuer_id = issuer_test(8, mode)
    client_secret = issuer_test(8, mode, secret = True)
  
    headers = {
        'Content-Type': 'application/json',
        'X-API-KEY': client_secret
    }
    with open('./verifiable_credentials/Pid.json', 'r') as f:
        credential = json.loads(f.read())
    data = { 
        "issuer_id": issuer_id,
        "vc": {"Pid" : credential}, 
        "issuer_state": "test9",
        "pre-authorized_code": False,
        "credential_type": ['Pid'],
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
    issuer_id = issuer_test(10, mode)
    client_secret = issuer_test(10, mode, secret = True)
    
    with open('./verifiable_credentials/Pid.json', 'r') as f:
        credential = json.loads(f.read())

    headers = {
        'Content-Type': 'application/json',
        'X-API-KEY': client_secret
    }
    data = { 
        "issuer_id": issuer_id,
        "vc": {"Pid" : credential}, 
        "issuer_state": 'test10',
        "credential_type":  ['Pid'],
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
    issuer_id = issuer_test(11, mode)
    client_secret = issuer_test(11, mode, secret = True)
    
    with open('./verifiable_credentials/Pid.json', 'r') as f:
        credential = json.loads(f.read())

    headers = {
        'Content-Type': 'application/json',
        'X-API-KEY': client_secret
    }

    data = { 
        "issuer_id" : issuer_id,
        "vc": {"Pid" : credential}, 
        "issuer_state": "test11",
        "credential_type":  ['Pid'],
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
    issuer_id = issuer_test(12, mode)
    client_secret = issuer_test(12, mode, secret = True)

    headers = {
        'Content-Type': 'application/json',
        'X-API-KEY': client_secret
    }
    with open('./verifiable_credentials/IdentityCredential.json', 'r') as f:
        credential1 = json.loads(f.read())
    with open('./verifiable_credentials/Pid.json', 'r') as f:
        credential2 = json.loads(f.read())
    
    data = { 
        "issuer_id": issuer_id,
        "vc": {
            "IdentityCredential" : credential1,
            "Pid": credential2
        }, 
        "issuer_state": "test12",
        "pre-authorized_code": False,
        "credential_type": ['IdentityCredential', 'Pid'],
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
    issuer_id = issuer_test(13, mode)
    client_secret = issuer_test(13, mode, secret= True)

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
        "user_pin": "ABCD",
        "input_mode": "text",
        "callback": mode.server + 'sandbox/issuer/callback',
        }
    resp = requests.post(api_endpoint, headers=headers, json=data)
    try:
        qrcode = resp.json()['redirect_uri']
    except Exception:
        return jsonify("No qr code")
    return redirect(qrcode) 


def test_14(mode):
    api_endpoint = mode.server + "sandbox/oidc4vc/issuer/api"
    issuer_id = issuer_test(14, mode)
    client_secret = issuer_test(14, mode, secret = True)
   
    vc = 'InsuranceLegalPerson'
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
    resp = requests.post(api_endpoint, headers=headers, json=data)
    try:
        qrcode = resp.json()['redirect_uri']
    except Exception:
        return jsonify("No qr code")
    return redirect(qrcode)


def test_15(mode):
    api_endpoint = mode.server + "sandbox/oidc4vc/issuer/api"
    issuer_id = issuer_test(15, mode)
    client_secret = issuer_test(15, mode, secret = True)
   
    offer = ["DBCGuest", "Pid", "EmailPass"]
    with open('./verifiable_credentials/Pid.json', 'r') as f:
        credential = json.loads(f.read())
    headers = {
        'Content-Type': 'application/json',
        'X-API-KEY': client_secret
    }
    data = { 
        "issuer_id": issuer_id,
        "vc": {
            "Pid" : credential,
            "DBCGuest": build_credential_offered(["DBCGuest"])["DBCGuest"],
            "EmailPass": build_credential_offered(["EmailPass"])["EmailPass"]
        },
        "issuer_state": "test7",
        "credential_type": offer,
        "pre-authorized_code": True,
        "callback": mode.server + 'sandbox/issuer/callback',
        }
    resp = requests.post(api_endpoint, headers=headers, json=data)
    try:
        qrcode = resp.json()['redirect_uri']
    except Exception:
        return jsonify("No qr code")
    return redirect(qrcode) 


def test_16(mode):
    api_endpoint = mode.server + "sandbox/oidc4vc/issuer/api"
    issuer_id = issuer_test(16, mode)
    client_secret = issuer_test(16, mode, secret = True)
   
    offer = ["IBANLegalPerson", "BankAccountBalance"]
    with open('./verifiable_credentials/IBANLegalPerson.jsonld', 'r') as f:
        credential_1 = json.loads(f.read())
    with open('./verifiable_credentials/BankAccountBalance.jsonld', 'r') as f:
        credential_2 = json.loads(f.read())
    headers = {
        'Content-Type': 'application/json',
        'X-API-KEY': client_secret
    }
    data = { 
        "issuer_id": issuer_id,
        "vc": {
            "IBANLegalPerson": credential_1,
            "BankAccountBalance": credential_2
        },
        "issuer_state": "test7",
        "credential_type": offer,
        "pre-authorized_code": True,
        "callback": mode.server + 'sandbox/issuer/callback',
        }
    resp = requests.post(api_endpoint, headers=headers, json=data)
    try:
        qrcode = resp.json()['redirect_uri']
    except Exception:
        return jsonify("No qr code")
    return redirect(qrcode) 


def test_17(mode):
    api_endpoint = mode.server + "sandbox/oidc4vc/issuer/api"
    issuer_id = issuer_test(17, mode)
    client_secret = issuer_test(17, mode, secret = True)
  
    offer = ["Lpid"]
    with open('./verifiable_credentials/Lpid.json', 'r') as f:
        credential = json.loads(f.read())
    headers = {
        'Content-Type': 'application/json',
        'X-API-KEY': client_secret
    }
    data = { 
        "issuer_id": issuer_id,
        "vc": {
            "Lpid": credential,
        },
        "issuer_state": "test17",
        "credential_type": offer,
        "pre-authorized_code": True,
        "callback": mode.server + 'sandbox/issuer/callback',
        }
    resp = requests.post(api_endpoint, headers=headers, json=data)
    try:
        qrcode = resp.json()['redirect_uri']
    except Exception:
        return jsonify("No qr code")
    return redirect(qrcode) 

# Badge employee
def test_18(mode):
    api_endpoint = mode.server + "sandbox/oidc4vc/issuer/api"
    issuer_id = issuer_test(18, mode)
    client_secret = issuer_test(18, mode, secret = True)
  
    offer = ["EmployeeBadge"]
    with open('./verifiable_credentials/EmployeeBadge.json', 'r') as f:
        credential = json.loads(f.read())
    credential['role'] = "employee"
    credential['given_name'] = "Fitz"
    credential['family_name'] = "Arwick"
    headers = {
        'Content-Type': 'application/json',
        'X-API-KEY': client_secret
    }
    data = { 
        "issuer_id": issuer_id,
        "vc": {
            "EmployeeBadge": credential,
        },
        "issuer_state": "test18",
        "credential_type": offer,
        "pre-authorized_code": True,
        "callback": mode.server + 'sandbox/issuer/callback',
        }
    resp = requests.post(api_endpoint, headers=headers, json=data)
    try:
        qrcode = resp.json()['redirect_uri']
    except Exception:
        return jsonify("No qr code")
    return redirect(qrcode) 


# Badge admin
def test_19(mode):
    api_endpoint = mode.server + "sandbox/oidc4vc/issuer/api"
    issuer_id = issuer_test(19, mode)
    client_secret = issuer_test(19, mode, secret = True)
   
    offer = ["EmployeeBadge"]
    with open('./verifiable_credentials/EmployeeBadge.json', 'r') as f:
        credential = json.loads(f.read())
    credential['role'] = "admin"
    credential['given_name'] = "Doug"
    credential['family_name'] = "Bower"
    headers = {
        'Content-Type': 'application/json',
        'X-API-KEY': client_secret
    }
    data = { 
        "issuer_id": issuer_id,
        "vc": {
            "EmployeeBadge": credential,
        },
        "issuer_state": "test19",
        "credential_type": offer,
        "pre-authorized_code": True,
        "callback": mode.server + 'sandbox/issuer/callback',
        }
    resp = requests.post(api_endpoint, headers=headers, json=data)
    try:
        qrcode = resp.json()['redirect_uri']
    except Exception:
        return jsonify("No qr code")
    return redirect(qrcode) 


# Badge legal_representative
def test_20(mode):
    api_endpoint = mode.server + "sandbox/oidc4vc/issuer/api"
    issuer_id = issuer_test(20, mode)
    client_secret = issuer_test(20, mode, secret = True)
  
    offer = ["EmployeeBadge"]
    with open('./verifiable_credentials/EmployeeBadge.json', 'r') as f:
        credential = json.loads(f.read())
    credential['role'] = "legal_representative"
    credential['given_name'] = "Pitt"
    credential['family_name'] = "Warfall"
    headers = {
        'Content-Type': 'application/json',
        'X-API-KEY': client_secret
    }
    data = { 
        "issuer_id": issuer_id,
        "vc": {
            "EmployeeBadge": credential,
        },
        "issuer_state": "test20",
        "credential_type": offer,
        "pre-authorized_code": True,
        "callback": mode.server + 'sandbox/issuer/callback',
        }
    resp = requests.post(api_endpoint, headers=headers, json=data)
    try:
        qrcode = resp.json()['redirect_uri']
    except Exception:
        return jsonify("No qr code")
    return redirect(qrcode) 

# Badge Manager
def test_21(mode):
    api_endpoint = mode.server + "sandbox/oidc4vc/issuer/api"
    issuer_id = issuer_test(21, mode)
    client_secret = issuer_test(21, mode, secret = True)
   
    offer = ["EmployeeBadge"]
    with open('./verifiable_credentials/EmployeeBadge.json', 'r') as f:
        credential = json.loads(f.read())
    credential['role'] = "manager"
    credential['given_name'] = "John"
    credential['family_name'] = "Wick"

    headers = {
        'Content-Type': 'application/json',
        'X-API-KEY': client_secret
    }
    data = { 
        "issuer_id": issuer_id,
        "vc": {
            "EmployeeBadge": credential,
        },
        "issuer_state": "test21",
        "credential_type": offer,
        "pre-authorized_code": True,
        "callback": mode.server + 'sandbox/issuer/callback',
        }
    resp = requests.post(api_endpoint, headers=headers, json=data)
    try:
        qrcode = resp.json()['redirect_uri']
    except Exception:
        return jsonify("No qr code")
    return redirect(qrcode) 


def build_credential_offered(offer):
    """_summary_

    Args:
        offer (_type_): _description_

    Returns:
        _type_: _description_
    """
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


def webhook():
    print("webhook reçu = ", request.json)
    return jsonify('ok')