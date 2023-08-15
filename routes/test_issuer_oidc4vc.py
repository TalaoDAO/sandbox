from flask import Flask, redirect, jsonify, request
import base64
from datetime import datetime, timedelta
import json
import uuid
import requests

REDIRECT = True


def init_app(app,red, mode) :
    app.add_url_rule('/sandbox/issuer/ebsiv2',  view_func=issuer_ebsiv2, methods = ['GET'], defaults={'mode' : mode})

    app.add_url_rule('/sandbox/issuer/hedera',  view_func=issuer_hedera, methods = ['GET'], defaults={'mode' : mode})
    app.add_url_rule('/sandbox/issuer/hedera_2',  view_func=issuer_hedera_2, methods = ['GET'], defaults={'mode' : mode})
    app.add_url_rule('/sandbox/issuer/hedera_30',  view_func=issuer_hedera_3, methods = ['GET'], defaults={'mode' : mode})


    app.add_url_rule('/sandbox/issuer/gaia-x',  view_func=issuer_gaiax, methods = ['GET'], defaults={'mode' : mode})

    app.add_url_rule('/sandbox/issuer/default',  view_func=issuer_default, methods = ['GET'], defaults={'mode' : mode})
    app.add_url_rule('/sandbox/issuer/default_2',  view_func=issuer_default_2, methods = ['GET'], defaults={'mode' : mode}) # test 
    app.add_url_rule('/sandbox/issuer/default_30',  view_func=issuer_default_3, methods = ['GET'], defaults={'mode' : mode}) # test

    app.add_url_rule('/sandbox/issuer/ebsiv3',  view_func=issuer_ebsiv3, methods = ['GET'], defaults={'mode' : mode}) # test 8

    app.add_url_rule('/sandbox/issuer/callback',  view_func=issuer_callback, methods = ['GET'])


def issuer_callback():
    return jsonify("Great ! request = " + json.dumps(request.args))


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
        "pre-authorized_code" : str(uuid.uuid1()),
        "credential_type" : vc,
        "callback" : mode.server + '/sandbox/issuer/callback',
        "redirect" : REDIRECT
        }
    resp = requests.post(api_endpoint, headers=headers, json = data)
    if REDIRECT :
        try :
            qrcode =  resp.json()['redirect_uri']
        except :
            return jsonify("No qr code")
        return redirect(qrcode) 
    else :
        return jsonify(resp.json()['qrcode'])
   


# Test 8
def issuer_ebsiv3(mode):
    if mode.myenv == 'aws' :
        api_endpoint = "https://talao.co/sandbox/ebsi/issuer/api/     "
        client_secret = ""
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
        "pre-authorized_code" : str(uuid.uuid1()),
        "credential_type" : offer,
        "callback" : mode.server + '/sandbox/issuer/callback',
        "redirect" : REDIRECT,
        "user_pin_required" : False
        }
    resp = requests.post(api_endpoint, headers=headers, json = data)
    if REDIRECT :
        try :
            qrcode =  resp.json()['redirect_uri']
        except :
            return jsonify("No qr code")
        return redirect(qrcode) 
    else :
        return jsonify(resp.json()['qrcode'])
   

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
        "pre-authorized_code" : str(uuid.uuid1()),
        "credential_type" : offer,
        "callback" : mode.server + '/sandbox/issuer/callback',
        "redirect" : REDIRECT,
        "user_pin_required" : True,
        "user_pin" : "1000"
        }
    resp = requests.post(api_endpoint, headers=headers, json = data)
    if REDIRECT :
        try :
            qrcode =  resp.json()['redirect_uri']
        except :
            return jsonify("No qr code")
        return redirect(qrcode) 
    else :
        return jsonify(resp.json()['qrcode'])
    

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
        "pre-authorized_code" : str(uuid.uuid1()),
        "credential_type" : offer,
        "callback" : mode.server + '/sandbox/issuer/callback',
        "redirect" : REDIRECT
        }
    resp = requests.post(api_endpoint, headers=headers, json = data)
    if REDIRECT :
        try :
            qrcode =  resp.json()['redirect_uri']
        except :
            return jsonify("No qr code")
        return redirect(qrcode) 
    else :
        return jsonify(resp.json()['qrcode'])


def issuer_default_2(mode):
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
    data = { 
        "vc" : build_credential_offered(offer), 
        "pre-authorized_code" : str(uuid.uuid1()),
        "credential_type" : offer,
        "callback" : mode.server + '/sandbox/issuer/callback',
        "redirect" : REDIRECT
        }
    resp = requests.post(api_endpoint, headers=headers, json = data)
    if REDIRECT :
        try :
            qrcode =  resp.json()['redirect_uri']
        except :
            return jsonify("No qr code")
        return redirect(qrcode) 
    else :
        return jsonify(resp.json()['qrcode'])
    


def issuer_default_3(mode):
    if mode.myenv == 'aws' :
        api_endpoint = "https://talao.co/sandbox/ebsi/issuer/api/cejjvswuep"
        client_secret = "731dc86d-2abb-11ee-825b-9db9eb02bfb8"
    else :       
        api_endpoint = mode.server + "sandbox/ebsi/issuer/api/omjqeppxps"
        client_secret = "731dc86d-2abb-11ee-825b-9db9eb02bfb8"

    offer = ["VerifiableId", "Phoneproof"]

    headers = {
        'Content-Type': 'application/json',
        'Authorization' : 'Bearer ' + client_secret
    }
    data = { 
        "vc" : build_credential_offered(offer), 
        "pre-authorized_code" : str(uuid.uuid1()),
        "credential_type" : offer,
        "callback" : mode.server + '/sandbox/issuer/callback',
        "redirect" : REDIRECT
        }
    resp = requests.post(api_endpoint, headers=headers, json = data)
    if REDIRECT :
        try :
            qrcode =  resp.json()['redirect_uri']
        except :
            return jsonify("No qr code")
        return redirect(qrcode) 
    else :
        return jsonify(resp.json()['qrcode'])


def issuer_gaiax(mode):
    if mode.myenv == 'aws' :
        api_endpoint = "https://talao.co/sandbox/ebsi/issuer/api/mfyttabosy"
        client_secret = "c0ab5d96-3113-11ee-a3e3-0a1628958560"
    else  :
        api_endpoint = mode.server + "sandbox/ebsi/issuer/api/cqmygbreop"
        client_secret = "a71f33f9-3100-11ee-825b-9db9eb02bfb8"

    offer = "EmployeeCredential"
    headers = {
        'Content-Type': 'application/json',
        'Authorization' : 'Bearer ' + client_secret
    }
    data = { 
        "vc" : build_credential_offered(offer), 
        "pre-authorized_code" : str(uuid.uuid1()),
        "credential_type" : offer,
        "callback" : mode.server + '/sandbox/issuer/callback',
        "redirect" : REDIRECT
        }
    resp = requests.post(api_endpoint, headers=headers, json = data)
    if REDIRECT :
        try :
            qrcode =  resp.json()['redirect_uri']
        except :
            return jsonify("No qr code")
        return redirect(qrcode) 
    else :
        return jsonify(resp.json()['qrcode'])


def issuer_hedera(mode):
    if mode.myenv == 'aws' :
        api_endpoint = "https://talao.co/sandbox/ebsi/issuer/api/nkpbjplfbi"
        client_secret = "ed055e57-3113-11ee-a280-0a1628958560"
    
    else :
        api_endpoint = mode.server + "sandbox/ebsi/issuer/api/uxzjfrjptk"
        client_secret = "2675ebcf-2fc1-11ee-825b-9db9eb02bfb8"

    offer = ["EmployeeCredential", "VerifiableId"]
    headers = {
        'Content-Type': 'application/json',
        'Authorization' : 'Bearer ' + client_secret
    }
    data = { 
        "vc" : build_credential_offered(offer), 
        "pre-authorized_code" : str(uuid.uuid1()),
        "credential_type" : offer,
        "callback" : mode.server + '/sandbox/issuer/callback',
        "redirect" : REDIRECT
        }
    resp = requests.post(api_endpoint, headers=headers, json = data)
    if REDIRECT :
        try :
            qrcode =  resp.json()['redirect_uri']
        except :
            return jsonify("No qr code")
        return redirect(qrcode) 
    else :
        return jsonify(resp.json()['qrcode'])
   

def issuer_hedera_2(mode):
    if mode.myenv == 'aws' :
        api_endpoint = "https://talao.co/sandbox/ebsi/issuer/api/gxstfttnum"
        client_secret = "ed055e57-3113-11ee-a280-0a1628958560"
    
    else :
        api_endpoint = mode.server + "sandbox/ebsi/issuer/api/fixmtbwkfr"
        client_secret = "2675ebcf-2fc1-11ee-825b-9db9eb02bfb8"

    offer = ["GreencypherPass", 'ListOfProjects']
    headers = {
        'Content-Type': 'application/json',
        'Authorization' : 'Bearer ' + client_secret
    }
    data = { 
        "vc" : build_credential_offered(offer), 
        "pre-authorized_code" : str(uuid.uuid1()),
        "credential_type" : offer,
        "callback" : mode.server + '/sandbox/issuer/callback',
        "redirect" : REDIRECT
        }
    resp = requests.post(api_endpoint, headers=headers, json = data)
    if REDIRECT :
        try :
            qrcode =  resp.json()['redirect_uri']
        except :
            return jsonify("No qr code")
        return redirect(qrcode) 
    else :
        return jsonify(resp.json()['qrcode'])


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

# Python Flask http server loop
if __name__ == '__main__':
    IP = "127.0.0.1"
    app.run( host = IP, port=4000, debug =True)
