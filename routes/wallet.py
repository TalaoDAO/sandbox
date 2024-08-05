"""

issuance https://dutchblockchaincoalition.github.io/CompanyPassport/technical/issuance

"""



import base64
from flask import Flask, request, jsonify, render_template, redirect, session
from jwcrypto import jwk, jwt
import requests
import json
from datetime import date
import sys
from urllib.parse import urlencode
import pkce
import logging
from datetime import datetime
from oidc4vc import get_payload_from_token 
from wallet_db_api import create_wallet_credential, list_wallet_credential, delete_wallet_credential
logging.basicConfig(level=logging.INFO)
from wallet_for_backend import get_wallet_configuration, get_wallet_attestation
import uuid
import copy
from datetime import datetime, timedelta


# wallet key for testing purpose

KEY_DICT = {
    "kty": "EC",
    "d": "d_PpSCGQWWgUc1t4iLLH8bKYlYfc9Zy_M7TsfOAcbg8",
    "crv": "P-256",
    "x": "ngy44T1vxAT6Di4nr-UaM9K3Tlnz9pkoksDokKFkmNc",
    "y": "QCRfOKlSM31GTkb4JHx3nXB4G_jSPMsbdjzlkT_UpPc",
    "alg": "ES256",
}
wallet_key = jwk.JWK(**KEY_DICT)
KEY_DICT['kid'] = wallet_key.thumbprint()
pub_key = copy.copy(KEY_DICT)
del pub_key['d']


pub_key_json = json.dumps(pub_key).replace(" ", "")
DID = "did:jwk:" + base64.urlsafe_b64encode(pub_key_json.encode()).decode().replace("=", "")
VM = DID + "#0"


def init_app(app, red, mode):
    app.add_url_rule('/wallet', view_func=wallet, methods=['GET'])
    app.add_url_rule('/wallet/issuer', view_func=wallet_issuer, methods=['GET', 'POST']) # discover
    app.add_url_rule('/wallet/verifier', view_func=wallet_verifier, methods=['GET', 'POST'])
    app.add_url_rule('/wallet/credential/select', view_func=credential_select, methods=['GET', 'POST'],  defaults={'mode': mode})
    app.add_url_rule('/wallet/qeea/select', view_func=QEEA_select, methods=['GET', 'POST'], defaults={'red': red, 'mode': mode})
    app.add_url_rule('/wallet/about', view_func=about, methods=['GET'])
    app.add_url_rule('/wallet/credential', view_func=credential, methods=['GET', 'POST'])
    app.add_url_rule('/wallet/personal', view_func=personal, methods=['GET', 'POST'], defaults={'mode': mode})

    app.add_url_rule('/wallet/get_attestation', view_func=get_attestation, methods=['GET', 'POST'], defaults={'red': red, 'mode': mode})
    app.add_url_rule('/wallet/update_configuration', view_func=update_configuration, methods=['GET', 'POST'], defaults={'red': red, 'mode': mode})

    app.add_url_rule('/wallet/callback', view_func=callback, methods=['GET', 'POST'], defaults={'red': red, 'mode': mode})

    app.add_url_rule('/wallet/login', view_func=wallet_login, methods=['GET', 'POST'], defaults={'mode': mode})

    app.add_url_rule('/wallet/.well-known/openid-configuration', view_func=web_wallet_openid_configuration, methods=['GET'])
    return

def get_attestation(red, mode):
    get_wallet_attestation()
    return redirect('/wallet')


def update_configuration(red, mode):
    get_wallet_configuration()
    return redirect('/wallet')


def get_configuration():
    f = open("wallet_configuration.json", 'r')
    return json.loads(f.read())


def credential():
    if request.method == 'POST':
        if request.form["button"] == "delete":
            id = request.args['id']
            delete_wallet_credential(id)
        return redirect('/wallet')
    id = request.args['id']
    my_list = list_wallet_credential()
    for credential in my_list:
        if id == json.loads(credential)['id'] == id:
            token = json.loads(credential)['credential']
            payload = get_payload_from_token(token)
            break
    f = open("wallet_configuration.json", 'r')
    config = json.loads(f.read())['generalOptions']
    logo = config["companyLogo"]
    title = config["splashScreenTitle"]
    color = config[ "primaryColor"]
    return render_template(
        'wallet/credential_display.html',
        credential=json.dumps(payload, indent=4),
        color=color,
        title=title,
        logo=logo,
        id=id
        
    )

def about():
    f = open("wallet_configuration.json", 'r')
    config = json.loads(f.read())['generalOptions']
    logo = config["companyLogo"]
    title = config["splashScreenTitle"]
    color = config[ "primaryColor"]
    return render_template(
        'wallet/wallet_about.html',
        about=json.dumps(config, indent=4),
        color=color,
        title=title,
        logo=logo
        
    )


def personal(mode):
    f = open("wallet_configuration.json", 'r')
    config = json.loads(f.read())['generalOptions']
    logo = config["companyLogo"]
    title = config["splashScreenTitle"]
    color = config[ "primaryColor"]
    if not request.args.get('certificate'):
        return render_template(
            'wallet/personal_issuer.html',
            logo=logo,
            title=title,
            color=color
            )
    else:
        certificate = request.args['certificate']
        api_endpoint = mode.server + "sandbox/oidc4vc/issuer/api"
        if mode.myenv == 'aws':
            issuer_id = "tdiwmpyhzc"
            client_secret = "5972a3b8-45c3-11ee-93f5-0a1628958560"
        else: 
            issuer_id = "raamxepqex"
            client_secret = "5381c36b-45c2-11ee-ac39-9db132f0e4a1"
        offer = [certificate]
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
            qrcode_value_uri = resp.json()['qrcode_value']
        except Exception:
            return jsonify("No qr code")
        resp = requests.get(qrcode_value_uri)
        url = resp.json()['qrcode_value']
        return render_template(
            'wallet/personal.html',
            url=url,
            color=color,
            title=title,
            logo=logo
        )



def web_wallet_openid_configuration():
    config = {
        "credential_offer_endpoint": "/wallet"        
    }
    return jsonify(config)


def wallet_issuer():
    f = open("wallet_configuration.json", 'r')
    config = json.loads(f.read())
    my_list = config["discoverCardsOptions"]["displayExternalIssuer"] 
    issuer_list = ""
    for issuer in my_list:
        name = issuer["title"]
        description = issuer["description"]
        url = issuer['redirect']
        href = "/wallet/qeea/select?url=" + url
        iss = """<tr>
            <td>""" + "<a href=" + href + ">" + name + """</td>
            <td>""" + description + """</td>
            <td>""" + url + """</td>
            <td>""" + "contact@test.com" + """...</td>
            </tr>"""
        issuer_list += iss
    logo = get_configuration()["generalOptions"]["companyLogo"]
    title = get_configuration()["generalOptions"]["splashScreenTitle"]
    color = get_configuration()["generalOptions"][ "primaryColor"]
    return render_template(
        "wallet/wallet_issuer.html",
        issuer_list=issuer_list,
        title=title,
        logo=logo,
        color=color
    )

    
def wallet_verifier():
    if request.method == 'GET':
        return render_template('wallet/wallet_verifier.html')


def wallet_login(mode):
    if request.method == 'GET':
        credential_offer = request.args.get('credential_offer',"")
        credential_offer_uri = request.args.get('credential_offer_uri', "")
        return render_template(
            "wallet/wallet_login.html",
            credential_offer_uri=credential_offer_uri,
            credential_offer=credential_offer,
            title="My Wallet"
        )
    else:
        if request.form['button'] == "eudi":
            if mode.myenv == 'aws':
                client_id = "mnpqhqqrlw"
            else:
                client_id = "nyudzjxuhj"
            url = mode.server + "sandbox/verifier/app/authorize?client_id=" + client_id + "&scope=openid&response_type=id_token&response_mode=query&redirect_uri=" + mode.server + "sandbox/verifier/callback3"
            return redirect(url)
        session["wallet_connected"] = True
        #get_wallet_configuration()
        credential_offer = request.form.get('credential_offer')
        credential_offer_uri = request.form.get('credential_offer_uri')
        if credential_offer:
            redirect_uri = '/wallet?' + urlencode({"credential_offer": credential_offer})
        elif credential_offer_uri:
            redirect_uri = '/wallet?' + urlencode({"credential_offer_uri": credential_offer_uri})
        else:
            redirect_uri = '/wallet'
        return redirect(redirect_uri)


def wallet():
    if not session.get("wallet_connected"):
        if not request.args:
            return redirect('/wallet/login')
        redirect_uri = '/wallet/login?' + urlencode(request.args)
        return redirect(redirect_uri)
    else:
        title = get_configuration()["generalOptions"]["splashScreenTitle"]
        color = get_configuration()["generalOptions"][ "primaryColor"]
        logo = get_configuration()["generalOptions"]["companyLogo"]
        if not request.args:
            my_list = list_wallet_credential()
            credential_list = ""
            for credential in my_list:
                token = json.loads(credential)['credential']
                display = json.loads(json.loads(credential)['metadata'])["display"]
                id = json.loads(credential)['id']
                payload = get_payload_from_token(token)
                vc_type = payload["vc"]['type']
                for vc in vc_type:
                    if vc != "VerifiableCredential":
                        break
                exp = str(date.fromtimestamp(payload['exp']))
                iat = str(date.fromtimestamp(payload['iat']))
                try:
                    src = display[0]["background_image"]["url"]
                    name = display[0]["name"]
                    image = """<a href="/wallet/credential?id=""" + id + """"><img  src=" """ + src + """ " style="width: 150px;border-radius:5px;"></a> """
                except Exception:
                    image = "No image"
                cred = """<tr>
                    <td>""" + image + """</td>
                    <td>""" + name + """</td>
                    <td> QEAA </td>
                    <td>""" + iat + """</td>
                    <td>""" + exp + """</td>
                    <td>""" + "Active" + """</td>
                    </tr>"""
                credential_list += cred
            return render_template(
                "wallet/wallet_credential.html",
                credential_list=credential_list,
                title=title,
                color=color,
                logo=logo
            )
        else:
            # Issuer initiated with pre authorized code
            if request.args.get('credential_offer_uri'):
                r = requests.get(request.args.get('credential_offer_uri'))
                credential_offer = r.json()
                if r.status_code == 404:
                    return jsonify('credential offer expired')
            elif request.args.get('credential_offer'):
                credential_offer = json.loads(request.args.get('credential_offer'))
            else:
                return redirect("/wallet")
            logging.info("credential offer = %s", credential_offer)
            credentials = credential_offer['credential_configuration_ids']
            issuer = credential_offer['credential_issuer']
            pre_authorized_code = credential_offer['grants'].get('urn:ietf:params:oauth:grant-type:pre-authorized_code', [{}])['pre-authorized_code']
            credential_2_select = ""
            for vc in credentials:
                credential_2_select += "<option value=" + vc + ">" + vc + "</option>"
            return render_template(
                "wallet/credential_select.html",
                credential_2_select=credential_2_select,
                pre_authorized_code=pre_authorized_code,
                issuer=issuer,
                logo=logo,
                title=title,
                color=color
            )


def credential_select(mode):
    """
    Issuer initiated with pre authorized code
    """
    vc = request.form.get("vc")
    issuer = request.form.get("issuer")
    issuer_config_url = issuer + '/.well-known/openid-credential-issuer'
    issuer_config = requests.get(issuer_config_url).json()
    credential_metadata = issuer_config['credential_configurations_supported'][vc]
    logging.info("credential configuration = %s", json.dumps(issuer_config['credential_configurations_supported'], indent=4))
    pre_authorized_code = request.form.get("pre_authorized_code")
    vc_format = credential_metadata['format']
    if vc_format == "vc+sd-jwt":
        vct = credential_metadata['credential_definition']['vct']
        vc_type = None
    else:
        vc_type = credential_metadata['credential_definition']['type']
        vct = None
    credential = pre_authorized_code_flow(issuer, pre_authorized_code, vct, vc_type, vc_format, mode) 
    if credential:
        create_wallet_credential(
            {
                "credential": credential,
                "metadata": json.dumps(credential_metadata)
            }
        )
    return redirect("/wallet")   


def QEEA_select(red, mode):
    """
    Wallet initiated with authorization code flow
    
    """
    my_list = get_configuration()["discoverCardsOptions"]["displayExternalIssuer"]
    if request.args.get('url'):
        for issuer in my_list:
            if issuer['redirect'] == request.args.get('url'):
                my_list = [issuer]
                break
    cred_list = ""
    for issuer in my_list:
        name = issuer["title"]
        description = issuer["description"]
        issuer = issuer['redirect']
        issuer_config_url = issuer + '/.well-known/openid-credential-issuer'
        issuer_config = requests.get(issuer_config_url).json()
        offer_list = issuer_config['credential_configurations_supported'].keys()
        for cred in offer_list:
            description = issuer_config['credential_configurations_supported'][cred]["display"][0].get("description", "No description")
            scope = issuer_config['credential_configurations_supported'][cred]["scope"]
            href = build_authorization_request(issuer, scope, red, mode, issuer_config)
            cred_name = issuer_config['credential_configurations_supported'][cred]["display"][0]["name"]
            attestation = """<tr>
                <td><a href=""" + href +">" + cred_name + """</a></td>
                <td>""" + description + """</td>
                </tr>"""
            cred_list += attestation
    title = get_configuration()["generalOptions"]["splashScreenTitle"]
    logo = get_configuration()["generalOptions"]["companyLogo"]
    color = get_configuration()["generalOptions"][ "primaryColor"]
    return render_template(
        "wallet/offer_select.html",
        cred_list=cred_list,
        title=title,
        logo=logo,
        color=color,
        name=name
    )


def build_authorization_request(issuer, scope, red, mode, issuer_config) -> str:
    """
    Build and authorization request
    """
    authorization_endpoint = issuer_config['authorization_endpoint']
    code_verifier, code_challenge = pkce.generate_pkce_pair()
    state = str(uuid.uuid1())
    data = {
        "redirect_uri": mode.server + 'wallet/callback',
        "client_id": DID, 
        "scope": scope,
        "response_type": "code",
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "state": state
    }
    red.setex(state, 1000, json.dumps(
        {
            "issuer": issuer,
            "scope": scope,
            "code_verifier": code_verifier
        })
    )
    redirect_uri = authorization_endpoint + '?' + urlencode(data)
    
    return redirect_uri


def callback(red, mode):
    """
    For authorization code flow call back, wallet intiated flow 
    
    """
    code = request.args['code']
    state = request.args.get('state')
    data = json.loads(red.get(state).decode())
    issuer = data['issuer']
    scope = data['scope']
    code_verifier = data.get('code_verifier')
    
    # access token request
    logging.info('This is a authorized code flow')
    result = token_request(issuer, code, 'authorization_code', mode, code_verifier)
    logging.info('token endpoint response = %s', result)
    if result.get('error'):
        logging.warning('token endpoint error return code = %s', result)
        return redirect("/wallet") 

    # access token received
    access_token = result["access_token"]
    c_nonce = result.get("c_nonce", "")
    logging.info('access token received = %s', access_token)
    
    #build proof of key ownership
    proof = build_proof_of_key(KEY_DICT, DID, VM, issuer , c_nonce)
    logging.info("proof of key ownership sent = %s", proof)

    # credential request
    issuer_config_url = issuer + '/.well-known/openid-credential-issuer'
    issuer_config = requests.get(issuer_config_url).json()
    vc_list = issuer_config['credential_configurations_supported'].keys()
    for vc in vc_list:
        if issuer_config['credential_configurations_supported'][vc]['scope'] == scope:
            break
    credential_metadata = issuer_config['credential_configurations_supported'][vc]
    vc_format = credential_metadata['format']
    if vc_format == "vc+sd-jwt":
        vct = credential_metadata['credential_definition']['vct']
        type = None
    else:
        type = credential_metadata['credential_definition']['type']
        vct = None
    result = credential_request(issuer, access_token, vct, type, vc_format, proof)

    if result.get('error'):
        logging.warning('credential endpoint error return code = %s', result)
        return
    # credential received
    logging.info("'credential endpoint response = %s", result)  
    credential = result["credential"]
    if credential:
        create_wallet_credential(
            {
                "credential": credential,
                "metadata": json.dumps(credential_metadata)
            }
        )
    return redirect("/wallet")     


def token_request(issuer, code, grant_type, mode, code_verifier):
    issuer_config_url = issuer + '/.well-known/openid-credential-issuer'
    issuer_config = requests.get(issuer_config_url).json()
    logging.info("issuer configuration = %s", json.dumps(issuer_config, indent=4))
    if issuer_config.get("authorization_server"):
        authorization_server_url = issuer + '/.well-known/openid-configuration'
        authorization_server_config = requests.get(authorization_server_url).json()
        logging.info("authorization server configuration = %s", json.dumps(authorization_server_config, indent=4))
        token_endpoint = authorization_server_config['token_endpoint']
    else:
        token_endpoint = issuer_config['token_endpoint']
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    data = {
        "grant_type": grant_type,
        "client_id": DID,
        "redirect_uri": mode.server + "wallet/callback",
    }
    # depending on the grant type
    if grant_type == 'urn:ietf:params:oauth:grant-type:pre-authorized_code':
        data["pre-authorized_code"] = code
    elif grant_type == 'authorization_code':
        data['code'] = code
        data['code_verifier'] = code_verifier
    else:
        logging.error("grant type is unknown")
        return
    
    logging.info("token request data = %s", data)
    logging.info("token endpoint =%s", token_endpoint)
    try:
        resp = requests.post(token_endpoint, headers=headers, data = data)
    except Exception:
            logging.error("Request error = %s", str(e))
            return
    logging.info("status_code token endpoint = %s", resp.status_code)
    if resp.status_code > 399:
        logging.warning("status code = %s", resp.status_code)
    logging.info("token endpoint response = %s", resp.json())
    return resp.json()


def credential_request(issuer, access_token, vct, type, format, proof):
    issuer_config_url = issuer + '/.well-known/openid-credential-issuer'
    issuer_config = requests.get(issuer_config_url).json()
    credential_endpoint = issuer_config['credential_endpoint']
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + access_token
        }
    
    data = { 
        "format": format,
        "proof": {
            "proof_type": "jwt",
            "jwt": proof
        },
        "credential_definition": {}
    }
    if format == "vc+sd-jwt":
        data["credential_definition"] = {"vct": vct}
    else:
        data["credential_definition"] = {"type": type}

    logging.info('credential endpoint request = %s', data)
    resp = requests.post(credential_endpoint, headers=headers, data = json.dumps(data))
    logging.info('status code credential endpoint = %s', resp.status_code)
    if resp.status_code > 399:
        logging.error(resp.content)
    logging.info("credential endpoint response = %s", resp.json())
    return resp.json()


def build_proof_of_key(key, iss, kid, aud, nonce):
    key = json.loads(key) if isinstance(key, str) else key
    signer_key = jwk.JWK(**key) 
    header = {
        'typ': 'openid4vci-proof+jwt',
        'alg': 'ES256',
        "kid": kid
    }

    payload = {
        'iss': iss,
        'nonce': nonce,
        'iat': datetime.timestamp(datetime.now()),
        'aud': aud  # Credential Issuer URL
    }  
    token = jwt.JWT(header=header, claims=payload, algs=['ES256'])
    token.make_signed_token(signer_key)
    return token.serialize()


# pre authorized code
def  pre_authorized_code_flow(issuer, code, vct, type, format, mode):
    # access token request
    logging.info('This is a pre_authorized-code flow')
    result = token_request(issuer, code, 'urn:ietf:params:oauth:grant-type:pre-authorized_code', mode, None)
    logging.info('token endpoint response = %s', result)
    if result.get('error'):
        logging.warning('token endpoint error return code = %s', result)
        sys.exit()

    # access token received
    access_token = result["access_token"]
    c_nonce = result.get("c_nonce", "")
    logging.info('access token received = %s', access_token)
    
    #build proof of key ownership
    proof = build_proof_of_key(KEY_DICT, DID, VM, issuer, c_nonce)
    logging.info("proof of key ownership sent = %s", proof)

    # credential request
    result = credential_request(issuer, access_token, vct, type, format, proof)

    if result.get('error'):
        logging.warning('credential endpoint error return code = %s', result)
        return "Error"
    # credential received
    logging.info("credential endpoint response = %s", result)  
    return result["credential"]


# authorization code flow
def authorization_code_flow(issuer, scope, vct, type, format):
    # authorization request
    
    # access token request
    logging.info('This is an authorization code flow')
    result = token_request(issuer, code)
    logging.info('token endpoint response = %s', result)
    if result.get('error'):
        logging.warning('token endpoint error return code = %s', result)
        sys.exit()
    access_token = result["access_token"]
    c_nonce = result.get("c_nonce", "")
    logging.info('access token received = %s', access_token)
    
    #build proof of key ownership
    proof = build_proof_of_key(KEY_DICT, DID, VM, issuer, c_nonce)
    logging.info("proof of key ownership sent = %s", proof)

    # credential request
    result = credential_request(issuer, access_token, vct, type, format, proof)
    if result.get('error'):
        logging.warning('credential endpoint error return code = %s', result)
        return
    logging.info("'credential endpoint response = %s", result)  
    return result["credential"]


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