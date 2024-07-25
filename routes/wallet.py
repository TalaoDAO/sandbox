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
from wallet_db_api import create_wallet_credential, list_wallet_credential, list_wallet_issuer
logging.basicConfig(level=logging.INFO)
from wallet_for_backend import get_wallet_configuration
import uuid

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

pub_key = {
    "crv": "P-256",
    "kty": "EC",
    "kid": wallet_key.thumbprint(),
    "x": "ngy44T1vxAT6Di4nr-UaM9K3Tlnz9pkoksDokKFkmNc",
    "y": "QCRfOKlSM31GTkb4JHx3nXB4G_jSPMsbdjzlkT_UpPc",
}


pub_key_json = json.dumps(pub_key).replace(" ", "")
DID = "did:jwk:" + base64.urlsafe_b64encode(pub_key_json.encode()).decode().replace("=", "")
VM = DID + "#0"


def init_app(app, red, mode):
    app.add_url_rule('/wallet', view_func=wallet, methods=['GET', 'POST'])
    app.add_url_rule('/wallet/issuer', view_func=wallet_issuer, methods=['GET', 'POST']) # discover
    app.add_url_rule('/wallet/verifier', view_func=wallet_verifier, methods=['GET', 'POST'])
    app.add_url_rule('/wallet/credential/select', view_func=credential_select, methods=['GET', 'POST'])
    app.add_url_rule('/wallet/qeea/select', view_func=QEEA_select, methods=['GET', 'POST'], defaults={'red': red, 'mode': mode})

    app.add_url_rule('/wallet/callback', view_func=callback, methods=['GET', 'POST'], defaults={'red': red, 'mode': mode})

    app.add_url_rule('/wallet/login', view_func=wallet_login, methods=['GET', 'POST'])

    app.add_url_rule('/wallet/.well-known/openid-configuration', view_func=web_wallet_openid_configuration, methods=['GET'])
    return


def update_logo():
    f = open("wallet_configuration.json", 'r')
    config = json.loads(f.read())
    return config["generalOptions"]["companyLogo"]


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
    return render_template(
        "wallet/wallet_issuer.html",
        issuer_list=issuer_list,
        title="Discover",
        logo=update_logo()
    )

    
def wallet_verifier():
    if request.method == 'GET':
        return render_template('wallet/wallet_verifier.html')


def wallet_login():
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
    if request.method == 'GET':
        if not session.get("wallet_connected"):
            if not request.args:
                return redirect('/wallet/login')
            redirect_uri = '/wallet/login?' + urlencode(request.args)
            return redirect(redirect_uri)
        else:
            if not request.args:
                my_list = list_wallet_credential()
                credential_list = ""
                for credential in my_list:
                    token = json.loads(credential)['credential']
                    id = json.loads(credential)['id']
                    payload = get_payload_from_token(token)
                    vc_type = payload["vc"]['type']
                    for vc in vc_type:
                        if vc != "VerifiableCredential":
                            break
                    exp = str(date.fromtimestamp(payload['exp']))
                    iat = str(date.fromtimestamp(payload['iat']))
                    cred = """<tr>
                    <td><a href="/wallet/credential?id=""" + id + """">""" + vc + """</a></td>
                    <td>""" + payload['jti'] + """...</td>
                    <td>""" + exp + """</td>
                    <td>""" + iat + """</td>
                    <td>""" + "Active" + """</td>
                    <td>""" + payload["iss"] + """...</td>
                    </tr>"""
                    credential_list += cred
                return render_template(
                    "wallet/wallet_credential.html",
                    credential_list=credential_list,
                    title="My Wallet",
                    logo=update_logo()
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
                    issuer=issuer
                )


def credential_select():
    """
    Issuer initiated with pre authorized code
    """
    vc = request.form.get("vc")
    issuer = request.form.get("issuer")
    issuer_config_url = issuer + '/.well-known/openid-credential-issuer'
    issuer_config = requests.get(issuer_config_url).json()
    credential_metadata = json.dumps(issuer_config['credential_configurations_supported'][vc])
    pre_authorized_code = request.form.get("pre_authorized_code")
    vc_format = credential_metadata['format']
    if vc_format == "vc+sd-jwt":
        vct = credential_metadata['credential_definition']['vct']
        vc_type = None
    else:
        vc_type = credential_metadata['credential_definition']['type']
        vct = None
    credential =  pre_authorized_code_flow(issuer, pre_authorized_code, vct, vc_type, vc_format) 
    if credential:
        create_wallet_credential(
            {
                "credential": credential,
                "metadata": credential_metadata
            }
        )
    return redirect("/wallet")   


def QEEA_select(red, mode):
    """
    Wallet initiated with authorization code flow
    
    """
    f = open("wallet_configuration.json", 'r')
    config = json.loads(f.read())
    my_list = config["discoverCardsOptions"]["displayExternalIssuer"]
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
            href = build_authorization_request(issuer, scope, red, mode)
            attestation = """<tr>
                <td>""" + name + """</td>
                <td><a href=""" + href +">" + cred + """</a></td>
                <td>""" + description + """</td>
                </tr>"""
            cred_list += attestation
    return render_template(
        "wallet/offer_select.html",
        cred_list=cred_list,
        title="Select an offer"
    )


def build_authorization_request(issuer, scope, red, mode) -> str:
    """
    Build and authorization request
    """
    issuer_config_url = issuer + '/.well-known/openid-credential-issuer'
    issuer_config = requests.get(issuer_config_url).json()
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
            "scope": scope
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
    
    # access token request
    logging.info('This is a pre_authorized-code flow')
    result = token_request(issuer, code)
    logging.info('token endpoint response = %s', result)
    if result.get('error'):
        logging.warning('token endpoint error return code = %s', result)
        sys.exit()

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




def token_request(issuer, code, grant_type='urn:ietf:params:oauth:grant-type:pre-authorized_code'):
    issuer_config_url = issuer + '/.well-known/openid-credential-issuer'
    issuer_config = requests.get(issuer_config_url).json()
    if issuer_config.get("authorization_server"):
        authorization_server_url = issuer + '/.well-known/openid-configuration'
        authorization_server_config = requests.get(authorization_server_url).json()
        token_endpoint = authorization_server_config['token_endpoint']
    else:
        token_endpoint = issuer_config['token_endpoint']
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    data = {
        "grant_type": grant_type,
        "client_id": DID,
        "redirect_uri": "WALLET_REDIRECT_URI",
    }
    # depending on the grant type
    if grant_type == 'urn:ietf:params:oauth:grant-type:pre-authorized_code':
        data["pre-authorized_code"] = code
    else:
        logging.error("grant type is unknown")
        return
    
    logging.info("token request data = %s", data)
    resp = requests.post(token_endpoint, headers=headers, data = data)
    logging.info("status_code token endpoint = %s", resp.status_code)
    if resp.status_code > 399:
        print("error sur le token endpoint = ", resp.content)
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
def  pre_authorized_code_flow(issuer, code, vct, type, format):
    # access token request
    logging.info('This is a pre_authorized-code flow')
    result = token_request(issuer, code)
    logging.info('token endpoint response = %s', result)
    if result.get('error'):
        logging.warning('token endpoint error return code = %s', result)
        sys.exit()

    # access token received
    access_token = result["access_token"]
    c_nonce = result.get("c_nonce", "")
    logging.info('access token received = %s', access_token)
    
    #build proof of key ownership
    proof = build_proof_of_key(KEY_DICT, DID, VM, issuer , c_nonce)
    logging.info("proof of key ownership sent = %s", proof)

    # credential request
    result = credential_request(issuer, access_token, vct, type, format, proof)

    if result.get('error'):
        logging.warning('credential endpoint error return code = %s', result)
        return
    # credential received
    logging.info("'credential endpoint response = %s", result)  
    return result["credential"]


# authorization code flow
def  authorization_code_flow(issuer, scope, vct, type, format):
    # authorization request
    
    
    # access token request
    logging.info('This is an authorization code flow')
    result = token_request(issuer, code)
    logging.info('token endpoint response = %s', result)
    if result.get('error'):
        logging.warning('token endpoint error return code = %s', result)
        sys.exit()

    # access token received
    access_token = result["access_token"]
    c_nonce = result.get("c_nonce", "")
    logging.info('access token received = %s', access_token)
    
    #build proof of key ownership
    proof = build_proof_of_key(KEY_DICT, DID, VM, issuer , c_nonce)
    logging.info("proof of key ownership sent = %s", proof)

    # credential request
    result = credential_request(issuer, access_token, vct, type, format, proof)

    if result.get('error'):
        logging.warning('credential endpoint error return code = %s', result)
        return
    # credential received
    logging.info("'credential endpoint response = %s", result)  
    return result["credential"]

