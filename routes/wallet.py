import base64
from flask import Flask, request, jsonify, render_template, redirect, session
from jwcrypto import jwk, jwt
import requests
import json
from datetime import date
import sys
from urllib.parse import urlencode

import logging
from datetime import datetime
from oidc4vc import get_payload_from_token 
from wallet_db_api import create_wallet_credential, list_wallet_credential, list_wallet_issuer
logging.basicConfig(level=logging.INFO)


# wallet key for testing purpose

KEY_DICT = {
    "kty" : "EC",
    "d" : "d_PpSCGQWWgUc1t4iLLH8bKYlYfc9Zy_M7TsfOAcbg8",
    "crv" : "P-256",
    "x" : "ngy44T1vxAT6Di4nr-UaM9K3Tlnz9pkoksDokKFkmNc",
    "y" : "QCRfOKlSM31GTkb4JHx3nXB4G_jSPMsbdjzlkT_UpPc",
    "alg" : "ES256",
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
    app.add_url_rule('/wallet', view_func=wallet, methods=['GET', 'POST'], defaults={'red': red, 'mode': mode})
    app.add_url_rule('/wallet/issuer', view_func=wallet_issuer, methods=['GET', 'POST'], defaults={'red': red, 'mode': mode})
    app.add_url_rule('/wallet/verifier', view_func=wallet_verifier, methods=['GET', 'POST'], defaults={'red': red, 'mode': mode})
    app.add_url_rule('/wallet/credential/select', view_func=credential_select, methods=['GET', 'POST'])
    app.add_url_rule('/wallet/offer/select/<issuer_id>', view_func=offer_select, methods=['GET', 'POST'])

    app.add_url_rule('/wallet/login', view_func=wallet_login, methods=['GET', 'POST'])

    app.add_url_rule('/wallet/.well-known/openid-configuration', view_func=web_wallet_openid_configuration, methods=['GET'])
    return


def web_wallet_openid_configuration():
    config = {
        "credential_offer_endpoint": "/wallet"        
    }
    return jsonify(config)


def wallet_issuer(red, mode):
    if request.method == 'GET':
        my_list = list_wallet_issuer()
        issuer_list = ""
        for issuer in my_list:
            name = json.loads(issuer)["name"]
            url = json.loads(issuer)['url']
            issuer_id = json.loads(issuer)['id']
            href = "/wallet/offer/select/" + issuer_id 
            iss = """<tr>
                <td>""" + "<a href=" + href + ">" + name + """</td>
                <td>""" + url + """</td>
                <td>""" + "contact@test.com" + """...</td>
                </tr>"""
            issuer_list += iss
        return render_template(
            "wallet/wallet_issuer.html",
            issuer_list=issuer_list,
            title="Discover"
            )
    else:
        return redirect("/wallet")
    
def wallet_verifier(red, mode):
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
        credential_offer = request.form.get('credential_offer')
        credential_offer_uri = request.form.get('credential_offer_uri')
        if credential_offer:
            redirect_uri = '/wallet?' + urlencode({"credential_offer": credential_offer})
        elif credential_offer_uri:
            redirect_uri = '/wallet?' + urlencode({"credential_offer_uri": credential_offer_uri})
        else:
            redirect_uri = '/wallet'
        return redirect(redirect_uri)


def wallet(red, mode):
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
                    payload = get_payload_from_token(token)
                    vc_type = payload["vc"]['type']
                    for vc in vc_type:
                        if vc != "VerifiableCredential":
                            break
                    exp = str(date.fromtimestamp(payload['exp']))
                    iat = str(date.fromtimestamp(payload['iat']))
                    cred = """<tr>
                    <td>""" + vc + """</td>
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
                    title="My Wallet"
                )
            else:
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
    vc = request.form.get("vc")
    issuer = request.form.get("issuer")
    issuer_config_url = issuer + '/.well-known/openid-credential-issuer'
    issuer_config = requests.get(issuer_config_url).json()
    metadata = json.dumps(issuer_config['credential_configurations_supported'][vc])
    pre_authorized_code = request.form.get("pre_authorized_code")
    credential = get_credential(vc, issuer, pre_authorized_code)
    if credential:
        create_wallet_credential(
            {
                "credential": credential,
                "metadata": metadata
            }
        )
    return redirect("/wallet")   


def offer_select(issuer_id):
    if request.method == 'GET':
        issuer_list = list_wallet_issuer()
        for iss in issuer_list:
            if issuer_id == json.loads(iss)['id']:
                issuer = json.loads(iss)['url']
                break
        issuer_config_url = issuer + '/.well-known/openid-credential-issuer'
        issuer_config = requests.get(issuer_config_url).json()
        offer_list = issuer_config['credential_configurations_supported'].keys()
        offer_select_list = ""
        for offer in offer_list:
            offer_select_list += "<option value=" + offer + ">" + offer + "</option>"
        return render_template(
            "wallet/offer_select.html",
            offer_select_list=offer_select_list,
            title="Select an offer",
            issuer_id=issuer_id
        )
    else:
        offer = request.form.get("offer")
        print("offer selected = ", offer)
        return jsonify(offer)



def get_credential(credential, issuer, pre_authorized_code):
    issuer_config_url = issuer + '/.well-known/openid-credential-issuer'
    issuer_config = requests.get(issuer_config_url).json()
    #print("issuer config = ", issuer_config)
    vc = issuer_config['credential_configurations_supported'][credential]
    print("vc = ", vc)
    vc_format = vc['format']
    if vc_format == "vc+sd-jwt":
        vct = vc['credential_definition']['vct']
        vc_type = None
    else:
        vc_type = vc['credential_definition']['type']
        vct = None
    print('this is a pre authorized code flow')
    return pre_authorized_code_flow(issuer, pre_authorized_code, vct, vc_type, vc_format) 


def token_request(issuer, code) :
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
        "grant_type" : 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
        "pre-authorized_code" : code,
        "client_id" : DID,
        "redirect_uri" : "WALLET_REDIRECT_URI",
        "tx_code" : 4444
    }
    logging.info("token request data = %s", data)
    resp = requests.post(token_endpoint, headers=headers, data = data)
    logging.info("status_code token endpoint = %s", resp.status_code)
    if resp.status_code > 399 :
        print("error sur le token endpoint = ", resp.content)
    return resp.json()




def credential_request(issuer, access_token, vct, type, format, proof) :
    issuer_config_url = issuer + '/.well-known/openid-credential-issuer'
    issuer_config = requests.get(issuer_config_url).json()
    credential_endpoint = issuer_config['credential_endpoint']
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + access_token 
        }
    
    data = { 
        "format": format,
        "proof" : {
            "proof_type": "jwt",
            "jwt": proof
        }
    }
    if format == "vc+sd-jwt":
        data.update({  
            "credential_definition" :{
                "vct": vct
            }
        })
    else:
        data.update({  
            "credential_definition": {
                "type": type,
                "credentialSubject": {
                        "bankName": {
                        },
                        "leiCodeBank": {
                        },
                        "swiftNumber": {
                        },
                        "iban": {
                        },
                        "accountHolder": {
                        }
                    }
            }
        })

    logging.info('credential endpoint request = %s', data)
    resp = requests.post(credential_endpoint, headers=headers, data = json.dumps(data))
    logging.info('status code credential endpoint = %s', resp.status_code)
    if resp.status_code > 399 :
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


# If pre authorized code, the script starts here.  not the wallet starts the local server
def  pre_authorized_code_flow(issuer, code, vct, type, format):
    # access token request
    logging.info('This is a pre_authorized-code flow')
    result = token_request(issuer, code)
    logging.info('token endpoint response = %s', result)
    if result.get('error') :
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

    if result.get('error') :
        logging.warning('credential endpoint error return code = %s', result)
        return
    # credential received
    logging.info("'credential endpoint response = %s", result)  
    return result["credential"]

