"""
This is a bridge between the SIOPV2 flow used by EBSI with a verifier and a standard Openid authorization code flow or implicit flow with used with the customer application

Customer can use any OpenId lib in its own framework to access an EBSI conformant wallet

OIDC4VP: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html
SIOPV2: https://openid.net/specs/openid-connect-self-issued-v2-1_0.html

"""

from flask import request, render_template, redirect
from flask import session, Response, jsonify
import json
import uuid
from urllib.parse import urlencode, quote, unquote
import logging
import base64
from datetime import datetime
from jwcrypto import jwk, jwt
from db_api import read_oidc4vc_verifier
import pkce # https://github.com/xzava/pkce
import oidc4vc
from profile import profile
import pex
import didkit
import requests
import x509_attestation
import base64

logging.basicConfig(level=logging.INFO)

# customer application 
ACCESS_TOKEN_LIFE = 2000
CODE_LIFE = 2000

# wallet
QRCODE_LIFE = 2000

# OpenID key of the OP for customer application
RSA_KEY_DICT = json.load(open("keys.json", "r"))['RSA_key']
rsa_key = jwk.JWK(**RSA_KEY_DICT) 
public_rsa_key = rsa_key.export(private_key=False, as_dict=True)


def init_app(app, red, mode):
    # endpoints for OpenId customer application
    app.add_url_rule('/sandbox/verifier/app/authorize',  view_func=oidc4vc_authorize, methods=['GET', 'POST'], defaults={"red": red, "mode": mode})
    app.add_url_rule('/sandbox/verifier/app/token',  view_func=oidc4vc_token, methods=['GET', 'POST'], defaults={"red": red, 'mode': mode})
    app.add_url_rule('/sandbox/verifier/app/logout',  view_func=oidc4vc_logout, methods=['GET', 'POST'])
    app.add_url_rule('/sandbox/verifier/app/userinfo',  view_func=oidc4vc_userinfo, methods=['GET', 'POST'], defaults={"red": red})
    app.add_url_rule('/sandbox/verifier/app/.well-known/openid-configuration', view_func=oidc4vc_openid_configuration, methods=['GET'], defaults={'mode': mode})
    app.add_url_rule('/sandbox/verifier/app/jwks.json', view_func=oidc4vc_jwks, methods=['GET'])
    
    # endpoints for wallet
    app.add_url_rule('/verifier/wallet', view_func=oidc4vc_login_qrcode, methods=['GET', 'POST'], defaults={'red': red, 'mode': mode})
    app.add_url_rule('/verifier/wallet/.well-known/openid-configuration',  view_func=wallet_openid_configuration, methods = ['GET'])
    app.add_url_rule('/verifier/wallet/endpoint/<stream_id>',  view_func=oidc4vc_response_endpoint, methods=['POST'],  defaults={'red': red}) # redirect_uri for PODST
    app.add_url_rule('/verifier/wallet/request_uri/<stream_id>',  view_func=oidc4vc_request_uri, methods=['GET'], defaults={'red': red})
    app.add_url_rule('/verifier/wallet/client_metadata_uri/<verifier_id>',  view_func=wallet_metadata_uri, methods=['GET'], defaults={'red': red})
    app.add_url_rule('/verifier/wallet/presentation_definition_uri/<verifier_id>',  view_func=presentation_definition_uri, methods=['GET'], defaults={'red': red})
    app.add_url_rule('/verifier/wallet/followup',  view_func=oidc4vc_login_followup, methods=['GET'], defaults={'red': red})
    app.add_url_rule('/verifier/wallet/stream',  view_func=oidc4vc_login_stream, defaults={ 'red': red})
    return
    

def convert_jwt2jsonld_vc(vc):
    payload = oidc4vc.get_payload_from_token(vc)
    return payload.get('vc')


def oidc4vc_build_id_token(client_id, sub, nonce, vp, mode):
    """
    Build an Id_token for application 
    """
    verifier_key = jwk.JWK(**RSA_KEY_DICT) 
    header = {
        "typ": "JWT",
        "kid": RSA_KEY_DICT['kid'],
        "alg": "RS256"
    }
    # https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
    payload = {
        "iss": mode.server + 'sandbox/verifier/app',
        "iat": datetime.timestamp(datetime.now()),
        "aud": client_id,
        "exp": datetime.timestamp(datetime.now()) + 1000,
        "sub": sub,
    }
    if nonce:
        payload['nonce'] = nonce
    if vp:
        if vp.get("vc+sd-jwt"):
            payload['vc+sd-jwt'] = vp["vc+sd-jwt"]
            vc_list = []
        elif vp.get("dc+sd-jwt"):
            payload['dc+sd-jwt'] = vp["dc+sd-jwt"]
            vc_list = []
        elif isinstance(vp['verifiableCredential'], dict):
            vc_list = [vp['verifiableCredential']]
        else:
            vc_list = vp['verifiableCredential']
        # https://www.iana.org/assignments/jwt/jwt.xhtml
        for vc in vc_list:
            if isinstance(vc, str):
                vc = convert_jwt2jsonld_vc(vc)
                if not vc: return
            if 'EmailPass' in vc['type'] :
                payload['email'] = vc['credentialSubject']['email']
            elif 'PhoneProof' in vc['type']:
                payload['phone'] = vc['credentialSubject']['phone']
            elif 'VerifiableId'in vc['type']:
                payload['given_name'] = vc['credentialSubject'].get('firstName')
                payload['family_name'] = vc['credentialSubject'].get('familyName')
                payload['birthdate'] = vc['credentialSubject'].get('dateOfBirth')
                if vc['credentialSubject'].get('placeOfBirth'):
                    payload['birthplace'] = vc['credentialSubject'].get('placeOfBirth')
                if vc['credentialSubject'].get('gender'):
                    payload['gender'] = vc['credentialSubject'].get('gender')
            elif 'Over18' in vc['type']:
                payload['is_over_18'] = True
            elif 'Over15' in vc['type']:
                payload['is_over_15'] = True
            else:
                logging.info("VC type not supported in id_token")
            
    logging.info("ID Token payload = %s", payload)
    token = jwt.JWT(header=header, claims=payload, algs=["RS256"])
    token.make_signed_token(verifier_key)
    return token.serialize()


def oidc4vc_jwks():
    return jsonify({"keys": [public_rsa_key]})


def b64url_no_pad_decode(s: str) -> bytes:
    # Add back the missing padding if needed
    try:
        padding_needed = (4 - len(s) % 4) % 4
        s += "=" * padding_needed
        return base64.urlsafe_b64decode(s)
    except:
        return base64.urlsafe_b64decode(s)

# For customer app
def oidc4vc_openid_configuration(mode):
    """
    For the customer application of the saas platform  
    https://openid.net/specs/openid-connect-self-issued-v2-1_0.html#name-dynamic-self-issued-openid-
    """
    return {
        "issuer": mode.server + 'sandbox/verifier/app',
        "authorization_endpoint":  mode.server + 'sandbox/verifier/app/authorize',
        "token_endpoint": mode.server + 'sandbox/verifier/app/token',
        "userinfo_endpoint": mode.server + 'sandbox/verifier/app/userinfo',
        "logout_endpoint": mode.server + 'sandbox/verifier/app/logout',
        "jwks_uri": mode.server + 'sandbox/verifier/app/jwks.json',
        "scopes_supported": ["openid"],
        "response_types_supported": ["code", "id_token"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic"]
    }


# authorization server for customer application
"""
response_type supported = code or id_token or vp_token
code -> authorization code flow
id_token -> implicit flow
# https://openid.net/specs/openid-4-verifiable-presentations-1_0.html
"""


def oidc4vc_authorize(red, mode):
    """ 
    code_wallet_data = 
        {
            "vp_token_payload",: xxxxx
            "sub": xxxxxx,
            "presentation_submission": "xxx"
        }
    """
    logging.info("authorization endpoint request  = %s", request.args)
    # user is connected, successful exit to client with code
    if session.get('verified') and request.args.get('code'):
        code = request.args['code']
        try:
            code_data = json.loads(red.get(code).decode())
        except Exception as e:
            logging.error("code expired  = %s", str(e))
            session.clear()
            return jsonify({'error': "access_denied"}), 400

        # authorization code flow -> redirect with code
        if code_data['response_type'] == 'code':
            logging.info("response_type = code: successful redirect to client with code = %s", code) 
            resp = {'code': code,  'state': code_data.get('state')} if code_data.get('state') else {'code': code}
            logging.info('response to redirect_uri = %s', resp)
            return redirect(code_data['redirect_uri'] + '?' + urlencode(resp))

        # implicit flow -> redirect with id_token USED FOR TESTING PURPOSE ON SANDBOX
        elif code_data['response_type'] == 'id_token':
            logging.info("response_type = id_token") 
            sep = "?" if code_data['response_mode'] == 'query' else "#"
            try:
                code_wallet_data = json.loads(red.get(code + "_wallet_data").decode())
            except Exception:
                logging.error("code expired")
                resp = {'error': "access_denied"}
                redirect_uri = code_data['redirect_uri']
                session.clear()
                return redirect(redirect_uri + sep + urlencode(resp)) 
            if code_wallet_data['vp_format'] == 'ldp_vp':
                vp = code_wallet_data['vp_token_payload']
                id_token = oidc4vc_build_id_token(code_data['client_id'], code_wallet_data['sub'], code_data['nonce'], vp, mode)
            elif code_wallet_data['vp_format'] in ["vc+sd-jwt", "dc+sd-jwt"]:
                id_token = code_wallet_data['vp_token_payload']
                if isinstance(id_token, list):
                    id_token = id_token[0]
            else:
                vp = code_wallet_data['vp_token_payload'].get('vp')
                logging.info(" code_wallet_data['vp_token_payload'] = %s", code_wallet_data['vp_token_payload'])
                id_token = oidc4vc_build_id_token(code_data['client_id'], code_wallet_data['sub'], code_data['nonce'], vp, mode)
            
            resp = {
                "id_token": id_token,
                "wallet_id_token": code_wallet_data['id_token'],
                "presentation_submission": json.dumps(code_wallet_data['presentation_submission']) 
            }
            redirect_url = code_data['redirect_uri'] + sep + urlencode(resp)
            logging.info("redirect url = %s", redirect_url)
            return redirect(redirect_url)

        else:
            logging.error("session expired")
            resp = {'error': "access_denied"}
            redirect_uri = code_data['redirect_uri']
            session.clear()
            return redirect(redirect_uri + '?' + urlencode(resp)) 

    # error in login, exit, clear session
    if 'error' in request.args:
        logging.warning('Error in the login process, redirect to client with error code = %s', request.args['error'])
        code = request.args['code']
        try:
            code_data = json.loads(red.get(code).decode())
        except Exception:
            return jsonify({'error': "access_denied"}), 400
        resp = {
            'error': request.args['error'],
            'error_description': request.args.get('error_description')
        }
        if code_data.get('state'):
            resp['state'] = code_data['state']
        redirect_uri = code_data['redirect_uri']
        red.delete(code)
        session.clear()
        return redirect(redirect_uri + '?' + urlencode(resp)) 
    
    # User is not connected
    def manage_error_request(msg):
        session.clear()
        resp = {'error': msg}
        return redirect(request.args['redirect_uri'] + '?' + urlencode(resp))

    session['verified'] = False
    logging.info('user is not connected in OP')
    # PKCE https://datatracker.ietf.org/doc/html/draft-ietf-oauth-spop-14
    try:
        data = {
            'client_id': request.args['client_id'],  # required
            'scope': request.args['scope'].split(),  # required
            'state': request.args.get('state'),
            'response_type': request.args['response_type'],  # required
            'redirect_uri': request.args['redirect_uri'],  # required
            'nonce': request.args.get('nonce'),
            'code_challenge': request.args.get('code_challenge'),
            'code_challenge_method': request.args.get('code_challenge_method'),
            "expires": datetime.timestamp(datetime.now()) + CODE_LIFE,
            'response_mode': request.args.get('response_mode'),
        }
        if request.args.get('authorization_details'):
            decoded = unquote(request.args.get("authorization_details"))
            data["transaction_data"] = base64.urlsafe_b64encode(decoded.encode()).decode().rstrip("=")
            logging.info("transaction data = %s", data["transaction_data"])
                        
    except Exception as e:
        logging.warning('invalid request received in authorization server: %s', str(e))
        try:
            return manage_error_request("invalid_request_object")
        except Exception:
            session.clear()
            return jsonify({'error': 'request malformed'}), 400

    if not read_oidc4vc_verifier(request.args['client_id']):
        logging.warning('client_id not found in client data base')
        return manage_error_request("unauthorized_client")

    session['redirect_uri'] = request.args['redirect_uri']
    if request.args['response_type'] not in ["code", "id_token"]:
        logging.warning('unsupported response type %s', request.args['response_type'])
        return manage_error_request("unsupported_response_type")

    # creation grant = code
    code = str(uuid.uuid1())
    red.setex(code, CODE_LIFE, json.dumps(data))
    resp = {'code': code}
    return redirect('/verifier/wallet?code=' + code)


# token endpoint for customer application
def oidc4vc_token(red, mode):
    #https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
    logging.info("token endpoint request ")
    
    def manage_error(error, error_description=None, status=400):
        logging.warning(error)
        endpoint_response = {"error": error}
        if error_description:
            endpoint_response['error_description'] = error_description
        headers = {
            "Cache-Control": "no-store",
            "Pragma": "no-cache",
            'Content-Type': 'application/json'
        }
        return Response(response=json.dumps(
            endpoint_response),
            status=status,
            headers=headers
        )
        
    try:
        token = request.headers['Authorization']
        token = token.split(" ")[1]
        token = base64.b64decode(token).decode()
        client_secret = token.split(":")[1]
        client_id = token.split(":")[0]
        logging.info('Authentication client_secret_basic')
    except Exception:
        try:
            client_id = request.form['client_id']
            client_secret = request.form['client_secret']
            logging.info('Authorization client_secret_post')
        except Exception:
            return manage_error("request_not_supported", error_description="Client authentication method not supported")
    try:
        verifier_data = json.loads(read_oidc4vc_verifier(client_id))
        grant_type = request.form['grant_type']
        code = request.form['code']
        redirect_uri = request.form['redirect_uri']
    except Exception:
        return manage_error("invalid_request")
    
    code_verifier = request.form.get('code_verifier')

    try:
        data = json.loads(red.get(code).decode())
    except Exception:
        logging.error("red get probleme sur code")
        return manage_error("invalid_grant")
        
    if client_id != data['client_id']:
        return manage_error("invalid_client")
    if not verifier_data.get("pkce") and verifier_data['client_secret'] != client_secret:
        return manage_error("invalid_client")
    elif redirect_uri != data['redirect_uri']:
        return manage_error("invalid_redirect_uri")
    elif grant_type != 'authorization_code':
        return manage_error("unauthorized_client")
    if verifier_data.get('pkce') == 'on' and not code_verifier:
        logging.warning("pb code verifier")
        return manage_error("invalid_request")
    if verifier_data.get("pkce") and pkce.get_code_challenge(code_verifier) != data['code_challenge']:
        logging.warning('code verifier not correct')
        return manage_error("unauthorized_client")
    
    # token response
    try:
        code_wallet_data = json.loads(red.get(code + "_wallet_data").decode())
    except Exception:
        logging.error("redis get problem to get code_wallet_data")
        return manage_error("invalid_grant")
    if code_wallet_data['vp_format'] == 'ldp_vp':
        vp = code_wallet_data['vp_token_payload']
        id_token = oidc4vc_build_id_token(client_id, code_wallet_data['sub'], data['nonce'], vp, mode)
    elif code_wallet_data['vp_format'] in ['vc+sd-jwt', "dc+sd-jwt"]:
        id_token = code_wallet_data['vp_token_payload']
    else:
        vp = code_wallet_data['vp_token_payload'].get('vp')
        id_token = oidc4vc_build_id_token(client_id, code_wallet_data['sub'], data['nonce'], vp, mode)
    logging.info('id_token and access_token sent to client from token endpoint')
    access_token = str(uuid.uuid1())
    endpoint_response = {
        "id_token": id_token,
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": ACCESS_TOKEN_LIFE
    }
    red.setex(
        access_token + '_wallet_data',
        ACCESS_TOKEN_LIFE,
        json.dumps({
            "client_id": client_id,
            "sub": code_wallet_data['sub'],
            "vp_token_payload": code_wallet_data['vp_token_payload']
        })
    )
    headers = {
        "Cache-Control": "no-store",
        "Pragma": "no-cache",
        'Content-Type': 'application/json'}
    return Response(response=json.dumps(endpoint_response), headers=headers)


# logout endpoint
#https://openid.net/specs/openid-connect-rpinitiated-1_0-02.html
def oidc4vc_logout():
    if not session.get('verified'):
        return jsonify('Forbidden'), 403
    if request.method == "GET":
        #  id_token_hint = request.args.get('id_token_hint')
        post_logout_redirect_uri = request.args.get('post_logout_redirect_uri')
    elif request.method == "POST":
        #  id_token_hint = request.form.get('id_token_hint')
        post_logout_redirect_uri = request.form.get('post_logout_redirect_uri')
    if not post_logout_redirect_uri:
        post_logout_redirect_uri = session.get('redirect_uri')
    session.clear()
    logging.info("logout call received, redirect to %s", post_logout_redirect_uri)
    return redirect(post_logout_redirect_uri)


# userinfo endpoint
def oidc4vc_userinfo(red):
    logging.info("user info endpoint request")
    try:
        access_token = request.headers["Authorization"].split()[1]
    except Exception:
        logging.warning("Access token is passed as argument by application")
        access_token = request.args['access_token']

    try:
        wallet_data = json.loads(red.get(access_token + '_wallet_data').decode())
        payload = {
            "sub": wallet_data['sub'],
            "vp_token_payload": wallet_data["vp_token_payload"]
        }
        payload.update(oidc4vc.decode_sd_jwt(wallet_data["vp_token_payload"]))
        headers = {
            "Cache-Control": "no-store",
            "Pragma": "no-cache",
            "Content-Type": "application/json"}
        return Response(response=json.dumps(payload), headers=headers)
    
    except Exception:
        logging.warning("access token expired")
        headers = {
            'WWW-Authenticate': 'Bearer realm="userinfo", error="invalid_token", error_description = "The access token expired"',
            "Content-Type": "application/json"
        }
        return Response(status=401,headers=headers)

    
################################# SIOPV2 + OIDC4VP ###########################################


def wallet_openid_configuration():
    config = json.load(open("ebsiv3_siopv2_openid_configuration.json", "r"))
    return jsonify(config)


def build_jwt_request(key, kid, iss, aud, request, client_id_scheme=None, client_id=None) -> str:
    if key:
        key = json.loads(key) if isinstance(key, str) else key
        signer_key = jwk.JWK(**key) 
        alg = oidc4vc.alg(key)
    else:
        alg = "none"
        signer_key = None
    header = {
        'typ': "oauth-authz-req+jwt",
        'alg': alg,
    }
    if client_id_scheme == "x509_san_dns":
        header['x5c'] = x509_attestation.build_x509_san_dns()
    elif client_id_scheme == "verifier_attestation":
        header['jwt'] = x509_attestation.build_verifier_attestation(client_id)
    elif client_id_scheme == "redirect_uri":
        pass
    else:  # DID by default
        header['kid'] = kid
    
    payload = {
        'iss': iss,
        'aud': aud,
        'exp': int(datetime.timestamp(datetime.now())) + 1000
    }
    payload |= request
    if key:
        token = jwt.JWT(header=header, claims=payload, algs=[alg])
        token.make_signed_token(signer_key)
        return token.serialize()
    else:
        token = base64.urlsafe_b64encode(json.dumps(header).encode()).decode()
        token += '.'
        token += base64.urlsafe_b64encode(json.dumps(payload).encode()).decode()
        return token


def wallet_metadata_uri(verifier_id, red):
    #  https://openid.net/specs/openid-connect-registration-1_0.html
    try:
        wallet_metadata = json.loads(red.get("client_metadata_" + verifier_id).decode())
    except Exception:
        return jsonify('Request timeout'), 408
    return jsonify(wallet_metadata)


def build_verifier_metadata(client_id, redirect_uri) -> dict:
    try:
        verifier_data = json.loads(read_oidc4vc_verifier(client_id))
    except Exception as e:
        logging.warning("wallet metadata failed to build = %s", str(e))
        return {}
    verifier_metadata = json.load(open('verifier_metadata.json', 'r'))        
    #verifier_metadata['request_uri_parameter_supported'] = bool(verifier_data.get('request_uri_parameter_supported'))
    #verifier_metadata['request_parameter_supported'] = bool(verifier_data.get('request_parameter_supported'))
    #verifier_metadata['redirect_uris'] = [redirect_uri]
    return verifier_metadata


def presentation_definition_uri(verifier_id, red):
    try:
        presentation_definition = json.loads(red.get("presentation_definition_" + verifier_id).decode())
    except Exception:
        return jsonify('Request timeout'), 408
    return jsonify(presentation_definition)

                                        
def oidc4vc_login_qrcode(red, mode):
    stream_id = str(uuid.uuid1())
    try:
        code_data = red.get(request.args['code']).decode()
    except Exception:
        logging.error("session expired in login_qrcode")
        return render_template("verifier_oidc/verifier_session_problem.html", message='Session expired')
    
    try:
        verifier_id = json.loads(code_data)['client_id']
        nonce = json.loads(code_data).get('nonce')   
    except Exception:
        logging.error("client id or nonce missing")
        return render_template("verifier_oidc/verifier_session_problem.html", message='Server error ')
    
    verifier_data = json.loads(read_oidc4vc_verifier(verifier_id))
    verifier_profile = profile[verifier_data['profile']]
        
    if verifier_data.get('id_token') and not verifier_data.get('vp_token'):
        response_type = 'id_token'
    elif verifier_data.get('id_token') and verifier_data.get('vp_token'):
        response_type = 'vp_token id_token'
    elif verifier_data.get('vp_token') and not verifier_data.get('id_token'):
        response_type = 'vp_token'
    else:
        return render_template("verifier_oidc/verifier_session_problem.html", message='Invalid configuration')
    
    # manage the choice of prefix for testing purpose
    if not request.form.get('prefix'):
        if response_type == 'id_token':
            prefix = verifier_profile["siopv2_prefix"]
        else:
            prefix = verifier_profile["oidc4vp_prefix"] 
    else:
        prefix = request.form.get('prefix')      
    
    # Manage presentation definition with a subset of PEX 2.0
    if 'vp_token' in response_type:
        presentation_definition = str()
        prez = {}

    if 'vp_token' in response_type and not verifier_data['group']:
        if not prez:
            prez = pex.Presentation_Definition(verifier_data['application_name'], "Altme presentation definition subset of PEX v2.0")  
        for i in ["1", "2", "3", "4"]:
            vc = 'vc_' + i
            reason = 'reason_' + i
            if verifier_data[vc] != 'None':
                if verifier_data.get('filter_type_array') and verifier_data[vc] != "$.nationalities":
                    prez.add_constraint_with_type_array(
                        "$.type",
                        verifier_data[vc],
                        "Input descriptor for credential " + i,
                        verifier_data[reason],
                        id= verifier_data[vc].lower() + '_' + i
                    )
                elif verifier_data.get('filter_type_array') and verifier_data[vc] == "$.nationalities":
                    prez.add_constraint_with_type_array(
                        "$.nationalities",
                        verifier_data[vc],
                        "Input descriptor for credential " + i,
                        verifier_data[reason],
                        id= verifier_data[vc].lower() + '_' + i
                    )
                elif profile[verifier_data['profile']].get("verifier_vp_type") in ['vc+sd-jwt', "dc+sd-jwt"]:
                    prez.add_constraint(
                        "$.vct",
                        verifier_data[vc],
                        "Input descriptor for credential " + i,
                        verifier_data[reason],
                        id=verifier_data[vc].lower() + '_' + i
                    )
                elif profile[verifier_data['profile']].get("verifier_vp_type") in ['vc+sd-jwt', "dc+sd-jwt"] and verifier_data[vc] == "$.age_equal_or_over.18":
                    prez.add_constraint(
                        "$.age_equal_or_over.18",
                        verifier_data[vc],
                        "Input descriptor for credential " + i,
                        verifier_data[reason],
                        id=verifier_data[vc].lower() + '_' + i
                    )
                else:
                    prez.add_constraint(
                        "$.vc.credentialSubject.type",
                        verifier_data[vc],
                        "Input descriptor for credential " + i,
                        verifier_data[reason],
                        id=verifier_data[vc].lower() + '_' + i
                    )
    
    if 'vp_token' in response_type and verifier_data['group']:
        if not prez:
            prez = pex.Presentation_Definition(verifier_data['application_name'], "Talao-Altme presentation definition with a subset of PEX v2.0 syntax")  
        prez.add_group("Group A", "A", count=1)
        for i in ["5", "6", "7", "8"]:
            vc = 'vc_' + i
            if verifier_data[vc] != 'None':
                prez.add_constraint_with_group(
                    "$.credentialSubject.type",
                    verifier_data[vc],
                    "Input descriptor for credential " + i,
                    "",
                    "A",
                    id=verifier_data[vc].lower() + '_' + i
                )

    if 'vp_token' in response_type and verifier_data.get('group_B'):
        if not prez:
            prez = pex.Presentation_Definition(verifier_data['application_name'], "Altme presentation definition subset of PEX v2.0")  
        prez.add_group("Group B", "B", min=1)
        for i in ["9", "10", "11", "12"]:
            vc = 'vc_' + i
            if verifier_data[vc] != 'None':
                prez.add_constraint_with_group(
                    "$.credentialSubject.type",
                    verifier_data[vc],
                    "Input descriptor for credential " + i,
                    "",
                    "B",
                    id=verifier_data[vc].lower() + '_' + i
                )

    # add format depending on profile
    if 'vp_token' in response_type: 
        if profile[verifier_data['profile']].get("verifier_vp_type") == 'ldp_vp':
            prez.add_format_ldp_vp()
            prez.add_format_ldp_vc()
        elif profile[verifier_data['profile']].get("verifier_vp_type") == 'all_vp':
            prez.add_format_all_vp()
            prez.add_format_all_vc()
        elif profile[verifier_data['profile']].get("verifier_vp_type") == 'jwt_vp':
            prez.add_format_jwt_vp()
            prez.add_format_jwt_vc()
        elif profile[verifier_data['profile']].get("verifier_vp_type") == 'jwt_vp_json':
            prez.add_format_jwt_vp_json()
            prez.add_format_jwt_vc_json()
        elif profile[verifier_data['profile']].get("verifier_vp_type") == 'jwt_vp_json-ld':
            prez.add_format_jwt_vp_json()
            prez.add_format_jwt_vc_json()
        elif profile[verifier_data['profile']].get("verifier_vp_type") in ['vc+sd-jwt', "dc+sd-jwt"]:
            prez.add_format_sd_jwt()
        else:
            return render_template("verifier_oidc/verifier_session_problem.html", message='VOP format not supported')

    nonce = nonce or str(uuid.uuid1())
    redirect_uri = mode.server + "verifier/wallet/endpoint/" + stream_id
    
    # general authorization request
    authorization_request = { 
        "response_type": response_type,
        "state": str(uuid.uuid1()),  # unused
        "response_uri": redirect_uri,
    }
    if verifier_data.get('jarm'):
        authorization_request["response_mode"] = "direct_post.jwt"
    else:
        authorization_request["response_mode"] = "direct_post"

    # Set client_id
    if verifier_data.get('client_id_scheme') == "x509_san_dns":
        client_id = "talao.co"
    elif verifier_data.get('client_id_scheme') == "redirect_uri":
        client_id = redirect_uri
    elif verifier_data.get('client_id_scheme') == "did":
        client_id = verifier_data['did']
    else:
        client_id = verifier_data['did']
    
    authorization_request['client_id'] = client_id
        
    wallet_metadata = build_verifier_metadata(verifier_id, redirect_uri)
    
    authorization_request['nonce'] = nonce

    # OIDC4VP
    if 'vp_token' in response_type:
        if verifier_data.get('predefined_presentation_definition') in [None, 'None']:
            logging.info('no predefined presentation definition')
            presentation_definition = prez.get()
            logging.info("presentation_definition = %s", presentation_definition)
        else:
            presentation_definition = json.load( open(verifier_data.get('predefined_presentation_definition') +'.json', 'r'))
        
        authorization_request['aud'] = 'https://self-issued.me/v2'
            
        # client_metadata uri
        if verifier_data.get('client_metadata_uri'):
            red.setex("client_metadata_" + verifier_id, QRCODE_LIFE, json.dumps(wallet_metadata))
            client_metadata_uri = mode.server + "verifier/wallet/client_metadata_uri/" + verifier_id
        
        # client_id_scheme depending of OIDC4VP draft between 13 and 22 included
        if int(verifier_profile['oidc4vpDraft']) > 13 and int(verifier_profile['oidc4vpDraft']) < 22: #TODO
            authorization_request['client_id_scheme'] = verifier_data.get('client_id_scheme')
        elif int(verifier_profile['oidc4vpDraft']) >= 22:
            if verifier_data.get('client_id_scheme') == "x509_san_dns":
                authorization_request['client_id'] = "x509_san_dns:talao.co"
            elif verifier_data.get('client_id_scheme') == "redirect_uri":
                authorization_request['client_id'] = "redirect_uri:" + client_id
            elif verifier_data.get('client_id_scheme') == "verifier_attestation":
                authorization_request['client_id'] = "verifier_attestation:" + client_id
            else:
                pass
        

        # presentation_definition_uri
        if verifier_data.get('presentation_definition_uri'):
            red.setex("presentation_definition_" + verifier_id, QRCODE_LIFE, json.dumps(presentation_definition))        
            presentation_definition_uri = mode.server + 'verifier/wallet/presentation_definition_uri/' + verifier_id
    else:
        presentation_definition = None
        
    # SIOPV2
    if 'id_token' in response_type:
        authorization_request['scope'] = 'openid'

    # store data
    data = { 
        "pattern": authorization_request,
        "code": request.args['code'],
        "client_id": client_id,
        "verifier_id": verifier_id
    }
    red.setex(stream_id, QRCODE_LIFE, json.dumps(data))

    # Request uri    
    if 'vp_token' in response_type:
        if verifier_data.get('client_metadata_uri'):
            authorization_request['client_metadata_uri'] = client_metadata_uri
        else:
            authorization_request['client_metadata'] = wallet_metadata

        if verifier_data.get('presentation_definition_uri'):
            authorization_request['presentation_definition_uri'] = presentation_definition_uri
        else:
            authorization_request['presentation_definition'] = presentation_definition
    
    if response_type == "id_token" and verifier_data.get('request_uri_parameter_supported'):
        authorization_request['client_metadata'] = wallet_metadata
    
    # Data transaction integgration
    transaction_data = []
    if json.loads(code_data).get("transaction_data"): 
        authorization_request["transaction_data"] = [json.loads(code_data)["transaction_data"]]
        for td in authorization_request["transaction_data"]:
            transaction_data.append(json.loads(b64url_no_pad_decode(td).decode()))
        
    # manage request_uri as jwt
    if verifier_data.get('client_id_scheme') == "redirect_uri":
        key = None
    else:
        key = verifier_data['jwk']

    request_as_jwt = build_jwt_request(
        key,
        verifier_data['verification_method'],
        client_id,  # iss ??????
        'https://self-issued.me/v2', # aud requires static siopv2 data
        authorization_request,
        client_id_scheme=verifier_data.get('client_id_scheme'),
        client_id=client_id
    )
    
    # QRCode preparation with authorization_request_displayed
    if verifier_data.get('request_uri_parameter_supported') or verifier_data['profile'] in ["HAIP", "POTENTIAL"]: # request uri as jwt
        red.setex("request_uri_" + stream_id, QRCODE_LIFE, request_as_jwt)
        authorization_request_displayed = { 
            "client_id": client_id,
            "request_uri": mode.server + "verifier/wallet/request_uri/" + stream_id 
        }
    elif verifier_data.get('request_parameter_supported') and not verifier_data.get('request_uri_parameter_supported'):
        authorization_request = {}
        authorization_request['request'] = request_as_jwt
        authorization_request["client_id"] = client_id
        authorization_request_displayed = authorization_request
    else:
        authorization_request_displayed = authorization_request

    url = prefix + '?' + urlencode(authorization_request_displayed)
    if not verifier_data.get('request_uri_parameter_supported'):
        if not verifier_data.get('client_metadata_uri'):
            url += '&client_metadata=' + quote(json.dumps(wallet_metadata))
        if not verifier_data.get('presentation_definition_uri'):
            url += '&presentation_definition=' + quote(json.dumps(presentation_definition))
    
    # get request uri as jwt
    try:
        r = requests.get(authorization_request_displayed['request_uri'], timeout=10)
        request_uri_jwt = r.content.decode()
    except Exception:
        request_uri_jwt = ""

    deeplink_altme = mode.deeplink_altme + 'app/download/authorize?' + urlencode(authorization_request_displayed)
    logging.info("weblink for same device flow = %s", deeplink_altme)
    qrcode_page = verifier_data.get('verifier_landing_page_style')
    
    # test qrcode size
    logging.info("qrcode qize = %s", len(url))
    if len(url) > 2900:
        return jsonify("This QR code is too big, use request uri")

    try:
        request_uri_header = json.dumps(oidc4vc.get_header_from_token(request_uri_jwt), indent=4)
        request_uri_payload = json.dumps(oidc4vc.get_payload_from_token(request_uri_jwt), indent=4)
    except Exception as e:
        logging.warning("token decryption problem = %s", str(e))
        request_uri_header = ""
        request_uri_payload = ""
        
    return render_template(
        qrcode_page,
        url=url,
        request_uri=request_uri_jwt,
        request_uri_header=request_uri_header,
        request_uri_payload=request_uri_payload,
        url_json=unquote(url),
        presentation_definition=json.dumps(presentation_definition, indent=4),
        client_metadata=json.dumps(wallet_metadata, indent=4),
        transaction_data=json.dumps(transaction_data),
        deeplink_altme=deeplink_altme,
        stream_id=stream_id,
        title=verifier_data.get('title', "None"),
        page_title=verifier_data['page_title'],
        page_subtitle=verifier_data['page_subtitle'],
        page_description=verifier_data.get('page_description', "None"),
        code=request.args['code']
    )


def oidc4vc_request_uri(stream_id, red):
    """
    Request by uri
    https://www.rfc-editor.org/rfc/rfc9101.html
    """
    try:
        payload = red.get("request_uri_" + stream_id).decode()
    except Exception:
        return jsonify("Request timeout"), 408
    headers = { 
        "Content-Type": "application/oauth-authz-req+jwt",
        "Cache-Control": "no-cache"
    }
    return Response(payload, headers=headers)


async def oidc4vc_response_endpoint(stream_id, red):
    logging.info("Enter wallet response endpoint")
    logging.info("Header = %s", request.headers)
    logging.info("Form = %s", request.form)
    
    # prepare the verifier response to wallet
    response_format = "Unknown"
    vc_format = "Unknown"
    state_status = 'unknown'
    vp_format = "Unknown"
    presentation_submission_status = "Unknown"
    vp_token_status = "Unknown"
    id_token_status = "Unknown"
    aud_status = "unknown"
    nonce_status = "Unknown"
    subject_syntax_type = "DID"
    vp_token_payload = {}
    id_token_payload = {}
    access = True
    qrcode_status = "Unknown"
    id_token = vp_token = None
    presentation_submission = None
    
    event_data = json.dumps({
        "stream_id": stream_id,
        "followup": "wait"})
    red.publish('api_oidc4vc_verifier', event_data)

    try:
        qrcode_status = "ok"
        data = json.loads(red.get(stream_id).decode())
        verifier_id = data['verifier_id']
        verifier_data = json.loads(read_oidc4vc_verifier(verifier_id))
        logging.info('Verifier profile = %s', verifier_data['profile'])
    except Exception:
        qrcode_status = "QR code expired"
        logging.info("QR code expired")
        access = False

    # get if error
    if request.form.get('error'):
        response_data = {
            "error":  request.form.get('error'),
            "error_description": request.form.get('error_description')
        }
        logging.warning("wallet response error = %s", json.dumps(response_data, indent=4))
        access = False
    
    # get id_token, vp_token and presentation_submission
    if access:
        if request.form.get('response'):
            response = oidc4vc.get_payload_from_token(request.form['response'])
            logging.info("direct_post.jwt, JARM mode")
        else:
            logging.info("direct_post")
            response = request.form
        
        vp_token = response.get('vp_token')
        id_token = response.get('id_token')
        presentation_submission = response.get('presentation_submission')
        
        if vp_token and not presentation_submission:
            presentation_submission_status = "Not received"
            logging.info('No presentation submission received')
            access = False
        else:
            presentation_submission_status = "ok"
            logging.info('presentation submission received = %s', presentation_submission)
            if isinstance(presentation_submission, str):
                presentation_submission = json.loads(presentation_submission)
                logging.info("presentation submission is a string")
            else:
                logging.info("presentation submission is a dict /json object")
        
        if id_token:
            logging.info('id token received = %s', id_token)
        else:
            id_token_status = "Not received"
        
        def format(vp, type="vp"):
            if not vp:
                return "no token"
            elif isinstance(vp, dict):
                vp = json.dumps(vp)
            if vp[:1] == "{":
                return "ldp_" + type
            elif isinstance(vp, list):
                return "array of sd-jwt vc"
            elif len(vp.split("~")) > 1:
                return "vc+sd-jwt"
            else:
                return "jwt_" + type + "_json"
        
        vp_format = format(vp_token)   
        logging.info("VP format = %s", vp_format)   
        if vp_token and presentation_submission:
            logging.info('vp token received = %s', vp_token)
            vp_format_presentation_submission = presentation_submission["descriptor_map"][0]["format"]
            logging.info("VP format from presentation submission = %s", vp_format_presentation_submission)
            if vp_format not in ["vc+sd-jwt", "dc+sd-jwt", "ldp_vp", "jwt_vp_json", "jwt_vp", "jwt_vp_json-ld"]:
                logging.error("vp format unknown")
                access = False
            elif vp_format_presentation_submission == "jwt_vp" and vp_format == "jwt_vp_json":
                pass
            elif vp_format != vp_format_presentation_submission:
                presentation_submission_status = "vp_format = " + vp_format + " but presentation submission vp_format = " + vp_format_presentation_submission
                logging.warning(presentation_submission_status)
                
        elif vp_token and not presentation_submission:
            vp_token_status = "Not checked as presentation submission is missing"
        else:
            vp_token_status = "Not received"
        
        if not id_token and not vp_token:
            response_format = "invalid request format",
            access = False
        else:
            response_format = "ok"
        
        state = response.get('id_token')

    if access:
        nonce = data['pattern'].get('nonce')

    # check id_token signature
    if access and id_token:
        try:
            oidc4vc.verif_token(id_token)
        except Exception as e:
            id_token_status = "signature check failed"
            logging.warning(" id_token invalid format %s", str(e))
            access = False
    
    if access and id_token:
        try:
            id_token_payload = oidc4vc.get_payload_from_token(id_token)
            id_token_header = oidc4vc.get_header_from_token(id_token)
            id_token_jwk = id_token_header.get('jwk')
            id_token_kid = id_token_header.get('kid')
            id_token_iss = id_token_payload['iss']
            id_token_sub = id_token_payload['sub']
            id_token_sub_jwk = id_token_payload.get('sub_jwk')
        except Exception:
            id_token_status += " id_token invalid format, iss or sub is missing "
            access = False
            logging.info(" id_token invalid format, iss or sub is missing ")
    
    if access and id_token:
        if id_token_sub != id_token_iss:
            id_token_status += " id_token invalid format, iss and sub should be equal "
            access = False
            logging.info(" id_token invalid format, iss and sub should be equal ")
        if id_token_sub_jwk:
            subject_syntax_type = "JWK Thumbprint"
        if not id_token_sub_jwk and not id_token_kid and not id_token_jwk:
            access = False
            id_token_status += " id_token not correct format, kid or jwk missiong "
            logging.info("not correct format")
        if id_token_sub_jwk and id_token_kid:
            id_token_status += " id_token kid and jwk both present "
            access = False
        
    if access and id_token:
        if id_token_kid:
            if id_token_sub != id_token_iss:
                id_token_status += " id token sub != iss"    
            if id_token_sub != id_token_kid.split("#")[0]:
                id_token_status += " id token sub != kid "
        if id_token_sub_jwk:
            if id_token_sub != id_token_iss:
                id_token_status += " id token sub != iss"   
                
    # check vp_token signature
    if access and vp_token:
        if vp_format in ["jwt_vp", "jwt_vp_json"]:
            if len(vp_token.split("~")) > 1: # sd_jwt
                vp_token = vp_token.split("~")[0]
            try:
                oidc4vc.verif_token(vp_token)
                vp_token_status = "ok"
                vp_token_payload = oidc4vc.get_payload_from_token(vp_token)
            except Exception as e:
                vp_token_status = "signature check failed"
                access = False
                logging.warning("signature check failed %s", str(e))
        elif vp_format in ["vc+sd-jwt", "dc+sd-jwt"]:
            vcsd_jwt = vp_token.split("~")
            nb_disclosure = len(vcsd_jwt)
            logging.info("nb of disclosure = %s", nb_disclosure - 2 )
            disclosure = []
            for i in range(1, nb_disclosure-1):
                _disclosure = vcsd_jwt[i]
                _disclosure += "=" * ((4 - len(_disclosure) % 4) % 4)
                try:
                    logging.info("disclosure #%s = %s", i, base64.urlsafe_b64decode(_disclosure.encode()).decode())
                    disc = base64.urlsafe_b64decode(_disclosure.encode()).decode()
                    disclosure.append(disc)
                except Exception:
                    print("i = ", i)
                    print("_disclosure = ", _disclosure)
            logging.info("vp token signature not checked yet")
            vp_token_payload = vp_token
        else: # ldp_vp
            verifyResult = json.loads(await didkit.verify_presentation(vp_token, "{}"))
            vp_token_status = verifyResult
            vp_token_payload = json.loads(vp_token)

    # check types of vc
    if access and vp_token:
        vc_format = ""
        if vp_format in ["jwt_vp", "jwt_vp_json"]:
            vc_list = oidc4vc.get_payload_from_token(vp_token)['vp']["verifiableCredential"]
            for vc in vc_list:
                vc_format += " " + format(vc, type="vc")
        elif vp_format in ["vc+sd-jwt", "dc+sd-jwt"]:
            vc_format = "vc+sd-jwt"
        else:
            vc_list = json.loads(vp_token)["verifiableCredential"]
            if isinstance(vc_list, dict):
                vc_list = [vc_list]
            for vc in vc_list:
                vc_format += " " + format(vc, type="vc")

    # check nonce and aud in vp_token
    if access and vp_token:
        if vp_format == "ldp_vp":
            vp_sub = json.loads(vp_token)['holder']
            if json.loads(vp_token)['proof'].get('challenge') == nonce:
                nonce_status = "ok"
            else:
                nonce_status = "failed in vp_token for challenge "
                access = False
            if json.loads(vp_token)['proof'].get('domain') == data['client_id']:
                aud_status = "ok"
            else:
                aud_status = "failed in vp_token for domain "
                access = False
        elif vp_format in ["vc+sd-jwt", "dc+sd-jwt"]:
            logging.info("nonce and aud not tested with sd-jwt")
        else:
            try:
                vp_sub = vp_token_payload['iss']
            except Exception:
                logging.error("iss is missiong in vp_token")
                vp_sub = vp_token_payload['sub']
            if oidc4vc.get_payload_from_token(vp_token)['nonce'] == nonce:
                nonce_status = "ok"
            else:
                nonce_status = "failed in vp_token nonce "
                access = False
            if oidc4vc.get_payload_from_token(vp_token)['aud'] == data['client_id']:
                aud_status = "ok"
            else:
                aud_status = "failed in vp_token aud"
                access = False
    
    #  check profile compliance
    if access:
        if verifier_data['profile'] == 'DEFAULT' and vp_token:
            if vp_format != 'ldp_vp':
                logging.warning("wrong VP type for profile DEFAULT")
                access = False
            elif vp_sub[:12] != 'did:key:z6Mk':
                logging.warning("wrong key for profile DEFAULT")
            else:
                logging.info('Profile DEFAULT is respected')
        else:
            pass
        
    status_code = 200 if access else 400
    
    try:
        state_status = state
    except Exception:
        state_status = "Unknown"
        
    detailed_response = {
        "wallet_error_response": request.form.get('error'),
        "wallet_error_description_response": request.form.get('error_description'),
        "created": datetime.timestamp(datetime.now()),
        "qrcode_status": qrcode_status,
        "state": state_status,
        "vp format": vp_format,
        "vc format": vc_format,
        "subject_syntax_type": subject_syntax_type,
        "presentation_submission_status": presentation_submission_status,
        "nonce_status": nonce_status,
        "aud_status": aud_status,
        "response_format": response_format,
        "id_token_status": id_token_status,
        "vp_token_status": vp_token_status,
        "status_code": status_code,
    }
    logging.info("response detailed = %s", json.dumps(detailed_response, indent=4))

    if status_code == 400:
        response = {
            "error": "access_denied",
            "error_description": json.dumps(detailed_response)
        }
        logging.info("Access denied")
    else:
        response = "{}"
    
    # follow up
    if id_token:
        sub = id_token_payload.get('sub')
    else:
        try:
            sub = vp_sub
        except Exception:
            sub = "Error"
    
    # data sent to application
    wallet_data = json.dumps({
                    "access": access,
                    "detailed_response": json.dumps(detailed_response),
                    "vp_token_payload": vp_token_payload, # jwt_vp payload or json-ld 
                    "vp_format": vp_format,
                    "sub": sub,
                    "id_token": id_token,
                    "presentation_submission": presentation_submission
                    })
    red.setex(stream_id + "_wallet_data", CODE_LIFE, wallet_data)
    event_data = json.dumps({"stream_id": stream_id})
    red.publish('api_oidc4vc_verifier', event_data)
    return jsonify(response), status_code


def oidc4vc_login_followup(red):  
    """
    check if user is connected or not and redirect data to authorization server
    Prepare de data to transfer
    create activity record
    """
    logging.info("Enter follow up endpoint")
    try:
        stream_id = request.args.get('stream_id')
        code = json.loads(red.get(stream_id).decode())['code']
    except Exception:
        return jsonify("Forbidden"), 403
    try:
        stream_id_wallet_data = json.loads(red.get(stream_id + '_wallet_data').decode())
    except Exception as e:
        logging.error("code expired in follow up = %d", str(e))
        resp = {
            'code': code,
            'error': "access_denied",
            'error_description': "Session expired"
        }
        session['verified'] = False
        return redirect('/sandbox/verifier/app/authorize?' + urlencode(resp))

    if not stream_id_wallet_data['access']:
        resp = {
            'code': code,
            'error': 'access_denied',
            'error_description': stream_id_wallet_data['detailed_response']
        }
        session['verified'] = False
    else:
        session['verified'] = True
        red.setex(code + "_wallet_data", CODE_LIFE, json.dumps(stream_id_wallet_data))
        resp = {'code': code}

    return redirect('/sandbox/verifier/app/authorize?' + urlencode(resp))


def oidc4vc_login_stream(red):
    def login_event_stream(red):
        pubsub = red.pubsub()
        pubsub.subscribe('api_oidc4vc_verifier')
        for message in pubsub.listen():
            if message['type']=='message':
                yield 'data: %s\n\n' % message['data'].decode()
    headers = { "Content-Type": "text/event-stream",
                "Cache-Control": "no-cache",
                "X-Accel-Buffering": "no"}
    return Response(login_event_stream(red), headers=headers)

