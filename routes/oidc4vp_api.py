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
from urllib.parse import urlencode
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
    
    # endpoints for siopv2 wallet
    app.add_url_rule('/sandbox/verifier/wallet',  view_func=oidc4vc_login_qrcode, methods=['GET', 'POST'], defaults={'red': red, 'mode': mode})
    app.add_url_rule('/sandbox/verifier/wallet/.well-known/openid-configuration',  view_func=wallet_openid_configuration, methods = ['GET'])

    app.add_url_rule('/sandbox/verifier/wallet/endpoint/<stream_id>',  view_func=oidc4vc_login_endpoint, methods=['POST'],  defaults={'red': red}) # redirect_uri for PODST
    app.add_url_rule('/sandbox/verifier/wallet/request_uri/<id>',  view_func=oidc4vc_request_uri, methods=['GET'], defaults={'red': red})
    app.add_url_rule('/sandbox/verifier/wallet/client_metadata_uri/<id>',  view_func=client_metadata_uri, methods=['GET'], defaults={'red': red})
    app.add_url_rule('/sandbox/verifier/wallet/presentation_definition_uri/<id>',  view_func=presentation_definition_uri, methods=['GET'], defaults={'red': red})
    app.add_url_rule('/sandbox/verifier/wallet/followup',  view_func=oidc4vc_login_followup, methods=['GET'], defaults={'red': red})

    app.add_url_rule('/sandbox/verifier/wallet/stream',  view_func=oidc4vc_login_stream, defaults={ 'red': red})
    return
    

def oidc4vc_build_id_token(client_id, sub, nonce, mode):
    """
    Build an Id_token for application 

    alg value: https://www.rfc-editor.org/rfc/rfc7518#section-3
    https://jwcrypto.readthedocs.io/en/latest/jwk.html
    """
    verifier_key = jwk.JWK(**RSA_KEY_DICT) 
    header = {
        "typ":"JWT",
        "kid": RSA_KEY_DICT['kid'],
        "alg": "RS256"
    }
    # https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
    payload = {
        "iss": mode.server + 'sandbox/verifier/app',
        "nonce": nonce,
        "iat": datetime.timestamp(datetime.now()),
        "aud": client_id,
        "exp": datetime.timestamp(datetime.now()) + 1000,
        "sub": sub,
    }  
    logging.info("ID Token payload = %s", payload)
    token = jwt.JWT(header=header, claims=payload, algs=["RS256"])
    token.make_signed_token(verifier_key)
    return token.serialize()


def oidc4vc_jwks():
    return jsonify({"keys": [public_rsa_key]})


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
    logging.info("authorization endpoint request  = %s", request.args)
    """ https://www.rfc-editor.org/rfc/rfc6749.html#section-4.1.2
    code_wallet_data = 
    {
        "vp_token_payload",: xxxxx
        "sub": xxxxxx
    }
    """
    # user is connected, successful exit to client with code
    if session.get('verified') and request.args.get('code'):
        code = request.args['code']
        code_data = json.loads(red.get(code).decode())
        
        # authorization code flow -> redirect with code
        if code_data['response_type'] == 'code':
            logging.info("response_type = code: successful redirect to client with code = %s", code) 
            resp = {'code': code,  'state': code_data.get('state')} if code_data.get('state') else {'code': code}
            logging.info('response to redirect_uri = %s', resp)
            return redirect(code_data['redirect_uri'] + '?' + urlencode(resp)) 

        # implicit flow -> redirect with id_token
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
            
            id_token = oidc4vc_build_id_token(code_data['client_id'], code_wallet_data['sub'], code_data['nonce'], mode)
            resp = {"id_token": id_token} 
            logging.info("redirect to application with id-token = %s", id_token)
            return redirect(code_data['redirect_uri'] + sep + urlencode(resp))

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
        code_data = json.loads(red.get(code).decode())
        resp = {'error': request.args['error']}
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
            'response_mode': request.args.get('response_mode')
        }
    except Exception:
        logging.warning('invalid request received in authorization server')
        try:
            return manage_error_request("invalid_request_object")
        except Exception:
            session.clear()
            return jsonify('request malformed'), 400

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
    return redirect('/sandbox/verifier/wallet?code=' + code)


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
    id_token = oidc4vc_build_id_token(client_id, code_wallet_data['sub'], data['nonce'], mode)
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
"""
https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
only access token is needed
"""


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
        headers = {
            "Cache-Control": "no-store",
            "Pragma": "no-cache",
            "Content-Type": "application/json"}
        return Response(response=json.dumps(payload), headers=headers)
    
    except Exception:
        logging.warning("access token expired")
        headers = {'WWW-Authenticate': 'Bearer realm="userinfo", error="invalid_token", error_description = "The access token expired"'}
        return Response(status=401,headers=headers)
    
################################# SIOPV2 + OIDC4VP ###########################################


def wallet_openid_configuration():
    config = json.load(open("ebsiv3_siopv2_openid_configuration.json", "r"))
    return jsonify(config)


def build_jwt_request(key, kid, iss, aud, request) -> str:
    """
    For wallets natural person as jwk is added in header
    https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-proof-types
    """
    key = json.loads(key) if isinstance(key, str) else key
    signer_key = jwk.JWK(**key) 
    header = {
        'typ':'JWT',
        'alg': oidc4vc.alg(key),
        'kid': kid
    }
    payload = {
        'iss': iss,
        'aud': aud,
        'exp': datetime.timestamp(datetime.now()) + 1000,
    }
    payload |= request
    token = jwt.JWT(header=header, claims=payload, algs=[oidc4vc.alg(key)])
    token.make_signed_token(signer_key)
    return token.serialize()


def client_metadata_uri(id, red):
    #  https://openid.net/specs/openid-connect-registration-1_0.html
    try:
        client_metadata = json.loads(red.get(id).decode())
    except Exception:
        return jsonify('Request timeout'), 408
    return jsonify(client_metadata)


def build_client_metadata(client_id, redirect_uri) -> dict:
    try:
        verifier_data = json.loads(read_oidc4vc_verifier(client_id))
    except Exception:
        return
    return {
        'subject_syntax_types_supported': [
            "did:key",
            "did:ebsi",
            "did:tz",
            "did:key",
            "did:ethr",
            "did:polygonid",
            "did:pkh",
            "did:hedera",
            "did:web"
        ], 
        'redirect_uris': [redirect_uri],
        'request_parameter_supported': bool(
            verifier_data.get('request_parameter_supported')
        ),
        'request_uri_parameter_supported': bool(
            verifier_data.get('request_uri_parameter_supported')
        ),
        'cryptographic_suites_supported': [
            'ES256K',
            'ES256',
            'EdDSA',
            'RS256',
        ], 
        'client_name': 'Talao-Altme Verifier',
        "logo_uri": "https://altme.io/",
        "contacts": ["contact@talao.io"]
    }


def presentation_definition_uri(id, red):
    try:
        presentation_definition = json.loads(red.get(id).decode())
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
    
    verifier_id = json.loads(code_data)['client_id']
    nonce = json.loads(code_data).get('nonce')   
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
                if verifier_data.get('filter_type_array'):
                    prez.add_constraint_with_type_array(
                        "$.type",
                        verifier_data[vc],
                        "Input descriptor for credential " + i,
                        verifier_data[reason],
                        id= verifier_data[vc].lower() + '_' + i
                    )
                else:
                    prez.add_constraint(
                        "$.credentialSubject.type",
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
    if 'vp_token' in response_type and profile[verifier_data['profile']].get("verifier_vp_type") == 'ldp_vp':
        prez.add_format_ldp_vp()
        prez.add_format_ldp_vc()
    if 'vp_token' in response_type and profile[verifier_data['profile']].get("verifier_vp_type") == 'jwt_vp':
        prez.add_format_jwt_vp()
        prez.add_format_jwt_vc()

    nonce = nonce or str(uuid.uuid1())
    redirect_uri = mode.server + "sandbox/verifier/wallet/endpoint/" + stream_id
    
    # general authorization request
    authorization_request = { 
        "response_type": response_type,
        "state": str(uuid.uuid1())  # unused
    }
    
    if response_type == 'id_token':
        authorization_request['response_mode'] = 'post'
    else:
        authorization_request['response_mode'] = 'direct_post'
    
    # TEST 10 TODO
    if verifier_id not in ["ejqwxtjdlu", "zkzkwshdns"]:    
        if response_type == 'vp_token' and verifier_data['profile'] != "EBSI-V3":
            authorization_request['response_uri'] = redirect_uri
        else:
            authorization_request['redirect_uri'] = redirect_uri
    
    # Set client_id, use W3C DID identifier for client_id "on" ou None
    if not verifier_data.get('client_id_as_DID'):
        client_id = redirect_uri
    else:
        client_id = verifier_data['did']
    
    authorization_request['client_id'] = client_id

    # OIDC4VP
    if 'vp_token' in response_type:
        authorization_request['nonce'] = nonce 
            
        # client_metadata_uri
        id = str(uuid.uuid1())
        client_metadata = build_client_metadata(client_id, redirect_uri)
        red.setex(id, QRCODE_LIFE, json.dumps(client_metadata))
        authorization_request['client_metadata_uri'] = mode.server + "sandbox/verifier/wallet/client_metadata_uri/" + id
        
        # client_id_scheme
        if verifier_data.get('client_id_as_DID'):
            authorization_request['client_id_scheme'] = 'did'
        else:
            authorization_request['client_id_scheme'] = 'redirect_uri'
        
        # presentation_definition
        presentation_definition = prez.get()
        authorization_request['presentation_definition'] = presentation_definition   # TODO
        authorization_request['aud'] = 'https://self-issued.me/v2'   #TODO implies wallet profile 

        # presentation_definition_uri
        if verifier_data.get('presentation_definition_uri'):
            id = str(uuid.uuid1())
            red.setex(id, QRCODE_LIFE, json.dumps(presentation_definition))        
            authorization_request['presentation_definition_uri'] = mode.server + 'sandbox/verifier/wallet/presentation_definition_uri/' + id
            if authorization_request.get('presentation_definition'):
                del authorization_request['presentation_definition']
        
    # SIOPV2
    if 'id_token' in response_type:
        authorization_request['scope'] = 'openid'       
        authorization_request['registration'] = json.dumps(json.load(open('siopv2_config.json', 'r')))           


    # manage request_uri as jwt
    request_as_jwt = build_jwt_request(
        verifier_data['jwk'],
        verifier_data['verification_method'],
        verifier_data['did'],
        'https://self-issued.me/v2', # aud requires static siopv2 data
        authorization_request
    )
    
    if verifier_data.get('request_uri_parameter_supported'):
        id = str(uuid.uuid1())
        red.setex(id, QRCODE_LIFE, json.dumps(request_as_jwt))
        authorization_request_displayed = { 
            "client_id": client_id,
            "request_uri": mode.server + "sandbox/verifier/wallet/request_uri/" + id 
        }
    else:
        if 'vp_token' not in response_type and verifier_data.get('request_parameter_supported'):
            authorization_request['request'] = request_as_jwt
        authorization_request_displayed = authorization_request

    # store data
    data = { 
        "pattern": authorization_request,
        "code": request.args['code'],
        "client_id": client_id,
        "verifier_id": verifier_id
    }
    red.setex(stream_id, QRCODE_LIFE, json.dumps(data))

    if 'vp_token' not in response_type:
        presentation_definition = {"N/A": "N/A"}
        
    url = prefix + '?' + urlencode(authorization_request_displayed)
    deeplink_talao = mode.deeplink_talao + 'app/download/authorize?' + urlencode(authorization_request_displayed)
    deeplink_altme = mode.deeplink_altme + 'app/download/authorize?' + urlencode(authorization_request_displayed)
    logging.info("weblink for same device flow = %s", deeplink_altme)
    qrcode_page = verifier_data.get('verifier_landing_page_style')
    return render_template(
        qrcode_page,
        url=url,
        authorization_request=json.dumps(authorization_request, indent=4),
        url_json=json.dumps(authorization_request_displayed, indent=4),
        presentation_definition=json.dumps(presentation_definition, indent=4),
        client_metadata=json.dumps(build_client_metadata(client_id, redirect_uri), indent=4),
        deeplink_talao=deeplink_talao,
        deeplink_altme=deeplink_altme,
        stream_id=stream_id,
        title=verifier_data['title'],
        page_title=verifier_data['page_title'],
        page_subtitle=verifier_data['page_subtitle'],
        page_description=verifier_data['page_description'],
        code=request.args['code']
    )
    

def oidc4vc_request_uri(id, red):
    """
    Request by uri
    https://www.rfc-editor.org/rfc/rfc9101.html
    """
    try:
        payload = red.get(id).decode().replace('"', '')
    except Exception:
        return jsonify("Request timeout"), 408
    headers = { "Content-Type": "application/oauth-authz-req+jwt",
                "Cache-Control": "no-cache"
    }
    return Response(payload, headers=headers)


async def oidc4vc_login_endpoint(stream_id, red):
    logging.info("Enter wallet response endpoint")
    """
    https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.2
    
    """
    access = True
    qrcode_status = "Unknown"

    try:
        qrcode_status = "ok"
        data = json.loads(red.get(stream_id).decode())
        verifier_id = data['verifier_id']
        verifier_data = json.loads(read_oidc4vc_verifier(verifier_id))
        logging.info('Profile = %s', verifier_data['profile'])
    except Exception:
        qrcode_status = "QR code expired"
        access = False

    # prepare the verifier response to wallet
    response_format = "Unknown"
    vc_type = "Unknown"
    state_status = 'unknown'
    vp_type = "Unknown"
    presentation_submission_status = "Unknown"
    vp_token_status = "Unknown"
    id_token_status = "Unknown"
    aud_status = "unknown"
    nonce_status = "Unknown"
    subject_syntax_type = "DID"
    vp_token_payload = {}
    id_token_payload = {}

    # get id_token, vp_token and presentation_submission
    if access:
        vp_token = request.form.get('vp_token')
        id_token = request.form.get('id_token')
        presentation_submission = request.form.get('presentation_submission')
        response_format = "ok"
        logging.info('id_token received = %s', id_token)

        state = request.form.get('id_token')

        # check types of vp
        if vp_token:
            if vp_token[:2] == "ey":
                vp_type = "jwt_vp"
            elif json.loads(vp_token).get("@context"):
                vp_type = "ldp_vp"
            else:
                vp_type = "Unknown"
                logging.error("vp token type unknown %s $s", vp_token, type(vp_token))

        if vp_token and vp_type == "ldp_vp":
            logging.info('vp token received = %s', json.dumps(json.loads(vp_token), indent=4))
        else: 
            logging.info('vp token received = %s', vp_token)
        
        if presentation_submission:
            logging.info('presentation submission received = %s', json.dumps(json.loads(presentation_submission), indent=4))
        else: 
            logging.info('presentation submission received = %s', "")

        if not id_token and not vp_token:
            response_format = "invalid request format",
            access = False
    
    if access and not id_token:
        id_token_status = "Not received"
    
    if access and not vp_token:
        vp_token_status = "Not received"
    
    if access and not presentation_submission:
        presentation_submission_status = "Not received"
        
    # check presentation submission
    if access and vp_token:
        if not presentation_submission:
            presentation_submission_status = "Not found"
            access = False 
        else:
            presentation_submission_status = "ok"

    if access:
        nonce = data['pattern'].get('nonce')

    # check id_token signature
    if access and id_token:
        try:
            oidc4vc.verif_token(id_token, nonce)
        except Exception:
            id_token_status = "signature check failed"
            access = False 
    
    if access and id_token:
        try:
            id_token_payload = oidc4vc.get_payload_from_token(id_token)
            id_token_header = oidc4vc.get_header_from_token(id_token)
            id_token_jwk = id_token_header.get('jwk')
            id_token_kid = id_token_header.get('kid')
            id_token_iss = id_token_payload.get('iss')
            id_token_sub = id_token_payload.get('sub')
            id_token_sub_jwk = id_token_payload.get('sub_jwk')
            id_token_nonce = id_token_payload.get('nonce')
        except Exception:
            id_token_status += " id_token invalid format "
            access = False
        if id_token_sub_jwk:
            subject_syntax_type = "JWK Thumbprint"
        if not id_token_sub_jwk and not id_token_kid:
            access = False
        if id_token_sub_jwk and id_token_kid:
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
        if vp_type == "jwt_vp":
            try:
                oidc4vc.verif_token(vp_token, nonce)
                vp_token_status = "ok"
                vp_token_payload = oidc4vc.get_payload_from_token(vp_token)
            except Exception:
                vp_token_status = "signature check failed"
                access = False
        else:
            verifyResult = json.loads(await didkit.verify_presentation(vp_token, "{}"))
            vp_token_status = verifyResult

    # check VC signature

    # check types of vc
    if access and vp_token:
        vc_type = ""
        if vp_type == "jwt_vp":
            vc_list = oidc4vc.get_payload_from_token(vp_token)['vp']["verifiableCredential"]
            for vc in vc_list:
                try:
                    vc[:2] == "ey" 
                    vc_type += " jwt_vc"
                except Exception:
                    vc_type += " ldp_vc"
        else:
            vc_list = json.loads(vp_token)["verifiableCredential"]
            if isinstance(vc_list, dict):
                vc_list = [vc_list]
            for vc in vc_list:
                try:
                    vc[:2] == "ey" 
                    vc_type += " jwt_vc"
                except Exception:
                    vc_type += " ldp_vc"

    # check nonce and aud in vp_token
    if access and vp_token:
        if vp_type == "ldp_vp":
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
        else:
            vp_sub = vp_token_payload['iss']
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
    
    status_code = 200 if access else 400
    
    # Testing
    if verifier_id in ["zvuzyxjhjk", "rkubsscrkt"]:
        print("Test case error ")
        status_code = 400
        access = False

    if state:
        state_status = state
        
    detailed_response = {
        "created": datetime.timestamp(datetime.now()),
        "qrcode_status": qrcode_status,
        "state": state_status,
        "vp type": vp_type,
        "vc type": vc_type,
        "subject_syntax_type": subject_syntax_type,
        "presentation_submission_status": presentation_submission_status,
        "nonce_status": nonce_status,
        "aud_status": aud_status,
        "response_format": response_format,
        "id_token_status": id_token_status,
        "vp_token_status": vp_token_status,
        "status_code": status_code,
    }
    if status_code == 400:
        response = {
            "error": "access_denied",
            "error_description": json.dumps(detailed_response)
        }
    # TEST
    elif verifier_id in ["novanyhlhs", "uxcdccjhmq"]:
        response = {
            "redirect_uri": "https://altme.io",
            "response_code": "1223456789"
        }
    else:
        response = "{}"
    
    logging.info("response = %s", json.dumps(response, indent=4))
    logging.info("response detailed = %s", json.dumps(detailed_response, indent=4))
    
    # follow up
    if id_token:
        sub = id_token_payload.get('sub')
    else:
        sub = vp_sub
    wallet_data = json.dumps({
                    "access": access,
                    "vp_token_payload": vp_token_payload,
                    "sub": sub
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
    except Exception:
        logging.error("code expired in follow up")
        resp = {
            'code': code,
            'error': "access_denied",
            'error_description': ""
        }
        session['verified'] = False
        return redirect('/sandbox/verifier/app/authorize?' + urlencode(resp))

    if not stream_id_wallet_data['access']:
        resp = {
            'code': code,
            'error': 'access_denied',
            'error_description': ""
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

