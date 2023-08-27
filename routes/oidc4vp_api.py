"""
This is a bridge between the SIOPV2 flow used by EBSI with a verifier and a standard Openid authorization code flow or implicit flow with used with the customer application

Customer can use any OpenId lib in its own framework to access an EBSI conformant wallet


"""

from flask import jsonify, request, render_template, redirect
from flask import session, Response, jsonify
import json
import uuid
from urllib.parse import urlencode
import logging
import base64
from datetime import datetime
from jwcrypto import jwk, jwt
from db_api import read_ebsi_verifier
import pkce # https://github.com/xzava/pkce
import oidc4vc
from profile import profile
from oidc4vc_constante import type_2_schema
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
public_rsa_key =  rsa_key.export(private_key=False, as_dict=True)


def init_app(app,red, mode) :
    # endpoints for OpenId customer application
    app.add_url_rule('/sandbox/ebsi/authorize',  view_func=ebsi_authorize, methods = ['GET', 'POST'], defaults={"red" : red, "mode" : mode})
    app.add_url_rule('/sandbox/ebsi/token',  view_func=ebsi_token, methods = ['GET', 'POST'], defaults={"red" : red, 'mode' : mode})
    app.add_url_rule('/sandbox/ebsi/logout',  view_func=ebsi_logout, methods = ['GET', 'POST'])
    app.add_url_rule('/sandbox/ebsi/userinfo',  view_func=ebsi_userinfo, methods = ['GET', 'POST'], defaults={"red" : red})
    app.add_url_rule('/sandbox/ebsi/.well-known/openid-configuration', view_func=ebsi_openid_configuration, methods=['GET'], defaults={'mode' : mode})
    app.add_url_rule('/sandbox/ebsi/jwks.json', view_func=ebsi_jwks, methods=['GET'])
    
    # endpoints for siopv2 wallet
    app.add_url_rule('/sandbox/ebsi/login',  view_func=ebsi_login_qrcode, methods = ['GET', 'POST'], defaults={'red' : red, 'mode' : mode})
    app.add_url_rule('/sandbox/ebsi/login/endpoint/<stream_id>',  view_func=ebsi_login_endpoint, methods = ['POST'],  defaults={'red' : red}) # redirect_uri for PODST
    app.add_url_rule('/sandbox/ebsi/login/request_uri/<stream_id>',  view_func=ebsi_request_uri, methods = ['GET'], defaults={'red' : red})
    app.add_url_rule('/sandbox/ebsi/login/client_metadata_uri/<stream_id>',  view_func=client_metadata_uri, methods = ['GET'], defaults={'red' : red})
    app.add_url_rule('/sandbox/ebsi/login/followup',  view_func=ebsi_login_followup, methods = ['GET', 'POST'], defaults={'red' :red})
    app.add_url_rule('/sandbox/ebsi/login/stream',  view_func=ebsi_login_stream, defaults={ 'red' : red})
    return
    

def ebsi_build_id_token(client_id, sub, nonce, mode) :
    """
    Build an Id_token for application 

    alg value : https://www.rfc-editor.org/rfc/rfc7518#section-3
    https://jwcrypto.readthedocs.io/en/latest/jwk.html
    """
    verifier_key = jwk.JWK(**RSA_KEY_DICT) 
    header = {
        "typ" :"JWT",
        "kid": RSA_KEY_DICT['kid'],
        "alg": "RS256"
    }
    # https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
    payload = {
        "iss" : mode.server +'sandbox/ebsi',
        "nonce" : nonce,
        "iat": datetime.timestamp(datetime.now()),
        "aud" : client_id,
        "exp": datetime.timestamp(datetime.now()) + 1000,
        "sub" : sub,
    }  
    logging.info("ID Token payload = %s", payload)
    token = jwt.JWT(header=header,claims=payload, algs=["RS256"])
    token.make_signed_token(verifier_key)
    return token.serialize()
   

def ebsi_jwks() :
    return jsonify({"keys" : [public_rsa_key]})


# For customer app
def ebsi_openid_configuration(mode):
    """
    For the customer application of the saas platform  
    https://openid.net/specs/openid-connect-self-issued-v2-1_0.html#name-dynamic-self-issued-openid-
    """
    oidc = {
        "issuer": mode.server + 'sandbox/ebsi',
        "authorization_endpoint":  mode.server + 'sandbox/ebsi/authorize',
        "token_endpoint": mode.server + 'sandbox/ebsi/token',
        "userinfo_endpoint": mode.server + 'sandbox/ebsi/userinfo',
        "logout_endpoint": mode.server + 'sandbox/ebsi/logout',
        "jwks_uri": mode.server + 'sandbox/ebsi/jwks.json',
        "scopes_supported": ["openid diploma verifiableid"],
        "response_types_supported": ["code", "id_token"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic"]
    }
    return jsonify(oidc)


# authorization server for customer application
"""
response_type supported = code or id_token or vp_token
code -> authorization code flow
id_token -> implicit flow

# https://openid.net/specs/openid-4-verifiable-presentations-1_0.html

"""
def ebsi_authorize(red, mode) :
    logging.info("authorization endpoint request  = %s", request.args)
    """ https://www.rfc-editor.org/rfc/rfc6749.html#section-4.1.2
     code_wallet_data = 
    {
        "vp_token_payload", : xxxxx
        "sub" : xxxxxx
    }
    """
    # user is connected, successfull exit to client with code
    if session.get('verified') and request.args.get('code') :
        code = request.args['code'] 
        code_data = json.loads(red.get(code).decode())
        
        # authorization code flow -> redirect with code
        if code_data['response_type'] == 'code' :
            logging.info("response_type = code : successfull redirect to client with code = %s", code) 
            resp = {'code' : code,  'state' : code_data.get('state')}  if  code_data.get('state') else {'code' : code}
            logging.info('response to redirect_uri = %s', resp)
            return redirect(code_data['redirect_uri'] + '?' + urlencode(resp)) 

        # implicit flow -> redirect with id_token
        elif code_data['response_type'] == 'id_token' :
            logging.info("response_type = id_token") 
            sep = "?" if code_data['response_mode'] == 'query' else "#"
            try :
                code_wallet_data = json.loads(red.get(code + "_wallet_data").decode())
            except :
                logging.error("code expired")
                resp = {'error' : "access_denied"}
                redirect_uri = code_data['redirect_uri']
                session.clear()
                return redirect(redirect_uri + sep + urlencode(resp)) 
            id_token = ebsi_build_id_token(code_data['client_id'], code_wallet_data['sub'], code_data['nonce'], mode)
            resp = {"id_token" : id_token} 
            logging.info("redirect to client with id-token = %s", id_token)
            return redirect(code_data['redirect_uri'] + sep + urlencode(resp))
        
        else :
            logging.error("session expired")
            resp = {'error' : "access_denied"}
            redirect_uri = code_data['redirect_uri']
            session.clear()
            return redirect(redirect_uri + '?' + urlencode(resp)) 
    
    # error in login, exit, clear session
    if 'error' in request.args :
        logging.warning('Error in the login process, redirect to client with error code = %s', request.args['error'])
        code = request.args['code']
        code_data = json.loads(red.get(code).decode())
        resp = {'error' : request.args['error']}
        if code_data.get('state') :
            resp['state'] = code_data['state']
        redirect_uri = code_data['redirect_uri']
        red.delete(code)
        session.clear()
        return redirect(redirect_uri + '?' + urlencode(resp)) 
    
    # User is not connected
    def manage_error_request(msg) :
        session.clear()
        resp = {'error' : msg}
        return redirect(request.args['redirect_uri'] + '?' +urlencode(resp))

    session['verified'] = False
    logging.info('user is not connected in OP')
    # PKCE https://datatracker.ietf.org/doc/html/draft-ietf-oauth-spop-14
    try :
        data = {
            'client_id' : request.args['client_id'], # required
            'scope' : request.args['scope'].split(), # required
            'state' : request.args.get('state'),
            'response_type' : request.args['response_type'], # required
            'redirect_uri' : request.args['redirect_uri'], # required
            'nonce' : request.args.get('nonce'),
            'code_challenge' : request.args.get('code_challenge'),
            'code_challenge_method' : request.args.get('code_challenge_method'),
            "expires" : datetime.timestamp(datetime.now()) + CODE_LIFE,
            'response_mode' : request.args.get('response_mode')
        }
    except :
        logging.warning('invalid request received in authorization server')
        try :
            return manage_error_request("invalid_request_object")
        except :
            session.clear()
            return jsonify('request malformed'), 400

    if not read_ebsi_verifier(request.args['client_id']) :
        logging.warning('client_id not found in client data base')
        return manage_error_request("unauthorized_client")
   
    session['redirect_uri'] = request.args['redirect_uri']
    if request.args['response_type'] not in ["code", "id_token"] :
        logging.warning('unsupported response type %s', request.args['response_type'])
        return manage_error_request("unsupported_response_type")

    # creation grant = code
    code = str(uuid.uuid1())
    red.setex(code, CODE_LIFE, json.dumps(data))
    resp = {'code' : code}
    return redirect('/sandbox/ebsi/login?code=' + code)
   

# token endpoint for customer application
def ebsi_token(red, mode) :
    #https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
    logging.info("token endpoint request ")

    def manage_error (msg) :
        logging.warning(msg)
        endpoint_response= {"error": msg}
        headers = {'Content-Type': 'application/json'}
        return Response(response=json.dumps(endpoint_response), status=400, headers=headers)
        
    try :
        token = request.headers['Authorization']
        token = token.split(" ")[1]
        token = base64.b64decode(token).decode()
        client_secret = token.split(":")[1]
        client_id = token.split(":")[0]
        verifier_data = json.loads(read_ebsi_verifier(client_id))
        grant_type =  request.form['grant_type']
        code = request.form['code']
        redirect_uri = request.form['redirect_uri']
        code_verifier = request.form.get('code_verifier')
    except :
        return manage_error("invalid_request")
     
    try :
        data = json.loads(red.get(code).decode())
    except :
        logging.error("red get probleme sur code")
        return manage_error("invalid_grant") 
    
    if client_id != data['client_id'] :
        return manage_error("invalid_client")
    if not verifier_data.get("pkce") and verifier_data['client_secret'] != client_secret :
        return manage_error("invalid_client")
    elif redirect_uri != data['redirect_uri']:
        return manage_error("invalid_redirect_uri")
    elif grant_type != 'authorization_code' :
        return manage_error("unhauthorized_client")
    if verifier_data.get('pkce') == 'on' and not code_verifier :
        logging.warning("pb code verifier")
        return manage_error("invalid_request")
    if verifier_data.get("pkce") and pkce.get_code_challenge(code_verifier) != data['code_challenge'] :
        logging.warning('code verifier not correct')
        return manage_error("unhauthorized_client")
    
    # token response
    try :
        code_wallet_data = json.loads(red.get(code + "_wallet_data").decode())
    except :
        logging.error("redis get problem to get code_ebsi")
        return manage_error("invalid_grant")
    id_token = ebsi_build_id_token(client_id, code_wallet_data['sub'], data['nonce'], mode)
    logging.info('id_token and access_token sent to client from token endpoint')
    access_token = str(uuid.uuid1())
    endpoint_response = {"id_token" : id_token,
                        "access_token" : access_token,
                        "token_type" : "Bearer",
                        "expires_in": ACCESS_TOKEN_LIFE
                        }
    red.setex(access_token + '_wallet_data', 
            ACCESS_TOKEN_LIFE,
            json.dumps({
                "client_id" : client_id,
                "sub" : code_wallet_data['sub'],
                "vp_token_payload" : code_wallet_data['vp_token_payload']}))
    headers = {
        "Cache-Control" : "no-store",
        "Pragma" : "no-cache",
        'Content-Type': 'application/json'}
    return Response(response=json.dumps(endpoint_response), headers=headers)
 

# logout endpoint
#https://openid.net/specs/openid-connect-rpinitiated-1_0-02.html
def ebsi_logout() :
    if not session.get('verified') :
        return jsonify ('Forbidden'), 403
    if request.method == "GET" :
        id_token_hint = request.args.get('id_token_hint')
        post_logout_redirect_uri = request.args.get('post_logout_redirect_uri')
    elif request.method == "POST" :
        id_token_hint = request.form.get('id_token_hint')
        post_logout_redirect_uri = request.form.get('post_logout_redirect_uri')
    if not post_logout_redirect_uri :
        post_logout_redirect_uri = session.get('redirect_uri')
    session.clear()
    logging.info("logout call received, redirect to %s", post_logout_redirect_uri)
    return redirect(post_logout_redirect_uri)


# userinfo endpoint
"""
 https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
 only access token is needed

"""
def ebsi_userinfo(red) :
    logging.info("user info endpoint request")
    access_token = request.headers["Authorization"].split()[1]
    try :
        wallet_data = json.loads(red.get(access_token + '_wallet_data').decode())
        payload = {
            "sub" : wallet_data['sub'],
            "vp_token_payload" : wallet_data["vp_token_payload"]
        }
        headers = {
            "Cache-Control" : "no-store",
            "Pragma" : "no-cache",
            "Content-Type": "application/json"}
        return Response(response=json.dumps(payload), headers=headers)
    
    except :
        logging.warning("access token expired")
        headers = {'WWW-Authenticate' : 'Bearer realm="userinfo", error="invalid_token", error_description = "The access token expired"'}
        return Response(status=401,headers=headers)
    
################################# SIOPV2 OIDC4VP ###########################################

"""
https://openid.net/specs/openid-connect-self-issued-v2-1_0.html#section-10

example of an siopv2 authorisation request
qrcode ="openid://
    ?scope=openid
    &response_type=id_token
    &client_id=https%3A%2F%2Fapi-conformance.ebsi.eu%2Fconformance%2Fv2%2Fverifier-mock%2Fauthentication-responses
    &redirect_uri=https%3A%2F%2Fapi-conformance.ebsi.eu%2Fconformance%2Fv2%2Fverifier-mock%2Fauthentication-responses
    &claims=%7B%22id_token%22%3A%7B%22email%22%3Anull%7D%2C%22vp_token%22%3A%7B%22presentation_definition%22%3A%7B%22id%22%3A%22conformance_mock_vp_request%22%2C%22input_descriptors%22%3A%5B%7B%22id%22%3A%22conformance_mock_vp%22%2C%22name%22%3A%22Conformance%20Mock%20VP%22%2C%22purpose%22%3A%22Only%20accept%20a%20VP%20containing%20a%20Conformance%20Mock%20VA%22%2C%22constraints%22%3A%7B%22fields%22%3A%5B%7B%22path%22%3A%5B%22%24.vc.credentialSchema%22%5D%2C%22filter%22%3A%7B%22allOf%22%3A%5B%7B%22type%22%3A%22array%22%2C%22contains%22%3A%7B%22type%22%3A%22object%22%2C%22properties%22%3A%7B%22id%22%3A%7B%22type%22%3A%22string%22%2C%22pattern%22%3A%22https%3A%2F%2Fapi-conformance.ebsi.eu%2Ftrusted-schemas-registry%2Fv2%2Fschemas%2Fz3kRpVjUFj4Bq8qHRENUHiZrVF5VgMBUe7biEafp1wf2J%22%7D%7D%2C%22required%22%3A%5B%22id%22%5D%7D%7D%5D%7D%7D%5D%7D%7D%5D%2C%22format%22%3A%7B%22jwt_vp%22%3A%7B%22alg%22%3A%5B%22ES256K%22%5D%7D%7D%7D%7D%7D
    &nonce=051a1861-cfb6-48c8-861a-a61af5d1c139
    &conformance=36c751ad-7c32-4baa-ab5c-2a303aad548f"

"""
def build_jwt_request_for_siopv2(key, kid, iss, aud, redirect_uri, nonce):
    """
  For wallets natural person as jwk is added in header
  https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-proof-types
  """
    key = json.loads(key) if isinstance(key, str) else key
    signer_key = jwk.JWK(**key) 
    header = {
        'typ' :'JWT',
        'alg': oidc4vc.alg(key),
        'kid' : kid
    }
    payload = {
        'iss' : iss, 
        'aud' : aud,
        'scope' : "openid",
        'redirect_uri' : redirect_uri,
        'client_id' : iss,
        "response_type": "id_token",
        "response_mode": "post",
        'exp': datetime.timestamp(datetime.now()) + 1000,
        'nonce' : nonce
    }  
    token = jwt.JWT(header=header,claims=payload, algs=[oidc4vc.alg(key)])
    token.make_signed_token(signer_key)
    return token.serialize()


def client_metadata_uri(stream_id, red):
    #https://openid.net/specs/openid-connect-registration-1_0.html
    return jsonify(client_metadata(stream_id, red))


def client_metadata(stream_id, red) :
    client_metadata = {
        'subject_syntax_types_supported': [
            "did:key",
            "did:ebsi",
            "did:tz",
            "did:ion",
            "did:key",
            "did:ethr",
            "did:ala",
            "did:sol",
            "did:peer",
            "did:polygonid",
            "did:pkh",
            "did:hedera",
            "did:web"
        ], 
        'cryptographic_suites_supported' : ['ES256K','ES256','EdDSA','RS256'],
        'client_name': 'Talao-Altme Verifier',
        "logo_uri": "https://altme.io/",
        "contacts": ["contact@talao.io"]
    }
    return client_metadata


def ebsi_login_qrcode(red, mode):
    stream_id = str(uuid.uuid1())
    try :
        client_id = json.loads(red.get(request.args['code']).decode())['client_id']
        nonce = json.loads(red.get(request.args['code']).decode()).get('nonce')
        verifier_data = json.loads(read_ebsi_verifier(client_id))
        verifier_profile = profile[verifier_data['profile']]
    except :
        logging.error("session expired in login_qrcode")
        return render_template("verifier_oidc/verifier_session_problem.html", message='Session expired')
    
    if verifier_data.get('id_token') and not verifier_data.get('vp_token') :
        response_type = 'id_token'
    elif verifier_data.get('id_token') :
        response_type = 'id_token vp_token'
    elif verifier_data.get('vp_token') :
        response_type = 'vp_token'
    else :
        return render_template("verifier_oidc/verifier_session_problem.html", message='Invalid configuration')
    
    # Manage presentation definition with a subset of PEX 2.0
    
    if 'vp_token' in response_type and not verifier_data['group'] :    
        prez = pex.Presentation_Definition(verifier_data['application_name'], "Talao-Altme presentation definition with a subset of PEX v2.0 syntax")  
        for i in ["1", "2", "3", "4"] :
            vc = 'vc_' + i
            reason = 'reason_' + i
            if verifier_data[vc] != 'None'   :
                if verifier_data['profile'] == "EBSI-V2" :
                    prez.add_constraint("$.credentialSchema.id", type_2_schema[verifier_data[vc]], "Input descriptor for credential " + i , verifier_data[reason])
                else :
                    prez.add_constraint("$.credentialSubject.type",
                                        verifier_data[vc],
                                        "Input descriptor for credential " + i,
                                        verifier_data[reason],
                                        id = verifier_data[vc].lower() + '_' + i)
    
    if 'vp_token' in response_type and verifier_data['group'] : 
        prez = pex.Presentation_Definition(verifier_data['application_name'], "Talao-Altme presentation definition with a subset of PEX v2.0 syntax")  
        prez.add_group("Group A", "A")
        for i in ["5", "6", "7", "8"] :
            vc = 'vc_' + i
            if verifier_data[vc] != 'None'   :
                if verifier_data['profile'] == "EBSI-V2" :
                    prez.add_constraint_with_group("$.credentialSchema.id", type_2_schema[verifier_data[vc]], "Input descriptor for credential " + i, "", "A")
                else :
                    prez.add_constraint_with_group("$.credentialSubject.type",
                                                        verifier_data[vc],
                                                        "Input descriptor for credential " + i,
                                                        "",
                                                        "A",
                                                        id=verifier_data[vc].lower() + '_' + i)
        
    # add format depending on profile
    if 'vp_token' in response_type and profile[verifier_data['profile']].get("verifier_vp_type") == 'ldp_vp' :
                prez.add_format_ldp_vp()
                prez.add_format_ldp_vc()
    if 'vp_token' in response_type and profile[verifier_data['profile']].get("verifier_vp_type") == 'jwt_vp' :
                prez.add_format_jwt_vp()
                prez.add_format_jwt_vc()

    if 'vp_token' in response_type :
        presentation_definition = prez.get()
    else :
        presentation_definition = ""

    nonce = nonce if nonce else str(uuid.uuid1())
    authorization_request = { 
        "response_type" : response_type,
        "client_id" : verifier_data['did'],
        "redirect_uri" : mode.server + "sandbox/ebsi/login/endpoint/" + stream_id,
        "nonce" : nonce
    }
   
    if verifier_data['profile'] == "EBSI-V2" :
        # previoous release of the OIDC4VC specifications
        # OIDC claims parameter https://openid.net/specs/openid-connect-core-1_0.html#ClaimsParameter
        authorization_request['scope'] = 'openid'
        authorization_request['claims'] = {"vp_token":{"presentation_definition": presentation_definition}}
        prefix = verifier_profile["oidc4vp_prefix"]
    
    else :
        authorization_request['response_mode'] = 'post'
        authorization_request['aud'] = 'https://self-issued.me/v2'
        authorization_request['client_metadata_uri'] = mode.server + "sandbox/ebsi/login/client_metadata_uri/" + stream_id
        # SIOPV2
        if 'id_token' in response_type :
            authorization_request['scope'] = 'openid'
            prefix = verifier_profile["siopv2_prefix"]
        
        # OIDC4VP
        if 'vp_token' in response_type :
            authorization_request['presentation_definition'] = presentation_definition
            prefix = verifier_profile["oidc4vp_prefix"]
        
        if 'id_token' in response_type and not 'vp_token' in response_type :
            authorization_request['request'] = build_jwt_request_for_siopv2(
                verifier_data['jwk'],
                verifier_data['verification_method'],
                verifier_data['did'],
                'https://self-issued.me/v2',
                mode.server + "sandbox/ebsi/login/endpoint/" + stream_id,
                nonce)

    if not verifier_data.get('request_uri')  :
        authorization_request_displayed = authorization_request
    else :
        authorization_request_displayed = { 
            "client_id" : verifier_data['did'],
            "request_uri" : mode.server + "sandbox/ebsi/login/request_uri/" + stream_id 
        }
    data = { 
        "pattern": authorization_request,
        "code" : request.args['code'],
        "client_id" : client_id
    }
    red.setex(stream_id, QRCODE_LIFE, json.dumps(data))
    url = prefix + '?' + urlencode(authorization_request_displayed)
    deeplink_talao = mode.deeplink_talao + 'app/download/ebsi?' + urlencode({'uri' : url})
    deeplink_altme= mode.deeplink_altme + 'app/download/ebsi?' + urlencode({'uri' : url})
    qrcode_page = verifier_data.get('verifier_landing_page_style')
    logging.info ('url = %s', authorization_request)
    return render_template(qrcode_page,
                            back_button = False,
							url=url,
                            authorization_request=json.dumps(authorization_request, indent=4),
                            url_json=json.dumps(authorization_request_displayed, indent=4),
                            client_metadata=json.dumps(client_metadata(stream_id, red), indent=4),
                            deeplink_talao=deeplink_talao,
                            deeplink_altme=deeplink_altme,
							stream_id=stream_id,
                            title=verifier_data['title'],
                            page_title=verifier_data['page_title'],
                            page_subtitle=verifier_data['page_subtitle'],
                            page_description=verifier_data['page_description'],
                            )
    

def ebsi_request_uri(stream_id, red) :
    """
    Request by uri
    https://www.rfc-editor.org/rfc/rfc9101.html
    """
    try :
        payload = json.loads(red.get(stream_id).decode())['pattern']
        client_id = json.loads(red.get(stream_id).decode())['client_id']
    except :
        return jsonify("Gone"), 410
    verifier_data = json.loads(read_ebsi_verifier(client_id))
    verifier_key = verifier_data['jwk']
    verifier_key = json.loads(verifier_key) if isinstance(verifier_key, str) else verifier_key
    signer_key = jwk.JWK(**verifier_key) 
    header = {
      'typ' :'JWT',
      'kid': oidc4vc.verification_method(verifier_data['did'], verifier_key),
      'alg': oidc4vc.alg(verifier_key)
    }
    token = jwt.JWT(header=header,claims=payload, algs=[oidc4vc.alg(verifier_key)])
    token.make_signed_token(signer_key)
    # https://tedboy.github.io/flask/generated/generated/flask.Response.html
    headers = { "Content-Type" : "application/oauth-authz-req+jwt",
                "Cache-Control" : "no-cache"
    }
    return Response(token.serialize(), headers=headers)



async def ebsi_login_endpoint(stream_id, red):
    logging.info("Enter wallet response endpoint")
    """
    https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.2
    
    """
    access = "ok"
    qrcode_status = "Unknown"

    try :
        qrcode_status = "ok"
        data = json.loads(red.get(stream_id).decode())
        client_id = data['client_id']
        verifier_data = json.loads(read_ebsi_verifier(client_id))
        #verifier_profile = profile[verifier_data['profile']]
        logging.info('Profile = %s', verifier_data['profile'])
    except :
        qrcode_status = "QR code expired"
        access = "access_denied"

    # prepare the verifier response to wallet
    response_format = "Unknown"
    vc_type = "Unknown"
    vp_type = "Unknown"
    presentation_submission_status = "Unknown"
    vp_token_status = "Unknown"
    id_token_status = "Unknown"
    credential_status = "unknown"
    issuer_status = "Unknown"
    aud_status = "unknown"
    nonce_status = "Unknown"
    vp_token_payload = {}
    id_token_payload = {}

    # get id_token, vp_token and presentation_submission
    if access == "ok" :
        vp_token =request.form.get('vp_token')
        id_token = request.form.get('id_token')
        presentation_submission =request.form.get('presentation_submission')
        response_format = "ok"
        logging.info('id_token received = %s', id_token)
        # check types of vp
        if vp_token :
            if vp_token[:2] == "ey" :
                vp_type = "jwt_vp"
            elif json.loads(vp_token).get("@context") :
                vp_type = "ldp_vp"
            else :
                vp_type = "Unknown"
                logging.error("vp token type unknown %s $s", vp_token, type(vp_token))

        if vp_token and vp_type == "ldp_vp" :
            logging.info('vp token received = %s', json.dumps(json.loads(vp_token), indent=4))
        else : 
            logging.info('vp token received = %s', vp_token)
        
        if presentation_submission :
            logging.info('presentation submission received = %s', json.dumps(json.loads(presentation_submission), indent=4))
        else : 
            logging.info('presentation submission received = %s', "")

        if not id_token and not vp_token :
            response_format = "invalid request format",
            access = "access_denied"
    
    if  access == "ok"  and not id_token :
        id_token_status = "Not received"
    
    if  access == "ok"  and not vp_token :
        vp_token_status = "Not received"
    
    if  access == "ok"  and not presentation_submission :
        presentation_submission_status = "Not received"
         
    # check presentation submission
    if  access == "ok"  and vp_token and verifier_data['profile'] != "EBSI-V2" :
        if not presentation_submission :
            presentation_submission_status = "Not found"
            access = "access_denied" 
        else :
            presentation_submission_status = "ok"

    if  access == "ok" :
        nonce = data['pattern']['nonce']

    # check id_token signature
    if access == "ok"  and id_token :
        try :
            oidc4vc.verif_token(id_token, nonce)
        except :
            id_token_status = "signature check failed"
            access = "access_denied" 
    
    if access == "ok"  and id_token :
        try :
            id_token_payload = oidc4vc.get_payload_from_token(id_token)
            id_token_header = oidc4vc.get_header_from_token(id_token)
            id_token_jwk = id_token_header.get('jwk')
            id_token_kid = id_token_header['kid']
            id_token_iss = id_token_payload.get('iss')
            id_token_sub = id_token_payload.get('sub')
            id_token_nonce = id_token_payload.get('nonce')
        except :
            id_token_status += "id_token invalid format "
            access = "access_denied" 

    if access == "ok" and id_token :
        if id_token_sub != id_token_iss :
            id_token_status += " id token sub != iss"    
        if id_token_sub != id_token_kid.split("#")[0] :
            id_token_status += " id token sub != kid "
        
    if  access == "ok" and verifier_data['profile'] in ["EBSI-V2"] and not id_token_jwk :
        id_token_status += " jwk is missing "
        
    if  access == "ok" and id_token :
        if nonce != id_token_nonce :
            id_token_status += " nonce does not match "

    # check vp_token signature
    if access == 'ok' and vp_token :
        if vp_type == "jwt_vp" :
            try :
                oidc4vc.verif_token(vp_token, nonce)
                vp_token_status = "ok"
                vp_token_payload = oidc4vc.get_payload_from_token(vp_token)
            except :
                vp_token_status = "signature check failed"
                access = "access_denied"
        else :
            verifyResult = json.loads(await didkit.verify_presentation(vp_token, "{}" ))
            vp_token_status = verifyResult

    # check VC signature

    # check types of vc
    if access == 'ok' and vp_token :
        vc_type = ""
        if vp_type == "jwt_vp" :
            vc_list = oidc4vc.get_payload_from_token(vp_token)['vp']["verifiableCredential"]
            for vc in vc_list :
                try :
                    vc[:2] == "ey" 
                    vc_type += " jwt_vc"
                except :
                    vc_type += " ldp_vc"
        else :
            vc_list = json.loads(vp_token)["verifiableCredential"]
            if isinstance(vc_list, dict) :
                vc_list = [vc_list]
            for vc in vc_list :
                try :
                    vc[:2] == "ey" 
                    vc_type += " jwt_vc"
                except  :
                    vc_type += " ldp_vc"

    # check holder binding

    # check nonce and aud in vp_token
    if access == 'ok' and vp_token :
        if profile[verifier_data['profile']][ "verifier_vp_type"] == "jwt_vp" :
            if oidc4vc.get_payload_from_token(vp_token)['nonce'] == nonce :
                nonce_status = "ok"
            else :
                nonce_status = "failed in vp_token"
                access = "access_denied"
            if oidc4vc.get_payload_from_token(vp_token)['aud'] == verifier_data['did'] :
                aud_status = "ok"
            else :
                aud_status = "failed in vp_token"
                access = "access_denied"
        else :
            if json.loads(vp_token)['proof'].get('challenge') == nonce :
                nonce_status = "ok"
            else :
                nonce_status = "failed in vp_token"
                access = "access_denied"
            if json.loads(vp_token)['proof'].get('domain') == verifier_data['did'] :
                aud_status = "ok"
            else :
                aud_status = "failed in vp_token"
                #access = "access_denied"

    if access == "access_denied" :
        status_code = 400
    else :
        status_code = 200

    response = {
      "created": datetime.timestamp(datetime.now()),
      "qrcode_status" : qrcode_status,
      "vp type" : vp_type,
      "vc type" : vc_type,
      "presentation_submission_status" : presentation_submission_status,
      "nonce_status" : nonce_status,
      "aud_status" : aud_status,
      "response_format" : response_format,
      "id_token_status" : id_token_status,
      "vp_token_status" : vp_token_status,
      #"issuer_status" : issuer_status,
      #"credential_status" : credential_status,
      "access" : access,
      "status_code" : status_code    
    }
    logging.info("response = %s",json.dumps(response, indent=4))
    # follow up
    wallet_data = json.dumps({
                    "access" : access,
                    "vp_token_payload" : vp_token_payload,
                    "sub" : id_token_payload.get('sub')
                    })
    red.setex(stream_id + "_wallet_data", CODE_LIFE, wallet_data)
    event_data = json.dumps({"stream_id" : stream_id})           
    red.publish('api_ebsi_verifier', event_data)
    return jsonify(response), status_code



def ebsi_login_followup(red):  
    """
    check if user is connected or not and redirect data to authorization server
    Prepare de data to transfer
    create activity record
    """
    logging.info("Enter follow up endpoint")
    try :
        stream_id = request.args.get('stream_id')
    except :
        return jsonify("Forbidden"), 403 
    code = json.loads(red.get(stream_id).decode())['code']
    try :
        stream_id_wallet_data = json.loads(red.get(stream_id + '_wallet_data').decode())
    except :
        logging.error("code expired in follow up")
        resp = {'code' : code, 'error' : "access_denied"}
        session['verified'] = False
        return redirect ('/sandbox/ebsi/authorize?' + urlencode(resp))

    if stream_id_wallet_data['access'] != 'ok' :
        resp = {'code' : code, 'error' : stream_id_wallet_data['access']}
        session['verified'] = False
    else :
        session['verified'] = True
        red.setex(code +"_wallet_data", CODE_LIFE, json.dumps(stream_id_wallet_data))
        resp = {'code' : code}

    return redirect ('/sandbox/ebsi/authorize?' + urlencode(resp))


def ebsi_login_stream(red):
    def login_event_stream(red):
        pubsub = red.pubsub()
        pubsub.subscribe('api_ebsi_verifier')
        for message in pubsub.listen():
            if message['type']=='message':
                yield 'data: %s\n\n' % message['data'].decode()
    headers = { "Content-Type" : "text/event-stream",
                "Cache-Control" : "no-cache",
                "X-Accel-Buffering" : "no"}
    return Response(login_event_stream(red), headers=headers)
