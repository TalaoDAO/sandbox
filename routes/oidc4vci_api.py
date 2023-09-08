"""
NEW


https://issuer.walt.id/issuer-api/default/oidc

EBSI V2 https://openid.net/specs/openid-connect-4-verifiable-credential-issuance-1_0-05.html

support Authorization code flow and pre-authorized code flow of OIDC4VCI

"""
from flask import jsonify, request, render_template, Response, redirect
import json
from datetime import datetime, timedelta
import uuid
import logging
import requests
import didkit
from urllib.parse import urlencode
import db_api
import oidc4vc
from oidc4vc_constante import type_2_schema
from profile import profile
from urllib.parse import parse_qs, urlparse
from jwcrypto import jwk, jwt


logging.basicConfig(level=logging.INFO)

API_LIFE = 5000
ACCESS_TOKEN_LIFE = 1000
GRANT_LIFE = 5000
C_NONCE_LIFE = 5000
ACCEPTANCE_TOKEN_LIFE = 28*24*60*60


def init_app(app,red, mode) :
    # endpoint for application if redirect to local page (test)
    app.add_url_rule('/sandbox/ebsi/issuer/<issuer_id>/<stream_id>',  view_func=ebsi_issuer_landing_page, methods = ['GET', 'POST'], defaults={'red' :red, 'mode' : mode})
    app.add_url_rule('/sandbox/ebsi/issuer_stream',  view_func=ebsi_issuer_stream, methods = ['GET', 'POST'], defaults={'red' :red})
    app.add_url_rule('/sandbox/ebsi/issuer_followup/<stream_id>',  view_func=ebsi_issuer_followup, methods = ['GET'], defaults={'red' :red})

    # api for application
    app.add_url_rule('/sandbox/ebsi/issuer/api/<issuer_id>',  view_func=issuer_api_endpoint, methods = ['POST'], defaults={'red' :red, 'mode' : mode})
    
    # OIDC4VCI protocol with wallet
    app.add_url_rule('/sandbox/ebsi/issuer/<issuer_id>/.well-known/openid-configuration', view_func=ebsi_issuer_openid_configuration, methods=['GET'], defaults={'mode' : mode})
    app.add_url_rule('/sandbox/ebsi/issuer/<issuer_id>/.well-known/openid-credential-issuer', view_func=ebsi_issuer_openid_configuration, methods=['GET'], defaults={'mode' : mode})

    app.add_url_rule('/sandbox/ebsi/issuer/<issuer_id>/authorize',  view_func=ebsi_issuer_authorize, methods = ['GET', 'POST'], defaults={'red' :red, 'mode' : mode})
    app.add_url_rule('/sandbox/ebsi/issuer/<issuer_id>/token',  view_func=ebsi_issuer_token, methods = ['POST'], defaults={'red' :red, 'mode' : mode})
    app.add_url_rule('/sandbox/ebsi/issuer/<issuer_id>/credential',  view_func=ebsi_issuer_credential, methods = ['POST'], defaults={'red' :red})
    app.add_url_rule('/sandbox/ebsi/issuer/<issuer_id>/deferred',  view_func=ebsi_issuer_deferred, methods = ['POST'], defaults={'red' :red})

    app.add_url_rule('/sandbox/ebsi/issuer/<issuer_id>/authorize_server/.well-known/openid-configuration',  view_func=ebsi_issuer_authorization_server, methods = ['GET'], defaults={'mode' :mode})

    app.add_url_rule('/sandbox/ebsi/issuer/credential_offer_uri/<id>',  view_func=ebsi_issuer_credential_offer_uri, methods = ['GET'], defaults={'red' :red})

    # test ebsiv3 
    app.add_url_rule('/sandbox/ebsiv3/redirect_uri',  view_func=ebsiv3_redirect_uri, methods = ['GET', 'POST'], defaults={'red' :red})
    return


def front_publish(stream_id, red, error=None ) :
    # send event to front channel to go forward callback and send credential to wallet
    data = {'stream_id' : stream_id}
    if error :
        data['error'] = error
    red.publish('issuer_oidc', json.dumps(data))


def manage_error(error, error_description, red, stream_id=None, status=400) :
    """
    Return error code to wallet and front channel
    https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-error-response
    """
    logging.warning(error_description)   
    payload = {
        'error' : error,
        'error_description' : error_description
    }
    headers = {
        'Cache-Control' : 'no-store',
        'Content-Type': 'application/json'}
    if stream_id :
        front_publish(stream_id, red, error=error)
    return {'response' : json.dumps(payload), 'status' : status, 'headers' : headers}


def ebsi_issuer_openid_configuration(issuer_id, mode):
    doc = oidc(issuer_id, mode)
    if not doc :
        return jsonify('Not found'), 404
    return jsonify(doc)


def oidc(issuer_id, mode) :
    """
    Attention for EBSI "types" = id of data model
    https://openid.net/specs/openid-connect-4-verifiable-credential-issuance-1_0-05.html
    ATTENTION new standard is https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html
    """
    try :
        issuer_data = json.loads(db_api.read_ebsi_issuer(issuer_id)) 
        issuer_profile = profile[issuer_data['profile']]
    except :
        logging.warning('issuer_id not found for %s', issuer_id)
        return
    
    # Credentials_supported section
    cs = list()
    for _vc in issuer_profile.get('credentials_supported'):
        oidc_data = {
            'format': _vc.get('format', 'missing, contact@talao.co'),
            'types' : _vc.get('types', 'missing, contact@talao.co'),
            'display' : _vc.get('display', 'missing, contact@talao.co')
        }
        if issuer_data['profile'] != "EBSI-V3" :
            oidc_data.update(
                {
                    'cryptographic_binding_methods_supported': _vc.get('cryptographic_binding_methods_supported', 'missing, contact@talao.co'),
                    'cryptographic_suites_supported': _vc.get('cryptographic_suites_supported', 'missing, contact@talao.co')}
                )
        if _vc.get('id') :
            oidc_data['id'] = _vc['id']
        if _vc.get('trust_framework') :
            oidc_data['trust_framework'] = _vc['trust_framework']
        cs.append(oidc_data)

    # general section
    # https://www.rfc-editor.org/rfc/rfc8414.html#page-4
    openid_configuration = dict()
    openid_configuration.update({
        'credential_issuer': mode.server + 'sandbox/ebsi/issuer/' + issuer_id,
        'credential_endpoint': mode.server + 'sandbox/ebsi/issuer/' + issuer_id + '/credential',
        'deferred_credential_endpoint': mode.server + 'sandbox/ebsi/issuer/' + issuer_id + '/deferred',
        'credentials_supported' : cs,
        'credential_supported' : cs # To be removed later
    })
    if issuer_profile.get('service_documentation') :
        openid_configuration['service_documentation'] = issuer_profile['service_documentation']
    if issuer_profile.get('batch_credential_endpoint_support') :
        openid_configuration['batch_credential_endpoint'] = mode.server + 'sandbox/ebsi/issuer/' + issuer_id + '/batch'

    # setup credential manifest as optional
    #https://openid.net/specs/openid-connect-4-verifiable-credential-issuance-1_0-05.html#name-server-metadata    
    if issuer_profile.get('credential_manifest_support')  :
        cm = list()  
        for _vc in issuer_profile.get('credentials_types_supported') :
            file_path = './credential_manifest/' + _vc + '_credential_manifest.json'
            cm_to_add = json.load(open(file_path))
            cm_to_add['issuer']['id'] = issuer_data.get('did' , 'Unknown')
            cm_to_add['issuer']['name'] = issuer_data['application_name']
            cm.append(cm_to_add)
        openid_configuration['credential_manifests'] = cm

    # setup authorization server 
    if issuer_profile.get('authorization_server_support')  :
        openid_configuration['authorization_server']=  mode.server + 'sandbox/ebsi/issuer/' + issuer_id + '/authorize_server'
    else :
        authorization_server_config = json.load(open("authorization_server_config.json"))
        openid_configuration['authorization_endpoint'] = mode.server + 'sandbox/ebsi/issuer/' + issuer_id + '/authorize'
        openid_configuration['token_endpoint'] = mode.server + 'sandbox/ebsi/issuer/' + issuer_id + '/token'
        openid_configuration.update(authorization_server_config)   
    return openid_configuration


def ebsi_issuer_authorization_server(issuer_id, mode) :
    authorization_server_config = json.load(open("authorization_server_config.json"))
    config = {
        'authorization_endpoint':  mode.server + 'sandbox/ebsi/issuer/' + issuer_id + '/authorize',
        'token_endpoint': mode.server + 'sandbox/ebsi/issuer/' + issuer_id + '/token'}
    config.update(authorization_server_config)   
    return jsonify(config)


# Customer API
def issuer_api_endpoint(issuer_id, red, mode) :
    """
    This API returns the QRcode page URL to redirect user or the QR code by value if the template is managed by the application

    headers = {
        'Content-Type': 'application/json',
        'Authorization' : 'Bearer <client_secret>'
    }

    data = { 
        "vc" : OPTIONAL -> { "EmployeeCredendial" : {}, ....}, json object, VC as a json-ld not signed { "EmployeeCredendial" : [ {"identifier1" : {}},  ....}
        "deferred_vc" : CONDITIONAL, REQUIRED in case of 2nd deferred call
        "issuer_state" : REQUIRED, string,
        "credential_type" : REQUIRED -> array or string name of the credentials offered
        "pre-authorized_code" : REQUIRED , bool
        "user_pin_required" : OPTIONAL bool, default is false 
        "user_pin" : CONDITIONAL, string, REQUIRED if user_pin_required is True
        "callback" : REQUIRED, string, this the user redirect route at the end of the flow
        }
    resp = requests.post(token_endpoint, headers=headers, data = data)
    return resp.json()

    """
    # check API format    
    try :
        token = request.headers['Authorization']
        client_secret = token.split(" ")[1]
    except :
        return Response(**manage_error("Unauthorized", "Unhauthorized token", red, status= 401))    
    try :
        issuer_data = json.loads(db_api.read_ebsi_issuer(issuer_id))
    except :
        return Response(**manage_error("Unauthorized", "Unhauthorized client_id", red, status= 401))    
    try :
        issuer_state =  request.json['issuer_state']
    except :
        return Response(**manage_error("Bad request", "issuer_state missing", red, status= 401))   
    try :
        credential_type = request.json['credential_type']  
    except :
        return Response(**manage_error("Bad request", "credential_type missing", red, status= 401))    
    try :
        pre_authorized_code = request.json["pre-authorized_code"]
    except :
        return Response(**manage_error("Bad request", "pre-authorized_code is missing", red, status= 401))    
    
    # check if client_id exists 
    if client_secret != issuer_data['client_secret'] :
        logging.warning("Client secret is incorrect")
        return Response(**manage_error("Unauthorized", "Client secret is incorrect", red, status=401))
    
    # Check vc and vc_deferred
    vc =  request.json.get('vc')
    deferred_vc = request.json.get('deferred_vc')
    if vc and not request.json.get('callback') :
        return Response(**manage_error("Bad request", "callback missing", red, status= 401))   
    if vc and deferred_vc :
        return Response(**manage_error("Bad request", "deferred_vc and vc not allowed", red, status= 401))   
    
    # Check if user pin exists
    if request.json.get('user_pin_required') and not request.json.get('user_pin') :
        return Response(**manage_error("Unauthorized", "User pin is not set", red, status=401))
    
    # check if credential offered is supported
    issuer_profile = profile[issuer_data['profile']]
    credential_type = credential_type if isinstance(credential_type, list) else [credential_type]
    for _vc in credential_type :
        if _vc not in issuer_profile['credentials_types_supported'] :
              logging.error("Credential not supported %s", _vc)
              return Response(**manage_error("Unauthorized", "Credential not supported", red, status=401))

    nonce = str(uuid.uuid1())
    # generate pre-authorized_code as jwt or string
    if pre_authorized_code :
        if profile[issuer_data['profile']].get('pre-authorized_code_as_jwt') :
            pre_authorized_code =  oidc4vc.build_pre_authorized_code(
                issuer_data['jwk'],
                'https://self-issued.me/v2',
                mode.server + 'sandbox/ebsi/issuer/' + issuer_id,
                issuer_data['verification_method'],
                nonce
             )
        else :
            pre_authorized_code =  str(uuid.uuid1())
    
    #vc_formats_supported = issuer_profile['issuer_vc_type']
    stream_id = str(uuid.uuid1())
    application_data = {
        'vc' : vc,
        'nonce' : nonce,
        'stream_id' : stream_id,
        #'issuer_vc_type' : vc_formats_supported,
        'issuer_id' : issuer_id,
        'issuer_state' : request.json.get('issuer_state'),
        'credential_type' : credential_type,
        'pre-authorized_code' : pre_authorized_code,
        'user_pin_required' : request.json.get('user_pin_required'),
        'user_pin' : request.json.get('user_pin'),
        'callback' : request.json.get('callback')
    }
    # For deferred API call only VC is stored in redis with issuer_state as key
    if deferred_vc and red.get(issuer_state) :
        application_data.update({
            'deferred_vc' : deferred_vc,
            'deferred_vc_iat' :  round(datetime.timestamp(datetime.now())),
            'deferred_vc_exp' :  round(datetime.timestamp(datetime.now())) + ACCEPTANCE_TOKEN_LIFE
        })
        red.setex(issuer_state, API_LIFE, json.dumps(application_data))
    else :
        # for authorization code flow
        red.setex(issuer_state, API_LIFE, json.dumps(application_data))
    
    # for pre authorized code
    if pre_authorized_code : 
        red.setex(pre_authorized_code, GRANT_LIFE, json.dumps(application_data))

    # for front page management
    red.setex(stream_id, API_LIFE, json.dumps(application_data))
    response = {"redirect_uri" : mode.server+ 'sandbox/ebsi/issuer/' + issuer_id +'/' + stream_id }
    logging.info('initiate qrcode = %s', mode.server+ 'sandbox/ebsi/issuer/' + issuer_id +'/' + stream_id)
    return jsonify(response)


def build_credential_offer(issuer_id, credential_type, pre_authorized_code, issuer_state, issuer_profile, vc, user_pin_required, mode) :
    #  https://openid.net/specs/openid-connect-4-verifiable-credential-issuance-1_0-05.html#name-pre-authorized-code-flow
    if issuer_profile == 'EBSI-V2' :
        offer  = { 
            'issuer' : mode.server +'sandbox/ebsi/issuer/' + issuer_id,
            'credential_type'  : type_2_schema[credential_type[0]],
        }
        if pre_authorized_code :
            offer['pre-authorized_code'] = pre_authorized_code
    # same as EBSIV2 but without schema
    elif issuer_profile == 'GAIA-X' :
        if len(credential_type)== 1 :
            credential_type = credential_type[0]
        offer  = { 
            "issuer" : mode.server +'sandbox/ebsi/issuer/' + issuer_id,
            "credential_type"  : credential_type,
        }
        if pre_authorized_code :
            offer['pre-authorized_code'] = pre_authorized_code
            if user_pin_required :
                offer['user_pin_required'] : True
    
    # new OIDC4VCI standard with  credentials as an array ofjson objects (EBSI-V3)
    elif profile[issuer_profile].get('credentials_as_json_object_array') :
        offer  = { 
            "credential_issuer" : mode.server +'sandbox/ebsi/issuer/' + issuer_id,
            "credentials"  : []
        }
        if pre_authorized_code  :
            offer['grants'] ={
                "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                    "pre-authorized_code": pre_authorized_code
                }
            }
            if user_pin_required :
                offer['grants']["urn:ietf:params:oauth:grant-type:pre-authorized_code"].update({'user_pin_required' : True})
        else :
            offer["grants"] ={
                "authorization_code": {"issuer_state" : issuer_state}
            }
        for one_vc in credential_type :
            for supported_vc in profile[issuer_profile]['credentials_supported'] :
                if one_vc in  supported_vc['types'] :
                    offer["credentials"].append({
                        'format': supported_vc['format'],
                        'types': supported_vc['types'],
                })
                if vc.get('trust_framework') :
                    offer[ 'trust_framework'] = supported_vc['trust_framework']
    
    # new OIDC4VCI standard with  credentials as an array of strings
    else :
        offer  = { 
            "credential_issuer" : mode.server +'sandbox/ebsi/issuer/' + issuer_id,
            "credentials"  : credential_type
        }
        if pre_authorized_code  :
            offer['grants'] ={
                "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                    "pre-authorized_code": pre_authorized_code
                }
            }
            if user_pin_required :
                offer['grants']["urn:ietf:params:oauth:grant-type:pre-authorized_code"].update({'user_pin_required' : True})
        else :
            offer["grants"] ={
                "authorization_code": {"issuer_state" : issuer_state}
            }
    return offer


def ebsi_issuer_credential_offer_uri(id, red):
    """
    credential_offer_uri endpoint
    return 201
    """
    try :
        offer = json.loads(red.get(id).decode())
    except :
        logging.warning("session expired")
        return jsonify("Session expired"), 404
    return jsonify(offer),201


# QRcode page for credential offer
def ebsi_issuer_landing_page(issuer_id, stream_id, red, mode) :
    try :
        application_data = json.loads(red.get(stream_id).decode())
    except :
        logging.warning("session expired")
        return jsonify("Session expired"), 404
    credential_type = application_data['credential_type']
    pre_authorized_code = application_data['pre-authorized_code']
    user_pin_required = application_data['user_pin_required']
    issuer_state = application_data['issuer_state']
    vc = application_data['vc']
    issuer_data = json.loads(db_api.read_ebsi_issuer(issuer_id))
    data_profile = profile[issuer_data['profile']]
    offer = build_credential_offer(issuer_id,
                        credential_type,
                        pre_authorized_code,
                        issuer_state,
                        issuer_data['profile'],
                        vc,
                        user_pin_required,
                        mode)
    
    # credentilaoffer is passed by value 
    if issuer_data['profile']  not in ['EBSI-V2', 'GAIA-X'] :
        url_to_display = data_profile['oidc4vci_prefix'] + '?' + urlencode ({'credential_offer' : json.dumps(offer)})
        json_url  = {"credential_offer" : offer}
    else :
        url_to_display = data_profile['oidc4vci_prefix'] + '?' + urlencode(offer)
        json_url = offer

    # credential offer is passed by reference  : credential offer uri
    if issuer_data.get('credential_offer_uri') :
        id = str(uuid.uuid1())
        credential_offer_uri = mode.server + 'sandbox/ebsi/issuer/credential_offer_uri/' + id
        red.setex(id, GRANT_LIFE, json.dumps(offer))
        logging.info('credential offer uri =%s', credential_offer_uri)
        url_to_display =  data_profile['oidc4vci_prefix'] + '?credential_offer_uri=' + credential_offer_uri

    openid_configuration  = json.dumps(oidc(issuer_id, mode), indent=4)
    deeplink_talao = mode.deeplink_talao + 'app/download/ebsi?' + urlencode({'uri' : url_to_display })
    deeplink_altme = mode.deeplink_altme + 'app/download/ebsi?' + urlencode({'uri' : url_to_display})
    qrcode_page = issuer_data.get('issuer_landing_page')
    logging.info("QR code page = %s", qrcode_page)
    return render_template(
        qrcode_page,
        openid_configuration = openid_configuration,
        url_data = json.dumps(json_url,indent = 6),
        url=url_to_display,
        deeplink_altme=deeplink_altme,
        deeplink_talao=deeplink_talao,
        stream_id=stream_id,
        issuer_id=issuer_id,
        page_title=issuer_data['page_title'],
        page_subtitle=issuer_data['page_subtitle'],
        page_description=issuer_data['page_description'],
        title=issuer_data['title'],
        landing_page_url=issuer_data['landing_page_url'],
        issuer_state=request.args.get('issuer_state')
    )


def ebsi_issuer_authorize(issuer_id, red, mode) :
    def authorization_error_response(error, error_description, stream_id, red) :
        """
        https://www.rfc-editor.org/rfc/rfc6749.html#page-26
        """
        # front channel follow up 
        if stream_id  :
            event_data = json.dumps({'stream_id' : stream_id})           
            red.publish('issuer_oidc', event_data)
        logging.warning(error_description)
        resp = {
            'error_description' : error_description,
            'error' : error
        }
        return redirect(redirect_uri + '?' + urlencode(resp))
   
    try :
        response_type = request.args["response_type"]
        scope = request.args['scope']
        client_id = request.args['client_id']
        authorization_details = request.args["authorization_details"]
        redirect_uri = request.args['redirect_uri']
        nonce = request.args.get("nonce")
        issuer_state=request.args['issuer_state']
        code_challenge = request.args.get("code_challenge")
        code_challenge_method = request.args.get("code_challenge_method")
        client_metadata = request.args.get("client_metadata")
        state = request.args['state']
    except :
        return jsonify('invalid_request'), 400
    
    print('redirect_uri = ', redirect_uri)
    print('code_challenge = ', code_challenge)
    print('client_metadat = ', client_metadata)
    print('authorization details = ', authorization_details)
     
    try :
        issuer_state_data = json.loads(red.get(issuer_state).decode())
        stream_id = issuer_state_data['stream_id']
    except :
        logging.warning('issuer_state not found in authorization code flow')
        return jsonify('invalid_request'), 400

    logging.info('authorization_details = %s', authorization_details[0])
    if scope != "openid" :
        authorization_error_response('invalid_scope', 'scope not supported', stream_id, red)
    if 'id_token' not in response_type and 'vp_token' not in response_type :
        authorization_error_response('invalid_response_type', 'response_type not supported', stream_id, red)

    issuer_data = json.loads(db_api.read_ebsi_issuer(issuer_id)) 
    TEST = ""
    if TEST == "EBBSI-V3" :
        # test pour EBSI v3
        #def build_jwt_request_ebsiv3 (issuer_key, issuer_kid, client_id, aud, redirect_uri, nonce):
        #client_id = mode.server + 'sandbox/ebsi/issuer/' + issuer_id
        request_as_jwt = build_jwt_request_ebsiv3(
            issuer_data['jwk'], # issuer_key
            issuer_data['verification_method'], # issuer_kid
            issuer_data['did'],
            client_id, # aud
            mode.server + "sandbox/ebsiv3/redirect_uri", #redirect_uri
            'nonce'
        )  
        #print('request = ', request_as_jwt)
        request_data = {
            "state" : "state",
            "aud" : client_id,
            "client_id" :  issuer_data['did'],
            "redirect_uri" : mode.server + "sandbox/ebsiv3/redirect_uri",
            "respone_type" : "id_token",
            "nonce" : "nonce",
            "response_mode" : "direct_post",
            "scope" : "openid",
            "request" : request_as_jwt,
        }
        ebsiv3_wallet_request = "openid:?" + urlencode(request_data)
        print("ebsiv3_wallet_request = ", ebsiv3_wallet_request)
        return redirect (ebsiv3_wallet_request)

    offer_data = json.loads(red.get(issuer_state).decode())
    stream_id = offer_data['stream_id']
    vc = offer_data['vc']
    credential_type =  offer_data['credential_type']
    
    # Code creation
    issuer_data = json.loads(db_api.read_ebsi_issuer(issuer_id))
    if profile[issuer_data['profile']].get('pre-authorized_code_as_jwt') :
        code =  oidc4vc.build_pre_authorized_code(
            issuer_data['jwk'],
            'https://self-issued.me/v2',
            mode.server + 'sandbox/ebsi/issuer/' + issuer_id,
            issuer_data['verification_method'],
            nonce
        )
    else  :
        code = str(uuid.uuid1())
    
    code_data = {
        'credential_type' : credential_type,
        'issuer_id' : issuer_id,
        #'format' : format,
        'issuer' : issuer_data['issuer'],
        'issuer_state' : issuer_state,
        'state' : state,
        'stream_id' : stream_id,
        'vc' : vc,
        'code_challenge' : code_challenge, 
        'code_challenge_method' : code_challenge_method
    }
    red.setex(code, GRANT_LIFE, json.dumps(code_data))    
    resp = {'code' : code}
    if state :
        resp['state'] = state
    return redirect(redirect_uri + '?' + urlencode(resp))


def ebsiv3_redirect_uri(red) :
    print('request form = ', request.form)
    return jsonify('ok from redire_uri')


# for ebsiv3 test
def build_jwt_request_ebsiv3 (issuer_key, issuer_kid, client_id, aud, redirect_uri, nonce):
    key = json.loads(issuer_key) if isinstance(issuer_key, str) else issuer_key
    signer_key = jwk.JWK(**key) 
    header = {
        'typ' :'JWT',
        'alg': oidc4vc.alg(key),
        'kid' : issuer_kid
    }
    payload = {
        'iss' : client_id, 
        'aud' : aud,
        'scope' : "openid",
        "state" : "state",
        'redirect_uri' : redirect_uri,
        'client_id' : client_id,
        "response_type": "id_token",
        "response_mode": "direct_post",
        'exp': datetime.timestamp(datetime.now()) + 1000,
        'nonce' : nonce
    }
    token = jwt.JWT(header=header,claims=payload, algs=[oidc4vc.alg(issuer_key)])
    token.make_signed_token(signer_key)
    return token.serialize()


# token endpoint
def ebsi_issuer_token(issuer_id, red, mode) :
    """
    https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-token-endpoint
    https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
    """
    logging.info("token endpoint request = %s", json.dumps(request.form))

    grant_type =  request.form.get('grant_type')
    if not grant_type :
        return Response(**manage_error("invalid_request", "Request format is incorrect", red))
    
    if grant_type == 'urn:ietf:params:oauth:grant-type:pre-authorized_code' :
        code = request.form.get('pre-authorized_code')   
        user_pin = request.form.get('user_pin')
        logging.info('user_pin = %s', user_pin)
    
    elif grant_type == 'authorization_code' :
        code = request.form.get('code')
    
    if not code : 
        logging.warning('code is missing')
        return Response(**manage_error("invalid_grant", "Request format is incorrect", red))

    try :
        data = json.loads(red.get(code).decode())
    except :
        return Response(**manage_error("invalid_grant", "Grant code expired", red))     
    
    if data.get('user_pin_required') and not user_pin :
            return Response(**manage_error("invalid_request", "User pin is missing", red))
    
    if data.get('user_pin_required') and data.get('user_pin') != user_pin :
            return Response(**manage_error("invalid_grant", "User pin is incorrect", red))

    # token response
    access_token = str(uuid.uuid1())
    vc = data.get('vc')
    endpoint_response = {
        'access_token' : access_token,
        'c_nonce' : str(uuid.uuid1()),
        'token_type' : 'Bearer',
        'expires_in': ACCESS_TOKEN_LIFE
    }
    # multiple VC of the same type
    if isinstance(vc, list) :
        identifiers = list()
        authorization_details = list()
        for vc_type in vc :
            types = vc_type['types']
            vc_list = vc_type['list']
            for one_vc in vc_list :
                identifiers.append(one_vc['identifier'])        
            authorization_details.append({
                "type": "openid_credential",
                "locations": [mode.server + '/sandbox/ebsi/issuer/api/' + issuer_id],
                "format": "jwt_vc",
                "types": types,
                "identifiers" : identifiers 
            })
    endpoint_response['organisations_details'] = authorization_details
    print("access token = ", access_token)
    
    access_token_data = {
        'expires_at': datetime.timestamp(datetime.now()) + ACCESS_TOKEN_LIFE,
        #'pre_authorized_code' : code,
        'c_nonce' : endpoint_response.get('c_nonce'),
        #'format' : data.get('issuer_vc_type'),
        'credential_type' : data.get('credential_type'),
        'vc' : data.get('vc'),
        'stream_id' : data.get('stream_id'),
        'issuer_state' : data.get('issuer_state'),
    }

    red.setex(access_token, ACCESS_TOKEN_LIFE,json.dumps(access_token_data))

    headers = {
        'Cache-Control' : 'no-store',
        'Content-Type': 'application/json'}
    return Response(response=json.dumps(endpoint_response), headers=headers)
 

# credential endpoint
async def ebsi_issuer_credential(issuer_id, red) :
    """
    https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-endpoint
    
    """
    logging.info("credential endpoint request")
    # Check access token
    try :
        access_token = request.headers['Authorization'].split()[1]
    except :
        return Response(**manage_error("invalid_token", "Access token not passed in request header", red))
    try :
        access_token_data = json.loads(red.get(access_token).decode())
    except :
        return Response(**manage_error("invalid_token", "Access token expired", red)) 
        
    # to manage followup screen
    stream_id = access_token_data.get('stream_id')
    issuer_data = json.loads(db_api.read_ebsi_issuer(issuer_id))
    logging.info('Profile = %s', issuer_data['profile'])
    #issuer_profile = profile[issuer_data['profile']]
    
    # Check request 
    try :
        result = request.json
        proof_format = result['format']
        proof_type  = result['proof']['proof_type']
        proof = result['proof']['jwt']
    except :
        return Response(**manage_error("invalid_request", "Invalid request format", red, stream_id=stream_id)) 
    
    logging.info('credential request = %s', request.json)
    
    if proof_type != 'jwt' : 
        return Response(**manage_error("unsupported_credential_type", "The credential proof type is not supported =%s", proof_type)) 

    # Get credential type requested
    if result.get("types") :
        found = False
        for vc_type in result['types'] :
            if vc_type not in ['VerifiableCredential', 'VerifiableAttestation'] :
                credential_type = vc_type
                found = True
                break
        if not found :  
            return Response(**manage_error('invalid_request', 'VC type not found', red, stream_id=stream_id)) 
    elif result.get('type') :
        credential_type = result['type']
    else :
        return Response(**manage_error('invalid_request', 'Invalid request format', red, stream_id=stream_id)) 
    logging.info('credential type requested = %s', credential_type)
    
    # check proof format requested
    logging.info('proof format requested = %s', proof_format)
    if proof_format not in ['jwt_vc','jwt_vc_json', 'jwt_vc_json-ld', 'ldp_vc'] :
        return Response(**manage_error('invalid_or_missing_proof', 'The proof is invalid', red, stream_id=stream_id)) 

    # Check proof of key ownership received (OPTIONAL check)
    logging.info('proof of key ownership received = %s', proof)
    try :
        oidc4vc.verif_token(proof, access_token_data['c_nonce'])
        logging.info('proof of ownership is validated')
    except Exception as e :
        logging.warning('proof of ownership error = %s', str(e))

    proof_payload=oidc4vc.get_payload_from_token(proof)

    # deferred use case 
    if issuer_data.get('deferred_flow') :
        acceptance_token = str(uuid.uuid1())
        payload = {
            'acceptance_token' : acceptance_token,
            'c_nonce': str(uuid.uuid1()),
            'c_nonce_expires_in': ACCEPTANCE_TOKEN_LIFE
        }
        acceptance_token_data = {
            'issuer_id' : issuer_id,
            'format' : proof_format,
            'subjectId' : proof_payload.get('iss'),
            'issuer_state' : access_token_data['issuer_state'],
            'credential_type' : credential_type,
            'c_nonce': str(uuid.uuid1()),
            'c_nonce_expires_at': datetime.timestamp(datetime.now()) + ACCEPTANCE_TOKEN_LIFE
        }
        red.setex(acceptance_token, ACCEPTANCE_TOKEN_LIFE,json.dumps(acceptance_token_data))
        headers = {
            'Cache-Control' : 'no-store',
            'Content-Type': 'application/json'}
        return Response(response=json.dumps(payload), headers=headers)
        
    # for EBSI V2
    if credential_type in ['https://api-conformance.ebsi.eu/trusted-schemas-registry/v2/schemas/z22ZAMdQtNLwi51T2vdZXGGZaYyjrsuP1yzWyXZirCAHv'] :
        credential_type = 'VerifiableId' 
    elif  credential_type in ['https://api.preprod.ebsi.eu/trusted-schemas-registry/v1/schemas/0xbf78fc08a7a9f28f5479f58dea269d3657f54f13ca37d380cd4e92237fb691dd'] :
        credential_type = 'VerifiableDiploma' 
    logging.info("credential type = %s", credential_type)
    
    try :
        credential = access_token_data['vc'][credential_type]
    except :
        # send event to front to go forward callback and send credential to wallet
        return Response(**manage_error('unsupported_credential_type', 'The credential type is not offered', red, stream_id=stream_id))
    credential_signed = await sign_credential(credential,
                                            proof_payload.get('iss'),
                                            issuer_data['did'],
                                            issuer_data['jwk'],
                                            issuer_data['verification_method'],
                                            access_token_data['c_nonce'],
                                            proof_format
                                            ) 
    logging.info('credential signed sent to wallet = %s', credential_signed)

    # send event to front to go forward callback and send credential to wallet
    front_publish(access_token_data['stream_id'], red)
    
    # Transfer VC
    payload = {
        'format' : proof_format,
        'credential' : credential_signed, # string or json depending on the format
        'c_nonce': str(uuid.uuid1()),
        'c_nonce_expires_in': C_NONCE_LIFE
    }

    # update nonce in access token for next VC request
    access_token_data['c_nonce'] = payload['c_nonce']
    red.setex(access_token, ACCESS_TOKEN_LIFE,json.dumps(access_token_data))
    headers = {
        'Cache-Control' : 'no-store',
        'Content-Type': 'application/json'}
    return Response(response=json.dumps(payload), headers=headers)


async def ebsi_issuer_deferred(issuer_id, red):
    """
    Deferred endpoint

    https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-deferred-credential-endpoin
    """
    logging.info("deferred endpoint request")
    # Check access token
    try :
        acceptance_token = request.headers['Authorization'].split()[1]
    except :
        return Response(**manage_error("invalid_request", "Acceptance token not passed in request header", red, status=400))
    
    # Offer expired, VC is no more available return 410
    try :
        acceptance_token_data = json.loads(red.get(acceptance_token).decode())
    except :
        return Response(**manage_error("invalid_token", "Acceptance token expired", red, status=410)) 
        
    issuer_state = acceptance_token_data['issuer_state']
    credential_type = acceptance_token_data['credential_type']
    
    # VC is not ready return 404
    try : 
        deferred_data = json.loads(red.get(issuer_state).decode())
        credential = deferred_data['deferred_vc'][credential_type]
    except :
        return Response(**manage_error("invalid_token", "Credential is not available yet", red, status=404)) 

    print(deferred_data)
    issuer_data = json.loads(db_api.read_ebsi_issuer(issuer_id))
   
    
    #sign_credential
    credential_signed = await sign_credential(credential,
                                            acceptance_token_data['subjectId'],
                                            issuer_data['did'],
                                            issuer_data['jwk'],
                                            issuer_data['verification_method'],
                                            acceptance_token_data['c_nonce'],
                                            acceptance_token_data['format']
                                            )  
    logging.info('credential signed sent to wallet = %s', credential_signed)
    
    # delete deferred VC data
    red.delete(issuer_state)

     # Transfer VC
    payload = {
        'format' : acceptance_token_data['format'],
        'credential' : credential_signed, # string or json depending on the format
        'c_nonce': str(uuid.uuid1()),
        'c_nonce_expires_in': C_NONCE_LIFE
    }
    headers = {
        'Cache-Control' : 'no-store',
        'Content-Type': 'application/json'}
    return Response(response=json.dumps(payload), headers=headers)


def ebsi_issuer_followup(stream_id, red):  
    try :
        user_data = json.loads(red.get(stream_id).decode())
    except :
        return jsonify('Unhautorized'), 401
    callback = user_data['callback']
    if not callback :
        issuer_id = user_data['issuer_id']
        issuer_data = db_api.read_ebsi_issuer(issuer_id)
        callback = json.loads(issuer_data)['callback']
    callback_uri = callback + '?issuer_state=' + user_data.get('issuer_state')
    if request.args.get('error') :
        callback_uri +='&error=' + request.args.get('error') 
    return redirect(callback_uri) 
 

# server event push for user agent EventSource
def ebsi_issuer_stream(red):
    def event_stream(red):
        pubsub = red.pubsub()
        pubsub.subscribe('issuer_oidc')
        for message in pubsub.listen():
            if message['type']=='message':
                yield 'data: %s\n\n' % message['data'].decode()  
    headers = { 'Content-Type' : 'text/event-stream',
                'Cache-Control' : 'no-cache',
                'X-Accel-Buffering' : 'no'}
    return Response(event_stream(red), headers=headers)


async def sign_credential(credential, wallet_did, issuer_did, issuer_key, issuer_vm, c_nonce, format ) :
    credential['id']= 'urn:uuid:' + str(uuid.uuid1())
    credential['credentialSubject']['id'] = wallet_did
    credential['issuer']= issuer_did
    credential['issued'] = datetime.now().replace(microsecond=0).isoformat() + 'Z'
    credential['issuanceDate'] = datetime.now().replace(microsecond=0).isoformat() + 'Z'
    credential['validFrom'] = datetime.now().replace(microsecond=0).isoformat() + 'Z'
    credential['expirationDate'] =  (datetime.now() + timedelta(days= 365)).isoformat() + 'Z'
    credential['validUntil'] =  (datetime.now() + timedelta(days= 365)).isoformat() + 'Z'
    if format in ['jwt_vc', 'jwt_vc_json', 'jwt_vc_json-ld'] :        
        credential_signed = oidc4vc.sign_jwt_vc(credential, issuer_vm , issuer_key, c_nonce)
    else : #  proof_format == 'ldp_vc' :
        didkit_options = {
                'proofPurpose': 'assertionMethod',
                'verificationMethod': issuer_vm
        }
        credential_signed =  await didkit.issue_credential(
                json.dumps(credential),
                didkit_options.__str__().replace("'", '"'),
                issuer_key
                )
        result = await didkit.verify_credential(credential_signed, '{}')   
        logging.info('signature check with didkit = %s', result)
        credential_signed = json.loads(credential_signed)
    return credential_signed




"""
    authorization details
   [
  {
    "type": "openid_credential",
    "locations": [
      "http://192.168.0.20:3000/sandbox/ebsi/issuer/kwcdgsspng"
    ],
    "format": "jwt_vc",
    "types": [
      "VerifiableCredential",
      "VerifiableAttestation",
      "VerifiableDiploma"
    ]
    }
    ]

"""

"""
    GET /sandbox/ebsi/issuer/kwcdgsspng/authorize?
    response_type=code
    &client_id=did%3Akey%3Az2dmzD81cgPx8Vki7JbuuMmFYrWPgYoytykUZ3eyqht1j9Kbs5869W47bN5DBoWQGig9f25zS7vnMo5eYpXgyyxPwNnBjA3XXtbYBDEqFkH5mYTFs2eFgEbiUcKwxhuYhnYmrzUJjhJCB6i6NeQVKDxEYhK7Kdep64yzc81wAGhndjJnhJ
    &redirect_uri=https%3A%2F%2Fexample.com
    &scope=openid
    &issuer_state=0843ddae-497b-11ee-a8c2-bd4f8da6aefe
    &state=29471082-28af-41a7-8495-8530a957f56e
    &nonce=4bfd6ae1-5e42-48cc-bbd1-53fba218311e
    &code_challenge=lf3q5-NObcyp41iDSIL51qI7pBLmeYNeyWnNcY2FlW4
    &code_challenge_method=S256
    &authorization_details=%5B%7B%22type%22%3A%22openid_credential%22,%22locations%22%3A%5B%22http%3A%2F%2F192.168.0.20%3A3000%2Fsandbox%2Febsi%2Fissuer%2Fkwcdgsspng%22%5D,%22format%22%3A%22jwt_vc%22,%22types%22%3A%5B%22VerifiableCredential%22,%22VerifiableAttestation%22,%22VerifiableDiploma%22%5D%7D%5D
    &client_metadata=%7B%22authorization_endpoint%22%3A%22openid%3A%22,%22scopes_supported%22%3A%5B%22openid%22%5D,%22response_types_supported%22%3A%5B%22vp_token%22,%22id_token%22%5D,%22subject_types_supported%22%3A%5B%22public%22%5D,%22id_token_signing_alg_values_supported%22%3A%5B%22ES256%22%5D,%22request_object_signing_alg_values_supported%22%3A%5B%22ES256%22%5D,%22vp_formats_supported%22%3A%7B%22jwt_vp%22%3A%7B%22alg_values_supported%22%3A%5B%22ES256%22%5D%7D,%22jwt_vc%22%3A%7B%22alg_values_supported%22%3A%5B%22ES256%22%5D%7D%7D,%22subject_syntax_types_supported%22%3A%5B%22urn%3Aietf%3Aparams%3Aoauth%3Ajwk-thumbprint%22,%22did%3Akey%3Ajwk_jcs-pub%22%5D,%22id_token_types_supported%22%3A%5B%22subject_signed_id_token%22%5D%7D HTTP/1.1
    """

"""
 headers = {
        'Content-Type': 'application/json',
        'Authorization' : 'Bearer <client_secret>'
    }

    data = { 
        "vc" : OPTIONAL -> { "VerifiableId" : { ......}}, json object, VC as a json-ld not signed
        "issuer_state" : REQUIRED, string,
        "credential_type" : [ "VerifiableId"]
        "pre-authorized_code" : True
        "user_pin_required" : True
        "user_pin" : REQUIRED
        "callback" : REQUIRED, string, this the user redirect route at the end of the flow
        }
    resp = requests.post(url, headers=headers, data = data)

    """

"""
GET /sandbox/ebsi/issuer/pcbrwbvrsi/authorize?
response_type=code
&client_id=did%3Akey%3AzQ3shRDkkch8btUzfQhWRuqM4E6hBXR7e1x2Y8S56CzEn9KHX
&redirect_uri=https%3A%2F%2Fapp.altme.io%2Fapp%2Fdownload%2Foidc4vc%2Fopenid-credential-offer%3A%2F%2F%3Fcredential_offer_uri%3Dhttps%3A%2F%2Ftalao.co%2Fsandbox%2Febsi%2Fissuer%2Fcredential_offer_uri%2F5212f8e5-4e0b-11ee-8a55-0a1628958560&scope=openid&issuer_state=51d4ae69-4e0b-11ee-b4de-0a1628958560&state=%5B0%5D&nonce=7c95aad4-f750-4a22-b367-61fbff152e5e&code_challenge=lf3q5-NObcyp41iDSIL51qI7pBLmeYNeyWnNcY2FlW4&code_challenge_method=S256&authorization_details=%5B%7B%22type%22%3A%22openid_credential%22%2C%22locations%22%3A%5B%22https%3A%2F%2Ftalao.co%2Fsandbox%2Febsi%2Fissuer%2Fpcbrwbvrsi%22%5D%2C%22format%22%3A%22jwt_vc%22%2C%22types%22%3A%5B%22VerifiableCredential%22%2C%22VerifiableAttestation%22%2C%22VerifiableDiploma%22%5D%7D%5D&client_metadata=%7B%22authorization_endpoint%22%3A%22openid%3A%22%2C%22scopes_supported%22%3A%5B%22openid%22%5D%2C%22response_types_supported%22%3A%5B%22vp_token%22%2C%22id_token%22%5D%2C%22subject_types_supported%22%3A%5B%22public%22%5D%2C%22id_token_signing_alg_values_supported%22%3A%5B%22ES256%22%5D%2C%22request_object_signing_alg_values_supported%22%3A%5B%22ES256%22%5D%2C%22vp_formats_supported%22%3A%7B%22jwt_vp%22%3A%7B%22alg_values_supported%22%3A%5B%22ES256%22%5D%7D%2C%22jwt_vc%22%3A%7B%22alg_values_supported%22%3A%5B%22ES256%22%5D%7D%7D%2C%22subject_syntax_types_supported%22%3A%5B%22urn%3Aietf%3Aparams%3Aoauth%3Ajwk-thumbprint%22%2C%22did%F0%9F%94%91jwk_jcs-pub%22%5D%2C%22id_token_types_supported%22%3A%5B%22subject_signed_id_token%22%5D%7D

"""