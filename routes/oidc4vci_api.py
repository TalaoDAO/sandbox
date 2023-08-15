"""
NEW


https://issuer.walt.id/issuer-api/default/oidc

https://openid.net/specs/openid-connect-4-verifiable-credential-issuance-1_0-05.html

support Authorization code flow and pre-authorized code flow of OIDC4VCI

"""
from flask import jsonify, request, render_template, Response, redirect
import json
from datetime import datetime, timedelta
import uuid
import logging
import didkit
from urllib.parse import urlencode
import db_api
import oidc4vc
from oidc4vc_constante import type_2_schema
from profile import profile


logging.basicConfig(level=logging.INFO)

API_LIFE = 5000
ACCESS_TOKEN_LIFE = 1000
GRANT_LIFE = 5000
C_NONCE_LIFE = 5000


def init_app(app,red, mode) :
    # endpoint for application if redirect to local page (test)
    app.add_url_rule('/sandbox/ebsi/issuer/<issuer_id>/<stream_id>',  view_func=ebsi_issuer_landing_page, methods = ['GET', 'POST'], defaults={'red' :red, 'mode' : mode})
    app.add_url_rule('/sandbox/ebsi/issuer_stream',  view_func=ebsi_issuer_stream, methods = ['GET', 'POST'], defaults={'red' :red})
    app.add_url_rule('/sandbox/ebsi/issuer_followup/<stream_id>',  view_func=ebsi_issuer_followup, methods = ['GET'], defaults={'red' :red})

    # api 
    app.add_url_rule('/sandbox/ebsi/issuer/api/<issuer_id>',  view_func=issuer_api_endpoint, methods = ['POST'], defaults={'red' :red, 'mode' : mode})
    
    # OIDC4VCI protocol with wallet
    app.add_url_rule('/sandbox/ebsi/issuer/<issuer_id>/.well-known/openid-configuration', view_func=ebsi_issuer_openid_configuration, methods=['GET'], defaults={'mode' : mode})
    app.add_url_rule('/sandbox/ebsi/issuer/<issuer_id>/.well-known/openid-credential-issuer', view_func=ebsi_issuer_openid_configuration, methods=['GET'], defaults={'mode' : mode})

    app.add_url_rule('/sandbox/ebsi/issuer/<issuer_id>/authorize',  view_func=ebsi_issuer_authorize, methods = ['GET', 'POST'], defaults={'red' :red})
    app.add_url_rule('/sandbox/ebsi/issuer/<issuer_id>/token',  view_func=ebsi_issuer_token, methods = ['POST'], defaults={'red' :red})
    app.add_url_rule('/sandbox/ebsi/issuer/<issuer_id>/credential',  view_func=ebsi_issuer_credential, methods = ['POST'], defaults={'red' :red})

    app.add_url_rule('/sandbox/ebsi/issuer/credential_offer_uri/<id>',  view_func=ebsi_issuer_credential_offer_uri, methods = ['GET'], defaults={'red' :red})

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
    
    # Credential supported section
    cs = list()
    for vc in issuer_profile['credential_supported']:
        try :
            file_path = './verifiable_credentials/' + vc + '.jsonld'
        except :
            logging.warning('Credential not found  %s', vc)
            return
        credential = json.load(open(file_path))
        oidc_data = {
            'format': issuer_profile['issuer_vc_type'],
            'types' : credential['type'],
            'cryptographic_binding_methods_supported': issuer_profile['cryptographic_binding_methods_supported'],
            'cryptographic_suites_supported': issuer_profile['cryptographic_suites_supported']
        }
        if issuer_data['profile'] != 'EBSI-V3' :
            oidc_data['id'] = vc
        else :
            oidc_data["trust_framework"] = {
                    "name": "ebsi",
                    "type": "Accreditation",
                    "uri": "TIR link towards accreditation"
                }
            # https://api-conformance.ebsi.eu/docs/ct/providers-and-wallets-metadata#credential-issuer-metadata
        cs.append(oidc_data)
        
    # Credential manifest section
    #https://openid.net/specs/openid-connect-4-verifiable-credential-issuance-1_0-05.html#name-server-metadata    
    cm = list()  
    for vc in issuer_profile['credential_supported']:
        file_path = './credential_manifest/' + vc + '_credential_manifest.json'
        cm_to_add = json.load(open(file_path))
        cm_to_add['issuer']['id'] = issuer_data.get('did' , 'Unknown')
        cm_to_add['issuer']['name'] = issuer_data['application_name']
        cm.append(cm_to_add)
    
    # https://www.rfc-editor.org/rfc/rfc8414.html#page-4
    openid_configuration = dict()
    if issuer_profile.get('service_documentation') :
        openid_configuration['service_documentation'] = issuer_profile['service_documentation']
    openid_configuration .update({
        'credential_issuer': mode.server + 'sandbox/ebsi/issuer/' + issuer_id,
        'authorization_endpoint':  mode.server + 'sandbox/ebsi/issuer/' + issuer_id + '/authorize',
        'token_endpoint': mode.server + 'sandbox/ebsi/issuer/' + issuer_id + '/token',
        'credential_endpoint': mode.server + 'sandbox/ebsi/issuer/' + issuer_id + '/credential',
        'pre-authorized_grant_anonymous_access_supported' : False,
        'subject_syntax_types_supported': issuer_profile['subject_syntax_types_supported'],
        'credential_supported' : cs,
        'credential_manifests' : cm,
    })
    return openid_configuration


# Customer API
def issuer_api_endpoint(issuer_id, red, mode) :
    """
    This API returns the QRcode page URL to redirect user or the QR code content if the page is managed by application

    headers = {
        'Content-Type': 'application/json',
        'Authorization' : 'Bearer <client_secret>'
    }
    data = { 
        "vc" : { "EmployeeCredendial" : {}, ....}, -> REQUIRED : object, VC as a json-ld not signed
        "pre-authorized_code" : "lklkjlkjh",   -> OPTIONAL, string if no it will be an authorization flow
        "issuer_state" : OPTIONAL, string, opaque to wallet
        "credential_type" : REQUIRED -> array or string name of the credential
        "user_pin_required" : false -> OPTIONAL, bool, False by default
        "user_pin" : OPTIONAL
        "callback" : OPTIONAL, string, this the route for at the end of the flo
        "redirect" : True by default OPTIONAL, bool, allow to use a local template
        }
    resp = requests.post(token_endpoint, headers=headers, data = data)
    return resp.json()

    """    
    try :
        token = request.headers['Authorization']
        client_secret = token.split(" ")[1]
        issuer_data = json.loads(db_api.read_ebsi_issuer(issuer_id))
        vc =  request.json['vc']
        credential_type = request.json['credential_type']  
    except :
        return Response(**manage_error("invalid_request", "Request format is incorrect", red))
    
    redirect = request.json.get('redirect', True)
    pre_authorized_code = request.json.get('credential_type')

    if client_secret != issuer_data['client_secret'] :
        return Response(**manage_error("Unauthorized", "Client secret is incorrect", red, status=401))
    
    issuer_profile = profile[issuer_data['profile']]

    credential_type_checklist = credential_type if isinstance(credential_type, list) else [credential_type]
    for _vc in credential_type_checklist :
        if _vc not in issuer_profile[ 'credential_supported'] :
              logging.warning("Credential not supported %s", _vc)
              return Response(**manage_error("Unauthorized", "Credential not supported", red, status=401))
    
    if request.json.get('user_pin_required') and not request.json.get('user_pin') :
        return Response(**manage_error("Unauthorized", "User pin is not set", red, status=401))

    issuer_vc_type = issuer_profile['issuer_vc_type']
    user_data = {
        'vc' : vc,
        'issuer_vc_type' : issuer_vc_type,
        'issuer_id' : issuer_id,
        'issuer_state' : request.json.get('issuer_state'),
        'credential_type' : credential_type,
        'pre-authorized_code' : request.json.get('pre-authorized_code'),
        'user_pin_required' : request.json.get('user_pin_required'),
        'user_pin' : request.json.get('user_pin'),
        'callback' : request.json.get('callback')
    }
    if redirect :
        stream_id = str(uuid.uuid1())
        logging.info('Test mode')
        red.setex(stream_id, API_LIFE, json.dumps(user_data))
        response = {"redirect_uri" : mode.server+ 'sandbox/ebsi/issuer/' + issuer_id +'/' + stream_id }
        logging.info('initiate qrcode = %s', mode.server+ 'sandbox/ebsi/issuer/' + issuer_id +'/' + stream_id)
        return jsonify( response)
    
    url_data, code_data = build_credential_offer(issuer_id,
                                                credential_type,
                                                pre_authorized_code,
                                                issuer_vc_type,
                                                profile,
                                                vc,
                                                request.json.get('user_pin_required'),
                                                request.json.get('user_pin'),
                                                mode)
    if not url_data :
        return Response(**manage_error("Internal server error", "Server error", red, status=500))

    if issuer_data['profile']  != 'EBSI-V2' :
        qrcode = issuer_profile['oidc4vci_prefix'] + '?' + urlencode({"credential_offer" : json.dumps(url_data)})
    else :
        qrcode = issuer_profile['oidc4vci_prefix'] + '?' + urlencode(url_data)
    response = {"qrcode" : qrcode}
    logging.info("Qrcode value is sent back to application = %s", qrcode)
    red.setex(pre_authorized_code, GRANT_LIFE, json.dumps(code_data)) 
    return jsonify(response)


def build_credential_offer(issuer_id, credential_type, pre_authorized_code, issuer_vc_type, issuer_profile, vc, user_pin_required, user_pin, mode) :
   
    if issuer_profile == 'EBSI-V2' :
        url_data  = { 
            'issuer' : mode.server +'sandbox/ebsi/issuer/' + issuer_id,
            'credential_type'  : type_2_schema[credential_type],
        }

    elif issuer_profile == 'GAIA-X' :
        if isinstance(credential_type, str) :
            credential_type = [credential_type]
        if len(credential_type)== 1 :
            credential_type = credential_type[0]
        url_data  = { 
            "issuer" : mode.server +'sandbox/ebsi/issuer/' + issuer_id,
            "credential_type"  : credential_type,
        }

    # new OIDC4VCI standard with  credential as json object
    elif issuer_profile == 'EBSI-V3' :
        if isinstance(credential_type, str) :
            credential_type = [credential_type]
        url_data  = { 
            "credential_issuer" : mode.server +'sandbox/ebsi/issuer/' + issuer_id,
            "credentials"  : []
        }
        for vc in credential_type :
            credential = json.load(open('verifiable_credentials/' + vc + '.jsonld', 'r'))
            url_data["credentials"].append({
                'format': profile[issuer_profile]['issuer_vc_type'],
                'types': credential['type'],
                'trust_framework': profile[issuer_profile]['trust_framework']
            })
    
    else :
        # new OIDC4VCI standard with credential as json string
        if isinstance(credential_type, str) :
            credential_type = [credential_type]
        url_data  = { 
            "credential_issuer" : mode.server +'sandbox/ebsi/issuer/' + issuer_id,
            "credentials"  : credential_type
        }
                
    #  https://openid.net/specs/openid-connect-4-verifiable-credential-issuance-1_0-05.html#name-pre-authorized-code-flow
    if pre_authorized_code and profile in ['EBSI-V2', 'GAIA-X'] :
        url_data['pre-authorized_code'] = pre_authorized_code
        url_data['user_pin_required']= user_pin_required
    
    elif pre_authorized_code  :
        url_data['grants'] ={
            "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                "pre-authorized_code": pre_authorized_code,
                "user_pin_required": user_pin_required
            }
        }
    
    else :
        url_data["grants"] ={
            "authorization_code": {}
        }
    code_data = {
            'credential_type' : credential_type,
            'format' : issuer_vc_type,
            'vc' : vc,
            'issuer_id' : issuer_id,
            "user_pin_required": user_pin_required,
            'user_pin' : user_pin
    }
    return url_data, code_data


def ebsi_issuer_credential_offer_uri(id, red):
    try :
        url = red.get(id).decode()
    except :
        logging.warning("session expired")
        return jsonify("Session expired"), 404
    return jsonify(url)


# initiate endpoint with QRcode for API in case of test
def ebsi_issuer_landing_page(issuer_id, stream_id, red, mode) :
    try :
        user_data = json.loads(red.get(stream_id).decode())
    except :
        logging.warning("session expired")
        return jsonify("Session expired"), 404
    credential_type = user_data['credential_type']
    pre_authorized_code = user_data['pre-authorized_code']
    user_pin_required = user_data['user_pin_required']
    user_pin = user_data['user_pin']
    issuer_vc_type = user_data['issuer_vc_type']
    vc = user_data['vc']
    issuer_data = json.loads(db_api.read_ebsi_issuer(issuer_id))
    data_profile = profile[issuer_data['profile']]
    url_data, code_data = build_credential_offer(issuer_id, credential_type, pre_authorized_code, issuer_vc_type, issuer_data['profile'], vc, user_pin_required, user_pin, mode)
    code_data['stream_id'] = stream_id  # to manage the followup screen
    red.setex(pre_authorized_code, GRANT_LIFE, json.dumps(code_data))
    if issuer_data['profile']  not in ['EBSI-V2', 'GAIA-X'] :
        url_to_display = data_profile['oidc4vci_prefix'] + "?" + urlencode( {'credential_offer' : json.dumps(url_data)})
        json_url  = {"credential_offer" : json.loads(json.dumps(url_data))}
    else :
        url_to_display = data_profile['oidc4vci_prefix'] + '?' + urlencode(url_data)
        json_url = url_data
    # credential offer uri
    if issuer_data.get('credential_offer_uri') :
            id = str(uuid.uuid1())
            credential_offer_uri = mode.server + 'sandbox/ebsi/issuer/credential_offer_uri/' + id
            red.setex(id, GRANT_LIFE, url_to_display)
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
        landing_page_url=issuer_data['landing_page_url']
    )


def ebsi_issuer_authorize(issuer_id, red) :
    """
    DEPRECATAED

    """
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

    logging.info("authorization request received = %s", request.args)
    try :
        client_id = request.args['client_id']
        redirect_uri = request.args['redirect_uri']
        op_state = request.args.get('op_state')
        issuer_state = request.args.get('issuer_state')
    except :
        return jsonify('invalid_request'), 400
    
    op_state = op_state if op_state else issuer_state

    try :
        scope = request.args['scope']
    except :
        return authorization_error_response("invalid_request", "scope is missing", op_state, red)
    
    try :
        response_type = request.args['response_type']
    except :
        return authorization_error_response("invalid_request", "reponse_type is missing", op_state, red)
    
    try :
        credential_type = json.loads(request.args['authorization_details'])[0]['credential_type']
    except :
        return authorization_error_response("invalid_request", "credential_type is missing", op_state, red)
    
    try :
        format = json.loads(request.args['authorization_details'])[0]['format']
    except :
        return authorization_error_response("invalid_request", "format is missing", op_state, red)
    if not db_api.read_ebsi_issuer(issuer_id) :
        return authorization_error_response("unauthorized_client", "issuer_id not found in data base", op_state, red)
    issuer_data = json.loads(db_api.read_ebsi_issuer(issuer_id))
    if scope != 'openid' :
        return authorization_error_response("invalid_scope", "unsupported scope", op_state, red)
    if response_type != 'code' :
        return authorization_error_response("unsupported_response_type", "unsupported response type", op_state, red)
    if credential_type != issuer_data['credential_to_issue'] :
        return authorization_error_response("invalid_request", "unsupported credential type", op_state, red)
    if format not in ['jwt_vc', 'jwt_vc_json'] :
        return authorization_error_response("invalid_request", "unsupported format", op_state, red)

    # Code creation
    code = str(uuid.uuid1())
    code_data = {
        'credential_type' : credential_type,
        'format' : format,
        'stream_id' : op_state,
        'vc' : "vc_for_test",
        'code_challenge' : request.args.get('code_challenge'), 
        'code_challenge_method' : request.args.get('code_challenge_method'),
    }
    red.setex(code, GRANT_LIFE, json.dumps(code_data))    

    resp = {'code' : code}
    if request.args.get('state') :
        resp['state'] = request.args['state']
    return redirect(redirect_uri + '?' + urlencode(resp))



# token endpoint
def ebsi_issuer_token(issuer_id, red) :
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
        code = request.form.GET('code')
    
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

    endpoint_response = {
        'access_token' : access_token,
        'c_nonce' : str(uuid.uuid1()),
        'token_type' : 'Bearer',
        'expires_in': ACCESS_TOKEN_LIFE
    }
    token_endpoint_data = {
        'access_token' : access_token,
        'pre_authorized_code' : code,
        'c_nonce' : endpoint_response.get('c_nonce'),
        'format' : data.get('format'),
        'credential_type' : data.get('credential_type'),
        'vc' : data.get('vc'),
        'stream_id' : data.get('stream_id'),
        'issuer_id' : data.get('issuer_id')
    }

    red.setex(access_token, ACCESS_TOKEN_LIFE,json.dumps(token_endpoint_data))

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
    
    # to manage followuip screen
    stream_id = access_token_data.get('stream_id')
    
    issuer_data = json.loads(db_api.read_ebsi_issuer(issuer_id))
    logging.info('Profile = %s', issuer_data['profile'])

    issuer_profile = profile[issuer_data['profile']]
    
    # Check request 
    try :
        result = request.json
        proof_format = result['format']
        proof_type  = result['proof']['proof_type']
        proof = result['proof']['jwt']
    except :
        return Response(**manage_error("invalid_request", "Invalid request format", red, stream_id=stream_id)) 
    
    if proof_type != 'jwt' : 
        return Response(**manage_error("unsupported_credential_type", "The credential proof type is not supported =%s", proof_type)) 

    # get type of credential requested
    try :
        credential_type = result['type']
    except :
        try :
            credential_type = result['types']
            if isinstance(credential_type, list) :
                for type in credential_type :
                    if type != 'VerifiableCredential' :
                        credential_type = type
                        break 
        except :
            return Response(**manage_error('invalid_request', 'Invalid request format', red, stream_id=stream_id)) 
    
    logging.info('credential type requested = %s', credential_type)
    
    credential_is_supported = False
    if issuer_data['profile'] != 'EBSI-V2' :
        for vc in issuer_profile['credential_supported'] :
            if vc == credential_type :
                credential_is_supported = True
                logging.info('credential is supported')
                break
        if not credential_is_supported : 
            return Response(**manage_error('unsupported_credential_type', 'The credential type is not supported', red, stream_id=stream_id)) 

    # check proof format requested
    logging.info('proof format requested = %s', proof_format)
    if proof_format not in ['jwt_vc','jwt_vc_json', 'jwt_vc_json-ld', 'ldp_vc'] :#TODO
        return Response(**manage_error('unsupported_credential_format', 'The proof format requested is not supported', red, stream_id=stream_id)) 

    # Check proof  of key ownership received (OPTIONAL check)
    logging.info('proof of key ownership received = %s', proof)
    try :
        oidc4vc.verif_token(proof, access_token_data['c_nonce'])
        logging.info('proof of ownership is validated')
    except Exception as e :
        logging.warning('proof of ownership error = %s', str(e))

    proof_payload=oidc4vc.get_payload_from_token(proof)
    issuer_data = json.loads(db_api.read_ebsi_issuer(issuer_id))
    
    # for EBSI ......
    if credential_type in ['https://api-conformance.ebsi.eu/trusted-schemas-registry/v2/schemas/z22ZAMdQtNLwi51T2vdZXGGZaYyjrsuP1yzWyXZirCAHv'] :
        credential_type = 'VerifiableId' 
    elif  credential_type in ['https://api.preprod.ebsi.eu/trusted-schemas-registry/v1/schemas/0xbf78fc08a7a9f28f5479f58dea269d3657f54f13ca37d380cd4e92237fb691dd'] :
        credential_type = 'VerifiableDiploma' 
    try :
        credential = access_token_data['vc'][credential_type]
    except :
        # send event to front to go forward callback and send credential to wallet
        return Response(**manage_error('unsupported_credential_type', 'The credential type is not offered', red, stream_id=stream_id)) 

    credential['id']= 'urn:uuid:' + str(uuid.uuid1())
    credential['credentialSubject']['id'] = proof_payload.get('iss')
    credential['issuer']= issuer_data['did']
    credential['issued'] = datetime.now().replace(microsecond=0).isoformat() + 'Z'
    credential['issuanceDate'] = datetime.now().replace(microsecond=0).isoformat() + 'Z'
    credential['validFrom'] = datetime.now().replace(microsecond=0).isoformat() + 'Z'
    credential['expirationDate'] =  (datetime.now() + timedelta(days= 365)).isoformat() + 'Z'
    credential['validUntil'] =  (datetime.now() + timedelta(days= 365)).isoformat() + 'Z'
    
    issuer_key =  issuer_data['jwk'] 
    issuer_vm = issuer_data['verification_method'] 

    if proof_format in ['jwt_vc', 'jwt_vc_json', 'jwt_vc_json-ld'] :        
        credential_signed = oidc4vc.sign_jwt_vc(credential, issuer_vm , issuer_key, access_token_data['c_nonce'])
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
    logging.info('credential signed sent to wallet = %s', credential_signed)

    # send event to front to go forward callback and send credential to wallet
    front_publish(access_token_data['stream_id'], red)
    
    # Transfer VC
    payload = {
        #'acceptance_token' : None,
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
    callback_uri = callback + '?pre-authorized_code=' + user_data.get('pre-authorized_code')
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



