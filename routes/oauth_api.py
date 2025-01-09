"""
NEW
https://issuer.walt.id/issuer-api/default/oidc
EBSI V2 https://openid.net/specs/openid-connect-4-verifiable-credential-issuance-1_0-05.html
support Authorization code flow and pre-authorized code flow of OIDC4VCI
"""
import copy
import json
import logging
import random
import uuid
from datetime import datetime, timedelta
from profile import profile
from random import randint
from urllib.parse import urlencode
import urllib
import db_api
import oidc4vc  # type: ignore
import pkce
import requests
from flask import (Response, flash, jsonify, redirect,  # type: ignore
                render_template, request, session)
from jwcrypto import jwk # type: ignore


logging.basicConfig(level=logging.INFO)

API_LIFE = 5000
ACCESS_TOKEN_LIFE = 10000
GRANT_LIFE = 5000
C_NONCE_LIFE = 5000
ACCEPTANCE_TOKEN_LIFE = 28 * 24 * 60 * 60
STATUSLIST_ISSUER_KEY = json.dumps(json.load(open('keys.json', 'r'))['talao_Ed25519_private_key'])


def init_app(app, red, mode):
    
    # AS endpoint   
    app.add_url_rule('/issuer/<issuer_id>/standalone/authorize', view_func=standalone_issuer_authorize, methods=['GET'], defaults={'red': red, 'mode': mode})
    app.add_url_rule('/issuer/<issuer_id>/standalone/authorize/par', view_func=standalone_issuer_authorize_par, methods=['POST'], defaults={'red': red, 'mode':mode})
    app.add_url_rule('/issuer/<issuer_id>/standalone/token', view_func=standalone_issuer_token, methods=['POST'], defaults={'red': red, 'mode': mode},)
    
    # login with login/password authorization code flow
    app.add_url_rule('/issuer/<issuer_id>/standalone/authorize/login', view_func=standalone_issuer_authorize_login, methods=['GET', 'POST'], defaults={'red': red})
    # login with PID authorization code flow
    app.add_url_rule("/issuer/<issuer_id>/standalone/authorize/pid", view_func=standalone_issuer_authorize_pid, methods=['POST'], defaults={'red': red})

    return


def front_publish(stream_id, red, error=None, error_description=None):
    # send event to front channel to go forward callback and send credential to wallet
    data = {'stream_id': stream_id}
    if error:
        data['error'] = error
    if error_description:
        data['error_description'] = error_description
    red.publish('issuer_oidc', json.dumps(data))


def wallet_error_uri():
    error = request.args.get('error')
    error_description = request.args.get('error_description')
    header = request.args.get('header')
    body = request.args.get('body')
    arguments = request.args.get('arguments')
    return render_template(
        'issuer_oidc/issuer_error_uri.html',
        header=header,
        error=error,
        error_description=error_description,
        body=body,
        arguments=arguments
    )


def error_uri_build(request, error, error_description, mode):
    if request.headers.get('Content-Type') == 'application/json':
        body = json.dumps(request.json)
    elif not request.headers.get('Content-Type'):
        body = ''
    else:
        body = json.dumps(request.form)

    data = {
        'header': str(request.headers),
        'arguments': json.dumps(request.args),
        'body': body,
        'error': error,
        'error_description': error_description
    }
    return mode.server + 'issuer/error_uri?' + urlencode(data)


def manage_error(error, error_description, red, mode, request=None, stream_id=None, status=400, webhook=None):
    """
    Return error code to wallet and front channel
    https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-error-response
    """
    # front channel
    if stream_id:
        front_publish(stream_id, red, error=error, error_description=error_description)
    
    if webhook:
        requests.post(webhook, json={"event": "ERROR"}, timeout=10)

    # wallet
    payload = {
        'error': error,
        'error_description': error_description,
    }
    if error == 'invalid_proof':
        payload['c_nonce'] = str(uuid.uuid1())
        payload['c_nonce_expires_in'] = 86400
    
    if request:
        payload['error_uri'] = error_uri_build(request, error, error_description, mode)
    
    logging.info('endpoint error response = %s', json.dumps(payload, indent=4))

    headers = {'Cache-Control': 'no-store', 'Content-Type': 'application/json'}
    return {'response': json.dumps(payload), 'status': status, 'headers': headers}



def thumbprint(key):
    signer_key = jwk.JWK(**key)
    return signer_key.thumbprint()


# jwks endpoint
def issuer_jwks(issuer_id):
    issuer_data = json.loads(db_api.read_oidc4vc_issuer(issuer_id))
    pub_key = copy.copy(json.loads(issuer_data['jwk']))
    del pub_key['d']
    pub_key['kid'] = pub_key.get('kid') if pub_key.get('kid') else thumbprint(pub_key)
    jwks = {'keys': [pub_key]}
    logging.info('issuer jwks = %s', jwks)
    return jsonify(jwks)


def authorization_error(error, error_description, stream_id, red, state):
    """
    https://www.rfc-editor.org/rfc/rfc6749.html#page-26
    """
    resp = {
        'error_description': error_description,
        'error': error
    }
    # front channel follow up
    if not stream_id:
        return jsonify(resp)
    front_publish(stream_id, red, error=error, error_description=error_description)
    if state:
        resp['state'] = state
    return urlencode(resp)


# pushed authorization endpoint endpoint
def standalone_issuer_authorize_par(issuer_id, red, mode):
    logging.info('request header = %s', request.headers)
    logging.info('request body = %s', json.dumps(request.form, indent=4))
    
    # DPoP
    if request.headers.get('DPoP'):
        try:
            DPoP_header = oidc4vc.get_header_from_token(request.headers.get('DPoP'))
            DPoP_payload = oidc4vc.get_payload_from_token(request.headers.get('DPoP'))
            logging.info('DPoP header = %s', json.dumps(DPoP_header, indent=4))
            logging.info('DPoP payload = %s', json.dumps(DPoP_payload, indent=4))
        except Exception as e:
            return Response(**manage_error('invalid_request', 'DPoP is incorrect ' + str(e), red, mode, request=request))
    else:
        logging.info('No DPoP')
        
    try:
        issuer_data = json.loads(db_api.read_oidc4vc_issuer(issuer_id))
    except Exception:
        logging.warning('issuer_id not found for %s', issuer_id)
        return
    if issuer_data['profile'] in ['HAIP', 'POTENTIAL']:
        if not request.form.get('client_assertion_type') and not request.headers.get('Oauth-Client-Attestation'):
            return Response(**manage_error('invalid_request', 'HAIP and POTENTIAL request client assertion authentication', red, mode, request=request))
    
    # Check content of client assertion and proof of possession (DPoP)
    if request.form.get('client_assertion'):
        client_assertion = request.form.get('client_assertion').split("~")[0]
        logging.info('client _assertion = %s', client_assertion)
        if request.form.get('client_id') != oidc4vc.get_payload_from_token(client_assertion).get('sub'):
            return Response(**manage_error('invalid_request', 'client_id does not match client assertion sub', red, mode, request=request))
        try:
            DPoP = request.form.get('client_assertion').split("~")[1]
        except Exception:
            return Response(**manage_error('invalid_request', 'PoP is missing', red, mode, request=request))
        logging.info('proof of possession = %s', DPoP)
        if oidc4vc.get_payload_from_token(client_assertion).get('sub') != oidc4vc.get_payload_from_token(DPoP).get('iss'):
            return Response(**manage_error('invalid_request', 'sub of client assertion does not match proof of possession iss', red, mode, request=request))
    
    elif request.headers.get('Oauth-Client-Attestation'):
        client_assertion = request.headers.get('Oauth-Client-Attestation')
        logging.info('OAuth-Client-Attestation = %s', client_assertion)
        if request.form.get('client_id') != oidc4vc.get_payload_from_token(client_assertion).get('sub'):
            return Response(**manage_error('invalid_request', 'client_id does not match client assertion sub', red, mode, request=request))
        try:
            DPoP = request.headers.get('Oauth-Client-Attestation-Pop')
        except Exception:
            return Response(**manage_error('invalid_request', 'PoP is missing', red, mode, request=request))
        logging.info('OAuth-Client-Attestation-PoP = %s', DPoP)
        if oidc4vc.get_payload_from_token(client_assertion).get('sub') != oidc4vc.get_payload_from_token(DPoP).get('iss'):
            return Response(**manage_error('invalid_request', 'sub of client assertion does not match proof of possession iss', red, mode, request=request))
    else:
        logging.warning("No client assertion / wallet attestation")
    try:
        request_uri_data = {
            'redirect_uri': request.form['redirect_uri'],
            'client_id': request.form['client_id'],
            'response_type': request.form['response_type'],
            'scope': request.form['scope'],
            'issuer_state': request.form.get('issuer_state'),
        }
    except Exception:
        return Response(**manage_error('invalid_request', 'Request format is incorrect', None, red, None))
    request_uri_data.update({
        'nonce': request.form.get('nonce'),
        'code_challenge': request.form.get('code_challenge'),
        'code_challenge_method': request.form.get('code_challenge_method'),
        'client_metadata': request.form.get('client_metadata'),
        'state': request.form.get('state'),
        'authorization_details': request.form.get('authorization_details')
    })
    request_uri = 'urn:ietf:params:oauth:request_uri:' + str(uuid.uuid1())
    red.setex(request_uri, 50, json.dumps(request_uri_data))
    endpoint_response = {
        'request_uri': request_uri,
        'expires_in': 50
    }
    headers = {
        'Cache-Control': 'no-store',
        'Content-Type': 'application/json'
    }
    return Response(response=json.dumps(endpoint_response), headers=headers)


# IDP login for authorization code flow
def standalone_issuer_authorize_login(issuer_id, red):
    if request.method == 'GET':
        session['login'] = False
        session['test'] = False
        return render_template('issuer_oidc/authorize.html', url= '/issuer/' + issuer_id + '/standalone/authorize/login')
    if not red.get( request.form['test']):
        flash('Wrong test name', 'danger')
        #return redirect('/issuer/' + issuer_id + '/standalone/authorize/login') 
    session['login'] = True
    session['test'] = request.form['test']
    return redirect('/issuer/' + issuer_id + '/standalone/authorize?test=' + session['test']) 


# PID login for authorization code flow
def standalone_issuer_authorize_pid(issuer_id, red):
    state = request.form['state']
    code_data = json.loads(red.get(state).decode())
    # Code creation
    code = str(uuid.uuid1()) #+ '.' + str(uuid.uuid1()) + '.' + str(uuid.uuid1())
    red.setex(code, GRANT_LIFE, json.dumps(code_data))
    resp = {'code': code}
    if code_data['state']:
        resp['state'] = code_data['state']
    redirect_uri = code_data['redirect_uri']
    session.clear()
    return redirect(redirect_uri + '?' + urlencode(resp))


# authorization code endpoint
def standalone_issuer_authorize(issuer_id, red, mode):
    # user not logged
    if not session.get('login'):
        logging.info('User is not logged')
        try:
            issuer_data = json.loads(db_api.read_oidc4vc_issuer(issuer_id))
        except Exception:
            logging.warning('issuer_id not found for %s', issuer_id)
            return
        
        # Push Authorization Request
        if request_uri:= request.args.get('request_uri'):
            try:
                request_uri_data = json.loads(red.get(request_uri).decode())   
            except Exception:
                logging.warning('redirect uri failed')
                return jsonify({
                    'error': 'invalid_request',
                    'error_description': 'request is expired'
                }), 403
            client_id = request_uri_data.get('client_id')
            issuer_state = request_uri_data.get('issuer_state')
            redirect_uri = request_uri_data.get('redirect_uri')
            issuer_state = request_uri_data.get('client_id')
            response_type = request_uri_data.get('response_type')
            scope = request_uri_data.get('scope')
            nonce = request_uri_data.get('nonce')
            code_challenge = request_uri_data.get('code_challenge')
            code_challenge_method = request_uri_data.get('code_challenge_method')
            client_metadata = request_uri_data.get('client_metadata')
            wallet_issuer = request_uri_data.get('wallet_issuer')
            state = request_uri_data.get('state')
            authorization_details = request_uri_data.get('authorization_details')
        
        # Standard Authorization code flow
        else:
            try:
                redirect_uri = request.args['redirect_uri']
            except Exception:
                return jsonify({
                    'error': 'access_denied',
                    'error_description': 'redirect_uri is missing'
                }), 403
            try:
                response_type = request.args['response_type']
            except Exception:
                return redirect(redirect_uri + '?' + authorization_error('invalid_request', 'response_type is missing', None, red, state))
            try:
                scope = request.args['scope']
            except Exception:
                return redirect(redirect_uri + '?' + authorization_error('invalid_request', 'scope is missing', None, red, state))
            nonce = request.args.get('nonce')
            client_id = request.args.get('client_id')
            scope = request.args.get('scope')
            code_challenge = request.args.get('code_challenge')
            code_challenge_method = request.args.get('code_challenge_method')
            client_metadata = request.args.get('client_metadata')
            wallet_issuer = request.args.get('wallet_issuer')
            state = request.args.get('state')  # wallet state
            issuer_state = request.args.get('issuer_state') 
            authorization_details = request.args.get('authorization_details')
        
        logging.info('client_id of the wallet = %s', client_id)
        logging.info('redirect_uri = %s', redirect_uri)
        logging.info('code_challenge = %s', code_challenge)
        logging.info('client_metadata = %s ', client_metadata)
        logging.info('wallet_issuer = %s ', wallet_issuer)
        logging.info('authorization details = %s', authorization_details)
        logging.info('scope = %s', scope)
        if response_type != 'code':
            return redirect(redirect_uri + '?' + authorization_error('invalid_response_type', 'response_type not supported', None, red, state))
        
        # redirect user to login/password screen or redirect to VP request
        code_data = {
            'client_id': client_id,
            'scope': scope,
            'nonce': nonce,
            'authorization_details': authorization_details,
            'redirect_uri': redirect_uri,
            'issuer_id': issuer_id,
            'issuer_state': issuer_state,
            'state': state,
            'code_challenge': code_challenge,
            'code_challenge_method': code_challenge_method,
        }
        session['code_data'] = code_data
        # redirect user to login/password screen
        if issuer_state != "pid_authentication":
            return redirect('/issuer/' + issuer_id + '/standalone/authorize/login')
        
        # redirect user to VP request to get a PID
        else:
            # fetch credential.
            issuer_data = json.loads(db_api.read_oidc4vc_issuer(issuer_id))
            issuer_profile = profile[issuer_data['profile']]
            vc_list = issuer_profile["credential_configurations_supported"].keys()
            for vc in vc_list:
                if issuer_profile["credential_configurations_supported"][vc]["scope"] == session['code_data']['scope']:
                    break
            try:
                f = open("./verifiable_credentials/" + vc + ".jsonld", 'r')
            except Exception:
                # for vc+sd-jwt 
                try:
                    f = open("./verifiable_credentials/" + vc + ".json", 'r')
                except Exception:
                    logging.error("file not found")
                    return redirect(redirect_uri + '?' + authorization_error('invalid_request', 'VC not found', None, red, state))
            credential = json.loads(f.read())
            if client_metadata:
                wallet_authorization_endpoint = json.loads(client_metadata)['authorization_endpoint']
            elif wallet_issuer:
                resp = requests.get(wallet_issuer + '/.well-known/openid-configuration')
                wallet_authorization_endpoint = resp.json()['authorization_endpoint']
            else:
                logging.error('no wallet metadata')
                return redirect(redirect_uri + '?' + authorization_error('invalid_request', 'Wallet authorization endpoint not found', None, red, state))
            
            with open('presentation_definition_for_PID.json', 'r') as f:
                presentation_definition = json.loads(f.read())
            VP_request = {
                "aud": "https://self-issued.me/v2",
                "client_id": "did:web:talao.co",
                "client_id_scheme": "redirect_uri",
                "exp": 1829170402,
                "iss": "did:web:talao.co",
                "nonce": "5381697f-8c86-11ef-9061-0a1628958560",
                "response_mode": "direct_post",
                "response_type": "vp_token",
                "response_uri": mode.server + 'issuer/' + issuer_id + '/standalone/authorize/pid',
                "state": str(uuid.uuid1()),
                "presentation_definition": presentation_definition
            }
            code_data["stream_id"] = None
            code_data["vc"] = {vc: credential}
            code_data["credential_type"] = [vc]
            red.setex(VP_request['state'], 10000, json.dumps(code_data))
            return redirect(wallet_authorization_endpoint + "?" + urlencode(VP_request))
    
    # return from login/password screen
    logging.info('user is logged')
    session['login'] = False
    test = request.args.get('test')
    try:
        """
        issuer initiated authorization code flow with QR code
        """
        offer_data = json.loads(red.get(test).decode())
    except Exception:
        """ 
        wallet initiated authorization code flow -> create offer_data from file as it is needed for web wallet tests
        
        """
        # fetch credential
        issuer_data = json.loads(db_api.read_oidc4vc_issuer(issuer_id))
        issuer_profile = profile[issuer_data['profile']]
        vc_list = issuer_profile["credential_configurations_supported"].keys()
        for vc in vc_list:
            if issuer_profile["credential_configurations_supported"][vc]["scope"] == session['code_data']['scope']:
                break
        try:
            f = open("./verifiable_credentials/" + vc + ".jsonld", 'r')
        except Exception:
            # for vc+sd-jwt 
            try:
                f = open("./verifiable_credentials/" + vc + ".json", 'r')
            except Exception:
                logging.error("file not found")
                return redirect(redirect_uri + '?' + authorization_error('invalid_request', 'VC not found', None, red, state))
        credential = json.loads(f.read())
        offer_data = {
            "stream_id": None,
            "vc": {vc: credential},
            "credential_type": [vc]
        }
    
    # update code data with credential value   
    vc = offer_data['vc']
    try:
        session['code_data']['stream_id'] = offer_data['stream_id']
        session['code_data']['vc'] = vc
        session['code_data']['credential_type'] = offer_data['credential_type']
    except Exception:
        redirect_uri = session['code_data']['redirect_uri']
        logging.error('code_data key error oidc_vci 612')
        return redirect(redirect_uri + '?' + authorization_error('invalid_request', 'Session expired', None, red, state))

    # Code creation
    code = str(uuid.uuid1()) #+ '.' + str(uuid.uuid1()) + '.' + str(uuid.uuid1())
    red.setex(code, GRANT_LIFE, json.dumps(session['code_data']))
    resp = {'code': code}
    if session['code_data']['state']:
        resp['state'] = session['code_data']['state']
    redirect_uri = session['code_data']['redirect_uri']
    session.clear()
    return redirect(redirect_uri + '?' + urlencode(resp))


# token endpoint
def standalone_issuer_token(issuer_id, red, mode):
    """
    token endpoint: https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
    DPoP: https://datatracker.ietf.org/doc/rfc9449/
    """
    logging.info('token endoint header %s', request.headers)
    logging.info('token endoint form %s', json.dumps(request.form, indent=4))
    issuer_data = json.loads(db_api.read_oidc4vc_issuer(issuer_id))
    issuer_profile = profile[issuer_data['profile']]
    
    # display DPoP
    if request.headers.get('DPoP'):
        try:
            DPoP_header = oidc4vc.get_header_from_token(request.headers.get('DPoP'))
            DPoP_payload = oidc4vc.get_payload_from_token(request.headers.get('DPoP'))
            logging.info('DPoP header = %s', json.dumps(DPoP_header, indent=4))
            logging.info('DPoP payload = %s', json.dumps(DPoP_payload, indent=4))
        except Exception as e:
            return Response(**manage_error('invalid_request', 'DPoP is incorrect ' + str(e), red, mode, request=request))
    else:
        logging.info('No DPoP')
    
    # check grant type
    grant_type = request.form.get('grant_type')
    if not grant_type:
        return Response(**manage_error('invalid_request', 'Request format is incorrect, grant is missing', red, mode, request=request))

    if grant_type == 'urn:ietf:params:oauth:grant-type:pre-authorized_code' and not request.form.get('pre-authorized_code'):
        return Response(**manage_error('invalid_request', 'Request format is incorrect, this grant type is not supported', red, mode, request=request))

    if grant_type == 'urn:ietf:params:oauth:grant-type:pre-authorized_code':
        code = request.form.get('pre-authorized_code')
        if int(issuer_profile['oidc4vciDraft']) >= 13:
            user_pin = request.form.get('tx_code')
        else:
            user_pin = request.form.get('user_pin')
    elif grant_type == 'authorization_code':
        code = request.form.get('code')
        user_pin = None
    else:
        return Response(**manage_error('invalid_request', 'Grant type not supported', red, mode, request=request))
    if not code and grant_type != 'client_credentials':
        return Response(**manage_error('invalid_request', 'Request format is incorrect, code is missing', red, mode, request=request))
    if grant_type == 'authorization_code' and not request.form.get('redirect_uri'):
        return Response(**manage_error('invalid_request', 'Request format is incorrect, redirect_uri is missing', red, mode, request=request))

    # display client_authentication method
    if request.form.get('assertion') or request.form.get('client_assertion') or request.headers.get('Oauth-Client-Attestation'):
        client_authentication_method = 'client_secret_jwt'
    elif request.headers.get('Authorization'):
        client_authentication_method = 'client_secret_basic'
    elif request.form.get('client_id') and request.form.get('client_secret'):
        client_authentication_method = 'client_secret_post'
    elif request.form.get('client_id'):
        client_authentication_method = 'client_id'
    else:
        client_authentication_method = 'none'
    logging.info('client authentication method = %s', client_authentication_method)

    # Profile check
    if issuer_profile in ['EBSI-V3', 'DIIP']:
        if not request.form.get('client_id'):
            return Response(**manage_error('invalid_request', 'Client incorrect authentication method', red, mode, request=request))
        if not request.form.get('client_id')[:3] != 'did':
            return Response(**manage_error('invalid_request', 'Client incorrect authentication method', red, mode, request=request))
    
    elif issuer_data['profile'] in ['HAIP', 'POTENTIAL']:
        if not request.form.get('client_assertion_type') and not request.headers.get('Oauth-Client-Attestation'):
            return Response(**manage_error('invalid_request', 'HAIP requests client assertion authentication', red, mode, request=request))
    else:
        pass
    
    # Check content of client assertion and proof of possession (PoP)
    if client_authentication_method == 'client_secret_jwt':
        try:
            # https://www.ietf.org/archive/id/draft-ietf-oauth-attestation-based-client-auth-03.html
            client_assertion = request.headers.get('Oauth-Client-Attestation')
            logging.info('OAuth-Client-Attestation = %s', client_assertion)
            if request.form.get('client_id') != oidc4vc.get_payload_from_token(client_assertion).get('sub'):
                return Response(**manage_error('invalid_request', 'client_id does not match client assertion subject', red, mode, request=request))
            PoP = request.headers.get('Oauth-Client-Attestation-Pop')
            logging.info('OAuth-Client-Attestation-PoP = %s', PoP)
            if oidc4vc.get_payload_from_token(client_assertion).get('sub') != oidc4vc.get_payload_from_token(PoP).get('iss'):
                return Response(**manage_error('invalid_request', 'sub of client assertion does not match proof of possession iss', red, mode, request=request))
        except Exception:
            #https://www.ietf.org/archive/id/draft-ietf-oauth-attestation-based-client-auth-02.html    
            client_assertion = request.form.get('client_assertion').split("~")[0]
            logging.info('client _assertion = %s', client_assertion)
            if request.form.get('client_id') != oidc4vc.get_payload_from_token(client_assertion).get('sub'):
                return Response(**manage_error('invalid_request', 'client_id does not match client assertion subject', red, mode, request=request))
            PoP = request.form.get('client_assertion').split("~")[1]
            logging.info('client assertion PoP = %s', PoP)
            if oidc4vc.get_payload_from_token(client_assertion).get('sub') != oidc4vc.get_payload_from_token(PoP).get('iss'):
                return Response(**manage_error('invalid_request', 'sub of client assertion does not match proof of possession iss', red, mode, request=request))

    # check code validity
    try:
        data = json.loads(red.get(code).decode())
    except Exception:
        return Response(**manage_error('access_denied', 'Grant code expired', red, mode, request=request, status=404))
    stream_id = data['stream_id']
        
    # check PKCE
    if grant_type == 'authorization_code' and int(issuer_profile['oidc4vciDraft']) >= 10:
        code_verifier = request.form.get('code_verifier')
        code_challenge_calculated = pkce.get_code_challenge(code_verifier)
        if code_challenge_calculated != data['code_challenge']:
            return Response(**manage_error('access_denied', 'Code verifier is incorrect', red, mode, request=request, stream_id=stream_id, status=404))

    # check tx_code
    if data.get('user_pin_required') and not user_pin:
        return Response(**manage_error('invalid_request', 'User code is missing', red, mode, request=request, stream_id=stream_id))
    logging.info('user_pin = %s', data.get('user_pin'))
    if data.get('user_pin_required') and data.get('user_pin') not in [user_pin, str(user_pin)]:
        return Response(**manage_error('invalid_grant', 'User code is incorrect', red, mode, request=request, stream_id=stream_id, status=404))

    # token endpoint response
    access_token = str(uuid.uuid1())
    refresh_token = str(uuid.uuid1())
    vc = data.get('vc')
    endpoint_response = {
        'access_token': access_token,
        'token_type': 'bearer',
        'expires_in': ACCESS_TOKEN_LIFE,
        'refresh_token': refresh_token
    }
    if int(issuer_profile['oidc4vciDraft']) < 14 and issuer_id not in ['kivrsduinn']:
        endpoint_response['c_nonce'] = str(uuid.uuid1())
        endpoint_response['c_nonce_expires_in'] = 1704466725
        red.setex(endpoint_response['c_nonce'], 60, 'nonce')
        
    # authorization_details in case of multiple VC of the same type
    authorization_details = []
    if int(issuer_profile['oidc4vciDraft']) >= 13 and isinstance(vc, list):
        for vc_type in vc:
            types = vc_type['types']
            vc_list = vc_type['list']
            identifiers = [one_vc['identifier'] for one_vc in vc_list]
            authorization_details.append(
                {
                    'type': 'openid_credential',
                    'format': 'jwt_vc_json',
                    'credential_definition': {
                        'type': types
                    },
                    'credential_identifiers': identifiers,
                }
            )
        logging.info('token endpoint response with authorization details')
        endpoint_response['authorization_details'] = authorization_details

    access_token_data = {
        'expires_at': datetime.timestamp(datetime.now()) + ACCESS_TOKEN_LIFE,
        'c_nonce': endpoint_response.get('c_nonce'),
        'credential_type': data.get('credential_type'),
        'vc': data.get('vc'),
        'webhook': data.get('webhook'),
        'authorization_details': authorization_details,
        'stream_id': data.get('stream_id'),
        'issuer_state': data.get('issuer_state'),
        'client_id': request.form.get('client_id'),
        'scope': request.form.get('scope')
    }
    logging.info('token endpoint response = %s', json.dumps(endpoint_response, indent=4))
    red.setex(access_token, ACCESS_TOKEN_LIFE, json.dumps(access_token_data))
    headers = {'Cache-Control': 'no-store', 'Content-Type': 'application/json'}
    return Response(response=json.dumps(endpoint_response), headers=headers)