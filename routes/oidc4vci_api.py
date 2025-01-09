"""
NEW
https://issuer.walt.id/issuer-api/default/oidc
EBSI V2 https://openid.net/specs/openid-connect-4-verifiable-credential-issuance-1_0-05.html
support Authorization code flow and pre-authorized code flow of OIDC4VCI
"""
import contextlib
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

import didkit

logging.basicConfig(level=logging.INFO)

API_LIFE = 5000
ACCESS_TOKEN_LIFE = 10000
GRANT_LIFE = 5000
C_NONCE_LIFE = 5000
ACCEPTANCE_TOKEN_LIFE = 28 * 24 * 60 * 60
STATUSLIST_ISSUER_KEY = json.dumps(json.load(open('keys.json', 'r'))['talao_Ed25519_private_key'])


def init_app(app, red, mode):
    # endpoint for application if redirect to local page (test)
    app.add_url_rule('/sandbox/ebsi/issuer/<issuer_id>/<stream_id>', view_func=oidc_issuer_landing_page, methods=['GET', 'POST'],defaults={'red': red, 'mode': mode})
    
    # endpoint for application to get the qrcode value
    app.add_url_rule('/sandbox/ebsi/issuer/qrcode/<issuer_id>/<stream_id>', view_func=oidc_issuer_qrcode_value, methods=['GET', 'POST'], defaults={'red': red, 'mode': mode})

    app.add_url_rule('/sandbox/ebsi/issuer_stream', view_func=oidc_issuer_stream, methods=['GET', 'POST'], defaults={'red': red})
    app.add_url_rule('/sandbox/ebsi/issuer_followup/<stream_id>', view_func=oidc_issuer_followup, methods=['GET'], defaults={'red': red})
    
    # OIDC4VCI protocol with wallet
    app.add_url_rule('/issuer/<issuer_id>/.well-known/openid-credential-issuer', view_func=credential_issuer_openid_configuration_endpoint, methods=['GET'], defaults={'mode': mode})
    
    # AS endpoint when issuer = AS
    app.add_url_rule('/issuer/<issuer_id>/.well-known/openid-configuration', view_func=openid_configuration, methods=['GET'], defaults={'mode': mode},)
    app.add_url_rule('/issuer/<issuer_id>/.well-known/oauth-authorization-server', view_func=oauth_authorization_server, methods=['GET'], defaults={'mode': mode},)
    
    app.add_url_rule('/issuer/<issuer_id>/authorize', view_func=issuer_authorize, methods=['GET'], defaults={'red': red, 'mode': mode})
    app.add_url_rule('/issuer/<issuer_id>/authorize/par', view_func=issuer_authorize_par, methods=['POST'], defaults={'red': red, 'mode':mode})
    app.add_url_rule('/issuer/<issuer_id>/token', view_func=issuer_token, methods=['POST'], defaults={'red': red, 'mode': mode},)
    
    # Issuer endpoint
    app.add_url_rule('/issuer/<issuer_id>/credential', view_func=issuer_credential, methods=['POST'], defaults={'red': red, 'mode': mode})
    app.add_url_rule('/issuer/<issuer_id>/deferred', view_func=issuer_deferred, methods=['POST'], defaults={'red': red, 'mode': mode},)
    app.add_url_rule('/issuer/credential_offer_uri/<id>', view_func=issuer_credential_offer_uri, methods=['GET'], defaults={'red': red})
    app.add_url_rule('/issuer/nonce', view_func=issuer_nonce, methods=['POST'], defaults={'red': red})

    # standalone AS metadata
    app.add_url_rule('/issuer/<issuer_id>/standalone/.well-known/oauth-authorization-server', view_func=standalone_oauth_authorization_server, methods=['GET'], defaults={'mode': mode},)
    
    
    app.add_url_rule('/issuer/error_uri', view_func=wallet_error_uri, methods=['GET'])
        
    # login with login/password authorization code flow
    app.add_url_rule('/issuer/<issuer_id>/authorize/login', view_func=issuer_authorize_login, methods=['GET', 'POST'], defaults={'red': red})
    # login with PID authorization code flow
    app.add_url_rule("/issuer/<issuer_id>/authorize/pid", view_func=issuer_authorize_pid, methods=['POST'], defaults={'red': red})

    # OIDC4VCI protocol with web wallet
    app.add_url_rule('/issuer/<issuer_id>/redirect', view_func=issuer_web_wallet_redirect, methods=['GET', 'POST'], defaults={'red': red, 'mode': mode})

    # keys for  sd-jwt vc
    app.add_url_rule('/.well-known/jwt-vc-issuer/issuer/<issuer_id>', view_func=openid_jwt_vc_issuer_configuration, methods=['GET'], defaults={'mode': mode})

    # keys for jwt_vc_json and jwt_vc_json-ld
    app.add_url_rule('/issuer/<issuer_id>/jwks', view_func=issuer_jwks, methods=['GET'])

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


# credential issuer openid configuration endpoint
def credential_issuer_openid_configuration_endpoint(issuer_id, mode):
    logging.info("Call credential issuer configuration endpoint")
    doc = credential_issuer_openid_configuration(issuer_id, mode)
    headers = {'Cache-Control': 'no-store', 'Content-Type': 'application/json'}
    return Response(response=json.dumps(doc), headers=headers)


# Credential issuer metadata
def credential_issuer_openid_configuration(issuer_id, mode):
    """
    /.well-known/openid-credential-issuer
    """
    try:
        issuer_data = json.loads(db_api.read_oidc4vc_issuer(issuer_id))
        issuer_profile = profile[issuer_data['profile']]
    except Exception:
        logging.warning('issuer_id not found for %s', issuer_id)
        return

    # general section
    credential_issuer_openid_configuration = {
        'credential_issuer': mode.server + 'issuer/' + issuer_id,
        "display": [
            {
                "name": "Talao issuer",
                "locale": "en-US",
                "logo": {
                    "uri": "https://talao.co/static/img/talao.png",
                    "alt_text": "Talao logo"
                }
            },
            {
                "name": "Talao issuer",
                "locale": "fr-FR",
                "logo": {
                    "uri": "https://talao.co/static/img/talao.png",
                    "alt_text": "Talao logo"
                }
            }
        ],
        'credential_endpoint': mode.server + 'issuer/' + issuer_id + '/credential',
        'deferred_credential_endpoint': mode.server + 'issuer/' + issuer_id + '/deferred',
    }
    
    # nonce endpoint to add for draft >= 14
    if int(issuer_profile.get("oidc4vciDraft")) >= 13: # TODO
        credential_issuer_openid_configuration['nonce_endpoint'] = mode.server + 'issuer/nonce'

    # setup authorization server attribute
    """
    the authorization server URL list is provided in the issuer metadata
    """    
    if issuer_profile.get('authorization_server_support') and int(issuer_profile["oidc4vciDraft"]) >= 13:
        if int(issuer_profile.get("oidc4vciDraft", "11")) >= 13:
            credential_issuer_openid_configuration['authorization_servers'] = [ mode.server + 'issuer/' + issuer_id + '/standalone', "https://fake.com/as"]
            credential_issuer_openid_configuration['jwks_uri'] = mode.server + 'issuer/' + issuer_id + '/jwks'
        else: # EBSI
            credential_issuer_openid_configuration['authorization_server'] = mode.server + 'issuer/' + issuer_id

    # Credentials supported section
    if int(issuer_profile.get("oidc4vciDraft", "11")) >= 13:
        credential_issuer_openid_configuration.update(
            {'credential_configurations_supported':  issuer_profile.get('credential_configurations_supported')}
        )
    else:
        credential_issuer_openid_configuration.update(
            {'credentials_supported': issuer_profile.get('credentials_supported')}
        )

    # setup credential manifest as optional 
    if issuer_profile.get('credential_manifest_support'):
        cm = []
        for _vc in issuer_profile.get('credentials_types_supported'):
            file_path = './credential_manifest/' + _vc + '_credential_manifest.json'
            try:
                cm_to_add = json.load(open(file_path))
                cm_to_add['issuer']['id'] = issuer_data.get('did', 'Unknown')
                cm_to_add['issuer']['name'] = issuer_data['application_name']
                cm.append(cm_to_add)
            except Exception:
                logging.warning('credential manifest not found for %s', _vc)
        credential_issuer_openid_configuration['credential_manifests'] = cm

    return credential_issuer_openid_configuration


# jwt vc issuer openid configuration
def openid_jwt_vc_issuer_configuration(issuer_id, mode):
    issuer_data = json.loads(db_api.read_oidc4vc_issuer(issuer_id))
    pub_key = copy.copy(json.loads(issuer_data['jwk']))
    del pub_key['d']
    pub_key['kid'] = pub_key.get('kid') if pub_key.get('kid') else thumbprint(pub_key)
    jwks = {'keys': [pub_key]}
    choice_bool = random.choice([True, False])
    if choice_bool:
        config = {
            'issuer': mode.server + 'issuer/' + issuer_id,
            'jwks': jwks
        }
    else:
        config = {
            'issuer': mode.server + 'issuer/' + issuer_id,
            'jwks_uri': mode.server + 'issuer/' + issuer_id + '/jwks'
        }
    logging.info("jwks for sd-jwt config = %s", config)
    return jsonify(config)


# /.well-known/openid-configuration endpoint  authorization server endpoint for draft 11 DEPRECATED
def openid_configuration(issuer_id, mode):
    logging.warning("Call to openid-configuration endpoint")
    headers = {'Cache-Control': 'no-store', 'Content-Type': 'application/json'}
    return Response(response=json.dumps(as_openid_configuration(issuer_id, mode)), headers=headers)    #return jsonify(as_openid_configuration(issuer_id, mode))


# /.well-known/oauth-authorization-server endpoint
def oauth_authorization_server(issuer_id, mode):
    issuer_data = json.loads(db_api.read_oidc4vc_issuer(issuer_id))
    issuer_profile = profile[issuer_data['profile']]
    if issuer_profile.get('authorization_server_support') and int(issuer_profile["oidc4vciDraft"]) >= 13:
        logging.error("CALL TO WRONG AUTHORIZATION SERVER")
    logging.info("Call to oauth-authorization-server endpoint")
    headers = {'Cache-Control': 'no-store', 'Content-Type': 'application/json'}
    return Response(response=json.dumps(as_openid_configuration(issuer_id, mode)), headers=headers)    #return jsonify(as_openid_configuration(issuer_id, mode))


# /standalone/.well-known/oauth-authorization-server endpoint
def standalone_oauth_authorization_server(issuer_id, mode):
    logging.info("Call to the standalone oauth-authorization-server endpoint")
    try:
        issuer_data = json.loads(db_api.read_oidc4vc_issuer(issuer_id))
    except Exception:
        logging.warning('issuer_id not found for %s', issuer_id)
        return
    headers = {'Cache-Control': 'no-store', 'Content-Type': 'application/json'}
    authorization_server_config = json.load(open('authorization_server_config.json'))
    config = {
        'issuer': mode.server + 'issuer/' + issuer_id +'/standalone',
        'authorization_endpoint': mode.server + 'issuer/' + issuer_id + '/standalone/authorize',
        'token_endpoint': mode.server + 'issuer/' + issuer_id + '/standalone/token',
        'jwks_uri':  mode.server + 'issuer/' + issuer_id + '/jwks',
        'pushed_authorization_request_endpoint': mode.server +'issuer/' + issuer_id + '/standalone/authorize/par' ,
        'pre-authorized_grant_anonymous_access_supported': True
    }
    if issuer_data['profile'] in ['HAIP', 'POTENTIAL']:
        config['require_pushed_authorization_requests'] = True
    config.update(authorization_server_config)
    config['issuer'] = mode.server + 'issuer/' + issuer_id + '/standalone'
    return Response(response=json.dumps(config), headers=headers)


# authorization server configuration 
def as_openid_configuration(issuer_id, mode):
    try:
        issuer_data = json.loads(db_api.read_oidc4vc_issuer(issuer_id))
    except Exception:
        logging.warning('issuer_id not found for %s', issuer_id)
        return
    authorization_server_config = json.load(open('authorization_server_config.json'))
    config = {
        'issuer': mode.server + 'issuer/' + issuer_id,
        'authorization_endpoint': mode.server + 'issuer/' + issuer_id + '/authorize',
        'token_endpoint': mode.server + 'issuer/' + issuer_id + '/token',
        'jwks_uri':  mode.server + 'issuer/' + issuer_id + '/jwks',
        'pushed_authorization_request_endpoint': mode.server +'issuer/' + issuer_id + '/authorize/par' ,
        'pre-authorized_grant_anonymous_access_supported': True
    }
    if issuer_data['profile'] in ['HAIP', 'POTENTIAL']:
        config['require_pushed_authorization_requests'] = True
    config.update(authorization_server_config)
    return config


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


def build_credential_offer(issuer_id, credential_type, pre_authorized_code, issuer_state, user_pin_required, tx_code_input_mode, tx_code_length, tx_code_description, mode):
    if not tx_code_input_mode:
        tx_code_input_mode = 'text'
    if not tx_code_length:
        tx_code_length = 4
    if not tx_code_description:
        tx_code_description = 'Please enter the secret code you received by email'
    issuer_data = json.loads(db_api.read_oidc4vc_issuer(issuer_id))
    issuer_profile = issuer_data['profile']
    profile_data = profile[issuer_profile]

    # OIDC4VCI standard with credentials as an array ofjson objects (EBSI-V3)
    if int(profile_data['oidc4vciDraft']) <= 11 and profile_data['credentials_as_json_object_array']:
        offer = {
            'credential_issuer': f'{mode.server}issuer/{issuer_id}',
            'credentials': [],
        }
        if pre_authorized_code:
            offer['grants'] = {
                'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
                    'pre-authorized_code': pre_authorized_code
                }
            }
            if user_pin_required:
                offer['grants'][
                    'urn:ietf:params:oauth:grant-type:pre-authorized_code'
                ].update({'user_pin_required': True})
        else:
            offer['grants'] = {'authorization_code': {'issuer_state': issuer_state}}

        for one_vc in credential_type:
            for supported_vc in profile_data['credentials_supported']:
                if one_vc in supported_vc['types']:
                    offer['credentials'].append(
                        {
                            'format': supported_vc['format'],
                            'types': supported_vc['types'],
                        }
                    )
                if supported_vc.get('trust_framework'):
                    offer['trust_framework'] = supported_vc['trust_framework']

    elif profile_data['oidc4vciDraft'] == '11':
        # https://openid.github.io/OpenID4VCI/openid-4-verifiable-credential-issuance-wg-draft.html
        offer = {
            'credential_issuer': f'{mode.server}issuer/{issuer_id}',
            'credentials': credential_type,
        }
        if pre_authorized_code:
            offer['grants'] = {
                'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
                    'pre-authorized_code': pre_authorized_code
                }
            }
            if user_pin_required:
                offer['grants'][
                    'urn:ietf:params:oauth:grant-type:pre-authorized_code'
                ].update({'user_pin_required': True})
        else:
            offer['grants'] = {'authorization_code': {'issuer_state': issuer_state}}

    else:  # Draft 13
        offer = {
            'credential_issuer': f'{mode.server}issuer/{issuer_id}',
            'credential_configuration_ids': credential_type,
        }
        if pre_authorized_code:
            offer['grants'] = {
                'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
                    'pre-authorized_code': pre_authorized_code
                }
            }
            if profile_data['authorization_server_support'] and int(profile_data["oidc4vciDraft"]) >= 13:
                offer['grants']['urn:ietf:params:oauth:grant-type:pre-authorized_code'].update({"authorization_server": mode.server + 'issuer/' + issuer_id + '/standalone'})
            if user_pin_required:
                offer['grants'][
                    'urn:ietf:params:oauth:grant-type:pre-authorized_code'
                ].update({
                    'tx_code': {
                        'length': tx_code_length,
                        'input_mode': tx_code_input_mode,
                        'description': tx_code_description
                    }
                })
        else:
            offer['grants'] = {'authorization_code': {'issuer_state': issuer_state}}
            if profile_data['authorization_server_support'] and int(profile_data["oidc4vciDraft"]) >= 13:
                offer['grants']['authorization_code'].update({"authorization_server": mode.server + 'issuer/' + issuer_id + '/standalone'})
    return offer


def issuer_credential_offer_uri(id, red):
    """
    credential_offer_uri endpoint
    return 201
    """
    try:
        offer = json.loads(red.get(id).decode())
    except Exception:
        logging.warning('session expired')
        return jsonify('Session expired'), 404
    return jsonify(offer), 201


# Display QRcode page for credential offer
def oidc_issuer_landing_page(issuer_id, stream_id, red, mode):
    session['stream_id'] = stream_id
    try:
        session_data = json.loads(red.get(stream_id).decode())
    except Exception:
        logging.warning('session expired')
        return jsonify('Session expired'), 404
    issuer_data = json.loads(db_api.read_oidc4vc_issuer(issuer_id))
    issuer_profile = issuer_data['profile']
    profile_data = profile[issuer_profile]
    
    credential_type = session_data['credential_type']
    pre_authorized_code = session_data['pre-authorized_code']
    user_pin_required = session_data['user_pin_required']
    input_mode = session_data.get('input_mode')
    input_length = session_data.get('input_length')
    input_description = session_data.get('input_description')
    issuer_state = session_data['issuer_state']
    offer = build_credential_offer(issuer_id, credential_type, pre_authorized_code, issuer_state,  user_pin_required, input_mode, input_length, input_description, mode)
    issuer_data = json.loads(db_api.read_oidc4vc_issuer(issuer_id))
    data_profile = profile[issuer_data['profile']]
    # credential offer is passed by value
    url_to_display = data_profile['oidc4vci_prefix'] + '?' + urlencode({'credential_offer': json.dumps(offer)})
    json_url = {'credential_offer': offer}
    logging.info("credential offer = %s", json.dumps(offer, indent=6))

    # credential offer is passed by reference: credential offer uri
    arg_for_web_wallet = ""
    if issuer_data.get('credential_offer_uri'):
        id = str(uuid.uuid1())
        credential_offer_uri = (
            f'{mode.server}issuer/credential_offer_uri/{id}'
        )
        red.setex(id, GRANT_LIFE, json.dumps(offer))
        logging.info('credential offer uri = %s', credential_offer_uri)
        url_to_display = (
            data_profile['oidc4vci_prefix']
            + '?credential_offer_uri='
            + urllib.parse.quote(credential_offer_uri, safe='')
        )
        arg_for_web_wallet = '?credential_offer_uri=' + credential_offer_uri
    else:
        arg_for_web_wallet = '?' + urlencode({'credential_offer': json.dumps(offer)})
    
    resp = requests.get(mode.server + 'issuer/' + issuer_id + '/.well-known/openid-credential-issuer', timeout=10)
    credential_issuer_configuration = resp.json()
    
    if profile_data['authorization_server_support'] and int(profile_data["oidc4vciDraft"]) >= 13:
        url_authorization_server = mode.server + 'issuer/' + issuer_id + '/standalone/.well-known/oauth-authorization-server'
    else:
        url_authorization_server = mode.server + 'issuer/' + issuer_id + '/.well-known/oauth-authorization-server'
    resp = requests.get(url_authorization_server, timeout=10)
    oauth_authorization_server = resp.json()
    
    resp = requests.get(mode.server + 'issuer/' + issuer_id + '/.well-known/openid-configuration', timeout=10)
    openid_configuration = resp.json()
    
    qrcode_page = issuer_data.get('issuer_landing_page')
    logging.info('QR code page file = %s', qrcode_page)
    return render_template(
        qrcode_page,
        openid_credential_configuration=json.dumps(credential_issuer_configuration, indent=4),
        openid_configuration=json.dumps(openid_configuration, indent=4),
        oauth_authorization_server= json.dumps(oauth_authorization_server, indent=4),
        url_data=json.dumps(json_url, indent=6),
        arg_for_web_wallet=arg_for_web_wallet,
        url=url_to_display,
        deeplink_altme=mode.deeplink_altme + 'app/download/oidc4vc?' + urlencode({'uri': url_to_display}),
        deeplink_talao=mode.deeplink_talao + 'app/download/oidc4vc?' + urlencode({'uri': url_to_display}),
        stream_id=stream_id,
        issuer_id=issuer_id,
        page_title=issuer_data['page_title'],
        page_subtitle=issuer_data['page_subtitle'],
        landing_page_url=issuer_data['landing_page_url'],
        issuer_state=request.args.get('issuer_state'),
    )


# Same as previous but Return QRcode value
def oidc_issuer_qrcode_value(issuer_id, stream_id, red, mode):
    try:
        session_data = json.loads(red.get(stream_id).decode())
    except Exception:
        logging.warning('session expired')
        return jsonify('Session expired'), 404
    credential_type = session_data['credential_type']
    pre_authorized_code = session_data['pre-authorized_code']
    user_pin_required = session_data['user_pin_required']
    issuer_state = session_data['issuer_state']
    input_mode = session_data.get('input_mode')
    input_length = session_data.get('input_length')
    input_description = session_data.get('input_description')
    offer = build_credential_offer(issuer_id, credential_type, pre_authorized_code, issuer_state,  user_pin_required, input_mode, input_length, input_description, mode)
    issuer_data = json.loads(db_api.read_oidc4vc_issuer(issuer_id))
    data_profile = profile[issuer_data['profile']]
    # credential offer is passed by value
    url_to_display = data_profile['oidc4vci_prefix'] + '?' + urlencode({'credential_offer': json.dumps(offer)})

    # credential offer is passed by reference: credential offer uri
    if issuer_data.get('credential_offer_uri'):
        id = str(uuid.uuid1())
        credential_offer_uri = (
            f'{mode.server}issuer/credential_offer_uri/{id}'
        )
        red.setex(id, GRANT_LIFE, json.dumps(offer))
        logging.info('credential offer uri = %s', credential_offer_uri)
        url_to_display = (
            data_profile['oidc4vci_prefix']
            + '?credential_offer_uri='
            + credential_offer_uri
        )        
    return jsonify({"qrcode_value": url_to_display})


def issuer_web_wallet_redirect(issuer_id, red, mode):
    arg_for_web_wallet = request.form['arg_for_web_wallet']
    web_wallet_url = request.form["web_wallet_url"]
    wallet_config_url = web_wallet_url + '/.well-known/openid-configuration'
    wallet_config = requests.get(wallet_config_url).json()
    wallet_credential_offer_endpoint = wallet_config.get('credential_offer_endpoint')
    if not wallet_credential_offer_endpoint:
        logging.error("wallet credential offer endpoint not found")
        return jsonify("wallet credential offer endpoint not found"), 400
    redirect_uri = wallet_credential_offer_endpoint + arg_for_web_wallet
    return redirect(redirect_uri)


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
def issuer_authorize_par(issuer_id, red, mode):
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
    
    # test if a standalone AS is used
    issuer_data = json.loads(db_api.read_oidc4vc_issuer(issuer_id))
    issuer_profile = profile[issuer_data['profile']]
    if issuer_profile.get('authorization_server_support') and int(issuer_profile["oidc4vciDraft"]) >= 13:
        return Response(**manage_error('invalid_request', 'invalid authorization server', red, mode, request=request))
    
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
def issuer_authorize_login(issuer_id, red):
    if request.method == 'GET':
        session['login'] = False
        session['test'] = False
        return render_template('issuer_oidc/authorize.html', url= '/issuer/' + issuer_id + '/authorize/login')
    if not red.get( request.form['test']):
        flash('Wrong test name', 'danger')
        #return redirect('/issuer/' + issuer_id + '/authorize/login') 
    session['login'] = True
    session['test'] = request.form['test']
    return redirect('/issuer/' + issuer_id + '/authorize?test=' + session['test']) 


# PID login for authorization code flow
def issuer_authorize_pid(issuer_id, red):
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
def issuer_authorize(issuer_id, red, mode):
    
    # test if a standalone AS is used
    issuer_data = json.loads(db_api.read_oidc4vc_issuer(issuer_id))
    issuer_profile = profile[issuer_data['profile']]
    if issuer_profile.get('authorization_server_support') and int(issuer_profile["oidc4vciDraft"]) >= 13:
        logging.error("wrong authorization endpoint used")
        return jsonify({
                    'error': 'invalid_request',
                    'error_description': 'invalid authorization server'
                }), 403
    
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
            return redirect('/issuer/' + issuer_id + '/authorize/login')
        
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
                "response_uri": mode.server + 'issuer/' + issuer_id + '/authorize/pid',
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


# nonce endpoint
def issuer_nonce(red):
    """
    https://openid.github.io/OpenID4VCI/openid-4-verifiable-credential-issuance-wg-draft.html#name-nonce-endpoint
    """
    nonce = str(uuid.uuid1())
    logging.info("Call of the nonce endpoint, nonce = %s", nonce)
    endpoint_response = {"c_nonce": nonce}
    red.setex(nonce, 60,'nonce')
    headers = {'Cache-Control': 'no-store', 'Content-Type': 'application/json'}
    return Response(response=json.dumps(endpoint_response), headers=headers)


# token endpoint
def issuer_token(issuer_id, red, mode):
    """
    token endpoint: https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
    DPoP: https://datatracker.ietf.org/doc/rfc9449/
    """
    logging.info('token endoint header %s', request.headers)
    logging.info('token endoint form %s', json.dumps(request.form, indent=4))
    issuer_data = json.loads(db_api.read_oidc4vc_issuer(issuer_id))
    issuer_profile = profile[issuer_data['profile']]
    
    # test if standalone AS is used
    if issuer_profile.get('authorization_server_support') and int(issuer_profile["oidc4vciDraft"]) >= 13:
        return Response(**manage_error('invalid_request', 'invalid token endpoint', red, mode, request=request))
    
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


# credential endpoint
async def issuer_credential(issuer_id, red, mode):
    logging.info('credential endoint header %s', request.headers)
    logging.info('credential endpoint request %s', json.dumps(request.json, indent=4))
    
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
        
    # Check access token
    try:
        access_token = request.headers['Authorization'].split()[1]
    except Exception:
        return Response(**manage_error('invalid_token', 'Access token not passed in request header', red, mode, request=request))
    try:
        access_token_data = json.loads(red.get(access_token).decode())
    except Exception:
        return Response(**manage_error('invalid_token', 'Access token expired', red, mode, request=request))

    # to manage followup screen
    stream_id = access_token_data.get('stream_id')
    
    # issuer profile
    issuer_data = json.loads(db_api.read_oidc4vc_issuer(issuer_id))
    issuer_profile = profile[issuer_data['profile']]
    logging.info('OIDC4VCI Draft = %s', issuer_profile['oidc4vciDraft'])

    # Check request format
    try:
        result = request.json
    except Exception:
        return Response(**manage_error('invalid_request', 'Invalid request format', red, mode, request=request, stream_id=stream_id))

    # check vc format
    vc_format = result.get('format')
    logging.info('format in credential request = %s', vc_format)
    if vc_format and vc_format not in ['ldp_vc', 'vc+sd-jwt', 'jwt_vc_json', 'jwt_vc_json-ld', 'jwt_vc']:
        return Response(**manage_error('unsupported_credential_format', 'Invalid VC format: ' + vc_format, red, mode, request=request, stream_id=stream_id))
    if int(issuer_profile['oidc4vciDraft']) >= 13:
        if result.get('format') == 'vc+sd-jwt' and not result.get('vct'):
            return Response(**manage_error('invalid_request', 'Invalid request format, vct is missing for vc+sd-jwt format', red, mode, request=request, stream_id=stream_id))
        elif result.get('format') in ['ldp_vc', 'jwt_vc_json-ld']:
            try:
                credential_definition = result['credential_definition']
                type = credential_definition['type'] # to check if it exists
                context = credential_definition['@context'] # to check if it exists
            except Exception:
                return Response(**manage_error('invalid_request', 'Invalid request format, type or @context is missing for ldp_vc or jwt_vc_json-ld', red, mode, request=request, stream_id=stream_id))
        elif result.get('format') == 'jwt_vc_json':
            try:
                credential_definition = result['credential_definition']
                type = credential_definition['type']  # to check if it exists
            except Exception:
                return Response(**manage_error('invalid_request', 'Invalid request format, type  is missing for jwt_vc_json', red, mode, request=request, stream_id=stream_id))

    # check types fo deprecated draft
    if int(issuer_profile['oidc4vciDraft']) < 13 and not result.get('types'):
        return Response(**manage_error('unsupported_credential_format', 'Invalid VC format, types is missing', red, mode, request=request, stream_id=stream_id))

    # check proof if it exists depending on type of proof
    if proof := result.get('proof'):
        proof_type = result['proof']['proof_type']
        if proof_type == 'jwt':
            proof = result['proof']['jwt']
            proof_header = oidc4vc.get_header_from_token(proof)
            proof_payload = oidc4vc.get_payload_from_token(proof)
            logging.info('Proof header = %s', json.dumps(proof_header, indent=4))
            logging.info('Proof payload = %s', json.dumps(proof_payload, indent=4))
            if not proof_payload.get('nonce'):
                return Response(**manage_error('invalid_proof', 'c_nonce is missing', red, mode, request=request, stream_id=stream_id, status=403))
            try:
                oidc4vc.verif_token(proof, 'nonce')
                logging.info('proof is validated')
            except Exception:
                logging.error('proof is not validated')
                #return Response(**manage_error('invalid_proof', 'Proof of key ownership, signature verification error: ' + str(e), red, mode, request=request, stream_id=stream_id, status=403))
            if not red.get(proof_payload['nonce']):
                logging.error('nonce does not exist')
            else:
                logging.info('nonce exists')
            
            if proof_header.get('jwk'):  # used for HAIP
                wallet_jwk = proof_header.get('jwk')
                wallet_identifier = "jwk_thumbprint"
            else:
                wallet_identifier = "did"
                wallet_jwk = oidc4vc.resolve_did(proof_header.get('kid'))

            wallet_did = access_token_data['client_id']
            if wallet_did and proof_payload.get('iss') and wallet_did != proof_payload.get('iss'):
                logging.warning('iss %s of proof of key is different from client_id %s', wallet_did ,access_token_data['client_id'] )
                return Response(**manage_error('invalid_proof', 'iss of proof of key is different from client_id', red, mode, request=request, stream_id=stream_id))
        
        elif proof_type == 'ldp_vp':
            wallet_identifier = "did"
            wallet_jwk = None
            proof = result['proof']['ldp_vp']
            proof = json.dumps(proof) if isinstance(proof, dict) else proof
            proof_check = await didkit.verify_presentation(proof, '{}')
            wallet_did = json.loads(proof).get('holder')
            logging.info('ldp_vp proof check  = %s', proof_check)
            if access_token_data['client_id'] and wallet_did and wallet_did != access_token_data['client_id']:
                logging.warning('iss %s of proof of key is different from client_id %s', wallet_did, access_token_data['client_id'] )
                return Response(**manage_error('invalid_proof', 'iss of proof of key is different from client_id in token request', red, mode, request=request, stream_id=stream_id))
        else:
            return Response(**manage_error('invalid_proof', 'Proof type not supported', red, mode, request=request, stream_id=stream_id))
    else:
        logging.warning('No proof available -> Bearer credential, wallet_did = client_id')
        wallet_jwk = None
        if vc_format == 'ldp_vc':
            wallet_did = None
        else:
            wallet_did = access_token_data['client_id']
        
    logging.info('wallet_did = %s', wallet_did)
    logging.info('wallet_identifier = %s', wallet_identifier)
    logging.info('wallet_jwk = %s', wallet_jwk)

    # Get credential type requested
    credential_identifier = None
    credential_type = None
    if int(issuer_profile['oidc4vciDraft']) >= 13:   # standard case
        credentials_supported = list(issuer_profile['credential_configurations_supported'].keys())
        if vc_format == 'vc+sd-jwt' and result.get('vct'):  # vc+sd-jwt'
            vct = result.get('vct')
            for vc in credentials_supported:
                if issuer_profile['credential_configurations_supported'][vc].get('vct') == vct:
                    credential_type = vc
                    break
        else:
            vc_type = result['credential_definition'].get('type')
            vc_type.sort()
            for vc in credentials_supported:
                issuer_profile['credential_configurations_supported'][vc]['credential_definition']['type'].sort()
                if issuer_profile['credential_configurations_supported'][vc]['credential_definition']['type'] == vc_type:
                    credential_type = vc
                    break
        if not credential_type:
            return Response(**manage_error('unsupported_credential_type', 'VC type not found', red, mode, request=request, stream_id=stream_id))
    
    elif int(issuer_profile['oidc4vciDraft']) == 11:
        credentials_supported = issuer_profile['credentials_supported']
        if vc_format == 'vc+sd-jwt' and result.get('vct'):  # draft 11 with vc+sd-jwt'
            vct = result.get('vct')
            for vc in credentials_supported:
                if vc['vct'] == vct:
                    credential_type = vc
                    break
        else:
            types = result.get('types')
            types.sort()
            for vc in credentials_supported:
                vc['types'].sort()
                if vc['types'] == types:
                    credential_type = vc['id']
                    break
        if not credential_type:
            return Response(**manage_error('unsupported_credential_type', 'VC type not found', red, mode, request=request, stream_id=stream_id))
    
    # EBSI V3
    elif int(issuer_profile['oidc4vciDraft']) < 11:
        for one_type in result.get('types'):
            if one_type not in ['VerifiableCredential', 'VerifiableAttestation']:
                credential_type = one_type
                break
        if not credential_type:
            return Response(**manage_error('unsupported_credential_type', 'VC type not found', red, mode, request=request, stream_id=stream_id))
    else:
        return Response(**manage_error('invalid_request', 'Invalid request format', red, mode, request=request, stream_id=stream_id))
    logging.info('credential type = %s', credential_type)
    
    # deferred use case
    if issuer_data.get('deferred_flow'):  # draft 13 only
        logging.info('Deferred flow')
        deferred_random = str(uuid.uuid1())
        payload = {
            'c_nonce': str(uuid.uuid1()),
            'c_nonce_expires_in': ACCEPTANCE_TOKEN_LIFE,
        }   
        payload.update({'transaction_id': deferred_random})
        deferred_data = {
            'issuer_id': issuer_id,
            'access_token': access_token,
            'format': vc_format,
            'subjectId': wallet_did,
            'issuer_state': access_token_data['issuer_state'],
            'credential_type': credential_type,
            'c_nonce': payload['c_nonce'],
            'c_nonce_expires_at': datetime.timestamp(datetime.now()) + ACCEPTANCE_TOKEN_LIFE,
        }
        red.setex(deferred_random, ACCEPTANCE_TOKEN_LIFE, json.dumps(deferred_data))
        headers = {'Cache-Control': 'no-store', 'Content-Type': 'application/json'}
        return Response(response=json.dumps(payload), headers=headers)

    # get credential to issue
    credential = None
    if credential_identifier:
        logging.info("Multiple VCs of the same type")
        for one_type in access_token_data["vc"]:
            for one_credential in one_type["list"]:
                if one_credential["identifier"] == credential_identifier:
                    vc_format = one_type["vc_format"]
                    credential = one_credential["value"]
                    logging.info("credential found for identifier = %s", credential_identifier)
                    break
    else:
        logging.info("Only one VC of the same type")
        try:
            credential = access_token_data["vc"][credential_type]
        except Exception:
            return Response(**manage_error("unsupported_credential_type", "The credential type is not offered", red, mode, request=request, stream_id=stream_id, ))
    if not credential:
        return Response(**manage_error("unsupported_credential_type", "Credential is not found for this credential identifier", red, mode, request=request, stream_id=stream_id,))

    # sign_credential(credential, wallet_did, issuer_id, c_nonce, format, issuer, mode, duration=365, wallet_jwk=None, wallet_identifier=None):
    credential_signed = await sign_credential(
        credential,
        wallet_did,
        issuer_id,
        access_token_data.get("c_nonce", "nonce"),
        vc_format,
        mode.server + 'issuer/' + issuer_id,  # issuer
        mode,
        wallet_jwk=wallet_jwk,
        wallet_identifier=wallet_identifier # "did" or 
    )
    logging.info("credential signed sent to wallet = %s", credential_signed)
    if not credential_signed:
        return Response(**manage_error("internal_error", "Credential signing error", red, mode, request=request, stream_id=stream_id,))

    # send event to front to go forward callback and send credential to wallet
    front_publish(access_token_data["stream_id"], red)

    # Transfer VC
    c_nonce = str(uuid.uuid1())
    payload = {
        "credential": credential_signed,  # string or json depending on the format
        "c_nonce": c_nonce,
        "c_nonce_expires_in": C_NONCE_LIFE,
    }
    
    if int(issuer_profile['oidc4vciDraft']) < 13:
        payload.update({"format": vc_format})

    # update nonce in access token for next VC request
    access_token_data["c_nonce"] = c_nonce
    red.setex(access_token, ACCESS_TOKEN_LIFE, json.dumps(access_token_data))

    # send event to webhook if it exists    
    if webhook := access_token_data['webhook']:
        data = {
                "event": "CREDENTIAL_SENT",
        }
        requests.post(webhook, json=data, timeout=10)
    
    # update counter for issuance of verifiable id
    if issuer_id in ["vqzljjitre", "lbeuegiasm"]:
        data = {
            "vc": "verifiableid",
            "count": "1"
            }
        requests.post('https://issuer.talao.co/counter/update', data=data, timeout=10)

    # send VC to wallet
    headers = {"Cache-Control": "no-store", "Content-Type": "application/json"}
    return Response(response=json.dumps(payload), headers=headers)


async def issuer_deferred(issuer_id, red, mode):
    """
    Deferred endpoint
    https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-deferred-credential-endpoin
    """
    logging.info("deferred endpoint request")

    # Check access token
    try:
        access_token = request.headers["Authorization"].split()[1]
    except Exception:
        return Response(**manage_error("invalid_request", "Access token not passed in request header", red, mode, request=request))
    try:
        transaction_id = request.json["transaction_id"]
    except Exception:
        return Response(**manage_error("invalid_request", "Transaction id not passed in request body", red, mode, request=request))


    # Offer expired, VC is no more available return 410
    try:
        transaction_id_data = json.loads(red.get(transaction_id).decode())
    except Exception:
        return Response(**manage_error("invalid_transaction_id", "Transaction data expired", red, mode, request=request, status=400))

    # check access token 
    if access_token != transaction_id_data.get("access_token"):
        return Response(**manage_error("invalid_request", "access token does not fit transaction_id", red, mode, request=request, status=410))

    issuer_state = transaction_id_data["issuer_state"]
    credential_type = transaction_id_data["credential_type"]

    # VC is not ready return 400, issuance_pending
    try:
        deferred_data = json.loads(red.get(issuer_state).decode())
        credential = deferred_data["deferred_vc"][credential_type]
    except Exception:
        payload = {
            'error': "issuance_pending",
            'interval': 30,
            'error_description': "Credential is not available yet",
        }
        logging.info('endpoint error response = %s', json.dumps(payload, indent=4))
        headers = {'Cache-Control': 'no-store', 'Content-Type': 'application/json'}
        return Response(response=json.dumps(payload), status=400, headers=headers)

    # sign_credential
    credential_signed = await sign_credential(
        credential,
        transaction_id_data["subjectId"],
        issuer_id,
        transaction_id_data["c_nonce"],
        transaction_id_data["format"],
        mode.server + 'issuer/' + issuer_id,
        mode
    )
    if not credential_signed:
        return Response(**manage_error("internal_error", "Credential signature failed due to format", red, mode, request=request, status=404))

    logging.info("credential signed sent to wallet = %s", credential_signed)

    # delete deferred VC data
    red.delete(issuer_state)

    # Transfer VC
    payload = {
        "format": transaction_id_data["format"],
        "credential": credential_signed,  # string or json depending on the format
        "c_nonce": str(uuid.uuid1()),
        "c_nonce_expires_in": C_NONCE_LIFE,
    }
    headers = {"Cache-Control": "no-store", "Content-Type": "application/json"}
    return Response(response=json.dumps(payload), headers=headers)


def oidc_issuer_followup(stream_id, red):
    try:
        user_data = json.loads(red.get(stream_id).decode())
    except Exception:
        return jsonify("Unauthorized"), 401
    callback = user_data["callback"]
    if not callback:
        issuer_id = user_data["issuer_id"]
        issuer_data = db_api.read_oidc4vc_issuer(issuer_id)
        callback = json.loads(issuer_data)["callback"]
    callback_uri = callback + '?'
    data = {"issuer_state": user_data.get("issuer_state")}
    if request.args.get("error"):
        data["error"] = request.args.get("error")
    if request.args.get("error_description"):
        data["error_description"] = request.args.get("error_description")
    logging.info('callback uri = %s', callback_uri + urlencode(data))
    return redirect(callback_uri + urlencode(data))


# server event push for user agent EventSource
def oidc_issuer_stream(red):
    def event_stream(red):
        pubsub = red.pubsub()
        pubsub.subscribe("issuer_oidc")
        for message in pubsub.listen():
            if message["type"] == "message":
                yield "data: %s\n\n" % message["data"].decode()

    headers = {
        "Content-Type": "text/event-stream",
        "Cache-Control": "no-cache",
        "X-Accel-Buffering": "no",
    }
    return Response(event_stream(red), headers=headers)


async def sign_credential(credential, wallet_did, issuer_id, c_nonce, format, issuer, mode, duration=365, wallet_jwk=None, wallet_identifier=None):
    issuer_data = json.loads(db_api.read_oidc4vc_issuer(issuer_id))
    issuer_did = issuer_data["did"]
    issuer_key = issuer_data["jwk"]
    issuer_vm = issuer_data["verification_method"]
    jti = 'urn:uuid:' + str(uuid.uuid1())
    
    if format == 'vc+sd-jwt':
        credential["status"] = {
            "status_list": {
                "idx": randint(0, 99999),
                "uri": mode.server + "issuer/statuslist/1"
            }
        }
        if issuer_id in ['raamxepqex', 'tdiwmpyhzc']:
            x5c = True
        else:
            x5c = False
        return oidc4vc.sign_sd_jwt(credential, issuer_key, issuer, wallet_jwk, wallet_did, wallet_identifier, x5c=x5c)
    elif format in ['ldp_vc', 'jwt_vc_json-ld']:
        logging.info("wallet did = %s", wallet_did)
        if wallet_did:
            credential['credentialSubject']['id'] = wallet_did
        else:
            try:
                del credential['credentialSubject']['id']
            except Exception:
                pass
        credential["id"] = jti
        try:
            credential['issuer']["id"] = issuer_did
        except Exception:
            credential['issuer'] = issuer_did
        credential['issuanceDate'] = datetime.now().replace(microsecond=0).isoformat() + "Z"
        credential['expirationDate'] = (datetime.now() + timedelta(days=duration)).isoformat() + "Z"
        
    elif format in ['jwt_vc_json', 'jwt_vc']:     # jwt_vc format is used for ebsi V3 only with draft 10/11
        credential = clean_jwt_vc_json(credential)
        index = str(randint(0, 99999))
        credential["credentialStatus"] = [{
            "id":  mode.server + "sandbox/issuer/bitstringstatuslist/1#" + index,
            "type": "BitstringStatusListEntry",
            "statusPurpose": "revocation",
            "statusListIndex": index,
            "statusListCredential":  mode.server + "sandbox/issuer/bitstringstatuslist/1"
        }]
    else:
        logging.error('credential format not supported %s', format)
        return
    logging.info("credential to sign = %s", credential)
    if format in ['jwt_vc', 'jwt_vc_json', 'jwt_vc_json-ld']:
        # sign_jwt_vc(vc, kid, issuer_key, nonce, iss, jti, sub)
        if issuer_data.get("issuer_id_as_url"):
            kid = oidc4vc.thumbprint_str(issuer_key)
            credential_signed = oidc4vc.sign_jwt_vc(credential, kid, issuer_key, c_nonce, issuer, jti, wallet_did)
        else:
            credential_signed = oidc4vc.sign_jwt_vc(credential, issuer_vm, issuer_key, c_nonce, issuer_did, jti, wallet_did)
    else:  # proof_format == 'ldp_vc':
        try:
            didkit_options = {
                "proofPurpose": "assertionMethod",
                "verificationMethod": issuer_vm,
            }
            credential_signed = await didkit.issue_credential(
                json.dumps(credential),
                didkit_options.__str__().replace("'", '"'),
                issuer_key,
            )
        except Exception as e:
            logging.warning("Didkit exception = %s", str(e))
            logging.warning('incorrect json_ld = %s', json.dumps(credential))
            return
        logging.info('VC signed with didkit')
        #result = await didkit.verify_credential(credential_signed, '{}')
        #logging.info('signature check with didkit = %s', result)
        credential_signed = json.loads(credential_signed)
    return credential_signed


def clean_jwt_vc_json(credential):
    vc = copy.copy(credential)
    # vc['@context'] = ['https://www.w3.org/2018/credentials/v1']
    with contextlib.suppress(Exception):
        del vc['@context']
        del vc['issuer']
        del vc['issued']
        del vc['id']
        del vc['issuanceDate']
        del vc['credentialSubject']['id']
        del vc['expirationDate']
        del vc['validFrom']
        del vc['validUntil']
        del vc['credentialStatus']
        #del vc['credentialSchema']
    return vc
