"""
NEW
https://issuer.walt.id/issuer-api/default/oidc
EBSI V2 https://openid.net/specs/openid-connect-4-verifiable-credential-issuance-1_0-05.html
support Authorization code flow and pre-authorized code flow of OIDC4VCI
"""
from flask import jsonify, request, render_template, Response, redirect, session
import json
from datetime import datetime, timedelta
import uuid
import logging
import didkit
from urllib.parse import urlencode
import db_api
import oidc4vc
from profile import profile
import pkce
import requests
import copy
from jwcrypto import jwk
import contextlib

logging.basicConfig(level=logging.INFO)

API_LIFE = 5000
ACCESS_TOKEN_LIFE = 10000
GRANT_LIFE = 5000
C_NONCE_LIFE = 5000
ACCEPTANCE_TOKEN_LIFE = 28 * 24 * 60 * 60


def init_app(app, red, mode):
    # endpoint for application if redirect to local page (test)
    app.add_url_rule(
        '/sandbox/ebsi/issuer/<issuer_id>/<stream_id>',
        view_func=oidc_issuer_landing_page,
        methods=['GET', 'POST'],
        defaults={'red': red, 'mode': mode},
    )
    app.add_url_rule(
        '/sandbox/ebsi/issuer_stream',
        view_func=oidc_issuer_stream,
        methods=['GET', 'POST'],
        defaults={'red': red},
    )
    app.add_url_rule(
        '/sandbox/ebsi/issuer_followup/<stream_id>',
        view_func=oidc_issuer_followup,
        methods=['GET'],
        defaults={'red': red},
    )
    # OIDC4VCI protocol with wallet
    app.add_url_rule('/issuer/<issuer_id>/.well-known/openid-credential-issuer', view_func=credential_issuer_openid_configuration_endpoint, methods=['GET'], defaults={'mode': mode})
    app.add_url_rule('/issuer/<issuer_id>/authorize', view_func=issuer_authorize, methods=['GET'], defaults={'red': red, 'mode': mode})
    app.add_url_rule('/issuer/<issuer_id>/authorize/par', view_func=issuer_authorize_par, methods=['POST'], defaults={'red': red})

    app.add_url_rule('/issuer/<issuer_id>/token', view_func=issuer_token, methods=['POST'], defaults={'red': red, 'mode': mode},)
    app.add_url_rule('/issuer/<issuer_id>/credential', view_func=issuer_credential, methods=['POST'], defaults={'red': red, 'mode': mode})
    app.add_url_rule('/issuer/<issuer_id>/deferred', view_func=issuer_deferred, methods=['POST'], defaults={'red': red, 'mode': mode},)
    app.add_url_rule('/issuer/<issuer_id>/.well-known/openid-configuration', view_func=authorization_server_openid_configuration, methods=['GET'], defaults={'mode': mode},)
    app.add_url_rule('/issuer/credential_offer_uri/<id>', view_func=issuer_credential_offer_uri, methods=['GET'], defaults={'red': red})
    app.add_url_rule('/issuer/error_uri', view_func=wallet_error_uri, methods=['GET'])
    app.add_url_rule('/issuer/<issuer_id>/.well-known/jwt-vc-issuer', view_func=openid_jwt_vc_issuer_configuration, methods=['GET'], defaults={'mode': mode})
    app.add_url_rule('/issuer/<issuer_id>/jwks', view_func=issuer_jwks, methods=['GET', 'POST'])

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


def manage_error(error, error_description, red, mode, request=None, stream_id=None, status=400):
    """
    Return error code to wallet and front channel
    https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-error-response
    """
    # console
    logging.warning('manage error = %s', error_description)

    # front channel
    if stream_id:
        front_publish(stream_id, red, error=error, error_description=error_description)

    # wallet
    payload = {
        'error': error,
        'error_description': error_description,
    }
    if request:
        payload['error_uri'] = error_uri_build(request, error, error_description, mode)

    headers = {'Cache-Control': 'no-store', 'Content-Type': 'application/json'}
    return {'response': json.dumps(payload), 'status': status, 'headers': headers}


# credential issuer openid configuration endpoint
def credential_issuer_openid_configuration_endpoint(issuer_id, mode):
    doc = credential_issuer_openid_configuration(issuer_id, mode)
    return jsonify(doc) if doc else (jsonify('Not found'), 404)


# for wallet
def credential_issuer_openid_configuration(issuer_id, mode):
    try:
        issuer_data = json.loads(db_api.read_oidc4vc_issuer(issuer_id))
        issuer_profile = profile[issuer_data['profile']]
    except Exception:
        logging.warning('issuer_id not found for %s', issuer_id)
        return

    # general section
    credential_issuer_openid_configuration = {
        'credential_issuer': mode.server + 'issuer/' + issuer_id,
        'credential_endpoint': mode.server + 'issuer/' + issuer_id + '/credential',
        'deferred_credential_endpoint': mode.server + 'issuer/' + issuer_id + '/deferred',
    }

    # Credentials supported section
    cs = issuer_profile.get('credentials_supported')
    if int(issuer_profile.get("oidc4vciDraft", "11")) >= 13:
        credential_issuer_openid_configuration.update({'credential_configurations_supported': cs})
    else:
        credential_issuer_openid_configuration.update({'credentials_supported': cs})

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

    # setup authorization server if needed
    if issuer_profile.get('authorization_server_support'):
        credential_issuer_openid_configuration['authorization_server'] = mode.server + 'issuer/' + issuer_id
    else:
        as_config = json.load(open('authorization_server_config.json'))
        as_config.update({
            'authorization_endpoint': mode.server + 'issuer/' + issuer_id + '/authorize',
            'token_endpoint': mode.server + 'issuer/' + issuer_id + '/token',
            'jwks_uri':  mode.server + 'issuer/' + issuer_id + '/jwks',
            'pushed_authorization_request_endpoint' : mode.server +'issuer/' + issuer_id + '/authorize/par' 
        })
        credential_issuer_openid_configuration.update(as_config)

    return credential_issuer_openid_configuration


# jwt vc issuer openid configuration
def openid_jwt_vc_issuer_configuration(issuer_id, mode):
    config = {
        'issuer': mode.server + 'issuer/' + issuer_id,
        'jwks_uri': mode.server + 'issuer/' + issuer_id + '/jwks'
    }
    return jsonify(config)


# authorization server endpoint
def authorization_server_openid_configuration(issuer_id, mode):
    return jsonify(as_openid_configuration(issuer_id, mode))


# authorization server configuration
def as_openid_configuration(issuer_id, mode):
    authorization_server_config = json.load(open('authorization_server_config.json'))
    config = {
        'authorization_endpoint': mode.server + 'issuer/' + issuer_id + '/authorize',
        'token_endpoint': mode.server + 'issuer/' + issuer_id + '/token',
        'jwks_uri':  mode.server + 'issuer/' + issuer_id + '/jwks',
        'pushed_authorization_request_endpoint' : mode.server +'issuer/' + issuer_id + '/authorize/par' 
    }
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
    pub_key['kid'] = thumbprint(pub_key)
    return jsonify({'keys': [pub_key]})


def build_credential_offer(issuer_id, credential_type, pre_authorized_code, issuer_state, user_pin_required, mode):
    issuer_data = json.loads(db_api.read_oidc4vc_issuer(issuer_id))
    issuer_profile = issuer_data['profile']
    profile_data = profile[issuer_profile]

    if profile_data['oidc4vciDraft'] == '8':
        #  https://openid.net/specs/openid-connect-4-verifiable-credential-issuance-1_0-05.html#name-pre-authorized-code-flow
        if len(credential_type) == 1:
            credential_type = credential_type[0]
        offer = {
            'issuer': f'{mode.server}issuer/{issuer_id}',
            'credential_type': credential_type,
        }
        if pre_authorized_code:
            offer['pre-authorized_code'] = pre_authorized_code
            if user_pin_required:
                offer['user_pin_required'] = True

    # OIDC4VCI standard with credentials as an array ofjson objects (EBSI-V3)
    elif int(profile_data['oidc4vciDraft']) <= 11 and profile_data['credentials_as_json_object_array']:
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

    elif profile_data['oidc4vciDraft'] in ['11', '12']:
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
            if user_pin_required:
                offer['grants'][
                    'urn:ietf:params:oauth:grant-type:pre-authorized_code'
                ].update({
                    "tx_code": {
                        "length": 4,
                        "input_mode": "numeric",
                        "description": "Please provide the one-time code which was sent via e-mail"
                    }
                })
        else:
            offer['grants'] = {'authorization_code': {'issuer_state': issuer_state}}
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
    credential_type = session_data['credential_type']
    pre_authorized_code = session_data['pre-authorized_code']
    user_pin_required = session_data['user_pin_required']
    issuer_state = session_data['issuer_state']
    offer = build_credential_offer(issuer_id, credential_type, pre_authorized_code, issuer_state,  user_pin_required, mode)

    issuer_data = json.loads(db_api.read_oidc4vc_issuer(issuer_id))
    data_profile = profile[issuer_data['profile']]
    # credential offer is passed by value
    if issuer_data.get('oidc4vciDraft', '11') == '8' or data_profile['oidc4vciDraft'] == '8':
        url_to_display = data_profile['oidc4vci_prefix'] + '?' + urlencode(offer)
        json_url = offer
    else:
        url_to_display = data_profile['oidc4vci_prefix'] + '?' + urlencode({'credential_offer': json.dumps(offer)})
        json_url = {'credential_offer': offer}

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

    qrcode_page = issuer_data.get('issuer_landing_page')
    logging.info('QR code page = %s', qrcode_page)
    return render_template(
        qrcode_page,
        openid_credential_configuration=json.dumps(credential_issuer_openid_configuration(issuer_id, mode), indent=4),
        openid_configuration=json.dumps(as_openid_configuration(issuer_id, mode), indent=4),
        url_data=json.dumps(json_url, indent=6),
        url=url_to_display,
        deeplink_altme=mode.deeplink_altme + 'app/download/oidc4vc?' + urlencode({'uri': url_to_display}),
        deeplink_talao=mode.deeplink_talao + 'app/download/oidc4vc?' + urlencode({'uri': url_to_display}),
        stream_id=stream_id,
        issuer_id=issuer_id,
        page_title=issuer_data['page_title'],
        page_subtitle=issuer_data['page_subtitle'],
        page_description=issuer_data['page_description'],
        title=issuer_data['title'],
        landing_page_url=issuer_data['landing_page_url'],
        issuer_state=request.args.get('issuer_state'),
    )


def authorization_error(error, error_description, stream_id, red, state):
    """
    https://www.rfc-editor.org/rfc/rfc6749.html#page-26
    """
    # front channel follow up
    front_publish(stream_id, red, error=error, error_description=error_description)
    resp = {
        'error_description': error_description,
        'error': error
    }
    if state:
        resp['state'] = state
    return urlencode(resp)


# pushed authorization endpoint endpoint
def issuer_authorize_par(issuer_id, red):
    try:
        request_uri_data = {
            "issuer_state": request.form.get('issuer_state'),
            "scope": request.form.get('scope'),
            "nonce": request.form.get('nonce'),
            "code_challenge": request.form.get('code_challenge'),
            "code_challenge_method": request.form.get('code_challenge_method'),
            "client_metadata": request.form.get('client_metadata'),
            "state": request.form.get('state'),
            "authorization_details": request.form.get('authorization_details')
        }
    except Exception:
        return jsonify({'error': 'access_denied'}), 403
    request_uri = "urn:ietf:params:oauth:request_uri:" + str(uuid.uuid1())
    red.setex(request_uri, 50, json.dumps(request_uri_data))
    endpoint_response ={
        "request_uri": request_uri,
        "expires_in": 50
    }
    headers = {
        "Cache-Control": "no-store",
        "Content-Type": "application/json"
    }
    return Response(response=json.dumps(endpoint_response), headers=headers)


# authorization code endpoint
def issuer_authorize(issuer_id, red, mode):
    if request_uri := request.args.get('request_uri'):
        try:
            request_uri_data = json.loads(red.get(request_uri).decode())
            redirect_uri = request_uri_data['redirect_uri']
        except:
             return jsonify({'error': 'invalid_request'}), 403
        try:
            issuer_state = request_uri_data.get('issuer_state')
            stream_id = json.loads(red.get(issuer_state).decode())['stream_id']
        except:
            return jsonify({'error': 'access_denied'}), 403
        try:
            response_type = request_uri_data['response_type']
        except Exception:
            return redirect(redirect_uri + '?' + authorization_error('invalid_request', 'Response type is missing', stream_id, red, state))
        scope = request_uri_data.get('scope')
        nonce = request_uri_data.get('nonce')
        code_challenge = request_uri_data.get('code_challenge')
        code_challenge_method = request_uri_data.get('code_challenge_method')
        client_metadata = request_uri_data.get('client_metadata')
        state = request_uri_data.get('state')
        authorization_details = request_uri_data.get('authorization_details')
    else:
        try:
            redirect_uri = request.args['redirect_uri']
        except Exception:
            return jsonify({'error': 'invalid_request'}), 403
        try:
            issuer_state = request.args['issuer_state']
            stream_id = json.loads(red.get(issuer_state).decode())['stream_id']
        except Exception:
            return jsonify({'error': 'access_denied'}), 403
        scope = request.args.get('scope')
        nonce = request.args.get('nonce')
        code_challenge = request.args.get('code_challenge')
        code_challenge_method = request.args.get('code_challenge_method')
        client_metadata = request.args.get('client_metadata')
        state = request.args.get('state')  # wallet state
        authorization_details = request.args.get('authorization_details')
        try:
            response_type = request.args['response_type']
        except Exception:
            return redirect(redirect_uri + '?' + authorization_error('invalid_request', 'Response type is missing', stream_id, red, state))
    try:
        client_id = request.args['client_id']  # client_id of the wallet
        logging.info('client_id of the wallet = %s', client_id)
    except Exception:
        return redirect(redirect_uri + '?' + authorization_error('invalid_request', 'Client id is missing', stream_id, red, state))

    logging.info('redirect_uri = %s', redirect_uri)
    logging.info('code_challenge = %s', code_challenge)
    logging.info('client_metadata = %s', client_metadata)
    logging.info('authorization details = %s', authorization_details)
    logging.info('scope = %s', scope)

    if response_type != 'code':
        return redirect(redirect_uri + '?' + authorization_error('invalid_response_type', 'response_type not supported', stream_id, red, state))

    issuer_data = json.loads(db_api.read_oidc4vc_issuer(issuer_id))

    offer_data = json.loads(red.get(issuer_state).decode())
    vc = offer_data['vc']
    credential_type = offer_data['credential_type']

    # Code creation
    issuer_data = json.loads(db_api.read_oidc4vc_issuer(issuer_id))
    if profile[issuer_data['profile']].get('pre-authorized_code_as_jwt'):
        code = oidc4vc.build_pre_authorized_code(
            issuer_data['jwk'],
            'https://self-issued.me/v2',
            mode.server + 'issuer/' + issuer_id,
            issuer_data['verification_method'],
            nonce,
        )
    else:
        code = str(uuid.uuid1()) + '.' + str(uuid.uuid1()) + '.' + str(uuid.uuid1())

    code_data = {
        'credential_type': credential_type,
        'client_id': client_id,
        'scope': scope,
        'authorization_details': authorization_details,
        'issuer_id': issuer_id,
        'issuer_state': issuer_state,
        'state': state,
        'stream_id': stream_id,
        'vc': vc,
        'code_challenge': code_challenge,
        'code_challenge_method': code_challenge_method,
    }
    red.setex(code, GRANT_LIFE, json.dumps(code_data))
    resp = {'code': code}
    if state:
        resp['state'] = state
    return redirect(redirect_uri + '?' + urlencode(resp))


# token endpoint
def issuer_token(issuer_id, red, mode):
    """
    https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-token-endpoint
    https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
    """
    logging.info('token endoint header %s', request.headers)
    logging.info('token endoint form %s', json.dumps(request.form, indent=4))
    issuer_data = json.loads(db_api.read_oidc4vc_issuer(issuer_id))
    issuer_profile = profile[issuer_data['profile']]

    # error response https://datatracker.ietf.org/doc/html/rfc6749#section-4.2.2.1
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
    else:
        return Response(**manage_error('invalid_request', 'Grant type not supported', red, mode, request=request))
    if not code:
        return Response(**manage_error('invalid_request', 'Request format is incorrect, code is missing', red, mode, request=request))
    if grant_type == 'authorization_code' and not request.form.get('redirect_uri'):
        return Response(**manage_error('invalid_request', 'Request format is incorrect, redirect_uri is missing', red, mode, request=request))


    # display client_authentication method
    if request.headers.get('Authorization'):
        client_authentication_method = 'client_secret_basic'
    elif request.form.get('client_id') and request.form.get('client_secret'):
        client_authentication_method = 'client_secret_post'
    elif request.form.get('client_id'):
        client_authentication_method = 'client_id'
    elif request.form.get('assertion') or request.form.get('client_assertion'):
        client_authentication_method = 'client_secret_jwt)'
    else:
        client_authentication_method = 'none'
    logging.info('client authentication method = %s', client_authentication_method)

    if issuer_profile in ["EBSI-V3", "DIIP"]:
        if not request.form.get('client_id'):
            return Response(**manage_error('invalid_request', 'Client incorrect authentication method', red, mode, request=request))
        if not request.form.get('client_id')[:3] != "did":
            return Response(**manage_error('invalid_request', 'Client incorrect authentication method', red, mode, request=request))

    # Code expired
    try:
        data = json.loads(red.get(code).decode())
    except Exception:
        return Response(**manage_error('access_denied', 'Grant code expired', red, mode, request=request, status=404))

    stream_id = data['stream_id']

    # check code verifier
    if grant_type == 'authorization_code' and int(issuer_profile['oidc4vciDraft']) >= 10:
        code_verifier = request.form.get('code_verifier')
        code_challenge_calculated = pkce.get_code_challenge(code_verifier)
        if code_challenge_calculated != data['code_challenge']:
            return Response(**manage_error('access_denied', 'Code verifier is incorrect', red, mode, request=request, stream_id=stream_id, status=404))

    # PIN code
    if data.get("user_pin_required") and not user_pin:
        return Response(**manage_error("invalid_request", "User pin is missing", red, mode, request=request, stream_id=stream_id))
    logging.info('user_pin = %s', data.get("user_pin"))
    if data.get("user_pin_required") and data.get("user_pin") != user_pin:
        return Response(**manage_error("access_denied", "User pin is incorrect", red, mode, request=request, stream_id=stream_id, status=404))

    # token endpoint response
    access_token = str(uuid.uuid1())
    refresh_token = str(uuid.uuid1())
    vc = data.get("vc")
    endpoint_response = {
        "access_token": access_token,
        "c_nonce": str(uuid.uuid1()),
        "token_type": "Bearer",
        "expires_in": ACCESS_TOKEN_LIFE,
        "c_nonce_expires_in": 1704466725,
        "refresh_token": refresh_token
    }
    if issuer_profile == "GAIN-POC":
        endpoint_response.update({
            "scope": None,
            "refresh_token": refresh_token
        })
    
    # authorization_details in case of multiple VC of the same type
    authorization_details = []
    if int(issuer_profile['oidc4vciDraft']) >= 12 and isinstance(vc, list):
        for vc_type in vc:
            types = vc_type["types"]
            vc_list = vc_type["list"]
            identifiers = [one_vc["identifier"] for one_vc in vc_list]
            authorization_details.append(
                {
                    "type": "openid_credential",
                    "format": "jwt_vc_json",
                    "credential_definition": {
                        "type": types
                    },
                    "credential_identifiers": identifiers,
                }
            )
        logging.info("token endpoint response with authorization details")
        endpoint_response["authorization_details"] = authorization_details

    access_token_data = {
        "expires_at": datetime.timestamp(datetime.now()) + ACCESS_TOKEN_LIFE,
        "c_nonce": endpoint_response.get("c_nonce"),
        "credential_type": data.get("credential_type"),
        "vc": data.get("vc"),
        "authorization_details": authorization_details,
        "stream_id": data.get("stream_id"),
        "issuer_state": data.get("issuer_state"),
        "client_id": request.form.get('client_id')
    }
    logging.info('token endpoint response = %s', json.dumps(endpoint_response, indent=4))
    red.setex(access_token, ACCESS_TOKEN_LIFE, json.dumps(access_token_data))
    headers = {"Cache-Control": "no-store", "Content-Type": "application/json"}
    return Response(response=json.dumps(endpoint_response), headers=headers)


# credential endpoint
async def issuer_credential(issuer_id, red, mode):
    """
    https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-endpoint

    """
    logging.info("credential endpoint request %s", json.dumps(request.json, indent=4))
    
    # Check access token
    try:
        access_token = request.headers["Authorization"].split()[1]
    except Exception:
        return Response(**manage_error("invalid_token", "Access token not passed in request header", red, mode, request=request))
    try:
        access_token_data = json.loads(red.get(access_token).decode())
    except Exception:
        return Response(**manage_error("invalid_token", "Access token expired", red, mode, request=request))

    # to manage followup screen
    stream_id = access_token_data.get("stream_id")
    
    # issuer profile
    issuer_data = json.loads(db_api.read_oidc4vc_issuer(issuer_id))
    issuer_profile = profile[issuer_data['profile']]
    logging.info('OIDC4VCI Draft = %s', issuer_profile['oidc4vciDraft'])

    # Check request format
    try:
        result = request.json
    except Exception:
        return Response(**manage_error("invalid_request", "Invalid request format", red, mode, request=request, stream_id=stream_id))

    # check vc format
    vc_format = result.get("format")
    logging.info("format in credential request = %s", vc_format)
    if vc_format and vc_format not in ["ldp_vc", "vc+sd-jwt", "jwt_vc_json", "jwt_vc_json-ld", "jwt_vc"]:
        return Response(**manage_error("unsupported_credential_format", "Invalid VC format : " + vc_format, red, mode, request=request, stream_id=stream_id))
    if int(issuer_profile['oidc4vciDraft']) >= 13:
        if result.get('format') == "vc+sd-jwt" and not result.get("vct"):
            return Response(**manage_error("invalid_request", "Invalid request format, vct is missing for vc+sd-jwt format", red, mode, request=request, stream_id=stream_id))

    # check types
    if int(issuer_profile['oidc4vciDraft']) < 13:
        if vc_format in ["ldp_vc", "jwt_vc_json", "jwt_vc_json-ld", "jwt_vc"] and not result.get('types') :
            return Response(**manage_error("unsupported_credential_format", "Invalid VC format, types is missing", red, mode, request=request, stream_id=stream_id))

    # check proof if it exists depending on type of proof
    proof = result.get("proof")
    if proof:
        proof_type = result["proof"]["proof_type"]
        if proof_type == 'jwt':
            proof = result["proof"]["jwt"]
            proof_header = oidc4vc.get_header_from_token(proof)
            proof_payload = oidc4vc.get_payload_from_token(proof)
            logging.info('Proof header = %s', json.dumps(proof_header, indent=4))
            logging.info('Proof payload = %s', json.dumps(proof_payload, indent=4))
            try:
                oidc4vc.verif_token(proof, access_token_data["c_nonce"])
                logging.info("proof is validated")
            except Exception as e:
                return Response(**manage_error("invalid_proof", "Proof of key ownership, signature verification error: " + str(e), red, mode, request=request, stream_id=stream_id))
            wallet_jwk = proof_header.get('jwk')  # GAIN POC
            if not wallet_jwk:  # Baseline profile with kid
                wallet_jwk = oidc4vc.resolve_did(proof_header.get('kid'))
            iss = proof_payload.get("iss")
            if access_token_data['client_id'] and iss != access_token_data['client_id']:
                return Response(**manage_error("invalid_proof", "iss of proof of key is different from client_id", red, mode, request=request, stream_id=stream_id))
        elif proof_type == 'ldp_vp':
            proof = result["proof"]["ldp_vp"]
            proof = json.dumps(proof) if isinstance(proof, dict) else proof
            proof_check = await didkit.verify_presentation(proof, '{}')
            iss = json.loads(proof)['holder']
            wallet_jwk = None
            logging.info("ldp_vp proof check  = %s", proof_check)
            if iss != access_token_data['client_id']:
                return Response(**manage_error("invalid_proof", "iss of proof of key is different from client_id in token request", red, mode, request=request, stream_id=stream_id))
        else:
            return Response(**manage_error("invalid_proof", "The credential proof type is not supported", red, mode, request=request, stream_id=stream_id))
    else:
        logging.warning('No proof available -> Bearer credential, iss = client_id')
        wallet_jwk = None
        if vc_format == 'ldp_vc':
            iss = None  # wallet_did
        else:
            iss = access_token_data['client_id']  # wallet_did
    logging.info("iss / wallet_did = %s", iss)

    # Get credential type requested
    credential_identifier = None
    credential_type = None
    if int(issuer_profile['oidc4vciDraft']) >= 13:
        credentials_supported = list(issuer_profile["credentials_supported"].keys())
        if vc_format == "vc+sd-jwt" and result.get('vct'):  # draft 13 with vc+sd-jwt"
            vct = result.get('vct')
            for vc in credentials_supported:
                if issuer_profile["credentials_supported"][vc]['vct'] == vct:
                    credential_type = vc
                    break
        else:
            vc_type = result['credential_definition'].get('type')
            vc_type.sort()
            for vc in credentials_supported:
                issuer_profile["credentials_supported"][vc]['credential_definition']['type'].sort()
                if issuer_profile["credentials_supported"][vc]['credential_definition']['type'] == vc_type:
                    credential_type = vc
                    break
        if not credential_type:
            return Response(**manage_error("invalid_request", "VC type not found", red, mode, request=request, stream_id=stream_id))
    elif int(issuer_profile['oidc4vciDraft']) == 12:
        if result.get("credential_identifier"):  # draft = 12
            credential_identifier = result.get("credential_identifier")
            logging.info("credential identifier = %s", credential_identifier)
        else:
            credentials_supported = issuer_profile["credentials_supported"]
            types = result.get('types')
            types.sort()
            for vc in credentials_supported:
                vc['types'].sort()
                if vc['types'] == types:
                    credential_type = vc['id']
                    break
            if not credential_type:
                return Response(**manage_error("invalid_request", "VC type not found", red, mode, request=request, stream_id=stream_id))
    elif int(issuer_profile['oidc4vciDraft']) == 11:
        credentials_supported = issuer_profile["credentials_supported"]
        if vc_format == "vc+sd-jwt" and result.get('vct'):  # draft 11 with vc+sd-jwt"
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
            return Response(**manage_error("invalid_request", "VC type not found", red, mode, request=request, stream_id=stream_id))
    elif int(issuer_profile['oidc4vciDraft']) < 11:
        for one_type in result["types"]:
            if one_type not in ["VerifiableCredential", "VerifiableAttestation"]:
                credential_type = one_type
                break
        if not credential_type:
            return Response(**manage_error("invalid_request", "VC type not found", red, mode, request=request, stream_id=stream_id))
    else:
        return Response(**manage_error("invalid_request", "Invalid request format", red, mode, request=request, stream_id=stream_id))
    logging.info("credential type = %s", credential_type)
    
    # deferred use case
    if issuer_data.get("deferred_flow"):
        deferred_random = str(uuid.uuid1())
        payload = {
            "c_nonce": str(uuid.uuid1()),
            "c_nonce_expires_in": ACCEPTANCE_TOKEN_LIFE,
        }
        if int(issuer_profile['oidc4vciDraft']) == 12:
            payload.update({"acceptance_token": deferred_random})
        elif int(issuer_profile['oidc4vciDraft']) > 12:
            payload.update({"transaction_id": deferred_random})
        else:
            return Response(**manage_error("invalid_request", "Deferred not supported", red, mode, request=request, stream_id=stream_id))
        deferred_data = {
            "issuer_id": issuer_id,
            "format": vc_format,
            "subjectId": iss,
            "issuer_state": access_token_data["issuer_state"],
            "credential_type": credential_type,
            "c_nonce": payload['c_nonce'],
            "c_nonce_expires_at": datetime.timestamp(datetime.now()) + ACCEPTANCE_TOKEN_LIFE,
        }
        red.setex(deferred_random, ACCEPTANCE_TOKEN_LIFE, json.dumps(deferred_data))
        headers = {"Cache-Control": "no-store", "Content-Type": "application/json"}
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

    # sign_credential(credential, wallet_did, issuer_did, issuer_key, issuer_vm, c_nonce, format, issuer, duration=365, wallet_jwk=None):
    credential_signed = await sign_credential(
        credential,
        iss,  # wallet_did
        issuer_id,
        access_token_data["c_nonce"],
        vc_format,
        mode.server + 'issuer/' + issuer_id,  # issuer
        wallet_jwk=wallet_jwk
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

    # update counter for issuance of verifiable id
    if issuer_id in ["vqzljjitre", "lbeuegiasm"]:
        data = {
            "vc": "verifiableid",
            "count": "1"
            }
        requests.post('https://issuer.talao.co/counter/update', data=data)

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
        acceptance_token = request.headers["Authorization"].split()[1]
    except Exception:
        return Response(**manage_error("invalid_request", "Acceptance token not passed in request header", red, mode, request=request))

    # Offer expired, VC is no more available return 410
    try:
        acceptance_token_data = json.loads(red.get(acceptance_token).decode())
    except Exception:
        return Response(**manage_error("invalid_token", "Acceptance token expired", red, mode, request=request, status=410))

    issuer_state = acceptance_token_data["issuer_state"]
    credential_type = acceptance_token_data["credential_type"]

    # VC is not ready return 404
    try:
        deferred_data = json.loads(red.get(issuer_state).decode())
        credential = deferred_data["deferred_vc"][credential_type]
    except Exception:
        return Response(**manage_error("issuance_pending", "Credential is not available yet", red, mode, request=request, status=404))

    # sign_credential
    credential_signed = await sign_credential(
        credential,
        acceptance_token_data["subjectId"],
        issuer_id,
        acceptance_token_data["c_nonce"],
        acceptance_token_data["format"],
        mode.server + 'issuer/' + issuer_id
    )
    if not credential_signed:
        return Response(**manage_error("internal_error", "Credential signature failed due to format", red, mode, request=request, status=404))

    logging.info("credential signed sent to wallet = %s", credential_signed)

    # delete deferred VC data
    red.delete(issuer_state)

    # Transfer VC
    payload = {
        "format": acceptance_token_data["format"],
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


async def sign_credential(credential, wallet_did, issuer_id, c_nonce, format, issuer, duration=365, wallet_jwk=None):
    issuer_data = json.loads(db_api.read_oidc4vc_issuer(issuer_id))
    issuer_did = issuer_data["did"]
    issuer_key = issuer_data["jwk"]
    issuer_vm = issuer_data["verification_method"]
    jti = 'urn:uuid:' + str(uuid.uuid1())
    if format == 'vc+sd-jwt':
        return oidc4vc.sign_sd_jwt(credential, issuer_key, issuer, wallet_jwk)
    elif format in ['ldp_vc', 'jwt_vc_json-ld']:
        if wallet_did:
            credential['credentialSubject']['id'] = wallet_did
        else:
            try:
                del credential['credentialSubject']['id']
            except Exception:
                pass
        credential["id"] = jti
        credential['issuer'] = issuer_did
        credential['issued'] = f"{datetime.now().replace(microsecond=0).isoformat()}Z"
        # credential['issuanceDate'] = datetime.now().replace(microsecond=0).isoformat() + "Z"
        credential['validFrom'] = datetime.now().replace(microsecond=0).isoformat() + "Z"
        # credential['expirationDate'] = (datetime.now() + timedelta(days=duration)).isoformat() + "Z"
        credential["validUntil"] = (datetime.now() + timedelta(days=duration)).isoformat() + "Z"
    elif format in ['jwt_vc_json', 'jwt_vc']:     # jwt_vc format is used for ebsi V3 only with draft 10
        credential = clean_jwt_vc_json(credential)
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
    vc['@context'] = ['https://www.w3.org/2018/credentials/v1']
    with contextlib.suppress(Exception):
        del vc['issuer']
        del vc['issued']
        del vc['id']
        del vc['issuanceDate']
        del vc['credentialSubject']['id']
        del vc['expirationDate']
        del vc['validFrom']
        del vc['validUntil']
        del vc['credentialStatus']
        del vc['credentialSchema']
    return vc
