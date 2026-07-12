
from jwcrypto import jwk, jwt
import copy
import json
import logging
import random
import uuid
from datetime import datetime, timedelta
from profile import profile
from random import randint
from urllib.parse import urlencode, urlparse
import urllib
import db_api
import oidc4vc  # type: ignore
import pkce
import requests
from flask import (Response, flash, jsonify, redirect, render_template, request, session)
import didkit
import x509_attestation
import mdoc

logging.basicConfig(level=logging.INFO)

API_LIFE = 5000
ACCESS_TOKEN_LIFE = 10000
GRANT_LIFE = 5000
C_NONCE_LIFE = 5000
ACCEPTANCE_TOKEN_LIFE = 28 * 24 * 60 * 60
#STATUSLIST_ISSUER_KEY = json.dumps(json.load(open('keys.json', 'r'))['talao_Ed25519_private_key'])

def init_app(app, red, mode):
    # endpoint for application if redirect to local page (test)
    app.add_url_rule('/sandbox/ebsi/issuer/<issuer_id>/<stream_id>', view_func=oidc_issuer_landing_page, methods=['GET', 'POST'],defaults={'red': red, 'mode': mode})
    
    # endpoint for application to get the qrcode value
    app.add_url_rule('/sandbox/ebsi/issuer/qrcode/<issuer_id>/<stream_id>', view_func=oidc_issuer_qrcode_value, methods=['GET', 'POST'], defaults={'red': red, 'mode': mode})

    app.add_url_rule('/sandbox/ebsi/issuer_stream', view_func=oidc_issuer_stream, methods=['GET', 'POST'], defaults={'red': red})
    app.add_url_rule('/sandbox/ebsi/issuer_followup/<stream_id>', view_func=oidc_issuer_followup, methods=['GET'], defaults={'red': red})
    
    # OIDC4VCI protocol credential issuer metadata
    # Legacy route for wallets using the old discovery URL
    app.add_url_rule(
        "/issuer/<issuer_id>/.well-known/openid-credential-issuer",
        endpoint="credential_issuer_metadata_legacy",
        view_func=credential_issuer_openid_configuration_endpoint,
        methods=["GET"],
        defaults={"mode": mode},
    )

    # OIDC4VCI draft 16+ route
    app.add_url_rule(
        "/.well-known/openid-credential-issuer/issuer/<issuer_id>",
        endpoint="credential_issuer_metadata_current",
        view_func=credential_issuer_openid_configuration_endpoint,
        methods=["GET"],
        defaults={"mode": mode},
    )

    # AS endpoint when issuer = AS
    #app.add_url_rule('/issuer/<issuer_id>/.well-known/openid-configuration', view_func=openid_configuration, methods=['GET'], defaults={'mode': mode},)
    app.add_url_rule('/issuer/<issuer_id>/.well-known/openid-configuration', view_func=oauth_authorization_server, methods=['GET'], defaults={'mode': mode},)

    app.add_url_rule('/issuer/<issuer_id>/.well-known/oauth-authorization-server', view_func=oauth_authorization_server, methods=['GET'], defaults={'mode': mode},)
    app.add_url_rule('/.well-known/oauth-authorization-server/issuer/<issuer_id>', view_func=oauth_authorization_server, methods=['GET'], defaults={'mode': mode},)

    app.add_url_rule('/issuer/<issuer_id>/standalone/.well-known/oauth-authorization-server', view_func=standalone_oauth_authorization_server, methods=['GET'], defaults={'mode': mode},)
    app.add_url_rule('/.well-known/oauth-authorization-server/issuer/<issuer_id>/standalone', view_func=standalone_oauth_authorization_server, methods=['GET'], defaults={'mode': mode},)

    app.add_url_rule('/issuer/<issuer_id>/authorize', view_func=issuer_authorize, methods=['GET'], defaults={'red': red, 'mode': mode})
    app.add_url_rule('/issuer/<issuer_id>/authorize/par', view_func=issuer_authorize_par, methods=['POST'], defaults={'red': red, 'mode':mode})
    app.add_url_rule('/issuer/<issuer_id>/token', view_func=issuer_token, methods=['POST'], defaults={'red': red, 'mode': mode},)
    
    # Issuer endpoint
    app.add_url_rule('/issuer/<issuer_id>/credential', view_func=issuer_credential, methods=['POST'], defaults={'red': red, 'mode': mode})
    app.add_url_rule('/issuer/<issuer_id>/deferred', view_func=issuer_deferred, methods=['POST'], defaults={'red': red, 'mode': mode},)
    app.add_url_rule('/issuer/credential_offer_uri/<id>', view_func=issuer_credential_offer_uri, methods=['GET'], defaults={'red': red})
    app.add_url_rule('/issuer/nonce', view_func=issuer_nonce, methods=['POST'], defaults={'red': red})

    app.add_url_rule('/issuer/error_uri', view_func=wallet_error_uri, methods=['GET'])
        
    # login with login/password authorization code flow
    app.add_url_rule('/issuer/<issuer_id>/authorize/login', view_func=issuer_authorize_login, methods=['GET', 'POST'], defaults={'red': red})
    # login with PID authorization code flow
    app.add_url_rule('/issuer/<issuer_id>/authorize/pid', view_func=issuer_authorize_pid, methods=['POST'], defaults={'red': red})

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


def manage_error(error, error_description, red,  stream_id=None, status=400, webhook_data=None):
    """
    Return error code to wallet and front channel
    https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-error-response
    """
    # front channel
    if stream_id:
        front_publish(stream_id, red, error=error, error_description=error_description)
    
    if webhook_data and webhook_data.get("webhook_url"):
        json_data = {
            "event": "ERROR",
            "issuer_state": webhook_data.get("issuer_state")
        }
        try:
            requests.post(webhook_data.get("webhook_url"), json=json_data, timeout=10)
        except Exception:
            logging.exception("Webhook notification failed")

    # wallet
    payload = {
        'error': error,
        'error_description': error_description,
    }
    if error == 'invalid_proof':
        payload['c_nonce'] = str(uuid.uuid1())
        payload['c_nonce_expires_in'] = 86400
    
    logging.info('endpoint error response = %s', json.dumps(payload, indent=4))

    headers = {'Cache-Control': 'no-store', 'Content-Type': 'application/json'}
    return {'response': json.dumps(payload), 'status': status, 'headers': headers}


def build_signed_metadata(key, sub, metadata) -> str:
    """
    Sign OpenID4VCI signed metadata with the same private key
    as the mdoc Document Signer certificate.

    The `key` argument is kept for backward compatibility but
    is intentionally not used.
    """
    logging.info("Signed metadata are requested by the wallet")
    signer_key_dict = x509_attestation.SIGNER_KEY
    signer_key = jwk.JWK(**signer_key_dict)
    algorithm = x509_attestation.alg(
        signer_key_dict
    )

    public_key = signer_key.export(
        private_key=False,
        as_dict=True
    )

    public_key.pop("d", None)

    signer_kid = (
        public_key.get("kid")
        or thumbprint(public_key)
    )

    header = {
        "typ": "openidvci-issuer-metadata+jwt",
        "alg": algorithm,
        "kid": signer_kid,
        "x5c": x509_attestation.build_x509_san_dns(),
    }

    now = int(
        datetime.timestamp(datetime.now())
    )

    payload = {
        "iss": sub,
        "sub": sub,
        "iat": now,
    }

    payload.update(metadata)

    token = jwt.JWT(
        header=header,
        claims=payload,
        algs=[algorithm]
    )

    token.make_signed_token(
        signer_key
    )

    logging.info(
        "Signed metadata signed with mdoc signer kid = %s",
        signer_kid
    )

    return token.serialize()


def _credential_metadata_response_type() -> str:
    """
    Return application/jwt only when the client explicitly
    requests application/jwt.

    Accept: */* and missing Accept headers return JSON.
    """

    accept_header = request.headers.get(
        "Accept",
        ""
    ).strip()

    logging.info(
        "Credential Issuer Metadata Accept header = %s",
        accept_header or "<missing>"
    )

    if not accept_header:
        return "application/json"

    accepted_types = [
        item.strip().split(";", 1)[0].strip().lower()
        for item in accept_header.split(",")
    ]

    # A wildcard does not constitute an explicit request
    # for the signed JWT representation.
    if "application/jwt" not in accepted_types:
        return "application/json"

    jwt_quality = request.accept_mimetypes[
        "application/jwt"
    ]

    json_quality = request.accept_mimetypes[
        "application/json"
    ]

    if jwt_quality <= 0:
        return "application/json"

    # Return JWT when it is explicitly requested and is not
    # less preferred than JSON.
    if jwt_quality >= json_quality:
        return "application/jwt"

    return "application/json"

# credential issuer openid configuration endpoint
def credential_issuer_openid_configuration_endpoint(
    issuer_id,
    mode
):
    """
    Return Credential Issuer Metadata as:

    - application/json: unsigned JSON metadata;
    - application/jwt: signed metadata JWT.

    The representation is selected using the wallet's Accept
    header.
    """

    logging.info(
        "Call Credential Issuer Metadata endpoint: %s",
        request.url
    )

    logging.info(
        "Credential Issuer Metadata request headers: %s",
        dict(request.headers)
    )

    try:
        issuer_data = json.loads(
            db_api.read_oidc4vc_issuer(
                issuer_id
            )
        )

        issuer_profile = profile[
            issuer_data["profile"]
        ]

    except Exception:
        logging.exception(
            "Issuer configuration not found: %s",
            issuer_id
        )

        return Response(
            response=json.dumps({
                "error": "server_error",
                "error_description": (
                    "Credential Issuer configuration "
                    "was not found"
                ),
            }),
            status=500,
            headers={
                "Cache-Control": "no-store",
                "Content-Type": "application/json",
            },
        )

    metadata = (
        credential_issuer_openid_configuration(
            issuer_id,
            mode
        )
    )

    if not isinstance(metadata, dict):
        logging.error(
            "Credential Issuer Metadata is not "
            "a JSON object"
        )

        return Response(
            response=json.dumps({
                "error": "server_error",
                "error_description": (
                    "Credential Issuer Metadata "
                    "could not be generated"
                ),
            }),
            status=500,
            headers={
                "Cache-Control": "no-store",
                "Content-Type": "application/json",
            },
        )

    draft = int(
        issuer_profile.get(
            "oidc4vciDraft",
            13
        )
    )

    #
    # Validate the well-known URL for draft 16+.
    #
    if draft > 15:
        parsed_request_url = urlparse(
            request.url
        )

        expected_path = (
            "/.well-known/"
            "openid-credential-issuer/"
            "issuer/"
            + issuer_id
        )

        if parsed_request_url.path != expected_path:
            logging.warning(
                "Invalid Credential Issuer Metadata "
                "URL for draft %s: received=%s, "
                "expected=%s",
                draft,
                parsed_request_url.path,
                expected_path,
            )

    response_type = (
        _credential_metadata_response_type()
    )

    #
    # Signed representation.
    #
    if response_type == "application/jwt":
        credential_issuer_identifier = (
            metadata.get("credential_issuer")
        )

        if not credential_issuer_identifier:
            logging.error(
                "credential_issuer is missing "
                "from generated metadata"
            )

            return Response(
                response=json.dumps({
                    "error": "server_error",
                    "error_description": (
                        "credential_issuer is missing "
                        "from metadata"
                    ),
                }),
                status=500,
                headers={
                    "Cache-Control": "no-store",
                    "Content-Type": "application/json",
                },
            )

        try:
            signed_metadata = build_signed_metadata(
                issuer_data.get("jwk"),
                credential_issuer_identifier,
                metadata,
            )

        except Exception:
            logging.exception(
                "Signed Credential Issuer Metadata "
                "generation failed"
            )

            return Response(
                response=json.dumps({
                    "error": "server_error",
                    "error_description": (
                        "Signed Credential Issuer "
                        "Metadata generation failed"
                    ),
                }),
                status=500,
                headers={
                    "Cache-Control": "no-store",
                    "Content-Type": "application/json",
                },
            )

        logging.info(
            "Returning signed Credential Issuer "
            "Metadata as application/jwt"
        )

        return Response(
            response=signed_metadata,
            status=200,
            headers={
                "Cache-Control": "no-store",
                "Content-Type": "application/jwt",
                "Vary": "Accept",
            },
        )

    #
    # Mandatory unsigned JSON representation.
    #
    logging.info(
        "Returning unsigned Credential Issuer "
        "Metadata as application/json"
    )

    return Response(
        response=json.dumps(
            metadata,
            separators=(",", ":"),
        ),
        status=200,
        headers={
            "Cache-Control": "no-store",
            "Content-Type": "application/json",
            "Vary": "Accept",
        },
    )


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
        return {"error": "server_error"}

    # general section
    credential_issuer_configuration = {
        'credential_issuer': mode.server + 'issuer/' + issuer_id,
        'display': [
            {
                'name': 'Talao issuer',
                'locale': 'en-US',
                'logo': {
                    'uri': 'https://talao.co/static/img/talao.png',
                    'alt_text': 'Talao logo'
                }
            },
            {
                'name': 'Talao issuer',
                'locale': 'fr-FR',
                'logo': {
                    'uri': 'https://talao.co/static/img/talao.png',
                    'alt_text': 'Talao logo'
                }
            }
        ],
        'authorization_servers': [mode.server + 'issuer/' + issuer_id ],
        'credential_endpoint': mode.server + 'issuer/' + issuer_id + '/credential',
        'deferred_credential_endpoint': mode.server + 'issuer/' + issuer_id + '/deferred',
        "dpop_signing_alg_values_supported": [
            "ES256",
            "ES384",
            "ES512"
        ],
    }
    
    # nonce endpoint to add for draft >= 14
    if int(issuer_profile.get('oidc4vciDraft')) >= 13: # TODO
        credential_issuer_configuration['nonce_endpoint'] = mode.server + 'issuer/nonce'

    # setup authorization server attribute
    # the authorization server URL list is provided in the issuer metadata
    
    if issuer_profile.get('authorization_server_support') and int(issuer_profile['oidc4vciDraft']) >= 13:
        if int(issuer_profile.get('oidc4vciDraft', '11')) >= 13:
            credential_issuer_configuration['authorization_servers'] = [ mode.server + 'issuer/' + issuer_id + '/standalone', 'https://fake.com/as']
            credential_issuer_configuration['jwks_uri'] = mode.server + 'issuer/' + issuer_id + '/jwks'
        else: # EBSI
            credential_issuer_configuration['authorization_server'] = mode.server + 'issuer/' + issuer_id

    # Credentials supported section
    if int(issuer_profile.get('oidc4vciDraft', '11')) >= 13:
        credential_configurations = copy.deepcopy(
            issuer_profile.get('credential_configurations_supported', {})
        )

        credential_issuer_configuration[
            'credential_configurations_supported'
        ] = credential_configurations
    else:
        credential_issuer_configuration.update(
            {'credentials_supported': issuer_profile.get('credentials_supported')}
        )

    return credential_issuer_configuration


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
    logging.info('jwks for sd-jwt config = %s', config)
    return jsonify(config)


# /.well-known/openid-configuration endpoint  authorization server endpoint for draft 11 DEPRECATED
def openid_configuration(issuer_id, mode):
    logging.warning('Call to openid-configuration endpoint')
    issuer_data = json.loads(db_api.read_oidc4vc_issuer(issuer_id))
    issuer_profile = profile[issuer_data['profile']]
    if int(issuer_profile['oidc4vciDraft']) >= 13:
        logging.error('CALL TO WRONG ENDPOINT')
        message = {'error': 'access_denied', 'error_description': 'invalid endpoint'}
        return jsonify(message), 404
    headers = {'Cache-Control': 'no-store', 'Content-Type': 'application/json'}
    return Response(response=json.dumps(as_openid_configuration(issuer_id, mode)), headers=headers)    #return jsonify(as_openid_configuration(issuer_id, mode))


# /.well-known/oauth-authorization-server endpoint
def oauth_authorization_server(issuer_id, mode):
    issuer_data = json.loads(db_api.read_oidc4vc_issuer(issuer_id))
    issuer_profile = profile[issuer_data['profile']]
    headers = {'Cache-Control': 'no-store', 'Content-Type': 'application/json'}
    if issuer_profile.get('authorization_server_support') and int(issuer_profile['oidc4vciDraft']) >= 13:
        logging.error('CALL TO WRONG AUTHORIZATION SERVER')
        message = {'error': 'access_denied', 'error_description': 'invalid authorization server'}
        return jsonify(message), 404
    logging.info('Call to oauth-authorization-server endpoint')
    return Response(response=json.dumps(as_openid_configuration(issuer_id, mode)), headers=headers)    #return jsonify(as_openid_configuration(issuer_id, mode))


# /standalone/.well-known/oauth-authorization-server endpoint
def standalone_oauth_authorization_server(issuer_id, mode):
    logging.info('Call to the standalone oauth-authorization-server endpoint')
    issuer_data = json.loads(db_api.read_oidc4vc_issuer(issuer_id))
    issuer_profile = profile[issuer_data['profile']]
    if not issuer_profile.get('authorization_server_support'):
        logging.error('CALL TO WRONG AUTHORIZATION SERVER')
        message = {'error': 'access_denied', 'error_description': 'invalid authorization server'}
        return jsonify(message), 404
    headers = {'Cache-Control': 'no-store', 'Content-Type': 'application/json'}
    authorization_server_config = json.load(open('authorization_server_config.json'))
    config = {
        'issuer': mode.server + 'issuer/' + issuer_id + '/standalone',
        'authorization_endpoint': mode.server + 'issuer/' + issuer_id + '/standalone/authorize',
        'token_endpoint': mode.server + 'issuer/' + issuer_id + '/standalone/token',
        'jwks_uri':  mode.server + 'issuer/' + issuer_id + '/jwks',
        'pushed_authorization_request_endpoint': mode.server + 'issuer/' + issuer_id + '/standalone/authorize/par' ,
        'pre-authorized_grant_anonymous_access_supported': True
    }
    if issuer_data['profile'] in ['HAIP', 'POTENTIAL']:
        config['require_pushed_authorization_requests'] = True
    config.update(authorization_server_config)
    return Response(response=json.dumps(config), headers=headers)


# authorization server configuration 
def as_openid_configuration(issuer_id, mode):
    issuer_data = json.loads(db_api.read_oidc4vc_issuer(issuer_id))
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
    if isinstance(key, str):
        key = json.loads(key)
    signer_key = jwk.JWK(**key)
    return signer_key.thumbprint()


# jwks endpoint
def issuer_jwks(issuer_id):
    issuer_data = json.loads(
        db_api.read_oidc4vc_issuer(issuer_id)
    )

    issuer_public_key = copy.copy(
        json.loads(issuer_data["jwk"])
    )

    issuer_public_key.pop("d", None)

    issuer_public_key["kid"] = (
        issuer_public_key.get("kid")
        or thumbprint(issuer_public_key)
    )

    mdoc_public_key = jwk.JWK(
        **x509_attestation.SIGNER_KEY
    ).export(
        private_key=False,
        as_dict=True
    )

    mdoc_public_key.pop("d", None)

    mdoc_public_key["kid"] = (
        mdoc_public_key.get("kid")
        or thumbprint(mdoc_public_key)
    )
    jwks = {
        "keys": [
            issuer_public_key,
            mdoc_public_key
        ]
    }
    logging.info(
        "issuer jwks = %s",
        jwks
    )
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
            if profile_data['authorization_server_support'] and int(profile_data['oidc4vciDraft']) >= 13:
                offer['grants']['urn:ietf:params:oauth:grant-type:pre-authorized_code'].update({'authorization_server': mode.server + 'issuer/' + issuer_id + '/standalone'})
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
            if profile_data['authorization_server_support'] and int(profile_data['oidc4vciDraft']) >= 13:
                offer['grants']['authorization_code'].update({'authorization_server': mode.server + 'issuer/' + issuer_id + '/standalone'})
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
    return jsonify(offer), 200


# Display QRcode page for credential offer
def oidc_issuer_landing_page(issuer_id, stream_id, red, mode):
    session['stream_id'] = stream_id
    try:
        session_data = json.loads(red.get(stream_id).decode())
        issuer_data = json.loads(db_api.read_oidc4vc_issuer(issuer_id))
    except Exception:
        logging.error('session expired')
        return jsonify('Session expired'), 404
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
    logging.info('credential offer = %s', json.dumps(offer, indent=6))

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
        arg_for_web_wallet = urlencode({'credential_offer_uri': credential_offer_uri})
    else:
        arg_for_web_wallet = urlencode({'credential_offer': json.dumps(offer)})
            
    resp = requests.get(mode.server + 'issuer/' + issuer_id + '/.well-known/openid-credential-issuer', timeout=10)
    credential_issuer_configuration = resp.json()
    
    if profile_data['authorization_server_support'] and int(profile_data['oidc4vciDraft']) >= 13:
        url_authorization_server = mode.server + 'issuer/' + issuer_id + '/standalone/.well-known/oauth-authorization-server'
    else:
        url_authorization_server = mode.server + 'issuer/' + issuer_id + '/.well-known/oauth-authorization-server'
    resp = requests.get(url_authorization_server, timeout=10)
    oauth_authorization_server = resp.json()
    
    resp = requests.get(mode.server + 'issuer/' + issuer_id + '/.well-known/openid-configuration', timeout=10)
    this_openid_configuration = resp.json()
    
    deeplink_talao = 'talao-openid-credential-offer://?' + urlencode({'credential_offer': json.dumps(offer)})
    deeplink_altme = 'altme-openid-credential-offer://?' + urlencode({'credential_offer': json.dumps(offer)})
    
    deeplink_standard = 'openid-credential-offer://?' + urlencode({'credential_offer': json.dumps(offer)})
    
    qrcode_page = issuer_data.get('issuer_landing_page')
    logging.info('QR code page file = %s', qrcode_page)
    return render_template(
        qrcode_page,
        openid_credential_configuration=json.dumps(credential_issuer_configuration, indent=4),
        openid_configuration=json.dumps(this_openid_configuration, indent=4),
        oauth_authorization_server=json.dumps(oauth_authorization_server, indent=4),
        url_data=json.dumps(json_url, indent=6),
        arg_for_web_wallet=arg_for_web_wallet,
        url=url_to_display,
        deeplink_altme=deeplink_altme,
        deeplink_talao=deeplink_talao,
        deeplink_standard=deeplink_standard,
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
        offer_id = str(uuid.uuid1())
        credential_offer_uri = (
            f'{mode.server}issuer/credential_offer_uri/{offer_id}'
        )
        red.setex(offer_id, GRANT_LIFE, json.dumps(offer))
        logging.info('credential offer uri = %s', credential_offer_uri)
        url_to_display = (
            data_profile['oidc4vci_prefix']
            + '?credential_offer_uri='
            + credential_offer_uri
        )        
    return jsonify({'qrcode_value': url_to_display})


# Issuer sends the offer to the web wallet credential offer endpoint
def issuer_web_wallet_redirect(issuer_id, red, mode):
    arg_for_web_wallet = request.args['arg_for_web_wallet']
    web_wallet_url = request.args['web_wallet_url'].rstrip("/")
    
    try:
        wallet_config_url = web_wallet_url + '/.well-known/openid-configuration'
        wallet_config = requests.get(wallet_config_url, timeout=10).json()
        wallet_credential_offer_endpoint = wallet_config.get('credential_offer_endpoint') or web_wallet_url
    except Exception:
        wallet_credential_offer_endpoint = web_wallet_url
    
    redirect_uri = wallet_credential_offer_endpoint + "?" + arg_for_web_wallet
    logging.info("redirect_uri to web wallet = %s", redirect_uri)
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
        return urlencode(resp)
    
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
            return Response(**manage_error('invalid_request', 'DPoP is incorrect ' + str(e), red))
    else:
        logging.info('No DPoP')
        
    try:
        issuer_data = json.loads(db_api.read_oidc4vc_issuer(issuer_id))
    except Exception:
        logging.warning('issuer_id not found for %s', issuer_id)
        return
    if issuer_data['profile'] in ['HAIP']:
        if not request.form.get('client_assertion_type') and not request.headers.get('Oauth-Client-Attestation'):
            logging.warning('HAIP mandates client assertion authentication')
    
    # test if a standalone AS is used
    issuer_data = json.loads(db_api.read_oidc4vc_issuer(issuer_id))
    issuer_profile = profile[issuer_data['profile']]
    if issuer_profile.get('authorization_server_support') and int(issuer_profile['oidc4vciDraft']) >= 13:
        return Response(**manage_error('invalid_request', 'invalid authorization server', red))
    
    # Check content of client assertion and proof of possession (DPoP)
    client_assertion = None
    client_assertion_pop = None
    effective_client_id = request.form.get("client_id")
    # Legacy format:
    # client_assertion=<attestation>~<proof_of_possession>
    if request.form.get("client_assertion"):
        combined_assertion = request.form.get("client_assertion")

        try:
            client_assertion, client_assertion_pop = combined_assertion.split("~", 1)
        except ValueError:
            return Response(**manage_error(
                "invalid_client",
                "Client assertion proof of possession is missing",
                red
            ))

        logging.info(
            "Client assertion received in form parameter = %s",
            client_assertion
        )
        logging.info(
            "Client assertion proof of possession = %s",
            client_assertion_pop
        )

    # OAuth Client Attestation headers
    elif request.headers.get("Oauth-Client-Attestation"):
        client_assertion = request.headers.get(
            "Oauth-Client-Attestation"
        )
        client_assertion_pop = request.headers.get(
            "Oauth-Client-Attestation-Pop"
        )

        logging.info(
            "OAuth-Client-Attestation = %s",
            client_assertion
        )
        logging.info(
            "OAuth-Client-Attestation-PoP = %s",
            client_assertion_pop
        )

        if not client_assertion_pop:
            return Response(**manage_error(
                "invalid_client",
                "OAuth-Client-Attestation-PoP header is missing",
                red
            ))

    else:
        logging.warning(
            "No client assertion or OAuth Client Attestation"
        )

    if client_assertion:
        try:
            client_assertion_payload = (
                oidc4vc.get_payload_from_token(client_assertion)
            )
            client_assertion_pop_payload = (
                oidc4vc.get_payload_from_token(client_assertion_pop)
            )
        except ValueError as error:
            return Response(**manage_error(
                "invalid_client",
                "Invalid Client Attestation: " + str(error),
                red
            ))

        attestation_subject = client_assertion_payload.get("sub")

        if not attestation_subject:
            return Response(**manage_error(
                "invalid_client",
                "Client Attestation subject is missing",
                red
            ))

        # client_id is optional in an anonymous pre-authorized flow.
        # When it is present, it must match the attestation subject.
        if (
            effective_client_id is not None
            and effective_client_id != attestation_subject
        ):
            return Response(**manage_error(
                "invalid_client",
                "client_id does not match Client Attestation subject",
                red
            ))

        pop_issuer = client_assertion_pop_payload.get("iss")

        if pop_issuer != attestation_subject:
            return Response(**manage_error(
                "invalid_client",
                "Client Attestation subject does not match "
                "proof of possession issuer",
                red
            ))

        # When client_id is absent, use the attested subject as the
        # effective client identifier.
        effective_client_id = (
            effective_client_id or attestation_subject
        )

        logging.info(
            "Effective client_id = %s",
            effective_client_id
        )
        
    try:
        request_uri_data = {
            'redirect_uri': request.form['redirect_uri'],
            'client_id': request.form['client_id'],
            'response_type': request.form['response_type'],
            'scope': request.form['scope'],
            'issuer_state': request.form.get('issuer_state'),
        }
    except Exception:
        return Response(**manage_error('invalid_request', 'Request format is incorrect', red,  ))
    
    request_uri_data.update({
        'nonce': request.form.get('nonce'),
        'code_challenge': request.form.get('code_challenge'),
        'code_challenge_method': request.form.get('code_challenge_method'),
        'client_metadata': request.form.get('client_metadata'),
        'wallet_issuer': request.form.get('wallet_issuer'),
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


# IDP login for authorization code flow for testing purpose only
def issuer_authorize_login(issuer_id, red):
    if request.method == 'GET':
        session['login'] = False
        session['test'] = False
        return render_template('issuer_oidc/authorize.html', url = '/issuer/' + issuer_id + '/authorize/login')
    if not red.get(request.form['test']):
        flash('Wrong test name', 'danger')
        #return redirect('/issuer/' + issuer_id + '/authorize/login') 
    session['login'] = True
    session['test'] = request.form['test']
    return redirect('/issuer/' + issuer_id + '/authorize?test=' + session['test']) 


# PID login for authorization code flow for testing purpose only
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
    if issuer_profile.get('authorization_server_support') and int(issuer_profile['oidc4vciDraft']) >= 13:
        logging.error('wrong authorization endpoint used')
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
        if request_uri := request.args.get('request_uri'):
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
        if issuer_state != 'pid_authentication':
            return redirect('/issuer/' + issuer_id + '/authorize/login')
        
        # redirect user to VP request to get a PID
        else:
            # fetch credential.
            issuer_data = json.loads(db_api.read_oidc4vc_issuer(issuer_id))
            issuer_profile = profile[issuer_data['profile']]
            vc_list = issuer_profile['credential_configurations_supported'].keys()
            for vc in vc_list:
                if issuer_profile['credential_configurations_supported'][vc]['scope'] == session['code_data']['scope']:
                    break
            try:
                f = open('./verifiable_credentials/' + vc + '.jsonld', 'r')
            except Exception:
                # for vc+sd-jwt 
                try:
                    f = open('./verifiable_credentials/' + vc + '.json', 'r')
                except Exception:
                    logging.error('file not found')
                    return redirect(redirect_uri + '?' + authorization_error('invalid_request', 'VC not found', None, red, state))
            credential = json.loads(f.read())
            if client_metadata:
                wallet_authorization_endpoint = json.loads(client_metadata)['authorization_endpoint']
            elif wallet_issuer:
                wallet_issuer_url = wallet_issuer + '/.well-known/openid-configuration'
                resp = requests.get(wallet_issuer_url, timeout=10)
                wallet_authorization_endpoint = resp.json()['authorization_endpoint']
            else:
                logging.error('no wallet metadata')
                return redirect(redirect_uri + '?' + authorization_error('invalid_request', 'Wallet authorization endpoint not found', None, red, state))
            
            with open('presentation_definition_for_PID.json', 'r') as f:
                presentation_definition = json.loads(f.read())
            VP_request = {
                'aud': 'https://self-issued.me/v2',
                'client_id': 'did:web:talao.co',
                'client_id_scheme': 'redirect_uri',
                'exp': 1829170402,
                'iss': 'did:web:talao.co',
                'nonce': '5381697f-8c86-11ef-9061-0a1628958560',
                'response_mode': 'direct_post',
                'response_type': 'vp_token',
                'response_uri': mode.server + 'issuer/' + issuer_id + '/authorize/pid',
                'state': str(uuid.uuid1()),
                'presentation_definition': presentation_definition
            }
            code_data['stream_id'] = None
            code_data['vc'] = {vc: credential}
            code_data['credential_type'] = [vc]
            red.setex(VP_request['state'], 10000, json.dumps(code_data))
            return redirect(wallet_authorization_endpoint + '?' + urlencode(VP_request))
    
    # return from login/password screen
    logging.info('user is logged')
    session['login'] = False
    test = request.args.get('test')
    try:
        # issuer initiated authorization code flow with QR code
        offer_data = json.loads(red.get(test).decode())
    except Exception: 
        # wallet initiated authorization code flow -> create offer_data from file as it is needed for web wallet tests
        # fetch credential
        issuer_data = json.loads(db_api.read_oidc4vc_issuer(issuer_id))
        issuer_profile = profile[issuer_data['profile']]
        vc_list = issuer_profile['credential_configurations_supported'].keys()
        for vc in vc_list:
            if issuer_profile['credential_configurations_supported'][vc]['scope'] == session['code_data']['scope']:
                break
        try:
            f = open('./verifiable_credentials/' + vc + '.jsonld', 'r')
        except Exception:
            # for vc+sd-jwt 
            try:
                f = open('./verifiable_credentials/' + vc + '.json', 'r')
            except Exception:
                logging.error('file not found')
                return redirect(redirect_uri + '?' + authorization_error('invalid_request', 'VC not found', None, red, state))
        credential = json.loads(f.read())
        offer_data = {
            'stream_id': None,
            'vc': {vc: credential},
            'credential_type': [vc]
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
    logging.info('Call of the nonce endpoint, nonce = %s', nonce)
    endpoint_response = {'c_nonce': nonce}
    red.setex(nonce, 60,'nonce')
    headers = {'Cache-Control': 'no-store', 'Content-Type': 'application/json'}
    return Response(response=json.dumps(endpoint_response), headers=headers)


# token endpoint
def issuer_token(issuer_id, red, mode):
    """
    token endpoint: https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
    DPoP: https://datatracker.ietf.org/doc/rfc9449/
    """
    # TEST
    #return Response(**manage_error('invalid_grant', 'User code is incorrect', red,  status=404))

    logging.info('token endoint header %s', request.headers)
    logging.info('token endoint form %s', json.dumps(request.form, indent=4))
    issuer_data = json.loads(db_api.read_oidc4vc_issuer(issuer_id))
    issuer_profile = profile[issuer_data['profile']]
    
    draft = int(issuer_profile['oidc4vciDraft'])
    logging.info("OIDC4VCI Draft = %s", draft)
    
    
    # test if standalone AS is used
    if issuer_profile.get('authorization_server_support') and draft >= 13:
        return Response(**manage_error('invalid_request', 'invalid token endpoint', red,  ))
    
    # display DPoP
    if request.headers.get('DPoP'):
        try:
            DPoP_header = oidc4vc.get_header_from_token(request.headers.get('DPoP'))
            DPoP_payload = oidc4vc.get_payload_from_token(request.headers.get('DPoP'))
            logging.info('DPoP header = %s', json.dumps(DPoP_header, indent=4))
            logging.info('DPoP payload = %s', json.dumps(DPoP_payload, indent=4))
        except Exception as e:
            return Response(**manage_error('invalid_request', 'DPoP is incorrect ' + str(e), red,  ))
    else:
        logging.info('No DPoP')
    
    # check grant type
    grant_type = request.form.get('grant_type')
    if not grant_type:
        return Response(**manage_error('invalid_request', 'Request format is incorrect, grant is missing', red,  ))

    if grant_type == 'urn:ietf:params:oauth:grant-type:pre-authorized_code' and not request.form.get('pre-authorized_code'):
        return Response(**manage_error('invalid_request', 'Request format is incorrect, this grant type is not supported', red,  ))

    if grant_type == 'urn:ietf:params:oauth:grant-type:pre-authorized_code':
        code = request.form.get('pre-authorized_code')
        if draft >= 13:
            user_pin = request.form.get('tx_code')
        else:
            user_pin = request.form.get('user_pin')
    elif grant_type == 'authorization_code':
        code = request.form.get('code')
        user_pin = None
    else:
        return Response(**manage_error('invalid_request', 'Grant type not supported', red,  ))
    if not code and grant_type != 'client_credentials':
        return Response(**manage_error('invalid_request', 'Request format is incorrect, code is missing', red,  ))
    if grant_type == 'authorization_code' and not request.form.get('redirect_uri'):
        return Response(**manage_error('invalid_request', 'Request format is incorrect, redirect_uri is missing', red,  ))

    # display client_authentication method
    if request.headers.get('Oauth-Client-Attestation'):
        client_authentication_method = 'client_attestation'
    elif request.headers.get('Authorization'):
        client_authentication_method = 'client_secret_basic'
    elif request.form.get('client_id') and request.form.get('client_secret'):
        client_authentication_method = 'client_secret_post'
    elif request.form.get('client_id'):
        client_authentication_method = 'client_id'
    else:
        client_authentication_method = 'none'
    logging.info('client authentication method = %s', client_authentication_method)
    
    # Check content of client assertion and proof of possession (PoP)
   # Effective client identifier used later in the access token context.
    effective_client_id = request.form.get("client_id")

    # Check Client Attestation and its proof of possession.
    if client_authentication_method == "client_attestation":
        try:
            client_assertion = request.headers.get(
                "Oauth-Client-Attestation"
            )
            client_assertion_pop = request.headers.get(
                "Oauth-Client-Attestation-Pop"
            )

            if not client_assertion:
                return Response(**manage_error(
                    "invalid_client",
                    "OAuth-Client-Attestation header is missing",
                    red
                ))

            if not client_assertion_pop:
                return Response(**manage_error(
                    "invalid_client",
                    "OAuth-Client-Attestation-PoP header is missing",
                    red
                ))

            logging.info(
                "OAuth-Client-Attestation = %s",
                client_assertion
            )
            logging.info(
                "OAuth-Client-Attestation-PoP = %s",
                client_assertion_pop
            )

            client_assertion_payload = (
                oidc4vc.get_payload_from_token(client_assertion)
            )
            client_assertion_pop_payload = (
                oidc4vc.get_payload_from_token(
                    client_assertion_pop
                )
            )

            attestation_subject = client_assertion_payload.get(
                "sub"
            )
            pop_issuer = client_assertion_pop_payload.get(
                "iss"
            )

            if not attestation_subject:
                return Response(**manage_error(
                    "invalid_client",
                    "Client Attestation subject is missing",
                    red
                ))

            # client_id is optional in an anonymous
            # Pre-Authorized Code flow.
            # If provided, it must match the attestation subject.
            if (
                effective_client_id is not None
                and effective_client_id != attestation_subject
            ):
                return Response(**manage_error(
                    "invalid_client",
                    "client_id does not match "
                    "Client Attestation subject",
                    red
                ))

            if pop_issuer != attestation_subject:
                return Response(**manage_error(
                    "invalid_client",
                    "Client Attestation subject does not match "
                    "Client Attestation PoP issuer",
                    red
                ))

            # Since client_id was omitted by the wallet,
            # use the attested subject as effective client_id.
            effective_client_id = (
                effective_client_id or attestation_subject
            )

            logging.info(
                "Effective client_id = %s",
                effective_client_id
            )

        except ValueError as error:
            logging.exception(
                "Invalid OAuth Client Attestation"
            )
            return Response(**manage_error(
                "invalid_client",
                "Invalid OAuth Client Attestation: "
                + str(error),
                red
            ))

        except Exception as error:
            logging.exception(
                "OAuth Client Attestation processing failed"
            )
            return Response(**manage_error(
                "invalid_client",
                "OAuth Client Attestation processing failed: "
                + str(error),
                red
            ))

    # check code validity
    try:
        data = json.loads(red.get(code).decode())
    except Exception:
        return Response(**manage_error('access_denied', 'Grant code expired', red,  status=404))
    
    # get stream id
    stream_id = data['stream_id']
    
    # webhook data initialization
    webhook_data = {
        "webhook_url": data.get("webhook"),
        "issuer_state": data.get("issuer_state")
    }
        
    # check PKCE
    if grant_type == 'authorization_code' and draft >= 10:
        code_verifier = request.form.get('code_verifier')
        code_challenge_calculated = pkce.get_code_challenge(code_verifier)
        if code_challenge_calculated != data.get('code_challenge'):
            return Response(**manage_error('access_denied', 'Code verifier is incorrect', red,  stream_id=stream_id, status=404))

    # check tx_code
    if data.get('user_pin_required') and not user_pin:
        return Response(**manage_error('invalid_request', 'User code is missing', red,  stream_id=stream_id, webhook_data=webhook_data))
    logging.info('user_pin = %s', data.get('user_pin'))
    if data.get('user_pin_required') and data.get('user_pin') not in [user_pin, str(user_pin)]:
        return Response(**manage_error('invalid_grant', 'User code is incorrect', red,  stream_id=stream_id, status=404, webhook_data=webhook_data))

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
    
    # add nonce in token endpoint response
    if draft <= 13:
        endpoint_response['c_nonce'] = str(uuid.uuid1())
        endpoint_response['c_nonce_expires_in'] = 600
        # for testing
        red.setex(endpoint_response['c_nonce'], 600, 'nonce')
        
    # authorization_details in case of multiple VC of the same type
    authorization_details = []
    if draft >= 13 and isinstance(vc, list):
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
        'expires_at': (
            datetime.timestamp(datetime.now())
            + ACCESS_TOKEN_LIFE
        ),
        'c_nonce': endpoint_response.get('c_nonce'),
        'credential_type': data.get('credential_type'),
        'vc': data.get('vc'),
        'webhook': data.get('webhook'),
        'authorization_details': authorization_details,
        'stream_id': data.get('stream_id'),
        'issuer_state': data.get('issuer_state'),
        'client_id': effective_client_id,
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
            return Response(**manage_error('invalid_request', 'DPoP is incorrect ' + str(e), red,  ))
    else:
        logging.info('No DPoP')
        
    # Check access token
    try:
        access_token = request.headers['Authorization'].split()[1]
    except Exception:
        return Response(**manage_error('invalid_token', 'Access token not passed in request header', red,  ))
    try:
        access_token_data = json.loads(red.get(access_token).decode())
    except Exception:
        return Response(**manage_error('invalid_token', 'Access token expired', red,  ))

    # to manage followup screen
    stream_id = access_token_data.get('stream_id')
    
    # webhook data initialization
    webhook_data = {
        "webhook_url": access_token_data.get("webhook"),
        "issuer_state":access_token_data.get("issuer_state")
    }
    
    # issuer profile
    issuer_data = json.loads(db_api.read_oidc4vc_issuer(issuer_id))
    issuer_profile = profile[issuer_data['profile']]
    logging.info('OIDC4VCI Draft = %s', issuer_profile['oidc4vciDraft'])

    # Check request format
    try:
        result = request.json
    except Exception:
        return Response(**manage_error('invalid_request', 'Invalid request format', red,  stream_id=stream_id, webhook_data=webhook_data))

    # check vc format
    vc_format = result.get('format')
    credential_configuration_id = None
    logging.info('format in credential request = %s', vc_format)
    if vc_format and vc_format not in ['ldp_vc', 'dc+sd-jwt', 'vc+sd-jwt', 'jwt_vc_json', 'jwt_vc_json-ld', 'jwt_vc', 'mso_mdoc']:
        return Response(**manage_error('unsupported_credential_format', 'Invalid VC format: ' + vc_format, red,  stream_id=stream_id, webhook_data=webhook_data))
    
    if int(issuer_profile['oidc4vciDraft']) in [13, 14]:
        if result.get('format') in ['dc+sd-jwt', 'vc+sd-jwt'] and not result.get('vct'):
            return Response(**manage_error('invalid_request', 'Invalid request format, vct is missing', red,  stream_id=stream_id, webhook_data=webhook_data))
        elif result.get('format') in ['ldp_vc', 'jwt_vc_json-ld', 'jwt_vc_json'] and not result.get("credential_definition"):
            return Response(**manage_error('invalid_request', 'Invalid request format, credential definition is missing for ldp_vc or jwt_vc_json-ld', red,  stream_id=stream_id, webhook_data=webhook_data))
    
    elif int(issuer_profile['oidc4vciDraft']) >= 15:
        if vc_format:
            logging.warning("format is no more supported for OIDC4VCI Draft > 15")
        credential_configuration_id = result.get('credential_configuration_id')
        
    # check types
    if int(issuer_profile['oidc4vciDraft']) < 13 and not result.get('types'):
        return Response(**manage_error('unsupported_credential_format', 'Invalid VC format, types is missing', red,  stream_id=stream_id, webhook_data=webhook_data))
    
    # check proof if it exists depending on type of proof and draft
    try:
        if result.get('proof'):
            proof = result.get('proof')
            proof_type = proof.get('proof_type')
        else:
            proof = result.get('proofs')
            proof_type = "jwt"
        if not proof_type:
            return Response(**manage_error('unsupported_credential_format', 'Invalid requestformat, proof_type is missing', red,  stream_id=stream_id, webhook_data=webhook_data))
    except Exception:
        return Response(**manage_error('unsupported_credential_format', 'Invalid request format, proof(s) is missing', red,  stream_id=stream_id, webhook_data=webhook_data))

    wallet_jwk = []
    wallet_identifier = []
    wallet_did = []
    if proof:
        if proof_type == 'jwt':
            jwt_proof = proof.get('jwt') # maybe an array
            if isinstance(jwt_proof, str):
                jwt_proof = [jwt_proof]
            nb_proof = len(jwt_proof)
            logging.info("proof number = %s", nb_proof)
            i = 0 
            for proof in jwt_proof:
                proof_header = oidc4vc.get_header_from_token(proof)
                proof_payload = oidc4vc.get_payload_from_token(proof)
                logging.info('Proof header = %s', json.dumps(proof_header, indent=2))
                logging.info('Proof payload = %s', json.dumps(proof_payload, indent=2))
                if not proof_payload.get('nonce'):
                    return Response(**manage_error('invalid_proof', 'c_nonce is missing', red,  stream_id=stream_id, status=403, webhook_data=webhook_data))
                try:
                    oidc4vc.verif_token(proof)
                    logging.info('proof %s is validated', str(i))
                except ValueError as e :
                    logging.error( "Proof %s verification failed", str(i))
                    return Response(**manage_error('invalid_proof', 'Proof of key ownership, signature verification error: ' + str(e), red,  stream_id=stream_id, status=403, webhook_data=webhook_data))
                
                # check if nonce exists
                if not red.get(proof_payload['nonce']):
                    logging.error('nonce does not exist')
                    return Response(**manage_error('invalid_nonce', 'nonce does not exist', red,  stream_id=stream_id, webhook_data=webhook_data))
                else:
                    logging.info('nonce exists')
                
                if proof_header.get('jwk'):  # used for HAIP
                    wallet_jwk.append(proof_header.get('jwk'))
                    wallet_identifier.append('jwk_thumbprint')
                    wallet_did.append(access_token_data['client_id'])
                else:
                    wallet_identifier.append('did')
                    wallet_jwk.append(oidc4vc.resolve_did(proof_header.get('kid')))
                    wallet_did.append(proof_header.get('kid').split("#")[0])
                
        elif proof_type in ['ldp_vp', 'di_vp']:
            nb_proof = 1
            wallet_identifier = ['did']
            wallet_jwk = [None]
            proof = result['proof']['ldp_vp']
            proof = json.dumps(proof) if isinstance(proof, dict) else proof
            try:
                proof_check = await didkit.verify_presentation(proof, '{}') # VCDM 1.1
            except Exception:
                logging.warning("ldp_vp proof has not been checked")
            wallet_did = [json.loads(proof).get('holder')]
            logging.info('ldp_vp proof check  = %s', proof_check)
            if access_token_data['client_id'] and wallet_did and wallet_did != access_token_data['client_id']:
                logging.warning('iss %s of proof of key is different from client_id %s', wallet_did, access_token_data['client_id'] )
                return Response(**manage_error('invalid_proof', 'iss of proof of key is different from client_id in token request', red,  stream_id=stream_id, webhook_data=webhook_data))
        else:
            return Response(**manage_error('invalid_proof', 'Proof type not supported', red,  stream_id=stream_id))
    else:
        nb_proof = 1
        logging.warning('No proof available -> Bearer credential, wallet_did = client_id')
        wallet_jwk = [None]
        if vc_format == 'ldp_vc':
            return Response(**manage_error('invalid_proof', 'Crypto binding in ldp_vc format is required', red,  stream_id=stream_id, webhook_data=webhook_data))
        else:
            wallet_did = [access_token_data['client_id']]
    
    # delete nonce
    if proof_type == 'jwt' and proof_payload.get('nonce'):
        red.delete(proof_payload['nonce'])
    
    logging.info('wallet_did = %s', wallet_did)
    logging.info('wallet_identifier = %s', wallet_identifier)
    logging.info('wallet_jwk = %s', wallet_jwk)

    # Get credential type requested
    credential_identifier = None
    credential_type = None

    if int(issuer_profile['oidc4vciDraft']) >= 15:
        credential_type = credential_configuration_id
        try:
            vc_format = issuer_profile['credential_configurations_supported'][credential_type]["format"]
        except Exception:
            return Response(**manage_error('unsupported_format', 'format not found in credential issuer metadata', red,  stream_id=stream_id, webhook_data=webhook_data))
            
    elif int(issuer_profile['oidc4vciDraft']) in [13, 14]:
        credentials_supported = list(issuer_profile['credential_configurations_supported'].keys())
        if vc_format in ['dc+sd-jwt', 'vc+sd-jwt'] and result.get('vct'):  # vc+sd-jwt'
            vct = result.get('vct')
            for vc in credentials_supported:
                if issuer_profile['credential_configurations_supported'][vc].get('vct') == vct:
                    credential_type = vc
                    break
        else:
            try:
                vc_type = result['credential_definition'].get('type')
            except Exception:
                logging.error("credential definition does not exist, wrong request format")
                return Response(**manage_error('invalid_request', 'credential definition not found', red,  stream_id=stream_id, webhook_data=webhook_data))
            vc_type.sort()
            for vc in credentials_supported:
                issuer_profile['credential_configurations_supported'][vc]['credential_definition']['type'].sort()
                if issuer_profile['credential_configurations_supported'][vc]['credential_definition']['type'] == vc_type:
                    credential_type = vc
                    break
        if not credential_type:
            return Response(**manage_error('unsupported_credential_type', 'VC type not found', red,  stream_id=stream_id, webhook_data=webhook_data))
    
    elif int(issuer_profile['oidc4vciDraft']) == 11:
        credentials_supported = issuer_profile['credentials_supported']
        if vc_format == 'vc+sd-jwt' and result.get('vct'):  
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
            return Response(**manage_error('unsupported_credential_type', 'VC type not found', red,  stream_id=stream_id, webhook_data=webhook_data))
    
    # EBSI V3
    elif int(issuer_profile['oidc4vciDraft']) < 11:
        for one_type in result.get('types'):
            if one_type not in ['VerifiableCredential', 'VerifiableAttestation']:
                credential_type = one_type
                break
        if not credential_type:
            return Response(**manage_error('unsupported_credential_type', 'VC type not found', red,  stream_id=stream_id, webhook_data=webhook_data))
    else:
        return Response(**manage_error('invalid_request', 'Invalid request format', red,  stream_id=stream_id, webhook_data=webhook_data))
    logging.info('credential type = %s', credential_type)
    
    # check wallet key type for mso_doc
    if vc_format == 'mso_mdoc':
        for device_key in wallet_jwk:
            if not device_key:
                return Response(**manage_error(
                    'invalid_proof',
                    'mso_mdoc requires a device public key',
                    red,
                    stream_id=stream_id,
                    status=403,
                    webhook_data=webhook_data
                ))

            if (
                device_key.get('kty') != 'EC'
                or device_key.get('crv') != 'P-256'
                or not device_key.get('x')
                or not device_key.get('y')
            ):
                return Response(**manage_error(
                    'invalid_proof',
                    'mso_mdoc currently requires an EC P-256 device key',
                    red,
                    stream_id=stream_id,
                    status=403,
                    webhook_data=webhook_data
                ))
    
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
        logging.info('Multiple VCs of the same type')
        for one_type in access_token_data['vc']:
            for one_credential in one_type['list']:
                if one_credential['identifier'] == credential_identifier:
                    vc_format = one_type['vc_format']
                    credential = one_credential['value']
                    logging.info('credential found for identifier = %s', credential_identifier)
                    break
    else:
        logging.info('Only one VC of the same type = %s and format = %s', credential_type, vc_format)
        try:
            credential = access_token_data['vc'][credential_type]
        except Exception:
            return Response(**manage_error('unsupported_credential_type', 'The credential type is not offered', red,  stream_id=stream_id, webhook_data=webhook_data))
    if not credential:
        return Response(**manage_error('unsupported_credential_type', 'Credential is not found for this credential identifier', red,  stream_id=stream_id, webhook_data=webhook_data))

    # sign_credential(credential, wallet_did, issuer_id, c_nonce, format, issuer,  duration=365, wallet_jwk=None, wallet_identifier=None):
    credential_signed = []
    for i in range(nb_proof):
        credential_signed.append(await sign_credential(
            credential,
            wallet_did[i],
            issuer_id,
            access_token_data.get('c_nonce', 'nonce'),
            vc_format,
            mode.server + 'issuer/' + issuer_id,  # issuer
            mode,
            wallet_jwk=wallet_jwk[i],
            wallet_identifier=(
                wallet_identifier[i]
                if i < len(wallet_identifier)
                else None
            ),
            draft=int(issuer_profile['oidc4vciDraft'])
        ))
        logging.info('credential signed sent to wallet = %s', credential_signed)
        if not credential_signed:
            return Response(**manage_error('internal_error', 'Credential signing error', red,  stream_id=stream_id,webhook_data=webhook_data))
    
    # send event to front to go forward callback and send credential to wallet
    front_publish(access_token_data['stream_id'], red)

    # Transfer VC
    c_nonce = str(uuid.uuid1())
    if int(issuer_profile['oidc4vciDraft']) >= 20:
        payload = {"credentials": []}
        for i in range(nb_proof):
            payload["credentials"].append({
                "credential": credential_signed[i]
            })
    else:
        payload = {
            'credential': credential_signed[0],  # string or json depending on the format
            'c_nonce': c_nonce,
            'c_nonce_expires_in': C_NONCE_LIFE,
        }
    
    if int(issuer_profile['oidc4vciDraft']) < 13:
        payload.update({'format': vc_format})

    # update nonce in access token for next VC request
    access_token_data['c_nonce'] = c_nonce
    red.setex(access_token, ACCESS_TOKEN_LIFE, json.dumps(access_token_data))

    # send event to webhook if it exists    
    if webhook := access_token_data['webhook']:
        data = {
                'event': 'CREDENTIAL_SENT',
                'issuer_state': access_token_data.get("issuer_state")
        }
        requests.post(webhook, json=data, timeout=10)

    # send VC to wallet
    headers = {'Cache-Control': 'no-store', 'Content-Type': 'application/json'}
    return Response(response=json.dumps(payload), headers=headers)


async def issuer_deferred(issuer_id, red, mode):
    """
    Deferred endpoint
    https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-deferred-credential-endpoin
    """
    logging.info('deferred endpoint request')

    # Check access token
    try:
        access_token = request.headers['Authorization'].split()[1]
    except Exception:
        return Response(**manage_error('invalid_request', 'Access token not passed in request header', red,  ))
    try:
        transaction_id = request.json['transaction_id']
    except Exception:
        return Response(**manage_error('invalid_request', 'Transaction id not passed in request body', red,  ))


    # Offer expired, VC is no more available return 410
    try:
        transaction_id_data = json.loads(red.get(transaction_id).decode())
    except Exception:
        return Response(**manage_error('invalid_transaction_id', 'Transaction data expired', red,  status=400))

    # check access token 
    if access_token != transaction_id_data.get('access_token'):
        return Response(**manage_error('invalid_request', 'access token does not fit transaction_id', red,  status=410))

    issuer_state = transaction_id_data['issuer_state']
    credential_type = transaction_id_data['credential_type']

    # VC is not ready return 400, issuance_pending
    try:
        deferred_data = json.loads(red.get(issuer_state).decode())
        credential = deferred_data['deferred_vc'][credential_type]
    except Exception:
        payload = {
            'error': 'issuance_pending',
            'interval': 30,
            'error_description': 'Credential is not available yet',
        }
        logging.info('endpoint error response = %s', json.dumps(payload, indent=4))
        headers = {'Cache-Control': 'no-store', 'Content-Type': 'application/json'}
        return Response(response=json.dumps(payload), status=400, headers=headers)

    # sign_credential
    credential_signed = await sign_credential(
        credential,
        transaction_id_data['subjectId'],
        issuer_id,
        transaction_id_data['c_nonce'],
        transaction_id_data['format'],
        mode.server + 'issuer/' + issuer_id,
        mode
    )
    if not credential_signed:
        return Response(**manage_error('internal_error', 'Credential signature failed due to format', red,  status=404))

    logging.info('credential signed sent to wallet = %s', credential_signed)

    # delete deferred VC data
    red.delete(issuer_state)

    # Transfer VC
    payload = {
        'format': transaction_id_data['format'],
        'credential': credential_signed,  # string or json depending on the format
        'c_nonce': str(uuid.uuid1()),
        'c_nonce_expires_in': C_NONCE_LIFE,
    }
    headers = {'Cache-Control': 'no-store', 'Content-Type': 'application/json'}
    return Response(response=json.dumps(payload), headers=headers)


def oidc_issuer_followup(stream_id, red):
    try:
        user_data = json.loads(red.get(stream_id).decode())
    except Exception:
        return jsonify('Unauthorized'), 401
    callback = user_data['callback']
    if not callback:
        issuer_id = user_data['issuer_id']
        issuer_data = db_api.read_oidc4vc_issuer(issuer_id)
        callback = json.loads(issuer_data)['callback']
    callback_uri = callback + '?'
    data = {
        'issuer_state': user_data.get('issuer_state'),
        'stream_id': stream_id
    }
    if request.args.get('error'):
        data['error'] = request.args.get('error')
    if request.args.get('error_description'):
        data['error_description'] = request.args.get('error_description')
    logging.info('callback uri = %s', callback_uri + urlencode(data))
    return redirect(callback_uri + urlencode(data))


# server event push for user agent EventSource
def oidc_issuer_stream(red):
    def event_stream(red):
        pubsub = red.pubsub()
        pubsub.subscribe('issuer_oidc')
        for message in pubsub.listen():
            if message['type'] == 'message':
                yield 'data: %s\n\n' % message['data'].decode()

    headers = {
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache',
        'X-Accel-Buffering': 'no',
    }
    return Response(event_stream(red), headers=headers)


async def sign_credential(credential, wallet_did, issuer_id, c_nonce, format, issuer, mode, duration=365, wallet_jwk=None, wallet_identifier=None, draft=13):
    issuer_data = json.loads(db_api.read_oidc4vc_issuer(issuer_id))
    issuer_did = issuer_data['did']
    issuer_key = issuer_data['jwk']
    issuer_vm = issuer_data['verification_method']
    jti = 'urn:uuid:' + str(uuid.uuid1())
    if format in ['dc+sd-jwt', 'vc+sd-jwt']:
        credential['status'] = {
            'status_list': {
                'idx': randint(0, 99999),
                'uri': mode.server + 'issuer/statuslist/1'
            }
        }
        if issuer_data['profile'] in ['HAIP', 'POTENTIAL']:
            x5c = True
        else:
            x5c = False
        if not issuer_data.get('issuer_id_as_url'):
            issuer = issuer_did
            kid = issuer_vm
        else:
            kid = thumbprint(issuer_key)

        return oidc4vc.sign_sd_jwt(credential, issuer_key, issuer, wallet_jwk, wallet_did, wallet_identifier, kid, x5c=x5c, draft=draft)
    elif format == 'mso_mdoc':
        if not isinstance(credential, dict):
            raise ValueError('The mdoc payload must be a JSON object')

        if not credential.get('docType'):
            raise ValueError('The mdoc payload is missing doctype')

        if not credential.get('nameSpaces'):
            raise ValueError(
                'The mdoc payload must contain namespaces'
            )

        if not wallet_jwk:
            raise ValueError(
                'mso_mdoc requires a wallet public key obtained '
                'from the validated proof'
            )

        return mdoc.sign_mdoc(
            credential,
            issuer_key,
            wallet_jwk,
            validity_days=duration,
            x5chain=issuer_data.get('mdoc_x5chain'),
            kid=None,
            require_x5chain=issuer_data.get(
                'mdoc_require_x5chain',
                False
            )
        )
    elif format in ['ldp_vc', 'jwt_vc_json-ld']:
        logging.info('wallet did = %s', wallet_did)
        if wallet_did:
            credential['credentialSubject']['id'] = wallet_did
        else:
            credential['credentialSubject'].pop('id', None)
        credential['id'] = jti
        try:
            credential['issuer']['id'] = issuer_did
        except Exception:
            credential['issuer'] = issuer_did
        credential['issuanceDate'] = datetime.now().replace(microsecond=0).isoformat() + 'Z'
        credential['expirationDate'] = (datetime.now() + timedelta(days=duration)).replace(microsecond=0).isoformat() + 'Z'

        index = str(randint(0, 99999))
        credential['credentialStatus'] = {
            'id':  mode.server + 'sandbox/issuer/bitstringstatuslist/1#' + index,
            'type': 'BitstringStatusListEntry',
            'statusPurpose': 'revocation',
            'statusListIndex': index,
            'statusSize': 1,
            'statusListCredential':  mode.server + 'sandbox/issuer/bitstringstatuslist/1'
        }
        
    elif format in ['jwt_vc_json', 'jwt_vc']:     # jwt_vc format is used for ebsi V3 only with draft 10/11
        credential = clean_jwt_vc_json(credential)
        index = str(randint(0, 99999))
        credential['credentialStatus'] = {
            'id':  mode.server + 'sandbox/issuer/bitstringstatuslist/1#' + index,
            'type': 'BitstringStatusListEntry',
            'statusPurpose': 'revocation',
            'statusListIndex': index,
            'statusSize': 1,
            'statusListCredential':  mode.server + 'sandbox/issuer/bitstringstatuslist/1'
        }
    
    else:
        logging.error('credential format not supported %s', format)
        return
    logging.info('credential to sign = %s', credential)
    if format in ['jwt_vc', 'jwt_vc_json', 'jwt_vc_json-ld']:
        # sign_jwt_vc(vc, kid, issuer_key, nonce, iss, jti, sub)
        if issuer_data.get('issuer_id_as_url'):
            kid = thumbprint(issuer_key)
            credential_signed = oidc4vc.sign_jwt_vc(credential, kid, issuer_key, c_nonce, issuer, jti, wallet_did)
        else:
            credential_signed = oidc4vc.sign_jwt_vc(credential, issuer_vm, issuer_key, c_nonce, issuer_did, jti, wallet_did)
    else:  # proof_format == 'ldp_vc':
        # manage remote context
        old_context = credential['@context']
        new_context = ["https://www.w3.org/2018/credentials/v1", "https://w3id.org/security/suites/ed25519-2020/v1"]
        for url in old_context:
            if isinstance(url, dict):
                new_context.append(url)
            elif url not in  ["https://www.w3.org/2018/credentials/v1", "https://w3id.org/security/suites/ed25519-2020/v1"]:
                remote_file = requests.get(url, timeout=10).json()
                new_context.append(remote_file['@context'])
            else:
                pass
        credential["@context"] = new_context
        try:
            didkit_options = {
                'proofPurpose': 'assertionMethod',
                'verificationMethod': issuer_vm,
            }
            if issuer_vm in ["did:web:app.altme.io:issuer#key-1",  "did:web:talao.co#key-4"]:
                didkit_options["type"] = "Ed25519Signature2020"
            credential_signed = await didkit.issue_credential(
                json.dumps(credential),
                didkit_options.__str__().replace("'", '"'),
                issuer_key,
            )
            credential_signed_json = json.loads(credential_signed)
            # re set original @context
            credential_signed_json["@context"] = old_context
            credential_signed = json.dumps(credential_signed_json)
        except Exception as e:
            logging.warning('Didkit exception = %s', str(e))
            logging.warning('incorrect json_ld = %s', json.dumps(credential))
            return
        logging.info('VC signed with didkit')
        #result = await didkit.verify_credential(credential_signed, '{}')
        #logging.info('signature check with didkit = %s', result)
        credential_signed = json.loads(credential_signed)
    return credential_signed


def clean_jwt_vc_json(credential):
    vc = copy.copy(credential)
    vc.pop('@context', None)
    vc.pop('issuer', None)
    vc.pop('issued', None)
    vc.pop('id', None)
    vc.pop('issuanceDate', None)
    vc['credentialSubject'].pop('id', None)
    vc.pop('expirationDate', None)
    vc.pop('validFrom', None)
    vc.pop('validUntil', None)
    return vc