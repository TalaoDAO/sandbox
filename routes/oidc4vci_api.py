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

logging.basicConfig(level=logging.INFO)

API_LIFE = 5000
ACCESS_TOKEN_LIFE = 1000
GRANT_LIFE = 5000
C_NONCE_LIFE = 5000
ACCEPTANCE_TOKEN_LIFE = 28 * 24 * 60 * 60


def init_app(app, red, mode):
    # endpoint for application if redirect to local page (test)
    app.add_url_rule(
        "/sandbox/ebsi/issuer/<issuer_id>/<stream_id>",
        view_func=oidc_issuer_landing_page,
        methods=["GET", "POST"],
        defaults={"red": red, "mode": mode},
    )
    app.add_url_rule(
        "/sandbox/ebsi/issuer_stream",
        view_func=oidc_issuer_stream,
        methods=["GET", "POST"],
        defaults={"red": red},
    )
    app.add_url_rule(
        "/sandbox/ebsi/issuer_followup/<stream_id>",
        view_func=oidc_issuer_followup,
        methods=["GET"],
        defaults={"red": red},
    )

    # api for application
    app.add_url_rule(
        "/sandbox/ebsi/issuer/api/<issuer_id>",
        view_func=issuer_api_endpoint,
        methods=["POST"],
        defaults={"red": red, "mode": mode},
    )

    # OIDC4VCI protocol with wallet
    app.add_url_rule("/sandbox/ebsi/issuer/<issuer_id>/.well-known/openid-configuration", view_func=issuer_openid_configuration, methods=["GET"],defaults={"mode": mode})
    app.add_url_rule("/sandbox/ebsi/issuer/<issuer_id>/.well-known/openid-credential-issuer",view_func=issuer_openid_configuration, methods=["GET"], defaults={"mode": mode})
    app.add_url_rule("/sandbox/ebsi/issuer/<issuer_id>/authorize", view_func=issuer_authorize, methods=["GET", "POST"], defaults={"red": red, "mode": mode})
    app.add_url_rule("/sandbox/ebsi/issuer/<issuer_id>/token", view_func=issuer_token, methods=["POST"], defaults={"red": red, "mode": mode},)
    app.add_url_rule("/sandbox/ebsi/issuer/<issuer_id>/credential", view_func=issuer_credential, methods=["POST"], defaults={"red": red, "mode": mode})
    app.add_url_rule("/sandbox/ebsi/issuer/<issuer_id>/deferred", view_func=issuer_deferred, methods=["POST"], defaults={"red": red, "mode": mode},)
    app.add_url_rule("/sandbox/ebsi/issuer/<issuer_id>/authorize_server/.well-known/openid-configuration", view_func=issuer_authorization_server, methods=["GET"], defaults={"mode": mode},)
    app.add_url_rule("/sandbox/ebsi/issuer/credential_offer_uri/<id>", view_func=issuer_credential_offer_uri, methods=["GET"], defaults={"red": red})
    app.add_url_rule("/sandbox/ebsi/issuer/error_uri", view_func=wallet_error_uri, methods=["GET"])
    
    return


def front_publish(stream_id, red, error=None, error_description=None):
    # send event to front channel to go forward callback and send credential to wallet
    data = {"stream_id": stream_id}
    if error:
        data["error"] = error
    if error_description:
        data["error_description"] = error_description
    red.publish("issuer_oidc", json.dumps(data))


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
    if request.headers.get('Content-Type') == "application/json":
        body = json.dumps(request.json)
    elif not request.headers.get('Content-Type'):
        body = ""
    else:
        body = json.dumps(request.form)

    data = {
        "header": str(request.headers),
        "arguments": json.dumps(request.args),
        "body": body,
        "error": error,
        "error_description": error_description
    }
    return mode.server + 'sandbox/ebsi/issuer/error_uri?' + urlencode(data)


def manage_error(error, error_description, red, mode, request=None, stream_id=None, status=400):
    """
    Return error code to wallet and front channel
    https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-error-response
    """
    # console
    logging.warning("manage error = %s", error_description)
    
    # front channel
    if stream_id:
        front_publish(stream_id, red, error=error, error_description=error_description)
    
    # wallet
    payload = {
        "error": error,
        "error_description": error_description,
    }
    if request:
        payload['error_uri'] = error_uri_build(request, error, error_description, mode)

    headers = {"Cache-Control": "no-store", "Content-Type": "application/json"}
    return {"response": json.dumps(payload), "status": status, "headers": headers}


def issuer_openid_configuration(issuer_id, mode):
    doc = oidc(issuer_id, mode)
    return jsonify(doc) if doc else (jsonify("Not found"), 404)


def oidc(issuer_id, mode):
    try:
        issuer_data = json.loads(db_api.read_oidc4vc_issuer(issuer_id))
        issuer_profile = profile[issuer_data["profile"]]
    except Exception:
        logging.warning("issuer_id not found for %s", issuer_id)
        return

    # Credentials_supported section
    cs = []
    for _vc in issuer_profile.get("credentials_supported"):
        oidc_data = {
            "format": _vc.get("format", "missing, contact@talao.co"),
            "types": _vc.get("types", "missing, contact@talao.co"),
            "display": _vc.get("display", "missing, contact@talao.co"),
        }
        if issuer_data["profile"] != "EBSI-V3":
            oidc_data.update(
                {
                    "cryptographic_binding_methods_supported": _vc.get(
                        "cryptographic_binding_methods_supported",
                        "missing, contact@talao.co",
                    ),
                    "cryptographic_suites_supported": _vc.get(
                        "cryptographic_suites_supported", "missing, contact@talao.co"
                    ),
                }
            )
        if _vc.get("id"):
            oidc_data["id"] = _vc["id"]
        if _vc.get("trust_framework"):
            oidc_data["trust_framework"] = _vc["trust_framework"]
        cs.append(oidc_data)

    # general section
    # https://www.rfc-editor.org/rfc/rfc8414.html#page-4
    openid_configuration = {}
    openid_configuration.update(
        {
            "credential_issuer": mode.server + "sandbox/ebsi/issuer/" + issuer_id,
            "credential_endpoint": mode.server + "sandbox/ebsi/issuer/" + issuer_id + "/credential",
            "deferred_credential_endpoint": mode.server + "sandbox/ebsi/issuer/" + issuer_id + "/deferred",
            "credentials_supported": cs
        }
    )
    # TESTING TEST 6
    #if issuer_id in ["cejjvswuep", "ooroomolyd"] :
    #    del openid_configuration['credentials_supported']
        
    if issuer_profile.get("service_documentation"):
        openid_configuration["service_documentation"] = issuer_profile[
            "service_documentation"
        ]
    if issuer_profile.get("batch_credential_endpoint_support"):
        openid_configuration["batch_credential_endpoint"] = (
            mode.server + "sandbox/ebsi/issuer/" + issuer_id + "/batch"
        )

    # setup credential manifest as optional
    # https://openid.net/specs/openid-connect-4-verifiable-credential-issuance-1_0-05.html#name-server-metadata
    if issuer_profile.get("credential_manifest_support"):
        cm = []
        for _vc in issuer_profile.get("credentials_types_supported"):
            file_path = "./credential_manifest/" + _vc + "_credential_manifest.json"
            try:
                cm_to_add = json.load(open(file_path))
                cm_to_add["issuer"]["id"] = issuer_data.get("did", "Unknown")
                cm_to_add["issuer"]["name"] = issuer_data["application_name"]
                cm.append(cm_to_add)
            except Exception:
                logging.warning("credential manifest not found for %s", _vc)
        openid_configuration["credential_manifests"] = cm

    # setup authorization server
    if issuer_profile.get("authorization_server_support"):
        openid_configuration["authorization_server"] = mode.server + "sandbox/ebsi/issuer/" + issuer_id + "/authorize_server"
    else:
        authorization_server_config = json.load(open("authorization_server_config.json"))
        openid_configuration["authorization_endpoint"] = mode.server + "sandbox/ebsi/issuer/" + issuer_id + "/authorize"
        openid_configuration["token_endpoint"] = mode.server + "sandbox/ebsi/issuer/" + issuer_id + "/token"
        openid_configuration.update(authorization_server_config)
    return openid_configuration


def issuer_authorization_server(issuer_id, mode):
    authorization_server_config = json.load(open("authorization_server_config.json"))
    config = {
        "authorization_endpoint": mode.server + "sandbox/ebsi/issuer/" + issuer_id + "/authorize",
        "token_endpoint": f"{mode.server}sandbox/ebsi/issuer/{issuer_id}/token"
    }
    config.update(authorization_server_config)
    return jsonify(config)


# Customer API
def issuer_api_endpoint(issuer_id, red, mode):
    """
    This API returns the QRcode page URL to redirect user or the QR code by value if the template is managed by the application

    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer <client_secret>'
    }

    data = {
        "vc": OPTIONAL -> { "EmployeeCredendial": {}, ....}, json object, VC as a json-ld not signed { "EmployeeCredendial": [ {"identifier1": {}},  ....}
        "deferred_vc": CONDITIONAL, REQUIRED in case of 2nd deferred call
        "issuer_state": REQUIRED, string,
        "credential_type": REQUIRED -> array or string name of the credentials offered
        "pre-authorized_code": REQUIRED , bool
        "user_pin_required": OPTIONAL bool, default is false
        "user_pin": CONDITIONAL, string, REQUIRED if user_pin_required is True
        "callback": REQUIRED, string, this the user redirect route at the end of the flow
        "login" : OPTIONAL for authorization code flow with login
        }
    resp = requests.post(token_endpoint, headers=headers, data = json.dumps(data))
    return resp.json()

    """
    # check API format
    try:
        token = request.headers["Authorization"]
        client_secret = token.split(" ")[1]
    except Exception:
        return Response(
            **manage_error("unauthorized", "Unauthorized token", red, mode, status=401)
        )
    try:
        issuer_data = json.loads(db_api.read_oidc4vc_issuer(issuer_id))
    except Exception:
        return Response(
            **manage_error("unauthorized", "Unauthorized client_id", red, mode, status=401)
        )
    try:
        issuer_state = request.json["issuer_state"]
    except Exception:
        return Response(
            **manage_error("invalid_request", "issuer_state missing", red, mode, status=401)
        )
    try:
        credential_type = request.json["credential_type"]
    except Exception:
        return Response(
            **manage_error("invalid_request", "credential_type missing", red, mode, status=401)
        )
    try:
        pre_authorized_code = request.json["pre-authorized_code"]
    except Exception:
        return Response(
            **manage_error(
                "invalid_request", "pre-authorized_code is missing", red, mode, status=401
            )
        )

    # check if client_id exists
    if client_secret != issuer_data["client_secret"]:
        logging.warning("Client secret is incorrect")
        return Response(
            **manage_error(
                "unauthorized", "Client secret is incorrect", red, mode, status=401
            )
        )

    # Check vc and vc_deferred
    vc = request.json.get("vc")
    deferred_vc = request.json.get("deferred_vc")
    if vc and not request.json.get("callback"):
        return Response(
            **manage_error("invalid_request", "callback missing", red, status=401))
    if vc and deferred_vc:
        return Response(**manage_error("invalid_request", "deferred_vc and vc not allowed", red, mode, status=401))

    # Check if user pin exists
    if request.json.get("user_pin_required") and not request.json.get("user_pin"):
        return Response(**manage_error("invalid_request", "User pin is not set", red, mode, status=401))
    logging.info('user PIN stored =  %s', request.json.get("user_pin"))

    # check if user pin is string
    if request.json.get("user_pin_required") and request.json.get("user_pin") and not isinstance(request.json.get("user_pin"), str):
        return Response(
            **manage_error("invalid_request", "User pin must be string", red, mode, status=401))

    # check if credential offered is supported
    issuer_profile = profile[issuer_data["profile"]]
    credential_type = (
        credential_type if isinstance(credential_type, list) else [credential_type]
    )
    for _vc in credential_type:
        if _vc not in issuer_profile["credentials_types_supported"]:
            logging.error("Credential not supported -> %s", _vc)
            return Response(
                **manage_error("unauthorized", "Credential not supported " + _vc, red, mode, status=401))
            
    nonce = str(uuid.uuid1())

    # generate pre-authorized_code as jwt or string
    if pre_authorized_code:
        if profile[issuer_data["profile"]].get("pre-authorized_code_as_jwt"):
            pre_authorized_code = oidc4vc.build_pre_authorized_code(
                issuer_data["jwk"],
                "https://self-issued.me/v2",
                mode.server + "sandbox/ebsi/issuer/" + issuer_id,
                issuer_data["verification_method"],
                nonce,
            )
        else:
            pre_authorized_code = str(uuid.uuid1())

    stream_id = str(uuid.uuid1())
    session_data = {
        "vc": vc,
        "nonce": nonce,
        "stream_id": stream_id,
        "issuer_id": issuer_id,
        "issuer_state": request.json.get("issuer_state"),
        "credential_type": credential_type,
        "pre-authorized_code": pre_authorized_code,
        "user_pin_required": request.json.get("user_pin_required"),
        "user_pin": request.json.get("user_pin"),
        "callback": request.json.get("callback"),
        "login": request.json.get("login"),
    }

    # For deferred API call only VC is stored in redis with issuer_state as key
    if deferred_vc and red.get(issuer_state):
        session_data.update(
            {
                "deferred_vc": deferred_vc,
                "deferred_vc_iat": round(datetime.timestamp(datetime.now())),
                "deferred_vc_exp": round(datetime.timestamp(datetime.now()))
                + ACCEPTANCE_TOKEN_LIFE,
            }
        )
        red.setex(issuer_state, API_LIFE, json.dumps(session_data))
        logging.info(
            "Deferred VC has been issued with issuer_state =  %s", issuer_state
        )
    else:
        # for authorization code flow
        red.setex(issuer_state, API_LIFE, json.dumps(session_data))

    # for pre authorized code
    if pre_authorized_code:
        red.setex(pre_authorized_code, GRANT_LIFE, json.dumps(session_data))

    # for front page management
    red.setex(stream_id, API_LIFE, json.dumps(session_data))
    response = {
        "redirect_uri": mode.server
        + "sandbox/ebsi/issuer/"
        + issuer_id
        + "/"
        + stream_id
    }
    logging.info(
        "initiate qrcode = %s",
        mode.server + "sandbox/ebsi/issuer/" + issuer_id + "/" + stream_id,
    )
    return jsonify(response)


def build_credential_offer(
    issuer_id,
    credential_type,
    pre_authorized_code,
    issuer_state,
    issuer_profile,
    vc,
    user_pin_required,
    mode,
):
    #  https://openid.net/specs/openid-connect-4-verifiable-credential-issuance-1_0-05.html#name-pre-authorized-code-flow

    # Old same as EBSIV2 but without schema
    if issuer_profile == "GAIA-X":
        if len(credential_type) == 1:
            credential_type = credential_type[0]
        offer = {
            "issuer": f"{mode.server}sandbox/ebsi/issuer/{issuer_id}",
            "credential_type": credential_type,
        }
        if pre_authorized_code:
            offer["pre-authorized_code"] = pre_authorized_code
            if user_pin_required:
                offer["user_pin_required"]: True

    # new OIDC4VCI standard with  credentials as an array ofjson objects (EBSI-V3)
    elif profile[issuer_profile].get("credentials_as_json_object_array"):
        offer = {
            "credential_issuer": f"{mode.server}sandbox/ebsi/issuer/{issuer_id}",
            "credentials": [],
        }
        if pre_authorized_code:
            offer["grants"] = {
                "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                    "pre-authorized_code": pre_authorized_code
                }
            }
            if user_pin_required:
                offer["grants"][
                    "urn:ietf:params:oauth:grant-type:pre-authorized_code"
                ].update({"user_pin_required": True})
        else:
            offer["grants"] = {"authorization_code": {"issuer_state": issuer_state}}
        
        for one_vc in credential_type:
            for supported_vc in profile[issuer_profile]["credentials_supported"]:
                if one_vc in supported_vc["types"]:
                    offer["credentials"].append(
                        {
                            "format": supported_vc["format"],
                            "types": supported_vc["types"],
                        }
                    )
                if vc.get("trust_framework"):
                    offer["trust_framework"] = supported_vc["trust_framework"]

    # new OIDC4VCI standard with  credentials as an array of strings
    else:
        offer = {
            "credential_issuer": f'{mode.server}sandbox/ebsi/issuer/{issuer_id}',
            "credentials": credential_type,
        }
        if pre_authorized_code:
            offer["grants"] = {
                "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                    "pre-authorized_code": pre_authorized_code
                }
            }
            if user_pin_required:
                offer["grants"][
                    "urn:ietf:params:oauth:grant-type:pre-authorized_code"
                ].update({"user_pin_required": True})
        else:
            offer["grants"] = {"authorization_code": {"issuer_state": issuer_state}}
    return offer


def issuer_credential_offer_uri(id, red):
    """
    credential_offer_uri endpoint
    return 201
    """
    try:
        offer = json.loads(red.get(id).decode())
    except Exception:
        logging.warning("session expired")
        return jsonify("Session expired"), 404
    return jsonify(offer), 201


# Display QRcode page for credential offer
def oidc_issuer_landing_page(issuer_id, stream_id, red, mode):
    session['stream_id'] = stream_id
    try:
        session_data = json.loads(red.get(stream_id).decode())
    except Exception:
        logging.warning("session expired")
        return jsonify("Session expired"), 404
    credential_type = session_data["credential_type"]
    pre_authorized_code = session_data["pre-authorized_code"]
    user_pin_required = session_data["user_pin_required"]
    issuer_state = session_data["issuer_state"]
    vc = session_data["vc"]
    issuer_data = json.loads(db_api.read_oidc4vc_issuer(issuer_id))
    data_profile = profile[issuer_data["profile"]]
    offer = build_credential_offer(
        issuer_id,
        credential_type,
        pre_authorized_code,
        issuer_state,
        issuer_data["profile"],
        vc,
        user_pin_required,
        mode,
    )

    # credential offer is passed by value
    if issuer_data["profile"] not in ["GAIA-X"]:
        url_to_display = (
            data_profile["oidc4vci_prefix"]
            + "?"
            + urlencode({"credential_offer": json.dumps(offer)})
        )
        json_url = {"credential_offer": offer}
    else:
        url_to_display = data_profile["oidc4vci_prefix"] + "?" + urlencode(offer)
        json_url = offer

    # credential offer is passed by reference : credential offer uri
    if issuer_data.get("credential_offer_uri"):
        id = str(uuid.uuid1())
        credential_offer_uri = (
            f"{mode.server}sandbox/ebsi/issuer/credential_offer_uri/{id}"
        )
        red.setex(id, GRANT_LIFE, json.dumps(offer))
        logging.info("credential offer uri =%s", credential_offer_uri)
        url_to_display = (
            data_profile["oidc4vci_prefix"]
            + "?credential_offer_uri="
            + credential_offer_uri
        )

    openid_configuration = json.dumps(oidc(issuer_id, mode), indent=4)
    deeplink_talao = (
        mode.deeplink_talao + "app/download/oidc4vc?" + urlencode({"uri": url_to_display})
    )
    deeplink_altme = (
        mode.deeplink_altme + "app/download/oidc4vc?" + urlencode({"uri": url_to_display})
    )
    qrcode_page = issuer_data.get("issuer_landing_page")
    logging.info("QR code page = %s", qrcode_page)
    return render_template(
        qrcode_page,
        openid_configuration=openid_configuration,
        url_data=json.dumps(json_url, indent=6),
        url=url_to_display,
        deeplink_altme=deeplink_altme,
        deeplink_talao=deeplink_talao,
        stream_id=stream_id,
        issuer_id=issuer_id,
        page_title=issuer_data["page_title"],
        page_subtitle=issuer_data["page_subtitle"],
        page_description=issuer_data["page_description"],
        title=issuer_data["title"],
        landing_page_url=issuer_data["landing_page_url"],
        issuer_state=request.args.get("issuer_state"),
    )


def authorization_error(request, error, error_description, stream_id, red, mode, state=None):
        """
        https://www.rfc-editor.org/rfc/rfc6749.html#page-26
        """
        # front channel follow up
        front_publish(stream_id, red, error=error, error_description=error_description)
        resp = {
            "error_description": error_description,
            "error": error}
        
        # redirect arguments for errors
        resp['error_uri'] = error_uri_build(request, error, error_description, mode)
        if state:
            resp["state"] = state
        return urlencode(resp)


def issuer_authorize(issuer_id, red, mode):
    try:
        issuer_state = request.args["issuer_state"]
        stream_id = json.loads(red.get(issuer_state).decode())['stream_id']
    except Exception:
        return jsonify({"error": "access_denied"}), 403

    scope = request.args.get("scope")  # not required for this flow
    nonce = request.args.get("nonce")
    code_challenge = request.args.get("code_challenge")
    code_challenge_method = request.args.get("code_challenge_method")
    client_metadata = request.args.get("client_metadata")
    state = request.args.get("state")  # wallet state
    
    try:
        redirect_uri = request.args["redirect_uri"]
    except Exception:
        return jsonify({"error": "invalid_request"}), 403

    try:
        response_type = request.args["response_type"]
    except Exception:
        return redirect(redirect_uri + '?' + authorization_error(request, 'invalid_request', 'Response type is missing', stream_id, red, mode, state=state)) 

    try:
        client_id = request.args["client_id"]  # DID of the issuer
    except Exception:
        return redirect(redirect_uri + '?' + authorization_error(request, 'invalid_request', 'Client id is missing', stream_id, red, mode, state=state))
    
    try:
        authorization_details = request.args["authorization_details"]
    except Exception:
        return redirect(redirect_uri + '?' + authorization_error(request, 'invalid_request', 'Authorization details is missing', stream_id, red, mode, state=state))

    logging.info("redirect_uri = %s", redirect_uri)
    logging.info("code_challenge = %s", code_challenge)
    logging.info("client_metadata = %s", client_metadata)
    logging.info("authorization details = %s", authorization_details)
    logging.info("scope = %s", scope)
    
    if response_type != "code":
        return redirect(redirect_uri + '?' + authorization_error(request, 'invalid_response_type', 'response_type not supported', stream_id, red, mode, state=state))

    issuer_data = json.loads(db_api.read_oidc4vc_issuer(issuer_id))

    offer_data = json.loads(red.get(issuer_state).decode())
    vc = offer_data["vc"]
    credential_type = offer_data["credential_type"]

    # Code creation
    issuer_data = json.loads(db_api.read_oidc4vc_issuer(issuer_id))
    if profile[issuer_data["profile"]].get("pre-authorized_code_as_jwt"):
        code = oidc4vc.build_pre_authorized_code(
            issuer_data["jwk"],
            "https://self-issued.me/v2",
            mode.server + "sandbox/ebsi/issuer/" + issuer_id,
            issuer_data["verification_method"],
            nonce,
        )
    else:
        code = str(uuid.uuid1()) + '.' + str(uuid.uuid1()) + '.' + str(uuid.uuid1())

    code_data = {
        "credential_type": credential_type,
        "client_id": client_id,  # DID of the issuer
        "issuer_id": issuer_id,
        "issuer_state": issuer_state,
        "state": state,
        "stream_id": stream_id,
        "vc": vc,
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method,
    }
    red.setex(code, GRANT_LIFE, json.dumps(code_data))
    resp = {"code": code}
    if state:
        resp["state"] = state
    return redirect(redirect_uri + "?" + urlencode(resp))


# token endpoint
def issuer_token(issuer_id, red, mode):
    """
    https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-token-endpoint
    https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
    """
    logging.info("token endpoint request = %s", json.dumps(request.form))
    
    # error response https://datatracker.ietf.org/doc/html/rfc6749#section-4.2.2.1
    grant_type = request.form.get("grant_type")
    if not grant_type:
        return Response(**manage_error("invalid_request", "Request format is incorrect, grant is missing", red, mode, request=request))

    if grant_type == "urn:ietf:params:oauth:grant-type:pre-authorized_code" and not request.form.get("pre-authorized_code"):
        return Response(**manage_error("invalid_request", "Request format is incorrect, this grant type is not supported", red, mode, request=request))

    if grant_type == "urn:ietf:params:oauth:grant-type:pre-authorized_code":
        code = request.form.get("pre-authorized_code")
        user_pin = request.form.get("user_pin")
        logging.info("user_pin received = %s", user_pin)
    elif grant_type == "authorization_code":
        code = request.form.get("code")
    else:
        return Response(**manage_error("invalid_request", "Grant type not supported", red, mode, request=request))
    if not code:
        return Response(**manage_error("invalid_request", "Request format is incorrect, code is missing", red, mode, request=request))

    # TODO check code verifier
    logging.info("code = %s", code)

    # Code expired
    try:
        data = json.loads(red.get(code).decode())
    except Exception:
        return Response(**manage_error("access_denied", "Grant code expired", red, mode, request=request, status=404))
    
    stream_id = data['stream_id']
    
    # user PIN missing
    if data.get("user_pin_required") and not user_pin:
        return Response(**manage_error("invalid_request", "User pin is missing", red, mode, request=request, stream_id=stream_id))
    
    # wrong code verifier
    if grant_type == "authorization_code":
        code_verifier = request.form.get("code_verifier")
        code_challenge_calculated = pkce.get_code_challenge(code_verifier)
        if code_challenge_calculated != data['code_challenge']:
            return Response(**manage_error("access_denied", "Code verifier is incorrect", red, mode, request=request, stream_id=stream_id, status=404))
            
    # wrong PIN
    logging.info('user_pin = %s', data.get("user_pin"))
    if data.get("user_pin_required") and data.get("user_pin") != user_pin:
        return Response(**manage_error("access_denied", "User pin is incorrect", red, mode, request=request, stream_id=stream_id, status=404))

    # token response
    access_token = str(uuid.uuid1())
    vc = data.get("vc")
    endpoint_response = {
        "access_token": access_token,
        "c_nonce": str(uuid.uuid1()),
        "token_type": "Bearer",
        "expires_in": ACCESS_TOKEN_LIFE,
    }
    
    # authorization_details and multiple VC of the same type
    if isinstance(vc, list):
        authorization_details = []
        for vc_type in vc:
            types = vc_type["types"]
            vc_list = vc_type["list"]
            identifiers = [one_vc["identifier"] for one_vc in vc_list]
            authorization_details.append(
                {
                    "type": "openid_credential",
                    "locations": [
                        f"{mode.server}/sandbox/ebsi/issuer/api/{issuer_id}"
                    ],
                    "format": "jwt_vc",
                    "types": types,
                    "identifiers": identifiers,
                }
            )
        endpoint_response["authorization_details"] = authorization_details
    logging.info("token endpoint response = %s", endpoint_response)

    access_token_data = {
        "expires_at": datetime.timestamp(datetime.now()) + ACCESS_TOKEN_LIFE,
        "c_nonce": endpoint_response.get("c_nonce"),
        "credential_type": data.get("credential_type"),
        "vc": data.get("vc"),
        "stream_id": data.get("stream_id"),
        "issuer_state": data.get("issuer_state"),
    }

    red.setex(access_token, ACCESS_TOKEN_LIFE, json.dumps(access_token_data))

    headers = {"Cache-Control": "no-store", "Content-Type": "application/json"}
    return Response(response=json.dumps(endpoint_response), headers=headers)


# credential endpoint
async def issuer_credential(issuer_id, red, mode):
    """
    https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-endpoint

    """
    logging.info("credential endpoint request %s", json.dumps(request.json))
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
    issuer_data = json.loads(db_api.read_oidc4vc_issuer(issuer_id))
    logging.info("Profile = %s", issuer_data["profile"])
    # issuer_profile = profile[issuer_data['profile']]

    # Check request
    try:
        result = request.json
        vc_format = result["format"]
    except Exception:
        return Response(**manage_error("invalid_request", "Invalid request format", red, mode, request=request, stream_id=stream_id))

    proof = result.get("proof")
    if proof:
        proof_type = result["proof"]["proof_type"]
        proof = result["proof"]["jwt"]
        if proof_type != "jwt":
            return Response(**manage_error("unsupported_credential_type","The credential proof type is not supported", red, mode, request=request, stream_id=stream_id )            )
        # Check proof of key ownership received (OPTIONAL check)
        logging.info("proof of key ownership received = %s", proof)
        try:
            oidc4vc.verif_token(proof, access_token_data["c_nonce"])
            logging.info("proof of ownership is validated")
        except Exception as e:
            logging.warning("proof of ownership error = %s", e)
            return Response(**manage_error("access_denied", "Proof of key ownership, signature verification error : " + str(e), red, mode, request=request, stream_id=stream_id))
        proof_payload = oidc4vc.get_payload_from_token(proof)
    else:
        logging.warning('No proof available, Bearer credential)')
        proof_payload = None
        if vc_format == 'ldp_vc':
            return Response(**manage_error("access_denied", "Issuer does not support Bearer credential in ldp_vc format", red, mode, request=request, stream_id=stream_id))
        
    identifier = result.get("identifier")
    logging.info("identifier = %s", identifier)
    logging.info("credential request = %s", request.json)

    # check credential request format
    if not identifier and isinstance(access_token_data["vc"], list):
        return Response(
            **manage_error("unsupported_credential_type","identifier for multiple VC issuance expected", red, mode, request=request, stream_id=stream_id,
            )
        )

    # Get credential type requested
    if result.get("types"):
        found = False
        for vc_type in result["types"]:
            if vc_type not in ["VerifiableCredential", "VerifiableAttestation"]:
                credential_type = vc_type
                found = True
                break
        if not found:
            return Response(
                **manage_error("invalid_request", "VC type not found", red, mode, request=request, stream_id=stream_id))
    elif result.get("type"):
        credential_type = result["type"]
    else:
        return Response(**manage_error("invalid_request", "Invalid request format, type(s) is missing", red, mode, request=request, stream_id=stream_id))
    logging.info("credential type requested = %s", credential_type)

    # check credential format requested
    logging.info("proof format requested = %s", vc_format)
    if vc_format not in ["jwt_vc", "jwt_vc_json", "jwt_vc_json-ld", "ldp_vc"]:
        return Response(
            **manage_error(
                "invalid_or_missing_proof",
                "The proof format is invalid",
                red,
                mode,
                request=request,
                stream_id=stream_id,
            )
        )

    iss = proof_payload.get("iss") if proof else None

    # deferred use case
    
    if issuer_data.get("deferred_flow"):
        acceptance_token = str(uuid.uuid1())
        payload = {
            "acceptance_token": acceptance_token,
            "c_nonce": str(uuid.uuid1()),
            "c_nonce_expires_in": ACCEPTANCE_TOKEN_LIFE,
        }
        acceptance_token_data = {
            "issuer_id": issuer_id,
            "format": vc_format,
            "subjectId": iss,
            "issuer_state": access_token_data["issuer_state"],
            "credential_type": credential_type,
            "c_nonce": str(uuid.uuid1()),
            "c_nonce_expires_at": datetime.timestamp(datetime.now())
            + ACCEPTANCE_TOKEN_LIFE,
        }
        red.setex(
            acceptance_token, ACCEPTANCE_TOKEN_LIFE, json.dumps(acceptance_token_data)
        )
        headers = {"Cache-Control": "no-store", "Content-Type": "application/json"}
        return Response(response=json.dumps(payload), headers=headers)

    logging.info("credential type = %s", credential_type)

    if not identifier:
        logging.info("1 VC of the same type")
        try:
            credential = access_token_data["vc"][credential_type]
        except Exception:
            # send event to front to go forward callback and send credential to wallet
            return Response(
                **manage_error(
                    "unsupported_credential_type",
                    "The credential type is not offered",
                    red,
                    mode,
                    request=request,
                    stream_id=stream_id,
                )
            )
    else:
        found = False
        logging.info("Multiple VCs of the same type")
        for one_type in access_token_data["vc"]:
            if one_type["type"] == credential_type:
                for one_credential in one_type["list"]:
                    if one_credential["identifier"] == identifier:
                        credential = one_credential["value"]
                        found = True
                        break
                break
        if not found:
            return Response(
                **manage_error(
                    "unsupported_credential_type",
                    "The credential identifier is not found",
                    red,
                    mode,
                    request=request,
                    stream_id=stream_id,
                )
            )

    credential_signed = await sign_credential(
        credential,
        iss,
        issuer_data["did"],
        issuer_data["jwk"],
        issuer_data["verification_method"],
        access_token_data["c_nonce"],
        vc_format,
    )
    logging.info("credential signed sent to wallet = %s", credential_signed)

    # send event to front to go forward callback and send credential to wallet
    front_publish(access_token_data["stream_id"], red)

    # Transfer VC
    payload = {
        "format": vc_format,
        "credential": credential_signed,  # string or json depending on the format
        "c_nonce": str(uuid.uuid1()),
        "c_nonce_expires_in": C_NONCE_LIFE,
    }

    # update nonce in access token for next VC request
    access_token_data["c_nonce"] = payload["c_nonce"]
    red.setex(access_token, ACCESS_TOKEN_LIFE, json.dumps(access_token_data))
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
        return Response(
            **manage_error("invalid_request","Acceptance token not passed in request header", red, mode, request=request, status=400)        )

    # Offer expired, VC is no more available return 410
    try:
        acceptance_token_data = json.loads(red.get(acceptance_token).decode())
    except Exception:
        return Response(**manage_error("invalid_token", "Acceptance token expired", red, mode, request=request, status=410)
        )

    issuer_state = acceptance_token_data["issuer_state"]
    credential_type = acceptance_token_data["credential_type"]

    # VC is not ready return 404
    try:
        deferred_data = json.loads(red.get(issuer_state).decode())
        credential = deferred_data["deferred_vc"][credential_type]
    except Exception:
        return Response(**manage_error("invalid_token", "Credential is not available yet", red, mode, request=request, status=404))

    issuer_data = json.loads(db_api.read_oidc4vc_issuer(issuer_id))

    # sign_credential
    credential_signed = await sign_credential(
        credential,
        acceptance_token_data["subjectId"],
        issuer_data["did"],
        issuer_data["jwk"],
        issuer_data["verification_method"],
        acceptance_token_data["c_nonce"],
        acceptance_token_data["format"],
    )
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
    callback_uri = f"{callback}?issuer_state=" + user_data.get("issuer_state")
    if request.args.get("error"):
        callback_uri += "&error=" + request.args.get("error")
    if request.args.get("error_description"):
        callback_uri += "&error_description=" + request.args.get("error_description")
    print('callback uri = ', callback_uri)
    return redirect(callback_uri)


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


async def sign_credential(
    credential, wallet_did, issuer_did, issuer_key, issuer_vm, c_nonce, format
):
    credential["id"] = "urn:uuid:" + str(uuid.uuid1())
    credential["credentialSubject"]["id"] = wallet_did
    credential["issuer"] = issuer_did
    credential["issued"] = f"{datetime.now().replace(microsecond=0).isoformat()}Z"
    credential["issuanceDate"] = datetime.now().replace(microsecond=0).isoformat() + "Z"
    credential["validFrom"] = datetime.now().replace(microsecond=0).isoformat() + "Z"
    credential["expirationDate"] = (
        datetime.now() + timedelta(days=365)
    ).isoformat() + "Z"
    credential["validUntil"] = (datetime.now() + timedelta(days=365)).isoformat() + "Z"
    if format in ["jwt_vc", "jwt_vc_json", "jwt_vc_json-ld"]:
        credential_signed = oidc4vc.sign_jwt_vc(
            credential, issuer_vm, issuer_key, c_nonce
        )
    else:  #  proof_format == 'ldp_vc':
        didkit_options = {
            "proofPurpose": "assertionMethod",
            "verificationMethod": issuer_vm,
        }
        credential_signed = await didkit.issue_credential(
            json.dumps(credential),
            didkit_options.__str__().replace("'", '"'),
            issuer_key,
        )
        result = await didkit.verify_credential(credential_signed, "{}")
        logging.info("signature check with didkit = %s", result)
        credential_signed = json.loads(credential_signed)
    return credential_signed
