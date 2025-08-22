import os
import time
import markdown
from flask import Flask, redirect, request, render_template_string, jsonify, Response, render_template, send_file
from flask_mobility import Mobility
from flask_session import Session
from datetime import timedelta, datetime
from flask_qrcode import QRcode
import redis
import logging
import json
import environment
from components import message
from flask_restx import Resource, Api, fields
import uuid
import oidc4vc
from profile import profile
import db_api
import requests
from device_detector import SoftwareDetector
import hashlib
import base64
import AI_Agent


# Basic protocole
from routes import saas4ssi
# OIDC4VC
from routes import oidc4vp_api, oidc4vp_console
from routes import oidc4vci_api, oidc4vci_console
from routes import oauth_api
from routes import wallet


# for testing purpose
from routes import test_issuer_oidc4vc
from routes import test_verifier_oidc4vc
from routes import web_display_VP
from routes import waltid_server
from routes import mosip_issuer
from routes import statuslist


API_LIFE = 5000
#ACCESS_TOKEN_LIFE = 1000
GRANT_LIFE = 5000
ACCEPTANCE_TOKEN_LIFE = 28 * 24 * 60 * 60

with open("keys.json", "r") as f:
    ai_api_keys = json.load(f)["ai_api"]

logging.basicConfig(level=logging.INFO)

# Environment variables set in gunicornconf.py  and transfered to environment.py
mychain = os.getenv('MYCHAIN')
myenv = os.getenv('MYENV')
if not myenv:
    myenv='local'
mode = environment.currentMode(mychain, myenv)

# Redis init red = redis.StrictRedis()
red = redis.Redis(host='localhost', port=6379, db=0)

# Framework Flask and Session setup
app = Flask(__name__,
            static_url_path='/static') 

app.jinja_env.globals['Version'] = "0.6.0"
app.jinja_env.globals['Created'] = time.ctime(os.path.getctime('main.py'))
app.config['SESSION_PERMANENT'] = True
app.config['SESSION_COOKIE_NAME'] = 'altme_talao'
app.config['SESSION_TYPE'] = 'redis' # Redis server side session
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30) # cookie lifetime
app.config['SESSION_FILE_THRESHOLD'] = 100
app.config['SECRET_KEY'] = "sandbox" + mode.password
app.config["ALLOWED_IMAGE_EXTENSIONS"] = ["jpeg", "jpg", "png", "gif"]

# OIDC4VC issuer and verfier
oidc4vp_console.init_app(app, red, mode)
oidc4vp_api.init_app(app, red, mode)
oidc4vci_console.init_app(app, red, mode)
oidc4vci_api.init_app(app, red, mode)
oauth_api.init_app(app, red, mode)

#OIDC4VC web wallet
wallet.init_app(app, red, mode)

# MAIN functions
saas4ssi.init_app(app, red, mode)

# TEST
web_display_VP.init_app(app, red, mode)
test_issuer_oidc4vc.init_app(app, red, mode)
test_verifier_oidc4vc.init_app(app, red, mode)
statuslist.init_app(app, red, mode)
waltid_server.init_app(app, red, mode)
mosip_issuer.init_app(app, red, mode)

sess = Session()
sess.init_app(app)
qrcode = QRcode(app)
Mobility(app)


@app.errorhandler(403)
def page_abort(e):
    logging.warning('abort 403')
    return redirect(mode.server + 'login/')


@app.errorhandler(500)
def error_500(e):
    try:
        message.message("Error 500 on sandbox", 'thierry.thevenet@talao.io', str(e), mode)
    except Exception:
        pass
    return redirect(mode.server + '/sandbox')


def front_publish(stream_id, error=None, error_description=None):
    # send event to front channel to go forward callback and send credential to wallet
    data = {"stream_id": stream_id}
    if error:
        data["error"] = error
    if error_description:
        data["error_description"] = error_description
    red.publish("issuer_oidc", json.dumps(data))


def api_manage_error(error, error_description, stream_id=None, status=400):
    """
    Return error code to wallet and front channel
    https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-error-response
    """
    # console
    logging.warning("manage error = %s", error_description)
    payload = {
        "error": error,
        "error_description": error_description,
    }
    headers = {
        "Cache-Control": "no-store",
        "Content-Type": "application/json"
    }
    return {
        "response": json.dumps(payload),
        "status": status,
        "headers": headers
    }


def build_credential_offered(offer):
    credential_offered = dict()
    if isinstance(offer, str):
        offer = [offer]
    for vc in offer:
        try:
            with open('./verifiable_credentials/' + vc + '.jsonld', 'r') as f:
                credential = json.loads(f.read())
        except Exception:
            return
        credential['id'] = "urn:uuid:" + str(uuid.uuid4())
        credential['issuanceDate'] = datetime.now().replace(microsecond=0).isoformat() + "Z"
        #credential['issued'] = datetime.now().replace(microsecond=0).isoformat() + "Z"
        #credential['validFrom'] =  (datetime.now().replace(microsecond=0) + timedelta(days= 365)).isoformat() + "Z"
        credential['expirationDate'] =  (datetime.now().replace(microsecond=0) + timedelta(days= 365)).isoformat() + "Z"
        credential_offered[vc] = credential
    return credential_offered

@app.route('/md_file', methods=['GET'])
@app.route('/sandbox/md_file', methods=['GET'])
def md_file():
    # https://dev.to/mrprofessor/rendering-markdown-from-flask-1l41
    if request.args['file'] == 'privacy':
        content = open('privacy_en.md', 'r').read()
    elif request.args['file'] == 'terms_and_conditions':
        content = open('mobile_cgu_en.md', 'r').read()
    else:
        return redirect(mode.server + 'login/')
    return render_template_string( markdown.markdown(content, extensions=["fenced_code"]))


# Customer API for issuer - swagger support
authorizations = {
    'apikey': {
        'type': 'apiKey',
        'in': 'header',
        'name': 'X-API-KEY'
    }
}

api = Api(
    app,
    doc='/api/swagger',
    authorizations=authorizations,
    contact='contact@talao.io',
    description="API description for the Altme OIDC4VCI issuer.\n",
    titles="Altme issuer API"
)

ns = api.namespace('sandbox', description='To get the QR code value or the uri to redirect user browser to the QR code page created by the platform')

callback = mode.server + 'sandbox/issuer/callback'
offer = ["VerifiableId"]
vc = build_credential_offered(offer)

payload = api.model(
    'Payload input',
    {
        'issuer_id': fields.String(example="ooroomolyd", required=True),
        'vc': fields.Raw(example=vc),
        'deferred_vc': fields.String(),
        'issuer_state': fields.String(example='test', required=True),
        'credential_type': fields.List(fields.String, example=offer, required=True),
        'webhook': fields.String(),
        'pre-authorized_code': fields.Boolean(example=True, required=True),
        'user_pin_required': fields.Boolean(example=False),
        'user_pin': fields.String(),
        'input_length': fields.Integer(),
        "input_mode": fields.String(),
        "input_description": fields.String(),
        'callback': fields.String(example=callback, required=True),
    },
    description="API payload",
)


response = api.model(
    'Response',
    {
        'redirect_uri': fields.String(description='API response', required=True),
        'qrcode_value': fields.String(description='API response', required=True)
    }
)


@ns.route("/oidc4vc/issuer/api", endpoint='issuer')
class Issuer(Resource):
    @api.response(200, 'Success')
    @api.doc(responses={401: 'unauthorized'})
    @api.doc(responses={400: 'invalid request'})
    @api.doc(security='apikey')
    @api.expect(payload, validate=False)
    @api.doc(model=response)
    @api.doc(body=payload)
    def post(self):
        
        """
        This API returns the QRcode value and the page URL to redirect the user browser to a QR code to get her verifiable credential.

        headers = {
            'Content-Type': 'application/json',
            'X-API-KEY': '<issuer_secret>'
        }
        
        Swagger example: 
        issuer_id = ooroomolyd
        issuer_secret = f5fa78af-3aa9-11ee-a601-b33f6ebca22b
        

        payload = {
            "issuer_id": REQUIRED, see platform
            "vc": CONDITIONAL -> { "EmployeeCredendial": {@context: .....}, ....}, json object, VC as a json-ld not signed 
            "deferred_vc": CONDITIONAL, default is None REQUIRED if vc is nt sent 
            "issuer_state": REQUIRED, string,
            "credential_type": REQUIRED -> array of the credentials offered
            "pre-authorized_code": TRUE (authorized code flow not supported by swagger UI)
            "user_pin_required": OPTIONAL bool, default is false
            "user_pin": CONDITIONAL, string, REQUIRED if user_pin_required is True
            "callback": REQUIRED, string, this the user redirect route at the end of the flow
            }
        
        """
        # check API format
        try:
            client_secret = request.headers["X-API-KEY"]
        except Exception:
            return Response(**api_manage_error("unauthorized", "Unauthorized token", status=401))
        try:
            issuer_id = request.json["issuer_id"]
        except Exception:
            return Response(**api_manage_error("unauthorized", "Unauthorized token", status=401))
        try:
            issuer_data = json.loads(db_api.read_oidc4vc_issuer(issuer_id))
        except Exception:
            return Response(**api_manage_error("unauthorized", "Unauthorized client_id", status=401))
        try:
            issuer_state = request.json["issuer_state"]
        except Exception:
            return Response(**api_manage_error("invalid_request", "issuer_state missing"))
        try:
            credential_type = request.json["credential_type"]
        except Exception:
            return Response(**api_manage_error("invalid_request", "credential_type missing"))
        try:
            pre_authorized_code = request.json["pre-authorized_code"]
        except Exception:
            return Response(**api_manage_error("invalid_request", "pre-authorized_code is missing"))

        # check if client_id exists
        if client_secret != issuer_data["client_secret"]:
            logging.warning("Client secret is incorrect")
            return Response(**api_manage_error("unauthorized", "Client secret is incorrect", status=401))

        # Check vc and vc_deferred
        vc = request.json.get("vc")
        if vc and not request.json.get("callback"):
            return Response(**api_manage_error("invalid_request", "callback missing"))
    
        # Check deferred vc
        if issuer_data.get("deferred_flow"):
            deferred_vc = request.json.get("deferred_vc")
            if vc and deferred_vc:
                return Response(**api_manage_error("invalid_request", "deferred_vc and vc not allowed"))
        else:
            deferred_vc = None
        
        # Check if user pin exists
        if request.json.get("user_pin_required") and not request.json.get("user_pin"):
            return Response(**api_manage_error("invalid_request", "User pin is not set"))
        logging.info('user PIN stored =  %s', request.json.get("user_pin"))

        # check if user pin is string
        if request.json.get("user_pin_required") and request.json.get("user_pin") and not isinstance(request.json.get("user_pin"), str):
            return Response(**api_manage_error("invalid_request", "User pin must be string"))

        # check if credential offered is supported
        issuer_profile = profile[issuer_data["profile"]]
        credential_type = (
            credential_type if isinstance(credential_type, list) else [credential_type]
        )
        for _vc in credential_type:
            if _vc not in issuer_profile["credentials_types_supported"]:
                logging.error("Credential not supported -> %s", _vc)
                return Response(**api_manage_error("unauthorized", "Credential not supported " + _vc, status=401))
            
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
            "webhook": request.json.get("webhook"),
            "credential_type": credential_type,
            "pre-authorized_code": pre_authorized_code,
            "user_pin_required": request.json.get("user_pin_required"),
            "user_pin": request.json.get("user_pin"),
            "input_mode": request.json.get("input_mode"),
            "input_description": request.json.get("input_description"),
            "input_length": request.json.get("input_length"),
            "callback": request.json.get("callback"),
            "login": request.json.get("login"),
        }
        # For deferred API call only VC is stored in redis with issuer_state as key
        if deferred_vc and red.get(issuer_state): # red.get exists if the call without VC has been done previously
            session_data.update(
                {
                    "deferred_vc": deferred_vc,
                    "deferred_vc_iat": round(datetime.timestamp(datetime.now())), 
                    "deferred_vc_exp": round(datetime.timestamp(datetime.now())) + ACCEPTANCE_TOKEN_LIFE,
                }
            )
            red.setex(issuer_state, API_LIFE, json.dumps(session_data))
            logging.info("Deferred VC has been issued with issuer_state =  %s", issuer_state)
        else:
            # for authorization code flow
            red.setex(issuer_state, API_LIFE, json.dumps(session_data))

        # for pre authorized code
        if pre_authorized_code:
            red.setex(pre_authorized_code, GRANT_LIFE, json.dumps(session_data))

        # for front page management
        red.setex(stream_id, API_LIFE, json.dumps(session_data))
        
        # Get the QR code value from oidc4vci_api.py
        try:
            r = requests.get(mode.server + "sandbox/ebsi/issuer/qrcode/" + issuer_id + "/" + stream_id, timeout=10)
            qrcode_value = r.json()["qrcode_value"]
        except Exception:
            logging.error("QR code value error ")
            qrcode_value = ""
        
        # response to issuer
        api_response = {
            "redirect_uri": mode.server + "sandbox/ebsi/issuer/" + issuer_id + "/" + stream_id,
            "qrcode_value": qrcode_value
        }
        logging.info(
            "initiate qrcode = %s",
            mode.server + "sandbox/ebsi/issuer/" + issuer_id + "/" + stream_id,
        )
        return jsonify(api_response)


def hash(text):
    m = hashlib.sha256()
    m.update(text.encode())
    return base64.urlsafe_b64encode(m.digest()).decode().replace("=", "")


# download link with configuration
@app.route('/app/download', methods=['GET']) 
def app_download():
    configuration = {
        "login": request.args.get('login'),
        "password": request.args.get('password'),
        "wallet-provider": request.args.get('wallet-provider')
    }
    host = request.headers['X-Real-Ip']   #+ ' ' +  request.headers['User-Agent']
    host_hash = hash(host)
    logging.info('configuration : %s stored for wallet : %s',configuration, host)
    red.setex(host_hash, 300, json.dumps(configuration))
    return render_template('app_download/talao_app_download.html')


# callback link for browser problems
@app.route('/app/download/oidc4vc' , methods=['GET']) 
@app.route('/app/download/authorize' , methods=['GET']) 
@app.route('/app/download/callback' , methods=['GET']) 
def app_callback():
    return render_template('app_download/talao_app_download_callback.html')


@app.route('/install', methods=['GET'])
def link():
    configuration = {
        "login": request.args.get('login'),
        "password": request.args.get('password'),
        "wallet-provider": request.args.get('wallet-provider')
    }
    try:
        host = request.headers['X-Real-Ip'] #+ ' ' +  request.headers['User-Agent']
    except Exception:
        _message = "Not an https call"
        return render_template('app_download/install_link_error.html', message=_message)
        
    host_hash = hash(host)
    logging.info('configuration : %s stored for wallet : %s', configuration, host)
    red.setex(host_hash, 300, json.dumps(configuration))
    try:
        if request.MOBILE:
            ua = request.headers.get('User-Agent')
            device = SoftwareDetector(ua).parse()
            logging.info(device.os_name())
            if device.os_name() == "Android":
                return redirect('https://play.google.com/store/apps/details?id=co.talao.wallet')
            else:
                return redirect('https://apps.apple.com/fr/app/talao-wallet/id1582183266?platform=iphone')
        _message = "This installation link must be used through your smartphone"
        return render_template('app_download/install_link_error.html', message=_message)
    except Exception:
        _message = "Install link error"
        return render_template('app_download/install_link_error.html', message=_message)


# configuration for link to downloads with configuration
@app.route('/configuration' , methods=['GET']) 
def app_download_configuration():                           
    host = request.headers['X-Real-Ip'] # + ' ' + request.headers['User-Agent']
    host_hash = hash(host)
    logging.info('wallet call to get configuration = %s', host)
    try:
        configuration = json.loads(red.get(host_hash).decode())
        red.delete(host_hash)
        logging.info("Configuration sent to this wallet")
    except Exception:
        logging.warning("No configuration available for this wallet")
        configuration = {}
    return jsonify(configuration)


# Google universal link for Talao wallet
@app.route('/.well-known/assetlinks.json' , methods=['GET']) 
def assetlinks():
    document = json.load(open('assetlinks.json', 'r'))
    return jsonify(document)


# Apple universal link for Talao wallet
@app.route('/.well-known/apple-app-site-association' , methods=['GET']) 
def apple_app_site_association(): 
    document = json.load(open('apple-app-site-association', 'r'))
    return jsonify(document)


# .well-known DID API 
@app.route('/.well-known/did-configuration.json', methods=['GET'])
def well_known_did_configuration():
    document = json.load(open('well_known_did_configuration.jsonld', 'r'))
    headers = {
        "Content-Type": "application/did+ld+json",
        "Cache-Control": "no-cache"
    }
    return Response(json.dumps(document), headers=headers)


@app.route('/device_detector' , methods=['GET']) 
def device_detector():
    ua = request.headers.get('User-Agent')
    device = SoftwareDetector(ua).parse()
    logging.info(device.os_name())
    if device.os_name() == "Android":
        return redirect("https://play.google.com/store/apps/details?id=co.talao.wallet")
    else:
        return redirect("https://apps.apple.com/fr/app/talao-wallet/id1582183266?platform=iphone")


# .well-known DID API
@app.route('/.well-known/did.json', methods=['GET'])
@app.route('/did.json', methods=['GET'])
def well_known_did():
    """
    did:web:talao.co
    """
    DID_Document = json.load(open('DID_Document.json', 'r'))
    headers = {
        "Content-Type": "application/did+ld+json",
        "Cache-Control": "no-cache"
    }
    return Response(json.dumps(DID_Document), headers=headers)


# .well-known for walllet as authorization server
@app.route('/wallet_issuer/.well-known/openid-configuration', methods=['GET'])
@app.route('/wallet-issuer/.well-known/openid-configuration', methods=['GET'])
def wallet_issuer_well_known_did():
    wallet_issuer = json.load(open('wallet_metadata_for_verifiers.json', 'r'))
    headers = {
        "Content-Type": "application/json",
        "Cache-Control": "no-cache"
    }
    return Response(json.dumps(wallet_issuer), headers=headers)


# image server
@app.route('/image/bnb', methods=['GET'])
def bnb():
    filename = 'binance_card.jpg'
    return send_file(filename, mimetype='image/jpg')


@app.route('/image/inji', methods=['GET'])
def inji():
    filename = 'inji.png'
    return send_file(filename, mimetype='image/png')


# html page server
@app.route('/sandbox/oidc-ai')
def oidc_ai():
    return render_template('oidc_oidc4vc_ai.html')


# OpenAI tools for sandbox
@app.route('/qrcode', methods=['GET', 'POST'])
@app.route('/ai/qrcode', methods=['GET', 'POST'])
def qrcode():
    if  request.method == 'GET':
        with open("openai_counter.json", "r") as f:
            counter = json.load(f)
        request_number = str(counter["request_number"])
        return render_template("ai_qrcode.html", request_number=request_number)
    else:
        outfmt = request.form.get("outfmt", "text")
        model = request.form.get("mode", "flash")
        qrcode = request.form.get("qrcode")
        oidc4vci_draft = request.form.get("oidc4vci_draft")
        oidc4vp_draft = request.form.get("oidc4vp_draft")
        profile = request.form.get("profile")
        
        logging.info("qrcode = %s", qrcode)
        if not qrcode:
            return redirect('/qrcode')
        report = AI_Agent.analyze_qrcode(qrcode, oidc4vci_draft, oidc4vp_draft, profile, 'sandbox QR code', model)
        
        if outfmt == 'json':
            input = {
                "kind": "QR code analysis",
                "hash": hashlib.sha256(qrcode.encode("utf-8")).hexdigest()
            }
            report = AI_Agent.report_to_json_via_gpt(
                report,
                profile=profile,
                model="flash",
                input=input,
                drafts={"OIDCVCI": oidc4vci_draft, "0IDC4VP": oidc4vp_draft}
            )
            
            return Response(
                response=json.dumps(report, ensure_ascii=False, indent=2),
                mimetype="application/json; charset=utf-8",
                headers={"X-Content-Type-Options": "nosniff"}
            )
        
        return render_template("ai_report.html", back="/ai/qrcode", report= "\n\n" + report)



# OpenAI tools for sandbox
@app.route('/ai/vc', methods=['GET', 'POST'])
def vc():
    if  request.method == 'GET':
        with open("openai_counter.json", "r") as f:
            counter = json.load(f)
        request_number = str(counter["request_number"])
        return render_template("ai_vc.html", request_number=request_number)
    else:
        outfmt = request.form.get("outfmt", "text")
        model = request.form.get("mode", "flash")
        vc = request.form.get("vc")
        sdjwtvc_draft = request.form.get("sdjwtvc_draft")
        vcdm_draft = request.form.get("vcdm_draft")
        if not qrcode:
            return redirect('/ai/vc')
        report = AI_Agent.process_vc_format(vc, sdjwtvc_draft, vcdm_draft, "sandbox VC", model)
        print("report = ", report)
        if outfmt == 'json':
            input = {
                "kind": "VC analysis",
                "hash": hashlib.sha256(vc.encode("utf-8")).hexdigest()
            }
            report = AI_Agent.report_to_json_via_gpt(
                report,
                profile="",
                model="flash",
                input=input,
                drafts={"SD-JWT VC": sdjwtvc_draft, "W3C VCDM": vcdm_draft}
            )
            
            return Response(
                response=json.dumps(report, ensure_ascii=False, indent=2),
                mimetype="application/json; charset=utf-8",
                headers={"X-Content-Type-Options": "nosniff"}
            )
        return render_template("ai_report.html", back="/ai/vc", report= "\n\n" + report)
    

# OpenAI tools for wallet
@app.route('/ai/wallet/qrcode', methods=['POST'])
def qrcode_wallet():
    api_key = request.headers.get("Api-Key")
    if api_key not in ai_api_keys:
        return jsonify({"error": "access denied"}), 403
    qrcode_base64 = request.form.get("qrcode")
    if not qrcode_base64:
        return jsonify({"error": "missing qrcode"}), 400
    model = request.form.get('oidc4vciDraft', "escalation")
    oidc4vciDraft = request.form.get('oidc4vciDraft')
    oidc4vpDraft = request.form.get('oidc4vpDraft')
    profil = request.form.get('profil', 'custom')
    try:
        qrcode_str = base64.b64decode(qrcode_base64.encode()).decode()
    except Exception:
        return jsonify({"error": "invalid base64 format"}), 400
    try:
        report = AI_Agent.analyze_qrcode(qrcode_str, oidc4vciDraft, oidc4vpDraft, profil, 'wallet QR code', model)
    except Exception as e:
        logging.error("Error in analyze_qrcode: %s", e)
        return jsonify({"error": "internal processing error"}), 500
    logging.info("report = %s", report)
    report_base64 = base64.b64encode(report.encode()).decode()
    return report_base64


# OpenAI tools for wallet
@app.route('/ai/wallet/vc', methods=['POST'])
def vc_wallet():
    api_key = request.headers.get("Api-Key")
    if api_key not in ai_api_keys:
        return jsonify({"error": "access denied"}), 403
    vc_base64 = request.form.get("vc")
    model = request.form.get('oidc4vciDraft', "escalation")
    if not vc_base64:
        return jsonify({"error": "missing qrcode"}), 400
    try:
        vc_str = base64.b64decode(vc_base64.encode()).decode()
    except Exception:
        return jsonify({"error": "invalid base64 format"}), 400
    try:
        report = AI_Agent.process_vc_format(vc_str, "8", "1.1", "wallet VC", model)
    except Exception as e:
        logging.error("Error in analyze_qrcode: %s", e)
        return jsonify({"error": "internal processing error"}), 500
    logging.info("report = %s", report)
    report_base64 = base64.b64encode(report.encode()).decode()
    return report_base64


# ---------------------------
# /api/analyze-qrcode
# ---------------------------
@app.route('/api/analyze-qrcode', methods=['POST'])
def analyze_wallet_qrcode():
    """
    Analyze a wallet QR code with the AI agent and return a report.

    JSON Body
    ---------
    {
      "qrcode": "<base64-encoded QR code string>",                // required
      "oidc4vciDraft": "15",                                      // optional
      "oidc4vpDraft": "22",                                       // optional
      "profile": "EBSI",                                          // optional, default "custom"
      "format": "text" | "json",                                  // optional, default "text"
      "model": "flash" | "escalation" | "pro"                     // optional, default "flash"
    }
    """
    # api_key = request.headers.get("Api-Key")
    # if api_key not in ai_api_keys:
    #     return jsonify({"error": "access denied"}), 403

    # Parse JSON
    try:
        data = request.get_json(force=True)
    except Exception:
        return jsonify({"error": "invalid JSON body"}), 400

    if not data or "qrcode" not in data:
        return jsonify({"error": "missing 'qrcode' field"}), 400

    qrcode_base64 = data["qrcode"]
    oidc4vci_draft = data.get("oidc4vciDraft")
    oidc4vp_draft = data.get("oidc4vpDraft")
    profile = data.get("profile", "custom")
    model = data.get("model", "flash")
    output_format = data.get("format", "text")

    # Decode base64 QR content
    try:
        qrcode_str = base64.b64decode(qrcode_base64.encode("utf-8")).decode("utf-8")
    except Exception:
        return jsonify({"error": "invalid base64 for 'qrcode'"}), 400

    # Run the AI agent
    try:
        report = AI_Agent.analyze_qrcode(
            qrcode_str,
            oidc4vci_draft,
            oidc4vp_draft,
            profile,
            "QR code public API",
            model,
        )
    except Exception as e:
        logging.error("Error in analyze_qrcode: %s", e)
        return jsonify({"error": "internal processing error"}), 500

    # Structured JSON branch
    if output_format == "json":
        input_meta = {
            "kind": "QR code analysis",
            "hash": hashlib.sha256(qrcode_base64.encode("utf-8")).hexdigest(),
        }
        try:
            structured = AI_Agent.report_to_json_via_gpt(
                report,
                profile=profile,
                model="flash",
                input=input_meta,
                drafts={"OIDC4VCI": oidc4vci_draft, "OIDC4VP": oidc4vp_draft},
            )
        except Exception as e:
            logging.error("report_to_json_via_gpt failed: %s", e)
            return jsonify({"error": "internal processing error"}), 500

        return jsonify(structured), 200

    # Default: base64-encoded markdown
    report_base64 = base64.b64encode(report.encode("utf-8")).decode("utf-8")
    return jsonify({"report_base64": report_base64}), 200


# ---------------------------
# /api/analyze-vc
# ---------------------------
@app.route('/api/analyze-vc', methods=['POST'])
def api_analyze_vc():
    """
    Analyze a Verifiable Credential (VC) with the AI agent and return a report.

    JSON Body
    ---------
    {
      "vc": "<base64-encoded VC>",                                // required
      "sdjwtvc_draft": "12",                                      // optional
      "vcdm_draft": "2.0",                                        // optional
      "format": "text" | "json",                                  // optional, default "text"
      "model": "flash" | "escalation" | "pro"                     // optional, default "flash"
    }
    """
    # api_key = request.headers.get("Api-Key")
    # if api_key not in ai_api_keys:
    #     return jsonify({"error": "access denied"}), 403

    # Parse JSON
    try:
        data = request.get_json(force=True)
    except Exception:
        return jsonify({"error": "invalid JSON body"}), 400

    vc_b64 = (data or {}).get("vc")
    if not vc_b64:
        return jsonify({"error": "missing 'vc' field"}), 400

    sdjwtvc_draft = data.get("sdjwtvc_draft")
    vcdm_draft = data.get("vcdm_draft")
    model = data.get("model", "flash")
    output_format = data.get("format", "text")

    # Decode base64 VC content
    try:
        vc_str = base64.b64decode(vc_b64.encode("utf-8")).decode("utf-8")
    except Exception:
        return jsonify({"error": "invalid base64 for 'vc'"}), 400

    # Run the AI agent
    try:
        report = AI_Agent.process_vc_format(
            vc_str,
            sdjwtvc_draft,
            vcdm_draft,
            "analyze VC API",
            model,
        )
    except Exception as e:
        logging.error("VC analysis failed: %s", e)
        return jsonify({"error": "internal processing error"}), 500

    # Structured JSON branch
    if output_format == "json":
        input_meta = {
            "kind": "VC analysis",
            "hash": hashlib.sha256(vc_b64.encode("utf-8")).hexdigest(),
        }
        try:
            structured = AI_Agent.report_to_json_via_gpt(
                report,
                profile="",
                model="flash",
                input=input_meta,
                drafts={"SD-JWT VC": sdjwtvc_draft, "W3C VCDM": vcdm_draft},
            )
        except Exception as e:
            logging.error("report_to_json_via_gpt failed: %s", e)
            return jsonify({"error": "internal processing error"}), 500

        return jsonify(structured), 200

    # Default: base64-encoded markdown
    report_base64 = base64.b64encode(report.encode("utf-8")).decode("utf-8")
    return jsonify({"report_base64": report_base64}), 200



@app.route('/marketplace', methods=['GET'])
def marketplace():
    return render_template("marketplace.html")



@app.route('/.well-known/trusted-list.json', methods=['GET'])
def trusted_list_api():
    trusted_list = json.load(open('trusted-list.json', 'r'))
    return jsonify(trusted_list)


@app.route('/documentation/<page>')
def show_markdown_page(page):
    try:
        with open(f"documentation/{page}.md", "r") as f:
            content = f.read()
    except FileNotFoundError:
        return "Page not found", 404
    html_content = markdown.markdown(content, extensions=["tables", "fenced_code"])
    return render_template("markdown_template.html", page=page, html_content=html_content)



# MAIN entry point for test
if __name__ == '__main__':
    # info release
    logging.info('flask test serveur run with debug mode')
    app.run(host=mode.flaskserver,
            port=mode.port,
            debug=mode.test,
            threaded=True)
    
