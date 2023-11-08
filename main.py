import os
import time
import markdown
from flask import Flask, redirect, request, render_template_string, request, jsonify, Response, render_template
from flask_session import Session
from flask_mobility import Mobility
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
from device_detector import SoftwareDetector


# Basic protocole
#from routes import verifier_console, api_verifier
from routes import saas4ssi
# OIDC4VC
from routes import oidc4vp_api, oidc4vp_console
from routes import oidc4vci_api, oidc4vci_console
# for testing purpose
from routes import test_issuer_oidc4vc
from routes import test_verifier_oidc4vc
from routes import  web_wallet_test
from routes import web_display_VP


API_LIFE = 5000
#ACCESS_TOKEN_LIFE = 1000
GRANT_LIFE = 5000
ACCEPTANCE_TOKEN_LIFE = 28 * 24 * 60 * 60

logging.basicConfig(level=logging.INFO)

# Environment variables set in gunicornconf.py  and transfered to environment.py
mychain = os.getenv('MYCHAIN')
myenv = os.getenv('MYENV')
if not myenv :
    myenv='local'
mode = environment.currentMode(mychain, myenv)

# Redis init red = redis.StrictRedis()
red = redis.Redis(host='localhost', port=6379, db=0)


# Framework Flask and Session setup
#app = Flask(__name__)

app = Flask(__name__,
            static_url_path='/static') 


app.jinja_env.globals['Version'] = "0.3.0"
app.jinja_env.globals['Created'] = time.ctime(os.path.getctime('main.py'))
app.config['SESSION_PERMANENT'] = True
app.config['SESSION_COOKIE_NAME'] = 'altme_talao'
app.config['SESSION_TYPE'] = 'redis' # Redis server side session
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30) # cookie lifetime
app.config['SESSION_FILE_THRESHOLD'] = 100
app.config['SECRET_KEY'] = "sandbox" + mode.password
app.config["ALLOWED_IMAGE_EXTENSIONS"] = ["jpeg", "jpg", "png", "gif"]

# BASIC wallet protocol
#api_verifier.init_app(app, red, mode)
#api_issuer.init_app(app, red, mode)
#verifier_console.init_app(app, red, mode)
#issuer_console.init_app(app, red, mode)
# OIDC4VC wallet
oidc4vp_console.init_app(app, red, mode)
oidc4vp_api.init_app(app, red, mode)
oidc4vci_console.init_app(app, red, mode)
oidc4vci_api.init_app(app, red, mode)
# MAIN functions
saas4ssi.init_app(app, red, mode)

# TEST
web_display_VP.init_app(app, red, mode)
web_wallet_test.init_app(app, red, mode)
test_issuer_oidc4vc.init_app(app, red, mode)
test_verifier_oidc4vc.init_app(app, red, mode)

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
    message.message("Error 500 on sandbox", 'thierry.thevenet@talao.io', str(e), mode)
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
        credential['issued'] = datetime.now().replace(microsecond=0).isoformat() + "Z"
        credential['validFrom'] =  (datetime.now().replace(microsecond=0) + timedelta(days= 365)).isoformat() + "Z"
        credential['expirationDate'] =  (datetime.now().replace(microsecond=0) + timedelta(days= 365)).isoformat() + "Z"
        credential_offered[vc] = credential
    return credential_offered

@app.route('/md_file', methods=['GET'])
@app.route('/sandbox/md_file', methods=['GET'])
def md_file():
    # https://dev.to/mrprofessor/rendering-markdown-from-flask-1l41
    if request.args['file'] == 'privacy' :
        content = open('privacy_en.md', 'r').read()
    elif request.args['file'] == 'terms_and_conditions' :
        content = open('mobile_cgu_en.md', 'r').read()
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

ns = api.namespace('sandbox', description='To get the uri to redirect user browser to the QR code page created by the platform')

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
        'pre-authorized_code': fields.Boolean(example=True, required=True),
        'user_pin_required': fields.Boolean(example=False),
        'user_pin': fields.String(),
        'callback': fields.String(example=callback, required=True),
    },
    description="API payload",
)


response = api.model(
    'Response',
    {
        'redirect_uri': fields.String(description='API response', required=True),
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
        This API returns the QRcode page URL to redirect the user browser to the QR code to get her verifiable credential.

        headers = {
            'Content-Type': 'application/json',
            'X-API-KEY': '<issuer_secret>'
        }
        
        Swagger example : 
        issuer_id = ooroomolyd
        issuer_secret = f5fa78af-3aa9-11ee-a601-b33f6ebca22b
        

        payload = {
            "issuer_id": REQUIRED, see platform
            "vc": CONDITIONAL -> { "EmployeeCredendial": {@context : .....}, ....}, json object, VC as a json-ld not signed 
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
            "credential_type": credential_type,
            "pre-authorized_code": pre_authorized_code,
            "user_pin_required": request.json.get("user_pin_required"),
            "user_pin": request.json.get("user_pin"),
            "callback": request.json.get("callback"),
            "login": request.json.get("login"),
        }
        print("vc in main API = ", vc)
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
            logging.info("Deferred VC has been issued with issuer_state =  %s", issuer_state)
        else:
            # for authorization code flow
            red.setex(issuer_state, API_LIFE, json.dumps(session_data))

        # for pre authorized code
        if pre_authorized_code:
            red.setex(pre_authorized_code, GRANT_LIFE, json.dumps(session_data))

        # for front page management
        red.setex(stream_id, API_LIFE, json.dumps(session_data))
        response = {
            "redirect_uri": mode.server + "sandbox/ebsi/issuer/" + issuer_id + "/" + stream_id
        }
        logging.info(
            "initiate qrcode = %s",
            mode.server + "sandbox/ebsi/issuer/" + issuer_id + "/" + stream_id,
        )
        return jsonify(response)


# Google universal link
@app.route('/.well-known/assetlinks.json' , methods=['GET']) 
def assetlinks(): 
    document = json.load(open('assetlinks.json', 'r'))
    return jsonify(document)


# Apple universal link
@app.route('/.well-known/apple-app-site-association' , methods=['GET']) 
def apple_app_site_association(): 
    document = json.load(open('apple-app-site-association', 'r'))
    return jsonify(document)


# .well-known DID API 
@app.route('/.well-known/did-configuration.json', methods=['GET'])
def well_known_did_configuration():
    document = json.load(open('well_known_did_configuration.jsonld', 'r'))
    headers = {
        "Content-Type" : "application/did+ld+json",
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
@app.route('/.well-known/did.json', methods=['GET'], defaults={'mode' : mode})
@app.route('/did.json', methods=['GET'])
def well_known_did():
    """
    did:web:talao.co
    https://w3c-ccg.github.io/did-method-web/
    https://identity.foundation/.well-known/resources/did-configuration/#LinkedDomains
    """
    DidDocument = did_doc()
    headers = {
        "Content-Type" : "application/did+ld+json",
        "Cache-Control" : "no-cache"
    }
    return Response(json.dumps(DidDocument), headers=headers)


def did_doc():
    return {
        "@context": 
            [
                "https://www.w3.org/ns/did/v1",
                {
                    "@id": "https://w3id.org/security#publicKeyJwk",
                    "@type": "@json"
                }
            ],
            "id": "did:web:talao.co",
            "verificationMethod":
                [
                    {
                        "id": "did:web:talao.co#key-1",
                        "type": "JwsVerificationKey2020",
                        "controller": "did:web:talao.co",
                        "publicKeyJwk": {
                            "e":"AQAB",
                            "kid": "did:web:talao.co#key-1",
                            "kty": "RSA",
                            "n": "mIPHiLUlfIwj9udZARJg5FlyXuqMsyGHucbA-CqpJh98_17Qvd51SAdg83UzuCihB7LNYXEujnzEP5J5mAWsrTi0G3CRFk-pU_TmuY8p57M_NXvB1EJsOrjuki5HmcybzfkJMtHydD7gVotPoe-W4f8TxWqB54ve4YiFczG6A43yB3lLCYZN2wEWfwKD_FcaC3wKWdHFxqLkrulD4pVZQ_DwMNuf2XdCvEzpC33ZsU3DB6IxtcSbVejGCyq5EXroIh1-rp6ZPuCGExg8CjiLehsWvOmBac9wO74yfo1IF6PIrQQNkFA3vL2YWjp3k8SO0PAaUMF44orcUI_OOHXYLw"
                        }
                    },
                    {
                        "id": "did:web:talao.co#key-2",
                        "type": "JwsVerificationKey2020",
                        "controller": "did:web:talao.co",
                        "publicKeyJwk": {
                            "crv": "P-256",
                            "kty": "EC",
                            "x": "Bls7WaGu_jsharYBAzakvuSERIV_IFR2tS64e5p_Y_Q",
                            "y": "haeKjXQ9uzyK4Ind1W4SBUkR_9udjjx1OmKK4vl1jko"
                        }
                    },
                    {
                        "id": "did:web:talao.co#key-3",
                        "type": "JwsVerificationKey2020",
                        "controller": "did:web:talao.co",
                        "publicKeyJwk": {
                            "crv": "Ed25519",
                            "kty": "OKP",
                            "x": "FUoLewH4w4-KdaPH2cjZbL--CKYxQRWR05Yd_bIbhQo"
                        }
                    },
                ],
            "authentication" : [
                "did:web:talao.co#key-1",
            ],
            "assertionMethod" : [
                "did:web:talao.co#key-1",
                "did:web:talao.co#key-2",
                "did:web:talao.co#key-3"
            ],
            "keyAgreement" : [
                "did:web:talao.co#key-3"
            ],
            "capabilityInvocation":[
                "did:web:talao.co#key-1"
            ],
            "service": [
                {
                    "id": 'did:web:talao.co#domain-1',
                    "type": 'LinkedDomains',
                    "serviceEndpoint": "https://talao.co"
                }
            ]
        }


# MAIN entry point for test
if __name__ == '__main__':
    # info release
    logging.info('flask test serveur run with debug mode')
    app.run(host=mode.flaskserver,
            port=mode.port,
            debug=mode.test,
            threaded=True)
    
