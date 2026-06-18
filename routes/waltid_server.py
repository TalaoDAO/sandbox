from flask import Flask, render_template_string
from flask_qrcode import QRcode
import requests
from flask_session import Session
import redis
import json


# Redis init red = redis.StrictRedis()
red= redis.Redis(host='localhost', port=6379, db=0)

# Init Flask
app = Flask(__name__)

# Framework Flask and Session setup
app.config['SESSION_PERMANENT'] = True
app.config['SESSION_COOKIE_NAME'] = 'talao'
app.config['SESSION_TYPE'] = 'redis'
app.config['SESSION_FILE_THRESHOLD'] = 100

sess = Session()
sess.init_app(app)
qrcode = QRcode(app)


def init_app(app, red, mode):
    app.add_url_rule('/sandbox/issuer/waltid/test',  view_func=waltid, methods=['GET', 'POST'])
    return

payload = {
    "issuerKey": {
        "type": "jwk",
        "jwk": {
        "kty": "OKP",
        "d": "JvJIpga2GD8LJeRu4Sv-mL4thE31DuFlr9PA04CIoZY",
        "crv": "Ed25519",
        "kid": "iJMS5bkZVIlncfq_Lf_SuxJ2JtQ5Hvaz7tWPnAjUUds",
        "x": "FZdvwC8aGhRwqzWptej0NZgtwYAI1SyFg1mKDETOfqE"
        }
    },
    "issuerDid": "did:jwk:eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5Iiwia2lkIjoiaUpNUzVia1pWSWxuY2ZxX0xmX1N1eEoySnRRNUh2YXo3dFdQbkFqVVVkcyIsIngiOiJGWmR2d0M4YUdoUndxeldwdGVqME5aZ3R3WUFJMVN5RmcxbUtERVRPZnFFIn0",
    "credentialConfigurationId": "UniversityDegree_jwt_vc_json",
    "credentialData": {
        "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://www.w3.org/2018/credentials/examples/v1"
        ],
        "id": "http://example.gov/credentials/3732",
        "type": [
        "VerifiableCredential",
        "UniversityDegree"
        ],
        "issuer": {
        "id": "did:web:vc.transmute.world"
        },
        "issuanceDate": "2020-03-10T04:24:12.164Z",
        "credentialSubject": {
        "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
        "degree": {
            "type": "BachelorDegree",
            "name": "Bachelor of Science and Arts"
        }
        }
    },
    "mapping": {
        "id": "<uuid>",
        "issuer": {
        "id": "<issuerDid>"
        },
        "credentialSubject": {
        "id": "<subjectDid>"
        },
        "issuanceDate": "<timestamp>",
        "expirationDate": "<timestamp-in:365d>"
    },
    "authenticationMethod": "PRE_AUTHORIZED",
    "standardVersion": "DRAFT13"
    }



def waltid():
    url = 'https://issuer.demo.walt.id/openid4vc/jwt/issue'
    headers = {
        'Content-Type': 'application/json'
    }
    resp = requests.post(url, headers=headers, data=json.dumps(payload), timeout=10)
    if resp.status_code > 399 :
        print("status code = ", resp.content)
    code = resp.text
    html_string = """<html><head></head>
                        <body><div>     
                        <img src="{{ qrcode('""" + code + """') }}">
                        </div>
                        </body></html>"""
    return render_template_string(html_string) 



