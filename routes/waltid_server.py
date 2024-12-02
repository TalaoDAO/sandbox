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
            "kty": "EC",
            "d": "uTIT47GfSlRa0Da4CsyoIZpjjwQLFxmL2qmBuzZpEy0",
            "crv": "P-256",
            "kid": "FsHUZY4_tDJDvxdp5B6moS1kwpP7PBekw4KfK7m0LCU",
            "x": "keR9l4u1SaZKMZ7wHvj_3z44vP0sa3nlzrnc8UjpQV0",
            "y": "pmcaedg5dtc2R6ZPZfWCBY56_M_5fUZgsz4LWD0mG8U"
        } 
    },
    "issuerDid": "https://issuer.didaas.org",
    "credentialConfigurationId": "CustomEmployeeCredential_vc+sd-jwt",
    "credentialData": {
        "employee": {
            "name": "Dentsu Taro",
            "employeeId": "12346",
            "jobTitle": "Software Engineer",
            "department": "Engineering",
            "employmentStartDate": "2022-01-01",
            "employer": {
                "name": "TechCorp Ltd.",
                "id": "did:web:techcorp.com"
            }
        }
    },
    "selectiveDisclosure": {
        "fields": {
            "employee": {
                "sd": True,
                "children": {
                    "fields": {
                        "name": {
                            "sd": False
                        },
                        "employeeId": {
                            "sd": True
                        },
                        "jobTitle": {
                            "sd": False
                        },
                        "department": {
                            "sd": True
                        },
                        "employmentStartDate": {
                            "sd": False
                        },
                        "employer": {
                            "sd": False
                        }
                    }
                }
            }
        }
    },
    "authenticationMethod": "PRE_AUTHORIZED"
}



def waltid():
    url = "https://issuer.didaas.org/openid4vc/jwt/issue"
    headers = {
        'Content-Type': 'application/json'
    }
    resp = requests.post(url, headers=headers, data=json.dumps(payload)) 
    if resp.status_code > 399 :
        print("status code = ", resp.content)
    code = resp.text
    html_string = """<html><head></head>
                        <body><div>     
                        <img src="{{ qrcode('""" + code + """') }}">
                        </div>
                        </body></html>"""
    return render_template_string(html_string) 



