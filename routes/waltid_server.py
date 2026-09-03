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
  "profileId": "identityCredentialSdJwt",
  "authMethod": "PRE_AUTHORIZED",
  "txCode": {
    "input_mode": "numeric",
    "length": 6,
    "description": "Enter the PIN shown by the issuer"
  },
  "txCodeValue": "123456"
}



def waltid():
    url = 'https://issuer2.demo.walt.id/issuer2/credential-offers'
    headers = {
        'Content-Type': 'application/json'
    }
    resp = requests.post(url, headers=headers, data=json.dumps(payload), timeout=10)
    if resp.status_code > 399 :
        print("status code = ", resp.content)
        
    code = resp.json().get("credentialOffer")
    print("qrcode = ", code)
    html_string = """<html><head></head>
    <h1> TX code 123456 </h1>
    <h3>{{code}}</h3>
                        <body><div>     
                        <img src="{{ qrcode('""" + code + """') }}">
                        </div>
                        </body></html>"""
    return render_template_string(html_string, code=code) 



