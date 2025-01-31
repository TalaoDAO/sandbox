from flask import Flask, render_template_string
import json
from urllib.parse import urlencode


OFFER = {
    "credential_issuer": "https://injicertify-mosipid.collab.mosip.net/v1/certify/issuance",
    "credential_configuration_ids": [
        "MosipVerifiableCredential"
    ],
    "grants": {
        "authorization_code": {
            "authorization_server": "https://esignet-mosipid.collab.mosip.net"
        }
    }
}

"""
openid-credential-offer://?credential_offer=%7B%22credential_issuer%22%3A+%22https%3A%2F%2Ftalao.co%2Fissuer%2Fpexkhrzlmj%22%2C+%22credential_configuration_ids%22%3A+%5B%22Pid%22%5D%2C+%22grants%22%3A+%7B%22authorization_code%22%3A+%7B%22issuer_state%22%3A+%22test9%22%2C+%22authorization_server%22%3A+%22https%3A%2F%2Ftalao.co%2Fissuer%2Fpexkhrzlmj%2Fstandalone%22%7D%7D%7D

"""


def init_app(app, red, mode):
    app.add_url_rule('/sandbox/issuer/mosip',  view_func=mosip, methods=['GET'])
    return


def mosip():
    code = "openid-credential-offer://?" + urlencode({"credential_offer": json.dumps(OFFER)})
    html_string = """<html><head></head>
                        <body><div>     
                        <img src="{{ qrcode('""" + code + """') }}">
                        </div>
                        </body></html>"""
    return render_template_string(html_string)

