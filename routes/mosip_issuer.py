from flask import Flask, render_template_string
import json
from urllib.parse import urlencode


#  https://injicertify-academic.dev2.mosip.net/.well-known/openid-credential-issuer
# https://keycloak-26.dev2.mosip.net/auth/realms/inji-dev

OFFER = {
    "credential_issuer": "https://injicertify-academic.dev2.mosip.net",
    "credential_configuration_ids": [
        "UniversityCredential"
    ],
    "grants": {
        "authorization_code": {
            "authorization_server": "https://keycloak-26.dev2.mosip.net/auth/realms/inji-dev"
        }
    }
}

OFFER_NEW = {
    "credential_issuer": "https://injicertify-academic.dev-int-inji.mosip.net",
    "credential_configuration_ids": [
        "UniversityCredential"
    ],
    "grants": {
        "authorization_code": {
            "authorization_server": "https://keycloak-26.collab.mosip.net/auth/realms/inji"
        }
    }
}

OFFER2 = {
    "credential_issuer": "https://injicertify-landregistry.qa-inji1.mosip.net",
    "credential_configuration_ids": [
        "LandStatementCredential"
    ],
    "grants": {
        "authorization_code": {
            "authorization_server": "https://esignet-mock.released.mosip.net"
        }
    }
}







"""
openid-credential-offer://?credential_offer=%7B%22credential_issuer%22%3A+%22https%3A%2F%2Ftalao.co%2Fissuer%2Fpexkhrzlmj%22%2C+%22credential_configuration_ids%22%3A+%5B%22Pid%22%5D%2C+%22grants%22%3A+%7B%22authorization_code%22%3A+%7B%22issuer_state%22%3A+%22test9%22%2C+%22authorization_server%22%3A+%22https%3A%2F%2Ftalao.co%2Fissuer%2Fpexkhrzlmj%2Fstandalone%22%7D%7D%7D

"""


def init_app(app, red, mode):
    app.add_url_rule('/sandbox/issuer/mosip',  view_func=mosip, methods=['GET'])
    app.add_url_rule('/sandbox/issuer/mosip2',  view_func=mosip2, methods=['GET'])

    return


def mosip():
    code = "openid-credential-offer://?" + urlencode({"credential_offer": json.dumps(OFFER_NEW)})
    code_deeplink = "talao-" + code
    print(code_deeplink)
    button = '<a href ="' + code + '"><button><h1>Wallet deeplink for same device mode</h1></button></a>'
    html_string = """<html><head></head>
                        <body><div><div>  <center>   
                        <img src="{{ qrcode('""" + code + """') }}"> <br>
                          <p>{{code}}</p>
                        <br><br>""" + button + """</center></div></div></body></html>"""
                       
    return render_template_string(html_string, code=code)


def mosip2():
    code = "openid-credential-offer://?" + urlencode({"credential_offer": json.dumps(OFFER2)})
    code_deeplink = "talao-" + code
    print(code_deeplink)
    button = '<a href ="' + code + '"><button><h1>Wallet deeplink for same device mode</h1></button></a>'
    html_string = """<html><head></head>
                        <body><div><div>  <center>   
                        <img src="{{ qrcode('""" + code + """') }}"> <br>
                        <p>{{code}}</p>
                        <br><br>""" + button + """</center></div></div></body></html>"""
                       
    return render_template_string(html_string, code=code)
