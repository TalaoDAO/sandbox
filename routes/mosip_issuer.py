from flask import Flask, render_template_string
import json
from urllib.parse import urlencode


#  https://injicertify-academic.dev2.mosip.net/.well-known/openid-credential-issuer
# https://keycloak-26.dev2.mosip.net/auth/realms/inji-dev


ISSUER = "https://injicertify-academic.collab.mosip.net"
AS = "https://keycloak-26.collab.mosip.net/auth/realms/inji-collab"

OFFER = {
    "credential_issuer": ISSUER,
    "credential_configuration_ids": [
        "UniversityCredential",
        "University_Credential_SD_JWT"

    ],
    "grants": {
        "authorization_code": {
            "authorization_server": AS
        }
    }
}

OFFER_1 = {
    "credential_issuer": ISSUER,
    "credential_configuration_ids": [
        "UniversityCredential",
    ],
    "grants": {
        "authorization_code": {
            "authorization_server": AS
        }
    }
}



OFFER_2 = {
    "credential_issuer": ISSUER,
    "credential_configuration_ids": [
        "University_Credential_SD_JWT"
    ],
    "grants": {
        "authorization_code": {
            "authorization_server": AS
        }
    }
}





def init_app(app, red, mode):
    app.add_url_rule('/sandbox/issuer/mosip',  view_func=mosip, methods=['GET'])
    app.add_url_rule('/sandbox/issuer/mosip1',  view_func=mosip1, methods=['GET'])
    app.add_url_rule('/sandbox/issuer/mosip2',  view_func=mosip2, methods=['GET'])

    return



def mosip():
    code = "openid-credential-offer://?" + urlencode({"credential_offer": json.dumps(OFFER)})
    code_deeplink = "talao-" + code
    print(code_deeplink)
    button = '<a href ="' + code + '"><button><h1>Wallet deeplink for same device mode</h1></button></a>'
    html_string = """<html><head></head>
                        <body><div><div>  <center>   
                        <h1>""" + OFFER["credential_configuration_ids"][0] + """</h1><br>
                        <img src="{{ qrcode('""" + code + """') }}"> <br>
                          <p>{{code}}</p>
                        <br><br>""" + button + """</center></div></div></body></html>"""
                       
    return render_template_string(html_string, code=code)


def mosip1():
    code = "openid-credential-offer://?" + urlencode({"credential_offer": json.dumps(OFFER_1)})
    code_deeplink = "talao-" + code
    print(code_deeplink)
    button = '<a href ="' + code + '"><button><h1>Wallet deeplink for same device mode</h1></button></a>'
    html_string = """<html><head></head>
                        <body><div><div>  <center>   
                        <h1>""" + OFFER_1["credential_configuration_ids"][0] + """</h1><br>
                        <img src="{{ qrcode('""" + code + """') }}"> <br>
                          <p>{{code}}</p>
                        <br><br>""" + button + """</center></div></div></body></html>"""
                       
    return render_template_string(html_string, code=code)


def mosip2():
    code = "openid-credential-offer://?" + urlencode({"credential_offer": json.dumps(OFFER_2)})
    code_deeplink = "talao-" + code
    print(code_deeplink)
    button = '<a href ="' + code + '"><button><h1>Wallet deeplink for same device mode</h1></button></a>'
    html_string = """<html><head></head>
                        <body><div><div>  <center>   
                        <h1>""" + OFFER_2["credential_configuration_ids"][0] + """</h1><br>
                        <img src="{{ qrcode('""" + code + """') }}"> <br>
                        <p>{{code}}</p>
                        <br><br>""" + button + """</center></div></div></body></html>"""
                       
    return render_template_string(html_string, code=code)







# openid4vp://?client_id=injiverify.dev-int-inji.mosip.net&response_type=vp_token&response_mode=direct_post&nonce=MTc1MDc2OTcxMDU2MQ%3D%3D&state=req_e8ec2d33-3092-44c8-9f39-a49673f953a8&response_uri=https%3A%2F%2Finjiverify.dev-int-inji.mosip.net%2Fv1%2Fverify%2Fvp-submission%2Fdirect-post&presentation_definition=%7B%22id%22%3A%22c4822b58-7fb4-454e-b827-f8758fe27f9a%22%2C%22purpose%22%3A%22Relying+party+is+requesting+your+digital+ID+for+the+purpose+of+Self-Authentication%22%2C%22format%22%3A%7B%22ldp_vc%22%3A%7B%22proof_type%22%3A%5B%22Ed25519Signature2020%22%5D%7D%7D%2C%22input_descriptors%22%3A%5B%7B%22id%22%3A%22id+card+credential%22%2C%22format%22%3A%7B%22ldp_vc%22%3A%7B%22proof_type%22%3A%5B%22RsaSignature2018%22%5D%7D%7D%2C%22constraints%22%3A%7B%22fields%22%3A%5B%7B%22path%22%3A%5B%22%24.type%22%5D%2C%22filter%22%3A%7B%22type%22%3A%22object%22%2C%22pattern%22%3A%22MOSIPVerifiableCredential%22%7D%7D%5D%7D%7D%5D%7D&client_metadata=%7B%22client_name%22%3A%22injiverify.dev-int-inji.mosip.net%22%2C%22vp_formats%22%3A%7B%22ldp_vp%22%3A%7B%22proof_type%22%3A%5B%22Ed25519Signature2018%22%2C%22Ed25519Signature2020%22%2C%22RsaSignature2018%22%5D%7D%7D%7D