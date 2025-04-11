
import json
import openai
from openai import OpenAI
from urllib.parse import parse_qs, urlparse
import requests
from datetime import datetime
import hashlib
import base64

# Remplace par ta clé API
openapi_key = json.load(open("keys.json", "r"))['openai']

ENGINE = "gpt-3.5-turbo"
ISSUER_MODEL = "ft:gpt-3.5-turbo-0125:personal:oidc4vci-draft13:BLBljnoM"
VERIFIER_MODEL = "ft:gpt-3.5-turbo-0125:personal:oidc4vp-draft18:BLC032IA"
ADVICE = "\n\nFor a deeper analysis, review the cryptographic binding methods, signing algorithms, and specific scopes supported by the issuer and authorization server. Test with a reference wallet as the Talao Wallet or Altme Wallet."

client = OpenAI(
    api_key=openapi_key,
    timeout=15.0
)


def get_payload_from_token(token) -> dict:
    payload = token.split('.')[1]
    payload += "=" * ((4 - len(payload) % 4) % 4)  # solve the padding issue of the base64 python lib
    return json.loads(base64.urlsafe_b64decode(payload).decode())


def counter_update():
    counter = json.load(open("openai_counter.json", "r"))
    request_number = counter["request_number"]
    request_number += 1
    new_counter = { "request_number": request_number}
    counter_file = open("openai_counter.json", "w")
    counter_file.write(json.dumps(new_counter))
    counter_file.close()
    
    # send data to slack
    passwords = json.load(open("passwords.json", "r"))
    url = passwords["slack_url"]
    payload = {
        "channel": "#issuer_counter",
        "username": "issuer",
        "text": "New AI request has been issued ",
        "icon_emoji": ":ghost:"
        }
    data = {
        'payload': json.dumps(payload)
    }
    r = requests.post(url, data=data, timeout=10)
    
    return True


def store_report(qrcode, report, type):
    report_filename =  hashlib.sha256(report.encode('utf-8')).hexdigest() + '.json'
    with open("report/" + report_filename, "w") as f:
        f.write(json.dumps({
            "type": type,
            "date": datetime.now().replace(microsecond=0).isoformat() + 'Z',
            "qrcode": qrcode,
            "report": report
        }))
    f.close()
    return True
    

# OIDC4VP flow   
def analyze_vp(vc):
    response = client.responses.create(
        model="gpt-4o",
        instructions="You are a serious coding assistant that talks like an expert of https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-08.html",
        input="Here is the VC to analyze in sd-jwt format  " + vc + \
            "Can you: \
                1: provide the release of the sd-jwt VC specification used \
                2: verify that the type of VC is correct  \
                3: provide a resume of the content of this VC  \
                4: check that this VC respects the specifications of sd-jwt VC  \
                5: verify that the type of the Key Binding is correct  \
                6: list all errors or problems if any \
                7: mention the ChatGPT model used for this report"
    )
    counter_update()
    return response.output_text


# OIDC4VCI flow
def analyze_token_request(form):
    response = client.responses.create(
        model="gpt-4o",
        instructions="You are a serious coding assistant that talks like an expert of https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-ID1.html#name-token-endpoint",
        input="Here is the token request form " + form + \
            "Can you: \
                1: provide the release of the OIDC4VCI specification used \
                2: verify that the claims of the request are correct and if the nonce is provided  \
                3: provide a resume of the content of this request  \
                4: check that this VC respects the specifications of OIDC4VCI token request  \
                5: list all errors or problems if any \
                6: mention the ChatGPT model used for this report"
    )
    counter_update()
    return response.output_text


# OIDC4VCI flow
def analyze_credential_request(form):
    print("call API AI credential request")
    response = client.responses.create(
        model="gpt-4o",
        instructions="You are a serious coding assistant that talks like an expert of https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-ID1.html#name-credential-endpoint",
        input="Here is the credential request form " + form + \
            "Can you: \
                1: verify that the claims of the request are correct  \
                2: provide a resume of the content of this request  \
                3: check that this request respects the specifications of OIDC4VCI credential request  \
                4: list all errors or problems if any \
                5: mention the ChatGPT model used for this report"
    )
    counter_update()
    return response.output_text


# QR code for verifier
def get_verifier_request(qrcode):
    parse_result = urlparse(qrcode)
    result = parse_qs(parse_result.query)
    result = {k: v[0] for k, v in result.items()}
    if request_uri := result.get('request_uri'):
        request_jwt = requests.get(request_uri, timeout=10).text
        request = get_payload_from_token(request_jwt)
    elif request := result.get("request"):
        request_jwt = request
        request = get_payload_from_token(request_jwt)
    elif result.get("response_mode"):
        request = result
    else:
        request = None
    return json.dumps(request)


def get_issuer_data(qrcode):
    parse_result = urlparse(qrcode)
    result = parse_qs(parse_result.query)
    result = {k: v[0] for k, v in result.items()}
    if result.get('credential_offer_uri') :
        credential_offer_uri = result['credential_offer_uri']
        try:
            r = requests.get(credential_offer_uri, timeout=10)
        except Exception:
            return None, None
        credential_offer = r.json()
        if r.status_code == 404:
            return None, None
    else:
        credential_offer = json.loads(result['credential_offer'])
    issuer = credential_offer['credential_issuer']
    issuer_metadata_url = issuer + '/.well-known/openid-credential-issuer'
    try:
        issuer_metadata = requests.get(issuer_metadata_url, timeout=10).json()
    except Exception:
        return None, None
    if issuer_metadata.get("authorization_servers"):
        authorization_server = issuer_metadata.get("authorization_servers")[0]
    else:
        authorization_server = issuer
    authorization_server_url = authorization_server + '/.well-known/oauth-authorization-server'
    authorization_server_metadata = requests.get(authorization_server_url, timeout=10).json()
    return json.dumps(issuer_metadata), json.dumps(authorization_server_metadata)


def analyze_issuer_qrcode(qrcode):
    print("call API AI credential request for issuer QR code diagnostic")
    date = datetime.now().replace(microsecond=0).isoformat()
    issuer_metadata, authorization_server_metadata = get_issuer_data(qrcode)  
    mention = "\n\n The OpenAI model " + ENGINE + " is used in addition to a Web3 Digital Wallet dataset. This report is based on the OIDC4VCI specifications (Draft 13). Date of issuance :" + date + ". @copyright Web3 Digital Wallet 2025."
    if not issuer_metadata or not authorization_server_metadata:
        completion = client.chat.completions.create(
            model=ISSUER_MODEL,
            messages=[
                {
                    "role": "developer",
                    "content": "You are an expert of the specifications OIDC4VCI draft 13"
                },
                {             
                    "role": "user",
                    "content": "Here is the credential offer QR code form " + qrcode + \
                "Can you: \
                    1: Provide in 5 lines in good english the abstract of the content of the VC offered by this issuer \
                    2: QRcode -> check if format and content are correct, check that the required claims are not missing in using thes specification.\
                    3: Explain as the issuer metadata or authorization server metadata are not available, one cannot provide a report about this issuer"
                }
            ]
        )
        return completion.choices[0].message.content + ADVICE + mention
    try:
        completion = client.chat.completions.create(
            model=ISSUER_MODEL,
            messages=[
                {
                    "role": "developer",
                    "content": "You are an expert of the specifications OIDC4VCI Draft 13"
                },
                {             
                    "role": "user",
                    "content": "Here is the credential offer QR code form " + qrcode + \
                    "Can you: \
                        1: Provide in 5 lines in good english the abstract of the content of the VC offered by this issuer with the name of the issuer and the list of the claims of the VC\
                        2: Check that the required claims of the QR code are not missing\
                        3: Provide the type of flow (authorization code flow or pre authorized code flow) and if there is a transaction code to enter\
                        4: Provide an abstract of the issuer metadata " + issuer_metadata + "\
                        5: Check that the issuer metadata are correct and that the required claims are not missing\
                        6: Provide an abstract of the authorization server metadata " + authorization_server_metadata + "\
                        7: Check that the authorization server metadata are correct and that the required claims are not missing\
                        8: Provide the list of errors and warnings if any"
                }
            ]
        )
        result = completion.choices[0].message.content + ADVICE + mention
    except openai.APIConnectionError:
        result = "The server could not be reached"
    except openai.RateLimitError:
        result = "Rate limit exceeded. Retry later"
    counter_update()
    store_report(qrcode, result, "issuer")
    return result


def analyze_verifier_qrcode(qrcode):
    print("call API AI credential request for QR code diagnostic")
    date = datetime.now().replace(microsecond=0).isoformat() + 'Z'
    verifier_request = get_verifier_request(qrcode)
    mention = "\n\n The OpenAI model " + ENGINE + " is used in addition to a Web3 Digital Wallet dataset. This report is based on the OIDC4VP ID2 specifications (Draft 18). Date of issuance :" + date + ". @copyright Web3 Digital Wallet 2025."
    if not verifier_request:
        completion = client.chat.completions.create(
            #model="gpt-4o",
            model=VERIFIER_MODEL,
            messages=[
                {
                    "role": "developer",
                    "content": "You are an expert of the specifications OIDC4VP ID2 Draft 18"
                },
                {             
                    "role": "user",
                    "content": "Here is the credential request QR code " + qrcode + "and the credential request : " + verifier_request + "\
                    Can you: \
                        1: Provide in 50 words in good english the abstract of the content of the VC requested by this verifier \
                        2: QRcode -> check if format and content are correct, check that the required claims are not missing in using the specifications\
                        3: Explain as the issuer metadata or authorization server metadata are not available, one cannot provide a report about this issuer"
                }
            ]
        )
        return completion.choices[0].message.content + ADVICE + mention
    try:
        completion = client.chat.completions.create(
            model=VERIFIER_MODEL,
            messages=[
                {
                    "role": "developer",
                    "content": "You are an expert of the specifications OIDC4VP Draft 18"
                },
                {             
                    "role": "user",
                    "content": "Here is the credential request " + verifier_request + "\
                    Can you: \
                        1: Provide in 50 words in good english the abstract of the content of the VC requested by this verifier \
                        2: Check the format and content of the credential request and if all the required claims are present\
                        3: Check the client metadata and if they exist verify that the format is present\
                        4: Check the presentation definition to verify that all required claims are present\
                        5: Provide a precise list of errors and warnings if any"
                }
            ]
        )
        result = completion.choices[0].message.content + ADVICE + mention
    except openai.APIConnectionError:
        result = "The server could not be reached"
    except openai.RateLimitError:
        result = "Rate limit exceeded. Retry later"
    counter_update()
    store_report(qrcode, result, "verifier")
    return result


def analyze_qrcode(qrcode):
    parse_result = urlparse(qrcode)
    result = parse_qs(parse_result.query)
    if result.get('credential_offer_uri') or result.get('credential_offer'):
        return analyze_issuer_qrcode(qrcode)
    else:
        return analyze_verifier_qrcode(qrcode)
    
