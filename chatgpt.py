
import json
import openai
from openai import OpenAI
from urllib.parse import parse_qs, urlparse
import requests
from datetime import datetime
import hashlib
import base64

openapi_key = json.load(open("keys.json", "r"))['openai']

ENGINE = "gpt-3.5-turbo"
ISSUER_MODEL = "ft:gpt-3.5-turbo-0125:personal:oidc4vci-draft13:BLBljnoM"
VERIFIER_MODEL = "ft:gpt-3.5-turbo-0125:personal:oidc4vp-draft18:BLC032IA"
SDJWTVC_MODEL = "ft:gpt-3.5-turbo-0125:personal:sdjwtvc-draft10-1000:BLWSefAq"
ADVICE = "\n\nFor a deeper analysis, review the cryptographic binding methods, signing algorithms, and specific scopes supported by the issuer and authorization server."

client = OpenAI(
    api_key=openapi_key,
    timeout=25.0
)


def get_payload_from_token(token) -> dict:
    payload = token.split('.')[1]
    payload += "=" * ((4 - len(payload) % 4) % 4)  # solve the padding issue of the base64 python lib
    return json.loads(base64.urlsafe_b64decode(payload).decode())

def get_header_from_token(token) -> dict:
    payload = token.split('.')[0]
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
    

# OIDC4VP flow and wallet
def analyze_vp(token):
    vcsd = token.split("~")
    vcsd_jwt_payload = get_payload_from_token(vcsd[0])
    vcsd_jwt_header = get_header_from_token(vcsd[0])
    disclosure = ""
    if not vcsd[-1]:
        len_vcsd = len(vcsd)
        kbjwt_header = kbjwt_payload = "No KB"
    else:
        len_vcsd = len(vcsd)-1
        kbjwt_header = get_header_from_token(vcsd[-1])
        kbjwt_payload = get_payload_from_token(vcsd[-1])
    for i in range(1, len_vcsd):
        _disclosure = vcsd[i]
        _disclosure += "=" * ((4 - len(vcsd[i]) % 4) % 4)    
        disclosure += "\r\n" + base64.urlsafe_b64decode(_disclosure.encode()).decode()
    date = datetime.now().replace(microsecond=0).isoformat()
    mention = "\n\n The OpenAI model " + ENGINE + " is used in addition to a Web3 Digital Wallet dataset. This report is based on the IETF SD-JWT VC specifications (Draft 10). Date of issuance :" + date + ". @copyright Web3 Digital Wallet 2025."
    completion = client.chat.completions.create(
        model=SDJWTVC_MODEL,
        messages=[
                {
                    "role": "developer",
                    "content": "You are an expert of the specifications SD-JWT VC"
                },
                {             
                    "role": "user",
                    "content": "Here is the VC for validation purpose :\
                        the header of the VC :" + json.dumps(vcsd_jwt_header) + "\
                        the payload of the VC : "+ json.dumps(vcsd_jwt_payload) + "\
                        the disclosures : " + disclosure + "\
                        the KB header :" + json.dumps(kbjwt_header) + "\
                        the KB payload :" + json.dumps(kbjwt_payload) + "\
                        Give me a response with one line by point :\
                            1. Provide the identifier of the holder (cnf) and the identifier the issuer. \
                            2. Display the claims disclosed.\
                            3. check that all claims required in the header of the VC are not missing.\
                            3. check that all claims required in the payload of the VC are not missing.\
                            4. verify that the Key Binding jwt header and payload is correct.\
                            5. list all errors or problems if any."
                }
        ]
    )
    counter_update()
    print("response = ", completion.choices[0].message.content)
    return completion.choices[0].message.content + ADVICE + mention


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
        try:
            request_jwt = requests.get(request_uri, timeout=10).text
        except Exception:
            request_jwt = "Error: The request jwt is not available"
        request = get_payload_from_token(request_jwt)
    elif request := result.get("request"):
        request_jwt = request
        request = get_payload_from_token(request_jwt)
    elif result.get("response_mode"):
        request = result
    else:
        request = "Error: The response_mode is not present in the verifier request"
    if presentation_definition_uri := request.get("presentation_definition_uri"):
        try:
            presentation_definition = requests.get(presentation_definition_uri, timeout=10).text
        except Exception:
            presentation_definition = "Error: The presentation definition is not available"
        request.pop("presentation_definition_uri")
        request['presentation_definition'] = presentation_definition
    return json.dumps(request)


def get_issuer_data(qrcode):
    parse_result = urlparse(qrcode)
    result = parse_qs(parse_result.query)
    result = {k: v[0] for k, v in result.items()}
    if credential_offer_uri := result.get('credential_offer_uri') :
        try:
            credential_offer = requests.get(credential_offer_uri, timeout=10).json()
        except Exception:
            credential_offer = "Error: The credential offer is not available"
    else:
        credential_offer = json.loads(result['credential_offer'])
    issuer = credential_offer['credential_issuer']
    issuer_metadata_url = issuer + '/.well-known/openid-credential-issuer'
    try:
        issuer_metadata = requests.get(issuer_metadata_url, timeout=10).json()
    except Exception:
        issuer_metadata = "Error: Issuer metadata are not available"
    if issuer_metadata.get("authorization_servers"):
        authorization_server = issuer_metadata.get("authorization_servers")[0]
    else:
        authorization_server = issuer
    authorization_server_url = authorization_server + '/.well-known/oauth-authorization-server'
    try:
        authorization_server_metadata = requests.get(authorization_server_url, timeout=10).json()
    except Exception:
        authorization_server_metadata = "Error: The authorization server metadata are not available"
    return json.dumps(credential_offer), json.dumps(issuer_metadata), json.dumps(authorization_server_metadata)


def analyze_issuer_qrcode(qrcode):
    print("call API AI credential request for issuer QR code diagnostic")
    date = datetime.now().replace(microsecond=0).isoformat()
    credential_offer, issuer_metadata, authorization_server_metadata = get_issuer_data(qrcode)  
    mention = "\n\n The OpenAI model " + ENGINE + " is used in addition to a Web3 Digital Wallet dataset. This report is based on the OIDC4VCI specifications (Draft 13). Date of issuance :" + date + ". @copyright Web3 Digital Wallet 2025."
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
                    "content": "Here is the credential offer :" + credential_offer + \
                    "Can you give me a report with one line by point :\
                        1. Provide in 50 words maximum in good english the abstract of the content of the VC offered by this issuer with the name of the issuer and the list of the claims of the VC.\
                        2. Check that the required claims of the credential offer are not missing.\
                        3. Provide the type of flow (authorization code flow or pre authorized code flow) and if there is a transaction code to enter.\
                        4. Provide an abstract of the issuer metadata " + issuer_metadata + ".\
                        5. Check that the issuer metadata are correct and that the required claims are not missing.\
                        6. Provide an abstract of the authorization server metadata " + authorization_server_metadata + ".\
                        7. Check that the authorization server metadata are correct and that the required claims are not missing.\
                        8. Provide the list of errors and warnings if any."
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
                    "content": "Here is the credential request " + verifier_request + " of a verifier\
                    Can you give me a report with one line by point : \
                        1. Provide in 50 words maximum and in good english the abstract of the content of the VC requested by this verifier.\
                        2. Check that all the required claims of the credential request are present.\
                        3. Check that all the required claims of the presentation_definition are present.\
                        4. Check the client metadata claims and if they exist verify that the vp_format is present.\
                        5. Provide a precise list of errors and warnings if any."
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
    elif result.get('response_type') or result.get('request') or result.get("request_uri"):
        return analyze_verifier_qrcode(qrcode)
    else:
        return "This protocol is not supported"
    
