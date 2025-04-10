
import json
import openai
from openai import OpenAI
from urllib.parse import parse_qs, urlparse
import requests
from datetime import datetime

# Remplace par ta clé API
api_key = json.load(open("keys.json", "r"))['openai']


client = OpenAI(
    # This is the default and can be omitted
    api_key=api_key,
    timeout=15.0
)



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




def get_metadata(qrcode):
    parse_result = urlparse(qrcode)
    result = parse_qs(parse_result.query)
    if result.get('credential_offer_uri') :
        credential_offer_uri = result['credential_offer_uri'][0]
        try:
            r = requests.get(credential_offer_uri, timeout=10)
        except Exception:
            return None, None
        credential_offer = r.json()
        if r.status_code == 404:
            return None, None
    else:
        credential_offer = json.loads(result['credential_offer'][0])
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
    f = open("credential_offer_specification_13.md", "r")
    credential_offer_specification = f.read()
    f = open("issuer_metadata_specification_13.md", "r")
    issuer_metadata_specification = f.read()
    date = datetime.now().replace(microsecond=0).isoformat() + 'Z'
    issuer_metadata, authorization_server_metadata = get_metadata(qrcode)
    mention = "Add final mention : 1) the ChatGPT model gpt-4o is used in addition to Web3 Digital Wallet testing tools 2) report is based on the OIDC4VCI specifications Draft 13. \
                Do not forget to mention the date of the report :" + date + ". Give a precise answer without a question "
    if not issuer_metadata or not authorization_server_metadata:
        response = client.responses.create(
            model="gpt-4o",
            instructions="You are an expert of the specifications : OIDC4VCI Draft 13",
            input="Here is the credential offer QR code form " + qrcode + \
                "Can you: \
                    1: Provide in 5 lines in good english the abstract of the content of the VC offered by this issuer \
                    2: QRcode -> check if format and content are correct, check that the required claims are not missing in using this specification :" + credential_offer_specification +  "\
                    3: Explain as the issuer metadata or authorization server metadata are not available, one cannot provide a report about this issuer" + mention
        )
        return response.output_text
        
    try:
        response = client.responses.create(
            model="gpt-4o",
            instructions="You are an expert of the specifications : OIDC4VCI Draft 13",
            input="Here is the credential offer QR code form " + qrcode + \
                "Can you: \
                    1: Provide in 5 lines in good english the abstract of the content of the VC offered by this issuer \
                    3: QRcode -> check format and content is correct, check that the required claims are not missing in using this specification :" + credential_offer_specification +  "\
                    4: provide an abstract of the issuer metadata " + issuer_metadata + " \
                    5: Issuer metadata -> check that the issuer metadata are correct, check that the required claims are not missing in using : " + issuer_metadata_specification +"\
                    6: provide an abstract of the authorization server metadata " + authorization_server_metadata + " \
                    7: Authorization server metadata -> check that the authorization server metadata are correct, check the the required claims are not missing in using :" + issuer_metadata_specification +" \
                    8: provide a precise list of errors and warnings if any \
                    9: provide advices for a deeper analysis" + mention + "\
                    Answer should be a text file"
        )
        result = response.output_text
    except openai.APIConnectionError:
        result = "The server could not be reached"
    except openai.RateLimitError:
        result = "Rate limit exceeded. Retry later"
    counter_update()
    return result

#qrcode = "openid-credential-offer://?credential_offer=%7B%22credential_issuer%22%3A+%22https%3A%2F%2Ftalao.co%2Fissuer%2Fpexkhrzlmj%22%2C+%22credential_configuration_ids%22%3A+%5B%22Pid%22%5D%2C+%22grants%22%3A+%7B%22authorization_code%22%3A+%7B%22issuer_state%22%3A+%22test9%22%2C+%22authorization_server%22%3A+%22https%3A%2F%2Ftalao.co%2Fissuer%2Fpexkhrzlmj%2Fstandalone%22%7D%7D%7D"

#print(analyze_issuer_qrcode(qrcode))