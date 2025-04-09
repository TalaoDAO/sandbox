
import json
from openai import OpenAI
from urllib.parse import parse_qs, urlparse
import requests
from datetime import datetime

# Remplace par ta clé API
api_key = json.load(open("keys.json", "r"))['openai']


client = OpenAI(
    # This is the default and can be omitted
    api_key=api_key
)

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
    print("call API AI credential request")
    date = datetime.now().replace(microsecond=0).isoformat() + 'Z'
    issuer_metadata, authorization_server_metadata = get_metadata(qrcode)
    response = client.responses.create(
        model="gpt-4o",
        instructions="You are an expert of the specifications https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-ID1.html",
        input="Here is the credential offer QR code form " + qrcode + \
            "Can you: \
                1: Provide in 5 lines in good english the abstract of the content of the VC offered by this issuer \
                3: verify that the QRcode format and content is correct and check that the required claims are not missing  \
                4: check that the credential exist in the metadata " + issuer_metadata + " \
                5: verify that the issuer metadata are correct compared to the specifications and in particular check that the required claims are not missing \
                6: check that the authorization server exist " + authorization_server_metadata + " \
                7: verify that the authorization server metadata are correct compared to the specifications and check that the required claims are not missing \
                8: provide a list of errors or warnings if any \
                9: provide advices for a deeper analysis \
                10: mention the ChatGPT model is used with Web3 Digital Wallet tools for this report and it is based on the OIDC4VCI specifications. \
                Do not forget to mention the release of the specifications and the date of the report :" + date + ". Give a precise answer without a question "\
    )
    return response.output_text

#qrcode = "openid-credential-offer://?credential_offer=%7B%22credential_issuer%22%3A+%22https%3A%2F%2Ftalao.co%2Fissuer%2Fpexkhrzlmj%22%2C+%22credential_configuration_ids%22%3A+%5B%22Pid%22%5D%2C+%22grants%22%3A+%7B%22authorization_code%22%3A+%7B%22issuer_state%22%3A+%22test9%22%2C+%22authorization_server%22%3A+%22https%3A%2F%2Ftalao.co%2Fissuer%2Fpexkhrzlmj%2Fstandalone%22%7D%7D%7D"

#print(analyze_issuer_qrcode(qrcode))