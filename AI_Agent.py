"""
QR Code Analyzer for OIDC4VCI and OIDC4VP using OpenAI models
This module processes QR code data, validates VC/VP tokens, interacts with OpenAI to generate reports,
and stores results with Slack notifications and file logging.
"""

import json
from openai import OpenAI
import openai
from urllib.parse import parse_qs, urlparse
import requests
from datetime import datetime
import hashlib
import base64
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)

# Load API key
with open("keys.json", "r") as f:
    openai_key = json.load(f)["openai"]

# Define models and constants
ENGINE2 = "gpt-4-turbo"
ENGINE = "gpt-3.5-turbo"
ISSUER_MODEL = "ft:gpt-3.5-turbo-0125:personal:oidc4vci-draft13:BLBljnoM"
VERIFIER_MODEL = "ft:gpt-3.5-turbo-0125:personal:oidc4vp-draft18:BLC032IA"
SDJWTVC_MODEL = "ft:gpt-3.5-turbo-0125:personal:sdjwtvc-draft10-1000:BLWSefAq"
ADVICE = "\n\nFor a deeper analysis, review the cryptographic binding methods, signing algorithms, and specific scopes supported by the issuer and authorization server."

# Initialize OpenAI client
client = OpenAI(api_key=openai_key)

def base64url_decode(input_str):
    padding = '=' * ((4 - len(input_str) % 4) % 4)
    return base64.urlsafe_b64decode(input_str + padding)

def get_payload_from_token(token):
    # Extract payload section from JWT
    payload = token.split('.')[1]
    return json.loads(base64url_decode(payload).decode())

def get_header_from_token(token):
    # Extract header section from JWT
    header = token.split('.')[0]
    return json.loads(base64url_decode(header).decode())

def counter_update(place):
    # Update local request count and notify Slack channel
    with open("openai_counter.json", "r") as f:
        counter = json.load(f)
    counter["request_number"] += 1
    with open("openai_counter.json", "w") as f:
        json.dump(counter, f)

    with open("passwords.json", "r") as f:
        slack_url = json.load(f)["slack_ai_url"]

    payload = {
        "channel": "# issuer-and-ai",
        "username": "AI Agent",
        "text": f"New AI request has been issued from {place}",
        "icon_emoji": ":ghost:"
    }
    requests.post(slack_url, data={"payload": json.dumps(payload)}, timeout=10)
    return True

def store_report(qrcode, report, report_type):
    # Save report to file using SHA256 hash as filename
    filename = hashlib.sha256(report.encode('utf-8')).hexdigest() + '.json'
    report_data = {
        "type": report_type,
        "date": datetime.now().replace(microsecond=0).isoformat() + 'Z',
        "qrcode": qrcode,
        "report": report
    }
    with open(f"report/{filename}", "w") as f:
        json.dump(report_data, f)
    return True


def analyze_qrcode(qrcode, oidc4vciDraft, oidc4vpDraft, device):
    # Analyze a QR code and delegate based on protocol type
    parse_result = urlparse(qrcode)
    result = parse_qs(parse_result.query)
    if result.get('credential_offer_uri') or result.get('credential_offer'):
        return analyze_issuer_qrcode(qrcode, oidc4vciDraft, device)
    else:
        request, presentation_definition, error_description = get_verifier_request(qrcode, oidc4vpDraft)
        if not request or not presentation_definition:
            return "This QR code is not supported : " + error_description
        else:
            return analyze_verifier_qrcode(qrcode, oidc4vpDraft, device)
    

def get_verifier_request(qrcode, draft):
    # Parse verifier's QR code request
    parse_result = urlparse(qrcode)
    result = {k: v[0] for k, v in parse_qs(parse_result.query).items()}
    if request_uri := result.get('request_uri'):
        try:
            request_jwt = requests.get(request_uri, timeout=10).text
            request = get_payload_from_token(request_jwt)
        except Exception:
            return None, None, "Error: The request jwt is not available"
    elif request := result.get("request"):
        request_jwt = request
        request = get_payload_from_token(request_jwt)
    elif result.get("response_mode"):
        request = result
    else:
        return None, None, "Error: The request is not available"

    if presentation_definition_uri := request.get("presentation_definition_uri"):
        try:
            presentation_definition = json.loads(requests.get(presentation_definition_uri, timeout=10).text)
        except Exception:
            return request, None,  "Error: The presentation definition is not available"
        request.pop("presentation_definition_uri")
        request['presentation_definition'] = presentation_definition
    else:
        presentation_definition = request.get('presentation_definition')
    return request, presentation_definition, ""

def analyze_vp(token):
    # Analyze a VP token in SD-JWT format and generate a compliance report
    vcsd = token.split("~")
    jwt_header = get_header_from_token(vcsd[0])
    jwt_payload = get_payload_from_token(vcsd[0])

    # Handle disclosures
    disclosures = "\r\n".join(
        base64url_decode(vcsd[i]).decode() for i in range(1, len(vcsd) - 1 if vcsd[-1] else len(vcsd))
    )

    # Handle Key Binding JWT (if available)
    if vcsd[-1]:
        kb_header = get_header_from_token(vcsd[-1])
        kb_payload = get_payload_from_token(vcsd[-1])
    else:
        kb_header = kb_payload = "No KB"

    date = datetime.now().replace(microsecond=0).isoformat()
    mention = (
        f"\n\n The OpenAI model {ENGINE} is used in addition to a Web3 Digital Wallet dataset."
        f" This report is based on the IETF SD-JWT VC specifications (Draft 10)."
        f" Date of issuance: {date}. \u00a9 Web3 Digital Wallet 2025."
    )

    prompt = (
        "Here is the VC for validation purpose: "
        f"the header of the VC: {json.dumps(jwt_header)} "
        f"the payload of the VC: {json.dumps(jwt_payload)} "
        f"the disclosures: {disclosures} "
        f"the KB header: {json.dumps(kb_header)} "
        f"the KB payload: {json.dumps(kb_payload)} "
        "Give me a response with one line per point:\n"
        "1. Provide the identifier of the holder (cnf) and the identifier the issuer.\n"
        "2. Display the claims disclosed.\n"
        "3. Check that all claims required in the header of the VC are not missing.\n"
        "4. Check that all claims required in the payload of the VC are not missing.\n"
        "5. Verify that the Key Binding JWT header and payload is correct.\n"
        "6. List all errors or problems if any."
    )

    completion = client.chat.completions.create(
        model=SDJWTVC_MODEL,
        messages=[
            {"role": "developer", "content": "You are an expert of the specifications SD-JWT VC"},
            {"role": "user", "content": prompt}
        ]
    )

    counter_update("sandbox")
    return completion.choices[0].message.content + ADVICE + mention

def get_issuer_data(qrcode):
    # Retrieve issuer, metadata and authorization server data from a credential offer QR code
    parse_result = urlparse(qrcode)
    result = {k: v[0] for k, v in parse_qs(parse_result.query).items()}

    if credential_offer_uri := result.get('credential_offer_uri'):
        try:
            credential_offer = requests.get(credential_offer_uri, timeout=10).json()
        except Exception:
            credential_offer = "Error: The credential offer is not available"
    else:
        credential_offer = json.loads(result.get('credential_offer', '{}'))

    issuer = credential_offer.get('credential_issuer')
    issuer_metadata_url = f"{issuer}/.well-known/openid-credential-issuer"
    try:
        issuer_metadata = requests.get(issuer_metadata_url, timeout=10).json()
    except Exception:
        issuer_metadata = "Error: Issuer metadata are not available"

    authorization_server = issuer_metadata.get("authorization_servers", [issuer])[0]
    authorization_server_url = f"{authorization_server}/.well-known/oauth-authorization-server"
    try:
        authorization_server_metadata = requests.get(authorization_server_url, timeout=10).json()
    except Exception:
        authorization_server_metadata = "Error: The authorization server metadata are not available"

    return json.dumps(credential_offer), json.dumps(issuer_metadata), json.dumps(authorization_server_metadata)

def analyze_issuer_qrcode(qrcode, draft, device):
    # Analyze issuer QR code and generate a structured report using OpenAI
    if not draft:
        draft = "13"

    date = datetime.now().replace(microsecond=0).isoformat()
    credential_offer, issuer_metadata, authorization_server_metadata = get_issuer_data(qrcode)
    mention = (
        f"\n\n The OpenAI model {ENGINE} is used in addition to a Web3 Digital Wallet dataset."
        f" This report is based on the OIDC4VCI specifications Draft {draft}."
        f" Date of issuance: {date}. © Web3 Digital Wallet 2025."
    )

    messages = [
        {
            "role": "system",
            "content": f"You are a professional analyst and expert in OIDC4VCI Draft {draft} and digital credential specifications."
                       f" You write concise, structured reports for developers and product teams."
        },
        {
            "role": "user",
            "content": f"""
        Analyze the following credential offer and metadata and return a report in clear English using bullet points.

        --- Credential Offer ---
        {credential_offer}

        --- Issuer Metadata ---
        {issuer_metadata}

        --- Authorization Server Metadata ---
        {authorization_server_metadata}

        You **must** answer the **8 points below**, **in the exact order**, and using the **exact same section titles**.
        Each section should be concise, technically accurate, and clearly separated.

        Do not write introductory text. Start directly with point 1.

        1. **VC Summary**
        2. **Required Claims Check**
        3. **Flow Type**
        4. **Issuer Metadata Summary**
        5. **Issuer Metadata Check**
        6. **Authorization Server Metadata Summary**
        7. **Auth Server Metadata Check**
        8. **Errors & Warnings**
        """
        }
    ]

    try:
        completion = client.chat.completions.create(
            model=ISSUER_MODEL,
            temperature=0,
            max_tokens=1024,
            messages=messages
        )
        result = completion.choices[0].message.content + ADVICE + mention
    except openai.APIConnectionError:
        result = "The server could not be reached"
    except openai.RateLimitError:
        result = "The agent is busy right now, retry later!"
    except openai.BadRequestError:
        result = "Too much data, context length exceeded"

    counter_update(device)
    store_report(qrcode, result, "issuer")
    return result


def analyze_verifier_qrcode(qrcode, draft, device):
    # Analyze verifier QR code and generate a structured report using OpenAI
    if not draft:
        draft = "18"

    date = datetime.now().replace(microsecond=0).isoformat() + 'Z'
    verifier_request, presentation_definition, error_description = get_verifier_request(qrcode, draft)
    if not verifier_request or not presentation_definition:
        return error_description

    mention = (
        f"\n\n The OpenAI model {ENGINE} is used in addition to a Web3 Digital Wallet dataset."
        f" This report is based on the OIDC4VP ID2 specifications Draft {draft}."
        f" Date of issuance: {date}. © Web3 Digital Wallet 2025."
    )

    messages = [
        {
            "role": "system",
            "content": f"You are an expert in OIDC4VP Draft {draft}. You generate short, clear, and complete technical reports for engineers."
        },
        {
            "role": "user",
            "content": f"""
        Analyze the following verifier authorization request and presentation definition.

        --- Authorization Request ---
        {verifier_request}

        --- Presentation Definition ---
        {presentation_definition}

        You **must** answer the **five points below**, **in the exact order**, and using the **exact same section titles**.
        Each section should be concise, technically accurate, and clearly separated.

        Do not write introductory text. Start directly with point 1.

        1. **Abstract**
        2. **Authorization Request**, check that all required claims of OIDC4VP are in the request
        3. **Presentation Definition**, check that the presentation_definition is correct
        4. **Client Metadata**, check that the metadata are correct
        5. **Errors & Warnings**
        """
        }
    ]

    try:
        completion = client.chat.completions.create(
            model=ENGINE2,
            temperature=0,
            max_tokens=1024,
            messages=messages
        )
        result = completion.choices[0].message.content + ADVICE + mention
    except openai.APIConnectionError:
        result = "The server could not be reached"
    except openai.RateLimitError:
        result = "The agent is busy right now, retry later!"
    except openai.BadRequestError:
        result = "Too much data, context length exceeded"

    counter_update(device)
    store_report(qrcode, result, "verifier")
    return result
