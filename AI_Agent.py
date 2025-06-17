"""
QR Code Analyzer for OIDC4VCI and OIDC4VP using OpenAI models
This module processes QR code data, validates VC/VP tokens, interacts with OpenAI to generate reports,
and stores results with Slack notifications and file logging.
"""

import json
from urllib.parse import parse_qs, urlparse
import requests
from datetime import datetime
import hashlib
import base64
import logging
import re
import tiktoken


from langchain_openai import ChatOpenAI
from langchain_google_genai import ChatGoogleGenerativeAI

provider = "openai"
#provider = "gemini"


# Load API keys
with open("keys.json", "r") as f:
    keys = json.load(f)

openai_model = ChatOpenAI(
    api_key=keys["openai"],
    model="gpt-4o",
    temperature=0,
)

gemini_model = ChatGoogleGenerativeAI(
    google_api_key=keys["gemini"],
    model="gemini-1.5-pro-latest",
    temperature=0,
)

def get_llm_client():
    if provider.lower() == "openai":
        return openai_model
    elif provider.lower() == "gemini":
        return gemini_model
    else:
        raise ValueError(f"Unsupported provider: {provider}")

def engine():
    if provider.lower() == "openai":
        return "gpt-4-turbo"
    elif provider.lower() == "gemini":
        return "gemini-2.5-flash-preview-05-20"
    else:
        raise ValueError(f"Unsupported provider: {provider}")

# Configure logging
logging.basicConfig(level=logging.INFO)
    
# Define models and constants
ADVICE = "\n\nLLM can make mistakes. Check important info. For a deeper analysis, review the cryptographic binding methods, signing algorithms, and specific scopes supported by the issuer and authorization server."
MAX_RETRIES = 3
DELAY_SECONDS = 2

enc = tiktoken.encoding_for_model("gpt-4")  # or "gpt-3.5-turbo"


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


def clean_md(content):
    # Patterns to remove specific top-level sections
    for section in ["Introduction", "Terminology", "Document History", "Notices", "Acknowledgements", "Use Cases", "IANA Considerations", ]:
        pattern = rf"(?m)^# {section}[\s\S]*?(?=^\# |\Z)"
        content = re.sub(pattern, "", content)
    return content


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


def process_vc_format(vc: str, sdjwtvc_draft: str, vcdm_draft: str, device: str):
    """
    Detect the format of a Verifiable Credential (VC) and route to the correct analysis function.
    Args:
        vc (str): VC input as a string.
    Returns:
        str: Result of analysis or error message.
    """

    # 1. SD-JWT: starts with base64 segment and uses '~' delimiter
    if "~" in vc and "." in vc.split("~")[0]:
        return analyze_sd_jwt_vc(vc, sdjwtvc_draft, device)

    # 2. JWT VC (compact JWT): 3 base64 parts separated by dots
    if vc.count(".") == 2 and all(len(part.strip()) > 0 for part in vc.split(".")):
        return analyze_jwt_vc(vc, vcdm_draft, device)

    # 3. JSON-LD: must be valid JSON with @context
    try:
        vc_json = json.loads(vc)
        if "@context" in vc_json and "type" in vc_json:
            return analyze_jsonld_vc(vc_json, vcdm_draft, device)
    except json.JSONDecodeError:
        return "Invalid JSON. Cannot parse input."

    return "Unknown VC format. Supported formats: SD-JWT VC, JWT VC (compact), JSON-LD VC."


def analyze_qrcode(qrcode, oidc4vciDraft, oidc4vpDraft, profil, device):    
    # Analyze a QR code and delegate based on protocol type
    profile = ""
    if profil == "EBSI":
        oidc4vciDraft = "11"
        oidc4vpDraft = "18"
        profile = "Use only jwt_vc format. Use only did:key and did:ebsi as identifier"
    elif profil == "DIIP_V3":
        oidc4vciDraft = "13"
        oidc4vpDraft = "18"
        profile = "Use only sd-jwt vc, jwt_vc_json and ldp_vc (JSON-LD) format. Use only ES256 as key. Use only did:jwk and did:web as identifier"
    elif profil == "DIIP_V4":
        oidc4vciDraft = "15"
        oidc4vpDraft = "28"
        profile = "Use only sd-jwt vc, jwt_vc_json and ldp_vc (JSON-LD) format. Use only ES256 as key. Use only did:jwk and did:web as identifier"
    elif profil == "INJI":
        oidc4vciDraft = "13"
        oidc4vpDraft = "21"
        profile = "Use only ldp_vc (JSON-LD) format"
    elif profil == "EWC":
        oidc4vciDraft = "13"
        oidc4vpDraft = "18"
        profile = "Use only sd-jwt vc format and mdoc format"
    parse_result = urlparse(qrcode)
    logging.info('profil = %s, oidc4vci draft = %s, oidc4vp draft = %s', profil, oidc4vciDraft, oidc4vpDraft)
    result = parse_qs(parse_result.query)
    if result.get('credential_offer_uri') or result.get('credential_offer'):
        return analyze_issuer_qrcode(qrcode, oidc4vciDraft, profile, device)
    else:
        request, presentation_definition, error_description = get_verifier_request(qrcode, oidc4vpDraft)
        if not request or not presentation_definition:
            return "This QR code is not supported : " + error_description
        else:
            return analyze_verifier_qrcode(qrcode, oidc4vpDraft, profile, device)
    

def get_verifier_request(qrcode, draft):
    warning = ""
    # Parse verifier's QR code request
    parse_result = urlparse(qrcode)
    result = {k: v[0] for k, v in parse_qs(parse_result.query).items()}
    if request_uri := result.get('request_uri'):
        try:
            response = requests.get(request_uri, timeout=10)
            request_jwt = response.text
            request = get_payload_from_token(request_jwt)
        except Exception:
            return None, None, "Error: The request jwt is not available"
        content_type = response.headers.get("Content-Type")
        if content_type != "application/oauth-authz-req+jwt":
            return None, None, "Error: The request_uri response Content-Type must be application/oauth-authz-req+jwt"
    elif request := result.get("request"):
        request_jwt = request
        request = get_payload_from_token(request_jwt)
    elif result.get("response_mode"):
        request = result
        warning = "Passing OIDC request parameters via the request or request_uri parameter using a signed JWT is more secure than passing them as plain query parameters."
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
    
    if warning:
        warning = "Warning: " + warning
    return request, presentation_definition, warning


def analyze_sd_jwt_vc(token: str, draft: str, device: str) -> str:
    """
    Analyze a Verifiable Presentation (VP) in SD-JWT format and return a structured report.
    
    Args:
        token (str): The full SD-JWT token, formatted as base64url sections separated by `~`
        draft (str): Draft version number to load the appropriate spec documentation

    Returns:
        str: A markdown-formatted compliance report generated using OpenAI
    """
    # Split token into components: header~payload~disclosures...~key_binding_jwt (optional)
    vcsd = token.split("~")
    sd_jwt = vcsd[0]
    
    # Decode SD-JWT header and payload
    jwt_header = get_header_from_token(sd_jwt)
    jwt_payload = get_payload_from_token(sd_jwt)

    # Determine whether the last part is a Key Binding JWT (assumed to be a JWT if it contains 2 dots)
    is_kb_jwt = vcsd[-1].count('.') == 2

    # Disclosures are everything between vcsd[1] and vcsd[-2] if KB is present, otherwise vcsd[1:]
    disclosure_parts = vcsd[1:-1] if is_kb_jwt else vcsd[1:]

    # Decode disclosures
    disclosures = "\r\n".join(
        base64url_decode(part).decode() for part in disclosure_parts
    )

    # Decode Key Binding JWT (KB-JWT) if present
    if is_kb_jwt:
        kb_header = get_header_from_token(vcsd[-1])
        kb_payload = get_payload_from_token(vcsd[-1])
    else:
        kb_header = kb_payload = "No Key Binding JWT"

    # Load the appropriate specification content based on draft
    try:
        with open(f"./dataset/sdjwtvc/{draft}.txt", "r") as f:
            content = f.read()
    except FileNotFoundError:
        with open("./dataset/sdjwtvc/8.txt", "r") as fallback:
            content = fallback.read()
            draft = "8"

    # Token count logging for diagnostics
    tokens = enc.encode(content)
    logging.info("Token count: %s", len(tokens))

    # Timestamp and attribution
    date = datetime.now().replace(microsecond=0).isoformat()
    mention = (
        f"\n\nThe model {engine()} is used in conjunction with the Web3 Digital Wallet dataset.\n"
        f"This report is based on the IETF SD-JWT VC Draft {draft} specification.\n"
        f"Date of issuance: {date}. ©Web3 Digital Wallet 2025."
    )

    # Prompt for OpenAI model
    prompt = f"""
    --- Specifications ---
    {content}

    --- VC Data for Analysis ---
    VC Header: {json.dumps(jwt_header, indent=2)}
    VC Payload: {json.dumps(jwt_payload, indent=2)}
    Disclosures:
    {disclosures}
    Key Binding JWT Header: {json.dumps(kb_header, indent=2)}
    Key Binding JWT Payload: {json.dumps(kb_payload, indent=2)}

    --- Instructions ---
    Analyze the content above and provide answers to the following points, one per line:

    1. Provide the holder's identifier (cnf) and the issuer identifier.
    2. Display all disclosed claims.
    3. Check that no required claims are missing from the header.
    4. Check that no required claims are missing from the payload.
    5. Validate that the Key Binding JWT (if present) is structurally correct.
    6. List any errors, inconsistencies, or anomalies and propose improvements
    """

    # Call the OpenAI API
    llm = get_llm_client()  # Add 'provider' param to function
    response = llm.invoke([
        {"role": "system", "content": "You are an expert in SD-JWT VC specifications compliance."},
        {"role": "user", "content": prompt}
        ]).content

    # Update usage stats and return response
    counter_update(device)
    return response + ADVICE + mention


def analyze_jwt_vc(token, draft, device):
    """
    Analyze a Verifiable Presentation (VP) in JWT format and return a structured report.
    
    Args:
        token (str): The full token, formatted as base64url sections separated by `~`
        draft (str): Draft version number to load the appropriate spec documentation

    Returns:
        str: A markdown-formatted compliance report generated using OpenAI
    """
    
    llm = get_llm_client()

    # Decode SD-JWT header and payload
    jwt_header = get_header_from_token(token)
    jwt_payload = get_payload_from_token(token)

    # Load the appropriate specification content based on draft
    try:
        with open(f"./dataset/vcdm/{draft}.txt", "r") as f:
            content = f.read()
    except FileNotFoundError:
        with open("./dataset/vcdm/1.1.txt", "r") as fallback:
            draft = "1.1"
            content = fallback.read()

    # Token count logging for diagnostics
    tokens = enc.encode(content)
    logging.info("Token count: %s", len(tokens))

    # Timestamp and attribution
    date = datetime.now().replace(microsecond=0).isoformat()
    mention = (
        f"\n\nThe model {engine()} is used in conjunction with the Web3 Digital Wallet dataset.\n"
        f"This report is based on the W3C VCDM {draft} specification.\n"
        f"Date of issuance: {date}. ©Web3 Digital Wallet 2025."
    )

    # Prompt for OpenAI model
    prompt = f"""
    --- Specifications ---
    {content}

    --- VC Data for Analysis ---
    VC Header: {json.dumps(jwt_header, indent=2)}
    VC Payload: {json.dumps(jwt_payload, indent=2)}

    --- Instructions ---
    Analyze the content above and provide answers to the following points, one per line:

    1. Provide the holder's identifier and the issuer identifier.
    2. Display all claims.
    3. Check that no required claims are missing from the header.
    4. Check that no required claims are missing from the payload.
    5. List any errors, inconsistencies, or anomalies and propose improvements
    """

    # Call the LLM API
    llm = get_llm_client()  # Add 'provider' param to function
    response = llm.invoke([
        {"role": "system", "content": "You are an expert in JWT VC specifications compliance."},
        {"role": "user", "content": prompt}
    ]).content

    # Update usage stats and return response
    counter_update(device)
    return response + ADVICE + mention

    
def analyze_jsonld_vc(vc: str, draft: str, device: str) -> str:
    """
    Analyze a Verifiable Presentation (VP) in JSON-LD format and return a structured report.
    
    Args:
        vc (str): The full VC, 
        draft (str): Draft version number to load the appropriate spec documentation

    Returns:
        str: A markdown-formatted compliance report generated using OpenAI
    """

    # Load the appropriate specification content based on draft
    try:
        with open(f"./dataset/vcdm/{draft}.txt", "r", encoding="utf-8") as f:
            content = f.read()
    except FileNotFoundError:
        with open("./dataset/vcdm/1.1.txt", "r", encoding="utf-8") as fallback:
            content = fallback.read()
            draft = "1.1"
            
    # Token count logging for diagnostics
    tokens = enc.encode(content)
    logging.info("Token count: %s", len(tokens))

    # Timestamp and attribution
    date = datetime.now().replace(microsecond=0).isoformat()
    mention = (
        f"\n\nThe model {engine()} is used in conjunction with the Web3 Digital Wallet dataset.\n"
        f"This report is based on the W3C VC DM {draft} specification.\n"
        f"Date of issuance: {date}. ©Web3 Digital Wallet 2025."
    )

    # Prompt for OpenAI model
    prompt = f"""
    --- Specifications ---
    {content}

    --- VC Data for Analysis ---
    JSON-LD VC : {json.dumps(vc, indent=2)}

    --- Instructions ---
    Analyze the content above and provide answers to the following points, one per line:

    1. Provide the holder's identifier and the issuer identifier.
    2. Display all claims.
    3. Check that no required claims are missing from the VC.
    4. List any errors, inconsistencies, or anomalies and propose improvements
    """
    
    # Call the OpenAI API
    llm = get_llm_client()  # Add 'provider' param to function
    response = llm.invoke([
        {"role": "system", "content": "You are an expert in VC DM specifications compliance."},
        {"role": "user", "content": prompt}
    ]).content

    # Update usage stats and return response
    counter_update(device)
    return response + ADVICE + mention


def get_issuer_data(qrcode, draft):
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
    logging.info("AI Agent call for QR code diagnostic. issuer = %s", issuer)
    try:
        issuer_metadata = requests.get(issuer_metadata_url, timeout=10).json()
    except Exception:
        issuer_metadata = "Error: Issuer metadata are not available"

    try:
        authorization_server = issuer_metadata.get("authorization_servers", [issuer])[0]
    except Exception:
        try:
            authorization_server = credential_offer["grants"]["authorization_code"]["authorization_server"]
        except Exception:
            authorization_server_metadata = "Error: The authorization server is not found not"
            return json.dumps(credential_offer), json.dumps(issuer_metadata), json.dumps(authorization_server_metadata)
    
    logging.info("authorization server = %s", authorization_server)

    if int(draft) <= 11:
        authorization_server_url = f"{authorization_server}/.well-known/openid-configuration"
    else:
        authorization_server_url = f"{authorization_server}/.well-known/oauth-authorization-server"
    
    try:
        authorization_server_metadata = requests.get(authorization_server_url, timeout=10).json()
    except Exception:
        authorization_server_metadata = "Error: The authorization server metadata are not available or the draft " + draft + " is not correct ? "
    return json.dumps(credential_offer), json.dumps(issuer_metadata), json.dumps(authorization_server_metadata)


def analyze_issuer_qrcode(qrcode, draft, profile, device):    
    logging.info("draft = %s", draft)
    # Analyze issuer QR code and generate a structured report using OpenAI
    if not draft:
        draft = "13"

    date = datetime.now().replace(microsecond=0).isoformat()
    credential_offer, issuer_metadata, authorization_server_metadata = get_issuer_data(qrcode, draft)
    
    try:
        f = open("./dataset/oidc4vci/" + draft + ".md", "r")
        context = f.read()
        f.close()
    except Exception:
        f = open("./dataset/oidc4vci/13.md", "r")
        context = f.read()
        f.close
        draft = "13"
    
    # Token count logging for diagnostics
    tokens = enc.encode(context)
    logging.info("Token count: %s", len(tokens))
    
    context = clean_md(context) 
    if int(draft) <= 11:
        context += "\n If EBSI tell to the user to add did:key:jwk_jcs-pub as subject_syntax_type_supported in the authorization server metadata"
    mention = (
        f"\n\n The model {engine()} is used in addition to a Web3 Digital Wallet dataset."
        f" This report is based on the OIDC4VCI specifications Draft {draft}."
        f" Date of issuance: {date}. © Web3 Digital Wallet 2025."
    )

    messages = [
        {
            "role": "system",
            "content": f"""You are a compliance analyst specializing in OIDC4VCI Draft {draft}.
    You write precise, technical markdown reports for developers and product teams.
    Keep your answers structured, concise, and free of unnecessary commentary."""
        },
        {
            "role": "user",
            "content": f"""
    Analyze the following OIDC4VCI credential offer and related metadata.

    --- Context (OIDC4VCI Draft {draft}) ---
    {context}

    --- Profile Constraints ---
    {profile}

    --- Credential Offer ---
    {credential_offer}

    --- Issuer Metadata ---
    {issuer_metadata}

    --- Authorization Server Metadata ---
    {authorization_server_metadata}

    ### Instructions:
    - Follow the 9 report sections listed below, in **exact order and with exact titles**.
    - Use markdown formatting with **bold** section titles and bullet points if needed.
    - Keep answers short, accurate, and technical.
    - **Do not include any introduction or summary. Start directly with point 1.**

    ### Report Sections:

    1. **VC Summary**  
    2. **Required Claims Check**  
    3. **Flow Type**  
    4. **Issuer Metadata Summary**  
    5. **Issuer Metadata Check**  
    6. **Authorization Server Metadata Summary**  
    7. **Auth Server Metadata Check**  
    8. **Errors & Warnings**  
    9. **Improvements** – Suggest developer-focused enhancements  
    """
        }
    ]
    
    llm = get_llm_client()  
    response = llm.invoke(messages).content

    result = response + ADVICE + mention
    counter_update(device)
    store_report(qrcode, result, "issuer")
    return result


def analyze_verifier_qrcode(qrcode, draft, profile, device):   
    
    # Analyze verifier QR code and generate a structured report using OpenAI
    if not draft:
        draft = "18"

    date = datetime.now().replace(microsecond=0).isoformat() + 'Z'
    verifier_request, presentation_definition, error_warning = get_verifier_request(qrcode, draft)
    if not verifier_request or not presentation_definition:
        return error_warning
    
    try:
        f = open("./dataset/oidc4vp/" + draft + ".md", "r")
        context = f.read()
        f.close()
    except Exception:
        f = open("./dataset/oidc4vp/18.md", "r")
        context = f.read()
        f.close
        draft = "18"
    
    context = clean_md(context) 
    
    # Token count logging for diagnostics
    tokens = enc.encode(context)
    logging.info("Token count: %s", len(tokens))
    
    mention = (
        f"\n\n The model {engine()} is used in addition to a Web3 Digital Wallet dataset."
        f" This report is based on the OIDC4VP specifications Draft {draft}."
        f" Date of issuance: {date}. © Web3 Digital Wallet 2025."
    )

    messages = [
        {
            "role": "system",
            "content": f"""You are a compliance analyst specializing in OIDC4VP Draft {draft}.
    You write precise, technical markdown reports for engineers.
    Keep your answers structured, concise, and free of unnecessary commentary."""
        },
        {
            "role": "user",
            "content": f"""
    Analyze the following OIDC4VP authorization request and presentation definition.

    --- Context (OIDC4VP Draft {draft}) ---
    {context}

    --- Profile Constraints ---
    {profile}

    --- Warning ---
    {error_warning}

    --- Authorization Request ---
    {json.dumps(verifier_request, indent=2)}

    --- Presentation Definition ---
    {json.dumps(presentation_definition, indent=2)}

    ### Instructions:
    - Follow the 6 report sections listed below, in **exact order and with exact titles**.
    - Use markdown formatting with **bold** section titles and bullet points if needed.
    - Keep answers short, accurate, and technical.
    - **Do not include any introduction or summary. Start directly with point 1.**

    ### Report Sections:

    1. **Abstract**  
    2. **Authorization Request** – Check required OIDC4VP claims  
    3. **Presentation Definition** – Verify format and structure  
    4. **Client Metadata** – Validate content (if present)  
    5. **Errors & Warnings**  
    6. **Improvements** – Suggest developer-focused enhancements  
    """
        }
    ]

    llm = get_llm_client()  # Add 'provider' param to function
    response = llm.invoke(messages).content

    result = response + ADVICE + mention
    counter_update(device)
    store_report(qrcode, result, "verifier")
    return result
