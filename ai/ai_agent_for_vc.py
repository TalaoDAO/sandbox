"""
QR Code Analyzer for OIDC4VCI and OIDC4VP using OpenAI models
This module processes QR code data, validates VC/VP tokens, interacts with OpenAI to generate reports,
and stores results with Slack notifications and file logging.
"""

import json
from urllib.parse import urlparse
import requests
from datetime import datetime
import hashlib
import base64
import logging
import re
import tiktoken
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import ExtensionOID
#from cryptography.hazmat.primitives import serialization
import oidc4vc
from jwcrypto import jwk, jwt
from langchain_openai import ChatOpenAI
from langchain_google_genai import ChatGoogleGenerativeAI
from typing import Any, Dict, Optional, Tuple
from dataclasses import dataclass
import tsl # token statys list
import bsl
import didkit


# Load API keys
with open("keys.json", "r") as f:
    keys = json.load(f)

with open("rules_catalog_vc.json", "r") as f:
    RULES_CATALO_VC = json.load(f)

with open("rules_catalog_oidc4vc.json", "r") as f:
    RULES_CATALO_OIDC4VC = json.load(f)


openai_model_flash = ChatOpenAI(
    api_key=keys["openai"],
    model="gpt-4o-mini",
    #temperature=0
)


openai_model_escalation = ChatOpenAI(
    api_key=keys["openai"],
    model="gpt-5-mini",
    #temperature=0
)


openai_model_pro = ChatOpenAI(
    api_key=keys["openai"],
    model="gpt-5",
    #temperature=0
)


gemini_model_pro = ChatGoogleGenerativeAI(
    google_api_key=keys["gemini"],
    model="gemini-2.5-pro",
    #temperature=0
)

gemini_model_escalation = ChatGoogleGenerativeAI(
    google_api_key=keys["gemini"],
    model="gemini-2.5-flash",
    #temperature=0
)

gemini_model_flash = ChatGoogleGenerativeAI(
    google_api_key=keys["gemini"],
    model="gemini-2.5-flash-lite",
    #temperature=0
)

# call VCT registry
def trigger_generation(issuer: str, publish: bool = True, llm: bool = True) -> dict:
    API_URL = "https://vc-registry.com/vct/registry/api/generate_from_issuer"
    headers = {
        "Content-Type": "application/json",
        "X-API-Key": keys.get("generate_vct_from_issuer_key"),
    }
    payload = {
        "issuer": issuer,   # or use "issuers": ["url1", "url2"]
        "publish": publish,
        "llm": llm,
    }
    try:
        resp = requests.post(API_URL, headers=headers, data=json.dumps(payload), timeout=30)
        resp.raise_for_status()
        logging.info("Call to registry")
        return resp.json()
    except Exception as e:
        logging.error("Call to registry = %s ", str(e))


def get_llm_client(mode, provider):
    logging.info("mode = %s", mode)
    logging.info("provider = %s", provider)
    logging.info("engine = %s", engine(mode, provider))
    if mode == "flash":
        if provider == "openai":
            return openai_model_flash
        else:
            return gemini_model_flash
    elif mode == "escalation":
        if provider == "openai":
            return openai_model_escalation
        else:
            return gemini_model_escalation
    elif mode == "pro":
        if provider == "openai":
            return openai_model_pro
        else:
            return gemini_model_pro
    else:
        raise ValueError(f"Unsupported mode : {mode} or {provider}")


def engine(mode: str, provider: str ) -> str:
    if provider == "openai":
        return {
            "flash": "gpt-4o-mini",      # fast + accurate enough
            "escalation": "gpt-5-mini",  # medium depth
            "pro": "gpt-5"               # with spec-linking prompts
        }[mode]
    else:
        return {
            "flash": "gemini-2.5-flash-lite",      # fast + accurate enough
            "escalation": "gemini-2.5-flash",  # medium depth
            "pro": "gemini-2.5-pro"               # with spec-linking prompts
        }[mode]


# Configure logging
logging.basicConfig(level=logging.INFO)

# Define models and constants
ADVICE = "\n\nLLM can make mistakes. Check important info. For a deeper analysis, review the cryptographic binding methods, signing algorithms, and specific scopes supported by the issuer and authorization server."
MAX_RETRIES = 3
DELAY_SECONDS = 2

try:
    enc = tiktoken.encoding_for_model("gpt-5")
except Exception:
    # Some tiktoken versions may not have an explicit mapping for gpt-5 yet.
    # Prefer the newer 200k encoding if available; otherwise fall back to cl100k_base.
    try:
        enc = tiktoken.get_encoding("o200k_base")
    except Exception:
        enc = tiktoken.get_encoding("cl100k_base")


# ---------- Report style system (flash / escalation / pro) ----------

@dataclass
class ReportStyle:
    name: str
    bullets_max: int
    chars_per_bullet: int
    include_rationales: bool
    include_examples: bool
    include_spec_links: bool
    tone: str
    audience: str
    add_findings_counts: bool = False


REPORT_STYLES: Dict[str, ReportStyle] = {
    "flash": ReportStyle(
        name="flash",
        bullets_max=6,
        chars_per_bullet=160,
        include_rationales=False,
        include_examples=False,
        include_spec_links=False,
        tone="ultra-concise",
        audience="developer",
        add_findings_counts=True,
    ),
    "escalation": ReportStyle(
        name="escalation",
        bullets_max=12,
        chars_per_bullet=300,
        include_rationales=True,
        include_examples=False,
        include_spec_links=False,
        tone="concise",
        audience="developer",
    ),
    "pro": ReportStyle(
        name="pro",
        bullets_max=20,
        chars_per_bullet=480,
        include_rationales=True,
        include_examples=True,
        include_spec_links=True,
        tone="audit",
        audience="developer",
    ),
}


def style_for(model: str) -> ReportStyle:
    return REPORT_STYLES.get(model, REPORT_STYLES["escalation"])


# ---------- Spec link helpers for "pro" ----------
def spec_url_oidc4vci(draft: str) -> str:
    # https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-16.html
    try:
        specs = f"https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-{draft}.html"
    except Exception:
        specs = "https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html"
    logging.info("OIDC4VCI specs = %s", specs)
    return specs

        
def spec_url_oidc4vp(draft: str) -> str:
    # https://openid.net/specs/openid-4-verifiable-presentations-1_0-17.html
    try:
        specs = f"https://openid.net/specs/openid-4-verifiable-presentations-1_0-{draft}.html"
    except Exception:
        specs = "https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html"
    logging.info("OIDC4VP specs = %s", specs)
    return specs


def spec_url_sdjwtvc(draft: str) -> str:
    d = {"7": "07", "8": "08", "9": "09", "10": "10"}
    try:
        specs = f"https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-{d[draft]}.html"
    except Exception:
        specs = "https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-10.html"
    logging.info("SD-JWT VC specs = %s", specs)
    return specs



def spec_url_sdjwt(draft: str) -> str:
    d = {"22": "22"}
    try:
        specs = f"https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-{d[draft]}.html"
    except Exception:
        specs = "https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-22.html"
    logging.info("SD-JWT VC specs = %s", specs)
    return specs


def spec_url_vcdm(draft: str) -> str:
    if str(draft).startswith("2"):
        return "https://www.w3.org/TR/vc-data-model-2.0/"
    return "https://www.w3.org/TR/vc-data-model/"


def spec_url_haip() -> str:
    return "https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0.html"


# ---------- Prompt shaping per style ----------
def style_instructions(style: ReportStyle, domain: str, draft: str, extra_urls: Optional[Dict[str, str]] = None) -> str:
    base = [
        f"- Audience: {style.audience}. Tone: {style.tone}.",
        f"- Use Markdown. Max {style.bullets_max} bullets per section; keep bullets under ~{style.chars_per_bullet} chars.",
        "- Prefer short, technical wording (no fluff).",
    ]
    if style.add_findings_counts:
        base.append("- At the end of each section title, append (✓ pass / ⚠ warn / ✖ fail counts).")
    if style.include_rationales:
        base.append("- Provide 1-sentence rationale for each FAIL/WARN.")
    if style.include_examples:
        base.append("- When useful, include tiny examples (one-liners) for fixes (keep them brief).")
    if style.include_spec_links:
        base.append("- For each FAIL/WARN, add a **Spec** line with Markdown links to relevant sections.")
        urls = extra_urls or {}
        if domain == "oidc4vci":
            urls.setdefault("OIDC4VCI", spec_url_oidc4vci(draft))
        elif domain == "oidc4vp":
            urls.setdefault("OIDC4VP", spec_url_oidc4vp(draft))
        elif domain == "sdjwtvc":
            urls.setdefault("SD-JWT VC", spec_url_sdjwtvc(draft))
        elif domain in ("vcdm-jwt", "vcdm-jsonld"):
            urls.setdefault("VCDM", spec_url_vcdm(draft))
        if urls:
            base.append("- Use these base URLs for links: " + ", ".join([f"[{k}]({v})" for k, v in urls.items()]) + ".")
    if style.name == "flash":
        base.append("- Do not include any introduction or summary. Only the requested sections, as short checklists.")
    elif style.name == "escalation":
        base.append("- No introduction. Output the requested sections exactly as titled.")
    else:
        base.append("- No introduction. Output the requested sections exactly as titled. Add **Spec** links for each FAIL/WARN.")
    return "\n".join(base)


# ---------- Attribution footer ----------
def attribution(mode: str, spec_label: str, draft: str, provider: str) -> str:
    date = datetime.now().replace(microsecond=0).isoformat()
    base = (
        f"\n\nThe model {engine(mode, provider)} is used with the Web3 Digital Wallet dataset.\n"
        f"This report is based on {spec_label} {draft}.\n"
        f"Date of issuance: {date}. © Web3 Digital Wallet 2025."
    )
    if mode == "flash":
        return base + f"\nTip: 💡Switch to *Escalation* for deeper checks when results are uncertain."
    elif mode == "pro":
        return base + "\nSpec references included per finding. Always verify cryptographic operations with your conformance suite."
    return base + f"\nTip: 💡Switch to *Pro* for deeper checks and explicit links to specifications."


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


def load_leaf_cert_from_x5c(x5c_list):
    """Load the leaf certificate (first in x5c list) as an x509 object"""
    cert_der = base64.b64decode(x5c_list[0])
    return x509.load_der_x509_certificate(cert_der, default_backend())


def extract_san_domains_and_uris(cert):
    """Extract DNSNames and URIs from the SAN extension of the certificate"""
    try:
        san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
        dns_names = san.get_values_for_type(x509.DNSName)
        uris = san.get_values_for_type(x509.UniformResourceIdentifier)
        return dns_names, uris
    except x509.ExtensionNotFound:
        return [], []


def verify_issuer_matches_cert(issuer, x5c_list, token="vc"):
    cert = load_leaf_cert_from_x5c(x5c_list)
    dns_names, uris = extract_san_domains_and_uris(cert)

    match_dns = issuer in dns_names
    match_uri = issuer in uris
    
    subject = "Issuer" if token == "vc" else "client_id"
    if match_dns or match_uri:
        return f"Info: {subject} matches SAN DNS or URI in certificate."
    return (f"Error: {subject} does NOT match SAN DNS or URI in certificate. "
            f"SAN DNS in certificate = {dns_names} but {subject.lower()} = {issuer}")

def extract_SAN_DNS(pem_certificate):
    # Decode base64 and load the certificate
    cert_der = base64.b64decode(pem_certificate)
    cert = x509.load_der_x509_certificate(cert_der, backend=default_backend())
    # Extract SAN extension
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        dns_names = san.value.get_values_for_type(x509.DNSName)
        return dns_names
    except x509.ExtensionNotFound:
        return "Error: no SAN extension found in the x509 certificate."


async def process_vc_format(vc: str, sdjwtvc_draft: str, vcdm_draft: str, device: str, model: str, provider: str):
    """
    Detect the format of a Verifiable Credential (VC) and route to the correct analysis function.
    Args:
        vc (str): VC input as a string.
    Returns:
        str: Result of analysis or error message.
    """
    logging.info("VC received = %s", vc)
    if not vc:
        return "Invalid VC."

    # 1. SD-JWT: starts with base64 segment and uses '~' delimiter
    if "~" in vc and "." in vc.split("~")[0]:
        return analyze_sd_jwt_vc(vc, sdjwtvc_draft, device, model, provider)

    # 2. JWT VC (compact JWT): 3 base64 parts separated by dots
    if vc.count(".") == 2 and all(len(part.strip()) > 0 for part in vc.split(".")):
        return analyze_jwt_vc(vc, vcdm_draft, device, model, provider)

    # 3. JSON-LD: must be valid JSON with @context
    try:
        vc_json = json.loads(vc)
        if "@context" in vc_json and "type" in vc_json:
            return await analyze_jsonld_vc(vc_json, vcdm_draft, device, model, provider)
    except Exception as e:
        return "Invalid JSON. Cannot parse input. " + str(e)

    return "Unknown VC format. Supported formats: SD-JWT VC, JWT VC (compact), JSON-LD VC."




def _is_compact_jwt(value: str) -> bool:
    # quick check for "header.payload.signature" shape
    return isinstance(value, str) and value.count(".") == 2 and all(p.strip() for p in value.split("."))


def _safe_get_json(url: str, timeout: int = 10) -> Dict[str, Any]:
    if not url.lower().startswith(("https://", "http://")):
        raise ValueError("Only http(s) schemes are allowed for external fetches")
    headers = {"Accept": "application/json, */*;q=0.1"}
    r = requests.get(url, headers=headers, timeout=timeout)
    r.raise_for_status()
    return r.json()




def analyze_sd_jwt_vc(token: str, draft: str, device: str, model: str, provider: str) -> str:
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

    comment_1 = ""
    comment_2 = ""
    comment_3 = ""
    comment_4 = ""
    comment_5 = ""

    # Decode SD-JWT header and payload
    jwt_header = get_header_from_token(sd_jwt)
    jwt_payload = get_payload_from_token(sd_jwt)
    iss = jwt_payload.get("iss")
    kid = jwt_header.get("kid")
    vct = jwt_payload.get("vct")    
    integrity = jwt_payload.get("vct#integrity")
    
    if not iss:
        comment_1 = "Warning: iss is missing. iss is optional"
    elif iss.startswith("https://"):
        trigger_generation(iss)  # call VCT registry

    # check signature of the sd-jwt
    if x5c_list := jwt_header.get('x5c'):
        comment_1 = verify_issuer_matches_cert(iss, x5c_list)
        comment_4 = oidc4vc.verify_x5c_chain(x5c_list)
        try:
            # Extract the first certificate (leaf cert) from the x5c list
            cert_der = base64.b64decode(x5c_list[0])
            cert = x509.load_der_x509_certificate(cert_der)
            # Get public key from the cert
            public_key = cert.public_key()
            # Convert it to JWK format
            issuer_key = jwk.JWK.from_pyca(public_key)
            # Validate signature
            a = jwt.JWT.from_jose_token(sd_jwt)
            a.validate(issuer_key)
            comment_2 = "Info: VC is correctly signed with x5c public key"
        except Exception as e:
            comment_2 = f"Error: VC signature verification with x5c public key failed: {e}"

    elif jwt_header.get('jwk'):
        try:
            jwk_data = jwt_header['jwk']
            if isinstance(jwk_data, str):
                jwk_data = json.loads(jwk_data)
            issuer_key = jwk.JWK(**jwk_data)
            # Validate signature
            a = jwt.JWT.from_jose_token(sd_jwt)
            a.validate(issuer_key)
            comment_2 = "Info: VC is correctly signed with jwk in header"
        except Exception as e:
            comment_2 = f"Error: VC signature verification with jwk in header failed: {e}"

    elif kid:
        if iss and iss.startswith("did:"):
            if kid.startswith("did:"):
                pub_key = oidc4vc.resolve_did(kid)
                try:
                    issuer_key = jwk.JWK(**pub_key)
                    a = jwt.JWT.from_jose_token(sd_jwt)
                    a.validate(issuer_key)
                    comment_2 = "Info: VC is correctly signed with DID"
                except Exception as e:
                    comment_2 = f"Error: VC is not signed correctly with DID: {e}"
            else:
                comment_2 = "Error: kid should be a DID verification method"

        elif iss and iss.split(":")[0] in ["http", "https"]:
            parsed = urlparse(jwt_payload.get('iss'))
            domain = parsed.netloc
            path = parsed.path
            scheme = parsed.scheme
            well_known_url = f"{scheme}://{domain}/.well-known/jwt-vc-issuer{path}"
            logging.info("well known url = %s", well_known_url)

            try:
                metadata = requests.get(well_known_url, timeout=5).json()

                # Case 1: Embedded JWKS
                if "jwks" in metadata:
                    keys = metadata["jwks"].get("keys", [])

                # Case 2: External JWKS URI
                elif "jwks_uri" in metadata:
                    jwks_uri = metadata["jwks_uri"]
                    response = requests.get(jwks_uri, timeout=5)
                    response.raise_for_status()
                    jwks = response.json()
                    keys = jwks.get("keys", [])
                else:
                    comment_2 = "Error: Public key is not available in well-known/jwt-vc-issuer"
                    keys = []

                # Try to match key by 'kid'
                matching_key = next((key for key in keys if key.get('kid') == kid), None)

                if matching_key:
                    try:
                        issuer_key = jwk.JWK(**matching_key)
                        a = jwt.JWT.from_jose_token(sd_jwt)
                        a.validate(issuer_key)
                        comment_2 = "Info: VC is correctly signed with public key from issuer metadata"
                    except Exception as e:
                        comment_2 = f"Error: Signature validation failed: {e}"
                else:
                    comment_2 = f"Error: No matching key found for kid={kid}"

            except Exception as e:
                comment_2 = f"Error: Failed to fetch or parse issuer metadata: {e}"
        else:
            comment_2 = "Error: 'iss' is missing or improperly formatted."
    else:
        comment_2 = "Error: kid or x5c or jwk is missing in the header"
        
    # vct and vct#integrity 
    vct_json = {}
    if vct and vct.startswith("http"):
        try:
            resp = requests.get(vct, timeout=8)
            resp.raise_for_status()
            vct_json = resp.json()
            logging.info("vct JSON fetched successfully")
            if not integrity:
                comment_5 = "Warning: vct is available but vct#integrity is not provided"
            else:
                comment_5 = "Info: vct and vct#integrity have been uploaded"
        except requests.exceptions.RequestException as e:
            comment_5 = f"Error: could not fetch vct ({e})"
        except ValueError as e:
            comment_5 = f"Error: invalid JSON in vct ({e})"
            
    # Determine whether the last part is a Key Binding JWT (assumed to be a JWT if it contains 2 dots)
    is_kb_jwt = vcsd[-1].count('.') == 2

    # Disclosures are everything between vcsd[1] and vcsd[-2] if KB is present, otherwise vcsd[1:]
    disclosure_parts = vcsd[1:-1] if is_kb_jwt else vcsd[1:]

    # Decode disclosures
    try:
        disclosures = "\r\n".join(
            base64url_decode(part).decode() for part in disclosure_parts
        )
        comment_3 = "Info: Disclosures are formatted correctly"
    except Exception as e:
        comment_3 = f"Error: Disclosures are not formatted correctly: {e}"
        disclosures = "Error: Disclosures could not be decoded."

    logging.info("comment 1 = %s", comment_1)
    logging.info("comment 2 = %s", comment_2)
    logging.info("comment 3 = %s", comment_3)
    logging.info("comment 4 = %s", comment_4)
    logging.info("comment 5 = %s", comment_5) # vct

    # Decode Key Binding JWT (KB-JWT) if present
    if is_kb_jwt:
        kb_header = get_header_from_token(vcsd[-1])
        kb_payload = get_payload_from_token(vcsd[-1])
    else:
        kb_header = kb_payload = "No Key Binding JWT"

    # Load the appropriate SD-JWT VC specification content based on draft
    try:
        with open(f"./dataset/sdjwtvc/{draft}.txt", "r") as f:
            content = f.read()
    except FileNotFoundError:
        with open("./dataset/sdjwtvc/9.txt", "r") as fallback:
            content = fallback.read()
            draft = "9"
    
    # Load the appropriate SD-JWT specification (Draft 22)
    try:
        with open(f"./dataset/sdjwt/22.txt", "r") as f:
            content += "#\n\n" + f.read()
    except FileNotFoundError:
        logging.warning("SD-JWT specs not found")
        
            
    # Load the appropriate token status list specification (Draft 12)
    try:
        with open(f"./dataset/tsl/12.txt", "r") as f:
            content += "#\n\n" + f.read()
    except FileNotFoundError:
        logging.warning("TSL specs not found")
    
    # SD-JWT token status list lookup
    try:
        token_status_list_result = tsl.check_sd_jwt_vc_status(
            token,
            statuslist_jwt_jwk=None,
            statuslist_jwt_jwks_url=None,
            verify_statuslist_sig=False
        )
    except Exception as e:
        token_status_list_result = str(e)
    logging.info("lookup status list result = %s", token_status_list_result)

    
    # Token count logging for diagnostics
    tokens = enc.encode(content)
    logging.info("Token count: %s", len(tokens))

    # Timestamp and attribution
    mention = attribution(model, "SD-JWT VC", draft, provider)
    st = style_for(model)
    instr = style_instructions(st, domain="sdjwtvc", draft=draft)

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

    --- Comments ---
    {comment_1}
    {comment_2}
    {comment_3}
    {comment_4}
    {comment_5}
    
    ### vct and vct#integrity
    { vct_json}

    ### token status list lookup
    {token_status_list_result}
    
    ### Output style
    {instr}

    ### Report Sections (use these exact titles):
    1. **Holder & Issuer Identifiers**
    2. **Header Required Claims**
    3. **Payload Required Claims**
    4. **Key Binding JWT Check**
    5. **Signature Information**
    6. **Errors & Improvements**

    """

    # Call the OpenAI API
    llm = get_llm_client(model,provider)  # Add 'provider' param to function
    response = llm.invoke([
        {"role": "system", "content": "You are an expert in SD-JWT VC specifications compliance."},
        {"role": "user", "content": prompt}
        ]).content

    # Update usage stats and return response
    counter_update(device)
    return response + ADVICE + mention


def analyze_jwt_vc(token, draft, device, model, provider):
    """
    Analyze a Verifiable Presentation (VP) in JWT format and return a structured report.

    Args:
        token (str): The full token, formatted as base64url sections separated by `~`
        draft (str): Draft version number to load the appropriate spec documentation

    Returns:
        str: A markdown-formatted compliance report generated using OpenAI
    """

    # Decode SD-JWT header and payload
    jwt_header = get_header_from_token(token)
    jwt_payload = get_payload_from_token(token)
    
    kid = jwt_header.get("kid")
    iss = jwt_payload.get("iss")
    typ = jwt_header.get("typ")
    
    # Security check
    if typ in ["dc+sd-jwt", "vc+sd-jwt"]:
        logging.warning("VC analyze is redirected to sd-jwt process")
        return analyze_sd_jwt_vc(token, draft, device, model, provider)
    
    comment_1 = ""
    comment_2 = ""
    if kid:
        if iss and iss.startswith("did:"):
            if kid.startswith("did:"):
                pub_key = oidc4vc.resolve_did(kid)
                if not pub_key:
                    comment_1 = "Error: the kid is a DID but does not resolve."
                try:
                    issuer_key = jwk.JWK(**pub_key)
                    a = jwt.JWT.from_jose_token(token)
                    a.validate(issuer_key)
                    comment_2 = "Info: The kid resolves and the JWT-VC is correctly signed with DID"
                except Exception as e:
                    comment_2 = f"Error: JWT-VC is not signed correctly with DID: {e}"
            else:
                comment_1 = "Error: kid should be a DID verification method"
    # Load the appropriate specification content based on draft
    try:
        with open(f"./dataset/vcdm/{draft}.txt", "r") as f:
            content = f.read()
    except FileNotFoundError:
        with open("./dataset/vcdm/1.1.txt", "r") as fallback:
            draft = "1.1"
            content = fallback.read()
            
    # Load the appropriate Bitstring status list specification
    try:
        with open(f"./dataset/bsl/1.txt", "r") as f:
            content += "#\n\n" + f.read()
    except FileNotFoundError:
        logging.warning("BSL specs not found")
        
    # JSON-LD Bitstring status list lookup
    try:
        bistring_status_list_result = bsl.check_bitstring_status_jsonld(
            token,
            preferred_purpose="revocation",
            require_proof=False)
    except Exception as e:
        bistring_status_list_result = str(e)
    logging.info("lookup bitstring status list result = %s", bistring_status_list_result)


    # Token count logging for diagnostics
    tokens = enc.encode(content)
    logging.info("Token count: %s", len(tokens))

    # Timestamp and attribution
    mention = attribution(model, "VCDM", draft, provider)

    # Prompt for OpenAI model
    st = style_for(model)
    instr = style_instructions(st, domain="vcdm-jwt", draft=draft)

    prompt = f"""
--- Specifications ---
{content}

--- VC Data for Analysis ---
VC Header: {json.dumps(jwt_header, indent=2)}
VC Payload: {json.dumps(jwt_payload, indent=2)}

--- Comments ---
    {comment_1}
    {comment_2}

### token status list lookup
{bistring_status_list_result}

### Output style
{instr}

### Report Sections (use these exact titles):
1. **Holder & Issuer Identifiers**
2. **All Claims**
3. **Header Required Claims**
4. **Payload Required Claims**
5. **Errors & Improvements**

"""
    # Call the LLM API
    llm = get_llm_client(model, provider)  # Add 'provider' param to function
    response = llm.invoke([
        {"role": "system", "content": "You are an expert in JWT VC specifications compliance."},
        {"role": "user", "content": prompt}
    ]).content

    # Update usage stats and return response
    counter_update(device)
    return response + ADVICE + mention


async def analyze_jsonld_vc(vc: str, draft: str, device: str, model: str, provider: str) -> str:
    """
    Analyze a Verifiable Presentation (VP) in JSON-LD format and return a structured report.

    Args:
        vc (str): The full VC,
        draft (str): Draft version number to load the appropriate spec documentation

    Returns:
        str: A markdown-formatted compliance report generated using OpenAI
    """
    
    # take draft depending on @context
    if "https://www.w3.org/ns/credentials/v2" in vc.get("@context"):
        draft = "2.0"
        logging.warning("Draft has been updated to 2.0")
    elif "https://www.w3.org/2018/credentials/v1" in vc.get("@context"):
        draft = "1.1"
        logging.warning("Draft has been updated to 1.1")
    
    # Load the appropriate specification contenif not presentation_definition:
    # still analyze the request and return it
    try:
        with open(f"./dataset/vcdm/{draft}.txt", "r", encoding="utf-8") as f:
            content = f.read()
    except FileNotFoundError:
        with open("./dataset/vcdm/1.1.txt", "r", encoding="utf-8") as fallback:
            content = fallback.read()
            draft = "1.1"
    
    # Load the appropriate Bitstring status list specification
    try:
        with open(f"./dataset/bsl/1.txt", "r") as f:
            content += "#\n\n" + f.read()
        logging.warning("BSL specs merged")
    except FileNotFoundError:
        logging.warning("BSL specs not found")
        
        
    # JSON-LD Bitstring status list lookup
    try:
        bistring_status_list_result = bsl.check_bitstring_status_jsonld(
            vc,
            preferred_purpose="revocation",
            require_proof=False )
    except Exception as e:
        bistring_status_list_result = str(e)
    logging.info("lookup bitstring status list result = %s", bistring_status_list_result)
    
    
    # json_ld proof check
    if draft == "1.1":
        try:
            check_signature_result = await didkit.verify_credential(json.dumps(vc), '{}')
        except Exception as e:
            check_signature_result = str(e)
    else:
        check_signature_result = "Proof has not been checked."
    logging.info("check signature proof =%s", check_signature_result)
        
        
    # Token count logging for diagnostics
    tokens = enc.encode(content)
    # still analyze the request and return it
    logging.info("Token count: %s", len(tokens))

    # Timestamp and attribution
    mention = attribution(model, "VCDM", draft, provider)
    st = style_for(model)
    instr = style_instructions(st, domain="vcdm-jsonld", draft=draft)

    prompt = f"""
--- Specifications ---
{content}

--- VC Data for Analysis ---
JSON-LD VC : {json.dumps(vc, indent=2)}

### Proof check
{check_signature_result}

### token status list lookup
{bistring_status_list_result}

### Output style
{instr}

### Report Sections (use these exact titles):
1. **Holder & Issuer Identifiers**
2. **All Claims**
3. **Required Claims Check**
4. **Errors & Improvements**

"""


    # Call the OpenAI API
    llm = get_llm_client(model, provider)  # Add 'provider' param to function
    response = llm.invoke([
        {"role": "system", "content": "You are an expert in VC DM specifications compliance."},
        {"role": "user", "content": prompt}
    ]).content

    # Update usage stats and return response
    counter_update(device)
    return response + ADVICE + mention



def report_to_json_via_gpt(
    report_text: str,
    *,
    model: str = "flash",
    profile: str = "",
    input: Optional[Dict[str, Any]] = None,  # e.g., {"kind":"verifier_qr"} | {"kind":"issuer_qr"} | {"kind":"vc_sdjwt"} | {"kind":"vc_jsonld"} | {"kind":"vc_jwt"}
    drafts: Optional[Dict[str, str]] = None, # e.g., {"oidc4vci":"14","oidc4vp":"18","sdjwtvc":"10","vcdm":"2.0"}
    tool_version: str = "1.0.0",
) -> Dict[str, Any]:
    """
    LLM-based extractor that converts your human-readable report into a strict, machine-readable JSON object.
    Supports OIDC4VP / OIDC4VCI QR analyses and VC audits (SD-JWT VC, JSON-LD VC, VC-JWT).
    Returns a dict (never a raw string). If parsing fails, returns a minimal JSON object with zero findings.
    """
    # Safe defaults
    drafts = drafts or {}

    # ISO 8601 timestamp, Zulu
    timestamp = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

    # --------- RULES & CODES (for the model to use consistently) ----------
    # We ask the model to emit these codes/severities/messages when it detects them in the report.
    # This stabilizes outputs across: OIDC4VP, OIDC4VCI, SD-JWT VC, JSON-LD VC, VC-JWT.
    if input["kind"] == "VC analysis":
        rules_catalog = RULES_CATALO_VC
    else:
        rules_catalog = RULES_CATALO_OIDC4VC

    # Schema template (the model must fill this)
    schema_template = {
        "tool": "ai-agent",
        "version": tool_version,
        "input": input,
        "profile": profile,
        "drafts": drafts,
        "timestamp": timestamp,
        "summary": {"pass": 0, "warn": 0, "fail": 0},
        "findings": [
            # { "code":"...", "severity":"PASS|WARN|FAIL|INFO", "message":"...", "component":"..." , "spec":"<optional>", "location":"<optional>", "fix":"<optional>" }
        ],
    }

    # ---------- Prompt ----------
    system = (
        "You are a strict extractor that converts compliance reports into machine-readable JSON. "
        "Always return ONLY JSON that conforms to the required shape. No prose."
    )

    # Pass the rules catalog & shape as JSON strings so quoting is correct
    user = f"""
Extract machine-readable findings from the report below.

### Required JSON shape
{json.dumps(schema_template, ensure_ascii=False, indent=2)}

### Stable codes catalogue (choose the most appropriate; do not invent random codes)
{json.dumps(rules_catalog, ensure_ascii=False, indent=2)}

### Rules
- Return ONLY JSON. No markdown, no extra text.
- 'summary' MUST equal the counts derived from 'findings' (WARN → warn, FAIL → fail, PASS → pass; ignore INFO).
- Use codes from the catalogue above when possible (e.g., OIDC4VP_PD_MISSING, OIDC4VCI_OFFER_MISSING, SDJWTVC_ISS_MISSING, JSONLD_CONTEXT_MISSING, VCJWT_TYP_INVALID).
- Set 'component' appropriately: one of ["auth_request","presentation_definition","credential_offer","issuer_metadata","vc","kb_jwt","network","general"].
- Add optional fields when you can: 'spec' (URL), 'location' (JSONPath/field path), 'fix' (short hint).
- If the report indicates everything is OK for a specific check, you MAY add PASS items (sparingly).
- If nothing is extractable, return the shape with an empty 'findings' array and zeros in 'summary'.

--- REPORT START ---
{report_text}
--- REPORT END ---
""".strip()

    # ---------- LLM call ----------
    llm = get_llm_client(model, "openai")  # your existing helper
    resp_text = llm.invoke([
        {"role": "system", "content": system},
        {"role": "user", "content": user},
    ]).content

    # ---------- Parse & harden ----------
    def _coerce_json(payload: str) -> Optional[Dict[str, Any]]:
        try:
            return json.loads(payload)
        except Exception:
            # Try to salvage a JSON object from the text (first { ... } block)
            m = re.search(r"\{[\s\S]*\}$", payload.strip())
            if not m:
                return None
            try:
                return json.loads(m.group(0))
            except Exception:
                return None

    obj = _coerce_json(resp_text) or {
        "tool": "ai-agent",
        "version": tool_version,
        "input": input,
        "profile": profile,
        "drafts": drafts,
        "timestamp": timestamp,
        "summary": {"pass": 0, "warn": 0, "fail": 0},
        "findings": []
    }

    # Normalize minimal invariants
    if "summary" not in obj or "findings" not in obj or not isinstance(obj.get("findings"), list):
        obj["summary"] = {"pass": 0, "warn": 0, "fail": 0}
        obj["findings"] = []

    # Recompute summary to be safe
    counts = {"pass": 0, "warn": 0, "fail": 0}
    for f in obj["findings"]:
        sev = (f.get("severity") or "").upper()
        if sev == "WARN": counts["warn"] += 1
        elif sev == "FAIL": counts["fail"] += 1
        elif sev == "PASS": counts["pass"] += 1
    obj["summary"] = counts

    # Ensure required top-level fields exist
    obj.setdefault("tool", "ai-agent")
    obj.setdefault("version", tool_version)
    obj.setdefault("input", input)
    obj.setdefault("profile", profile)
    obj.setdefault("drafts", drafts)
    obj.setdefault("timestamp", timestamp)
    
    print("json =", json.dumps(obj, indent=4))

    return obj
