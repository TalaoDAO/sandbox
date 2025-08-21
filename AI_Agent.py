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
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import ExtensionOID
#from cryptography.hazmat.primitives import serialization
import oidc4vc
from jwcrypto import jwk, jwt
from langchain_openai import ChatOpenAI
#from langchain_google_genai import ChatGoogleGenerativeAI
from typing import Any, Dict, Optional, Tuple
from dataclasses import dataclass


# Load API keys
with open("keys.json", "r") as f:
    keys = json.load(f)


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

"""
gemini_model = ChatGoogleGenerativeAI(
    google_api_key=keys["gemini"],
    model="gemini-2.5-pro",
    #temperature=0
)

gemini_model_flash = ChatGoogleGenerativeAI(
    google_api_key=keys["gemini"],
    model="gemini-2.5-flash",
    #temperature=0
)
"""


def get_llm_client(model):
    logging.info("model = %s", model)
    if model == "flash":
        return openai_model_flash
    elif model == "escalation":
        return openai_model_escalation
    elif model == "pro":
        return openai_model_pro
    else:
        raise ValueError(f"Unsupported provider: {model}")


def engine(model: str) -> str:
    return {
        "flash": "gpt-4o-mini",      # fast + accurate enough
        "escalation": "gpt-5-mini",       # medium depth
        "pro": "gpt-5"               # with spec-linking prompts
    }[model]


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


def spec_url_vcdm(draft: str) -> str:
    if str(draft).startswith("2"):
        return "https://www.w3.org/TR/vc-data-model-2.0/"
    return "https://www.w3.org/TR/vc-data-model/"


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
def attribution(model: str, spec_label: str, draft: str) -> str:
    date = datetime.now().replace(microsecond=0).isoformat()
    base = (
        f"\n\nThe model {engine(model)} is used with the Web3 Digital Wallet dataset.\n"
        f"This report is based on {spec_label} {draft}.\n"
        f"Date of issuance: {date}. © Web3 Digital Wallet 2025."
    )
    if model == "flash":
        return base + "\nTip: Switch to *Escalation* for deeper checks when results are uncertain."
    elif model == "pro":
        return base + "\nSpec references included per finding. Always verify cryptographic operations with your conformance suite."
    return base + "\nLLMs can make mistakes. Verify cryptographic results."


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


def verify_issuer_matches_cert(issuer, x5c_list):
    cert = load_leaf_cert_from_x5c(x5c_list)
    dns_names, uris = extract_san_domains_and_uris(cert)

    match_dns = issuer in dns_names
    match_uri = any(issuer == uri or issuer in uri for uri in uris)

    if match_dns or match_uri:
        return "Info: Issuer matches SAN DNS or URI in certificate."
    else:
        return "Error: Issuer does NOT match SAN DNS or URI in certificate."


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


def process_vc_format(vc: str, sdjwtvc_draft: str, vcdm_draft: str, device: str, model: str):
    """
    Detect the format of a Verifiable Credential (VC) and route to the correct analysis function.
    Args:
        vc (str): VC input as a string.
    Returns:
        str: Result of analysis or error message.
    """

    # 1. SD-JWT: starts with base64 segment and uses '~' delimiter
    if "~" in vc and "." in vc.split("~")[0]:
        return analyze_sd_jwt_vc(vc, sdjwtvc_draft, device, model)

    # 2. JWT VC (compact JWT): 3 base64 parts separated by dots
    if vc.count(".") == 2 and all(len(part.strip()) > 0 for part in vc.split(".")):
        return analyze_jwt_vc(vc, vcdm_draft, device, model)

    # 3. JSON-LD: must be valid JSON with @context
    try:
        vc_json = json.loads(vc)
        if "@context" in vc_json and "type" in vc_json:
            return analyze_jsonld_vc(vc_json, vcdm_draft, device, model)
    except Exception as e:
        return "Invalid JSON. Cannot parse input. " + str(e)

    return "Unknown VC format. Supported formats: SD-JWT VC, JWT VC (compact), JSON-LD VC."


def analyze_qrcode(qrcode, oidc4vciDraft, oidc4vpDraft, profil, device, model):
    # Analyze a QR code and delegate based on protocol type
    profile = ""
    if profil == "EBSI":
        oidc4vciDraft = "11"
        oidc4vpDraft = "18"
        profile = "Use only jwt_vc format. Use only did:key and did:ebsi as identifier"
    elif profil == "DIIP_V3":
        oidc4vciDraft = "13"
        oidc4vpDraft = "20"
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
        return analyze_issuer_qrcode(qrcode, oidc4vciDraft, profile, device, model)
    else:
        return analyze_verifier_qrcode(qrcode, oidc4vpDraft, profile, device, model)


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


def _safe_get_text(url: str, timeout: int = 10) -> requests.Response:
    if not url.lower().startswith(("https://", "http://")):
        raise ValueError("Only http(s) schemes are allowed for external fetches")
    headers = {"Accept": "application/oauth-authz-req+jwt, text/plain;q=0.5, */*;q=0.1"}
    r = requests.get(url, headers=headers, timeout=timeout)
    r.raise_for_status()
    return r



def _content_type_is_authz_req_jwt(value: Optional[str]) -> bool:
    # Accept "application/oauth-authz-req+jwt" with optional parameters (charset=..., etc.)
    if not value:
        return False
    return value.split(";")[0].strip().lower() == "application/oauth-authz-req+jwt"


def get_verifier_request(qrcode: str, draft: str) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]], str]:
    """
    Parse a Verifier authorization request from a QR (OIDC4VP).
    Returns: (authorization_request_dict, presentation_definition_or_dcql, comment)
    - If a fatal problem occurs, (None, None, "Error: ...") is returned.
    """
    comments: list[str] = []
    try:
        parse_result = urlparse(qrcode)
        # Keep single-value params only; ignore repeated keys for simplicity
        query: Dict[str, str] = {k: v[0] for k, v in parse_qs(parse_result.query).items()}
    except Exception as e:
        return None, None, f"Error: cannot parse QR: {e}"

    request: Optional[Dict[str, Any]] = None
    presentation_obj: Optional[Dict[str, Any]] = None

    # 1) request_uri → fetch JWT
    if request_uri := query.get("request_uri"):
        try:
            resp = _safe_get_text(request_uri, timeout=10)
            request_jwt = resp.text.strip()
        except Exception as e:
            return None, None, f"Error: the request_uri could not be fetched: {e}"

        # Verify media type but accept minor variations (charset)
        if not _content_type_is_authz_req_jwt(resp.headers.get("Content-Type")):
            return None, None, "Error: request_uri response must be 'application/oauth-authz-req+jwt'"
        
        # Decode signed request JWT
        try:
            request = get_payload_from_token(request_jwt)
            header = get_header_from_token(request_jwt)
        except Exception as e:
            return None, None, f"Error: cannot decode request JWT: {e}"

        # x5c / iss binding (optional but recommended)
        if isinstance(header, dict) and (x5c_list := header.get("x5c")):
            iss = request.get("iss")
            if not iss:
                return None, None, "Error: iss is missing"
            comments.append(verify_issuer_matches_cert(iss, x5c_list))

    # 2) request (inline) → parse JWT
    elif inline_req := query.get("request"):
        request_jwt = inline_req.strip()
        if not _is_compact_jwt(request_jwt):
            return None, None, "Error: 'request' parameter is not a compact JWS"
        try:
            request = get_payload_from_token(request_jwt)
            header = get_header_from_token(request_jwt)
        except Exception as e:
            return None, None, f"Error: cannot decode inline request JWT: {e}"

        if isinstance(header, dict) and (x5c_list := header.get("x5c")):
            iss = request.get("iss")
            if not iss:
                return None, None, "Error: iss is missing"
            comments.append(verify_issuer_matches_cert(iss, x5c_list))

    # 3) Plain query params (least secure)
    elif query.get("response_mode"):
        request = query  # keep as-is
        comments.append(
            "Warning: Using plain query parameters. A signed 'request' or 'request_uri' JWT is more secure."
        )
    else:
        return None, None, "Error: no authorization request found (missing request_uri / request / response_mode)."

    # 4) Presentation Definition / DCQL resolution
    if not isinstance(request, dict):
        return None, None, "Error: malformed authorization request"

    # presentation_definition_uri
    if (pd_uri := request.get("presentation_definition_uri")):
        try:
            presentation_obj = _safe_get_json(pd_uri, timeout=10)
            # normalize: move into the request and drop the URI (helpers expect embedded PD)
            request = dict(request)
            request.pop("presentation_definition_uri", None)
            request["presentation_definition"] = presentation_obj
            comments.append("Info: Verifier uses 'presentation_definition_uri'.")
        except Exception as e:
            return request, None, f"Error: the Presentation Definition could not be fetched: {e}"

    # dcql_query (draft >= 23)
    elif request.get("dcql_query") and int(draft) >= 23:
        presentation_obj = {"dcql_query": request.get("dcql_query")}
        comments.append("Info: Verifier uses 'dcql_query' (Digital Credential Query).")

    # embedded presentation_definition
    elif request.get("presentation_definition"):
        try:
            # Ensure it’s a dict (some send JSON-encoded strings)
            pd = request["presentation_definition"]
            if isinstance(pd, str):
                pd = json.loads(pd)
            if not isinstance(pd, dict):
                raise ValueError("presentation_definition is not a JSON object")
            presentation_obj = pd
            comments.append("Info: Verifier embeds 'presentation_definition'.")
        except Exception as e:
            return request, None, f"Error: invalid embedded Presentation Definition: {e}"

    else:
        comments.append("Warning: No Presentation Definition / DCQL parameter found.")

    # Optional sanity: ensure required OIDC params exist (response_type, client_id, redirect_uri, scope, nonce/state, etc.)
    # Keep it advisory; don’t fail here to let the analyzer produce a full report later.
    for k in ("client_id", "redirect_uri"):
        if k not in request:
            comments.append(f"Warning: '{k}' is missing in authorization request.")

    return request, presentation_obj, "\n".join(comments)



def analyze_sd_jwt_vc(token: str, draft: str, device: str, model: str) -> str:
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

    # Decode SD-JWT header and payload
    jwt_header = get_header_from_token(sd_jwt)
    jwt_payload = get_payload_from_token(sd_jwt)
    iss =  jwt_payload.get("iss")
    kid =  jwt_header.get("kid")

    if not iss:
        comment_1 = "Error: iss is missing"

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
        with open("./dataset/sdjwtvc/9.txt", "r") as fallback:
            content = fallback.read()
            draft = "9"

    # Token count logging for diagnostics
    tokens = enc.encode(content)
    logging.info("Token count: %s", len(tokens))

    # Timestamp and attribution
    date = datetime.now().replace(microsecond=0).isoformat()
    mention = attribution(model, "SD-JWT VC", draft)
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
    llm = get_llm_client(model)  # Add 'provider' param to function
    response = llm.invoke([
        {"role": "system", "content": "You are an expert in SD-JWT VC specifications compliance."},
        {"role": "user", "content": prompt}
        ]).content

    # Update usage stats and return response
    counter_update(device)
    return response + ADVICE + mention


def analyze_jwt_vc(token, draft, device, model):
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
    mention = attribution(model, "VCDM", draft)


    # Prompt for OpenAI model

    st = style_for(model)
    instr = style_instructions(st, domain="vcdm-jwt", draft=draft)

    prompt = f"""
--- Specifications ---
{content}

--- VC Data for Analysis ---
VC Header: {json.dumps(jwt_header, indent=2)}
VC Payload: {json.dumps(jwt_payload, indent=2)}

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
    llm = get_llm_client(model)  # Add 'provider' param to function
    response = llm.invoke([
        {"role": "system", "content": "You are an expert in JWT VC specifications compliance."},
        {"role": "user", "content": prompt}
    ]).content

    # Update usage stats and return response
    counter_update(device)
    return response + ADVICE + mention


def analyze_jsonld_vc(vc: str, draft: str, device: str, model: str) -> str:
    """
    Analyze a Verifiable Presentation (VP) in JSON-LD format and return a structured report.

    Args:
        vc (str): The full VC,
        draft (str): Draft version number to load the appropriate spec documentation

    Returns:
        str: A markdown-formatted compliance report generated using OpenAI
    """

    # Load the appropriate specification contenif not presentation_definition:
    comment += "\nWarning: No presentation definition found"
    # still analyze the request and return it
    try:
        with open(f"./dataset/vcdm/{draft}.txt", "r", encoding="utf-8") as f:
            content = f.read()
    except FileNotFoundError:
        with open("./dataset/vcdm/1.1.txt", "r", encoding="utf-8") as fallback:
            content = fallback.read()
            draft = "1.1"

    # Token count logging for diagnostics
    tokens = enc.encode(content)
    comment += "\nWarning: No presentation definition found"
    # still analyze the request and return it
    logging.info("Token count: %s", len(tokens))

    # Timestamp and attribution
    date = datetime.now().replace(microsecond=0).isoformat()
    mention = attribution(model, "VCDM", draft)
    st = style_for(model)
    instr = style_instructions(st, domain="vcdm-jsonld", draft=draft)

    prompt = f"""
--- Specifications ---
{content}

--- VC Data for Analysis ---
JSON-LD VC : {json.dumps(vc, indent=2)}

### Output style
{instr}

### Report Sections (use these exact titles):
1. **Holder & Issuer Identifiers**
2. **All Claims**
3. **Required Claims Check**
4. **Errors & Improvements**

"""


    # Call the OpenAI API
    llm = get_llm_client(model)  # Add 'provider' param to function
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


def analyze_issuer_qrcode(qrcode, draft, profile, device, model):
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
        f.close()
        draft = "13"

    # Token count logging for diagnostics
    tokens = enc.encode(context)
    logging.info("Token count: %s", len(tokens))

    context = clean_md(context)
    if int(draft) <= 11:
        context += "\n If EBSI tell to the user to add did:key:jwk_jcs-pub as subject_syntax_type_supported in the authorization server metadata"
    mention = attribution(model, "OIDC4VCI", draft)


    st = style_for(model)
    instr = style_instructions(st, domain="oidc4vci", draft=draft)
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

    ### Output style
{instr}

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

    llm = get_llm_client(model)
    response = llm.invoke(messages).content

    result = response + ADVICE + mention
    counter_update(device)
    store_report(qrcode, result, "issuer")
    return result


def analyze_verifier_qrcode(qrcode, draft, profile, device, model):

    # Analyze verifier QR code and generate a structured report using OpenAI
    if not draft:
        draft = "18"

    date = datetime.now().replace(microsecond=0).isoformat() + 'Z'
    verifier_request, presentation_definition, comment = get_verifier_request(qrcode, draft)
    if not verifier_request:
        return comment
    
    if not presentation_definition:
    # request is valid but no PD/DCQL → keep request and warn
        comment += "\n Error: No presentation definition found"
    
    try:
        f = open("./dataset/oidc4vp/" + draft + ".md", "r")
        context = f.read()
        f.close()
    except Exception:
        f = open("./dataset/oidc4vp/18.md", "r")
        context = f.read()
        f.close()
        draft = "18"

    context = clean_md(context)

    # Token count logging for diagnostics
    tokens = enc.encode(context)
    logging.info("Token count: %s", len(tokens))

    mention = attribution(model, "OIDC4VP", draft)


    st = style_for(model)
    instr = style_instructions(st, domain="oidc4vp", draft=draft)
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

    --- Comment ---
    {comment}

    --- Authorization Request ---
    {json.dumps(verifier_request, indent=2)}

    --- Presentation Definition ---
    {json.dumps(presentation_definition, indent=2)}

    ### Output style
{instr}

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

    llm = get_llm_client(model)  # Add 'provider' param to function
    response = llm.invoke(messages).content

    result = response + ADVICE + mention
    counter_update(device)
    store_report(qrcode, result, "verifier")
    return result
