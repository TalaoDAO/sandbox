"""
QR Code Analyzer for OIDC4VCI and OIDC4VP using OpenAI models
This module processes QR code data, validates VC/VP tokens, interacts with OpenAI to generate reports,
and stores results with Slack notifications and file logging.


all specs are https://openid.net/specs/ 
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
import oidc4vc
from jwcrypto import jwk, jwt
from langchain_openai import ChatOpenAI
from langchain_google_genai import ChatGoogleGenerativeAI
from dataclasses import dataclass
from typing import Optional, Tuple, Any, Dict, List

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
        logging.error("call to registry = %s ", str(e))


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
    if spec_label == "OIDC4VCI" and draft == "18":
        draft = "Final 1.0"
    if spec_label == "OIDC4VP" and draft == "30":
        draft = "Final 1.0"
    base = (
        f"\n\nThe model {engine(mode, provider)} is used with the Web3 Digital Wallet dataset.\n"
        f"This report is based on {spec_label} {draft}.\n"
        f"Date of issuance: {date}. © Web3 Digital Wallet / Talao 2026."
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


def verify_issuer_matches_cert(issuer, x5c_list, draft, token="vc"):
    cert = load_leaf_cert_from_x5c(x5c_list)
    dns_names, uris = extract_san_domains_and_uris(cert)

    if int(draft) < 23:
        match_dns = issuer in dns_names
        match_uri = issuer in uris
    else:
        try:
            match_dns = issuer.split(":")[1] in dns_names
            match_uri = issuer.split(":")[1] in uris
        except Exception:
            return f"Error: {issuer} is not correctly formatted for this OIDC4VP Draft."

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
    

def analyze_qrcode(qrcode, oidc4vciDraft, oidc4vpDraft, profil, device, model, provider):
    
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
        profile = profil
    elif profil == "INJI":
        oidc4vciDraft = "13"
        oidc4vpDraft = "21"
        profile = "Use only ldp_vc (JSON-LD) format and sd-jwt VC format"
    elif profil == "EWC":
        oidc4vciDraft = "13"
        oidc4vpDraft = "18"
        profile = "Use only sd-jwt vc format and mdoc format"
    elif profil == "HAIP":
        oidc4vciDraft = "18"
        oidc4vpDraft = "30"
        profile = profil
    elif profil == "connectors":
        profile = "User is working with the API platform CONNECTORS, he must audit his own configuration. Check in particular the client metadata (vp formats)"
    parse_result = urlparse(qrcode)
    logging.info('profil = %s, oidc4vci draft = %s, oidc4vp draft = %s', profile, oidc4vciDraft, oidc4vpDraft)
    result = parse_qs(parse_result.query)
    if result.get('credential_offer_uri') or result.get('credential_offer'):
        return analyze_issuer_qrcode(qrcode, oidc4vciDraft, profile, device, model, provider)
    else:
        return analyze_verifier_qrcode(qrcode, oidc4vpDraft, profile, device, model, provider)


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


def b64url_no_pad_decode(s: str) -> bytes:
    # Add back the missing padding if needed
    padding_needed = (4 - len(s) % 4) % 4
    s += "=" * padding_needed
    return base64.urlsafe_b64decode(s)


def get_verifier_request(qrcode: str, draft: str) -> Tuple[str, str, str, List[dict]]:
    """Get and analyze the verifier request.

    Returns:
        Tuple[str, str, str, List[dict]]: request, transaction_id, comments, transaction_data
    

    def get_verifier_request(qrcode: str, draft: str) -> Tuple[
        Optional[Dict[str, Any]],    # authorization_request
        Optional[Dict[str, Any]],    # presentation_definition or dcql
        str,                         # response_type ("vp_token", "id_token", or "unknown")
        Optional[List[Dict[str, Any]]]]:  # transaction_data (or None)

    
    Parse a Verifier authorization request from a QR (OIDC4VP).
    Returns: (authorization_request_dict, presentation_definition_or_dcql, comment)
    - If a fatal problem occurs, (None, None, "Error: ...", None) is returned.
    """
    comments: list[str] = []
    try:
        parse_result = urlparse(qrcode)
        # Keep single-value params only; ignore repeated keys for simplicity
        query: Dict[str, str] = {k: v[0] for k, v in parse_qs(parse_result.query).items()}
    except Exception as e:
        return None, None, f"Error: cannot parse QR: {e}", None

    request: Optional[Dict[str, Any]] = None
    presentation_obj: Optional[Dict[str, Any]] = None

    # 1) request_uri → fetch JWT
    if request_uri := query.get("request_uri"):
        try:
            resp = _safe_get_text(request_uri, timeout=10)
            request_jwt = resp.text.strip()
        except Exception as e:
            return None, None, f"Error: the request_uri could not be fetched: {e}", None

        # Verify media type but accept minor variations (charset)
        if not _content_type_is_authz_req_jwt(resp.headers.get("Content-Type")):
            comments.append("Error: request_uri response must be 'application/oauth-authz-req+jwt'")
        
        # Decode signed request JWT
        try:
            request = get_payload_from_token(request_jwt)
            header = get_header_from_token(request_jwt)
        except Exception as e:
            return None, None, f"Error: cannot decode request JWT: {e}", None
        
        if header.get("alg") == "none":
            comments.append("Warning: the request_uri is not signed which is correct only if the client_id_scheme is 'redirect_uri'")
        else:
            comments.append("Info: the request_uri is signed which is great for safety")

        if isinstance(header, dict) and header.get("x5c"):
            iss = request.get("iss")
            if not iss:
                comments.append("Warning: iss is missing")
            # check signature of the request jwt
            if x5c_list := header.get('x5c'):
                comments.append(verify_issuer_matches_cert(iss, x5c_list, draft, token="request_jwt"))
                comments.append(oidc4vc.verify_x5c_chain(x5c_list))
                try:
                    # Extract the first certificate (leaf cert) from the x5c list
                    cert_der = base64.b64decode(x5c_list[0])
                    cert = x509.load_der_x509_certificate(cert_der)
                    # Get public key from the cert
                    public_key = cert.public_key()
                    # Convert it to JWK format
                    issuer_key = jwk.JWK.from_pyca(public_key)
                    # Validate signature
                    a = jwt.JWT.from_jose_token(request_jwt)
                    a.validate(issuer_key)
                    comments.append("Info: Request JWT is correctly signed with x5c public key")
                except Exception as e:
                    comments.append(f"Error: Request JWT signature verification with x5c public key failed: {e}")

    # 2) request (inline) → parse JWT
    elif inline_req := query.get("request"):
        request_jwt = inline_req.strip()
        if not _is_compact_jwt(request_jwt):
            return None, None, "Error: 'request' parameter is not a compact JWS", None
        try:
            request = get_payload_from_token(request_jwt)
            header = get_header_from_token(request_jwt)
        except Exception as e:
            return None, None, f"Error: cannot decode inline request JWT: {e}", None

        if isinstance(header, dict) and header.get("x5c"):
            iss = request.get("iss")
            if not iss:
                comments.append("Warning: iss is missing")

    # 3) Plain query params (least secure)
    elif query.get("response_mode"):
        request = query  # keep as-is
        comments.append(
            "Warning: Using plain query parameters. A signed 'request' or 'request_uri' JWT is more secure."
        )
    else:
        return None, None, "Error: no authorization request found (missing request_uri / request / response_mode).", None
    
    if request.get("response_mode") in ["direct_post", "direct_post.jwt"]:
        comments.append(
            "Info: response_uri must be present and redirect_uri must not be present."
        )
            
    # 4) Presentation Definition / DCQL resolution
    if not isinstance(request, dict):
        return None, None, "Error: malformed authorization request", None
    
    # transaction data
    if request.get("transaction_data"):
        transaction_data = []
        for td in request.get("transaction_data"):
            transaction_data.append(json.loads(b64url_no_pad_decode(td)))
    else:
        transaction_data = None

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
            return request, None, f"Error: the Presentation Definition could not be fetched: {e}", transaction_data

    # dcql_query (draft >= 23)
    elif request.get("dcql_query") and int(draft) >= 23:
        presentation_obj = {"dcql_query": request.get("dcql_query")}
        comments.append("Info: Verifier uses 'dcql_query' (Digital Credential Query).")
        
        if "credentials" not in request.get("dcql_query"):
            comments.append(f"Error: 'credentials' is missing in DCQL.")

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
            return request, None, f"Error: invalid embedded Presentation Definition: {e}", transaction_data
        
        for k in ("id", "input_descriptors"):
            if k not in pd:
                comments.append(f"Error: '{k}' is missing in presentation Definition.")

    elif request.get("response_type") == "id_token":
        comments.append("Info: It is an Id_token request wihout Presentation Definition or DCQL parameter.")
    
    elif request.get("response_type") not in ["vp_token", "vp_token id_token", "id_token vp_token"]: 
        comments.append("Error: No Presentation Definition / DCQL parameter found.")
    
    else:
        comments.append("Error: No Presentation Definition / DCQL parameter found.")
        
    
    # Optional sanity: ensure required OIDC params exist (response_type, client_id, redirect_uri, scope, nonce/state, etc.)
    # Keep it advisory; don’t fail here to let the analyzer produce a full report later.
    for k in ("client_id", "nonce", "response_mode"):
        if k not in request:
            comments.append(f"Error: '{k}' is missing in authorization request.")

    return request, presentation_obj, "\n".join(comments), transaction_data


def get_issuer_data(qrcode, draft):
    # Retrieve issuer, metadata and authorization server data from a credential offer QR code
    comment = ""
    parse_result = urlparse(qrcode)
    result = {k: v[0] for k, v in parse_qs(parse_result.query).items()}

    if credential_offer_uri := result.get('credential_offer_uri'):
        try:
            credential_offer = requests.get(credential_offer_uri, timeout=10).json()
        except Exception:
            credential_offer = "Error: The credential offer is not available through the URI endpoint"
            return credential_offer, None, None, comment
    else:
        try:
            credential_offer = json.loads(result.get('credential_offer', '{}'))
        except Exception:
            credential_offer = "Error: The credential offer is not a correct JSON structure"
            return credential_offer, None, None, comment
        
    issuer = credential_offer.get('credential_issuer')
    logging.info("credential offer = %s", credential_offer)
    
    # generate VCT in registry
    trigger_generation(issuer)
    
    # get issuer metadata
    if int(draft) >= 16:
        parsed = urlparse(issuer)
        scheme = parsed.scheme
        domain = parsed.netloc   # example.com:8443
        path = parsed.path
        issuer_metadata_url = f"{scheme}://{domain}/.well-known/openid-credential-issuer{path}"
    else:
        issuer_metadata_url = f"{issuer}/.well-known/openid-credential-issuer"
    logging.info("AI Agent call for QR code diagnostic. issuer = %s", issuer)
    try:
        resp = requests.get(issuer_metadata_url, timeout=10)
        content_type = (resp.headers.get("Content-Type") or "").split(";")[0].strip().lower()
        # If server returns a JWT (common in drafts >=15)
        if content_type in ("application/jwt", "text/plain"):
            logging.info("signed metadata as jwt")
            comment = "Info : the issuer metadata are signed"
            issuer_metadata = get_payload_from_token(resp.text.strip())
            for k in {"iat", "sub", "exp", "iss"}:
                issuer_metadata.pop(k, None)
        else:
            logging.info("metadata as json")
            comment = "Info : the issuer metadata are not signed"
            issuer_metadata = resp.json() 
            if "signed_metadata" in issuer_metadata: # draft 15
                comment = "Info : the issuer signed metadata have been passed in the json metadata"
                issuer_metadata = get_payload_from_token(issuer_metadata.get("signed_metadata"))
                for k in {"iat", "sub", "exp", "iss"}:
                    issuer_metadata.pop(k, None)
    except Exception as e:
        logging.info("error : %s", str(e))
        issuer_metadata = "Error: Issuer metadata are not available" + str(e)
    logging.info("Issuer metadata = %s", issuer_metadata)
    
    # get authorization server metadata
    try:
        authorization_server = issuer_metadata.get("authorization_servers", [issuer])[0]
    except Exception:
        try:
            authorization_server = credential_offer["grants"]["authorization_code"]["authorization_server"]
        except Exception:
            authorization_server_metadata = "Error: The authorization server is not found"
            return json.dumps(credential_offer), json.dumps(issuer_metadata), json.dumps(authorization_server_metadata), comment

    logging.info("authorization server = %s", authorization_server)

    if int(draft) <= 11:
        authorization_server_url = f"{authorization_server}/.well-known/openid-configuration"
    elif int(draft) >= 16:
        parsed = urlparse(authorization_server)
        scheme = parsed.scheme
        domain = parsed.netloc   # example.com:8443
        path = parsed.path
        authorization_server_url = f"{scheme}://{domain}/.well-known/oauth-authorization-server{path}"
    else:
        authorization_server_url = f"{authorization_server}/.well-known/oauth-authorization-server"

    try:
        authorization_server_metadata = requests.get(authorization_server_url, timeout=10).json()
    except Exception:
        authorization_server_metadata = "Error: The authorization server metadata are not available or the draft " + draft + " is not correct ? "
    
    logging.info("authorization server metadata = %s", authorization_server_metadata)
    return json.dumps(credential_offer), json.dumps(issuer_metadata), json.dumps(authorization_server_metadata), comment


def analyze_issuer_qrcode(qrcode, draft, profile, device, model, provider):
    logging.info("draft = %s", draft)
    # Analyze issuer QR code and generate a structured report using OpenAI
    if not draft:
        draft = "13"

    credential_offer, issuer_metadata, authorization_server_metadata, comment = get_issuer_data(qrcode, draft)

    try:
        f = open("./dataset/oidc4vci/" + draft + ".md", "r")
        context = f.read()
        f.close()
    except Exception:
        f = open("./dataset/oidc4vci/13.md", "r")
        context = f.read()
        f.close()
        draft = "13"
    
    if profile == "HAIP":
        f = open("./dataset/haip/final_1_0.md", "r")
        haip = f.read()
        f.close()
        haip = clean_md(haip)
        context += "\n\n" + haip
        logging.info("merge with HAIP specifications is processed")
    
    elif profile == "DIIP_V4":
        f = open("./dataset/diip/4.md", "r")
        haip = f.read()
        f.close()
        haip = clean_md(haip)
        context += "\n\n" + haip
        logging.info("merge with DIIP V4 specifications is processed")

    # Token count logging for diagnostics
    tokens = enc.encode(context)
    logging.info("Token count: %s", len(tokens))

    context = clean_md(context)
    if int(draft) <= 11:
        context += "\n If EBSI tell to the user to add did:key:jwk_jcs-pub as subject_syntax_type_supported in the authorization server metadata"
    mention = attribution(model, "OIDC4VCI", draft, provider)


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

    --- Comment ---
    {comment}
    
    
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

    llm = get_llm_client(model, provider)
    response = llm.invoke(messages).content

    result = response + ADVICE + mention
    counter_update(device)
    store_report(qrcode, result, "issuer")
    return result


def analyze_verifier_qrcode(qrcode, draft, profile, device, model, provider):

    # Analyze verifier QR code and generate a structured report using OpenAI
    if not draft:
        draft = "18"

    verifier_request, presentation_definition, comment, transaction_data = get_verifier_request(qrcode, draft)
    if not verifier_request:
        return comment
    
    if not presentation_definition:
    # request is valid but no PD/DCQL → keep request and warn
        comment += "\n Error: No presentation definition found"
        
    logging.info("all comments passed to et LLM = %s", comment)
    
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
    
    if profile == "HAIP":
        f = open("./dataset/haip/3.md", "r")
        haip = f.read()
        f.close()
        haip = clean_md(haip)
        context += "\n\n" + haip
        logging.info("merge with HAIP specifications is processed")
        
    elif profile == "DIIP_V4":
        f = open("./dataset/diip/4.md", "r")
        haip = f.read()
        f.close()
        haip = clean_md(haip)
        context += "\n\n" + haip
        logging.info("merge with DIIP V4 specifications is processed")

    # Token count logging for diagnostics
    tokens = enc.encode(context)
    logging.info("Token count: %s", len(tokens))

    mention = attribution(model, "OIDC4VP", draft, provider)

    if transaction_data:
        transaction_data_str = json.dumps(transaction_data)
    else:
        transaction_data_str = "No transaction data"

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
    
    --- Transaction Data ---
    {transaction_data_str}

    ### Output style
{instr}

### Report Sections:

    1. **Abstract**
    2. **Authorization Request** – Check required OIDC4VP claims
    3. **Presentation Definition** – Verify format and structure
    4. **Transaction Data** – Verify format and structure
    5. **Client Metadata** – Validate content (if present)
    6. **Errors & Warnings**
    7. **Improvements** – Suggest developer-focused enhancements
    """
        }
    ]

    llm = get_llm_client(model, provider)  # Add 'provider' param to function
    response = llm.invoke(messages).content

    result = response + ADVICE + mention
    counter_update(device)
    store_report(qrcode, result, "verifier")
    return result



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
- Remove duplicates in 'findings'. Two items are duplicates if they share the same 'code'.Keep only one per code. Prefer the item with the higher severity (FAIL > WARN > PASS > INFO).


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
    
    logging.info("json = %s", json.dumps(obj, indent=4))

    return obj
