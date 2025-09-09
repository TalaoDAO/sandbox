from __future__ import annotations

import json
import os
import re
import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Tuple, Union

logger = logging.getLogger("vc_type_builder")
if not logger.handlers:
    logging.basicConfig(level=logging.INFO)

try:
    import tiktoken  # type: ignore
except Exception as e:  # pragma: no cover
    tiktoken = None
    logger.debug("tiktoken not available: %s", e)

try:
    from langchain_openai import ChatOpenAI  # type: ignore
except Exception as e:
    ChatOpenAI = None
    logger.debug("langchain_openai not available: %s", e)

try:
    from langchain_google_genai import ChatGoogleGenerativeAI  # type: ignore
except Exception as e:
    ChatGoogleGenerativeAI = None
    logger.debug("langchain_google_genai not available: %s", e)

try:
    from langchain_core.messages import SystemMessage, HumanMessage  # type: ignore
except Exception:
    SystemMessage = None  # type: ignore
    HumanMessage = None  # type: ignore

@dataclass
class LLMConfig:
    provider: str = "openai"
    model: str = "gpt-5-mini"
    temperature: float = 1.0

def count_tokens(text: str, model_hint: Optional[str] = None) -> int:
    if tiktoken is not None:
        try:
            enc = tiktoken.encoding_for_model(model_hint or "gpt-5")
        except Exception:
            try:
                enc = tiktoken.get_encoding("o200k_base")
            except Exception:
                enc = tiktoken.get_encoding("cl100k_base")
        return len(enc.encode(text))
    return max(1, (len(text) // 4) + 1)

try:
    with open("keys.json", "r") as f:
        keys = json.load(f)
except Exception:
    keys = {}

# ---------------------------------------------------------------------------
# snake_case + EUDI/OIDC canonicalization
# ---------------------------------------------------------------------------

SDJWT_ENVELOPE = {"iss","sub","aud","jti","iat","nbf","exp","vct","cnf","typ"}

EUDI_ADDRESS_PROPS: Dict[str, Dict[str, Any]] = {
    "street_address": {"type": "string"},
    "locality": {"type": "string"},
    "region": {"type": "string"},
    "postal_code": {"type": "string"},
    "country": {"type": "string"},
}

def _to_snake(s: str) -> str:
    s = re.sub(r"[ \-]+", "_", s or "")
    s = re.sub(r"(?<=[a-z0-9])([A-Z])", r"_\1", s)
    s = s.lower()
    return re.sub(r"__+", "_", s).strip("_")

def _canonical_key(key: str) -> str:
    if key in SDJWT_ENVELOPE:
        return key
    k = _to_snake(key)
    synonyms = {
        # person names
        "firstname": "given_name",
        "first_name": "given_name",
        "givenname": "given_name",
        "lastname": "family_name",
        "last_name": "family_name",
        "surname": "family_name",
        "middlename": "middle_name",
        # birth
        "birth_date": "date_of_birth",
        "date_of_birth": "date_of_birth",
        "dob": "date_of_birth",
        "birth_place": "place_of_birth",
        "birthplace": "place_of_birth",
        # contact
        "phone": "phone_number",
        "mobile": "phone_number",
        "mobile_phone_number": "phone_number",
        "email_address": "email",
        # address
        "street": "street_address",
        "streetaddress": "street_address",
        "postalcode": "postal_code",
        # nationality
        "nationality": "nationalities",
    }
    return synonyms.get(k, k)

def _normalize_schema_node(node: Any) -> Any:
    """Recursively normalize JSON Schema node keys to snake_case + EUDI spellings."""
    if not isinstance(node, dict):
        return node
    t = node.get("type")

    if isinstance(node.get("enum"), list):
        node["enum"] = [str(v) for v in node["enum"]]

    if t == "object" and isinstance(node.get("properties"), dict):
        new_props: Dict[str, Any] = {}
        for raw_key, sub in node["properties"].items():
            key = _canonical_key(raw_key)
            sub_norm = _normalize_schema_node(sub)

            if key == "address" and isinstance(sub_norm, dict):
                sub_props = dict(sub_norm.get("properties") or {})
                sub_props = { _canonical_key(k2): _normalize_schema_node(v2) for k2, v2 in sub_props.items() }
                # ensure standard address subfields exist if address is present
                for k2, v2 in EUDI_ADDRESS_PROPS.items():
                    sub_props.setdefault(k2, v2.copy())
                sub_norm["type"] = "object"
                sub_norm["additionalProperties"] = sub_norm.get("additionalProperties", False)
                sub_norm["properties"] = sub_props

            new_props[key] = sub_norm
        node["properties"] = new_props

        if isinstance(node.get("required"), list):
            node["required"] = [_canonical_key(r) for r in node["required"] if isinstance(r, str)]

    elif t == "array" and isinstance(node.get("items"), dict):
        node["items"] = _normalize_schema_node(node["items"])

    return node

# ---------------------------------------------------------------------------
# LLM plumbing
# ---------------------------------------------------------------------------

def _build_llm_client(cfg: Optional[LLMConfig]) -> Optional[Any]:
    if cfg is None:
        return None
    if cfg.provider == "openai":
        if ChatOpenAI is None:
            raise RuntimeError("langchain_openai not installed")
        api_key = keys.get("openai") or os.environ.get("OPENAI_API_KEY") or os.environ.get("OPENAI_KEY")
        if not api_key:
            raise RuntimeError("Set OPENAI_API_KEY/OPENAI_KEY or add to keys.json")
        logger.info("Using OpenAI model %s", cfg.model)
        return ChatOpenAI(api_key=api_key, model=cfg.model, temperature=cfg.temperature)
    if cfg.provider == "gemini":
        if ChatGoogleGenerativeAI is None:
            raise RuntimeError("langchain_google_genai not installed")
        api_key = keys.get("gemini") or os.environ.get("GOOGLE_API_KEY") or os.environ.get("GEMINI_API_KEY")
        if not api_key:
            raise RuntimeError("Set GOOGLE_API_KEY/GEMINI_API_KEY or add to keys.json")
        logger.info("Using Gemini model %s", cfg.model)
        return ChatGoogleGenerativeAI(google_api_key=api_key, model=cfg.model, temperature=cfg.temperature)
    raise ValueError(f"Unknown provider: {cfg.provider}")

def _ensure_llm(cfg: Optional[LLMConfig], *, use_llm: bool, require_llm: bool, phase: str) -> Optional[Any]:
    if not use_llm:
        logger.info("LLM disabled for %s: use_llm=False → using heuristics", phase)
        return None
    try:
        client = _build_llm_client(cfg or LLMConfig())
        return client
    except Exception as e:
        msg = f"LLM unavailable for {phase}: {e}"
        if require_llm:
            logger.error(msg)
            raise
        logger.warning(msg + ", falling back to heuristics")
        return None

def _invoke_llm_json(client: Any, system_text: str, user_payload: Any, *, phase: str) -> Optional[Any]:
    if client is None:
        return None
    content = json.dumps(user_payload, ensure_ascii=False) if not isinstance(user_payload, str) else user_payload
    try:
        if SystemMessage is not None and HumanMessage is not None:
            messages = [SystemMessage(content=system_text), HumanMessage(content=content)]
            resp = client.invoke(messages)
        else:
            resp = client.invoke([("system", system_text), ("user", content)])
        text = getattr(resp, "content", resp)
        return json.loads(text)
    except Exception as e:
        logger.warning("LLM %s invocation failed: %s", phase, e)
        return None

# ---------------------------------------------------------------------------
# Utilities & parsing
# ---------------------------------------------------------------------------

def _slug(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", (s or "").lower()).strip("_")

def parse_quick_description(text: str) -> Dict[str, Any]:
    sections: List[Dict[str, Any]] = []
    current: Optional[Dict[str, Any]] = None
    for raw in (text or "").splitlines():
        ln = (raw or "").rstrip("\n")
        s = ln.strip()
        if not s:
            continue
        if not ln.startswith((" ", "\t", "-")):
            if current:
                sections.append(current)
            current = {"title": s, "fields": []}
        else:
            fld = s.lstrip("- ").strip()
            if fld:
                if current is None:
                    current = {"title": "General", "fields": []}
                current["fields"].append(fld)
    if current:
        sections.append(current)
    return {"sections": sections}

# ---------------------------------------------------------------------------
# Property inference (LLM + heuristics)
# ---------------------------------------------------------------------------

def _llm_props_from_text(description: str, *, client: Optional[Any]) -> Tuple[Dict[str, Any], List[str]]:
    if client is None:
        return {}, []
    system = "You output ONLY JSON with keys: properties, required."
    user = {
        "prompt": (
            "From the free-form description below, infer BUSINESS claims as JSON Schema fragments (Draft 2020-12).\n"
            "- Do NOT include envelope claims (iss, vct, cnf, iat, nbf, exp, aud, sub, jti, typ).\n"
            "- Prefer simple primitives; use object for naturally nested concepts (e.g. address with street_address/locality/region/postal_code/country).\n"
            "- Use snake_case for property names.\n"
            "- If the description concerns a NATURAL PERSON identity, prefer official EUDI PID / SD-JWT VC names, e.g.:\n"
            "  given_name, family_name, birthdate, nationalities, place_of_birth{country|region|locality},\n"
            "  address{street_address|locality|region|postal_code|country}, email, phone_number.\n"
            "Return ONLY JSON with: properties (object), required (array)."
        ),
        "description": description,
    }
    data = _invoke_llm_json(client, system, user, phase="props")
    if not isinstance(data, dict):
        return {}, []
    props = data.get("properties") or {}
    req = data.get("required") or []
    if not isinstance(props, dict) or not isinstance(req, list):
        return {}, []
    # normalize the LLM fragment
    frag = {"type": "object", "properties": props, "required": req}
    frag = _normalize_schema_node(frag)
    props_n = frag.get("properties", {})
    req_n = [x for x in frag.get("required", []) if isinstance(x, str)]
    logger.info("LLM props extracted: %d top-level fields", len(props_n))
    return props_n, req_n

def _heuristic_props_from_text(text: str) -> Tuple[Dict[str, Any], List[str]]:
    props: Dict[str, Any] = {}
    req: List[str] = []
    t = (text or "").lower()

    # EUDI/OIDC-style address
    if any(w in t for w in ("address", "resident", "residence")):
        props["address"] = {
            "type": "object",
            "additionalProperties": False,
            "properties": dict(EUDI_ADDRESS_PROPS),
        }

    # Identity basics (EUDI spellings)
    identity_candidates = [
        ("given_name", ["given name","firstname","first name","given_name"]),
        ("family_name", ["family name","surname","last name","family_name","lastname"]),
        ("date_of_birth", ["birthdate","date of birth","dob","birth date","birth_date"]),
        ("nationalities", ["nationality","nationalities"]),
        ("email", ["email","email address","email_address"]),
        ("phone_number", ["phone","mobile","phone number","mobile phone","mobile_phone_number"]),
    ]
    for key, needles in identity_candidates:
        if any(n in t for n in needles) and key not in props:
            if key == "nationalities":
                props[key] = {"type": "array", "items": {"type": "string"}, "minItems": 1}
            else:
                props[key] = {"type": "string"}

    # Place of birth
    if any(w in t for w in ("place of birth", "birth place", "place_of_birth")):
        props.setdefault("place_of_birth", {
            "type": "object",
            "additionalProperties": False,
            "properties": {"country":{"type":"string"}, "region":{"type":"string"}, "locality":{"type":"string"}},
        })

    if not props:
        props["description"] = {"type": "string"}

    # normalize the heuristic fragment (future-proof)
    frag = _normalize_schema_node({"type": "object", "properties": props, "required": req})
    props_n = frag.get("properties", {})
    req_n = list(frag.get("required", []))
    logger.info("Heuristic props extracted: %d top-level fields", len(props_n))
    return props_n, req_n

# ---------------------------------------------------------------------------
# Schema assembly
# ---------------------------------------------------------------------------

def generate_sdjwt_vc_schema(
    description: str,
    *,
    vct: str,
    issuer: Optional[str] = None,
    cfg: Optional[LLMConfig] = None,
    use_llm: bool = True,
    require_llm: bool = False,
) -> Dict[str, Any]:
    schema: Dict[str, Any] = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "iss": {"type": "string", "format": "uri"},
            "vct": {"type": "string", "const": vct},
            "iat": {"type": "integer"},
            "nbf": {"type": "integer"},
            "exp": {"type": "integer"},
            "cnf": {
                "type": "object",
                "additionalProperties": True,
                "properties": {"jwk": {"type": "object"}, "jkt": {"type": "string"}},
            },
        },
        "required": ["iss","vct","iat","cnf"],
    }
    if issuer:
        schema["properties"]["iss"]["const"] = issuer

    seed = parse_quick_description(description)
    looks_bulleted = bool(seed.get("sections")) and ("-" in description or "\n-" in description or "\n  -" in description)
    enriched_text = description if not looks_bulleted else f"{description}\n\n(Parsed sections: {json.dumps(seed, ensure_ascii=False)})"

    client = _ensure_llm(cfg, use_llm=use_llm, require_llm=require_llm, phase="schema")

    props: Dict[str, Any] = {}
    if client is not None:
        props, _ = _llm_props_from_text(enriched_text, client=client)
        if props:
            logger.info("Schema: using LLM-inferred properties")

    if not props:
        if looks_bulleted:
            for sec in seed.get("sections", []):
                title = _canonical_key(_to_snake(sec.get("title")))
                fields = [ _canonical_key(_to_snake(x)) for x in sec.get("fields", []) if _to_snake(x) ]
                if fields:
                    # Special-case address group to ensure EUDI shape
                    if title == "address":
                        sub_props = dict(EUDI_ADDRESS_PROPS)
                        for f in fields:
                            sub_props.setdefault(f, {"type": "string"})
                        props[title] = {
                            "type": "object",
                            "additionalProperties": False,
                            "properties": sub_props,
                        }
                    else:
                        props[title] = {
                            "type": "object",
                            "additionalProperties": False,
                            "properties": { f: {"type":"string"} for f in fields },
                        }
                elif title:
                    props[title] = {"type": "string"}
            logger.info("Schema: using deterministic bullet-to-schema mapping")
        else:
            props, _ = _heuristic_props_from_text(description)
            logger.info("Schema: using heuristic free-text mapping")

    # Normalize and merge (enforce snake_case + EUDI spellings)
    norm_props: Dict[str, Any] = {}
    props = _normalize_schema_node({"type": "object", "properties": props}).get("properties", {})
    for k, v in (props or {}).items():
        if k in SDJWT_ENVELOPE:
            continue
        nk = _canonical_key(k)
        nv = _normalize_schema_node(v or {"type": "string"})
        norm_props[nk] = nv or {"type": "string"}
    schema["properties"].update(norm_props)

    schema["required"] = ["iss","vct","iat","cnf"]
    return schema

# ---------------------------------------------------------------------------
# Metadata helpers
# ---------------------------------------------------------------------------

def _collect_leaf_paths(prefix: List[str], node: Mapping[str, Any]) -> List[List[str]]:
    t = node.get("type")
    if t == "object" and isinstance(node.get("properties"), dict) and node["properties"]:
        out: List[List[str]] = []
        for k, v in node["properties"].items():
            out += _collect_leaf_paths(prefix + [k], v or {})
        return out
    if t == "array" and isinstance(node.get("items"), dict):
        return _collect_leaf_paths(prefix + ["[]"], node.get("items") or {})
    return [prefix]

def _business_leaf_paths(schema: Mapping[str, Any]) -> List[List[str]]:
    props = dict(schema.get("properties", {}))
    paths: List[List[str]] = []
    for k, v in props.items():
        if k in SDJWT_ENVELOPE:
            continue
        paths += _collect_leaf_paths([k], v if isinstance(v, dict) else {})
    seen = set(); out: List[List[str]] = []
    for p in paths:
        key = tuple(p)
        if key not in seen:
            seen.add(key); out.append(p)
    return out

def _titleize(key: str) -> str:
    s = re.sub(r"[_\-]+", " ", key)
    s = re.sub(r"(?<!^)(?=[A-Z])", " ", s)
    return s.strip().replace("  ", " ").title()

def _llm_labels_for_paths(description: str, paths: List[List[str]], *, client: Optional[Any], languages: List[str]) -> Optional[List[Dict[str, Any]]]:
    if client is None:
        return None
    system = (
        "Return ONLY JSON: an array of objects. Each object must have:\n"
        "- path: string[] (claim path segments)\n"
        "- one property per language code with {name, description?}.\n"
        "Example: {path:[\"employee\",\"name\"], en:{name:\"Full Name\"}, fr:{name:\"Nom complet\"}}"
    )
    user = {
        "prompt": (
            "From the credential description below and the provided claim paths, produce UI labels for these languages: "
            + ", ".join(languages) + ".\n"
            "- Keep labels concise and human-friendly. If unsure, infer from the field name.\n"
            "- Use sentence case for descriptions; title case for names.\n"
        ),
        "description": description,
        "paths": paths,
        "languages": languages,
    }
    data = _invoke_llm_json(client, system, user, phase="labels")
    if isinstance(data, list):
        logger.info("LLM labels generated for %d paths", len(data))
        return data
    return None

def _fallback_labels(paths: List[List[str]], languages: List[str]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for p in paths:
        last = p[-1] if p else "field"
        base = _titleize(last.replace("[]"," items"))
        item: Dict[str, Any] = {"path": p}
        for lang in languages:
            item[lang] = {"name": base}
        out.append(item)
    logger.info("Fallback labels created for %d paths", len(out))
    return out

def _llm_type_display(description: str, vct: str, *, client: Optional[Any], languages: List[str]) -> Optional[List[Dict[str, Any]]]:
    if client is None:
        return None
    system = "Return ONLY JSON: an array of objects [{lang,name,description?}] for the requested languages."
    user = {
        "prompt": (
            "Propose localized display for this credential type for languages: "
            + ", ".join(languages) + ". Return exactly one entry per language code.\n"
        ),
        "vct": vct,
        "description": description,
        "languages": languages,
    }
    data = _invoke_llm_json(client, system, user, phase="type_display")
    if isinstance(data, list) and all(isinstance(x, dict) and x.get("lang") in set(languages) for x in data):
        langs = {x.get("lang") for x in data}
        if set(languages).issubset(langs):
            logger.info("LLM type display generated for %s", ", ".join(languages))
            return data
    return None

def _fallback_type_display(vct: str, languages: List[str]) -> List[Dict[str, Any]]:
    base = _titleize(vct.split("/")[-1].split(".")[-1]) or "Credential"
    desc = "Verifiable credential"
    logger.info("Fallback type display used for %s", ", ".join(languages))
    return [{"lang": lang, "name": base, "description": desc} for lang in languages]

def _apply_simple_rendering_to_display(display: List[Dict[str, Any]], simple_rendering: Optional[Dict[str, Any]]) -> None:
    if not simple_rendering:
        return
    # Minimal validation: accept CSS color strings (#RRGGBB etc.) and a logo.uri if present
    sr: Dict[str, Any] = {}
    for key in ("background_color", "text_color"):
        val = simple_rendering.get(key)
        if isinstance(val, str) and val.strip():
            sr[key] = val.strip()
    logo = simple_rendering.get("logo")
    if isinstance(logo, dict) and isinstance(logo.get("uri"), str) and logo.get("uri").strip():
        sr["logo"] = {"uri": logo.get("uri").strip()}
    if not sr:
        return
    for entry in display:
        entry.setdefault("rendering", {})["simple"] = sr

# ---------------------------------------------------------------------------
# Public: build full VCT metadata
# ---------------------------------------------------------------------------

def generate_vc_type_metadata(
    description: str,
    *,
    vct: str,
    issuer: Optional[str] = None,
    cfg: Optional[LLMConfig] = None,
    credential_name: Optional[str] = None,
    use_llm: bool = True,
    require_llm: bool = False,
    languages: Optional[List[str]] = None,
    simple_rendering: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    langs = [l.lower() for l in (languages or ["en","fr"]) if isinstance(l, str) and l.strip()]
    if not langs:
        langs = ["en","fr"]
    langs = list(dict.fromkeys(langs))

    client = _ensure_llm(cfg, use_llm=use_llm, require_llm=require_llm, phase="type_metadata")

    schema = generate_sdjwt_vc_schema(
        description,
        vct=vct,
        issuer=issuer,
        cfg=cfg,
        use_llm=use_llm,
        require_llm=require_llm,
    )

    paths = _business_leaf_paths(schema)
    labels = _llm_labels_for_paths(description, paths, client=client, languages=langs) or _fallback_labels(paths, languages=langs)
    type_display = _llm_type_display(description, vct, client=client, languages=langs) or _fallback_type_display(vct, languages=langs)

    # Attach rendering (same object for all languages)
    _apply_simple_rendering_to_display(type_display, simple_rendering)

    claims_md: List[Dict[str, Any]] = []
    for item in labels:
        p = item.get("path") or []
        disp = []
        for lang in langs:
            loc = (item.get(lang) or {})
            if loc.get("name"):
                d = {"lang": lang, "name": loc.get("name")}
                if loc.get("description"):
                    d["description"] = loc.get("description")
                disp.append(d)
        if not disp:
            base = _titleize((p[-1] if p else "field").replace("[]"," items"))
            disp = [{"lang": lang, "name": base} for lang in langs]
        claims_md.append({
            "path": p,
            "display": disp,
            "sd": "allowed"
        })

    type_md: Dict[str, Any] = {
        "vct": vct,
        "display": type_display,
        "schema": schema,
        "claims": claims_md,
    }

    if credential_name:
        try:
            type_md["schema"]["title"] = credential_name
            for entry in type_display:
                if not entry.get("name"):
                    entry["name"] = credential_name
        except Exception:
            pass

    return type_md

# ---------------------------------------------------------------------------
# Public: derive metadata from an existing schema
# ---------------------------------------------------------------------------

def _ensure_mapping_schema(schema: Union[str, Mapping[str, Any], Dict[str, Any]]) -> Dict[str, Any]:
    if isinstance(schema, str):
        try:
            schema_obj = json.loads(schema)
        except Exception as e:
            raise ValueError(f"Schema is not valid JSON: {e}") from e
    elif isinstance(schema, Mapping):
        schema_obj = dict(schema)
    else:
        raise ValueError("Schema must be a dict or JSON string")
    if not isinstance(schema_obj, dict):
        raise ValueError("Schema must be a JSON object at the root")
    return schema_obj

def generate_vc_type_metadata_from_schema(
    schema: Union[str, Mapping[str, Any]],
    *,
    vct: str,
    cfg: Optional[LLMConfig] = None,
    credential_name: Optional[str] = None,
    use_llm: bool = True,
    require_llm: bool = False,
    languages: Optional[List[str]] = None,
    simple_rendering: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    description = ""

    langs = [l.lower() for l in (languages or ["en","fr"]) if isinstance(l, str) and l.strip()]
    if not langs:
        langs = ["en","fr"]
    langs = list(dict.fromkeys(langs))

    client = _ensure_llm(cfg, use_llm=use_llm, require_llm=require_llm, phase="type_metadata")

    schema_obj = _ensure_mapping_schema(schema)
    # normalize incoming schema to snake_case/EUDI before deriving paths
    schema_obj = _normalize_schema_node(schema_obj)

    paths = _business_leaf_paths(schema_obj)
    labels = _llm_labels_for_paths(description, paths, client=client, languages=langs) or _fallback_labels(paths, languages=langs)
    type_display = _llm_type_display(description, vct, client=client, languages=langs) or _fallback_type_display(vct, languages=langs)

    # Attach rendering (same object for all languages)
    _apply_simple_rendering_to_display(type_display, simple_rendering)

    claims_md: List[Dict[str, Any]] = []
    for item in labels:
        p = item.get("path") or []
        disp = []
        for lang in langs:
            loc = (item.get(lang) or {})
            if loc.get("name"):
                d = {"lang": lang, "name": loc.get("name")}
                if loc.get("description"):
                    d["description"] = loc.get("description")
                disp.append(d)
        if not disp:
            base = _titleize((p[-1] if p else "field").replace("[]"," items"))
            disp = [{"lang": lang, "name": base} for lang in langs]
        claims_md.append({
            "path": p,
            "display": disp,
            "sd": "allowed"
        })

    type_md: Dict[str, Any] = {
        "vct": vct,
        "display": type_display,
        "schema": schema_obj,
        "claims": claims_md,
    }

    if credential_name:
        try:
            type_md["schema"]["title"] = credential_name
            for entry in type_display:
                if not entry.get("name"):
                    entry["name"] = credential_name
        except Exception:
            pass

    return type_md

# Convenience wrapper
def generate_sdjwt_vc_schema_from_description(
    description: str,
    *,
    vct: str,
    issuer: Optional[str] = None,
    cfg: Optional[LLMConfig] = None,
    use_llm: bool = True,
    require_llm: bool = False,
) -> Dict[str, Any]:
    return generate_sdjwt_vc_schema(description, vct=vct, issuer=issuer, cfg=cfg, use_llm=use_llm, require_llm=require_llm)

if __name__ == "__main__":
    cfg = LLMConfig(provider=os.environ.get("LLM_PROVIDER", "openai"),
                    model=os.environ.get("LLM_MODEL", "gpt-5-mini"),
                    temperature=0)
    VCT = os.environ.get("VCT", "https://issuer.example.com/vct/employee")
    demo_schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "iss": {"type": "string"},
            "vct": {"type": "string"},
            "employee": {
                "type": "object",
                "properties": {
                    "given_name": {"type": "string"},
                    "postal_code": {"type": "string"},
                    "address": {"type": "object", "properties": {"street": {"type":"string"}}}
                }
            }
        }
    }
    # Demo: normalization in action
    from copy import deepcopy
    print(json.dumps(generate_vc_type_metadata_from_schema(deepcopy(demo_schema), vct=VCT, cfg=cfg, use_llm=False, languages=["en","fr"]), indent=2))
