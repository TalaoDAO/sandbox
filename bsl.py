
"""
bsl.py — Bitstring Status List checker (JSON-LD or VC-JWT container)

- Accepts status list credentials delivered as **VC-JWT** (application/vc+jwt, application/jwt, text/plain)
  or **JSON/JSON-LD** (application/ld+json, application/json).
- Implements multibase(base64url-nopad) + GZIP expansion, MSB-first bit order, statusSize handling,
  minimum entries (131,072) check, and validity windows.
- Signature/proof verification is optional; wire in your own verifier via the `verify_statuslist_proof`
  callback if you need JOSE/COSE/Data Integrity enforcement.
"""

import base64
import gzip
import json
import time
from datetime import datetime
from typing import Any, Dict, Optional, Tuple, Union, Callable

import requests

Json = Dict[str, Any]


# ------------------ errors ------------------

class StatusCheckError(Exception):
    """Raised when Bitstring Status List resolution/validation fails."""
    pass


# ------------------ multibase (base64url-nopad) ------------------

def _mbase_b64url_decode(s: str) -> bytes:
    """
    Multibase base64url-no-pad decoder. Spec says encodedList is
    multibase + base64url(no padding), typically prefixed with 'u'.
    """
    if not s:
        raise ValueError("encodedList is empty")
    if s[0] in ("u", "U"):
        s = s[1:]
    # base64url without padding
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


# ------------------ ISO8601 utils (Z support) ------------------

def _parse_time(s: Optional[str]) -> Optional[int]:
    if not s:
        return None
    # Accept '...Z' form
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    return int(datetime.fromisoformat(s).timestamp())


# ------------------ bit access (MSB-first) ------------------

def _get_bit_msb_first(buf: bytes, bit_index: int) -> int:
    """
    Bit 0 is the left-most bit of the whole bitstring; within a byte,
    that means MSB-first (bit 7) down to LSB (bit 0).
    """
    if bit_index < 0:
        raise IndexError("bit_index negative")
    byte_i = bit_index // 8
    if byte_i >= len(buf):
        raise IndexError("bit_index out of range")
    within = bit_index % 8
    b = buf[byte_i]
    return (b >> (7 - within)) & 1


def _read_value_msb_first(buf: bytes, bit_offset: int, size: int) -> int:
    """Read `size` bits starting at `bit_offset`, MSB-first across the stream."""
    v = 0
    for i in range(size):
        v = (v << 1) | _get_bit_msb_first(buf, bit_offset + i)
    return v


# ------------------ JWT helpers ------------------

def _looks_like_compact_jwt(text: str) -> bool:
    parts = text.split(".")
    return len(parts) == 3 and all(parts)


def _b64url_to_json(b64: str) -> dict:
    pad = "=" * (-len(b64) % 4)
    return json.loads(base64.urlsafe_b64decode(b64 + pad))


def _parse_compact_jwt(token: str) -> Tuple[dict, dict]:
    """Parse (without verifying) a compact JWT and return (header, payload)."""
    h, p, _ = token.split(".", 2)
    return _b64url_to_json(h), _b64url_to_json(p)


# ------------------ fetching/parsing containers ------------------

def _fetch_raw(url: str) -> Tuple[bytes, str]:
    """
    Fetch bytes + content-type. Sends an Accept that prefers VC-JWT, but will
    accept JSON(-LD) and text/plain (some servers mislabel jwt as text/plain).
    """
    headers = {
        "Accept": "application/vc+jwt, application/jwt, application/ld+json, application/json, text/plain"
    }
    r = requests.get(url, headers=headers, timeout=15)
    r.raise_for_status()
    ctype = (r.headers.get("Content-Type") or "").lower()
    return r.content, ctype


def _parse_statuslist_container(
    content_bytes: bytes,
    content_type: str
) -> Tuple[dict, Optional[int], Optional[int], str]:
    """
    Returns: (status_list_vc_json, valid_from_epoch, valid_until_epoch, format)
      - format is "jwt" or "jsonld"
      - valid_from/until come from nbf/exp for JWT, or validFrom/validUntil for JSON-LD
    """
    text = None
    fmt = "jsonld"

    # Decide by content-type first; fall back to sniffing body.
    if "jwt" in content_type:
        fmt = "jwt"
    else:
        # Try to sniff
        try:
            text = content_bytes.decode("utf-8", errors="strict")
            if _looks_like_compact_jwt(text):
                fmt = "jwt"
            else:
                fmt = "jsonld"
        except Exception:
            fmt = "jsonld"

    if fmt == "jwt":
        if text is None:
            text = content_bytes.decode("utf-8", errors="replace")
        header, payload = _parse_compact_jwt(text)
        sl_vc = payload.get("vc")
        if not isinstance(sl_vc, dict):
            raise StatusCheckError("STATUS_VERIFICATION_ERROR: VC-JWT payload missing 'vc' object")
        # Validity from JWT container; tolerate string or int
        vf = payload.get("nbf")
        vu = payload.get("exp")
        vf = int(vf) if vf is not None else None
        vu = int(vu) if vu is not None else None
        return sl_vc, vf, vu, "jwt"

    # JSON/JSON-LD path
    try:
        sl_vc = json.loads(content_bytes.decode("utf-8"))
    except Exception as e:
        raise StatusCheckError(f"STATUS_RETRIEVAL_ERROR: cannot parse JSON(-LD): {e}")
    vf = _parse_time(sl_vc.get("validFrom"))
    vu = _parse_time(sl_vc.get("validUntil"))
    return sl_vc, vf, vu, "jsonld"


# ------------------ main API ------------------

def check_bitstring_status(
    vc: Union[str, Json],
    *,
    preferred_purpose: str = "revocation",
    require_proof: bool = False,
    verify_statuslist_proof: Optional[Callable[[Json, dict], None]] = None,
    # fetch_raw returns (bytes, content_type). Override to use your cache/CDN.
    fetch_raw: Optional[Callable[[str], Tuple[bytes, str]]] = None,
    minimum_entries: int = 131072,
) -> Dict[str, Any]:
    """
    Validate a JSON-LD VC's credentialStatus via Bitstring Status List, where
    the status list credential may be delivered as **VC-JWT** or **JSON-LD**.
    """
    if isinstance(vc, str):
        vc = json.loads(vc)

    # ---- Step 1: pick the BitstringStatusListEntry ----
    cs = vc.get("credentialStatus")
    entries = [cs] if isinstance(cs, dict) else (cs or [])
    if not entries:
        raise StatusCheckError("No credentialStatus")

    chosen = next(
        (e for e in entries
         if e.get("type") == "BitstringStatusListEntry" and e.get("statusPurpose") == preferred_purpose),
        None
    ) or next((e for e in entries if e.get("type") == "BitstringStatusListEntry"), None)

    if not chosen:
        raise StatusCheckError("No BitstringStatusListEntry found")

    purpose = str(chosen.get("statusPurpose"))
    idx_str = chosen.get("statusListIndex")
    list_url = chosen.get("statusListCredential")
    status_size = int(chosen.get("statusSize", 1))

    if idx_str is None or list_url is None:
        raise StatusCheckError("Missing statusListIndex or statusListCredential")
    try:
        index = int(idx_str, 10)
        if index < 0:
            raise ValueError()
    except Exception:
        raise StatusCheckError("statusListIndex must be a base-10 non-negative integer (string)")

    # ---- Step 2: dereference the status list credential (bytes + content-type) ----
    _fetcher = fetch_raw or _fetch_raw
    try:
        body, ctype = _fetcher(list_url)
    except Exception as e:
        raise StatusCheckError(f"STATUS_RETRIEVAL_ERROR: {e}")

    # ---- Step 3: parse container (JWT or JSON-LD) -> status list VC JSON ----
    sl_vc, list_valid_from, list_valid_until, container_fmt = _parse_statuslist_container(body, ctype)

    # Optional: proof verification (Data Integrity/JOSE/COSE) via hook
    if require_proof:
        if not verify_statuslist_proof:
            raise StatusCheckError("STATUS_VERIFICATION_ERROR: proof verification required but no verifier provided")
        # Pass both the VC JSON and a small container meta in case your verifier needs it
        container_meta = {"format": container_fmt, "content_type": ctype}
        verify_statuslist_proof(sl_vc, container_meta)

    # ---- Step 4: validate type & purpose; extract encodedList ----
    sl_types = sl_vc.get("type")
    if isinstance(sl_types, str):
        sl_types = [sl_types]
    if not (isinstance(sl_types, list) and "BitstringStatusListCredential" in sl_types):
        raise StatusCheckError("STATUS_VERIFICATION_ERROR: status list VC type invalid")

    subj = sl_vc.get("credentialSubject", {})
    subj_purpose = subj.get("statusPurpose")
    subj_purposes = [subj_purpose] if isinstance(subj_purpose, str) else list(subj_purpose or [])
    if purpose not in subj_purposes:
        raise StatusCheckError("STATUS_VERIFICATION_ERROR: statusPurpose mismatch")

    encoded_list = subj.get("encodedList")
    if not encoded_list:
        raise StatusCheckError("STATUS_VERIFICATION_ERROR: encodedList missing")

    # ---- Step 5: validity window & ttl ----
    now = int(time.time())
    if list_valid_from and now < list_valid_from:
        raise StatusCheckError("STATUS_VERIFICATION_ERROR: status list not yet valid")
    if list_valid_until and now >= list_valid_until:
        raise StatusCheckError("STATUS_VERIFICATION_ERROR: status list expired")

    ttl_ms = subj.get("ttl")

    # ---- Step 6: expand encodedList (multibase 'u' + base64url-no-pad + GZIP) ----
    try:
        compressed = _mbase_b64url_decode(encoded_list)
        bitstring_bytes = gzip.decompress(compressed)
    except Exception as e:
        raise StatusCheckError(f"STATUS_VERIFICATION_ERROR: cannot expand encodedList: {e}")

    total_bits = len(bitstring_bytes) * 8
    effective_entries = total_bits // status_size
    if effective_entries < max(minimum_entries, 1):
        raise StatusCheckError("STATUS_LIST_LENGTH_ERROR: status list shorter than minimum entries")

    # ---- Step 7: read value at index (MSB-first across stream) ----
    start_bit = index * status_size
    if start_bit + status_size > total_bits:
        raise StatusCheckError("RANGE_ERROR: index out of range for status list")
    status_value = _read_value_msb_first(bitstring_bytes, start_bit, status_size)

    # ---- Step 8: map result & optional message ----
    result: Dict[str, Any] = {
        "status": status_value,
        "purpose": purpose,
        "index": index,
        "statusSize": status_size,
        "valid": (status_value == 0),
        "list_id": sl_vc.get("id"),
        "list_validFrom": list_valid_from,
        "list_validUntil": list_valid_until,
        "ttl": ttl_ms,
        "container_format": container_fmt,
        "content_type": ctype,
    }

    # Optional human-readable message
    message = None
    status_messages = subj.get("statusMessages")
    if isinstance(status_messages, list):
        hex_code = f"0x{status_value:x}"
        for m in status_messages:
            if isinstance(m, dict) and m.get("status") == hex_code:
                message = m.get("message")
                break
    if message is None and isinstance(chosen.get("statusMessage"), list):
        hex_code = f"0x{status_value:x}"
        for m in chosen["statusMessage"]:
            if isinstance(m, dict) and m.get("status") == hex_code:
                message = m.get("message")
                break
    if message is None and status_size == 1:
        message = "unset" if status_value == 0 else "set"
    result["message"] = message
    return result


# Backwards-compatible alias (so older code continues to work)
def check_bitstring_status_jsonld(*args, **kwargs):
    return check_bitstring_status(*args, **kwargs)



# ------------------ example ------------------

if __name__ == "__main__":
    # Minimal example: pass your VC JSON (str or dict).
    # In production, set require_proof=True and provide verify_statuslist_proof(sl_vc).
    sample_vc_json = {"@context":["https://www.w3.org/2018/credentials/v1",{"EmailPass":"https://doc.wallet-provider.io/wallet/vc_type/#EmailPass","@vocab":"https://schema.org/"}],"id":"urn:uuid:6f05e26b-88da-11f0-a2e0-0a1628958560","type":["VerifiableCredential","EmailPass"],"credentialSubject":{"id":"did:key:z6MkonbKS9XpQuLzEtUszL47qnZWKCA4PqTyTbSBzbnfjxxd","type":"EmailPass","email":"john.doe@example.com"},"issuer":"did:web:app.altme.io:issuer","issuanceDate":"2025-09-03T15:26:59Z","proof":{"type":"EcdsaSecp256k1Signature2019","proofPurpose":"assertionMethod","verificationMethod":"did:web:app.altme.io:issuer#key-3","created":"2025-09-03T15:26:59.564Z","jws":"eyJhbGciOiJFUzI1NksiLCJjcml0IjpbImI2NCJdLCJiNjQiOmZhbHNlfQ..ypW6VKXK_TnL73s0xBuA4aCIOrEaFhJu9BLIUMWr165xwo_qwd41nqc1ioGpA6xg1Xr6NebyD_a7iwe_4MtmHA"},"expirationDate":"2025-09-03T15:27:59Z","credentialStatus":{"id":"https://talao.co/sandbox/issuer/bitstringstatuslist/1#17389","type":"BitstringStatusListEntry","statusPurpose":"revocation","statusSize":1,"statusListIndex":"17389","statusListCredential":"https://talao.co/sandbox/issuer/bitstringstatuslist/1"}}
    
   

    res = check_bitstring_status_jsonld(
        sample_vc_json,
        preferred_purpose="revocation",
        require_proof=False    )
    print(res)
