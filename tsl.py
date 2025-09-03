import base64
import json
import time
import zlib
from typing import Optional, Tuple, Literal, Dict, Any

import requests
try:
    import jwt  # PyJWT
except ImportError:
    raise RuntimeError("Please `pip install pyjwt requests`")

Status = Literal["active", "revoked", "suspended", "application_specific", "unknown"]

# --- Helpers --------------------------------------------------------------

def b64url_decode_to_bytes(s: str) -> bytes:
    # RFC7515 base64url without padding
    pad = '=' * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)

def get_jwt_parts(token: str) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    h_b64, p_b64, _ = token.split('.', 2)
    header = json.loads(b64url_decode_to_bytes(h_b64))
    payload = json.loads(b64url_decode_to_bytes(p_b64))
    return header, payload

def verify_jwt(token: str, jwk: Optional[Dict]=None, jwks_url: Optional[str]=None, audience: Optional[str]=None) -> Dict[str, Any]:
    """
    Verify JWT signature + standard checks. Returns payload dict.
    Provide either a single JWK (dict) or a JWKS URL. If neither is provided, skips signature verification.
    """
    options = {"verify_signature": bool(jwk or jwks_url), "verify_aud": audience is not None}
    if jwk:
        key = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(jwk)) if jwk.get("kty") in ("RSA",) else jwk
        return jwt.decode(token, key=key, algorithms=None, audience=audience, options=options)
    elif jwks_url:
        jwks = requests.get(jwks_url, timeout=10).json()
        return jwt.decode(token, algorithms=None, audience=audience, options=options, key=jwks)
    else:
        # Parse without verifying signature (NOT for production)
        _, payload = get_jwt_parts(token)
        return payload

def fetch_statuslist_token(uri: str, accept_cwt: bool=False) -> Tuple[str, str]:
    """
    GET the Status List Token at `uri`. Returns (body, content_type).
    Prefers JWT per draft; pass accept_cwt=True if you want CWT.
    """
    accept = "application/statuslist+cwt" if accept_cwt else "application/statuslist+jwt"
    resp = requests.get(uri, headers={"Accept": accept}, timeout=10)
    resp.raise_for_status()
    return resp.text, resp.headers.get("Content-Type", "")

def read_status_value(uncompressed: bytes, idx: int, bits: int) -> int:
    """
    Extract the status value at index `idx` given `bits` per token.
    Bit numbering is LSB-first within a byte (bit 0 is least significant).
    """
    if bits not in (1, 2, 4, 8):
        raise ValueError("bits must be one of 1,2,4,8")

    values_per_byte = 8 // bits
    byte_index = idx // values_per_byte
    offset_within_byte = idx % values_per_byte  # which chunk in this byte

    if byte_index >= len(uncompressed):
        raise IndexError("Index out of bounds for status list")

    b = uncompressed[byte_index]

    if bits == 8:
        return b
    elif bits == 4:
        # two 4-bit nibbles: value 0 at lower nibble (bits 0..3), 1 at upper (bits 4..7)
        if offset_within_byte == 0:
            return b & 0x0F
        else:
            return (b >> 4) & 0x0F
    elif bits == 2:
        # four 2-bit fields: positions 0..3 occupy bits [1:0], [3:2], [5:4], [7:6]
        shift = offset_within_byte * 2
        return (b >> shift) & 0b11
    else:  # bits == 1
        # eight 1-bit fields: position p is bit p
        shift = offset_within_byte
        return (b >> shift) & 0b1

def map_status_code(code: int) -> Status:
    # From the draft’s initial registry: 0x00 VALID, 0x01 INVALID, 0x02 SUSPENDED. :contentReference[oaicite:8]{index=8}
    if code == 0x00:
        return "active"
    elif code == 0x01:
        return "revoked"
    elif code == 0x02:
        return "suspended"
    elif code in (0x03, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F):
        return "application_specific"
    else:
        return "unknown"

# --- Main API -------------------------------------------------------------

def check_sd_jwt_vc_status(
    sd_jwt_vc: str,
    *,
    statuslist_jwt_jwk: Optional[Dict]=None,
    statuslist_jwt_jwks_url: Optional[str]=None,
    verify_statuslist_sig: bool=True,
) -> Dict[str, Any]:
    """
    Returns:
      {
        "status": "active" | "revoked" | "suspended" | "application_specific" | "unknown",
        "status_code": int,
        "bits": int,
        "index": int,
        "uri": str,
        "fetched_at": int,
        "ttl": Optional[int],
        "exp": Optional[int],
        "iat": int
      }
    """

    # 1) Extract status_list reference from the SD-JWT VC (we assume JOSE-serialized; we only parse payload here)
    try:
        _, vc_payload = get_jwt_parts(sd_jwt_vc)
    except Exception as e:
        raise ValueError(f"Invalid SD-JWT VC format: {e}")

    status_obj = (vc_payload or {}).get("status") or {}
    sl_info = status_obj.get("status_list") or {}
    if "idx" not in sl_info or "uri" not in sl_info:
        raise ValueError("SD-JWT VC is missing status.status_list.idx or status.status_list.uri")

    idx = int(sl_info["idx"])
    uri = str(sl_info["uri"])

    # 2) Fetch Status List Token (preferring JWT per draft) :contentReference[oaicite:9]{index=9}
    token_body, ctype = fetch_statuslist_token(uri, accept_cwt=False)
    if "statuslist+jwt" not in ctype:
        # You could add CWT handling here if needed.
        raise ValueError(f"Unsupported Status List content-type: {ctype}")

    # 3) Validate Status List Token structure and claims (signature optional based on flags) :contentReference[oaicite:10]{index=10}
    # Verify signature if requested; otherwise parse only.
    if verify_statuslist_sig and not (statuslist_jwt_jwk or statuslist_jwt_jwks_url):
        raise ValueError("Signature verification requested but no JWK or JWKS URL provided")

    # Peek header to ensure typ
    header, _ = get_jwt_parts(token_body)
    if header.get("typ") != "statuslist+jwt":
        raise ValueError('Status List JWT must have header typ="statuslist+jwt"')

    payload = verify_jwt(
        token_body,
        jwk=statuslist_jwt_jwk,
        jwks_url=statuslist_jwt_jwks_url,
        audience=None,  # no aud in the draft
    )

    # Required claims & relationships
    sub = payload.get("sub")
    iat = payload.get("iat")
    exp = payload.get("exp")
    ttl = payload.get("ttl")
    status_list = payload.get("status_list") or {}

    if not sub or sub != uri:
        raise ValueError("Status List Token 'sub' must equal the SD-JWT VC status_list.uri")  # :contentReference[oaicite:11]{index=11}
    if iat is None:
        raise ValueError("Status List Token missing 'iat'")  # :contentReference[oaicite:12]{index=12}
    if not isinstance(status_list, dict) or "bits" not in status_list or "lst" not in status_list:
        raise ValueError("Status List Token 'status_list' must contain 'bits' and 'lst'")  # :contentReference[oaicite:13]{index=13}

    now = int(time.time())
    if exp is not None and now >= int(exp):
        raise ValueError("Status List Token is expired")  # :contentReference[oaicite:14]{index=14}
    # ttl is advisory for caching; caller can use it to decide refetch cadence. :contentReference[oaicite:15]{index=15}

    bits = int(status_list["bits"])
    lst_b64 = str(status_list["lst"])

    # 4) Decompress lst (zlib/deflate) and read value at idx. :contentReference[oaicite:16]{index=16}
    compressed = b64url_decode_to_bytes(lst_b64)
    uncompressed = zlib.decompress(compressed)

    # Bounds check and bit extraction. :contentReference[oaicite:17]{index=17}
    val = read_status_value(uncompressed, idx, bits)
    mapped = map_status_code(val)

    return {
        "status": mapped,
        "status_code": val,
        "bits": bits,
        "index": idx,
        "uri": uri,
        "fetched_at": now,
        "ttl": ttl,
        "exp": exp,
        "iat": iat,
    }

# --- Example usage (pseudo) -----------------------------------------------
if __name__ == "__main__":
    sd_jwt_vc = "eyJhbGciOiJFZERTQSIsImtpZCI6ImRpZDp3ZWI6YXBwLmFsdG1lLmlvOmlzc3VlciNrZXktMSIsInR5cCI6InZjK3NkLWp3dCJ9.eyJfc2QiOlsiMDBMZVRaQ0pmbi04WUhXZ0ctcmZDeVV0T3JJWDJaRkdiakM3NjNBSVAxVSIsImdBVWVLcDRSS1hXME1WMWlsYjFEb1BsT1FTUE5VYjJvWW9RSzhNNGRwc2ciLCItMXIyVWlpZjUxcUhfWU51UmJTVFkwd1N1WmFQSHE3cVVHcVo4ZTVjUkowIiwiS2hVRDQ2aDBUTURpWUMxMDhDV2RJakJCUXZDcFgyN295ZFhuc2I2Z2NycyIsIjRSSUlmUEc5NUZsaTdlNVBSMS1BYVBHLXdOeEMxRU1UUmlFanlyV3JJUGciLCJEbVZpQjB3ek1BSk9Fd3ROWmJxSUNfcXZHY3I1VnZQRTFFRzc3MkpWU2dvIiwiZXlpN3FjRDE2RGlseWVHZ21CNG4xLXZvMlhGTlZTRUR4Szh4Tng1Y1hTRSIsIldlOVpmaUpNYVdKVEJaWDFQa0c0ZkhNakZhZlI1VU5vUGJibjM3a2ZnRjgiLCJfODVETWY5OWhobHBGUloxVlBoX3FFTEdJZVpWaGV0VEN6UE9JZmNaRWJvIiwiVUtwZ1FEbmRlc1drazB3dHJrNkkxNW1yWklOamdDZzVMTDFhV211dkdaVSIsIndaNmszTXlqemFyWWZPZldTR3ZOOWhzZDBkTWQ2ZmN5Vi0zUDVMbFRDaE0iLCJzWElTUE83X0lxVVdHU0VSblc0RzdQMVNFR2NqcFl4V1dURjFqNGFMV25RIiwiZUVUNDVLSkRVeXlianZiYWExMnVyM0V4TEQwOUkzOE0zWEs0dWViX0FwayIsIjlmalhuTWVzbW1hN2dhNzl3WnFERlpmWEhZRjdob1FGSk9NMkhaMkwyS3ciLCJmYm1iekFOMjJ0UHd5WkFSTlJuR21iREtLVUQtZktsajYtVVRFdGZsbjVFIiwiR2Jqb21KcVB5ZHc2T0Z2MVgzQmNkS1lUQjZkRXJGTVRHbkdMVlQtT2pVcyJdLCJfc2RfYWxnIjoic2hhLTI1NiIsImNuZiI6eyJraWQiOiJkaWQ6andrOmV5SmpjbllpT2lKUUxUSTFOaUlzSW10MGVTSTZJa1ZESWl3aWVDSTZJbUZUVkV0SWFVeG9iek5RTWxob2VWcFdaR1JQUldnNFYyVnVWbDg1TFhoa1UxWlpaVWQxVHkwM2NVa2lMQ0o1SWpvaU5HMVROMjVXV1ZocWRqbG5hbFUxYmtoM2FUZHJhMU42ZFZoa09VbHRVSEUyVUU1T2NFeFdTVlJ1VFNKOSJ9LCJleHAiOjE3ODYyMDYyMDMsImlhdCI6MTc1NDY3MDIwMywiaXNzIjoiZGlkOndlYjphcHAuYWx0bWUuaW86aXNzdWVyIiwibmF0aW9uYWxpdGllcyI6W3siLi4uIjoiRExsbmg2bF96MFpSNHNEdjk3ZDRQMU1scWRFRXd5ZGt0YnA0NXgtSlYyWSJ9LHsiLi4uIjoiVnRibVgxdGdibV9HVWhXQVdfT1BGcXVaUEtpUFNhUHdRZHZJQ2JSY3FaQSJ9XSwic3RhdHVzIjp7InN0YXR1c19saXN0Ijp7ImlkeCI6OTg5NjQsInVyaSI6Imh0dHBzOi8vdGFsYW8uY28vaXNzdWVyL3N0YXR1c2xpc3QvMSJ9fSwidmN0IjoiZXUuZXVyb3BhLmVjLmV1ZGkucGlkLjEifQ.8I-tiKk4o1OWgrhoDBZcAA4FSpN2KZIr_N0zC_OrfHt4KmZsGiQ6JsITK_65-QcDjRy-nMh-FkCM5knLm_vaCg~WyJqZlJ5V1VCTVlIRjJOdk44LWhYSXRBIiwgImdpdmVuX25hbWUiLCAiUGF0cmljayJd~WyJfeXcxM2Jab2NVbW84Z2lGdkhRNnp3IiwgImZhbWlseV9uYW1lIiwgIkRvZSJd~WyJUejRJbmN2Y2NHQ01EZjZnTnBBZDhnIiwgImJpcnRoX2RhdGUiLCAiMjAwMC0xMi0wMSJd~WyJZUTlJTXEwbHBkZVcxS043TXpSYlJRIiwgImJpcnRoX3BsYWNlIiwgIkRFIl0~WyJzcDJEOFFYOS1rTDVBTFZZaDVzOXNnIiwgImZvcm1hdHRlZCIsICIxMjMgVmlhIEFwcGlhLCBSb21lLCAwMDEwMCBMYXppbywgSXRhbHkiXQ~WyJpcnZlSW44TlJSS29XS25SbW1jbzZ3IiwgInN0cmVldF9hZGRyZXNzIiwgIjEyMyBWaWEgQXBwaWEiXQ~WyJsanBwUjVPNjVnOW5XQXUtVUFhVUZnIiwgImxvY2FsaXR5IiwgIlJvbWUiXQ~WyJxbmRnMmg3MllMenNuZHZpTzFfeEZ3IiwgInJlZ2lvbiIsICJMYXppbyJd~WyJSb3RQM2tTMlAzQ3lIUnFYWXBXUThRIiwgInBvc3RhbF9jb2RlIiwgIjAwMTAwIl0~WyJDV0Y5Y2tWTG85cFhVV2RURHd2T3pRIiwgImNvdW50cnkiLCAiSVQiXQ~WyJqSDd5bi1vY0lFV3BsYjdhVVpzNS1BIiwgImFkZHJlc3MiLCB7Il9zZCI6IFsienlXUzRWdXZZRFU4V1NjeGFJaDZWcnhPTndYRnM4Y1Q5YWh3djVQQ2lYbyIsICJzZTRFUUtJNmVvT01QNVNzT21TaXRrbGRUUEMyczZwVFVIZDBJTEZWNERFIiwgIjNFbXJiLUFpR1FRbDZ4UGd2RGV3R0RQWmZQa3NtRFpMa3djeHpSM3pNQk0iLCAiMWIxdWl1ckYwcVVtM1lsdE1jOUtOY2VWZVFEU3o4TkFEQms5WHh1U3liVSIsICJ0Uk9qZ1BFcHZvV3NRT2ZmYjByWGU5VGd5b011cUluaDRMdzNyOEZnNEEwIiwgIjFjSk5pX3BsYWlfT3VwXzF5ZHliVVNycVlvTXBPbHotSU13ZmlFRzY2aEUiLCAiVS1GYVlxZ3ZCbGVEZDlSZTZyU0dnVnZGQnljUzJrVHJDeUtNUV85Zm1EbyJdfV0~WyJ5YlhfSTBwMzRQU0dheF9RRWZwRkpBIiwgImxvY2FsaXR5IiwgIkxlaXB6aWciXQ~WyJ5WGNLcE5Dbl9PbHduTTAzNktOVm5nIiwgInJlZ2lvbiIsICJTYXhvbnkiXQ~WyI5VG5YUGJLanF4WjNNLW1JMDZmUkZ3IiwgImNvdW50cnkiLCAiREUiXQ~WyJwLUpLSkJFbDFyS3UxazZwekdkZW5RIiwgInBsYWNlX29mX2JpcnRoIiwgeyJfc2QiOiBbImc5WElQeVhEM1d0UWVsMmRuWlVYS2YxQWlES1dpcU4xMWVGYTRob1dDc0UiLCAib2lvYUkxMDJBcE5OcGpsVHNjeDJjMmcxWHUycXdydEJtdEZnRmhrd1IxRSIsICJ2OXJIMHpubHJjT3RVSnIwU2xFLVE3dXM5NFBIbC02RWdzTWk0ekpVT1A0IiwgImhEWWVpZ1ZKaG9XWS1qS0dMT1UtQm8yNnh4VjB6VlJ6R3pTSmZsSzByZjAiXX1d~WyI3WTVrZDVfQURxa2thZE9RWS1hWTlnIiwgIkRFIl0~WyJSNUY1R1htRXBnVWxlemtmYjR1MVJnIiwgIklUIl0~WyJNdW5IckpQdFdtWWxoaEkxTlY3Wlh3IiwgImFnZV9vdmVyXzEyIiwgdHJ1ZV0~WyI1eElJaVcwRFRKY2xTWGRZNXdUY1NBIiwgImFnZV9vdmVyXzE0IiwgdHJ1ZV0~WyJpSThQQlk5RTdBSWYwSXptX3M2UjRnIiwgImFnZV9vdmVyXzE2IiwgdHJ1ZV0~WyJ4eGVaN1VGMGNFQ1JBVWVYaExWWmRBIiwgImFnZV9vdmVyXzE4IiwgdHJ1ZV0~WyJIVjZYT2taU0g4bFdNLVNrQkJ3cFNRIiwgImFnZV9vdmVyXzIxIiwgdHJ1ZV0~WyJNbnpPZkg5b3c3Q3lEOVd0bE1mc1BnIiwgImFnZV9vdmVyXzY1IiwgZmFsc2Vd~WyJyVFlMMWd1Vjk5OVMwZ2ZMRkRHOG93IiwgInNleCIsIDFd~WyIxTFU4bVY1UkdDdWNZdS1uRHdBdWpnIiwgImlzc3VpbmdfY291bnRyeSIsICJERSJd~WyJXNGVrZVpFcDlDRUk3TmpIMGJsLWJBIiwgImlzc3VpbmdfYXV0aG9yaXR5IiwgIkRFIl0~"

    # Option A: verify with a single JWK (dict). Option B: pass a JWKS URL.
    # status_issuer_jwk = { ... }    # if you have it
    jwks_url = None                  # e.g., "https://issuer.example.com/.well-known/jwks.json"

    result = check_sd_jwt_vc_status(
        sd_jwt_vc,
        statuslist_jwt_jwk=None,
        statuslist_jwt_jwks_url=jwks_url,
        verify_statuslist_sig=False,  # set True in production with keys configured
    )
    print(result)
