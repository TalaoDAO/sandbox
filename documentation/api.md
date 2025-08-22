# APIs

Updated on **22 August 2025**.

The server base URL is `https://talao.co`.

---

## POST `/api/analyze-qrcode`

Analyze a base64-encoded QR code representing an authorization request and/or presentation definition within the OIDC4VC ecosystem. The service evaluates structure, protocol compliance (OIDC4VCI / OIDC4VP), and semantic correctness using an AI agent, then returns either a base64-encoded Markdown report or a structured JSON summary.

This API powers: `https://talao.co/ai/qrcode`

### Authentication

> **Note:** API key validation may be disabled in some deployments. If enabled, include the header below.

| Header  | Value              |
|---------|--------------------|
| Api-Key | Your authorized key |

---

### Request (JSON)

```jsonc
{
  "qrcode": "c29tZS1hc3NpZ24tdGV4dA==", // required, base64-encoded QR content
  "oidc4vciDraft": "12",                 // optional, OIDC4VCI draft version
  "oidc4vpDraft": "18",                  // optional, OIDC4VP draft version
  "profile": "EBSI",                     // optional, default "custom"
  "format": "text",                       // optional, "text" | "json" (default "text")
  "model": "flash"                        // optional, "flash" | "escalation" | "pro" (default "flash")
}
```

**Notes**
- `qrcode` must be **base64-encoded** to safely transmit non‑UTF‑8/binary payloads.
- When `format` = `json`, the service converts the AI report into a structured JSON object.

---

### Successful Responses

**When `format` = `text` (default):**
```json
{
  "report_base64": "<base64-encoded UTF-8 markdown report>"
}
```

**When `format` = `json`:**
```json
{
  // Structure produced from the AI report (keys may vary by input)
}
```

To decode the Markdown report in Python:
```python
import base64
print(base64.b64decode(response["report_base64"]).decode())
```

---

### Profiles

If `profile` is **custom** (default), OIDC4VC draft parameters apply directly. Other ecosystem profiles may adapt validation rules.

| Profile  | Ecosystem/Notes       |
|----------|------------------------|
| `EBSI`   | EBSI v3.x              |
| `INJI`   | MOSIP Inji stack       |
| `DIIP_V3`| FIDES DIIP v3.0        |
| `DIIP_V4`| FIDES DIIP v4.0        |
| `EWC`    | LSP EWC                |
| `custom` | Default behavior       |

---

### Error Responses

| HTTP | Body                                     | Meaning                           |
|-----:|------------------------------------------|-----------------------------------|
| 400  | `{ "error": "invalid JSON body" }`      | Malformed JSON payload            |
| 400  | `{ "error": "missing 'qrcode' field" }` | Required field not provided       |
| 400  | `{ "error": "invalid base64 for 'qrcode'" }` | Base64 decoding failed     |
| 403  | `{ "error": "access denied" }`          | API key invalid/missing (if enforced) |
| 500  | `{ "error": "internal processing error" }` | Unexpected processing error  |

---

### Example cURL

```bash
curl -X POST https://talao.co/api/analyze-qrcode   -H "Content-Type: application/json"   -H "Api-Key: your-api-key"   -d '{
        "qrcode": "c29tZS1hc3NpZ24tdGV4dA==",
        "oidc4vciDraft": "12",
        "oidc4vpDraft": "18",
        "profile": "EBSI",
        "format": "text",
        "model": "flash"
      }'
```

---

## POST `/api/analyze-vc`

Analyze a base64-encoded Verifiable Credential (VC). The service detects SD‑JWT VC, JWT VC (compact), or JSON‑LD VC format, evaluates compliance and structure using an AI agent, and returns either a base64-encoded Markdown report or a structured JSON summary.

This API powers: `https://talao.co/ai/vc`

### Authentication

> **Note:** API key validation may be disabled in some deployments. If enabled, include the header below.

| Header  | Value              |
|---------|--------------------|
| Api-Key | Your authorized key |

---

### Request (JSON)

```jsonc
{
  "vc": "BASE64_ENCODED_VC_STRING", // required
  "sdjwtvc_draft": "8",             // optional (SD-JWT VC related)
  "vcdm_draft": "1.1",              // optional (W3C VCDM related)
  "format": "text",                  // optional, "text" | "json" (default "text")
  "model": "flash"                   // optional, "flash" | "escalation" | "pro" (default "flash")
}
```

---

### Successful Responses

**When `format` = `text` (default):**
```json
{
  "report_base64": "<base64-encoded UTF-8 markdown report>"
}
```

**When `format` = `json`:**
```json
{
  // Structure produced from the AI report (keys may vary by input)
}
```

To decode the Markdown report in Python:
```python
import base64
print(base64.b64decode(response["report_base64"]).decode())
```

---

### Error Responses

| HTTP | Body                                   | Meaning                           |
|-----:|----------------------------------------|-----------------------------------|
| 400  | `{ "error": "invalid JSON body" }`     | Malformed JSON payload            |
| 400  | `{ "error": "missing 'vc' field" }`     | Required field not provided       |
| 400  | `{ "error": "invalid base64 for 'vc'" }`| Base64 decoding failed            |
| 403  | `{ "error": "access denied" }`         | API key invalid/missing (if enforced) |
| 500  | `{ "error": "internal processing error" }` | Unexpected processing error   |

---

### Example cURL

```bash
curl -X POST https://talao.co/api/analyze-vc   -H "Content-Type: application/json"   -H "Api-Key: your-api-key"   -d '{
        "vc": "BASE64_ENCODED_VC_STRING",
        "sdjwtvc_draft": "8",
        "vcdm_draft": "1.1",
        "format": "text",
        "model": "flash"
      }'
```

---

# JSON Rule Catalogs

This section documents the rule codes that can appear in the structured JSON outputs of the endpoints when `format` is set to `"json"`.


### Why these rule catalogs matter

- **Deterministic integrations:** Clients can build logic on top of stable `code` values, independent of natural-language wording.
- **Severity-aware UX:** `FAIL` vs `WARN` vs `INFO` lets apps decide whether to block flows, warn users, or log telemetry.
- **Compliance mapping:** Components (`auth_request`, `issuer_metadata`, `vc`, etc.) make it easy to highlight exactly *where* a problem originates.
- **Profile portability:** The same rule codes apply across profiles (EBSI, INJI, DIIP, etc.), simplifying multi-ecosystem support.
- **Testing & monitoring:** Codes are ideal for regression tests, dashboards, and alerting without brittle text matching.


---

## Rule Catalog — `/api/analyze-qrcode` (OIDC4VC)

Each JSON response in `format: "json"` mode uses the following machine-readable rule codes.

| Code | Severity | Component | Message |
|------|----------|-----------|---------|
| `CONTENT_TYPE_UNEXPECTED` | **FAIL** | `network` | Unexpected Content-Type received. |
| `GENERAL_PARSE_ERROR` | **FAIL** | `general` | Report could not be parsed. |
| `NETWORK_FETCH_FAILED` | **FAIL** | `network` | Network fetch failed or timed out. |
| `OIDC4VCI_ALG_MISMATCH_PROFILE` | **WARN** | `issuer_metadata` | Algorithm allowed by issuer but not by selected profile. |
| `OIDC4VCI_ALG_UNSUPPORTED` | **WARN** | `issuer_metadata` | Credential signature algorithm not supported by profile. |
| `OIDC4VCI_AUTHZ_CODE_PARAMS_MISSING` | **FAIL** | `issuer_metadata` | Authorization Code flow missing PKCE or required parameters. |
| `OIDC4VCI_AUTHZ_SERVER_MISSING` | **WARN** | `issuer_metadata` | authorization_server metadata missing; dynamic discovery may fail. |
| `OIDC4VCI_CONFIGURATION_MISSING` | **FAIL** | `issuer_metadata` | Issuer credential configurations are missing. |
| `OIDC4VCI_CREDENTIAL_ENDPOINT_MISSING` | **FAIL** | `issuer_metadata` | credential_endpoint missing in metadata. |
| `OIDC4VCI_CREDENTIAL_IDS_UNKNOWN` | **WARN** | `issuer_metadata` | Unknown credential_configuration_ids in offer or metadata. |
| `OIDC4VCI_DISPLAY_MISSING` | **WARN** | `issuer_metadata` | Display metadata missing; UX/localization may be degraded. |
| `OIDC4VCI_DPOP_REQUIRED_MISSING` | **WARN** | `issuer_metadata` | DPoP required by issuer/profile but not indicated. |
| `OIDC4VCI_ENDPOINT_MISMATCH` | **FAIL** | `issuer_metadata` | Endpoints in metadata do not align with offer/authorization server metadata. |
| `OIDC4VCI_FORMAT_UNSUPPORTED` | **WARN** | `issuer_metadata` | Requested credential format not supported by profile. |
| `OIDC4VCI_GRANT_COMBINATION_INVALID` | **FAIL** | `issuer_metadata` | Invalid or conflicting grant configuration. |
| `OIDC4VCI_GRANT_MISSING` | **FAIL** | `issuer_metadata` | Grant details (e.g., pre-authorized code, authorization_code) are missing. |
| `OIDC4VCI_ISSUER_METADATA_MISSING` | **FAIL** | `issuer_metadata` | Issuer .well-known metadata missing or unreachable. |
| `OIDC4VCI_ISSUER_MISMATCH` | **FAIL** | `issuer_metadata` | Issuer in offer does not match issuer metadata. |
| `OIDC4VCI_JTI_REPLAY_RISK` | **WARN** | `issuer_metadata` | No unique jti in client proofs; replay risk possible. |
| `OIDC4VCI_JWKS_MISSING` | **WARN** | `issuer_metadata` | JWKS/JWKS URI missing in metadata; key discovery may fail. |
| `OIDC4VCI_JWKS_UNREACHABLE` | **FAIL** | `issuer_metadata` | JWKS/JWKS URI unreachable or invalid. |
| `OIDC4VCI_LOCALE_UNSUPPORTED` | **WARN** | `issuer_metadata` | Requested locale not supported by display metadata. |
| `OIDC4VCI_OFFER_CT_BAD` | **FAIL** | `network` | credential_offer_uri returned unexpected Content-Type. |
| `OIDC4VCI_OFFER_JSON_INVALID` | **FAIL** | `credential_offer` | Credential offer JSON is invalid. |
| `OIDC4VCI_OFFER_MISSING` | **FAIL** | `credential_offer` | Credential offer is missing or invalid. |
| `OIDC4VCI_OFFER_URI_HTTP` | **FAIL** | `network` | credential_offer_uri must use HTTPS. |
| `OIDC4VCI_OFFER_URI_UNREACHABLE` | **FAIL** | `network` | credential_offer_uri unreachable or returned an error. |
| `OIDC4VCI_PREAUTH_CODE_MISSING` | **FAIL** | `credential_offer` | pre-authorized_code grant selected but code missing in offer. |
| `OIDC4VCI_PROFILE_CONFLICT` | **WARN** | `issuer_metadata` | Issuer configuration conflicts with selected ecosystem profile. |
| `OIDC4VCI_PROOF_REQUIRED_MISSING` | **FAIL** | `issuer_metadata` | Issuer requires a proof (e.g., JWT/CNF) but none was provided. |
| `OIDC4VCI_PROOF_TYPE_UNSUPPORTED` | **WARN** | `issuer_metadata` | Proof type not supported by profile or issuer. |
| `OIDC4VCI_SCOPE_MISSING` | **WARN** | `issuer_metadata` | Token scope missing or empty for issuance. |
| `OIDC4VCI_TOKEN_ENDPOINT_MISSING` | **FAIL** | `issuer_metadata` | token_endpoint missing in metadata. |
| `OIDC4VCI_USER_PIN_REQUIRED_MISSING` | **WARN** | `credential_offer` | User PIN required by offer but not provided. |
| `OIDC4VP_AUD_MISMATCH` | **FAIL** | `auth_request` | aud claim does not match the wallet/relying party. |
| `OIDC4VP_AUTHZ_MISSING` | **FAIL** | `auth_request` | Authorization request is missing or invalid. |
| `OIDC4VP_AUTHZ_PLAIN_PARAMS` | **WARN** | `auth_request` | Authorization request passed via plain query params; signed request/request_uri recommended. |
| `OIDC4VP_CLIENT_ID_MISSING` | **FAIL** | `auth_request` | client_id is missing. |
| `OIDC4VP_CLIENT_ID_SCHEME_INVALID` | **WARN** | `auth_request` | client_id scheme not supported by profile. |
| `OIDC4VP_CLIENT_METADATA_MISMATCH` | **FAIL** | `client_metadata` | Client metadata does not match request parameters. |
| `OIDC4VP_CLIENT_METADATA_MISSING` | **WARN** | `client_metadata` | Client metadata not provided or could not be fetched. |
| `OIDC4VP_CONSTRAINTS_INVALID` | **WARN** | `presentation_definition` | Constraints or fields filters are invalid or non-portable. |
| `OIDC4VP_CT_BAD` | **FAIL** | `network` | request_uri response Content-Type must be application/oauth-authz-req+jwt. |
| `OIDC4VP_DCQL_USED` | **INFO** | `presentation_definition` | Verifier uses 'dcql_query' (Digital Credential Query). |
| `OIDC4VP_DPOP_REQUIRED_MISSING` | **WARN** | `auth_request` | DPoP indicated by profile but not used in request/metadata. |
| `OIDC4VP_FORMATS_UNSUPPORTED` | **WARN** | `presentation_definition` | Requested VP/VC formats not supported by wallet profile. |
| `OIDC4VP_INPUT_DESCRIPTOR_MISSING` | **FAIL** | `presentation_definition` | No input_descriptors found in Presentation Definition. |
| `OIDC4VP_ISS_CERT_MISMATCH` | **FAIL** | `auth_request` | Issuer does not match certificate SAN (x5c) or allowed domains. |
| `OIDC4VP_ISS_MISSING` | **FAIL** | `auth_request` | 'iss' is missing from request JWT. |
| `OIDC4VP_NONCE_MISSING` | **WARN** | `auth_request` | nonce missing; replay protection may be weaker. |
| `OIDC4VP_PD_EMBEDDED` | **INFO** | `presentation_definition` | Verifier embeds 'presentation_definition'. |
| `OIDC4VP_PD_FETCH_FAILED` | **FAIL** | `presentation_definition` | presentation_definition_uri is unreachable or invalid. |
| `OIDC4VP_PD_INVALID` | **FAIL** | `presentation_definition` | Presentation Definition structure is invalid. |
| `OIDC4VP_PD_MISSING` | **WARN** | `presentation_definition` | Presentation Definition/DCQL not provided. |
| `OIDC4VP_PD_URI` | **INFO** | `presentation_definition` | Verifier uses 'presentation_definition_uri'. |
| `OIDC4VP_REDIRECT_URI_MISSING` | **FAIL** | `auth_request` | redirect_uri is missing in authorization request. |
| `OIDC4VP_REDIRECT_URI_UNREGISTERED` | **FAIL** | `auth_request` | redirect_uri not registered for this client_id. |
| `OIDC4VP_REQUEST_JWT_CRIT_UNSUPPORTED` | **FAIL** | `auth_request` | Unsupported 'crit' header in request JWT. |
| `OIDC4VP_REQUEST_JWT_EXPIRED` | **FAIL** | `auth_request` | Signed request JWT is expired or not yet valid. |
| `OIDC4VP_REQUEST_JWT_INVALID` | **FAIL** | `auth_request` | Signed request JWT is invalid or malformed. |
| `OIDC4VP_REQUEST_JWT_SIG_INVALID` | **FAIL** | `auth_request` | Signed request JWT signature verification failed. |
| `OIDC4VP_REQUEST_URI_HTTP` | **FAIL** | `network` | request_uri must use HTTPS. |
| `OIDC4VP_REQUEST_URI_TOO_LARGE` | **WARN** | `network` | request_uri payload size unusually large. |
| `OIDC4VP_REQUEST_URI_UNREACHABLE` | **FAIL** | `network` | request_uri is unreachable or returned an error. |
| `OIDC4VP_RESPONSE_MODE_UNSUPPORTED` | **WARN** | `auth_request` | response_mode value is unsupported by profile or verifier. |
| `OIDC4VP_RESPONSE_TYPE_UNSUPPORTED` | **FAIL** | `auth_request` | Unsupported or missing response_type for OIDC4VP. |
| `OIDC4VP_SCOPE_MISSING` | **WARN** | `auth_request` | scope is missing or empty. |
| `OIDC4VP_STATE_MISSING` | **WARN** | `auth_request` | state missing; CSRF protection may be weaker. |
| `OIDC4VP_TOK_BINDING_REQUIRED` | **WARN** | `auth_request` | Token binding/holder binding required by profile but not indicated. |
| `OIDC4VP_VP_FORMATS_MISSING` | **WARN** | `client_metadata` | vp_formats missing in verifier metadata. |
| `URL_HOSTNAME_MISMATCH` | **FAIL** | `network` | Hostname mismatch between request and expected issuer domain. |
| `URL_SCHEME_INSECURE` | **FAIL** | `network` | Insecure URL scheme (http) is not allowed for this context. |



---

## Rule Catalog — `/api/analyze-vc` (VC formats: SD‑JWT VC, JWT VC, JSON‑LD VC)

Each JSON response in `format: "json"` mode uses the following machine-readable rule codes.

| Code | Severity | Component | Message |
|------|----------|-----------|---------|
| `JSONLD_CANONICALIZATION_ERROR` | **FAIL** | `vc` | Canonicalization/normalization error during verification. |
| `JSONLD_CONTEXT_CONFLICT` | **WARN** | `vc` | Context term conflicts or redefinitions detected. |
| `JSONLD_CONTEXT_MISSING` | **FAIL** | `vc` | @context is missing or invalid. |
| `JSONLD_CONTEXT_REMOTE_FETCH_FAIL` | **FAIL** | `vc` | @context remote document could not be fetched/resolved. |
| `JSONLD_CONTROLLER_RESOLVE_FAIL` | **FAIL** | `vc` | Controller/DID Document could not be resolved. |
| `JSONLD_EVIDENCE_INVALID` | **WARN** | `vc` | Evidence object present but invalid format/content. |
| `JSONLD_KEY_NOT_AUTHORIZED` | **FAIL** | `vc` | Key not authorized for assertionMethod. |
| `JSONLD_PROOF_CREATED_INVALID` | **WARN** | `vc` | 'created' timestamp invalid or outside acceptable window. |
| `JSONLD_PROOF_MISSING` | **FAIL** | `vc` | Linked Data Proof is missing. |
| `JSONLD_PROOF_PURPOSE_INVALID` | **FAIL** | `vc` | proofPurpose invalid or not 'assertionMethod' when required. |
| `JSONLD_PROOF_TYPE_UNSUPPORTED` | **WARN** | `vc` | Linked Data Proof type is unsupported for profile. |
| `JSONLD_SCHEMA_VOCAB_UNKNOWN` | **WARN** | `vc` | Unknown vocabulary/terms (interoperability risk). |
| `JSONLD_SIG_VERIFICATION_FAILED` | **FAIL** | `vc` | Linked Data Proof verification failed. |
| `JSONLD_STATUS_2021_INVALID` | **FAIL** | `vc` | StatusList2021 entry invalid or not decodable. |
| `JSONLD_TYPE_MISSING` | **FAIL** | `vc` | VC 'type' is missing. |
| `JSONLD_VCDM_VERSION_UNEXPECTED` | **WARN** | `vc` | Unexpected VC Data Model version/terms for profile. |
| `JSONLD_VM_MISSING` | **FAIL** | `vc` | verificationMethod missing in proof. |
| `JSONLD_VM_RESOLVE_FAIL` | **FAIL** | `vc` | verificationMethod could not be resolved to a key. |
| `SDJWTVC_ALG_UNSUPPORTED` | **WARN** | `vc` | Unsupported or discouraged JWS 'alg'. |
| `SDJWTVC_AUD_MISMATCH` | **FAIL** | `kb_jwt` | 'aud' does not match verifier / RP. |
| `SDJWTVC_CLAIM_INTEGRITY_FAIL` | **FAIL** | `vc` | Reconstructed claims do not match signed payload. |
| `SDJWTVC_CRIT_UNSUPPORTED` | **FAIL** | `vc` | Unsupported 'crit' header present. |
| `SDJWTVC_DIGEST_MISMATCH` | **FAIL** | `vc` | Digest binding / disclosure hash mismatch. |
| `SDJWTVC_DISCLOSURE_DUPLICATE` | **WARN** | `vc` | Duplicate disclosures detected. |
| `SDJWTVC_DISCLOSURE_FORMAT` | **FAIL** | `vc` | Disclosure encoding/format invalid. |
| `SDJWTVC_DISCLOSURE_MISSING` | **FAIL** | `vc` | Required disclosures missing. |
| `SDJWTVC_EXP_INVALID` | **WARN** | `vc` | Token lifetime (exp/nbf/iat) is unusual or invalid. |
| `SDJWTVC_ISS_MISSING` | **FAIL** | `vc` | 'iss' claim missing in SD-JWT VC. |
| `SDJWTVC_KB_ALG_UNSUPPORTED` | **WARN** | `kb_jwt` | Key binding JWS algorithm unsupported by profile. |
| `SDJWTVC_KEYBINDING_MISSING` | **WARN** | `kb_jwt` | Key binding (holder binding) is missing or invalid. |
| `SDJWTVC_NONCE_MISSING` | **WARN** | `kb_jwt` | kb-jwt nonce missing where required. |
| `SDJWTVC_SUB_MISSING` | **FAIL** | `vc` | 'sub' claim missing in SD-JWT VC. |
| `SDJWTVC_TYP_INVALID` | **FAIL** | `vc` | Unexpected 'typ' for SD-JWT VC. |
| `SDJWTVC_UNBOUND_DISCLOSURE` | **FAIL** | `vc` | Disclosure present but not bound to SD-JWT claims. |
| `VCJWT_ALG_UNSUPPORTED` | **WARN** | `vc` | Unsupported or discouraged JWS 'alg' for VC-JWT. |
| `VCJWT_AUD_MISMATCH` | **FAIL** | `vc` | 'aud' does not match verifier / RP. |
| `VCJWT_CLAIMS_MISSING` | **FAIL** | `vc` | Required VC-JWT claims are missing (vc/iss/sub/nbf/exp). |
| `VCJWT_CRIT_UNSUPPORTED` | **FAIL** | `vc` | Unsupported 'crit' header present. |
| `VCJWT_EXP_INVALID` | **WARN** | `vc` | Token lifetime (exp/nbf/iat) is unusual or invalid. |
| `VCJWT_JWKS_UNREACHABLE` | **FAIL** | `vc` | JWKS/JWKS URI unreachable or invalid. |
| `VCJWT_KID_MISSING` | **WARN** | `vc` | 'kid' missing in header; key discovery may be ambiguous. |
| `VCJWT_SIG_VERIFICATION_FAILED` | **FAIL** | `vc` | JWT signature verification failed. |
| `VCJWT_SUBJECT_MISMATCH` | **FAIL** | `vc` | JWT 'sub' does not match 'vc.credentialSubject.id' when required. |
| `VCJWT_TYP_INVALID` | **FAIL** | `vc` | Unexpected 'typ' for VC-JWT. |
| `VCJWT_VC_ISSUER_MISMATCH` | **FAIL** | `vc` | JWT 'iss' does not match 'vc.issuer'. |
| `VCJWT_VC_OBJECT_MISSING` | **FAIL** | `vc` | 'vc' object missing in JWT claims. |
| `VC_AUD_MISMATCH` | **FAIL** | `vc` | 'aud' does not match the intended verifier/relying party. |
| `VC_CHARSET_INVALID` | **FAIL** | `vc` | Invalid character encoding or non-UTF-8 content. |
| `VC_DATA_FORMAT_INVALID` | **WARN** | `vc` | Field value format invalid (e.g., date/URI). |
| `VC_ISSUER_DID_RESOLVE_FAIL` | **FAIL** | `vc` | Issuer DID/URL could not be resolved. |
| `VC_ISSUER_ID_MISSING` | **FAIL** | `vc` | Issuer identifier is missing. |
| `VC_ISSUER_METHOD_NOT_ALLOWED` | **WARN** | `vc` | Issuer DID method not allowed by profile. |
| `VC_JTI_DUPLICATE` | **FAIL** | `vc` | Unique identifier re-use detected (possible replay). |
| `VC_JTI_MISSING` | **WARN** | `vc` | Unique identifier (jti/id) missing; replay protection may be weaker. |
| `VC_KEY_ALG_UNSUPPORTED` | **WARN** | `vc` | Signature algorithm not supported by profile. |
| `VC_KEY_FORMAT_MISMATCH` | **FAIL** | `vc` | Key format/type does not match signature/proof type. |
| `VC_KEY_NOT_AUTHORIZED` | **FAIL** | `vc` | Key is not authorized for assertion/proof purpose. |
| `VC_KEY_RESOLVE_FAIL` | **FAIL** | `vc` | Could not resolve verification key (DID Doc/JWKS/VM). |
| `VC_KEY_REVOKED` | **FAIL** | `vc` | Verification key has been revoked/expired. |
| `VC_KID_MISSING` | **WARN** | `vc` | Key identifier (kid/verificationMethod) is missing. |
| `VC_NONCE_MISMATCH` | **FAIL** | `vc` | Nonce/challenge mismatch with the verifier request. |
| `VC_NONCE_MISSING` | **WARN** | `vc` | Nonce/challenge missing where required by profile. |
| `VC_PARSE_ERROR` | **FAIL** | `vc` | Credential could not be parsed (malformed JSON/JWT/bytes). |
| `VC_SCHEMA_REQUIRED_MISSING` | **FAIL** | `vc` | Required fields missing by profile/schema. |
| `VC_SCHEMA_UNDECLARED_FIELDS` | **WARN** | `vc` | Undeclared or unexpected fields present (schema mismatch). |
| `VC_SIG_CRITICAL_HEADER_UNKNOWN` | **FAIL** | `vc` | Unknown or unsupported critical header/parameter present. |
| `VC_SIG_MALFORMED` | **FAIL** | `vc` | Signature/proof object malformed. |
| `VC_SIG_VERIFICATION_FAILED` | **FAIL** | `vc` | Signature/proof verification failed. |
| `VC_SIZE_EXCESSIVE` | **WARN** | `vc` | Credential size unusually large; may impact transport or verification. |
| `VC_STATUS_ENDPOINT_UNREACHABLE` | **FAIL** | `vc` | Status endpoint unreachable. |
| `VC_STATUS_LIST_INVALID` | **FAIL** | `vc` | Status list/entry invalid or could not be decoded. |
| `VC_STATUS_MISSING` | **WARN** | `vc` | No status information present (revocation/suspension unknown). |
| `VC_STATUS_REVOKED` | **FAIL** | `vc` | Credential is revoked. |
| `VC_STATUS_SUSPENDED` | **WARN** | `vc` | Credential is suspended. |
| `VC_SUBJECT_BINDING_MISSING` | **WARN** | `vc` | Holder binding is missing; cannot prove possession. |
| `VC_SUBJECT_ID_FORMAT_INVALID` | **WARN** | `vc` | credentialSubject.id format is invalid or unexpected. |
| `VC_SUBJECT_ID_MISSING` | **FAIL** | `vc` | credentialSubject.id (or equivalent) is missing when required. |
| `VC_TIME_CLOCK_SKEW_LARGE` | **WARN** | `vc` | Clock skew or token lifetime unusually large. |
| `VC_TIME_EXPIRED` | **FAIL** | `vc` | Credential is expired. |
| `VC_TIME_IAT_AFTER_EXP` | **FAIL** | `vc` | iat is after exp; time window invalid. |
| `VC_TIME_NBF_AFTER_EXP` | **FAIL** | `vc` | nbf is after exp; time window invalid. |
| `VC_TIME_NOT_YET_VALID` | **FAIL** | `vc` | Credential is not yet valid (nbf in future). |



> Note: Additional rule codes may be introduced over time. Clients should treat unknown codes as non-fatal unless marked with `severity: FAIL`.
