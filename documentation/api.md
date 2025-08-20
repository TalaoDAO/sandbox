# APIs

Updated the 2nd of June 2025.

This is a list of APIs available to help developers. The server is available at https://talao.co.


## POST `/api/analyze-qrcode`


Analyze a base64-encoded QR code representing an OIDC4VC authorization request and presentation definition. The system uses OpenAI to evaluate the request structure, protocol compliance (OIDC4VCI / OIDC4VP), and semantic correctness, then returns a detailed technical report in Markdown format (also base64-encoded).
This API is used to serve https://talao.co/ai/qrcode .

### Authentication

| Header    | Value               |
|-----------|---------------------|
| Api-Key   | Your authorized key |

---

### Request (JSON)

```json
{
  "qrcode": "c29tZS1hc3NpZ24tdGV4dA==",       // Base64-encoded QR code content
  "oidc4vciDraft": "12",                      // (optional) OIDC4VCI draft version
  "oidc4vpDraft": "18",                       // (optional) OIDC4VP draft version
  "profil": "EBSI"                            // (optional) profil
}
```

Note: The `qrcode` value **must be base64-encoded**. This allows for safe transmission of binary or non-UTF-8 data.

---

### Successful Response

```json
{
  "report_base64": "<base64-encoded markdown report>"
}
```

To decode the Markdown report in Python:

```python
import base64
decoded = base64.b64decode(response["report_base64"]).decode()
print(decoded)
```

---

### Profil

If profil is set to "custom" then OIDC4VC Drafts apply.

| Parameter    | Ecosystem            |
|-----------|---------------------|
| EBSI   | EBSI v3.x |
| INJI   | MOSIP Inji stack |
| DIIP_V3   | FIDES DIIP V 3.0  |
| DIIP_V4   | FIDES DIIP V 4.0  |
| EWC   | LSP EWC |
| custom   | Default value |

---

### Error Responses

| HTTP Code | Message                                 | Description                         |
|-----------|-----------------------------------------|-------------------------------------|
| 400       | `{"error": "missing qrcode"}`           | QR code field was not provided      |
| 400       | `{"error": "invalid base64 format"}`    | QR code could not be decoded        |
| 403       | `{"error": "access denied"}`            | Invalid or missing API key          |
| 500       | `{"error": "internal processing error"}`| Unhandled exception occurred        |

---

### Example cURL


```bash
curl -X POST https://talao.co/api/analyze-qrcode   -H "Content-Type: application/json"   -H "Api-Key: your-api-key"   -d '{
        "qrcode": "c29tZS1hc3NpZ24tdGV4dA==",
        "oidc4vciDraft": "12",
        "oidc4vpDraft": "18",
        "profil": "EBSI"
      }'
```

## POST `/api/analyze-vc`

Analyze a base64-encoded Verifiable Credential (VC). The system detects whether the VC is in SD-JWT VC, JWT VC (compact), or JSON-LD VC format, then evaluates its compliance using OpenAI. The response is a Markdown diagnostic report encoded in base64.

This endpoint is used to analyze a credential submitted via the AI sandbox.This API is used to serve https://talao.co/ai/vc .

### Authentication

| Header    | Value               |
|-----------|---------------------|
| Api-Key   | Your authorized key |

---

### Request (JSON)

```json
{
  "vc": "BASE64_ENCODED_VC_STRING",        // Required
  "sdjwtvc_draft": "8",                    // Optional - for SD-JWT VC format
  "vcdm_draft": "1.1"                       // Optional - for JWT VC format
}
```

---

### Successful Response

```json
{
  "report_base64": "<base64-encoded markdown report>"
}
```

To decode the Markdown report in Python:

```python
import base64
print(base64.b64decode(response["report_base64"]).decode())
```

---

### Error Responses

| HTTP Code | Message                                      | Description                            |
|-----------|----------------------------------------------|----------------------------------------|
| 400       | `{"error": "Missing 'vc' field"}`            | No VC was provided                     |
| 400       | `{"error": "Invalid base64 encoding for VC"}`| VC could not be base64-decoded         |
| 403       | `{"error": "Access denied"}`                 | API key is missing or invalid          |
| 500       | `{"error": "Internal processing error"}`     | Unexpected error in processing         |

---

### Example cURL

```bash
curl -X POST https://talao.co/api/analyze-vc \
  -H "Content-Type: application/json" \
  -H "Api-Key: your-api-key" \
  -d '{
        "vc": "BASE64_ENCODED_VC_STRING",
        "sdjwtvc_draft": "8",
        "vcdm_draft": "1.1"
      }'
```