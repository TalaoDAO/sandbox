# OIDC4VC QR Code Validator --- Developer Guide

This guide explains how to test your **issuers** and **verifiers** using
the `ai_qrcode.html` tool. It is aimed at developers who want to
validate compliance with **OIDC4VCI** (issuance) and **OIDC4VP**
(presentation) specifications.

------------------------------------------------------------------------

## 1. Purpose of the Tool

This validator lets you paste a **QR code or deeplink** from your issuer
or verifier and receive a **compliance report**.\
It analyzes metadata, JWTs, credential offers, authorization requests,
and presentation definitions against the appropriate **OIDC4VCI /
OIDC4VP draft versions** and ecosystem profiles (EBSI, DIIP, INJI, EWC,
etc.).

The output is a **Markdown-formatted report**, structured into sections
with checks, errors, and developer-oriented improvement suggestions.

------------------------------------------------------------------------

## 2. How to Use the Page

1.  **Open** `ai_qrcode.html` in your browser.\
2.  **Paste** the QR code content (or full deeplink URI) into the
    textarea.\
3.  **Select a profile**:
    -   `EBSI`, `DIIP V3`, `DIIP V4`, `INJI`, `EWC` (preconfigured with
        draft versions & constraints)\
    -   `Custom` (manually pick OIDC4VCI/OIDC4VP drafts)\
4.  **Choose an analysis mode**:
    -   ⚡ **Flash** (fast, lightweight checks)\
    -   🧠 **Escalation** (deeper reasoning for complex cases)\
    -   👑 **Pro** (not available here)\
5.  Click **Run Diagnostic**.\
6.  Read the generated **report**.

------------------------------------------------------------------------

## 3. Issuer QR Code Reports

When you analyze an **issuer QR code** (credential offer):

-   The system extracts:

    -   **Credential Offer** (from `credential_offer` or
        `credential_offer_uri`)\
    -   **Issuer Metadata** (from
        `/.well-known/openid-credential-issuer`)\
    -   **Authorization Server Metadata** (from
        `/.well-known/oauth-authorization-server` or legacy
        `openid-configuration`)

-   The AI agent generates a **9-section Markdown report**:

    1.  **VC Summary** -- overview of credential offer fields\
    2.  **Required Claims Check** -- verifies required claims exist\
    3.  **Flow Type** -- which OIDC4VCI flow is used (e.g., auth code,
        pre-auth)\
    4.  **Issuer Metadata Summary** -- highlights main entries\
    5.  **Issuer Metadata Check** -- validation of supported formats,
        algorithms, identifiers\
    6.  **Authorization Server Metadata Summary** -- configuration
        details\
    7.  **Auth Server Metadata Check** -- consistency with draft version
        & profile\
    8.  **Errors & Warnings** -- issues found\
    9.  **Improvements** -- actionable suggestions for developers

-   Example issues caught:

    -   Missing claims in the credential offer
    -   Inconsistent `authorization_server` references
    -   Wrong key algorithms for the selected profile
    -   Metadata not served under expected well-known paths

------------------------------------------------------------------------

## 4. Verifier QR Code Reports

When you analyze a **verifier QR code** (authorization request):

-   The system extracts:

    -   **Authorization Request** (from `request` or `request_uri`)\
    -   **Request JWT** (header, payload, and x5c/JWK if available)\
    -   **Presentation Definition** (embedded or fetched from
        `presentation_definition_uri`)

-   The AI agent generates a **6-section Markdown report**:

    1.  **Abstract** -- short description of request\
    2.  **Authorization Request** -- checks required OIDC4VP claims
        (`iss`, `client_id`, `response_type`, etc.)\
    3.  **Presentation Definition** -- validates schema, input
        descriptors, constraints\
    4.  **Client Metadata** -- inspects client details if present\
    5.  **Errors & Warnings** -- issues in JWT, x5c certificate, or
        parameters\
    6.  **Improvements** -- technical fixes and developer suggestions

-   Example issues caught:

    -   `iss` missing or not matching certificate SAN
    -   Wrong `Content-Type` on `request_uri` response
    -   Presentation definition schema errors
    -   Security warnings when passing parameters in plain query form
        instead of JWT

------------------------------------------------------------------------

## 5. Profiles and Draft Versions

The tool adapts automatically when a **profile** is selected:

-   **EBSI** → JWT VC only, `did:key` or `did:ebsi` identifiers\
-   **DIIP V3 / V4** → SD-JWT VC, JWT VC JSON, JSON-LD,
    `did:jwk`/`did:web`, ES256\
-   **INJI (MOSIP)** → JSON-LD only\
-   **EWC** → SD-JWT VC and mdoc formats

For **Custom** mode, you pick the **OIDC4VCI** and **OIDC4VP** draft
numbers manually.

------------------------------------------------------------------------

## 6. Report Attribution

Each report ends with attribution lines:

-   Which **LLM model** was used (e.g., GPT/Gemini Flash or Escalation)\
-   Which **spec draft** the validation is based on\
-   **Date of issuance**\
-   Reminder: *LLMs can make mistakes; cross-check cryptographic details
    manually*

------------------------------------------------------------------------

## 7. Developer Best Practices

-   Always test with **synthetic data** --- never use personal data.\
-   Match your ecosystem (EBSI, DIIP, etc.) to ensure correct drafts are
    applied.\
-   For quick feedback loops, stick with **Flash** mode; escalate only
    for edge cases.\
-   Automate testing in **CI/CD pipelines** by generating QR codes and
    running them through this tool.\
-   Review **Errors & Warnings** first, then apply the **Improvements**
    suggestions.

------------------------------------------------------------------------

## 8. Disclaimer

-   This tool integrates **OpenAI and Google LLMs** with **Web3 Digital Wallet
    testing datasets**.\
-   Reports are **diagnostic**, not certification.\
-   Always confirm results against the official specifications and your
    conformance suite.

------------------------------------------------------------------------

👉 With `ai_qrcode.html`, developers can validate issuer and verifier QR
codes quickly, spot compliance issues, and receive actionable
improvement guidance --- all in a structured Markdown report.
