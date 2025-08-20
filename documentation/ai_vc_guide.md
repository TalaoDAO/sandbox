# VC / VP Validator — Developer Guide

This guide explains how to test **Verifiable Credentials (VCs)** and **Verifiable Presentations (VPs)** using the `ai_vc.html` page. It targets developers validating compliance across **SD‑JWT VC**, **JWT VC**, and **JSON‑LD VC/VP** formats with the relevant specifications (SD‑JWT VC Drafts and W3C VCDM 1.1).

---

## 1) Purpose of the Tool

Paste a VC/VP payload into the page and receive a **structured compliance report**. The tool can analyze:

- **SD‑JWT VC** (with disclosures and optional **Key Binding JWT**)
- **JWT VC** (compact JWS)
- **JSON‑LD VC** or **VP**

Reports are format‑aware and check headers, payloads/claims, disclosures, cryptographic hints, and structural correctness according to the draft you select.

---

## 2) How to Use the Page

1. Open `ai_vc.html` in your browser.  
2. In **VC / VP payload**, paste one of the supported formats:  
   - **SD‑JWT VC**: `header.payload.signature~disclosure~...~kb-jwt`  
   - **JWT VC**: `header.payload.signature`  
   - **JSON‑LD VC / VP**: a valid JSON object with `@context` and `type`
3. Choose **Analysis mode**:  
   - ⚡ **Flash** — quickest pass for dev loops/CI.  
   - 🧠 **Escalation** — deeper reasoning for edge cases.  
   - 👑 **Pro** — not available on this page.
4. Pick **Drafts**:
   - **SD‑JWT VC Draft** (e.g., 9).  
   - **VCDM** (W3C VC Data Model, e.g., 1.1) — used for JWT VC & JSON‑LD VC checks.
5. Click **Run Diagnostic** and read the generated report.

Tips: Use the toolbar to **Paste**, **Clear**, or insert **Samples**. The character counter helps gauge payload size.

---

## 3) What the Reports Contain (by Format)

### A) SD‑JWT VC Reports

The analyzer splits the token on `~` into the **SD‑JWT**, **disclosures**, and optional **KB‑JWT**. It decodes the JWT header/payload and attempts to verify signature context using one of:

- `x5c` chain (and checks whether the **issuer (iss)** matches **SAN** DNS/URI in the leaf certificate)  
- `jwk` embedded in header  
- `kid` look‑up via:  
  - **DID methods** (if `iss` is DID and `kid` is a DID verification method)  
  - Issuer well‑known metadata at `/.well-known/jwt-vc-issuer` (matching `kid` against JWKS / `jwks_uri`)

If a **Key Binding JWT** is present (detected by the last part being a JWT), its header and payload are decoded.

**Report sections include:**

1. **Holder & Issuer Identifiers** — e.g., `cnf` (holder key) and `iss` (issuer).  
2. **Header Required Claims** — checks for missing/invalid header fields (e.g., `alg`, `kid`, `x5c` / `jwk`).  
3. **Payload Required Claims** — checks for required SD‑JWT VC claims (including `iss`).  
4. **Key Binding JWT Check** — if present, verifies structural correctness (header/payload are proper JWT sections) and consistency.  
5. **Signature Information** — outcome/observations from `x5c`/`jwk`/DID/metadata key resolution attempts.  
6. **Errors & Improvements** — concrete issues and developer‑focused fixes.

> **Note**: Disclosures are decoded and validated for format. Any decoding problems are flagged.

### B) JWT VC Reports

For compact **JWT VC**, the analyzer decodes header/payload and checks conformance against **VCDM** (e.g., 1.1).

**Report sections include:**

1. **Holder & Issuer Identifiers**  
2. **All Claims** — a readable list of claims found in the VC.  
3. **Header Required Claims** — missing/invalid header fields.  
4. **Payload Required Claims** — missing/invalid payload fields.  
5. **Errors & Improvements** — specific problems and remediations.

### C) JSON‑LD VC / VP Reports

The analyzer reads the JSON‑LD and checks structure against **VCDM**.

**Report sections include:**

1. **Holder & Issuer Identifiers**  
2. **All Claims** — lists fields and top‑level structure.  
3. **Required Claims Check** — for JSON‑LD VC/VP.  
4. **Errors & Improvements** — precise guidance on fixes.

---

## 4) Drafts & Standards

- **SD‑JWT VC Draft** (selectable in the page): picks the spec text used for checks.  
- **VCDM (e.g., 1.1)**: applied to **JWT VC** and **JSON‑LD** formats.  

These choices directly affect required claims and validation logic in the report.

---

## 5) Analysis Modes

- **Flash**: fast, low‑latency checks suitable for CI and quick loops.  
- **Escalation**: deeper reasoning — better for complex disclosures, signed metadata, DID resolution, and nuanced profile rules.  
- **Pro**: premium, disabled here.

---

## 6) Attribution in the Report

Each report ends with attribution lines indicating:

- **Model used** (e.g., GPT‑5 Flash or GPT‑5 for Escalation)  
- **Spec & draft** applied (SD‑JWT VC draft or VCDM version)  
- **Date of issuance**  
- A short reminder that LLMs can make mistakes and cryptographic results should be cross‑checked.

---

## 7) Developer Best Practices

- Use **synthetic data** only; do **not** paste personal data.  
- Start with **Flash**, escalate when uncertain or for advanced cases.  
- Keep your **draft selections** aligned with your ecosystem/spec target.  
- Automate in **CI/CD**: generate tokens → call this page → parse reports for regressions.  
- When using `x5c`, ensure the **issuer (iss)** aligns with a **SAN** DNS/URI in the leaf cert, and host a valid chain.  
- For `kid`‑based verification, ensure your well‑known metadata or DID doc exposes a matching public key.

---

## 8) Disclaimer

This tool combines **OpenAI models** with **Web3 Digital Wallet** testing datasets to produce diagnostic reports.  
They are **not certifications**. Always confirm against the official specifications and your conformance suite.

