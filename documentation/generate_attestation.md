# Generate VC Type Metadata (Platform Guide)

**Audience:** users of the platform.  
This guide shows how to use the **Generate VC Type Metadata** page (`generate_attestation.html`) to create a **VC Type Metadata** JSON file for any attestation. There is **no API step** here — everything happens in the web interface.

---

## What you’ll produce

A single **VC Type Metadata** JSON file that describes your credential type (VCT):
- **`vct`** — your credential type identifier (URL or URN).
- **`display[]`** — one entry per language (name/description) plus a **simple rendering** block (shared colors + optional logo).
- **`schema`** — the JSON Schema for your credential’s claims (uploaded by you or inferred from a description).
- **`claims[]`** — each business claim with localized labels (you can edit them in the editor before saving).

You will download this JSON to your desktop when you’re done.

---

## Quick Start (2 minutes)

1. Open **Generate VC Type Metadata** and locate the form.
2. In **VCT (URL or URN)**, paste or type your credential type identifier (e.g., `https://issuer.example.com/vct/email-verification`).  
3. Choose **Upload JSON Schema** *or* **Describe Attestation**:
   - **Upload JSON Schema** if you already have a schema (`.json` file).
   - **Describe Attestation** to let the tool infer a schema from bullets/free text.
4. (Optional) In **Display style**, pick **Background color**, **Text color**, and add a **Logo URL**. These apply to *all* languages.
5. Select your **Languages** (e.g., English and French).
6. Leave **Try using LLM** enabled unless you prefer deterministic labels only.
7. Click **Generate Metadata** → Review & edit the JSON in the editor → **Save JSON to Desktop**.

Tip: Use the **Format** and **Validate** buttons in the editor to keep your JSON clean.

---

## Step‑by‑Step: filling the form

### 1) VCT (URL or URN)
- Enter a stable identifier for this credential type.  
  - URL example: `https://issuer.example.com/vct/employee-card`  
  - URN example: `urn:uuid:…` (auto‑suggested when the page opens)

### 2) Choose your input mode
- **Upload JSON Schema**  
  - Click **Choose File** and select a `.json` file.  
  - The tool uses your schema as‑is (no inference).
- **Describe Attestation**  
  - Write bullets or short lines that list the claims you want. Example:  
    ```
    Email Verification
    - email (format: email)
    - verifiedAt (date-time)
    - method (enum: magic-link, code, oidc, other)
    ```
  - The tool infers a JSON Schema and the claim paths from this description.

### 3) Display style (branding for all languages)
- **Background color** — e.g., `#0b1020` (dark) or `#ffffff` (light).
- **Text color** — choose a readable color against your background.
- **Logo URL (optional)** — a public HTTPS image URL (PNG/SVG/JPG).  
These values are stored under `display[].rendering.simple` and are duplicated for every language so your branding stays consistent.

### 4) Languages
- Tick one or more languages (we recommend **English + your target locales**).  
- The tool creates one `display` entry per selected language and also localizes the claim labels.

### 5) Try using LLM
- When checked, the tool proposes human‑friendly names/descriptions for your type and claims.  
- If you uncheck it, the tool generates deterministic fallback labels (derived from field names).

### 6) Generate & edit
- Click **Generate Metadata**. A spinner appears while the JSON is built.
- The result opens in the **Editable JSON** area. You can:
  - **Format** — pretty‑print the JSON.
  - **Validate** — check JSON validity.
  - **Reset to Server Result** — discard your edits and reload the original.
  - **Copy** — copy the JSON to your clipboard.
  - **Save JSON to Desktop** — download the file (the filename includes the VCT and languages).

---

## Result overview (what you’ll see in the editor)

- **`vct`**: the identifier you provided.  
- **`display[]`**: one object per language, e.g.:
  ```json
  {
    "lang": "en",
    "name": "Email Verification",
    "description": "Verifiable credential",
    "rendering": {
      "simple": {
        "background_color": "#0b1020",
        "text_color": "#e6edf3",
        "logo": { "uri": "https://issuer.example.com/assets/logo.png" }
      }
    }
  }
  ```
- **`schema`**: either your uploaded JSON Schema or an inferred one (you can edit this too).
- **`claims[]`**: each entry maps a **claim path** to localized display labels, e.g.:
  ```json
  {
    "path": ["email"],
    "display": [
      { "lang": "en", "name": "Email" },
      { "lang": "fr", "name": "E‑mail" }
    ],
    "sd": "allowed"
  }
  ```

---

## Practical recipes

- **You already have a schema** → choose **Upload JSON Schema**, set branding & languages, **Generate**, then save.
- **You’re starting from scratch** → choose **Describe Attestation**, paste bullets, **Generate**, tweak the inferred schema/labels, then save.
- **Email Verification example**  
  - VCT: `https://issuer.example.com/vct/email-verification`  
  - Description:  
    ```
    Email Verification
    - email (format: email)
    - verifiedAt (date-time)
    - method (enum: magic-link, code, oidc, other)
    ```
  - Pick colors and a logo URL, choose languages, **Generate**, then **Save JSON**.

---

## Tips & best practices

- Use a **stable VCT** you control (URL or URN). If it’s a URL, consider hosting the JSON at that address later.
- Keep **names** short and **descriptions** clear; adjust them in the editor.
- Choose **high‑contrast** colors for readability.
- Start with **English + one locale**, expand once the labels look right.
- If the editor says *“Invalid JSON”*, click **Reset**, then **Format**, and re‑apply your edits carefully.

---

## Troubleshooting

- **“Invalid JSON Schema file”** when uploading → Ensure the file is valid JSON and uses `.json` extension.
- **Nothing happens on Generate** → Check that **VCT** is filled and either a **schema** file is selected or a **description** is written (depending on the mode).
- **Colors/logo not visible in JSON** → Make sure you set them in **Display style** before clicking **Generate**; they appear under `display[].rendering.simple`.
- **Weird labels** → Uncheck **Try using LLM** to switch to deterministic labels, or directly edit in the editor.
- **Can’t save** → The **Save JSON to Desktop** button only enables after a successful generation; ensure the editor shows a result.

---

## Where to get help

- On the page header, click **“Explain ?”** to open this guide.  
- If something looks off in the generated JSON, paste a small excerpt when you contact support — we’ll tell you exactly which part to tweak.

---

**You’re done!** You now have a VC Type Metadata file ready to share or to host under your VCT URL.
