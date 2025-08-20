# 📘 Welcome to the Documentation

_Last updated: April 1, 2025_

Welcome to the official documentation for the **Talao** and **Altme** wallets — powerful mobile applications designed for managing and presenting **Verifiable Credentials** in Self-Sovereign Identity (SSI) ecosystems. This guide also includes integration details for the **Wallet Provider Backend**, which supports enterprise and ecosystem deployment.

Whether you're a developer, integrator, or decision-maker, this documentation provides everything you need to build, test, and deploy identity flows using Talao and Altme.

---

## 💬 Need Help?

If you encounter issues, have questions, or would like a demo:

- 📧 [Contact us by email](mailto:contact@talao.io)
- 🐞 [Open a GitHub issue](https://github.com/TalaoDAO/AltMe/issues)
- 📅 [Request a demo](https://qhf0siml406.typeform.com/to/PdULRDIV?typeform-source=talao.io)

---

## 📱 Wallets Overview

Talao and Altme are open-source mobile wallets for collecting, storing, and presenting **Verifiable Credentials (VCs)**. These apps manage:

- User data associated with credentials
- Cryptographic keys for signing and authentication
- Exchange protocols with **Issuers** and **Verifiers** in SSI ecosystems

### Available Wallets:

- **Talao Wallet**
  - [Google Play](https://play.google.com/store/apps/details?id=co.talao.wallet)
  - [Apple Store](https://apps.apple.com/fr/app/talao-wallet/id1582183266?platform=iphone)

- **Altme Wallet**
  - [Google Play](https://play.google.com/store/apps/details?id=co.altme.alt.me.altme&hl=en-US&pli=1)
  - [Apple Store](https://apps.apple.com/fr/app/altme-wallet/id1633216869)

---

## 🛠️ Wallet Provider Backend

The **Wallet Provider Backend** is a secure web service that links wallet instances with ecosystems or trust frameworks. Its key roles include:

- Issuing **Wallet Unit Attestations (WUA)** to validate wallet integrity
- Managing wallet activation/suspension
- Supporting institutional onboarding and policy enforcement
- Providing enterprise-level configuration and user support

This component is ideal for regulated projects, trust frameworks, and national deployments.

---

## 📐 Standards Compliance

Talao and Altme are built with full support for SSI and verifiable credential standards:

### 📄 Credential Formats

- [W3C Verifiable Credential Data Model v1.1](https://www.w3.org/TR/vc-data-model/)
- [IETF SD-JWT VC Format](https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-01.html)

### 🔗 Exchange Protocols

- [OpenID for Verifiable Credentials](https://openid.net/sg/openid4vc/)
- [W3C Verifiable Presentation Request Draft](https://w3c-ccg.github.io/vp-request-spec/)

### 🔧 Ecosystem Profiles

- [EBSI](https://ec.europa.eu/digital-building-blocks/sites/display/EBSI/Home)
- [EUDI Wallet ARF](https://eu-digital-identity-wallet.github.io/eudi-doc-architecture-and-reference-framework/1.1.0/arf/)
- [DIIP – Decentralized Identity Interop Profile](https://dutchblockchaincoalition.org/en/bouwstenen-2/diip-2)
- [High Assurance Interop Profile (OpenID)](https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-sd-jwt-vc-1_0.html)

---

## ⚙️ Licensing & Usage

- **Talao & Altme Wallets**: Available open-source via [GitHub](https://github.com/TalaoDAO/AltMe)
- **Wallet Provider Backend**: Available under commercial license

> The wallets are fully autonomous. However, the backend adds advanced capabilities for enterprise use, project deployment, and complex configurations.