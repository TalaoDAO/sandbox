# Welcome

Updated the 1st of April 2025.

Here you will find the documentation concerning the use and integration of the Talao and Altme wallets. You will also find information concerning the use of the Wallet Provider Backend associated with these wallets.

If you encounter issues or have questions or if you want a demo do not hesitate to contact us.

[Contact us by email](mailto:contact@talao.io)

[Post a ticket on github](https://github.com/TalaoDAO/AltMe/issues)

[Fill this form for a demo](https://qhf0siml406.typeform.com/to/PdULRDIV?typeform-source=talao.io)

## Wallets

The Talao and Altme wallets are mobile applications for collecting, storing and presenting certificates in the verifiable credentials format. These wallets store the data associated with these certificates, the cryptographic keys associated with these certificates and the exchange protocols between the different stakeholders of a Self Sovereign Identity (SSI) architecture: the issuers (or attribute providers) and the verifiers (or Relying parties).

We provides 2 mobile wallets:

* Talao wallet : it is a self sovereign identity(SSI) wallet to support verifiable credentials,

  * [Talao Google store](https://play.google.com/store/apps/details?id=co.talao.wallet)
  * [Talao Apple store](https://apps.apple.com/fr/app/talao-wallet/id1582183266?platform=iphone)
* Altme wallet : it is a Self Sovereign Identity and crypto wallet to support verifiable credentials and crypto assets (token, NFT) on blockchains.

  * [Altme Google store](https://play.google.com/store/apps/details?id=co.altme.alt.me.altme&hl=en-US&pli=1)
  * [Altme Apple store](https://apps.apple.com/fr/app/altme-wallet/id1633216869)

## Wallet Provider Backend

The wallet provider backend is a web application that allows you to make the link between an organization, a project or a trusted environment (Trust framework) and the instance of a particular user's wallet.

The essential role of the Wallet Provider Backend is to issue and sign a certificate to each instance of the wallet whose purpose is to prove that the instance complies with the security and quality policy of the ecosystem. Subsequently, taking advantage of this infrastructure, other roles have been assigned to the Wallet Provider Backend: activation and suspension of users, configuration of wallet instances, user support, etc.

## Standards

The SSI Talao and Altme wallets have been developed according to several standards and in particular:

for the verifiable credential formats:

- [The W3C verifiable credential data model 1.1](https://www.w3.org/TR/vc-data-model/)
- [The SD-JWT based verifiable credential IETF specification](https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-01.html)

for protocols:

- [The OpenID for verifiable credential specifications](https://openid.net/sg/openid4vc/)
- [The W3C draft of Verifiable Presentation Request 2024](https://w3c-ccg.github.io/vp-request-spec/)

We also use specifications of ecosystems or technical profiles as:

* [EBSI](https://ec.europa.eu/digital-building-blocks/sites/display/EBSI/Home)
* [EUDI wallet / ARF](https://eu-digital-identity-wallet.github.io/eudi-doc-architecture-and-reference-framework/1.1.0/arf/)
* [The Decentralized Identity Interop Profile](https://dutchblockchaincoalition.org/en/bouwstenen-2/diip-2)
* [The High Assurance Interoperability Profile](https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-sd-jwt-vc-1_0.html)

## Notice

Talao and Altme wallets are **advanced SSI wallets**. They support different ecosystems, different VC formats, different protocol versions. They are useful tools for issuer and verifier developers but their customization also allows to simplify their appearance for all production project use cases.

The Altme and Talao wallets are available in open source code on the [Talao github repository](https://github.com/TalaoDAO/AltMe), the Wallet Provider Backend is offered in the form of a commercial license. The Talao and Altme wallets are autonomous and do not require access to the backend, however the latter is useful for a complex configuration of the wallet or for the deployment of projects in companies.
