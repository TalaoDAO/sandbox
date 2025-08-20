# Light Trusted List Mechanism

Updated the 2nd of August, 2025

## Table of Contents

1. [Overview](#overview)
2. [Objectives](#objectives)
3. [Use Cases for the Trusted List](#use-cases-for-the-trusted-list)
   - [Relying Parties Verify Attestation Issuers' Identities and Capabilities](#1-relying-parties-verify-attestation-issuers-identities-and-capabilities)
   - [Wallets Verify Relying Parties' Identities and Capabilities](#2-wallets-verify-relying-parties-identities-and-capabilities)
   - [Wallets Verify Issuers' Identities and Capabilities](#3-wallets-verify-issuers-identities-and-capabilities)
   - [Issuers or Relying Parties Verify Wallet Instance Attestations](#4-issuers-or-relying-parties-verify-wallets-instance-attestations)
4. [Ecosystem Roles and Responsibilities](#ecosystem-roles-and-responsibilities)
5. [User Trust Management Strategy](#user-trust-management-strategy)
6. [Certificate Chain Validation](#certificate-chain-validation)
7. [Compatibility with Other Standards](#compatibility-with-other-standards)
8. [Components](#components)
   - [Trusted List URL](#1-trusted-list-url)
   - [Trusted List API (JSON Format)](#2-trusted-list-api-json-format)
   - [Field Descriptions](#3-field-descriptions)
9. [Backend Management Interface](#backend-management-interface)
10. [Error Handling](#error-handling)
11. [Security Recommendations](#security-recommendations)
12. [Example Trusted List URL](#example-trusted-list-url)
13. [Signature Validation of the Trusted List](#signature-validation-of-the-trusted-list)
14. [Revocation Mechanism](#revocation-mechanism)
15. [Using cheqd for Trusted List Decentralized Support](#using-cheqd-for-trusted-list-decentralized-support)
    - [Step 1: Create a DID on cheqd (Python, Custodial Method)](#step-1-create-a-did-on-cheqd-python-custodial-method)
    - [Step 2: Publish Trusted List as DID-Linked Resource](#step-2-publish-trusted-list-as-did-linked-resource)
    - [Step 3: Retrieve the Trusted List](#step-3-retrieve-the-trusted-list)
16. [Security Threat Modeling](#security-threat-modeling)

## Overview

This specification defines a simple and light trusted list mechanism. The trusted list is based on **standard Public Key Infrastructure (PKI)** and **X.509 certificates issued by recognized Certificate Authorities (CAs) and/or  Decentralzed Identifiers (DIDs)**. The motivation behind this approach is to provide a **standards-based solution** to establish a **trusted ecosystem of issuers and verifiers** for small or medium sized **ecosystems estimated below 20/30 entities**. The approach explicitly takes into account the OIDC4VC protocol suite, supporting use cases such as issuance and verification of VCs.

This version of the specification also introduces **capability support** within the trusted model (e.g., what types of credentials or actions are trusted per entity) and **restricts trust anchor methods** to **just two mechanisms** : X.509 certificates and DIDs. This simplifies validation logic and implementation in constrained environments.

Unlike the ETSI TS 119 612 specification that defines complex XML-based trusted lists for qualified trust service providers (QTSPs), this specification offers a significantly **simpler and JSON-based alternative**. The goal is to enable **easier implementation, parsing, and maintenance**, especially suitable for ecosystems that do not require the full compliance and overhead of eIDAS-qualified services. Compared to approaches like the EBSI Trust Framework or OpenID Federation, this model avoids dynamic resolution or layered delegation by focusing on two static verification methods: X.509 certificates and DIDs. It offers capability-based trust while keeping implementation minimal and predictable.

Each wallet, issuer or verifier must retrieve and regularly update a list of trusted parties. This trusted list is provided by an ecosystem API specified by the wallet provider for wallet instances initialization. Each ecosystem must implement a compliant API to expose its trusted participants.

This specification is particularly targeted at **small to medium-sized ecosystems**, where a centralized trusted list is practical and operationally efficient. In practice it addresses the needs and requirements of many projects which use SSI technologies.

As an optional enhancement, the trusted list can also be published on a **decentralized ledger like cheqd** using **DID Linked Resources**. This provides tamper-evident distribution, cryptographic verification, and decentralized discoverability for higher security and transparency needs.

## Objectives

- Establish a secure trust framework between wallets, issuers, and verifiers using standard PKI principles or DIDs
- Provide a lightweight alternative to complex federation models for small and medium-sized ecosystems
- Promote interoperability and cross-ecosystem recognition of credential issuers and verifiers
- Support timely and manageable updates to trust relationships through routine trusted list refreshes
- Enable trusted operations without requiring complex or real-time federation or revocation mechanisms

## Use Cases for the Trusted List

The trusted list defined in this specification supports a range of **identity-related use cases** across relying parties (issuers), verifiers, and wallet providers. It acts as the **root of trust** for validating certificates, signatures, and metadata used in OIDC4VP, SD-JWT, and related protocols.

### 1. Relying Parties Verify Attestation Issuers’ Identities and Capabilities

Relying parties (e.g., merchants, service providers, or verifiers) must ensure that any **Verifiable Credential (VC)** or **SD-JWT** they receive is issued by a **recognized and trusted authority**. This validation is performed using the **trusted list** of root certificates and metadata, which provides the foundation for verifying issuer authenticity and capabilities:

- **Use of X.509 Root Certificates** The trusted list contains **X.509 root certificates** that serve as the anchors of trust.When an issuer embeds its signing certificate chain (e.g., using an `x5c` header in JWTs or JWS), the relying party:

  - Extracts the certificate chain from the credential.
  - Validates the chain back to one of the trusted root certificates.
  - Ensures the certificate has not been revoked and complies with the trust policy.
- **Support for DIDs (Decentralized Identifiers)** Some issuers use **DIDs** instead of or alongside traditional certificates (e.g., in JWT- or LD-based credentials).In such cases, the relying party checks:

  - That the DID method is supported (e.g., `did:web`, `did:ebsi`, or `did:jwk`).
  - That the DID document or verification key is signed or anchored to a trusted root or registry.
- **Capability Validation** Beyond verifying the identity of the issuer, the relying party must confirm that the issuer is **authorized to issue specific credential types**.For example:

  - A government agency listed in the trusted list may be authorized to issue **PID (Personal Identity Documents)** or **eIDAS credentials**.
  - A financial services provider may only be authorized for **AML/KYC status attestations**.
- **Credential Traceability** By validating the full certificate chain and ensuring it maps to an entry in the trusted list, the relying party can **trace any credential back to its source issuer**.
  This prevents the acceptance of credentials from unverified or rogue issuers.

**Example Flow:**

1. A merchant receives a user’s **identity SD-JWT VC** during a payment authorization.
2. The merchant extracts the `x5c` chain from the VC header.
3. The merchant checks that:
   - The chain validates to a root CA in the trusted list.
   - The issuer of the VC is authorized to issue **identity attributes**.
4. If all checks pass, the merchant accepts the credential as **trustworthy**.

### 2. Wallets Verify Relying Parties’ Identities and Capabilities

During an **OIDC4VP flow**, wallets must ensure that the relying party (merchant, verifier, or service provider) requesting a presentation is **legitimate and authorized**. This involves several verification steps:

- **JWT Signature Validation** The `authorization_request` is typically a signed JWT. The wallet validates:

  - The **signature** using the `client_id` (e.g., `client_id=x509_san_dns:<domain>`) to extract the relying party’s certificate chain.
  - That the signing certificate **chains back to one of the trusted root CAs** listed in the trusted list.
- **Capability Check** The wallet checks the **capabilities** of the relying party as listed in the trusted list:

  - Whether the verifier is authorized to request specific Verifiable Credential types (e.g., PID, AMLStatusCredential).
  - Whether the relying party is flagged for **specific regulatory roles**, such as AML-compliant KYC verifiers.
- **Domain Matching** When `x509_san_dns` is used as the client identifier, the wallet ensures that the **Subject Alternative Name (SAN)** in the certificate matches the expected domain (e.g., `merchant.example.com`).

**Example Flow:**

1. The wallet fetches and parses the trusted list.
2. On receiving an authorization request, the wallet extracts the certificate (`x5c` header).
3. The wallet verifies the certificate chain and cross-references the entity in the trusted list to confirm:
   - **Identity:** Valid x.509 root or DID.
   - **Capabilities:** Authorization to request the required VC types.

### 3. Wallets Verify Issuers’ Identities and Capabilities

Wallets also validate **issuers of Verifiable Credentials (VCs)** or **SD-JWT VCs** to ensure that the data presented to users originates from recognized and trusted authorities. This process involves:

- **Issuer Metadata Validation** Issuers may sign their metadata (e.g., OpenID configuration or credential schema) as JWTs. Wallets:

  - Validate the **JWT signature** using the issuer’s certificate or DID.
  - Confirm that the certificate **chains to a trusted root** listed in the trusted list.
- **Credential Type Verification** The wallet ensures that the issuer is explicitly trusted for the credential type being presented.For example:

  - A government authority listed in the trusted list can issue a **PID (Personal Identity Credential)**.
  - A regulated KYC provider can issue an **AMLStatusCredential**.
- **Issuer Endpoint Cross-Check** The `issuer` field or endpoint in the credential is compared to entries in the trusted list to verify it matches the **registered URL or DID**.
- **Data Integrity and Binding**For SD-JWT VCs:

  - The wallet validates that all selective disclosure hashes align with the issuer’s signature.
  - The chain of trust (issuer → root CA) is intact and matches the trusted list.

**Example Use Case:**
When a user imports a VC issued by "GovID Issuer A", the wallet:

1. Fetches the issuer’s `x5c` or DID from the credential.
2. Validates it against the trusted list (e.g., `https://example.com/issuer1`).
3. Confirms that "GovID Issuer A" is permitted to issue a `Pid` VC type.

### 4. Issuers or Relying Parties Verify Wallet Instance Attestations

To maintain the integrity and security of the ecosystem, **issuers** (e.g., identity authorities or financial institutions) and **relying parties** (e.g., merchants, service providers) must ensure that only **certified and trusted wallets** are allowed to participate in sensitive processes like **credential issuance**, **user authentication**, or **stablecoin transactions**.

- **Wallet Instance Attestations** Wallet providers may issue **attestation** describing:

  - **Supported features** – e.g., OIDC4VP compatibility, SD-JWT selective disclosure support.
  - **Compliance levels** – e.g., adherence to **EUDI Wallet** standards or MiCA/TFR requirements.
  - **Security certifications** – e.g., wallet storage being protected by **secure hardware (HSMs, Trusted Execution Environments)** or audits against ISO 27001.
- **Trusted List Validation** Issuers and relying parties verify that:

  1. The wallet instance is listed in the **trusted list** maintained by the ecosystem.
  2. The attestation’s signature or `x5c` certificate chain is **valid and traceable** to a trusted root.
  3. The wallet’s **declared capabilities** match the **requirements for the requested operation** (e.g., ability to sign Key Binding JWTs for stablecoin transactions).
- **Capability-Based Access Control** Wallet attestations allow issuers and verifiers to enforce **access policies**:

  - A wallet without KYC/AML certification cannot initiate a regulated stablecoin transfer.
  - A wallet that does not support selective disclosure may be blocked from presenting sensitive attributes.
- **Example Flow:**

  1. A merchant requests a stablecoin payment with KYC requirements.
  2. The wallet provides a **wallet attestation**, signed by the wallet provider, listing its **compliance status and technical capabilities**.
  3. The merchant validates the attestation against the trusted list to ensure the wallet:
     - Is **certified** by an approved wallet provider.
     - Meets **security and regulatory standards**.
  4. If valid, the wallet is allowed to complete the **OIDC4VP flow** and perform the payment transaction.
- **Benefits:**

  - Protects against **rogue or uncertified wallets** attempting to bypass compliance.
  - Ensures that all participants (wallets, issuers, merchants) adhere to **ecosystem security and privacy requirements**.
  - Facilitates interoperability by providing **machine-readable wallet certifications**.

## Ecosystem Roles and Responsibilities

### Ecosystem Authority

Each ecosystem authority is responsible for maintaining and publishing the trusted list. This
includes:

- Hosting the JSON API endpoint
- Ensuring the list is up-to-date and accurate
- Managing the lifecycle of issuer, verifier, and wallet-provider entries

### Issuers and Verifiers

Issuers and verifiers are responsible for:

- Downloading and caching the trusted list
- Verifying the authenticity and scope of credential-related data
- Relying only on entries validated through the trusted list structure

### Wallets

- Fetch the trusted list from the configured URL
- Parse and validate the list and root certificates or DIDs
- Filter valid issuers/verifiers by supported vcTypes
- Store a local copy with timestamp
- Trigger a refresh if the list is older than 24 hours
- Check and verify the trusted chain or resolve DIDs
- Manage user information and consent

## User Trust Management Strategy

The way in which each party (wallet provider, issuer, verifier) chooses to manage the trust status and presentation of trusted list data to end users is **out of scope** of this specification.

Examples include:

- A **wallet provider** may choose to simply inform the user about the trust status of a verifier and leave the access decision to the user.
- An **issuer** may decide to reject a credential issuance request if the verifier or wallet provider is not listed.
- A **verifier** may enforce access control based on list membership or certificate lineage. These decisions are implementation-specific and should align with each ecosystem's user experience, legal context, and risk posture.

## Certificate Chain Validation

Wallets and verifiers MUST perform standard X.509 path validation using the root certificates listed in the trusted list. Intermediate certificates (e.g., those included via x5c) must be validated up to a trusted root using established PKI rules. If X.509 certificates are not used, wallets MAY use DID-based key for validation.

## Compatibility with Other Standards

This specification is designed independently of the eIDAS Trusted List XML format and similar registries. It does not aim to be interoperable with those formats but instead offers a simplified alternative suitable for lightweight deployments.

## Components

### 1. Trusted List URL

JSON
Each wallet must be configured with a **Trusted List URL** , provided by its backend or ecosystem. This URL should return the list of trusted entities in JSON format. It may be downloaded:

- At first initialization
- Once daily thereafter

### 2. Trusted List API (JSON Format)

Each ecosystem must implement an HTTP(S) endpoint returning the following JSON structure:

```json

{
    "ecosystem": "eu-wallet-network",
    "lastUpdated": "2025-07-15T12:00:00Z",
    "entities": [
        {
            "id": "https://example.com/issuer1",
            "name": "GovID Issuer A",
            "description": "Issuer for testing purpose",
            "endpoint": "https://example.com/issuer1",
            "type": "issuer",
            "postalAddress": {
                "streetAddress": "Piazzale Flaminio 1B",
                "locality": "Rome",
                "postalCode": "00196",
                "countryName": "Italy"
            },
            "rootCertificates": [
                "MIIB..."
            ],
            "electronicAddress": {
                "uri": "mailto:leone.riello@infocert.it",
                "lang": "en"
            },
            "vcTypes": [
                "eu.europa.ec.eudi.pid.1",
                "EmailPass"
            ]
        },
        {
            "id": "did:web:talao.co:example",
            "name": "Talao Issuer",
            "description": "Issuer for testing purpose",
            "endpoint": "https://example.com/issuer2",
            "type": "issuer",
            "postalAddress": {
                "streetAddress": "Piazzale Flaminio 1B",
                "locality": "Rome",
                "postalCode": "00196",
                "countryName": "Italy"
            },
            "rootCertificates": [
                "MIIB..."
            ],
            "electronicAddress": {
                "uri": "mailto:leone.riello@infocert.it",
                "lang": "en"
            },
            "vcTypes": [
                "eu.europa.ec.eudi.pid.1",
                "AMLStatusCredential"
                "EmailPass"
            ]
        },
        {
            "id": "https://example.com/verifier1",
            "name": "KYC Verifier Co",
            "description": "Verifier for testing purpose",
            "type": "verifier",
            "postalAddress": {
                "streetAddress": "Piazzale Flaminio 1B",
                "locality": "Rome",
                "postalCode": "00196",
                "countryName": "Italy"
            },
            "rootCertificates": [
                "MIIC..."
            ],
            "vcTypes": [
                "eu.europa.ec.eudi.pid.1"
            ]
        },
        {
            "id": "https://wallet.example.com/provider",
            "name": "Altme Wallet Provider",
            "description": "Wallet provider for Talao and Altme",
            "type": "wallet-provider",
            "rootCertificates": [
                "MIID..."
            ]
        }
    ]
}
```

### 3. Field Descriptions

- `ecosystem` : REQUIRED. Unique identifier for the issuing ecosystem or trust domain
- `lastUpdated` : REQUIRED. ISO timestamp for the last update
- `entities` : REQUIRED. Array of a json object defining an issuer, a verifier or a wallet-provider.
  - `id` : REQUIRED. URI identifying the organization (URL or DID). It could be the `iss` of an sd-jwt, the subject of an x509 certificate or the `issuer` of a W3C VC. In case of a verifier this is the `client_id` of the OIDC4VP authorization request.
  - `name` : Human-readable name of the entity
  - `description`: Description of the service offered,
  - `endpoint`: For an issuer it is the credential issuer URL. For a verifier this is where the wallet (holder) is redirected to start the presentation flow.
  - `type` : REQUIRED.`issuer`, `verifier`, or `wallet-provider`
  - `postalAddress` : json object. The postalAddress field supports structured location data for better alignment with eIDAS ETSI TS 119 612. It includes:
    - `streetAddress` : Street and civic number
    - `locality` : City or town
    - `postalCod`e : Zip/postal code
    - `countryName` : Country of the entity
  - `electronicAddress` provides a URI (e.g., email or HTTPS address) and an optionallanguage tag.
  - `rootCertificates` : REQUIRED if `id` is not a DID. Array of PEM-formatted X.509 root certificates
  - `vcTypes` : REQUIRED for issuers and verifiers. Array of credential types supported or allowed to request(e.g., PersonIdentityCredential,AMLStatusCredential). It is the `vct` of an SD-JWT VC or `type` of the W3C VC.

## Backend Management Interface

The wallet backend must expose a configuration setting where:

- The **Trusted List URL** can be registered or updated
- Multiple ecosystem URLs can be supported if multi-ecosystem federation is needed

## Error Handling

- If the trusted list cannot be fetched, the wallet should use the last valid cached copy
- If no copy is available, wallet operations requiring verification should be restricted until retrieval is successful

## Security Recommendations

- The trusted list API endpoint must support HTTPS
- Certificates should be validated using standard X.509 verification chains or DID key identifiers
- Ecosystems should rotate keys and certificates periodically and version control updates

## Example Trusted List URL

```
https://talao.co/.well-known/trusted-list.json
```

## Signature Validation of the Trusted List

This level of trust assurance is not currently required in this specification. It is intentionally excluded to maintain simplicity and agility for small to medium-sized ecosystems, where centralized list management is practical and sufficient.

However, ecosystems that require stronger guarantees can optionally use decentralized methods, such as publishing the trusted list on the [cheqd network](https://cheqd.io/) as a [DID Linked Resource](https://w3c-ccg.github.io/did-linked-resources/). This enables cryptographic integrity, public discoverability, and versioning. In such setups, the trusted list can be signed and verified using the public key defined in the ecosystem’s DID Document, providing a decentralized alternative to traditional centralized signing.

## Revocation Mechanism

This specification adopts a **lightweight revocation mechanism** suitable for **small and medium-sized ecosystems**. Rather than implementing complex revocation infrastructures such as CRLs or OCSP, revocation is handled directly through updates to the trusted list. If an issuer or verifier is no longer trusted, the ecosystem authority simply **removes the corresponding entry** from the trusted list JSON. Since wallets refresh the list daily, the entity will automatically be excluded from trust evaluations after the next update.

Benefits

- No need for signature validation or certificate revocation lists
- Immediate enforcement upon list update
- Easy to maintain and monitor using a centralized endpoint

Considerations

- Wallets must refresh the trusted list at least once every 24 hours
- A local cache should be maintained for resilience in offline or degraded network scenarios

## Using cheqd for Trusted List Decentralized Support

[**cheqd**](https://cheqd.io/) is a decentralized identity network purpose-built for managing **trusted data** like Verifiable Credentials and trusted lists.
It enables organizations to create **Decentralized Identifiers (DIDs)** and publish **DID-Linked Resources** with cryptographic proofs, stored on a permissionless, tamper-evident ledger.

Unlike traditional API-based or static-trust models, cheqd brings **version control, public auditability, and decentralized integrity guarantees** to sensitive identity data. This ensures that every trusted list or credential registry remains **verifiable, immutable, and transparently governed** over time. With native support for self-sovereign identity (SSI), cheqd is optimized for ecosystems that demand **scalability, resilience, and zero-trust security by design**.

Storing the trusted list on a Distributed Ledger Technology (DLT) like cheqd means that updates, version history, and authenticity are **cryptographically verifiable** and **accessible without reliance on centralized endpoints**.
By anchoring trust data to a DID, ecosystem participants gain **strong guarantees of origin and control**, even across jurisdictions or infrastructure boundaries.

Changes to the list become transparent and auditable, enabling **real-time trust governance** and rollback in case of compromise.
This architecture enhances **security, resilience, and decentralization** across the full credential lifecycle—from issuance to revocation.
It replaces static, brittle trust models with a dynamic, interoperable foundation for next-generation digital identity systems.

We implement the [**DID Linked Resources**](https://w3c-ccg.github.io/did-linked-resources/) standard to bind trusted lists to a DID in a discoverable and structured way.
Each resource includes metadata (type, version, created date) and is resolvable via standard DID resolution protocols.
This enables wallets, issuers, and verifiers to independently fetch and verify trusted data **on-demand, from a single source of truth**.
The resource itself is signed and stored immutably, providing end-to-end **proof of authenticity and integrity**.
This approach supports **lightweight yet robust trust mechanisms**, enabling decentralized ecosystems to evolve securely at scale.

This guide explains how to:

1. Create a DID on **cheqd**
2. Publish a trusted list as a **DID-Linked Resource** (`TrustRegistry`)
3. Retrieve the trusted list from the DID using **Python**

### Step 1: Create a DID on cheqd (Custodial and Non-Custodial Methods)

The easiest way to create a DID on cheqd is using [cheqd Studio](https://docs.cheqd.io/product/studio/dids/create-did), a hosted API platform that manages cryptographic keys for you (custodial model).
This method is ideal for quick testing or integration scenarios where managing keys externally is not required.

If you prefer a **non-custodial approach**, where **you retain full control of your private keys**, several tools and SDKs are available:

- **[`cheqd-noded` CLI](https://docs.cheqd.io/node/operate/cli/cli-commands#create-did)**: Offers low-level control and lets you broadcast transactions directly to the cheqd network. You can generate key pairs locally and submit DID creation and resource transactions manually via the CLI.
- **[cheqd DID Registrar](https://docs.cheqd.io/product/registrar)**: A hosted API that supports non-custodial DID creation by allowing you to bring your own keys while using a RESTful interface.
- **[Veramo SDK](https://docs.cheqd.io/product/sdk/veramo)**: A JavaScript/TypeScript SDK for working with DIDs, credentials, and resources on cheqd.
- **[Credo SDK](https://docs.cheqd.io/product/sdk/credo)**: A Rust-based SDK designed for embedded and performant applications.
- **[ACA-Py integration](https://docs.cheqd.io/product/sdk/aca-py)**: For Hyperledger Aries environments, ACA-Py provides native support for cheqd-based DID management.

For more details on SDKs and tools that support DID creation and DID-Linked Resources (DLRs), refer to the cheqd [Understanding SDKs documentation](https://docs.cheqd.io/product/sdk/understanding-sdks).

These options enable developers to integrate DID management into a wide range of environments, from CLI-based workflows to full backend or agent-based architectures, while maintaining ownership and control of cryptographic keys.

Below is the Python example using cheqd Studio's custodial API:

```python
import requests
import base64

API_KEY = "your_cheqd_studio_api_key"
BASE_URL = "https://studio-api.cheqd.net"
HEADERS = {
    "x-api-key": API_KEY,
    "Content-Type": "application/json"
}

def create_did():
    payload = {
        "network": "testnet",              # or "mainnet"
        "identifierFormatType": "uuid",
        "verificationMethodType": "Ed25519VerificationKey2018"
    }
    response = requests.post(f"{BASE_URL}/did/create", headers=HEADERS, json=payload)
    response.raise_for_status()
    data = response.json()
    print("DID created:", data["did"])
    return data["did"]
```

### Step 2: Publish Trusted List as DID-Linked Resource

```python

def create_trust_registry_resource(did, file_path):
    with open(file_path, "rb") as f:
        content = f.read()
    b64_encoded = base64.urlsafe_b64encode(content).decode("utf-8")

    payload = {
        "data": b64_encoded,
        "encoding": "base64url",
        "name": "trusted-issuers-list",
        "type": "TrustRegistry",
        "version": "1.0.0"
    }

    url = f"{BASE_URL}/resource/create/{did}"
    response = requests.post(url, headers=HEADERS, json=payload)
    response.raise_for_status()
    res = response.json()
    print("DID-Linked Resource created:", res)
    return res
```

### Step 3: Retrieve the Trusted List

There are **multiple ways** to retrieve the trusted list associated with a DID on cheqd. Each method offers flexibility depending on how your system interacts with the DID infrastructure:

#### 1. Dereference the Resource URI Directly

If you already know the `resourceURI`—for instance, from prior registration, metadata, or a signed reference in a Verifiable Credential (VC)—you can retrieve the corresponding Trusted List resource from a DID on the cheqd network using a resolver:

[https://resolver.cheqd.net/1.0/identifiers/did:cheqd:testnet:6c905d9a-7e54-48cc-bee2-c093d621d24e/resources/9d996363-9a7f-48b2-85b3-0bea01c32615]()

This method is simple and ideal for static or well-known resource references.

#### 2. Dereference by Query Parameters

For instance if you don’t know the resource ID but want to retrieve **all resources of a given type** (e.g. `TrustRegistry`), you can query a DID with a `resourceType` parameter, as defined in [ADR-005](https://docs.cheqd.io/product/architecture/adr-list/adr-005-did-resolution-and-did-url-dereferencing):

[https://resolver.cheqd.net/1.0/identifiers/did:cheqd:testnet:did-uuid?resourceType=TrustRegistry]()

This is useful when:

- You want to dynamically discover the **latest** or **historic** trusted lists
- You need to validate a VC based on the list **active at issuance time**
- You want to support **lightweight list rotation** without needing new resource IDs

Because resources contain timestamps and versioning, wallets and verifiers can identify the correct list for time-based trust validation.

#### 3. Use the cheqd Studio API (Custodial Method)

If you used [cheqd Studio](https://docs.cheqd.io/product/studio/resources/create-resource) to publish your resource, you can fetch it securely with your API key:

```
GET https://studio-api.cheqd.net/resource/{did}/{resource_id}
Headers: x-api-key: YOUR_API_KEY
```

This is suitable for backend environments where API key management is acceptable.

#### 4. Use DID Resolution + linkedResourceMetadata (Standard Method)

The most interoperable and decentralized approach is to resolve the DID and inspect its metadata for linked resources of type `TrustRegistry`.

```python
import requests

def get_latest_trust_registry(did):
    resolvers = [
        "https://resolver.cheqd.net/1.0/identifiers/",
        "https://dev.uniresolver.io/1.0/identifiers/"
    ]

    for base in resolvers:
        try:
            r = requests.get(base + did, timeout=10)
            if r.status_code == 200:
                print(f"Resolved using: {base}")
                break
        except Exception:
            continue
    else:
        print("DID resolution failed.")
        return

    data = r.json()
    resources = data.get("didDocumentMetadata", {}).get("linkedResourceMetadata", [])
    trust_resources = [res for res in resources if res.get("resourceType") == "TrustRegistry"]

    if not trust_resources:
        print("No TrustRegistry resource found.")
        return

    latest = trust_resources[-1]
    resource_uri = latest.get("resourceURI")

    if not resource_uri:
        print("No resource URI found.")
        return

    full_url = base + resource_uri
    res_data = requests.get(full_url).json()
    print("Fetched trusted list:", res_data)
    return res_data
```

This approach works across **any resolver that supports DID Linked Resources**, and provides built-in discoverability, version tracking, and integrity assurance.

### Summary

With this approach:

- Your **trusted list** becomes a decentralized, verifiable asset
- **DIDs** provide identity assurance
- **cheqd's resource module** supports versioning, integrity, and public retrieval

## Security Threat Modeling

This section outlines potential threats to the trusted list mechanism, their impact, and possible mitigations. Some of these recommendations extend beyond the current scope of this specification but are valuable for future-proofing the ecosystem.

In particular, the use of decentralized infrastructure such as the [cheqd network](https://cheqd.io/) can significantly reduce risks related to data tampering, impersonation, and single points of failure. By anchoring the trusted list to a Decentralized Identifier (DID) and publishing it as a [DID Linked Resource](https://w3c-ccg.github.io/did-linked-resources/), ecosystems gain:

- **Tamper-evidence through blockchain anchoring**
- **Cryptographic verification of resource integrity and authorship**
- **Decentralized access via public resolvers (e.g., `https://resolver.cheqd.net/`)**
- **Version control and public audit trails for all updates**

This adds a resilient, standards-based layer of trust to any trusted list distribution mechanism and complements existing approaches like TLS, DNSSEC, or API access.

### 1. Threats Against Trusted List Integrity

- **Tampering with the Trusted List***Threat:* An attacker could modify the list during transit or at rest, injecting unauthorized entities.*Mitigation:*

  - Sign the trusted list with a **JWS (JSON Web Signature)** or CMS signature.
  - Distribute only over **TLS 1.3** with strict server authentication (e.g., certificate pinning).
  - **Publish the trusted list on a DLT like cheqd** using **DID Linked Resources**, ensuring tamper-evident access and cryptographic verifiability.
- **Fake Trusted List (Endpoint Impersonation)** *Threat:* A malicious endpoint could serve a fake trusted list.*Mitigation:*

  - Use **DNSSEC** and **HTTPS with CA-pinned certificates**.
  - Hardcode the root signing key fingerprints in wallets.
  - **Resolve the trusted list from the DID using decentralized DID resolvers**, such as `https://resolver.cheqd.net`.

### 2. Threats Against Authenticity and Authorization

- **Malicious Entity Insertion** *Threat:* A compromised backend might add fake issuers or merchants to the list.*Mitigation:*

  - Require **multi-signature approvals** for list updates.
  - Use a **public transparency log** (e.g., Merkle-tree-based, like Certificate Transparency).
  - **Track resource history using cheqd’s versioned DID Linked Resources.**
- **Key Compromise of Authority** *Threat:* If the ecosystem authority’s root signing key is compromised, the entire trust model collapses.*Mitigation:*

  - Use **Hardware Security Modules (HSMs)** to store signing keys.
  - Implement **key rotation** and backup secondary signing keys.
  - **Update the verification method in the DID Document** and re-publish the trusted list with a new key using cheqd.

By anchoring the trusted list to a **DID on cheqd**, ecosystems gain **cryptographic assurance**, **auditability**, and **resilience**, ensuring the trust model holds even under adversarial conditions.
