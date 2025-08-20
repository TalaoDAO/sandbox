# SSI parameters

Updated the 15th of October 2024.

This section allows an advanced user to specify the SSI profile of the wallets.

## Choose an SSI Profile or configure your own

This option allows to select a predefined ecosystem profiles or to define his own profiles through the tuning of parameters. Here is below the main features of the predefined profiles:


| Profiles  | VC format              | OIDC4VCI | DID     | Key   |
| :---------- | ------------------------ | ---------- | :-------- | ------- |
| Default   | ldp_vc                 | 11       | did:key | EdDSA |
| EBSI V3.x | jwt_vc                 | 11       | did:key | P-256 |
| EBSI V4.0 | jwt_vc_json, sd-jwt vc | 13       | did:key | P-256 |
| DIIP V2.1 | jwt_vc_json            | 13       | did:jwk | P-256 |
| DIIP V3.0 | sd-jwt vc              | 13       | did:jwk | P-256 |

If admin chooses to define its own SSI profile, he must set the following options:

## Wallet identifier

it can be any one of the DID methods of the list ([did:key](https://w3c-ccg.github.io/did-method-key/), [did:jwk](https://github.com/quartzjer/did-jwk/blob/main/spec.md)) associated to one of the types of keys available (EdDSA, P-256 or seck256k1). For EBSI the did:key method is specific, see specification [here](https://hub.ebsi.eu/vc-framework/did/natural-person).

* jwk thumbprint P-256,
* did:key with EdDSA key,
* did:key with EBSI encoding and P-256 key,
* did:key with secp256k1 key,
* did:key with P-256 key,
* did:jwk with P-256 key

In case of the HAIP / EUDI Architecture Reference Framework - ARF, choose the `jwk thumbprint` option as the wallet identifier.

### OID4VCI Client Type

The client type affects how the wallet authenticates and interacts with the authorization server during credential issuance.

* **did:** Decentralized Identifier, typically used for secure, decentralized identity interactions,
* **jwk thumbprint** used when the subject is identified via a jwk,
* **confidential:** for confidential clients that require secure and private interaction with the authorization server.

In case of the HAIP / EUDI Architecture Reference Framework - ARF, choose the `jwk thumbprint` option.

### Cryptographic Holder Binding

* **Yes (default):** Keeps cryptographic binding enabled, ensuring that credentials are cryptographically tied to the holder, providing higher security,
* **No:** Disables cryptographic binding, allowing credentials to be bound without cryptographic proofs for claim binding for instance.

In case of the EUDI Architecture Reference Framework - ARF, choose the `Yes` option.

Learn more about crypto binding [here](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-claims-based-binding-of-the).

### Scope parameters

Scope parameters define the issuer metadata identifier of the credential inside the authorization request. If scope is not used, wallet will use an authorization details object.

Enabling scope parameters provides more granular control over the credential issuance process.

In case of the HAIP / EUDI Architecture Reference Framework - ARF, choose the `scope` option.

Learn more about scope [here](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-using-scope-parameter-to-re).

### Client Authentication Method

Select one authentication method among the following ones:

* **None:** No authentication required.
* **Client ID:** Identifies the client with a unique ID.
* **Client Secret Basic:** Sends ID and secret in the HTTP header.
* **Client Secret Post:** Sends ID and secret in the request body.
* **Wallet Attestation:** Proves authenticity via attestation.

In case of the HAIP / EUDI Architecture Reference Framework - ARF, choose the `wallet attestation` option.

Learn more about authentication method [here](https://www.rfc-editor.org/rfc/rfc6749#section-2.3).

### Choosing a VC Format

Select the VC format:

* **ldp_vc:** W3C verifiable credentials using Linked Data Proofs.
* **jwt_vc:** EBSI compatible credentials in JWT format.
* **jwt_vc_json:** Structured JSON format with JWT flexibility.
* **jwt_vc_json-ld:** Linked data support with JWT.
* **vc+sd-jwt:** Selective disclosure for privacy in JWTs.
* **auto:** Wallet will select the format depending on issuer metadata.

**auto** means the wallet displays all VCs whatever the format.

In case of the HAIP / EUDI Architecture Reference Framework - ARF, choose the `vc+sd-jwt` option.

Learn more about VC format [here](https://www.w3.org/TR/vc-data-model/).

### OIDC4VCI Proof Type

The proof type determines how the wallet proves its key ownership when presenting credentials.

* **jwt:** Uses JWT to prove key ownership.
* **ldp_vp:** Verifiable Presentation with linkedin data proof.

In case of the HAIP / EUDI Architecture Reference Framework - ARF, choose the `jwt` option.

Learn more about proof type [here](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-proof-types).

### Proof of Possession Headers

This setting determines what data to include in the header of the JWT proof type.

* **kid:** Key ID, used to identify the key in the proof of possession.
* **jwk:** JSON Web Key, representing the key in a structured format for proof of possession.

In case of the HAIP / EUDI Architecture Reference Framework - ARF, choose the `jwk` option.

### Push Authorization Request (PAR)

PAR is an advanced feature that enhances security during the authorization process by ensuring the integrity of the request.

* **Yes:** Push authorization requests to the server,
* **No:** Uses traditional redirect for authorization requests.

In case of the HAIP / EUDI Architecture Reference Framework - ARF, choose the `Yes` option.

Learn more about PAR [here](https://datatracker.ietf.org/doc/html/rfc9126).

### Status List Cache

The Status List cache duration controls how long the wallet stores status lists used to verify credentials (e.g., revoked or valid). Adjusting this duration can balance performance with up-to-date information.
