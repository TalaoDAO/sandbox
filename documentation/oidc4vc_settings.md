# OIDC4VC parameters

Updated the 12th of December 2024.

To access the OIDC4VCI parameters:

1. Go to "Settings"
2. Choose profile "Custom",
3. Select the options you want to setup

This section allows an advanced user to specify manually the ecosystem technical options of his wallet.

More parameters are available through the Wallet Provider Backend. This feature can be hidden in case of a specific wallet configuration defined with the Wallet Provider Backend.

## Wallet Level

Wallet Security Level can be low (default) or strict.

If low security, wallet does not check the signature of the :

* verifiable credentials,
* status list credential,
* authorization request object (OIDC4VP)

## Default DID

it can be any one of the DID methods of the list ([did:key](https://w3c-ccg.github.io/did-method-key/), [did:jwk](https://github.com/quartzjer/did-jwk/blob/main/spec.md)) associated to one of the types of keys available (EdDSA, P-256 or seck256k1). For EBSI the did:key method is specific, see specification [here](https://hub.ebsi.eu/vc-framework/did/natural-person).

* did:key with EdDSA key,
* did:key with secp256k1 key,
* did:key with P-256 key,
* did:key with EBSI encoding and P-256 key,
* did:jwk with P-256 key

### OIDC4VCI

The OIDC4VCI draft release. For EBSI V3.x must be Draft 11.
Draft 14 is partially supported : nonce endpoint is supported for build 2.18.8 and above. In this case the wallet will call the nonce endpoint to get a nonce for the proof of key ownership and will not use the nonce provided by the token endpoint if any.

### Cryptographic Holder Binding

* **Yes (default):** Keeps cryptographic binding enabled, ensuring that credentials are cryptographically tied to the holder, providing higher security,
* **No:** Disables cryptographic binding, allowing credentials to be bound without cryptographic proofs for claim binding for instance.

Learn more about crypto binding [here](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-claims-based-binding-of-the).

### Scope parameters

Scope parameters define the specific scope of the credential inside the authorization request request. If scope is not used, wallet will use an authorization details object.

Learn more about scope [here](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-using-scope-parameter-to-re).

### Client Authentication Method

Select one authentication method among the following ones:

* **none:** No authentication required,
* **client_secret_basic:** Sends ID and secret in the HTTP header,
* **client_secret_post:** Sends ID and secret in the request body,
* **client_id:** Identifies the client with a unique ID.

Learn more about authentication method [here](https://www.rfc-editor.org/rfc/rfc6749#section-2.3). These client authentication methods allow pre-registered wallet. Choose "none" otherwise.

### Wallet Client_id scheme

The client type affects how the wallet authenticates and interacts with the authorization server during credential issuance.

* **DID:** Decentralized Identifier, typically used for secure, decentralized identity interactions,
* **P-256 JWK Thumbprint** Used when the subject is identified via a jwk thumbprint,
* **Pre-registered client:** Used for secure or private interaction with the authorization server.

### VC Format

Select the VC format:

* **ldp_vc:** W3C verifiable credentials using linked data proofs.
* **jwt_vc:** EBSI compatible credentials in jwt format.
* **jwt_vc_json:** Structured JSON format with jwt flexibility.
* **jwt_vc_json-ld:** Linked data support with jwt.
* **vc+sd-jwt:** Selective disclosure for privacy.

Learn more about VC format [here](https://www.w3.org/TR/vc-data-model/).

### OIDC4VCI Proof Type

The proof type determines how the wallet proves its key ownership when presenting credentials.

* **ldp_vp:** Verifiable Presentation with linkedin data proof,
* **jwt:** Uses JWT to prove key ownership..

Learn more about proof type [here](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-proof-types).

### Proof of Possession Headers

This setting determines what data to include in the header of the JWT proof type.

* **kid:** Key ID, used to identify the key in the proof of possession.
* **jwk:** JSON Web Key, representing the key in a structured format for proof of possession.

Learn more about proof of possession headers [here](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-proof-types).

### Push Authorization Request (PAR)

PAR is an advanced feature that enhances security during the authorization process by ensuring the integrity of the request.

* **Yes:** Push authorization requests to the server,
* **No:** Uses traditional redirect for authorization requests.

Learn more about PAR [here](https://datatracker.ietf.org/doc/html/rfc9126).

### StatusList caching

The Status List cache duration controls how long the wallet stores status lists used to verify credentials (e.g., revoked or valid). Adjusting this duration can balance performance with up-to-date information.

### Demonstrating Proof of Possession (DPoP)

This is the IETF RFC 9449 : which "... describes a mechanism for sender-constraining OAuth 2.0 tokens via a proof-of-possession mechanism on the application level. This mechanism allows for the detection of replay attacks with access and refresh tokens.
