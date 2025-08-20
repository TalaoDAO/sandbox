# Wallet Metadata

Updated the 8th of March 2025.

Metadata in the context of digital wallets like Talao and Altme describes the specific configurations that define the wallet’s compatibility, supported formats, cryptographic algorithms, and available features. They are crucial for setting up and integrating wallets for credential issuance and verification..

### Issuance : Wallet acts as a client for an issuer

Wallet endpoints start either with https://app.talao.co/xxxx for Talao wallet or with https://app.altme.io/xxx for Altme wallet.

Below metadata is for Talao wallet:

```json
{
    "vp_formats_supported":{
        "jwt_vp":{
            "alg":[
                "ES256",
                "ES256K",
                "EdDSA"
            ]
        },
        "jwt_vc":{
            "alg":[
                "ES256",
                "ES256K",
                "EdDSA"
            ]
        },
        "jwt_vp_json":{
            "alg":[
                "ES256",
                "ES256K",
                "EdDSA"
            ]
        },
        "jwt_vc_json":{
            "alg":[
                "ES256",
                "ES256K",
                "EdDSA"
            ]
        },
        "vc+sd-jwt":{
            "alg":[
                "ES256",
                "ES256K",
                "EdDSA"
            ]
        },
        "ldp_vp": {
            "proof_type": [
                "JsonWebSignature2020",
                "Ed25519Signature2018",
                "Ed25519Signature2020",
                "EcdsaSecp256k1Signature2019",
                "RsaSignature2018"
            ]
        },
        "ldp_vc": {
            "proof_type": [
                "JsonWebSignature2020",
                "Ed25519Signature2018",
                "Ed25519Signature2020",
                "EcdsaSecp256k1Signature2019",
                "RsaSignature2018"
            ]
        }
    },
    "grant_types": [
        "authorization code",
        "pre-authorized_code"
    ],
    "redirect_uris" [
        "https://app.talao.co/app/download/callback"
    ],
    "subject_syntax_types_supported": [
        "did:key",
        "did:jwk"
    ],
    "subject_syntax_types_discriminations": [
        "did:key:jwk_jcs-pub",
        "did:ebsi:v1"
    ],
    "response_types_supported":[
        "vp_token",
        "id_token"
    ],
    "token_endpoint_auth_method_supported": [
        "none",
        "client_id",
        "client_secret_post",
        "client_secret_basic",
        "client_secret_jwt"
    ],
    "credential_offer_endpoint_supported": [
        "openid-credential-offer://",
        "talao-openid-credential-offer://",
        "haip://",
        "https://app.talao.co/app/download/oidc4vc"
    ],
    "contacts": [
        "contact@talao.io"
    ]
}
```

### Verification: wallet acts as an Authorization Server for a verifier

Wallet endpoints start either with https://app.talao.co/xxxx for Talao wallet or with https://app.altme.io/xxx for Altme wallet.

Learn more about wallet metada [here](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-wallet-metadata-authorizati).

Below metadata is for Talao wallet:

```json
{
    "issuer": "https://app.talao.co/wallet-issuer",
    "wallet_name": "talao_wallet",
    "key_type": "software",
    "user_authentication": "system_biometry",
    "authorization_endpoint": "https://app.talao.co/app/download/authorize",
    "vp_formats_supported": {
        "jwt_vc_json": {
            "alg_values_supported": [
                "ES256",
                "ES256K",
                "EdDSA"
            ]
        },
        "jwt_vp_json": {
            "alg_values_supported": [
                "ES256",
                "ES256K",
                "EdDSA"
            ]
        },
        "jwt_vc_json-ld": {
            "alg_values_supported": [
                "ES256",
                "ES256K",
                "EdDSA"
            ]
        },
        "jwt_vp_json-ld": {
            "alg_values_supported": [
                "ES256",
                "ES256K",
                "EdDSA"
            ]
        },
        "vc+sd-jwt": {
            "alg_values_supported": [
                "ES256",
                "ES256K",
                "EdDSA"
            ]
        },
        "ldp_vp": {
            "proof_type": [
                "Ed25519Signature2018",
                "Ed25519Signature2020",
                "EcdsaSecp256k1Signature2019",
                "RsaSignature2018"
            ]
        },
        "ldp_vc": {
            "proof_type": [
                "Ed25519Signature2018",
                "Ed25519Signature2020",
                "EcdsaSecp256k1Signature2019",
                "RsaSignature2018"
            ]
        }
    },
    "id_token_types_supported": [
        "subject_signed_id_token"
    ],
    "client_id_schemes_supported":[
        "pre-registered",
        "did",
        "redirect_uri",
        "x509_san_dns",
        "verifier_attestation"
    ],
    "subject_syntax_types_supported":[
        "urn:ietf:params:oauth:jwk-thumbprint",
        "did:key",
        "did:jwk"
    ],
    "id_token_signing_alg_values_supported": [
        "ES256",
        "ES256K",
        "EdDSA"
    ],
    "request_object_signing_alg_values_supported": [
        "ES256",
        "ES256K",
        "EdDSA"
    ],
    "presentation_definition_uri_supported": true,
    "contacts": [
        "contact@talao.io"
    ]
}


```
