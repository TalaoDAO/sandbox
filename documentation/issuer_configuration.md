# Issuer configuration

Updated the 6th of July 2025.

The wallets support most of the VC options of the OIDC4VCI standard for issuer configuration.

## OIDC4VCI Specifications Drafts

OIDC4VCI has evolved rapidly between 2022 (Draft 10/11) and 2025 (Draft >= 15). The issuer metadata has changed multiple times. Right now wallets support Draft 10/11 and Draft 13 of the specifications. The selection of one Draft or another can be done manually in the wallet with the custom profile and the OIDCVC settings screen or through the wallet provider backend.

**EBSI V3.x is based on OIDC4VCI Draft 10**, DIIP V2.1, DIIP V3.0 uses Draft 13.

Specifications of the different Drafts are available here:

* [Draft 10/11](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-10.html) supported for EBSI V 3.x
* [Implementer Draft 1.0 (Draft 13)](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-ID1.html) supported
* [Draft 14](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-14.html) partially supported
    - nonce endpoint
* [Implementer Draft 2.0 (Draft 15)](https://openid.github.io/OpenID4VCI/openid-4-verifiable-credential-issuance-wg-draft.html) partially supported
    - dc+sd-jwt
    - json pointer for issuer metadata
    - credential response format

## OIDC4VCI flow and features

Wallets support:

* VC format ldp_vc, jwt_vc, jwt_vc_json, jwt_vc_json-ld, vc+sd-jwt,
* [VCDM 1.1](https://www.w3.org/TR/vc-data-model/),
* credential offer by value and by reference,
* pre authorized code (by default), authorized code flow, push authorization request, PKCE,
* [Attestation based client authentication](https://datatracker.ietf.org/doc/draft-ietf-oauth-attestation-based-client-auth/),
* `tx_code` with`input_mode` `text`or`numeric`, `lenght`and`description`,
* `authorization_details` and `scope`. Tune with OIDCVC settings or wallet provider backend to use `scope`.,
* authorization server as a standalone server associated to one VC type,
* dynamic credential request,
* client secret post, client secret basic and public client and anonymous authentication,
* bearer credential (no crypto binding),
* proof types as `jwt` or `ldp_vp`,
* proof of possession header with `kid` or `jwk`,
* deferred endpoint,
* [DPoP RFC 9449](https://datatracker.ietf.org/doc/html/rfc9449)
* nonce endpoint (Draft 14),
* key identifiers as jwk thumbprint of DID,
* keys as EdDSA, P-256, seckp256k1,
* All standards DID methods are supported for issuers and verifiers through a dedicated Universal Resolver. The EBSI APIs V5 are currently used for EBSI issuers.
* [Bitstring Status List V1.0](https://www.w3.org/TR/vc-bitstring-status-list/),
* [IETF Token Status List Draft 6](https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-06.html)

Wallets do not support:

* notification endpoint,
* batch endpoint of Draft 13,
* VCDM 2.0.

## Limitations due to VC formats

### JSON-LD VC (ldp_vc)

For linked data proof within the wallets only **did:key** and **did:jwk** DID method are supported with P-256. EdDSA keys is only available with **did:key**.

Wallets supports remote @context loading.

## Invocation schemes for issuance

Wallet support different invocation schemes:

* openid-credential-offer://,
* talao-openid-credential-offer:// or altme-openid-credential-offer://,
* haip://

Those schemes can be displayed as QR code for wallet app scanner, smartphone camera or as a deeplink / universal link (a button in a html page for the smartphone browser).

# Support of Universal Links and App Links

For security reasons Talao wallets use Universal Links and App Links to redirect to wallet authorization endpoints and callback endpoints. However those links are not supported by default by all browsers.

We suggest to use **Safari for IOS** phones and **Chrome for Android**. You may need to setup browser options manually to allow Universal links or App Links with Firefox, Brave, Samsung explorer or even Chrome on IOS.

On Android phones last testing in Feb 2025 show that Firefox and Brave work correctly but Samsung Internet does not.

## Dynamic Credential Request

Dynamic Credential Request is an option to operate a VP presentation for user authentication inside an authorization code flow.

The main difference between this process and the use of a VP authentication step (OIDC4VP) followed by the issuance of a VC by pre authorized code flow (OIDC4VCI) is that the VP(s) requested by the verifier for user authentication maybe adapted dynamically to the user identity and the VC requested,

In order to manage that combination wallet must provide its own authorization endpoint to the issuer. Our wallets support the `client_metadata` attribute when OIDC4VCI Draft is below or equal to 11 and the `wallet_issuer` attribute for more recent Draft, both added to the authorization request and push authorization request.

Example of client_metadata:

```json
{
    "authorization_endpoint":"https://app.altme.io/app/download/authorize",
    "scopes_supported":[
        "openid"
    ],
    "response_types_supported":[
        "vp_token","id_token"
    ],
    "client_id_schemes_supported":[
        "redirect_uri","did"
    ],
    "grant_types_supported":......
}

```

Here is a script of the issuance of a VC in using another VC as a mean of authentication:

1. Wallet makes an authorization request to the AS of the issuer through a QRcode or a deeplink. The `client_metadata` attribute (or wallet_issuer attribute) is added to the request aside the standard `redirect_uri` endpoint of the wallet. For this step the wallet opens a browser session and redirects the user agent to the AS authorization endpoint.
2. To process the authentication step, the issuer fetches the wallet authorization endpoint from the `client_metadata` and prepares a VP request with its own `reponse_uri` endpoint like a verifier. The VP request is sent as a redirect to the wallet authorization endpoint. For implementation issuer can add the `state` attribute to the VP request to link the request to the original wallet request.
3. Wallet selects the VP requested and transfers is through a POST to the `response_uri` endpoint provided in the VP request. The state is added to the `vp_token` and `presentation_submission`.
4. Issuer acting as a verifier validates the VP data needed to prepare the VC and redirects the user agent to the `redirect_uri` endpoint of the wallet with the `code`. For implementation the `state` can be associated to the `code`.
5. Wallet requests an `access_token` in exchange of the `code`. For implementation the `code` can be associated to the `access_token`.
6. Wallet requests the credential with the access token.

In case of the use of the `wallet_issuer` attribute, issuer must discover the wallet authorization endpoint through the standard `/.well-known/openid-configuration` endpoint:

* Talao: [https://app.talao.co/wallet-issuer/.well-known/openid-configuration](https://app.talao.co/wallet-issuer/.well-known/openid-configuration)
* Altme: [https://app.altme.io/wallet-issuer/.well-known/openid-configuration](https://app.altme.io/wallet-issuer/.well-known/openid-configuration)

Learn more about [Dynamic Credential Request](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-dynamic-credential-request).

## Wallet rendering - display credentials

### Attributes of a VC

Wallet support all the attributes of the display.

```json
"credential_configurations_supported": {
    "IBANLegalPerson": {
        "scope": "IBANLegalPerson_scope",
        "display": [
            {
                "name": "Company IBAN",
                "description": "IBAN",
                "text_color": "#FBFBFB",
                "text_color": "#FFFFFF",
                "logo": {
                    "uri": "https://i.ibb.co/ZdVm5Bg/abn-logo.png",
                    "alt_text": "ABN Amro logo"
                },
                "background_image": {
                    "uri": "https://i.ibb.co/kcb9XQ4/abncard-iban-lp.png",
                    "alt_text": "ABN Amro Card"
                }
            }
        ],
        ......
    }
}
```

The `uri` can be either a link or a data uri scheme. `text_color` and `background_color` are fallbacks options if links are not provided.

`name` is used as the VC name if there is no background image.

If `display` is not provided wallets use a fallback blue card with white text color.

### Attributes of a claim

Wallets show only but all claims that are in the issuer metadata, rules are:

* if there is a` display` attribute in the claim, wallet displays the label in bold with the claim value on the same line. Otherwise wallet displays the claim value alone,
* if the claim is a json object (nested claims) without `display` -> it goes to the line and indent,
* if the claim is a json object with a `display` -> it displays the label in bold and goes to the line and indent.

With this issuer metadata:

```json
"claims": {
    "given_name": {
        "display": [
            {
                "name": "Given Name",
                "locale": "en-US"
            }
        ]
    },
    "family_name": {
        "display": [
            {
                "name": "Surname",
                "locale": "en-US"
            }
        ]
    },
    "email": {},
    "phone_number": {},
    "address": {
        "street_address": {},
        "locality": {},
        "region": {},
        "country": {}
    },
    "birthdate": {},
    "is_over_18": {},
    "is_over_21": {},
    "is_over_65": {}
}
```

wallets rendering will be:

```
Given name: John
Surname: DOE
john.doe@gmail.com
+33678876876
13 rue de Paris
Paris
Paris
France
12/09/1990
True
True
False
```

Wallets support all attributes of the display :

```json
"claims": {
    "given_name": {
    "value_type": "string",
    "display": [
        {
            "name": "First Name",
            "locale": "en-US"
        },
   
```

`value_type` supported are:

* `string`,
* `integer`,
* `bool`,
* `email`,
* `uri`,
* `image/jpeg` , `image/png`

`email` and `uri` are active as you can launch the browser or open the smartphone email manager with a clic.

`order` is supported

`mandatory` in not supported.

## Nested json

Nested json can be implemented and each level displayed with its own label, language, etc.

Example of the issuer metadata of an address claim:

```json
 "address": {
    "mandatory": True,
    "value_type": "string",
    "display": [
        {"name": "Address", "locale": "en-US"},
        {"name": "Adresse", "locale": "fr-FR"}
    ],
    "formatted": {
        "mandatory": True,
        "value_type": "string",
        "display": [
            {"name": "Formatted", "locale": "en-US"},
            {"name": "Complete", "locale": "fr-FR"}
        ],
    },
    "street_address": {
        "mandatory": True,
        "value_type": "string",
        "display": [
            {"name": "Street address", "locale": "en-US"},
            {"name": "Rue", "locale": "fr-FR"}
        ],
    }
 }

```

## Locale

Locale language is chosen depending on the smartphone language. If the smartphone language translation is not provided with the claim, wallet will use locale. If locale is not provided in the issuer metadata, wallet will use english.

```json
"issuing_country": {
    "mandatory": true,
    "value_type": "string",
    "display": [
        {
            "name": "Issuing country",
        },
        {
            "name": "Issuing country",
            "locale": "en-US"
        },
        {
            "name": "Pays d'emission",
            "locale": "fr-FR"
        }
    ]
}
```

### Images

Use the value_type `image/jpeg` or `image/png`. If claim is `face` or `portrait` or `picture`, the image is displayed instead of the card.

Image can be provided as value or reference in the VC.

Example of VC image claim as value:

```json
{
"picture": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAUAAAAFCAYAAACNbyblAAAAHElEQVQI12P4//8/w38GIAXDIBKE0DHxgljNBAAO9TXL0Y4OHwAAAABJRU5ErkJggg=="
}

```

Example in issuer metadata

```json
"picture": {
    "mandatory": True,
    "value_type": "image/jpeg",
    "display": [
        {
            "name": "Picture",
            "locale": "en-US"
        },
        {
            "name": "Portrait",
            "locale": "fr-FR"}],
        },
```

## Type metadata of SD-JWT VC

Wallet does not support the [type metadata](https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-05.html#name-type-metadata) of the sd-jwt VC IETF standard.

## VC Status list support

Wallets support the following specifications depending on the VC format:

* ldp_vc, jwt_vc, jwt_vc_json, jwt_vc_json-l : [Bitstring Status List V1.0](https://www.w3.org/TR/vc-bitstring-status-list/)
* sd-jwt-vc : [Token Status List](https://datatracker.ietf.org/doc/draft-ietf-oauth-status-list/)

When the VC is received from the issuer or displayed, the wallet verifies the signature of the VC, the signature of the status list and the status of the VC. If any of these checked fails teh wallet display a red card status. These verification steps can by passed with an option in the wallet provider backed through a security low profile.

## Issuers integration

Wallets have been tested through different project implementations and interoperability events with most of the APIs and libs providers of the market. See below compatibility list with the date of the last tests.

* **Lissi** : OK on March 2025. The Lissi APIs support only sd-jwt VCs with JWK as wallet identifier and JWK in the proof of key. You will need to setup those parameters in the wallet through the custom profile or through the Wallet Provider backend. Contact us if needed.
* **Procivis**: OK on March 2025
* **Sphereon:** OK on Jan 2024
* **Authlete**: OK on March 2025, see below details
* **WaltId**: OK on March 2025, see below details
* **Meeco**: OK on Jan 2024
* **SICPA**: OK on March 2025
* **Netcetera**: OK on May 2024
* **Mosip Inji Certifier**: Ok on March 2025

## Waltid issuer integration

All `issuer.{..}`, `expirationDate`, `issuanceDate`and `credentialSubject.id` claims must be removed from the credential data as they are already provided in the json_jwt_vc as `iss`, `sub`, `iat`. Here is a correct configuration needed to make the waltid example running :

```json
{
    "issuerKey": {
        "type": "jwk",
        "jwk": {
        "kty": "EC",
        "d": "uTIT47GfSlRa0Da4CsyoIZpjjwQLFxmL2qmBuzZpEy0",
        "crv": "P-256",
        "kid": "FsHUZY4_tDJDvxdp5B6moS1kwpP7PBekw4KfK7m0LCU",
        "x": "keR9l4u1SaZKMZ7wHvj_3z44vP0sa3nlzrnc8UjpQV0",
        "y": "pmcaedg5dtc2R6ZPZfWCBY56_M_5fUZgsz4LWD0mG8U"
    }
    },
    "credentialConfigurationId": "UniversityDegree_jwt_vc_json",
    "credentialData":{
        "@context": [
            "https://www.w3.org/2018/credentials/v1",
            "https://www.w3.org/2018/credentials/examples/v1"
        ],
        "type": [
            "VerifiableCredential",
            "UniversityDegreeCredential"
        ],
        "credentialSubject": {
            "degree":{
                "type": "BachelorDegree",
                "name": "Bachelor of Science and Arts"
            }
        }
    },
    "authenticationMethod": "PRE_AUTHORIZED",
    "issuerDid": "did:jwk:eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2Iiwia2lkIjoiRnNIVVpZNF90REpEdnhkcDVCNm1vUzFrd3BQN1BCZWt3NEtmSzdtMExDVSIsIngiOiJrZVI5bDR1MVNhWktNWjd3SHZqXzN6NDR2UDBzYTNubHpybmM4VWpwUVYwIiwieSI6InBtY2FlZGc1ZHRjMlI2WlBaZldDQlk1Nl9NXzVmVVpnc3o0TFdEMG1HOFUifQ"
}
```

## Authlete issuer integration

This is the configuration needed to run the Authlete API [OIDC4VCI Demo](https://www.authlete.com/developers/oid4vci/#4-oid4vci-demo) in pre authorized code flow with a sd-jwt VC.

The specific topics here are the client_id pre-registered value to get the access token and the general use of jwk/cnf as DID are not supported. You can sign VCs with a JWK and a kid equal to a verificationMethod published in your DID Document but the `iss` attribute will remain the issuer URL and not the issuer DID.

You will need to have an access to the wallet provider backend to setup a custom profile and update the OIDC4VC options as follow:

1. Go to the `SSI Data` page
2. SSI profile (4.1) choose `custom profile`
3. Key Identifier (4.5) choose  `jwk thumbprint with P-256`
4. Client_id type (4.6) choose `pre-registered`
5. Client Authentication Method (4.9) choose `client id` and enter the example value `218232426`
6. OIDC4VCI Draft (4.10) select `Draft 13`
7. VC Format (4.13) choose `vc+sd-jwt`
8. Proof Type (4.14) select `jwt`
9. Proof of Possession Header (4.15) select `jwk`
10. Do not forget to save the configuration (bottom setup button)
11. Download the configuration to the wallet by scan or update it from the wallet if you already use it.

Go to the [issuer URL](https://trial.authlete.net/api/offer/issue), select the Pre Authorised Code Grant in the form, if needed you can add transaction code data. Submit the issuer form, scan the QR code, choose the IndentityCredential proposed in the wallet, follow the process and consent.

Use the developer mode to display the VC decoded inside the wallet or download it and use this [tool](https://www.sdjwt.co/) to decode it with all disclosures.

```json
{
  "kid": "J1FwJP87C6-QN_WSIOmJAQc6n5CQ_bZdaFJ5GDnW1Rk",
  "typ": "vc+sd-jwt",
  "alg": "ES256"
}

{
  "_sd": [
    "04le4bFu5-mavLr_ZiPP6cLyet2AoAEKN5SzbukwWi0",
    "1VmLs3WfKoHcQb-MlrRWx0kKkC8lmpL164jeRV9aGOA",
    "Mg5UREMN3elGQbOvcG9Mh6CaSTHyDgcMnzMLF21EEJw",
    "Wx9xvfgee4AQ4a0fbWCwGyxr3LB7g1mQQx0Oq4hy8A4",
    "eDlVzAalQrQavjMbSvGcppFhuFCuvZSy1RHliRy1xKs",
    "jt0qxHtMYfLXYYm7rySaKXpBP1SMJk3vX0-FgFE-Oqk",
    "k_r1tAt6TsnoqsNyrGOtyykCAFFD5pQCSNTuqFG9Xeg",
    "lqre2R2Xrj8FEyTX_yauPS4KRUb5a4BZt9cIXwVmzqs",
    "wrsr2ZuNmcy3-3l4-8pjQHMx7sq-sxbL0sVOiBT1tvY",
    "xDRY5VC6STHnuAuHHc2j1pgX4pBKfX69yJEh1WpItl8"
  ],
  "vct": "https://credentials.example.com/identity_credential",
  "_sd_alg": "sha-256",
  "iss": "https://trial.authlete.net",
  "cnf": {
    "jwk": {
      "kty": "EC",
      "use": "sig",
      "crv": "P-256",
      "kid": "okKqec7q60xoZwwePMiEGaAXwvLCt-WqMaX2V3L1Lr4",
      "x": "ptUUeO8I9lazDDBWKPTV-WZGedtQTt2gln2t0wKDjV8",
      "y": "YklhBu0YC2p7OUKy2ZYSqzCcDvXVtH_qBMwGBf6NmTY",
      "alg": "ES256"
    }
  },
  "iat": 1730468137
}

```

## Full issuance flow example

This example is based on the flow of [this issuer](https://talao.co/sandbox/issuer/test_2).

Below the URL encoded credential offer which is read as a QR code by the wallet:

```
openid-credential-offer://?credential_offer_uri=https://talao.co/issuer/credential_offer_uri/ca0f1c7e-9426-11ef-b6e7-0a1628958560
```

First the wallet calls the credential_offer_uri endpoint:

```https
GET /issuer/credential_offer_uri/ca0f1c7e-9426-11ef-b6e7-0a1628958560
Host: talao.co
```

The issuer responds with the credential offer which looks like this:

```json
{
      "credential_offer": {
            "credential_issuer": "https://talao.co/issuer/sobosgdtgd",
            "credential_configuration_ids": [
                  "InsuranceNaturalPerson"
            ],
            "grants": {
                  "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                        "pre-authorized_code": "dfc8ee59-9430-11ef-9e55-0a1628958560"
                  }
            }
      }
}
```

Then the wallet calls the issuer metadata endpoint:

```https
GET /issuer/sobosgdtgd/.well-known/openid-credential-issuer
Host: talao.co
```

The issuer responds with the issuer matadata which looks like this:

```json
{
    "credential_issuer": "https://talao.co/issuer/sobosgdtgd",
    "pre-authorized_grant_anonymous_access_supported": true,
    "display": [
        {
            "name": "Talao issuer",
            "locale": "en-US",
            "logo": {
                "uri": "https://talao.co/static/img/talao.png",
                "alt_text": "Talao logo"
            }
        },
        {
            "name": "Talao issuer",
            "locale": "fr-FR",
            "logo": {
                "uri": "https://talao.co/static/img/talao.png",
                "alt_text": "Talao logo"
            }
        }
    ],
    "credential_endpoint": "https://talao.co/issuer/sobosgdtgd/credential",
    "deferred_credential_endpoint": "https://talao.co/issuer/sobosgdtgd/deferred",
    "request_parameter_supported": true,
    "request_uri_parameter_supported": true,
    "subject_syntax_types_supported": [
        "urn:ietf:params:oauth:jwk-thumbprint",
        "did:key",
        "did:ebsi",
        "did:pkh",
        "did:ethr",
        "did:web",
        "did:jwk"
    ],
    "subject_syntax_types_discriminations": [
        "did:key:jwk_jcs-pub",
        "did:ebsi:v1"
    ],
    "subject_trust_frameworks_supported": [
        "ebsi"
    ],
    "id_token_types_supported": [
        "subject_signed_id_token"
    ],
    "credential_configurations_supported": {
        "InsuranceNaturalPerson": {
            "scope": "InsuranceNaturalPerson_scope",
            "display": [
                {
                    "locale": "en-US",
                    "name": "Issurance attestation",
                    "description": "Insurance for liability risks",
                    "background_color": "#3B6F6D",
                    "text_color": "#FFFFFF",
                    "logo": {
                        "uri": "https://dutchblockchaincoalition.org/assets/images/icons/Logo-DBC.png",
                        "alt_text": "AXA International."
                    },
                    "background_image": {
                        "uri": "https://i.ibb.co/CHqjxrJ/dbc-card-hig-res.png",
                        "alt_text": "AXA International"
                    }
                }
            ],
            "id": "InsuranceNaturalPerson",
            "credential_definition": {
                "type": [
                    "VerifiableCredential",
                    "InsuranceNaturalPerson"
                ],
                "credentialSubject": {
                    "insurerName": {
                        "display": [
                            {
                                "name": "Insurer name",
                                "locale": "en-US"
                            }
                        ]
                    },
                    "leiCodeInsurer": {
                        "display": [
                            {
                                "name": "LEI code",
                                "locale": "en-US"
                            }
                        ]
                    },
                    "contractId": {
                        "display": [
                            {
                                "name": "Contract Identifier",
                                "locale": "en-US"
                            }
                        ]
                    },
                    "insuredPerson": {}
                }
            },
            "format": "jwt_vc_json",
            "cryptographic_binding_methods_supported": [
                "did:jwk",
                "did:key"
            ],
            "proof_types_supported": {
                "jwt": {
                    "proof_signing_alg_values_supported": [
                        "ES256"
                    ]
                }
            },
            "credential_signing_alg_values_supported": [
                "ES256"
            ]
        }
    }
}

```

Then the wallet calls the authorization server metadata endpoint:

```https
GET /issuer/sobosgdtgd/.well-known/oauth-authorization-server
Host: talao.co
```

The authorization server responds with the matadata which looks like this:

```json

{
    "pre-authorized_grant_anonymous_access_supported": true,
    "display": [
        {
            "name": "Talao issuer",
            "locale": "en-US",
            "logo": {
                "uri": "https://talao.co/static/img/talao.png",
                "alt_text": "Talao logo"
            }
        },
        {
            "name": "Talao issuer",
            "locale": "fr-FR",
            "logo": {
                "uri": "https://talao.co/static/img/talao.png",
                "alt_text": "Talao logo"
            }
        }
    ],
    "scopes_supported": [
        "openid"
    ],
    "response_types_supported": [
        "vp_token",
        "id_token"
    ],
    "response_modes_supported": [
        "query"
    ],
    "grant_types_supported": [
        "authorization_code",
        "urn:ietf:params:oauth:grant-type:pre-authorized_code"
    ],
    "subject_types_supported": [
        "public",
        "pairwise"
    ],
    "id_token_signing_alg_values_supported": [
        "ES256",
        "ES256K",
        "EdDSA",
        "RS256"
    ],
    "request_object_signing_alg_values_supported": [
        "ES256",
        "ES256K",
        "EdDSA",
        "RS256"
    ],
    "token_endpoint_auth_methods_supported": [
        "client_secret_basic",
        "client_secret_post",
        "client_secret_jwt",
        "none"
    ],
    "request_authentication_methods_supported": {
        "authorization_endpoint": [
            "request_object"
        ]
    },
    "id_token_types_supported": [
        "subject_signed_id_token"
    ],
    "authorization_endpoint": "https://talao.co/issuer/sobosgdtgd/authorize",
    "token_endpoint": "https://talao.co/issuer/sobosgdtgd/token",
    "jwks_uri": "https://talao.co/issuer/sobosgdtgd/jwks",
    "pushed_authorization_request_endpoint": "https://talao.co/issuer/sobosgdtgd/authorize/par"
}

```

Then wallet calls the token endpoint with the pre authorized code and a client_id (optional):

```https
POST /issuer/sobosgdtgd/token HTTP/1.0
Host: talao.co
Content-Type: application/x-www-form-urlencoded
Content-Length: 321

grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code
&pre-authorized_code=dfc8ee59-9430-11ef-9e55-0a1628958560
&client_id=did:jwk:eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6IkthY0xyeG1OMXhNNGlrZWY2bHJRM1F5d25PVEdrR05xV3hhM2Rsc1pReDgiLCJ5IjoiYXZWZWgzY3Z5SVl1Q0NUVDF5YnZKeFoyeXNvQ2FuaDFOOE9nTzFBT1M3WSJ9
```

The issuer responds with an access token and a c_nonce (optional):

```json
{
    "access_token": "4fed3ac3-9431-11ef-b492-0a1628958560",
    "c_nonce": "4fed3cc1-9431-11ef-beed-0a1628958560",
    "token_type": "bearer",
    "expires_in": 10000,
    "c_nonce_expires_in": 1704466725,
    "refresh_token": "4fed3c24-9431-11ef-b9f1-0a1628958560"
}
```

Then the wallet calls the credential endpoint with the format and type of the credential and a proof of key ownership as a jwt:

```https
POST /issuer/sobosgdtgd/credential HTTP/1.0
Host: talao.co
Authorization: Bearer 4fed3ac3-9431-11ef-b492-0a1628958560
Content-Type: application/json
Content-Length: 932

{
    "format": "jwt_vc_json",
    "credential_definition": {
        "type": [
            "VerifiableCredential",
            "InsuranceNaturalPerson"
        ]
    },
    "proof": {
        "proof_type": "jwt",
        "jwt": "eyJhbGciOiJFUzI1NiIsInR5cCI6Im9wZW5pZDR2Y2ktcHJvb2Yrand0Iiwia2lkIjoiZGlkOmp3azpleUpqY25ZaU9pSlFMVEkxTmlJc0ltdDBlU0k2SWtWRElpd2llQ0k2SWt0aFkweHllRzFPTVhoTk5HbHJaV1kyYkhKUk0xRjVkMjVQVkVkclIwNXhWM2hoTTJSc2MxcFJlRGdpTENKNUlqb2lZWFpXWldnelkzWjVTVmwxUTBOVVZERjVZblpLZUZveWVYTnZRMkZ1YURGT09FOW5UekZCVDFNM1dTSjkjMCJ9.eyJpc3MiOiJkaWQ6andrOmV5SmpjbllpT2lKUUxUSTFOaUlzSW10MGVTSTZJa1ZESWl3aWVDSTZJa3RoWTB4eWVHMU9NWGhOTkdsclpXWTJiSEpSTTFGNWQyNVBWRWRyUjA1eFYzaGhNMlJzYzFwUmVEZ2lMQ0o1SWpvaVlYWldaV2d6WTNaNVNWbDFRME5VVkRGNVluWktlRm95ZVhOdlEyRnVhREZPT0U5blR6RkJUMU0zV1NKOSIsImlhdCI6MTczMDAxMjQ3MCwiYXVkIjoiaHR0cHM6Ly90YWxhby5jby9pc3N1ZXIvc29ib3NnZHRnZCIsIm5vbmNlIjoiNGZlZDNjYzEtOTQzMS0xMWVmLWJlZWQtMGExNjI4OTU4NTYwIn0.2rQCQ8PJy5bu8wVUJ76C_qVXcdrj5ajyUFNwk3agvMbPMH40B8fu0Oq5dMiz7h2YGPgjI87wQBjFHToEhaN-5w"
    }
}
```

The issuer responds with the credential:

```json
{
  "credential": "eyJhbGciOiJFZERTQSIsImtpZCI6ImRpZDp3ZWI6YXBwLmFsdG1lLmlvOmlzc3VlciNrZXktMSIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3NjE1NDg1MDAsImlhdCI6MTczMDAxMjUwMCwiaXNzIjoiZGlkOndlYjphcHAuYWx0bWUuaW86aXNzdWVyIiwianRpIjoidXJuOnV1aWQ6NTBjZmJmMzEtOTQzMS0xMWVmLTg1ZDUtMGExNjI4OTU4NTYwIiwibmJmIjoxNzMwMDEyNTAwLCJub25jZSI6IjRmZWQzY2MxLTk0MzEtMTFlZi1iZWVkLTBhMTYyODk1ODU2MCIsInN1YiI6ImRpZDpqd2s6ZXlKamNuWWlPaUpRTFRJMU5pSXNJbXQwZVNJNklrVkRJaXdpZUNJNklrdGhZMHh5ZUcxT01YaE5OR2xyWldZMmJISlJNMUY1ZDI1UFZFZHJSMDV4VjNoaE0yUnNjMXBSZURnaUxDSjVJam9pWVhaV1pXZ3pZM1o1U1ZsMVEwTlVWREY1WW5aS2VGb3llWE52UTJGdWFERk9PRTluVHpGQlQxTTNXU0o5IiwidmMiOnsiY3JlZGVudGlhbFN0YXR1cyI6W3siaWQiOiJodHRwczovL3RhbGFvLmNvL3NhbmRib3gvaXNzdWVyL2JpdHN0cmluZ3N0YXR1c2xpc3QvMSM2NTU1MiIsInN0YXR1c0xpc3RDcmVkZW50aWFsIjoiaHR0cHM6Ly90YWxhby5jby9zYW5kYm94L2lzc3Vlci9iaXRzdHJpbmdzdGF0dXNsaXN0LzEiLCJzdGF0dXNMaXN0SW5kZXgiOiI2NTU1MiIsInN0YXR1c1B1cnBvc2UiOiJyZXZvY2F0aW9uIiwidHlwZSI6IkJpdHN0cmluZ1N0YXR1c0xpc3RFbnRyeSJ9XSwiY3JlZGVudGlhbFN1YmplY3QiOnsiY29udHJhY3QiOnsiY29udHJhY3RBbW91bnQiOjEwMDAwMDAwLCJjb250cmFjdFR5cGUiOiJMaWFiaWxpdHkgcmlza3MiLCJjdXJyZW5jeSI6IkVVUiJ9LCJjb250cmFjdElkIjoiODk3ODk3NjUgOTc2OTY1IiwiaWQiOiIiLCJpbnN1cmVkUGVyc29uIjp7ImJpcnRoZGF0ZSI6IjIwMDAtMTItMDEiLCJmYW1pbHlfbmFtZSI6IkRvZSIsImdpdmVuX25hbWUiOiJKb2huIn0sImluc3VyZXJOYW1lIjoiQVhBIEludGVybmF0aW9uYWwiLCJsZWlDb2RlSW5zdXJlciI6IjAyMDk5ODc2RlI3NSJ9LCJleHBpcmF0aW9uRGF0ZSI6IjIwMjUtMTAtMjdUMDY6NTg6MzBaIiwiaWQiOiJ1cm46dXVpZDo0ZDQ3YTZiYS01MWNkLTQxZWYtOWJhYi1mYzQ5NjNiNWFmZjMiLCJpc3N1YW5jZURhdGUiOiIyMDI0LTEwLTI3VDA2OjU4OjMwWiIsInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJJbnN1cmFuY2VOYXR1cmFsUGVyc29uIl19fQ.1DI8Fwe-uWXF3FyxksgNVb453XylOBL8CeQuf-sPI0_Soo_MXHYmwGsKiS6m-rOVCNu4DihclrtIG4NElWbnAg"
}
```

The wallet stores the credential with the issuer metadata for correct rendering.
