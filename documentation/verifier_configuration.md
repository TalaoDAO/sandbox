# Verifier configuration

Updated the 29th of August 2025.

## OIDC4VP Specifications Drafts

Wallets support OIDC4VP specifications.

* [Implementer Draft 1 (Draft 8)](https://openid.net/specs/openid-connect-4-verifiable-presentations-1_0-ID1.html) supported
* [implementer Draft 2 (Draft 18)](https://openid.net/specs/openid-4-verifiable-presentations-1_0-ID2.html) supported
* [Draft 20](https://openid.net/specs/openid-4-verifiable-presentations-1_0-20.html) supported
* [Draft 21](https://openid.net/specs/openid-4-verifiable-presentations-1_0-21.html) added features not supported
* [Draft 22](https://openid.net/specs/openid-4-verifiable-presentations-1_0-22.html) partially supported
    - remove client_id_scheme
    - data_transaction support (as Final 1.0)
* [Implementer Draft 3 (Draft 23)](https://openid.net/specs/openid-4-verifiable-presentations-1_0-23.html) partially supported
    - dc+sd-jwt

Wallets support SIOPV2 specifications.

* [Implementer Draft 1 (Draft 7)](https://openid.net/specs/openid-connect-self-issued-v2-1_0-ID1.html) supported
* [Draft 13](https://openid.net/specs/openid-connect-self-issued-v2-1_0.html) supported

## OIDC4VP and SIOPV2 features

Wallets support:

* client_id_scheme as an attribute or as a prefix of client_id (draft 22),
* request in value and request_uri,
* presentation_definition and presentation_definition_uri,
* direct_post and direct_post.jwt,
* id_token, vp_token, id_token vp_token response_type,
* client_metadata
* signed response JARM

Wallets do not support:

* the Digital Credential Query Language (DCQL)
* transaction data
* request uri Method Post,
* encrypted response,
* openid federation 1.0.

## Invocation schemes for verification

Wallets support different invocation schemes:

* openid://,
* openid-vc://,
* openid4vp://,
* haip://,
* siopv2://
* https://app.altme.io/app/download/authorize,
* https://app.talao.co/app/download/authorize

Those schemes can be displayed as QR code for wallet app scanner, smartphone camera or as a deeplink / universal link (a button in a html page for the smartphone browser).

# Support of Universal Links and App Links

For security reasons Talao wallets use Universal Links and App Links to redirect to wallet authorization endpoints and callback endpoints. However those links are not supported by default by all browsers. We suggest to use **Safari for IOS** phones and **Chrome for Android**. You may need to setup browser options manually to allow Universal links and App Links with Firefox, Brave, Samsung explorer or even Chrome on IOS.

## client_id_scheme

Wallet supports the following [client_id_scheme](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-verifier-metadata-managemen) of verifiers:

* did : wallets resolve the DID Document to validate the request object signature, All standards DID methods are supported through an external instance of the DID resolver managed by Talao.
* x509_san_dns : wallets get the public key from the last X509 certificate to validate the request object signature. Wallets use the dNSName Subject Alternative Name (SAN) to request consent from user to present the VC.
* verifier_attestation: wallets validate the signature of the request object with the public key in the cnf of the verifier attestation,
* redirect_uri: there is no validation of the request as the request object must not be signed.

## Wallet metadata

Wallet metadata are available "out of band".

* Talao: [https://app.talao.co/wallet-issuer/.well-known/openid-configuration](https://app.talao.co/wallet-issuer/.well-known/openid-configuration)
* Altme: [https://app.altme.io/wallet-issuer/.well-known/openid-configuration](https://app.altme.io/wallet-issuer/.well-known/openid-configuration)

## VP format and VC format

Wallet supports:

* VC DM 1.1
* ldp_vp as and envelop of ldp_vc
* jwt_vp as an envelop of jwt_vc and/or ldp_vc
* jwt_vp_json as an envelop of jwt_vc_json and/or ldp_vc
* jwt_vp_json-ld as an envelop of jwt_vc_json-ld and/or ldp_vc
* Multiple VC in VP

Multiple sd-jwt presentation is not supported.

## Presentation definition examples

### Request a VC from one type (ldp_vc, jwt_vc_json, jwt_vc_json-d)

Example of a verifier which requests a VC with the type 'VerifiableId':

```json
"constraints": {
    "fields": [
        {
            "path": [
                "$.vc.type"
            ],
            "filter": {
                "type": "array",
                "contains": {
                    "const": "VerifiableId"
                }
            }
        }
    ]
}
```

### Request a SD-JWT VC from one type

Example of a verifier which requests the EUDIW PID:

```json
"constraints": {
    "fields": [
        {
            "path": [
                "$.vct"
            ],
            "filter": {
              "type": "string",
              "const": "urn:eu.europa.ec.eudi:pid:1"
            }
        }
    ]
}
```

### Request a SD-JWT VC for age over

Example of a verifier which requests an age over 18 proof with data minimmization:

```json
"constraints": {
    "limit_disclosure": "required",
    "fields": [
        {
            "path": [
                "$.age_over_18"
            ],
            "filter": {
              "type": "bool",
              "const": true
            }
        }
    ]
}
```

### Request a VC that contains one claim

Example of a verifier which requests a VC with an email claim what ever teh VC format:

```json
"constraints": {
    "fields": [
        {
            "path": [
                "$.email",
                "$.credentialSubject.email",
                "$.vc.credentialSubject.email"
            ]
        }
    ]
}
```

### Request a SD-JWT VC with only a limited list of claims

Example of a verifier which requests only the family_name and given_name of the user:

```json
"constraints": {
    "limit_disclosure": "required",
    "fields": [
        {
            "path": [
                "$.vct"
            ],
            "filter": {
                "type": "string",
                "const": "urn:eu.europa.ec.eudi:pid:1"
            }
        },
        {
            "path": [
                "$.family_name"
            ]
        },
        {
            "path": [
                "$.given_name"
            ]
        }
    ]
}

```

Example of a verifier which requests a proof of email and a proof of phone number:

### Request several VCs

Example of a verifier which requests a proof of email and a proof of phone number:

```json
"input_descriptors": [
    {
        "id": "emailpass_1",
        "name": "Input descriptor for credential 1",
        "constraints": {
            "fields": [
                {
                    "path": [
                        "$.vc.credentialSubject.type"
                    ],
                    "filter": {
                        "type": "string",
                        "const": "EmailPass"
                    }
                }
            ]
        }
    },
    {
        "id": "phoneproof_2",
        "name": "Input descriptor for credential 2",
        "constraints": {
            "fields": [
                {
                    "path": [
                        "$.vc.credentialSubject.type"
                    ],
                    "filter": {
                        "type": "string",
                            "const": "PhoneProof"
                    }
                }
            ]
        }
    }
],

```

## Submission presentation

Submission presentations sent by wallets include nested path (except for sd-jwt).

Example with 2 credentials:

```json
{
  "id": "d1871d8c-fce3-494a-9e76-dad774d743bc",
  "definition_id": "733aa2e6-92c5-11ef-816f-0a1628958560",
  "descriptor_map": [
    {
      "id": "verifiablediploma",
      "format": "jwt_vp",
      "path": "$",
      "path_nested": {
        "id": "verifiablediploma_1",
        "format": "jwt_vc",
        "path": "$.vp.verifiableCredential[0]"
      }
    },
    {

      "id": "verifiablediploma",
      "format": "jwt_vp",
      "path": "$",
      "path_nested": {
        "id": "verifiablediploma_2",
        "format": "jwt_vc",
        "path": "$.vp.verifiableCredential[1]"
      }
    }
  ]
}
```

## sd-jwt presentation rules

The presentation is done in two steps which are the choice of the credential then the selection of the data that will be presented. In case of only 1 credential that fits with the presentation_definition the choice step is by passed.

The credential contains 3 types of data:

* The standards jwt attributes as iss, iat, vct,...that are systematically presented and not displayed to the user during the process,
* The “disclosable” claims that are displayed and selectable (except for `limit_disclosure = required`),
* Other claims defined in the jwt are displayed to the user and not selectable

For data minimization purpose, in case of a presentation_definition including the `limit_disclosure = required` option, user can only accept or refuse to present the verifiable credential. The data set of the VC is limited to what is strictly required by the verifier.

## Submission Requirement Features

Learn more about this topic [here](https://identity.foundation/presentation-exchange/#submission-requirement-feature).

To be done

## Verifiers integration

Wallets have been tested through different project implementations and interoperability events with most of the APIs and libs providers of the market. See below compatibility list with the date of the last tests.

* **Lissi** : OK on March 2025
* **Procivis**: OK on March 2025
* **Sphereon:** OK on Jan 2024
* **WaltId**: OK on March 2025, see below details
* **Meeco**: OK on Jan 2024
* **SICPA**: OK on March 2025
* **Netcetera**: OK on May 2024

## Waltid integration

Integration of the example provided by waltid documentation must be updated by:

- QR code returned by Waltid API must be corrected as client_id must be equal to response_uri when `client_id_scheme = redirect_uri`. See [https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-verifier-metadata-managemen](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-verifier-metadata-managemen)
- `path` must be providd from upper object. Replace `$.type` by `$.vc.type`
- `type` is an array so filter must be set accordingly

```json
"constraints": {
    "fields": [
        {
            "path": [
                "$.vc.type"
            ],
            "filter": {
                "type": "array",
                "contains": {
                    "const": "UniversityDegreeCredential"
                }
            }
        }
    ]
}
```

## Full verifier flow example

This example is based on the flow of [this verifier](https://talao.co/sandbox/verifier/test_2).

Below the URL encoded authorization request presented by the verifier which is read as a QR code by the wallet:

```
openid-vc://?client_id=did:web:app.altme.io:issuer&request_uri=https://talao.co/verifier/wallet/request_uri/a4a76476-943b-11ef-baf6-0a1628958560
```

First wallet calls the request_uri endpoint to get the authorization request:

```http
GET /verifier/wallet/request_uri/a4a76476-943b-11ef-baf6-0a1628958560 HTTP/1.0
Host: talao.co
```

The verifier responds with a signed jwt:

```
eyJhbGciOiJFZERTQSIsImtpZCI6ImRpZDp3ZWI6YXBwLmFsdG1lLmlvOmlzc3VlciNrZXktMSIsInR5cCI6Im9hdXRoLWF1dGh6LXJlcStqd3QifQ.eyJhdWQiOiJodHRwczovL3NlbGYtaXNzdWVkLm1lL3YyIiwiY2xpZW50X2lkIjoiZGlkOndlYjphcHAuYWx0bWUuaW86aXNzdWVyIiwiY2xpZW50X2lkX3NjaGVtZSI6Im5vbmUiLCJjbGllbnRfbWV0YWRhdGEiOnsiY2xpZW50X25hbWUiOiJBbHRtZSBWZXJpZmllciBwbGF0Zm9ybSIsImlkX3Rva2VuX3NpZ25pbmdfYWxnX3ZhbHVlc19zdXBwb3J0ZWQiOlsiRVMyNTYiLCJFUzI1NmsiLCJFZERTQSJdLCJpZF90b2tlbl90eXBlc19zdXBwb3J0ZWQiOlsic3ViamVjdF9zaWduZWRfaWRfdG9rZW4iXSwicmVkaXJlY3RfdXJpcyI6WyJodHRwczovL3RhbGFvLmNvL3ZlcmlmaWVyL3dhbGxldC9lbmRwb2ludC9lMDE5NmVhNC05NDNiLTExZWYtYmZhNy0wYTE2Mjg5NTg1NjAiXSwicmVxdWVzdF9wYXJhbWV0ZXJfc3VwcG9ydGVkIjpmYWxzZSwicmVxdWVzdF91cmlfcGFyYW1ldGVyX3N1cHBvcnRlZCI6dHJ1ZSwicmVzcG9uc2VfbW9kZXNfc3VwcG9ydGVkIjpbInF1ZXJ5Il0sInJlc3BvbnNlX3R5cGVzX3N1cHBvcnRlZCI6WyJpZF90b2tlbiIsInZwX3Rva2VuIl0sInNjb3Blc19zdXBwb3J0ZWQiOlsib3BlbmlkIl0sInN1YmplY3Rfc3ludGF4X3R5cGVzX2Rpc2NyaW1pbmF0aW9ucyI6WyJkaWQ6a2V5Omp3a19qY3MtcHViIiwiZGlkOmVic2k6djEiXSwic3ViamVjdF9zeW50YXhfdHlwZXNfc3VwcG9ydGVkIjpbInVybjppZXRmOnBhcmFtczpvYXV0aDpqd2stdGh1bWJwcmludCIsImRpZDprZXkiLCJkaWQ6ZWJzaSIsImRpZDpldGhyIl0sInN1YmplY3RfdHJ1c3RfZnJhbWV3b3Jrc19zdXBwb3J0ZWQiOlsiZWJzaSJdLCJzdWJqZWN0X3R5cGVzX3N1cHBvcnRlZCI6WyJwdWJsaWMiXSwidnBfZm9ybWF0cyI6eyJqd3RfdnAiOnsiYWxnX3ZhbHVlc19zdXBwb3J0ZWQiOlsiRVMyNTYiLCJFUzI1NksiLCJFZERTQSJdfSwiand0X3ZwX2pzb24iOnsiYWxnX3ZhbHVlc19zdXBwb3J0ZWQiOlsiRVMyNTYiLCJFUzI1NksiLCJFZERTQSJdfSwibGRwX3ZjIjp7InByb29mX3R5cGUiOlsiSnNvbldlYlNpZ25hdHVyZTIwMjAiLCJFZDI1NTE5U2lnbmF0dXJlMjAxOCIsIkVjZHNhU2VjcDI1NmsxU2lnbmF0dXJlMjAxOSIsIlJzYVNpZ25hdHVyZTIwMTgiXX0sImxkcF92cCI6eyJwcm9vZl90eXBlIjpbIkpzb25XZWJTaWduYXR1cmUyMDIwIiwiRWQyNTUxOVNpZ25hdHVyZTIwMTgiLCJFY2RzYVNlY3AyNTZrMVNpZ25hdHVyZTIwMTkiLCJSc2FTaWduYXR1cmUyMDE4Il19LCJ2YytzZC1qd3QiOnsia2Itand0X2FsZ192YWx1ZXMiOlsiRVMyNTYiLCJFUzI1NksiLCJFZERTQSJdLCJzZC1qd3RfYWxnX3ZhbHVlcyI6WyJFUzI1NiIsIkVTMjU2SyIsIkVkRFNBIl19fX0sImV4cCI6MTczMDAxODAzNS41NTM3NjYsImlzcyI6ImRpZDp3ZWI6YXBwLmFsdG1lLmlvOmlzc3VlciIsIm5vbmNlIjoiZTAxOTkwZGEtOTQzYi0xMWVmLWE0MzAtMGExNjI4OTU4NTYwIiwicHJlc2VudGF0aW9uX2RlZmluaXRpb24iOnsiZm9ybWF0Ijp7Imp3dF92Y19qc29uIjp7ImFsZyI6WyJFUzI1NmsiLCJFUzI1NiIsIkVkRFNBIl19LCJqd3RfdnBfanNvbiI6eyJhbGciOlsiRVMyNTZrIiwiRVMyNTYiLCJFZERTQSJdfX0sImlkIjoiNjBmMzI4NzktM2FhMy0xMWVmLTlkZGMtOTNkMzg3NjMyOWMxIiwiaW5wdXRfZGVzY3JpcHRvcnMiOlt7ImNvbnN0cmFpbnRzIjp7ImZpZWxkcyI6W3siZmlsdGVyIjp7ImNvbnRhaW5zIjp7ImNvbnN0IjoiSW5zdXJhbmNlTmF0dXJhbFBlcnNvbiJ9LCJ0eXBlIjoiYXJyYXkifSwicGF0aCI6WyIkLnZjLnR5cGUiXX1dfSwiaWQiOiJJbnN1cmFuY2VfZm9yX25hdHVyYWxfcGVyc29uXzEiLCJuYW1lIjoiSW5wdXQgZGVzY3JpcHRvciBmb3IgY3JlZGVudGlhbCAxIn1dLCJuYW1lIjoiVGVzdCAjMiIsInB1cnBvc2UiOiJBbHRtZSBwcmVzZW50YXRpb24gZGVmaW5pdGlvbiBzdWJzZXQgb2YgUEVYIHYyLjAifSwicmVzcG9uc2VfbW9kZSI6ImRpcmVjdF9wb3N0IiwicmVzcG9uc2VfdHlwZSI6InZwX3Rva2VuIiwicmVzcG9uc2VfdXJpIjoiaHR0cHM6Ly90YWxhby5jby92ZXJpZmllci93YWxsZXQvZW5kcG9pbnQvZTAxOTZlYTQtOTQzYi0xMWVmLWJmYTctMGExNjI4OTU4NTYwIiwic3RhdGUiOiJlMDE5OTFjMS05NDNiLTExZWYtYjI5MS0wYTE2Mjg5NTg1NjAifQ.h3vmJaxxemOpb4oMfTAvZIWBGh_dzJQP1dNtV0GXLNgTZG8tA9YBM1asvV1KZ3uE8rwV6mVsQ8ZBMigxiDmFAQ
```

Which when decoded looks something like this:

```json
{
    "alg": "EdDSA",
    "kid": "did:web:app.altme.io:issuer#key-1",
    "typ": "oauth-authz-req+jwt"
}

{
    "aud": "https://self-issued.me/v2",
    "client_id": "did:web:app.altme.io:issuer",
    "client_id_scheme": "did",
    "client_metadata": {
        "client_name": "Altme Verifier platform",
        "id_token_signing_alg_values_supported": [
            "ES256",
            "ES256k",
            "EdDSA"
        ],
        "id_token_types_supported": [
            "subject_signed_id_token"
        ],
        "redirect_uris": [
            "https://talao.co/verifier/wallet/endpoint/e59b1eaf-943c-11ef-8d3c-0a1628958560"
        ],
        "request_parameter_supported": false,
        "request_uri_parameter_supported": true,
        "response_modes_supported": [
            "query"
        ],
        "response_types_supported": [
            "id_token",
            "vp_token"
        ],
        "scopes_supported": [
            "openid"
        ],
        "subject_syntax_types_discriminations": [
            "did:key:jwk_jcs-pub",
            "did:ebsi:v1"
        ],
        "subject_syntax_types_supported": [
            "urn:ietf:params:oauth:jwk-thumbprint",
            "did:key",
            "did:ebsi",
            "did:ethr"
        ],
        "subject_trust_frameworks_supported": [
            "ebsi"
        ],
        "subject_types_supported": [
            "public"
        ],
        "vp_formats": {
            "jwt_vp": {
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
            "ldp_vc": {
                "proof_type": [
                    "JsonWebSignature2020",
                    "Ed25519Signature2018",
                    "EcdsaSecp256k1Signature2019",
                    "RsaSignature2018"
                ]
            },
            "ldp_vp": {
                "proof_type": [
                    "JsonWebSignature2020",
                    "Ed25519Signature2018",
                    "EcdsaSecp256k1Signature2019",
                    "RsaSignature2018"
                ]
            },
            "vc+sd-jwt": {
                "kb-jwt_alg_values": [
                    "ES256",
                    "ES256K",
                    "EdDSA"
                ],
                "sd-jwt_alg_values": [
                    "ES256",
                    "ES256K",
                    "EdDSA"
                ]
            }
        }
    },
    "exp": 1730018474.288942,
    "iss": "did:web:app.altme.io:issuer",
    "nonce": "e59b4062-943c-11ef-90e1-0a1628958560",
    "presentation_definition": {
        "format": {
            "jwt_vc_json": {
                "alg": [
                    "ES256k",
                    "ES256",
                    "EdDSA"
                ]
            },
            "jwt_vp_json": {
                "alg": [
                    "ES256k",
                    "ES256",
                    "EdDSA"
                ]
            }
        },
        "id": "60f32879-3aa3-11ef-9ddc-93d3876329c1",
        "input_descriptors": [
            {
                "constraints": {
                    "fields": [
                        {
                            "filter": {
                                "contains": {
                                    "const": "InsuranceNaturalPerson"
                                },
                                "type": "array"
                            },
                            "path": [
                                "$.vc.type"
                            ]
                        }
                    ]
                },
                "id": "Insurance_for_natural_person_1",
                "name": "Input descriptor for credential 1"
            }
        ],
        "name": "Test #2",
        "purpose": "Altme presentation definition subset of PEX v2.0"
    },
    "response_mode": "direct_post",
    "response_type": "vp_token",
    "response_uri": "https://talao.co/verifier/wallet/endpoint/e59b1eaf-943c-11ef-8d3c-0a1628958560",
    "state": "e59b4145-943c-11ef-a658-0a1628958560"
}
```

The wallet sends the verifiable presentation with the state and submission presentation:

```https
POST /verifier/wallet/endpoint/e59b1eaf-943c-11ef-8d3c-0a1628958560 HTTP/1.0
Host: talao.co
Content-Type: application/x-www-form-urlencoded
Content-Length: 4363

state=e59b4145-943c-11ef-a658-0a1628958560
&vp_token=eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImRpZDpqd2s6ZXlKamNuWWlPaUpRTFRJMU5pSXNJbXQwZVNJNklrVkRJaXdpZUNJNklrdGhZMHh5ZUcxT01YaE5OR2xyWldZMmJISlJNMUY1ZDI1UFZFZHJSMDV4VjNoaE0yUnNjMXBSZURnaUxDSjVJam9pWVhaV1pXZ3pZM1o1U1ZsMVEwTlVWREY1WW5aS2VGb3llWE52UTJGdWFERk9PRTluVHpGQlQxTTNXU0o5IzAifQ.eyJpYXQiOjE3MzAwMTY5NTEsImp0aSI6InVybjp1dWlkOmYxOWQ2YTYzLTM0NDAtNDVlYy04NWI2LTQ4MTIwMjg2ZmYzMyIsIm5iZiI6MTczMDAxNjk0MSwiYXVkIjoiZGlkOndlYjphcHAuYWx0bWUuaW86aXNzdWVyIiwiZXhwIjoxNzMwMDE3OTUxLCJzdWIiOiJkaWQ6andrOmV5SmpjbllpT2lKUUxUSTFOaUlzSW10MGVTSTZJa1ZESWl3aWVDSTZJa3RoWTB4eWVHMU9NWGhOTkdsclpXWTJiSEpSTTFGNWQyNVBWRWRyUjA1eFYzaGhNMlJzYzFwUmVEZ2lMQ0o1SWpvaVlYWldaV2d6WTNaNVNWbDFRME5VVkRGNVluWktlRm95ZVhOdlEyRnVhREZPT0U5blR6RkJUMU0zV1NKOSIsImlzcyI6ImRpZDpqd2s6ZXlKamNuWWlPaUpRTFRJMU5pSXNJbXQwZVNJNklrVkRJaXdpZUNJNklrdGhZMHh5ZUcxT01YaE5OR2xyWldZMmJISlJNMUY1ZDI1UFZFZHJSMDV4VjNoaE0yUnNjMXBSZURnaUxDSjVJam9pWVhaV1pXZ3pZM1o1U1ZsMVEwTlVWREY1WW5aS2VGb3llWE52UTJGdWFERk9PRTluVHpGQlQxTTNXU0o5IiwidnAiOnsiQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiXSwiaWQiOiJ1cm46dXVpZDpmMTlkNmE2My0zNDQwLTQ1ZWMtODViNi00ODEyMDI4NmZmMzMiLCJ0eXBlIjpbIlZlcmlmaWFibGVQcmVzZW50YXRpb24iXSwiaG9sZGVyIjoiZGlkOmp3azpleUpqY25ZaU9pSlFMVEkxTmlJc0ltdDBlU0k2SWtWRElpd2llQ0k2SWt0aFkweHllRzFPTVhoTk5HbHJaV1kyYkhKUk0xRjVkMjVQVkVkclIwNXhWM2hoTTJSc2MxcFJlRGdpTENKNUlqb2lZWFpXWldnelkzWjVTVmwxUTBOVVZERjVZblpLZUZveWVYTnZRMkZ1YURGT09FOW5UekZCVDFNM1dTSjkiLCJ2ZXJpZmlhYmxlQ3JlZGVudGlhbCI6WyJleUpoYkdjaU9pSkZaRVJUUVNJc0ltdHBaQ0k2SW1ScFpEcDNaV0k2WVhCd0xtRnNkRzFsTG1sdk9tbHpjM1ZsY2lOclpYa3RNU0lzSW5SNWNDSTZJa3BYVkNKOS5leUpsZUhBaU9qRTNOakUxTkRnMU1EQXNJbWxoZENJNk1UY3pNREF4TWpVd01Dd2lhWE56SWpvaVpHbGtPbmRsWWpwaGNIQXVZV3gwYldVdWFXODZhWE56ZFdWeUlpd2lhblJwSWpvaWRYSnVPblYxYVdRNk5UQmpabUptTXpFdE9UUXpNUzB4TVdWbUxUZzFaRFV0TUdFeE5qSTRPVFU0TlRZd0lpd2libUptSWpveE56TXdNREV5TlRBd0xDSnViMjVqWlNJNklqUm1aV1F6WTJNeExUazBNekV0TVRGbFppMWlaV1ZrTFRCaE1UWXlPRGsxT0RVMk1DSXNJbk4xWWlJNkltUnBaRHBxZDJzNlpYbEthbU51V1dsUGFVcFJURlJKTVU1cFNYTkpiWFF3WlZOSk5rbHJWa1JKYVhkcFpVTkpOa2xyZEdoWk1IaDVaVWN4VDAxWWFFNU9SMnh5V2xkWk1tSklTbEpOTVVZMVpESTFVRlpGWkhKU01EVjRWak5vYUUweVVuTmpNWEJTWlVSbmFVeERTalZKYW05cFdWaGFWMXBYWjNwWk0xbzFVMVpzTVZFd1RsVldSRVkxV1c1YVMyVkdiM2xsV0U1MlVUSkdkV0ZFUms5UFJUbHVWSHBHUWxReFRUTlhVMG81SWl3aWRtTWlPbnNpWTNKbFpHVnVkR2xoYkZOMFlYUjFjeUk2VzNzaWFXUWlPaUpvZEhSd2N6b3ZMM1JoYkdGdkxtTnZMM05oYm1SaWIzZ3ZhWE56ZFdWeUwySnBkSE4wY21sdVozTjBZWFIxYzJ4cGMzUXZNU00yTlRVMU1pSXNJbk4wWVhSMWMweHBjM1JEY21Wa1pXNTBhV0ZzSWpvaWFIUjBjSE02THk5MFlXeGhieTVqYnk5ellXNWtZbTk0TDJsemMzVmxjaTlpYVhSemRISnBibWR6ZEdGMGRYTnNhWE4wTHpFaUxDSnpkR0YwZFhOTWFYTjBTVzVrWlhnaU9pSTJOVFUxTWlJc0luTjBZWFIxYzFCMWNuQnZjMlVpT2lKeVpYWnZZMkYwYVc5dUlpd2lkSGx3WlNJNklrSnBkSE4wY21sdVoxTjBZWFIxYzB4cGMzUkZiblJ5ZVNKOVhTd2lZM0psWkdWdWRHbGhiRk4xWW1wbFkzUWlPbnNpWTI5dWRISmhZM1FpT25zaVkyOXVkSEpoWTNSQmJXOTFiblFpT2pFd01EQXdNREF3TENKamIyNTBjbUZqZEZSNWNHVWlPaUpNYVdGaWFXeHBkSGtnY21semEzTWlMQ0pqZFhKeVpXNWplU0k2SWtWVlVpSjlMQ0pqYjI1MGNtRmpkRWxrSWpvaU9EazNPRGszTmpVZ09UYzJPVFkxSWl3aWFXUWlPaUlpTENKcGJuTjFjbVZrVUdWeWMyOXVJanA3SW1KcGNuUm9aR0YwWlNJNklqSXdNREF0TVRJdE1ERWlMQ0ptWVcxcGJIbGZibUZ0WlNJNklrUnZaU0lzSW1kcGRtVnVYMjVoYldVaU9pSktiMmh1SW4wc0ltbHVjM1Z5WlhKT1lXMWxJam9pUVZoQklFbHVkR1Z5Ym1GMGFXOXVZV3dpTENKc1pXbERiMlJsU1c1emRYSmxjaUk2SWpBeU1EazVPRGMyUmxJM05TSjlMQ0psZUhCcGNtRjBhVzl1UkdGMFpTSTZJakl3TWpVdE1UQXRNamRVTURZNk5UZzZNekJhSWl3aWFXUWlPaUoxY200NmRYVnBaRG8wWkRRM1lUWmlZUzAxTVdOa0xUUXhaV1l0T1dKaFlpMW1ZelE1TmpOaU5XRm1aak1pTENKcGMzTjFZVzVqWlVSaGRHVWlPaUl5TURJMExURXdMVEkzVkRBMk9qVTRPak13V2lJc0luUjVjR1VpT2xzaVZtVnlhV1pwWVdKc1pVTnlaV1JsYm5ScFlXd2lMQ0pKYm5OMWNtRnVZMlZPWVhSMWNtRnNVR1Z5YzI5dUlsMTlmUS4xREk4RndlLXVXWEYzRnl4a3NnTlZiNDUzWHlsT0JMOENlUXVmLXNQSTBfU29vX01YSFltd0dzS2lTNm0tck9WQ051NERpaGNscnRJRzRORWxXYm5BZyJdfSwibm9uY2UiOiJhNGE3OWRmOC05NDNiLTExZWYtOTkxZS0wYTE2Mjg5NTg1NjAifQ.7ZZjgn7yk50bBtP-gqWUocaW_Qp6iIR0ou6soXnX7FAazgOIH-wHiW-hgHvHF_rlgo7FY0YNu9x7Y7gW6cddEA
&presentation_submission={"id":"0b73fc2c-440a-4964-a9de-1fb26ae57a78","definition_id":"60f32879-3aa3-11ef-9ddc-93d3876329c1","descriptor_map":[{"id":"Insurance_for_natural_person_1","format":"jwt_vp_json","path":"$","path_nested":{"id":"Insurance_for_natural_person_1","format":"jwt_vc_json","path":"$.vp.verifiableCredential[0]"}}]}
```

The presentation submission decoded is:

```json
{
    "id":"2fd5df17-10e7-43ff-ae6c-bac1e5c2aeec",
    "definition_id":"60f32879-3aa3-11ef-9ddc-93d3876329c1",
    "descriptor_map":[
        {
            "id":"Insurance_for_natural_person_1",
            "format":"jwt_vp_json",
            "path":"$",
            "path_nested":{
                "id":"Insurance_for_natural_person_1",
                "format":"jwt_vc_json",
                "path":"$.vp.verifiableCredential[0]"
            }
        }
    ]
}

```
