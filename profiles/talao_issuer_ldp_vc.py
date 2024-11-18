TALAO_ISSUER = {   # draft 13 with ldp_vc
        "oidc4vciDraft": "13",
        "siopv2Draft": "12",
        "oidc4vpDraft": "18",
        "vc_format": "ldp_vc",
        "verifier_vp_type": "ldp_vp",
        "oidc4vci_prefix": "openid-credential-offer://",
        "authorization_server_support": False,
        "credentials_as_json_object_array": False,
        "siopv2_prefix": "openid-vc://",
        "oidc4vp_prefix": "openid-vc://",
        "credentials_types_supported": [
            "EmailPass",
            "PhoneProof",
            "VerifiableId"
        ],
        "credential_configurations_supported": {
            "VerifiableId": {
                "format": "ldp_vc",
                "scope": "VerifiableId_scope",
                "credential_definition": {
                    "type": ["VerifiableCredential", "VerifiableId"],
                    "@context": [
                        "https://www.w3.org/2018/credentials/v1",
                        {
                            "@vocab": "https://schema.org/",
                            "VerifiableId": {
                                "@id": "urn:employeecredential",
                                "@context": {
                                    "@version": 1.1,
                                    "@protected": True,
                                    "id": "@id",
                                    "type": "@type",
                                    "schema": "https://schema.org/",
                                    "familyName": "schema:lastName",
                                    "firstName": "schema:firstName",
                                    "dateOfBirth": "schema:birthDate",
                                    "gender": "schema:gender",
                                    "idRecto": "schema:image",
                                    "dateIssued": "schema:dateIssued",
                                    "idVerso": "schema:image"
                                }
                            }
                        }
                    ],
                },
                "cryptographic_binding_methods_supported": ["DID"],
                "credential_signing_alg_values_supported": [
                    "Ed25519Signature2018"
                ],
                "display": [
                    {
                        "name": "Verifiable Id",
                        "description": "This credential is a proof of your identity. You can use it when you need to prove your identity with services that have already adopted a decentralized identity system.",
                        "locale": "en-GB",
                    }
                ],
                "credentialSubject": {
                    "firstName": {
                        "mandatory": True,
                        "display": [{"name": "First Name", "locale": "en-US"}],
                    },
                    "familyName": {
                        "mandatory": True,
                        "display": [{"name": "Family Name", "locale": "en-US"}],
                    },
                    "gender": {
                        "mandatory": True,
                        "display": [{"name": "Gender", "locale": "en-US"}],
                    },
                    "dateOfBirth": {
                        "mandatory": True,
                        "display": [{"name": "Birth Date", "locale": "en-US"}],
                    },
                    "dateIssued": {
                        "mandatory": True,
                        "display": [{"name": "Issue Date", "locale": "en-US"}],
                    },
                },
            },
            "EmailPass": {
                "format": "ldp_vc",
                "scope": "EmailPass_scope",
                "cryptographic_binding_methods_supported": ["DID", "jwk"],
                "credential_signing_alg_values_supported": [
                    "Ed25519Signature2018"
                ],
                "display": [
                    {
                        "name": "Proof of Email",
                        "description": "Proof of email",
                        "locale": "en-GB"
                    },
                    {
                        "name": "Preuve d'adresse email",
                        "description": "Preuve d'adresse email",
                        "locale": "fr-FR"
                    }
                ],
                "credential_definition": {
                    "type": ["VerifiableCredential", "EmailPass"],
                    "@context": [
                        "https://www.w3.org/2018/credentials/v1",
                        {
                            "EmailPass": "https://doc.wallet-provider.io/wallet/vc_type/#EmailPass",
                            "@vocab": "https://schema.org/"
                        }
                    ],
                    "order": [
                        "email",
                    ],
                    "credentialSubject": {
                        "email": {
                            "mandatory": True,
                            "value_type": "email",
                            "display": [
                                {"name": "Email", "locale": "en-US"},
                                {"name": "Email", "locale": "fr-FR"}         
                            ]
                        }
                    }
                }
            },
            "PhoneProof": {
                "format": "ldp_vc",
                "scope": "PhoneProof_scope",
                "credential_definition": {
                    "type": ["VerifiableCredential", "PhoneProof"],
                    "@context": [
                        "https://www.w3.org/2018/credentials/v1",
                        {
                            "PhoneProof": "https://doc.wallet-provider.io/wallet/vc_type/#PhoneProof",
                            "@vocab": "https://schema.org/"
                        }
                    ],
                    "credentialSubject": {
                        "phone": {
                            "mandatory": True,
                            "value_type": "email",
                            "display": [
                                {
                                    "name": "Phone number",
                                    "locale": "en-US"
                                },
                                {
                                    "name": "Numéro de téléphone",
                                    "locale": "fr-FR"
                                }         
                            ]
                        }
                    }
                },
                "cryptographic_binding_methods_supported": ["DID", "jwk"],
                "credential_signing_alg_values_supported": [
                    "Ed25519Signature2018"
                ],
                "display": [
                    {
                        "name": "Proof of phone number",
                        "locale": "en-GB"
                    },
                    {
                        "name": "Preuve de numéro de téléphone",
                        "locale": "fr-FR"
                    }
                ],
            },
        },
        "grant_types_supported": [
            "authorization_code",
            "urn:ietf:params:oauth:grant-type:pre-authorized_code",
        ]
    }