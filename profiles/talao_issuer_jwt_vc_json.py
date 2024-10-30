TALAO_ISSUER = {   # DIIP v2.1
        "oidc4vciDraft": "13",
        "siopv2Draft": "12",
        "oidc4vpDraft": "18",
        "vc_format": "jwt_vc_json",
        "verifier_vp_type": "jwt_vp_json",
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
                "format": "jwt_vc_json",
                "scope": "VerifiableId_scope",
                "credential_definition": {
                    "type": ["VerifiableCredential", "VerifiableId"],
                    "order": [
                        "given_name",
                        "family_name",
                        "birth_date",
                        "age_over_18",
                        "gender",
                        "issuance_date",
                        "issuing_country",
                    ],
                    "credentialSubject": {
                        "given_name": {
                            "mandatory": True,
                            "display": [
                                {"name": "First name", "locale": "en-US"},
                                {"name": "Prénom(s)", "locale": "fr-FR"}         
                            ],
                        },
                        "family_name": {
                            "mandatory": True,
                            "display": [
                                {"name": "Family name", "locale": "en-US"},
                                {"name": "Nom", "locale": "fr-FR"}                                
                            ],
                        },
                        "birth_date": {
                            "mandatory": True,
                            "display": [
                                {"name": "Date of birth", "locale": "en-US"},
                                {"name": "Né(e) le", "locale": "fr-FR"}
                            ],
                        },
                        "age_over_18": {
                            "mandatory": True,
                            "display": [
                                {"name": "Over 18", "locale": "en-US"},
                                {"name": "Majorité", "locale": "fr-FR"}
                            ],
                        },
                        
                        "gender": {
                            "mandatory": True,
                            "display": [
                                {"name": "Gender", "locale": "en-US"},
                                {"name": "Sexe", "locale": "fr-FR"}
                            ]
                        },
                        "issuing_country": {
                            "mandatory": True,
                            "display": [
                                {"name": "Issuing country", "locale": "en-US"},
                                {"name": "Délivré par", "locale": "fr-FR"}
                            ],
                        },
                        "issuance_date": {
                            "mandatory": True,
                            "display": [
                                {"name": "Issuance date", "locale": "en-US"},
                                {"name": "Délivré le", "locale": "fr-FR"}
                            ],
                        },
                    },
                },
                "cryptographic_binding_methods_supported": [
                    "did:jwk",
                    "did:key"
                ],
                "proof_types_supported": {
                    "jwt": {
                        "proof_signing_alg_values_supported": ["ES256"]
                    }
                },
                "credential_signing_alg_values_supported": [
                    "ES256K",
                    "ES256",
                    "ES384",
                    "RS256",
                ],
                "display": [
                    {
                        "name": "Verifiable Id",
                        "decription": "Personal ID",
                        "locale": "en-US",
                        "background_color": "#12107c",
                        "text_color": "#FFFFFF",
                    }
                ],
            },
            "EmailPass": {
                "format": "jwt_vc_json",
                "scope": "EmailPass_scope",
                "cryptographic_binding_methods_supported": [
                    "did:jwk",
                    "did:key"
                ],
                "proof_types_supported": {
                    "jwt": {
                        "proof_signing_alg_values_supported": ["ES256"]
                    }
                },
                "credential_signing_alg_values_supported": [
                    "ES256K",
                    "ES256"
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
                    "type": [
                        "VerifiableCredential",
                        "EmailPass"
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
                "format": "jwt_vc_json",
                "scope": "PhoneProof_scope",
                "credential_definition": {
                    "type": [
                        "VerifiableCredential",
                        "PhoneProof"
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
                "cryptographic_binding_methods_supported": [
                    "did:jwk",
                    "did:key"
                ],
                "proof_types_supported": {
                    "jwt": {
                        "proof_signing_alg_values_supported": ["ES256"]
                    }
                },
                "credential_signing_alg_values_supported": [
                    "ES256K",
                    "ES256"
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