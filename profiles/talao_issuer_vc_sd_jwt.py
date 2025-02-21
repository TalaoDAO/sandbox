TALAO_ISSUER = { 
        "oidc4vciDraft": "13",
        "siopv2Draft": "12",
        "oidc4vpDraft": "18",
        "vc_format": "vc+sd-jwt",
        "verifier_vp_type": "vc+sd-jwt",
        "oidc4vci_prefix": "openid-credential-offer://",
        "authorization_server_support": False,
        "credentials_as_json_object_array": False,
        "siopv2_prefix": "openid-vc://",
        "oidc4vp_prefix": "openid-vc://",
        "credentials_types_supported": [
            "EmailPass",
            "PhoneProof",
            "Pid",
            "AgeProof",
            "BinanceCryptoAccount"
        ],
        "credential_configurations_supported": {
            "BinanceCryptoAccount": {
                "format": "vc+sd-jwt",
                "scope": "BinanceCryptoAccount_scope",
                "order": [
                    "blockchain"
                ],
                "claims": {
                        "blockchain": {
                            "value_type": "string",
                            "display": [{"name": "Blockchain", "locale": "en-US"},
                                        {"name": "Blockchain", "locale": "fr-FR"}]
                        },
                        "address": {
                            "value_type": "string",
                            "display": [{"name": "Address", "locale": "en-US"},
                                        {"name": "Adresse", "locale": "fr-FR"}]
                        }
                    },
                "cryptographic_binding_methods_supported": ["did", "jwk"],
                "credential_signing_alg_values_supported": [
                    "ES256K",
                    "ES256",
                    "EdDSA",
                    "RS256",
                ],
                "vct": "https://doc.wallet-provider.io/vc_type#binanceassociatedaddress",
                "display": [
                    {
                        "name": "Crypto Account Proof",
                        "locale": "en-US",
                        "background_color": "#ed7b76",
                        "text_color": "#FFFFFF",
                    }
                ],
            },
            "AgeProof": {
                "format": "vc+sd-jwt",
                "scope": "AgeProof_scope",
                "order": [
                    "age_equal_or_over", 
                ],
                "claims": {
                        "age_equal_or_over": {
                            "mandatory": True,
                            "value_type": "bool",
                            "display": [{"name": "Age", "locale": "en-US"},
                                        {"name": "Age", "locale": "fr-FR"}],
                            "12": {
                                "mandatory": True,
                                "value_type": "string",
                                "display": [
                                    {"name": "Over 12", "locale": "en-US"},
                                    {"name": "Plus de 12 ans", "locale": "fr-FR"}
                                ],
                            },
                            "14": {
                                "mandatory": True,
                                "value_type": "string",
                                "display": [
                                    {"name": "Over 14", "locale": "en-US"},
                                    {"name": "Plus de 14 ans", "locale": "fr-FR"}
                                ],
                            },
                            "16": {
                                "mandatory": True,
                                "value_type": "string",
                                "display": [
                                    {"name": "Over 16", "locale": "en-US"},
                                    {"name": "Plus de 16 ans", "locale": "fr-FR"}
                                ],
                            },
                            "18": {
                                "mandatory": True,
                                "value_type": "string",
                                "display": [
                                    {"name": "Over 18", "locale": "en-US"},
                                    {"name": "Plus de 18 ans", "locale": "fr-FR"}
                                ],
                            },
                            "21": {
                                "mandatory": True,
                                "value_type": "string",
                                "display": [
                                    {"name": "Over 21", "locale": "en-US"},
                                    {"name": "Plus de 21 ans", "locale": "fr-FR"}
                                ],
                            },
                            "65": {
                                "mandatory": True,
                                "value_type": "string",
                                "display": [
                                    {"name": "Senior", "locale": "en-US"},
                                    {"name": "Senior", "locale": "fr-FR"}
                                ],
                            }
                        }
                    },
                "cryptographic_binding_methods_supported": ["did", "jwk"],
                "credential_signing_alg_values_supported": [
                    "ES256K",
                    "ES256",
                    "EdDSA",
                    "RS256",
                ],
                "vct": "urn:eu.europa.ec.eudi:age_proof:1",
                "display": [
                    {
                        "name": "Age proof",
                        "locale": "en-US",
                        "background_color": "#14107c",
                        "text_color": "#FFFFFF",
                    },
                    {
                        "name": "Preuve d'age",
                        "locale": "fr-FR",
                        "background_color": "#14107c",
                        "text_color": "#FFFFFF",
                    }
                ],
            },
            "Pid": {
                "format": "vc+sd-jwt",
                "scope": "Pid_scope",
                "order": [
                    "given_name",
                    "family_name",
                    "birthdate",
                    "address",
                    "gender",
                    "place_of_birth",
                    "nationalities",
                    "issuing_country",
                    "issuing_authority"
                ],
                "claims": {
                        "given_name": {
                            "value_type": "string",
                            "display": [{"name": "First Name", "locale": "en-US"},
                                        {"name": "Prénom", "locale": "fr-FR"}],
                        },
                        "family_name": {
                            "value_type": "string",
                            "display": [{"name": "Family Name", "locale": "en-US"},
                                        {"name": "Nom", "locale": "fr-FR"}],
                        },
                        "birth_date": {
                            "value_type": "string",
                            "display": [{"name": "Birth date", "locale": "en-US"},
                                        {"name": "Date de naissance", "locale": "fr-FR"}],
                        },
                        "nationality": {
                            "value_type": "string",
                            "display": [{"name": "Nationality", "locale": "en-US"},
                                        {"name": "Nationalité", "locale": "fr-FR"}],
                        },
                        "gender": {
                            "value_type": "number",
                            "display": [{"name": "Gender", "locale": "en-US"},
                                        {"name": "Sexe", "locale": "fr-FR"}],
                        },
                        "age_over_12": {
                                "value_type": "bool",
                                "display": [
                                    {"name": "Over 12", "locale": "en-US"},
                                    {"name": "Plus de 12 ans", "locale": "fr-FR"}],
                        },
                        "age_over_14": {
                                "value_type": "bool",
                                "display": [
                                    {"name": "Over 14", "locale": "en-US"},
                                    {"name": "Plus de 14 ans", "locale": "fr-FR"}],
                        },
                        "age_over_16": {
                                "value_type": "bool",
                                "display": [
                                    {"name": "Over 16", "locale": "en-US"},
                                    {"name": "Plus de 16 ans", "locale": "fr-FR"}],
                        },
                        "age_over_18": {
                                "value_type": "bool",
                                "display": [
                                    {"name": "Over 18", "locale": "en-US"},
                                    {"name": "Plus de 18 ans", "locale": "fr-FR"}],
                        },
                        "age_over_21": {
                                "value_type": "bool",
                                "display": [
                                    {"name": "Over 21", "locale": "en-US"},
                                    {"name": "Plus de 21 ans", "locale": "fr-FR"}],
                        },
                        "age_over_65": {
                                "value_type": "bool",
                                "display": [
                                    {"name": "Senior", "locale": "en-US"},
                                    {"name": "Senior", "locale": "fr-FR"}],
                        },
                        "issuance_date": {
                            "value_type": "string",
                            "display": [{"name": "Issuance date", "locale": "en-US"},
                                        {"name": "Délivré le", "locale": "fr-FR"}],
                        },
                        "issuing_country": {
                            "value_type": "string",
                            "display": [{"name": "Issuing country", "locale": "en-US"},
                                        {"name": "Pays d'emission", "locale": "fr-FR"}],
                        },
                        "issuing_authority": {
                            "value_type": "string",
                            "display": [{"name": "Issuing authority", "locale": "en-US"},
                                        {"name": "Authorité", "locale": "fr-FR"}],
                        }
                    },
                "cryptographic_binding_methods_supported": ["did", "jwk"],
                "credential_signing_alg_values_supported": [
                    "ES256K",
                    "ES256",
                    "EdDSA",
                    "RS256",
                ],
                "vct": "eu.europa.ec.eudi.pid.1",
                "display": [
                    {
                        "name": "Personal ID",
                        "locale": "en-US",
                        "background_color": "#14107c",
                        "text_color": "#FFFFFF",
                    },
                    {
                        "name": "Personal ID",
                        "locale": "fr-FR",
                        "background_color": "#14107c",
                        "text_color": "#FFFFFF",
                    }
                ],
            },
            "EmailPass": {
                "format": "vc+sd-jwt",
                "vct": "talao:issuer:emailpass:1",
                "scope": "EmailPass_scope",
                "cryptographic_binding_methods_supported": ["did", "jwk"],
                "credential_signing_alg_values_supported": [
                    "ES256K",
                    "ES256",
                    "EdDSA",
                    "RS256",
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
                "claims": {
                    "email": {
                        "mandatory": True,
                        "value_type": "string",
                        "display": [
                            {"name": "Email", "locale": "en-US"},
                            {"name": "Email", "locale": "fr-FR"}
                        ],
                    },
                }
            },
            "PhoneProof": {
                "format": "vc+sd-jwt",
                "scope": "PhoneProof_scope",
                "vct": "talao:issuer:phoneproof:1",
                "claims": {
                    "phone": {
                        "mandatory": True,
                        "value_type": "string",
                        "display": [
                            {"name": "Phone", "locale": "en-US"},
                            {"name": "Numérole de téléphone", "locale": "fr-FR"}
                        ],
                    },
                },
                "cryptographic_binding_methods_supported": ["did", "jwk"],
                "credential_signing_alg_values_supported": [
                    "ES256K",
                    "ES256",
                    "EdDSA",
                    "RS256",
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