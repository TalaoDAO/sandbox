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
        ],
        "credential_configurations_supported": {
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