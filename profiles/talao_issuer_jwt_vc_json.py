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
        ],
        "credential_configurations_supported": {
            "EmailPass": {
                "format": "jwt_vc_json",
                "scope": "EmailPass_scope",
                "cryptographic_binding_methods_supported": ["DID", "jwk"],
                "credential_signing_alg_values_supported": [
                    "ES256K",
                    "ES256",
                    "ES384",
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
                 "credential_definition": {
                    "type": ["VerifiableCredential", "EmailPass"],
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
                "format": "jwt_vc_json",
                "scope": "PhoneProof_scope",
                "credential_definition": {
                    "type": ["VerifiableCredential", "PhoneProof"],
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
                    "ES256K",
                    "ES256",
                    "ES384",
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