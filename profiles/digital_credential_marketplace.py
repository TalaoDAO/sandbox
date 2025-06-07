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
            "Address",
        ],
        "credential_configurations_supported": {
            "Address": {
                "format": "vc+sd-jwt",
                "scope": "address_scope",
                "order": [
                    "resident_address",
                    "resident_state",
                    "resident_street",
                     "resident_city",
                    "resident_postal_code",
                    "resident_country",
                ],
                "claims": {
                        "resident_address": {
                            "value_type": "string",
                            "display": [{"name": "Address", "locale": "en-US"},
                                        {"name": "Adresse", "locale": "fr-FR"}],
                        },
                        "resident_state": {
                            "value_type": "string",
                            "display": [{"name": "State", "locale": "en-US"},
                                        {"name": "Région", "locale": "fr-FR"}],
                        },
                        "resident_city": {
                            "value_type": "string",
                            "display": [{"name": "City", "locale": "en-US"},
                                        {"name": "Ville", "locale": "fr-FR"}],
                        },
                        "resident_street": {
                            "value_type": "string",
                            "display": [{"name": "Street", "locale": "en-US"},
                                        {"name": "Rue", "locale": "fr-FR"}],
                        },
                        "resident_postal_code": {
                            "value_type": "string",
                            "display": [{"name": "Postal code", "locale": "en-US"},
                                        {"name": "code postal", "locale": "fr-FR"}],
                        },
                        "resident_country": {
                                "value_type": "bool",
                                "display": [
                                    {"name": "Country", "locale": "en-US"},
                                    {"name": "Pays", "locale": "fr-FR"}],
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
                    }
                },
                "cryptographic_binding_methods_supported": ["did", "jwk"],
                "credential_signing_alg_values_supported": [
                    "ES256K",
                    "ES256",
                    "EdDSA",
                    "RS256",
                ],
                "vct": "urn:address.1",
                "display": [
                    {
                        "name": "Proof of Address",
                        "locale": "en-US",
                        "background_color": "#14107c",
                        "text_color": "#FFFFFF",
                    },
                    {
                        "name": "Preuve d'Adresse",
                        "locale": "fr-FR",
                        "background_color": "#14107c",
                        "text_color": "#FFFFFF",
                    }
                ],
            },
          
        "grant_types_supported": [
            "authorization_code",
            "urn:ietf:params:oauth:grant-type:pre-authorized_code",
        ]
    }