DOCUMENTATION = {
    "oidc4vciDraft": "13",
    "siopv2Draft": "12",
    "oidc4vpDraft": "18",
    "vc_format": "jwt_vc_json",
    "verifier_vp_type": "jwt_vc_json",
    "oidc4vci_prefix": "openid-credential-offer://",
    "authorization_server_support": False,
    "credentials_as_json_object_array": False,
    "siopv2_prefix": "openid-vc://",
    "oidc4vp_prefix": "openid-vc://",
    "credentials_types_supported": [
        "InsuranceNaturalPerson",
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
                        "alt_text": "AXA International.",
                    },
                    "background_image": {
                        "uri": "https://i.ibb.co/CHqjxrJ/dbc-card-hig-res.png",
                        "alt_text": "AXA International",
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
                        "display": [{"name": "Insurer name", "locale": "en-US"}]
                    },
                    "leiCodeInsurer": {
                        "display": [{"name": "LEI code", "locale": "en-US"}]
                    },
                    "contractId": {
                        "display": [{"name": "Contract Identifier", "locale": "en-US"}]
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
                    "proof_signing_alg_values_supported": ["ES256"]
                }
            },
            "credential_signing_alg_values_supported": [
                "ES256"
            ]
        }
    },
    "grant_types_supported": [
        "authorization_code",
        "urn:ietf:params:oauth:grant-type:pre-authorized_code",
    ],
    "schema_for_type": False,
    "credential_manifest_support": False,
}
