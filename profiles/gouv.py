GOUV = {
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
        "InsuranceLegalPerson",
    ],
    "credential_configurations_supported": {
        "Kbis": {
            "scope": "Kbis_scope",
            "display": [
                {
                    "name": "Kabis attestation",
                    "description": "Company legal details",
                    "text_color": "#FBFBFB",
                    "logo": {
                        "url": "",
                        "alt_text": "AXA International",
                    },
                    "background_image": {
                        "url": "",
                        "alt_text": "AXA International",
                    },
                },
            ],
            "id": "Kbis",
            "credential_definition": {
                "type": ["VerifiableCredential", "Kbis"],
                "credentialSubject": {
                    "companyName": {
                        "display": [{"name": "Comapny name", "locale": "en-US"}]
                    },
                    "Identifier": {
                        "display": [{"name": "Identifier", "locale": "en-US"}]
                    },
                    "creationDate": {
                        "display": [{"name": "Creation date", "locale": "en-US"}]
                    },
                },
            },
            "format": "jwt_vc_json",
            "cryptographic_binding_methods_supported": ["did:jwk"],
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
