GOUV = {
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
        "Lpid",
    ],
    "credential_configurations_supported": {
        "Lpid": {
            "vct": "EWC_LPID_Attestation",
            "format": "vc+sd-jwt",
            "scope": "Lpid_scope",
            "claims": {
                "legal_person_id": {
                    "display": [
                        {
                            "name": "The EUID of the company",
                            "locale": "en-GB"
                        }
                    ]
                },
                "legal_person_name": {
                    "display": [
                        {
                            "name": "The name of the company",
                            "locale": "en-GB"
                        }
                    ]
                },
                "issuer_name": {
                    "display": [
                        {
                            "name": "Name of issuer from the MS that issued the ODI instance",
                            "locale": "en-GB"
                        }
                    ]
                },
                "issuer_id": {
                    "display": [
                        {
                            "name": "Id of the issuing authority. (Business register identifier for BRIS)",
                            "locale": "en-GB"
                        }
                    ]
                },
                "issuer_country": {
                    "display": [
                        {
                            "name": "Alpha-2 country code, as defined in ISO 3166-1, of the issuing country",
                            "locale": "en-GB"
                        }
                    ]
                },
                "issuance_date": {
                    "display": [
                        {
                            "name": "Date and possibly time of issuance",
                            "locale": "en-GB"
                        }
                    ]
                },
                "expire_date": {
                    "display": [
                        {
                            "name": "Date and possibly time of expiration",
                            "locale": "en-GB"
                        }
                    ]
                },
                "authentic_source_id": {
                        "display": [
                            {
                                "name": "Source of the issuing (Business register identifier for BRIS, HRB, etc)",
                                "locale": "en-GB"
                            }
                        ]
                },
                "authentic_source_name": {
                        "display": [
                            {
                                "name": "Name of issuer from the MS that issued the instance",
                                "locale": "en-GB"
                            }
                        ]
                },
                "credential_status": {
                        "display": [
                            {
                                "name": "Defines suspension and/or revocation details for the issued credential",
                                "locale": "en-GB"
                            }
                        ]
                },
                "credential_schema": {
                        "display": [
                            {
                                "name": "One or more schemas that validate the Verifiable Credential.",
                                "locale": "en-GB"
                            }
                        ]
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
                "name": "LPID attestation",
                "locale": "en-GB",
                "logo": {
                    "uri": "https://identity-provider.gov/cover.jpeg",
                    "alt_text": "Government Identity Provider"
                },
                "background_color": "#12107c",
                "text_color": "#FFFFFF"
            }
        ]
    }
}
}
        