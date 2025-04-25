BANK = {
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
            "IBANLegalPerson",
            "BankAccountBalance"
        ],
        "credential_configurations_supported": {
            "IBANLegalPerson": {
                "display": [
                    {
                        "name": "Company IBAN",
                        "description": "IBAN",
                        "text_color": "#FBFBFB",
                        "logo": {
                            "uri": "",
                            "alt_text": "CCF logo"
                        },
                        "background_image": {
                            "uri": "https://talao.co/static/img/ccf_card.jpeg",
                            "alt_text": "CCF Card"
                        }
                    }
                ],
                "id": "IBANLegalPerson",
                "credential_definition": {
                    "type": [
                        "VerifiableCredential",
                        "IBANLegalPerson"
                    ],
                    "credentialSubject": {
                        "bankName": {
                            "display": [
                                {
                                    "name": "Bank name",
                                    "locale": "en-US"
                                },
                                {
                                    "name": "Bank naam",
                                    "locale": "nl-NL"
                                }
                            ]
                        },
                        "leiCodeBank": {
                            "display": [
                                {
                                    "name": "LEI code",
                                    "locale": "en-US"
                                },
                                {
                                    "name": "LEI code",
                                    "locale": "nl-NL"
                                }
                            ]
                        },
                        "swiftNumber": {
                            "display": [
                                {
                                    "name": "SWIFT code",
                                    "locale": "en-US"
                                },
                                {
                                    "name": "SWIFT code",
                                    "locale": "nl-NL"
                                }
                            ]
                        },
                        "iban": {
                            "display": [
                                {
                                    "name": "IBAN",
                                    "locale": "en-US"
                                },
                                {
                                    "name": "IBAN",
                                    "locale": "nl-NL"
                                }
                            ]
                        },
                        "accountHolder": {
                            "display": [
                                {
                                    "name": "Account Holder",
                                    "locale": "en-US"
                                },
                                {
                                    "name": "Rekeninghouder",
                                    "locale": "nl-NL"
                                }
                            ]
                        }
                    }
                },
                "format": "jwt_vc_json",
                "scope": "IBANLegalPerson_scope",
                "cryptographic_binding_methods_supported": [
                    "did:jwk"
                ],
                "credential_signing_alg_values_supported": [
                    "ES256"
                ],
            },
            "BankAccountBalance": {
                "display": [
                    {
                        "name": "Bank Account Balance",
                        "description": "Bank Account Balance",
                        "text_color": "#FBFBFB",
                        "logo": {
                            "uri": "",
                            "alt_text": "CCF logo"
                        },
                        "background_image": {
                            "uri": "https://talao.co/static/img/ccf_card.jpeg",
                            "alt_text": "CCF Account Balance"
                        }
                    },
                    {
                        "locale": "en-US",
                        "name": "Bank ACcount Balance",
                        "description": "Bank Account Balance",
                        "text_color": "#FBFBFB",
                        "logo": {
                            "uri": "",
                            "alt_text": "CCF logo"
                        },
                        "background_image": {
                            "uri": "https://talao.co/static/img/ccf_card.jpeg",
                            "alt_text": "CCF Account Balance"
                        }
                    }
                ],
                "id": "BankAcountBalance",
                "credential_definition": {
                    "type": [
                        "VerifiableCredential",
                        "BankAccountBalance"
                    ],
                    "credentialSubject": {
                        "bankName": {
                            "display": [
                                {
                                    "name": "Bank name",
                                    "locale": "en-US"
                                },
                                {
                                    "name": "Bank naam",
                                    "locale": "nl-NL"
                                }
                            ]
                        },
                        "leiCodeBank": {
                            "display": [
                                {
                                    "name": "LEI code",
                                    "locale": "en-US"
                                },
                                {
                                    "name": "LEI code",
                                    "locale": "nl-NL"
                                }
                            ]
                        },
                        "swiftNumber": {
                            "display": [
                                {
                                    "name": "SWIFT code",
                                    "locale": "en-US"
                                },
                                {
                                    "name": "SWIFT code",
                                    "locale": "nl-NL"
                                }
                            ]
                        },
                        "iban": {
                            "display": [
                                {
                                    "name": "IBAN",
                                    "locale": "en-US"
                                },
                                {
                                    "name": "IBAN",
                                    "locale": "nl-NL"
                                }
                            ]
                        },
                        "accountBalance": {
                            "display": [
                                {
                                    "name": "Account Balance",
                                    "locale": "en-US"
                                }
                            ]
                        },
                        "currency": {
                            "display": [
                                {
                                    "name": "Currency",
                                    "locale": "en-US"
                                }
                            ]
                        }
                    }
                },
                "format": "jwt_vc_json",
                "scope": "BankAccountBalance_scope",
                "credential_signing_alg_values_supported": [
                    "ES256"
                ],
                "cryptographic_suites_supported": [
                    "ES256"
                ]
            },
        },
        "grant_types_supported": [
            "authorization_code",
            "urn:ietf:params:oauth:grant-type:pre-authorized_code",
        ],
        "schema_for_type": False,
        "credential_manifest_support": False
}
