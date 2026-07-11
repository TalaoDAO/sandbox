FINAL = {
    "oidc4vciDraft": "18",
    "oidc4vpDraft": "29",
    "siopv2Draft": "12",
    "oidc4vci_prefix": "openid-credential-offer://",
    "authorization_server_support": False,
    "credentials_as_json_object_array": False,
    "siopv2_prefix": "openid-vc://",
    "oidc4vp_prefix": "openid-vc://",
    "credentials_types_supported": [
        "AgentOwnership",
        "EmailPass",
        "PhoneProof",
        "Pid",
        "AgeProof",
        "SCA",
        "EmployeeBadge",
        "CryptoAccountProof",
        "eu.europa.ec.eudi.pid.1"
    ],
    "credential_configurations_supported": {
        "eu.europa.ec.eudi.pid.1": {
            "format": "mso_mdoc",
            "scope": "eu.europa.ec.eudi.pid.1",
            "cryptographic_binding_methods_supported": [
                "cose_key"
            ],
            "credential_signing_alg_values_supported": [
                -7
            ],
            "proof_types_supported": {
                "jwt": {
                "proof_signing_alg_values_supported": [
                    "ES256",
                ]
                }
            },
            "credential_metadata": {
                "display": [
                    {
                    "name": "Identité Digitale",
                    "locale": "fr",
                    "logo": {
                        "uri": "https://edwin-weakhanded-bryan.ngrok-free.dev/marianne.svg",
                        "alt_text": "Identité Digitale"
                    },
                    "background_color": "#1b1d22",
                    "text_color": "#ffffff"
                    }
                ],
                "claims": [
                {
                "path": [
                    "eu.europa.ec.eudi.pid.1",
                    "age_birth_year"
                ],
                "display": [
                    {
                    "name": "Birth Year",
                    "locale": "en"
                    },
                    {
                    "name": "Année de naissance",
                    "locale": "fr"
                    }
                ],
                "mandatory": False
                },
                {
                "path": [
                    "eu.europa.ec.eudi.pid.1",
                    "age_in_years"
                ],
                "display": [
                    {
                    "name": "Age in Years",
                    "locale": "en"
                    },
                    {
                    "name": "Âge en années",
                    "locale": "fr"
                    }
                ],
                "mandatory": False
                },
                {
                "path": [
                    "eu.europa.ec.eudi.pid.1",
                    "age_over_16"
                ],
                "display": [
                    {
                    "name": "Over 16 Years Old",
                    "locale": "en"
                    },
                    {
                    "name": "Plus de 16 ans",
                    "locale": "fr"
                    }
                ],
                "mandatory": False
                },
                {
                "path": [
                    "eu.europa.ec.eudi.pid.1",
                    "age_over_18"
                ],
                "display": [
                    {
                    "name": "Over 18 Years Old",
                    "locale": "en"
                    },
                    {
                    "name": "Plus de 18 ans",
                    "locale": "fr"
                    }
                ],
                "mandatory": False
                },
                {
                "path": [
                    "eu.europa.ec.eudi.pid.1",
                    "age_over_20"
                ],
                "display": [
                    {
                    "name": "Over 20 Years Old",
                    "locale": "en"
                    },
                    {
                    "name": "Plus de 20 ans",
                    "locale": "fr"
                    }
                ],
                "mandatory": False
                },
                {
                "path": [
                    "eu.europa.ec.eudi.pid.1",
                    "age_over_21"
                ],
                "display": [
                    {
                    "name": "Over 21 Years Old",
                    "locale": "en"
                    },
                    {
                    "name": "Plus de 21 ans",
                    "locale": "fr"
                    }
                ],
                "mandatory": False
                },
                {
                "path": [
                    "eu.europa.ec.eudi.pid.1",
                    "age_over_60"
                ],
                "display": [
                    {
                    "name": "Over 60 Years Old",
                    "locale": "en"
                    },
                    {
                    "name": "Plus de 60 ans",
                    "locale": "fr"
                    }
                ],
                "mandatory": False
                },
                {
                "path": [
                    "eu.europa.ec.eudi.pid.1",
                    "birth_date"
                ],
                "display": [
                    {
                    "name": "Date of Birth",
                    "locale": "en"
                    },
                    {
                    "name": "Date de naissance",
                    "locale": "fr"
                    }
                ],
                "mandatory": False
                },
                {
                "path": [
                    "eu.europa.ec.eudi.pid.1",
                    "birth_place"
                ],
                "display": [
                    {
                    "name": "Place of Birth",
                    "locale": "en"
                    },
                    {
                    "name": "Lieu de naissance",
                    "locale": "fr"
                    }
                ],
                "mandatory": False
                },
                {
                "path": [
                    "eu.europa.ec.eudi.pid.1",
                    "document_number"
                ],
                "display": [
                    {
                    "name": "Document Number",
                    "locale": "en"
                    },
                    {
                    "name": "Numéro de document",
                    "locale": "fr"
                    }
                ],
                "mandatory": False
                },
                {
                "path": [
                    "eu.europa.ec.eudi.pid.1",
                    "email_address"
                ],
                "display": [
                    {
                    "name": "Email Address",
                    "locale": "en"
                    },
                    {
                    "name": "Adresse e-mail",
                    "locale": "fr"
                    }
                ],
                "mandatory": False
                },
                {
                "path": [
                    "eu.europa.ec.eudi.pid.1",
                    "expiry_date"
                ],
                "display": [
                    {
                    "name": "Expiry Date",
                    "locale": "en"
                    },
                    {
                    "name": "Date d'expiration",
                    "locale": "fr"
                    }
                ],
                "mandatory": False
                },
                {
                "path": [
                    "eu.europa.ec.eudi.pid.1",
                    "family_name"
                ],
                "display": [
                    {
                    "name": "Family Name",
                    "locale": "en"
                    },
                    {
                    "name": "Nom de famille",
                    "locale": "fr"
                    }
                ],
                "mandatory": False
                },
                {
                "path": [
                    "eu.europa.ec.eudi.pid.1",
                    "family_name_birth"
                ],
                "display": [
                    {
                    "name": "Family Name at Birth",
                    "locale": "en"
                    },
                    {
                    "name": "Nom de famille à la naissance",
                    "locale": "fr"
                    }
                ],
                "mandatory": False
                },
                {
                "path": [
                    "eu.europa.ec.eudi.pid.1",
                    "given_name"
                ],
                "display": [
                    {
                    "name": "Given Name",
                    "locale": "en"
                    },
                    {
                    "name": "Prénom",
                    "locale": "fr"
                    }
                ],
                "mandatory": False
                },
                {
                "path": [
                    "eu.europa.ec.eudi.pid.1",
                    "given_name_birth"
                ],
                "display": [
                    {
                    "name": "Given Name at Birth",
                    "locale": "en"
                    },
                    {
                    "name": "Prénom à la naissance",
                    "locale": "fr"
                    }
                ],
                "mandatory": False
                },
                {
                "path": [
                    "eu.europa.ec.eudi.pid.1",
                    "issuance_date"
                ],
                "display": [
                    {
                    "name": "Issuance Date",
                    "locale": "en"
                    },
                    {
                    "name": "Date de délivrance",
                    "locale": "fr"
                    }
                ],
                "mandatory": False
                },
                {
                "path": [
                    "eu.europa.ec.eudi.pid.1",
                    "issuing_authority"
                ],
                "display": [
                    {
                    "name": "Issuing Authority",
                    "locale": "en"
                    },
                    {
                    "name": "Autorité de délivrance",
                    "locale": "fr"
                    }
                ],
                "mandatory": False
                },
                {
                "path": [
                    "eu.europa.ec.eudi.pid.1",
                    "issuing_country"
                ],
                "display": [
                    {
                    "name": "Issuing Country",
                    "locale": "en"
                    },
                    {
                    "name": "Pays de délivrance",
                    "locale": "fr"
                    }
                ],
                "mandatory": False
                },
                {
                "path": [
                    "eu.europa.ec.eudi.pid.1",
                    "issuing_jurisdiction"
                ],
                "display": [
                    {
                    "name": "Issuing Jurisdiction",
                    "locale": "en"
                    },
                    {
                    "name": "Juridiction de délivrance",
                    "locale": "fr"
                    }
                ],
                "mandatory": False
                },
                {
                "path": [
                    "eu.europa.ec.eudi.pid.1",
                    "mobile_phone_number"
                ],
                "display": [
                    {
                    "name": "Mobile Phone Number",
                    "locale": "en"
                    },
                    {
                    "name": "Numéro de téléphone mobile",
                    "locale": "fr"
                    }
                ],
                "mandatory": False
                },
                {
                "path": [
                    "eu.europa.ec.eudi.pid.1",
                    "nationality"
                ],
                "display": [
                    {
                    "name": "Nationalities",
                    "locale": "en"
                    },
                    {
                    "name": "Nationalités",
                    "locale": "fr"
                    }
                ],
                "mandatory": False
                },
                {
                "path": [
                    "eu.europa.ec.eudi.pid.1",
                    "personal_administrative_number"
                ],
                "display": [
                    {
                    "name": "Personal Administrative Number",
                    "locale": "en"
                    },
                    {
                    "name": "Numéro administratif personnel",
                    "locale": "fr"
                    }
                ],
                "mandatory": False
                },
                {
                "path": [
                    "eu.europa.ec.eudi.pid.1",
                    "portrait"
                ],
                "display": [
                    {
                    "name": "Portrait",
                    "locale": "en"
                    },
                    {
                    "name": "Portrait",
                    "locale": "fr"
                    }
                ],
                "mandatory": False
                },
                {
                "path": [
                    "eu.europa.ec.eudi.pid.1",
                    "resident_address"
                ],
                "display": [
                    {
                    "name": "Residential Address",
                    "locale": "en"
                    },
                    {
                    "name": "Adresse de résidence",
                    "locale": "fr"
                    }
                ],
                "mandatory": False
                },
                {
                "path": [
                    "eu.europa.ec.eudi.pid.1",
                    "resident_city"
                ],
                "display": [
                    {
                    "name": "Residential City",
                    "locale": "en"
                    },
                    {
                    "name": "Ville de résidence",
                    "locale": "fr"
                    }
                ],
                "mandatory": False
                },
                {
                "path": [
                    "eu.europa.ec.eudi.pid.1",
                    "resident_country"
                ],
                "display": [
                    {
                    "name": "Residential Country",
                    "locale": "en"
                    },
                    {
                    "name": "Pays de résidence",
                    "locale": "fr"
                    }
                ],
                "mandatory": False
                },
                {
                "path": [
                    "eu.europa.ec.eudi.pid.1",
                    "resident_house_number"
                ],
                "display": [
                    {
                    "name": "House Number",
                    "locale": "en"
                    },
                    {
                    "name": "Numéro de maison",
                    "locale": "fr"
                    }
                ],
                "mandatory": False
                },
                {
                "path": [
                    "eu.europa.ec.eudi.pid.1",
                    "resident_postal_code"
                ],
                "display": [
                    {
                    "name": "Postal Code",
                    "locale": "en"
                    },
                    {
                    "name": "Code postal",
                    "locale": "fr"
                    }
                ],
                "mandatory": False
                },
                {
                "path": [
                    "eu.europa.ec.eudi.pid.1",
                    "resident_state"
                ],
                "display": [
                    {
                    "name": "Residential State",
                    "locale": "en"
                    },
                    {
                    "name": "État de résidence",
                    "locale": "fr"
                    }
                ],
                "mandatory": False
                },
                {
                "path": [
                    "eu.europa.ec.eudi.pid.1",
                    "resident_street"
                ],
                "display": [
                    {
                    "name": "Street",
                    "locale": "en"
                    },
                    {
                    "name": "Rue",
                    "locale": "fr"
                    }
                ],
                "mandatory": False
                },
                {
                "path": [
                    "eu.europa.ec.eudi.pid.1",
                    "sex"
                ],
                "display": [
                    {
                    "name": "Sex",
                    "locale": "en"
                    },
                    {
                    "name": "Sexe",
                    "locale": "fr"
                    }
                ],
                "mandatory": False
                },
                {
                "path": [
                    "eu.europa.ec.eudi.pid.1",
                    "trust_anchor"
                ],
                "display": [
                    {
                    "name": "Trust Anchor",
                    "locale": "en"
                    },
                    {
                    "name": "Ancre de confiance",
                    "locale": "fr"
                    }
                ],
                "mandatory": False
                }
            ],
            },
            "doctype": "eu.europa.ec.eudi.pid.1"
        },
        "SCA": {
            "format": "dc+sd-jwt",
            "vct": "eudi:aptitude:crypto:1",
            "scope": "SCA_scope",
            "cryptographic_binding_methods_supported": ["jwk"],
            "credential_signing_alg_values_supported": ["ES256"],
            "proof_types_supported": {
                "jwt": {
                    "proof_signing_alg_values_supported": ["ES256"]
                }
            },
            "credential_metadata": {
                "display": [
                    {
                        "description": "Proof of Tezos crypto ownership for APTITUDE LSP use case",
                        "locale": "en-GB",
                        "background_color": "#1a73e8",
                        "text_color": "#FFFFFF",
                        "background_image": {
                            "uri": "https://talao.co/image/server/tezos-proof.png",
                            "alt_text": "Proof of Tezos crypto background image"
                        }
                    }
                ],
                "claims": [
                    {
                        "path": ["wallet_address"],
                        "display": [
                            {"name": "Address", "locale": "en-US"}
                        ]
                    },
                    {
                        "path": ["blockchain_network"],
                        "display": [
                            {"name": "Blockchain", "locale": "en-US"}
                        ]
                    }
                ]
            }
        },
        "AgentOwnership": {
            "format": "dc+sd-jwt",
            "scope": "AgentOwnership_scope",
            "order": ["owner_name", "owner_website"],
            "credential_metadata": {
                "claims": [
                    {
                        "path": ["owner_name"],
                        "display": [
                            {"name": "Owner " "name", "locale": "en-US"},
                            {"name": "Nom " "du " "fabricant", "locale": "fr-FR"},
                        ],
                    },
                    {
                        "path": ["owner_website"],
                        "display": [
                            {"name": "Website", "locale": "en-US"},
                            {"name": "Site " "web", "locale": "fr-FR"},
                        ],
                    },
                ],
                "display": [
                    {
                        "name": "AI Agent " "ownership",
                        "locale": "en-US",
                        "background_color": "#e2150b",
                        "text_color": "#080808",
                    }
                ],
            },
            "cryptographic_binding_methods_supported": ["did", "jwk"],
            "credential_signing_alg_values_supported": ["ES256", "EdDSA"],
            "proof_types_supported": {
                "jwt": {
                    "proof_signing_alg_values_supported": ["ES256", "EdDSA"]
                }
            },
            "vct": "urn:ai-agent:ownership:0001",
        },
        "CryptoAccountProof": {
            "format": "dc+sd-jwt",
            "scope": "CryptoAccountProof_scope",
            "order": ["blockchain_network", "wallet_address"],
            "credential_metadata": {
                "claims": [
                    {
                        "path": ["blockchain_network"],
                        "display": [
                            {"name": "Blockchain", "locale": "en-US"},
                            {"name": "Blockchain", "locale": "fr-FR"},
                        ],
                    },
                    {
                        "path": ["wallet_address"],
                        "display": [
                            {"name": "Address", "locale": "en-US"},
                            {"name": "Adresse", "locale": "fr-FR"},
                        ],
                    },
                ],
                "display": [
                    {
                        "name": "Crypto " "Account " "Proof",
                        "locale": "en-US",
                        "background_color": "#ed7b76",
                        "text_color": "#FFFFFF",
                        "background_image": {
                            "uri": "https://talao.co/image/server/ethereum-proof.png",
                            "alt_text": "Crypto "
                            "Account "
                            "Proof "
                            "background "
                            "image",
                        },
                    }
                ],
            },
            "cryptographic_binding_methods_supported": ["did", "jwk"],
            "credential_signing_alg_values_supported": [
                "ES256K",
                "ES256",
                "EdDSA",
                "RS256",
            ],
            "proof_types_supported": {
                "jwt": {
                    "proof_signing_alg_values_supported": ["ES256", "EdDSA"]
                }
            },
            "vct": "https://doc.wallet-provider.io/vc_type#binanceassociatedaddress",
        },
        "AgeProof": {
            "format": "dc+sd-jwt",
            "scope": "AgeProof_scope",
            "credential_metadata": {
                "claims": [
                    {
                        "path": ["age_equal_or_over", "12"],
                        "mandatory": True,
                        "display": [
                            {"name": "Over " "12", "locale": "en-US"},
                            {"name": "Plus " "de 12 " "ans", "locale": "fr-FR"},
                        ],
                    },
                    {
                        "path": ["age_equal_or_over", "14"],
                        "mandatory": True,
                        "display": [
                            {"name": "Over " "14", "locale": "en-US"},
                            {"name": "Plus " "de 14 " "ans", "locale": "fr-FR"},
                        ],
                    },
                    {
                        "path": ["age_equal_or_over", "16"],
                        "mandatory": True,
                        "display": [
                            {"name": "Over " "16", "locale": "en-US"},
                            {"name": "Plus " "de 16 " "ans", "locale": "fr-FR"},
                        ],
                    },
                    {
                        "path": ["age_equal_or_over", "18"],
                        "mandatory": True,
                        "display": [
                            {"name": "Over " "18", "locale": "en-US"},
                            {"name": "Plus " "de 18 " "ans", "locale": "fr-FR"},
                        ],
                    },
                    {
                        "path": ["age_equal_or_over", "21"],
                        "mandatory": True,
                        "display": [
                            {"name": "Over " "21", "locale": "en-US"},
                            {"name": "Plus " "de 21 " "ans", "locale": "fr-FR"},
                        ],
                    },
                    {
                        "path": ["age_equal_or_over", "65"],
                        "mandatory": True,
                        "display": [
                            {"name": "Senior", "locale": "en-US"},
                            {"name": "Senior", "locale": "fr-FR"},
                        ],
                    },
                ],
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
                    },
                ],
            },
            "cryptographic_binding_methods_supported": ["did", "jwk"],
            "credential_signing_alg_values_supported": ["ES256", "EdDSA"],
            "proof_types_supported": {
                "jwt": {
                    "proof_signing_alg_values_supported": ["ES256", "EdDSA"]
                }
            },
            "vct": "urn:eu.europa.ec.eudi:age_proof:1",
        },
        "Pid": {
            "format": "dc+sd-jwt",
            "scope": "Pid_scope",
            "credential_metadata": {
                "claims": [
                    {
                        "path": ["given_name"],
                        "display": [
                            {"name": "First Name", "locale": "en-US"},
                            {"name": "Prénom", "locale": "fr-FR"},
                        ],
                    },
                    {
                        "path": ["family_name"],
                        "display": [
                            {"name": "Family Name", "locale": "en-US"},
                            {"name": "Nom", "locale": "fr-FR"},
                        ],
                    },
                    {
                        "path": ["birth_date"],
                        "display": [
                            {"name": "Birth date", "locale": "en-US"},
                            {"name": "Date de " "naissance", "locale": "fr-FR"},
                        ],
                    },
                    {
                        "path": ["nationality"],
                        "display": [
                            {"name": "Nationality", "locale": "en-US"},
                            {"name": "Nationalité", "locale": "fr-FR"},
                        ],
                    },
                    {
                        "path": ["sex"],
                        "display": [
                            {"name": "Gender", "locale": "en-US"},
                            {"name": "Sexe", "locale": "fr-FR"},
                        ],
                    },
                    {
                        "path": ["age_over_12"],
                        "display": [
                            {"name": "Over 12", "locale": "en-US"},
                            {"name": "Plus de 12 " "ans", "locale": "fr-FR"},
                        ],
                    },
                    {
                        "path": ["age_over_14"],
                        "display": [
                            {"name": "Over 14", "locale": "en-US"},
                            {"name": "Plus de 14 " "ans", "locale": "fr-FR"},
                        ],
                    },
                    {
                        "path": ["age_over_16"],
                        "display": [
                            {"name": "Over 16", "locale": "en-US"},
                            {"name": "Plus de 16 " "ans", "locale": "fr-FR"},
                        ],
                    },
                    {
                        "path": ["age_over_18"],
                        "display": [
                            {"name": "Over 18", "locale": "en-US"},
                            {"name": "Plus de 18 " "ans", "locale": "fr-FR"},
                        ],
                    },
                    {
                        "path": ["age_over_21"],
                        "display": [
                            {"name": "Over 21", "locale": "en-US"},
                            {"name": "Plus de 21 " "ans", "locale": "fr-FR"},
                        ],
                    },
                    {
                        "path": ["age_over_65"],
                        "display": [
                            {"name": "Senior", "locale": "en-US"},
                            {"name": "Senior", "locale": "fr-FR"},
                        ],
                    },
                    {
                        "path": ["issuance_date"],
                        "display": [
                            {"name": "Issuance " "date", "locale": "en-US"},
                            {"name": "Délivré le", "locale": "fr-FR"},
                        ],
                    },
                    {
                        "path": ["issuing_country"],
                        "display": [
                            {"name": "Issuing " "country", "locale": "en-US"},
                            {"name": "Pays " "d'emission", "locale": "fr-FR"},
                        ],
                    },
                    {
                        "path": ["issuing_authority"],
                        "display": [
                            {"name": "Issuing " "authority", "locale": "en-US"},
                            {"name": "Authorité", "locale": "fr-FR"},
                        ],
                    },
                ],
                "display": [
                    {
                        "name": "Personal ID",
                        "locale": "en-US",
                        "background_color": "#1a73e8",
                        "text_color": "#FFFFFF",
                    },
                    {
                        "name": "Personal ID",
                        "locale": "fr-FR",
                        "background_color": "#1a73e8",
                        "text_color": "#FFFFFF",
                    },
                ],
            },
            "cryptographic_binding_methods_supported": ["did", "jwk"],
            "credential_signing_alg_values_supported": [
                "ES256",
                "EdDSA"
            ],
            "proof_types_supported": {
                "jwt": {
                    "proof_signing_alg_values_supported": ["ES256", "EdDSA"]
                }
            },
            "vct": "eu.europa.ec.eudi.pcd.1",
        },
        "EmailPass": {
            "format": "dc+sd-jwt",
            "vct": "talao:issuer:emailpass:1",
            "scope": "EmailPass_scope",
            "credential_metadata": {
                "claims": [
                    {
                        "path": ["email"],
                        "mandatory": True,
                        "display": [
                            {"name": "Email", "locale": "en-US"},
                            {"name": "Email", "locale": "fr-FR"},
                        ],
                    }
                ],
                "display": [
                    {
                        "name": "Proof of Email",
                        "description": "Proof of email",
                        "locale": "en-GB",
                        "background_color": "#1a73e8",
                        "text_color": "#FFFFFF",
                        "background_image": {
                            "uri": "https://talao.co/image/server/email-proof.png",
                            "alt_text": "Proof " "of " "email " "background " "image",
                        },
                    },
                    {
                        "name": "Preuve d'adresse email",
                        "description": "Preuve d'adresse email",
                        "locale": "fr-FR",
                        "background_color": "#1a73e8",
                        "text_color": "#FFFFFF",
                        "background_image": {
                            "uri": "https://talao.co/image/server/email-proof.png",
                            "alt_text": "Proof " "of " "email " "background " "image",
                        },
                    },
                ],
            },
            "cryptographic_binding_methods_supported": ["did", "jwk"],
            "credential_signing_alg_values_supported": ["ES256", "EdDSA"],
            "proof_types_supported": {
                "jwt": {
                    "proof_signing_alg_values_supported": ["ES256", "EdDSA"]
                }
            },
        },
        "PhoneProof": {
            "format": "dc+sd-jwt",
            "scope": "PhoneProof_scope",
            "vct": "talao:issuer:phoneproof:1",
            "credential_metadata": {
                "claims": [
                    {
                        "path": ["phone"],
                        "mandatory": True,
                        "display": [
                            {"name": "Phone", "locale": "en-US"},
                            {"name": "Numéro " "de " "téléphone", "locale": "fr-FR"},
                        ],
                    }
                ],
                "display": [
                    {
                        "name": "Proof of phone " "number",
                        "locale": "en-GB",
                        "background_color": "#1a73e8",
                        "text_color": "#FFFFFF",
                        "background_image": {
                            "uri": "https://talao.co/image/server/phone-proof.png",
                            "alt_text": "Proof " "of " "phone " "background " "image",
                        },
                    },
                    {
                        "name": "Preuve de numéro " "de téléphone",
                        "locale": "fr-FR",
                        "background_color": "#1a73e8",
                        "text_color": "#FFFFFF",
                        "background_image": {
                            "uri": "https://talao.co/image/server/phone-proof.png",
                            "alt_text": "Proof " "of " "phone " "background " "image",
                        },
                    },
                ],
            },
            "cryptographic_binding_methods_supported": ["did", "jwk"],
            "credential_signing_alg_values_supported": [
                "ES256K",
                "ES256",
                "EdDSA",
                "RS256",
            ],
            "proof_types_supported": {
                "jwt": {
                    "proof_signing_alg_values_supported": ["ES256", "EdDSA"]
                }
            },
        },
        "EmployeeBadge": {
            "format": "dc+sd-jwt",
            "scope": "EmployeeBadge_scope",
            "credential_metadata": {
                "claims": [
                    {
                        "path": ["id"],
                        "display": [{"name": "Employee " "ID", "locale": "en-US"}],
                    },
                    {
                        "path": ["employee"],
                        "display": [{"name": "Employee " "Details", "locale": "en-US"}],
                    },
                    {
                        "path": ["employee", "employeeId"],
                        "display": [{"name": "Employee " "ID", "locale": "en-US"}],
                    },
                    {
                        "path": ["employee", "jobTitle"],
                        "display": [
                            {"name": "Employee " "Job " "Title", "locale": "en-US"}
                        ],
                    },
                    {
                        "path": ["employee", "department"],
                        "display": [
                            {"name": "Employee " "Department", "locale": "en-US"}
                        ],
                    },
                    {
                        "path": ["employee", "employmentStartDate"],
                        "display": [
                            {"name": "Employee " "Start " "Date", "locale": "en-US"}
                        ],
                    },
                    {
                        "path": ["employee", "employer"],
                        "display": [{"name": "Employer " "Details", "locale": "en-US"}],
                    },
                    {
                        "path": ["employee", "employer", "employerName"],
                        "display": [{"name": "Employer " "Name", "locale": "en-US"}],
                    },
                    {
                        "path": ["employee", "employer", "employerId"],
                        "display": [
                            {"name": "DID " "of " "Employer", "locale": "en-US"}
                        ],
                    },
                ],
                "display": [
                    {
                        "name": "Employee " "Badge",
                        "locale": "en-US",
                        "background_color": "#2c5364",
                        "text_color": "#FFFFFF",
                    },
                    {
                        "name": "Badge " "entreprise",
                        "locale": "fr-FR",
                        "background_color": "#2c5364",
                        "text_color": "#FFFFFF",
                    },
                ],
            },
            "cryptographic_binding_methods_supported": ["did", "jwk"],
            "credential_signing_alg_values_supported": [
                "ES256",
                "EdDSA"
            ],
            "proof_types_supported": {
                "jwt": {
                    "proof_signing_alg_values_supported": ["ES256", "EdDSA"]
                }
            },
            "vct": "urn:eu.europa.ec.eudi:employee_badge:1",
        },
    },
    "grant_types_supported": [
        "authorization_code",
        "urn:ietf:params:oauth:grant-type:pre-authorized_code",
    ],
}
