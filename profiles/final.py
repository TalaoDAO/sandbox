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
                "ES256"
            ],
            "proof_types_supported": {
                "jwt": {
                    "proof_signing_alg_values_supported": [
                        "ES256",
                    ]
                }
            },
            
            "display": [
                    {
                        "name": "Digital Identity",
                        "locale": "en",
                        "logo": {
                            "uri": "https://edwin-weakhanded-bryan.ngrok-free.dev/marianne.svg",
                            "alt_text": "Identity Digitale"
                        },
                        "background_color": "#81df6e",
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
            "doctype": "eu.europa.ec.eudi.pid.1"
        },
    },
    "grant_types_supported": [
        "authorization_code",
        "urn:ietf:params:oauth:grant-type:pre-authorized_code",
    ],
}
