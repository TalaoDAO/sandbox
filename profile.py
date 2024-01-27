profile = {
    "EBSI-V3":
        {
            "oidc4vciDraft" : "10",
            "siopv2Draft": "12",
            "oidc4vpDraft": "13",
            "vc_format": "jwt_vc",
            "verifier_vp_type": "jwt_vp",
            "authorization_server_support": True,
            "credentials_as_json_object_array": True,
            "pre-authorized_code_as_jwt": True,
            "schema_for_type": False,
            "credential_manifest_support": False,
            "oidc4vci_prefix": "openid-credential-offer://",
            "siopv2_prefix": "openid-vc://",
            "oidc4vp_prefix": "openid-vc://",
            "credentials_types_supported": ["VerifiableDiploma",  "VerifiableId", "EmailPass"],
            "credentials_supported": [
                {
                    "format": "jwt_vc",
                    "types": [
                        "VerifiableCredential",
                        "VerifiableAttestation",
                        "VerifiableDiploma"
                    ],
                    "cryptographic_binding_methods_supported": [
                        "DID"
                    ],
                    "cryptographic_suites_supported": [
                        "ES256K",
                        "ES256",
                        "ES384",
                        "RS256"
                    ],
                    "display": [
                        {
                            "name": "Verifiable diploma",
                            "locale": "en-GB",
                            "description": "This the official EBSI VC Diploma"
                        }
                    ],
                    "trust_framework": {
                        "name": "ebsi",
                        "type": "Accreditation",
                        "uri": "TIR link towards accreditation"
                    }
                },
                {
                    "format": "jwt_vc",
                    "types": [
                        "VerifiableCredential",
                        "EmailPass"
                    ],
                    "cryptographic_binding_methods_supported": [
                        "DID"
                    ],
                    "cryptographic_suites_supported": [
                        "ES256K",
                        "ES256",
                        "ES384",
                        "RS256"
                    ],
                    "display": [
                        {
                            "name": "Email proof",
                            "description": "This is a verifiable credential",
                            "locale": "en-GB"
                        }
                    ],
                    "trust_framework": {
                        "name": "ebsi",
                        "type": "Accreditation",
                        "uri": "TIR link towards accreditation"
                    }
                },        
                {
                    "format": "jwt_vc",
                    "types": [
                        "VerifiableCredential",
                        "VerifiableAttestation",
                        "VerifiableId"
                    ],
                    "cryptographic_binding_methods_supported": [
                        "DID"
                    ],
                    "cryptographic_suites_supported": [
                        "ES256K",
                        "ES256",
                        "ES384",
                        "RS256"
                    ],
                    "display": [
                        {
                            "name": "Verifiable Id",
                            "description": "This is a verifiable credential",
                            "locale": "en-GB"
                            }
                        ],
                    "trust_framework": {
                        "name": "ebsi",
                        "type": "Accreditation",
                        "uri": "TIR link towards accreditation"
                    }
                }
            ],
            "grant_types_supported": [
                "authorization_code",
                "urn:ietf:params:oauth:grant-type:pre-authorized_code"
            ],
            "trust_framework": {
                "name": "ebsi",
                "type": "Accreditation",
                "uri": "TIR link towards accreditation"
            }
        },
    "DEFAULT":
        {
            "oidc4vciDraft" : "11",
            "siopv2Draft": "12",
            "oidc4vpDraft": "18",
            "vc_format": "ldp_vc",
            "verifier_vp_type": "ldp_vp",
            "oidc4vci_prefix": "openid-credential-offer://" ,
            "authorization_server_support": False,
            "credentials_as_json_object_array": False,
            "schema_for_type": False,
            "credential_manifest_support": True,
            "siopv2_prefix": "openid-vc://",
            "oidc4vp_prefix": "openid-vc://",
            "credentials_types_supported": ["EmployeeCredential",  "EthereumAssociatedAddress", "Over18", "VerifiableId", "EmailPass", "PhoneProof"],
            "trust_framework": {
                "name": "default",
                "type": "Accredition"
            },
            "credentials_supported": [
                {
                    "id": "EmployeeCredential",
                    "format": "ldp_vc",
                    "types": [
                        "VerifiableCredential",
                        "EmployeeCredential"
                    ],
                    "cryptographic_binding_methods_supported": [
                        "DID"
                    ],
                    "cryptographic_suites_supported": [
                        "ES256K",
                        "ES256",
                        "ES384",
                        "RS256"
                    ],
                    "display": [
                        {
                            "name": "Employee Credential",
                            "locale": "en-GB"
                        }
                    ]
                },
                 {
                    "id": "Over18",
                    "format": "ldp_vc",
                    "types": [
                        "VerifiableCredential",
                        "Over18"
                    ],
                    "cryptographic_binding_methods_supported": [
                        "DID"
                    ],
                    "cryptographic_suites_supported": [
                        "ES256K",
                        "ES256",
                        "ES384",
                        "RS256"
                    ],
                    "display": [
                        {
                            "name": "Over 18",
                            "description": "This is a verifiable credential",
                            "locale": "en-GB"
                        }
                    ]
                },
                {
                    "id": "EthereumAssociatedAddress",
                    "format": "ldp_vc",
                    "types": [
                        "VerifiableCredential",
                        "EthereumAssociatedAddress"
                    ],
                    "cryptographic_binding_methods_supported": [
                        "DID"
                    ],
                    "cryptographic_suites_supported": [
                        "ES256K",
                        "ES256",
                        "ES384",
                        "RS256"
                    ],
                    "display": [
                        {
                            "name": "Ethereum Associated Address",
                            "locale": "en-GB"
                        }
                    ]
                },
                {
                    "id": "VerifiableId",
                    "format": "ldp_vc",
                    "types": [
                        "VerifiableCredential",
                        "VerifiableId"
                    ],
                    "cryptographic_binding_methods_supported": [
                        "DID"
                    ],
                    "cryptographic_suites_supported": [
                        "ES256K",
                        "ES256",
                        "ES384",
                        "RS256"
                    ],
                    "display": [
                        {
                            "name": "Verifiable Id",
                            "locale": "en-GB"
                        }
                    ]
                },
                {
                    "id": "EmailPass",
                    "format": "ldp_vc",
                    "types": [
                        "VerifiableCredential",
                        "EmailPass"
                    ],
                    "cryptographic_binding_methods_supported": [
                        "DID"
                    ],
                    "cryptographic_suites_supported": [
                        "ES256K",
                        "ES256",
                        "ES384",
                        "RS256"
                    ],
                    "display": [
                        {
                            "name": "EmailPass",
                            "locale": "en-GB"
                        }
                    ]
                },
                {
                    "id": "PhoneProof",
                    "format": "ldp_vc",
                    "types": [
                        "VerifiableCredential",
                        "PhoneProof"
                    ],
                    "cryptographic_binding_methods_supported": [
                        "DID"
                    ],
                    "cryptographic_suites_supported": [
                        "ES256K",
                        "ES256",
                        "ES384",
                        "RS256"
                    ],
                    "display": [
                        {
                            "name": "Proof of phone number",
                            "locale": "en-GB"
                        }
                    ]
                }
            ],
            "grant_types_supported": [
                "authorization_code",
                "urn:ietf:params:oauth:grant-type:pre-authorized_code"
            ]
        },
    "DEFAULT-JWT":
        {
            "oidc4vciDraft" : "11",
            "siopv2Draft": "12",
            "oidc4vpDraft": "18",
            "vc_format": "jwt_vc_json",
            "verifier_vp_type": "jwt_vp",
            "oidc4vci_prefix": "openid-credential-offer://" ,
            "authorization_server_support": False,
            "credentials_as_json_object_array": False,
            "schema_for_type": False,
            "credential_manifest_support": False,
            "siopv2_prefix": "openid-vc://",
            "oidc4vp_prefix": "openid-vc://",
            "credentials_types_supported": ["EmployeeCredential",  "EthereumAssociatedAddress", "VerifiableId", "Over18", "EmailPass", "PhoneProof"],
            "credentials_supported": [
                {
                    "id": "EmployeeCredential",
                    "format": "jwt_vc_json",
                    "types": [
                        "VerifiableCredential",
                        "EmployeeCredential"
                    ],
                    "cryptographic_binding_methods_supported": [
                        "DID"
                    ],
                    "cryptographic_suites_supported": [
                        "ES256K",
                        "ES256",
                        "ES384",
                        "RS256"
                    ],
                    "display": [
                        {
                            "name": "EmployeeCredential",
                            "description": "This is a verifiable credential",
                            "locale": "en-GB"
                        }
                    ]
                },
                {
                    "id": "EthereumAssociatedAddress",
                    "format": "jwt_vc_json",
                    "types": [
                        "VerifiableCredential",
                        "EthereumAssociatedAddress"
                    ],
                    "cryptographic_binding_methods_supported": [
                        "DID"
                    ],
                    "cryptographic_suites_supported": [
                        "ES256K",
                        "ES256",
                        "ES384",
                        "RS256"
                    ],
                    "display": [
                        {
                            "name": "EthereumAssociatedAddress",
                            "description": "This is a verifiable credential",
                            "locale": "en-GB"
                        }
                    ]
                },
                {
                    "id": "VerifiableId",
                    "format": "jwt_vc_json",
                    "types": [
                        "VerifiableCredential",
                        "VerifiableId"
                    ],
                    "cryptographic_binding_methods_supported": [
                        "DID"
                    ],
                    "cryptographic_suites_supported": [
                        "ES256K",
                        "ES256",
                        "ES384",
                        "RS256"
                    ],
                    "display": [
                        {
                            "name": "Verifiable Id",
                            "description": "This is a verifiable credential",
                            "locale": "en-GB"
                        }
                    ]
                },
                 {
                    "id": "Over18",
                    "format": "jwt_vc_json",
                    "types": [
                        "VerifiableCredential",
                        "Over18"
                    ],
                    "cryptographic_binding_methods_supported": [
                        "DID"
                    ],
                    "cryptographic_suites_supported": [
                        "ES256K",
                        "ES256",
                        "ES384",
                        "RS256"
                    ],
                    "display": [
                        {
                            "name": "Over 18",
                            "description": "This is a verifiable credential",
                            "locale": "en-GB"
                        }
                    ]
                },
                {
                    "id": "EmailPass",
                    "format": "jwt_vc_json",
                    "types": [
                        "VerifiableCredential",
                        "EmailPass"
                    ],
                    "cryptographic_binding_methods_supported": [
                        "DID"
                    ],
                    "cryptographic_suites_supported": [
                        "ES256K",
                        "ES256",
                        "ES384",
                        "RS256"
                    ],
                    "display": [
                        {
                            "name": "EmailPass",
                            "description": "This is a verifiable credential",
                            "locale": "en-GB"
                        }
                    ]
                },
                {
                    "id": "PhoneProof",
                    "format": "jwt_vc_json",
                    "types": [
                        "VerifiableCredential",
                        "PhoneProof"
                    ],
                    "cryptographic_binding_methods_supported": [
                        "DID"
                    ],
                    "cryptographic_suites_supported": [
                        "ES256K",
                        "ES256",
                        "ES384",
                        "RS256"
                    ],
                    "display": [
                        {
                            "name": "Proof of phone number",
                            "description": "This is a verifiable credential",
                            "locale": "en-GB"
                        }
                    ]
                }
            ],
            "grant_types_supported": [
                "authorization_code",
                "urn:ietf:params:oauth:grant-type:pre-authorized_code"
            ]
        },
    "DEFAULT-VC-JWT-OIDC4VCI12":
        {
            "oidc4vciDraft" : "12",
            "siopv2Draft": "12",
            "oidc4vpDraft": "18",
            "vc_format": "jwt_vc_json",
            "verifier_vp_type": "jwt_vp",
            "oidc4vci_prefix": "openid-credential-offer://" ,
            "authorization_server_support": False,
            "credentials_as_json_object_array": False,
            "siopv2_prefix": "openid-vc://",
            "oidc4vp_prefix": "openid-vc://",
            "credentials_types_supported": ["EmployeeCredential",  "VerifiableId", "EmailPass",],
            "credentials_supported": {
                "EmployeeCredential": {
                    "format": "jwt_vc_json",
                    "credential_definition":{
                        "type": [
                            "VerifiableCredential",
                            "EmployeeCredential"
                        ],
                    },
                    "cryptographic_binding_methods_supported": [
                        "DID"
                    ],
                    "cryptographic_suites_supported": [
                        "ES256K",
                        "ES256",
                        "ES384",
                        "RS256"
                    ],
                    "display": [
                        {
                            "name": "Employee Credential",
                            "locale": "en-US",
                            "logo": {
                                "url": "https://exampleuniversity.com/public/logo.png",
                                "alt_text": "a square logo of a university"
                            },
                            "background_color": "#12107c",
                            "text_color": "#FFFFFF"
                        }
                    ]
                },
                "VerifiableId": {
                    "format": "jwt_vc_json",
                    "credential_definition": {
                        "type": [
                            "VerifiableCredential",
                            "VerifiableId"
                        ]
                    },
                    "cryptographic_binding_methods_supported": [
                        "DID"
                    ],
                    "cryptographic_suites_supported": [
                        "ES256K",
                        "ES256",
                        "ES384",
                        "RS256"
                    ],
                    "display": [
                        {
                            "name": "Verifiable Id",
                            "locale": "en-US",
                            "background_color": "#12107c",
                            "text_color": "#FFFFFF"
                        }
                    ]
                },
                "EmailPass" :{
                    "format": "jwt_vc_json",
                    "credential_deifnition" : {
                        "type": [
                            "VerifiableCredential",
                            "EmailPass"
                        ]
                    },
                    "cryptographic_binding_methods_supported": [
                        "DID"
                    ],
                    "cryptographic_suites_supported": [
                        "ES256K",
                        "ES256",
                        "ES384",
                        "RS256"
                    ],
                    "display": [
                        {
                            "name": "EmailPass",
                            "locale": "en-GB"
                        }
                    ]
                }
            },
            "grant_types_supported": [
                "authorization_code",
                "urn:ietf:params:oauth:grant-type:pre-authorized_code"
            ],
            "schema_for_type": False,
            "credential_manifest_support": False
        },
    "DEFAULT-VC-JWT-OIDC4VCI13":
        {
            "oidc4vciDraft" : "13",
            "siopv2Draft": "12",
            "oidc4vpDraft": "18",
            "vc_format": "jwt_vc_json",
            "verifier_vp_type": "jwt_vp",
            "oidc4vci_prefix": "openid-credential-offer://" ,
            "authorization_server_support": False,
            "credentials_as_json_object_array": False,
            "siopv2_prefix": "openid-vc://",
            "oidc4vp_prefix": "openid-vc://",
            "credentials_types_supported": ["EmployeeCredential",  "VerifiableId", "EmailPass",],
            "credential_configurations_supported": {
                "EmployeeCredential": {
                    "format": "jwt_vc_json",
                    "credential_definition":{
                        "type": [
                            "VerifiableCredential",
                            "EmployeeCredential"
                        ],
                    },
                    "cryptographic_binding_methods_supported": [
                        "DID"
                    ],
                    "cryptographic_suites_supported": [
                        "ES256K",
                        "ES256",
                        "ES384",
                        "RS256"
                    ],
                    "display": [
                        {
                            "name": "Employee Credential",
                            "locale": "en-US",
                            "logo": {
                                "url": "https://exampleuniversity.com/public/logo.png",
                                "alt_text": "a square logo of a university"
                            },
                            "background_color": "#12107c",
                            "text_color": "#FFFFFF"
                        }
                    ]
                },
                "VerifiableId": {
                    "format": "jwt_vc_json",
                    "credential_definition": {
                        "type": [
                            "VerifiableCredential",
                            "VerifiableId"
                        ]
                    },
                    "cryptographic_binding_methods_supported": [
                        "DID"
                    ],
                    "cryptographic_suites_supported": [
                        "ES256K",
                        "ES256",
                        "ES384",
                        "RS256"
                    ],
                    "display": [
                        {
                            "name": "Verifiable Id",
                            "locale": "en-US",
                            "background_color": "#12107c",
                            "text_color": "#FFFFFF"
                        }
                    ]
                },
                "EmailPass" :{
                    "format": "jwt_vc_json",
                    "credential_deifnition" : {
                        "type": [
                            "VerifiableCredential",
                            "EmailPass"
                        ]
                    },
                    "cryptographic_binding_methods_supported": [
                        "DID"
                    ],
                    "cryptographic_suites_supported": [
                        "ES256K",
                        "ES256",
                        "ES384",
                        "RS256"
                    ],
                    "display": [
                        {
                            "name": "EmailPass",
                            "locale": "en-GB"
                        }
                    ]
                }
            },
            "grant_types_supported": [
                "authorization_code",
                "urn:ietf:params:oauth:grant-type:pre-authorized_code"
            ],
            "schema_for_type": False,
            "credential_manifest_support": False
        },
    "DIIP":
        {
            "oidc4vciDraft" : "11",
            "siopv2Draft": "12",
            "oidc4vpDraft": "18",
            "vc_format": "jwt_vc_json",
            "verifier_vp_type": "jwt_vp",
            "oidc4vci_prefix": "openid-credential-offer://" ,
            "authorization_server_support": False,
            "credentials_as_json_object_array": False,
            "siopv2_prefix": "openid-vc://",
            "oidc4vp_prefix": "openid-vc://",
            "credentials_types_supported": ["GuestCredential", "PermanentResidentCard", "OpenBadgeCredential", "DBCGuest"],
            "credentials_supported": [
                {
                    "display": [
                        {
                            "name": "DBC Guest (DIIP)",
                            "description": "The DBC Guest credential is a DIIP example.",
                            "background_color": "#3B6F6D",
                            "text_color": "#FFFFFF",
                            "logo": {
                                "url": "https://dutchblockchaincoalition.org/assets/images/icons/Logo-DBC.png",
                                "alt_text": "An orange block shape, with the text Dutch Blockchain Coalition next to it, portraying the logo of the Dutch Blockchain Coalition."
                            },
                            "background_image": {
                                "url": "https://i.ibb.co/CHqjxrJ/dbc-card-hig-res.png",
                                "alt_text": "Connected open cubes in blue with one orange cube as a background of the card"
                            }
                        },
                        {
                            "locale": "en-US",
                            "name": "DBC Guest (DIIP)",
                            "description": "The DBC guest credential is a DIIP example.",
                            "background_color": "#3B6F6D",
                            "text_color": "#FFFFFF",
                            "logo": {
                                "url": "https://dutchblockchaincoalition.org/assets/images/icons/Logo-DBC.png",
                                "alt_text": "An orange block shape, with the text Dutch Blockchain Coalition next to it, portraying the logo of the Dutch Blockchain Coalition."
                            },
                            "background_image": {
                                "url": "https://i.ibb.co/CHqjxrJ/dbc-card-hig-res.png",
                                "alt_text": "Connected open cubes in blue with one orange cube as a background of the card"
                            }
                        },
                        {
                            "locale": "nl-NL",
                            "name": "DBC gast (DIIP)",
                            "description": "De DBC gast credential is een DIIP voorbeeld.",
                            "background_color": "#3B6F6D",
                            "text_color": "#FFFFFF",
                            "logo": {
                                "url": "https://dutchblockchaincoalition.org/assets/images/icons/Logo-DBC.png",
                                "alt_text": "Aaneengesloten open blokken in de kleur blauw, met een blok in de kleur oranje, die tesamen de achtergrond van de kaart vormen."
                            },
                            "background_image": {
                                "url": "https://i.ibb.co/CHqjxrJ/dbc-card-hig-res.png",
                                "alt_text": "Connected open cubes in blue with one orange cube as a background of the card"
                            }
                        }
                    ],
                    "format": "jwt_vc_json",
                    "trust_framework": None,
                    "types": [
                        "VerifiableCredential",
                        "DBCGuest"
                    ],
                    "id": "DBCGuest",
                    "scope": None
                },
                {
                    "display": [
                        {
                            "name": "Example University Degree",
                            "description": "JFF Plugfest 3 OpenBadge (JWT)",
                            "text_color": "#FFFFFF",
                            "background_color": "#1763c1",
                            "logo": {
                                "url": "https://w3c-ccg.github.io/vc-ed/plugfest-1-2022/images/JFF_LogoLockup.png",
                                "alt_text": "Red, magenta and yellow vertical lines with 3 black dots and the text JFF, depicting the Jobs For the Future logo."
                            }
                        },
                        {
                            "locale": "en-US",
                            "name": "Example University Degree",
                            "description": "JFF Plugfest 3 OpenBadge (JWT)",
                            "text_color": "#FFFFFF",
                            "background_color": "#1763c1",
                            "logo": {
                                "url": "https://w3c-ccg.github.io/vc-ed/plugfest-1-2022/images/JFF_LogoLockup.png",
                                "alt_text": "Red, magenta and yellow vertical lines with 3 black dots and the text JFF, depicting the Jobs For the Future logo."
                            }
                        }
                    ],
                    "format": "jwt_vc_json",
                    "trust_framework": None,
                    "types": [
                        "VerifiableCredential",
                        "OpenBadgeCredential"
                    ],
                    "id": "OpenBadgeCredential",
                    "scope": None
                },
                {
                    "display": [
                        {
                            "name": "Permanent Resident Card",
                            "description": "Government of Kakapo (JWT)",
                            "text_color": "#FFFFFF",
                            "background_color": "#3a2d2d",
                            "logo": {
                                "url": "https://i.ibb.co/kJm9Mpx/Screenshot-2023-08-18-000155.png",
                                "alt_text": "White shield with text Government of Kakapo and subtitle Ministry of Foreign Affairs."
                            }
                        },
                        {
                            "locale": "en-US",
                            "name": "Permanent Resident Card",
                            "description": "Government of Kakapo (JWT)",
                            "text_color": "#FFFFFF",
                            "background_color": "#3a2d2d",
                            "logo": {
                                "url": "https://i.ibb.co/kJm9Mpx/Screenshot-2023-08-18-000155.png",
                                "alt_text": "White shield with text Government of Kakapo and subtitle Ministry of Foreign Affairs."
                            }
                        }
                    ],
                    "format": "jwt_vc_json",
                    "trust_framework": None,
                    "types": [
                        "VerifiableCredential",
                        "PermanentResidentCard"
                    ],
                    "id": "PermanentResidentCard",
                    "scope": None
                },
                {
                    "display": [
                        {
                            "name": "Sphereon guest",
                            "description": "Demo credential",
                            "text_color": "#FFFFFF",
                            "background_color": "#1763c1",
                            "background_image": {
                                "url": "https://i.ibb.co/kmfrH4F/tulips.png",
                                "alt_text": "Black and white photo of tulips with one red tulip"
                            },
                            "logo": {
                                "url": "https://i.ibb.co/NWQQ9kt/sphereon-logo.png",
                                "alt_text": "Red square depicting Sphereon logo."
                            }
                        },
                        {
                            "locale": "en-US",
                            "name": "Demo credential",
                            "description": "Sphereon guest credential for demo purposes.",
                            "text_color": "#FFFFFF",
                            "background_image": {
                                "url": "https://i.ibb.co/kmfrH4F/tulips.png",
                                "alt_text": "Black and white photo of tulips with one red tulip"
                            },
                            "logo": {
                                "url": "https://i.ibb.co/NWQQ9kt/sphereon-logo.png",
                                "alt_text": "Red square depicting Sphereon logo."
                            }
                        },
                        {
                            "locale": "nl-NL",
                            "name": "Sphereon gast",
                            "description": "Sphereon gast credential wordt uitgegeven voor demo doeleinden.",
                            "text_color": "#FFFFFF",
                            "background_image": {
                                "url": "https://i.ibb.co/kmfrH4F/tulips.png",
                                "alt_text": "Black and white photo of tulips with one red tulip"
                            },
                            "logo": {
                                "url": "https://i.ibb.co/NWQQ9kt/sphereon-logo.png",
                                "alt_text": "Red square depicting Sphereon logo."
                            }
                        }
                    ],
                    "format": "jwt_vc_json",
                    "trust_framework": None,
                    "types": [
                        "VerifiableCredential",
                        "GuestCredential"
                    ],
                    "id": "GuestCredential",
                    "scope": None
                    }
                ],
                "grant_types_supported": [
                    "authorization_code",
                    "urn:ietf:params:oauth:grant-type:pre-authorized_code"
                ],
                "schema_for_type": False,
                "credential_manifest_support": False
        },
    "GAIN-POC":
        {
            "oidc4vciDraft" : "13",
            "siopv2Draft": "12",
            "oidc4vpDraft": "18",
            "vc_format": "vc+sd-jwt",
            "verifier_vp_type": "jwt_vp",
            "oidc4vci_prefix": "openid-credential-offer://" ,
            "authorization_server_support": False,
            "credentials_as_json_object_array": False,
            "siopv2_prefix": "openid-vc://",
            "oidc4vp_prefix": "openid-vc://",
            "credentials_types_supported": ["IdentityCredential"],
            "credentials_supported": {
                "IdentityCredential": {
                    "format": "vc+sd-jwt",
                    "scope": "identity_credential",
                    "cryptographic_binding_methods_supported": [
                        "jwk",
                        "x5c"
                    ],
                    "cryptographic_suites_supported": [
                        "ES256",
                        "ES384",
                        "ES512",
                        "ES256K"
                    ],
                    "credential_definition": {
                        "vct": "https://credentials.example.com/identity_credential"
                    },
                    "proof_types_supported": [
                        "jwt",
                        "cwt"
                    ],
                    "display": [
                        {
                            "name": "Identity Credential"
                        }
                    ]
                }
            },
            "grant_types_supported": [
                "authorization_code",
                "urn:ietf:params:oauth:grant-type:pre-authorized_code"
            ],
            "schema_for_type": False,
            "credential_manifest_support": False
        },
    "GAIA-X":
        {
            "oidc4vciDraft" : "8",
            "siopv2Draft": "12",
            "oidc4vpDraft": "10",
            "vc_format": "ldp_vc",
            "verifier_vp_type": "ldp_vp",
            "oidc4vci_prefix": "openid-initiate-issuance://" ,
            "siopv2_prefix": "openid://",
            "oidc4vp_prefix": "openid://",
            "authorization_server_support": False,
            "credentials_as_json_object_array": False,
            "credentials_types_supported":  ["EmployeeCredential",  "VerifiableId",  "EmailPass"],
            "credentials_supported": [
                {
                    "id": "EmployeeCredential",
                    "format": "ldp_vc",
                    "types": [
                        "VerifiableCredential",
                        "EmployeeCredential"
                    ],
                    "cryptographic_binding_methods_supported": [
                        "DID"
                    ],
                    "cryptographic_suites_supported": [
                        "ES256K",
                        "ES256",
                        "ES384",
                        "RS256"
                    ],
                    "display": [
                        {
                            "name": "EmployeeCredential",
                            "locale": "en-GB"
                        }
                    ]
                },
                {
                    "id": "VerifiableId",
                    "format": "ldp_vc",
                    "types": [
                        "VerifiableCredential",
                        "VerifiableId"
                    ],
                    "cryptographic_binding_methods_supported": [
                        "DID"
                    ],
                    "cryptographic_suites_supported": [
                        "ES256K",
                        "ES256",
                        "ES384",
                        "RS256"
                    ],
                    "display": [
                        {
                            "name": "Verifiable Id",
                            "locale": "en-GB"
                        }
                    ]
                },
                {
                    "id": "EmailPass",
                    "format": "ldp_vc",
                    "types": [
                        "VerifiableCredential",
                        "EmailPass"
                    ],
                    "cryptographic_binding_methods_supported": [
                        "DID"
                    ],
                    "cryptographic_suites_supported": [
                        "ES256K",
                        "ES256",
                        "ES384",
                        "RS256"
                    ],
                    "display": [
                        {
                            "name": "Proof of email",
                            "locale": "en-GB"
                        }
                    ]
                }
            ],
            "grant_types_supported": [
                "authorization_code",
                "urn:ietf:params:oauth:grant-type:pre-authorized_code"
            ],
            "schema_for_type": False,
            "credential_manifest_support": True
        },
    "HEDERA":
        {   
            "oidc4vciDraft" : "11",
            "siopv2Draft": "12",
            "oidc4vpDraft": "18",
            "verifier_vp_type": "jwt_vp",
            "vc_format": "jwt_vc_json",
            "oidc4vci_prefix": "openid-credential-offer-hedera://",
            "authorization_server_support": False,
            "credentials_as_json_object_array": False,
            "siopv2_prefix": "openid-hedera://",
            "oidc4vp_prefix": "openid-hedera://",
            "credentials_types_supported":  [
                "CetProject",
                "GntProject",
                "Gnt+Project",
                "SdgtProject",
                "RetProject",
                "HotProject",
                "XctProject",
                "GreencypherPass",
                "VerifiableId"
            ],
            "credentials_supported": [
                {
                    "id": "CetProject",
                    "vc_format": "jwt_vc_json-ld",
                    "types": [
                        "VerifiableCredential",
                        "CetProject"
                    ],
                    "cryptographic_binding_methods_supported": [
                        "DID"
                    ],
                    "cryptographic_suites_supported": [
                        "ES256K",
                        "ES256",
                        "RS256"
                    ]
                },
                {
                    "id": "GntProject",
                    "vc_format": "jwt_vc_json",
                    "types": [
                        "VerifiableCredential",
                        "GntProject"
                    ],
                    "cryptographic_binding_methods_supported": [
                        "DID"
                    ],
                    "cryptographic_suites_supported": [
                        "ES256K",
                        "ES256",
                        "RS256"
                    ]
                },
                {
                    "id": "Gnt+Project",
                    "vc_format": "jwt_vc_json",
                    "types": [
                        "VerifiableCredential",
                        "Gnt+Project"
                    ],
                    "cryptographic_binding_methods_supported": [
                        "DID"
                    ],
                    "cryptographic_suites_supported": [
                        "ES256K",
                        "ES256",
                        "RS256"
                    ]
                },
                {
                    "id": "SdgtProject",
                    "vc_format": "jwt_vc_json",
                    "types": [
                        "VerifiableCredential",
                        "SdgtProject"
                    ],
                    "cryptographic_binding_methods_supported": [
                        "DID"
                    ],
                    "cryptographic_suites_supported": [
                        "ES256K",
                        "ES256",
                        "RS256"
                    ]
                },
                 {
                    "id": "RetProject",
                    "vc_format": "jwt_vc_json",
                    "types": [
                        "VerifiableCredential",
                        "RetProject"
                    ],
                    "cryptographic_binding_methods_supported": [
                        "DID"
                    ],
                    "cryptographic_suites_supported": [
                        "ES256K",
                        "ES256",
                        "RS256"
                    ]
                },
                 {
                    "id": "HotProject",
                    "vc_format": "jwt_vc_json",
                    "types": [
                        "VerifiableCredential",
                        "HotProject"
                    ],
                    "cryptographic_binding_methods_supported": [
                        "DID"
                    ],
                    "cryptographic_suites_supported": [
                        "ES256K",
                        "ES256",
                        "RS256"
                    ]
                },
                 {
                    "id": "XctProject",
                    "vc_format": "jwt_vc_json",
                    "types": [
                        "VerifiableCredential",
                        "XctProject"
                    ],
                    "cryptographic_binding_methods_supported": [
                        "DID"
                    ],
                    "cryptographic_suites_supported": [
                        "ES256K",
                        "ES256",
                        "RS256"
                    ]
                },
                {
                    "id": "VerifiableId",
                    "vc_format": "jwt_vc_json",
                    "types": [
                        "VerifiableCredential",
                        "VerifiableId"
                ],
                    "cryptographic_binding_methods_supported": [
                        "DID"
                    ],
                    "cryptographic_suites_supported": [
                        "ES256K",
                        "ES256",
                        "RS256"
                    ]
                },
                {
                    "id": "GreencypherPass",
                    "vc_format": "jwt_vc_json",
                    "types": [
                        "VerifiableCredential",
                        "GreencypherPass"
                ],
                    "cryptographic_binding_methods_supported": [
                        "DID"
                    ],
                    "cryptographic_suites_supported": [
                        "ES256K",
                        "ES256",
                        "RS256"
                    ]
                }
            ],
            "grant_types_supported": [
                "urn:ietf:params:oauth:grant-type:pre-authorized_code"
            ],
            "schema_for_type": False,
            "credential_manifest_support": True
        }

}
