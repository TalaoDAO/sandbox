profile = {
    "EBSI-V3": {
        "oidc4vciDraft": "10",
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
        "credentials_types_supported": [
            "VerifiableDiploma2",
            "VerifiableId",
            "EmailPass",
            "IndividualVerifiableAttestation"
        ],
        "credentials_supported": [
            {
                "format": "jwt_vc",
                "types": [
                    "VerifiableCredential",
                    "VerifiableAttestation",
                    "VerifiableDiploma2",
                ],
                "cryptographic_binding_methods_supported": ["DID"],
                "cryptographic_suites_supported": ["ES256K", "ES256", "ES384", "RS256"],
                "display": [
                    {
                        "name": "EU Diploma",
                        "locale": "en-US",
                        "description": "This the official EBSI VC Diploma",
                        "background_color": "#3B6F6D",
                        "text_color": "#FFFFFF",
                        "logo": {
                            "url": "https://dutchblockchaincoalition.org/assets/images/icons/Logo-DBC.png",
                            "alt_text": "An orange block shape, with the text Dutch Blockchain Coalition next to it, portraying the logo of the Dutch Blockchain Coalition.",
                        },
                        "background_image": {
                            "url": "https://i.ibb.co/CHqjxrJ/dbc-card-hig-res.png",
                            "alt_text": "Connected open cubes in blue with one orange cube as a background of the card",
                        },
                    }
                ],
                "trust_framework": {
                    "name": "ebsi",
                    "type": "Accreditation",
                    "uri": "TIR link towards accreditation",
                },
                "credentialSubject": {
                    "givenNames": {
                        "display": [
                            {"name": "First Name", "locale": "en-US"},
                            {"name": "Prénom", "locale": "fr-FR"},                           
                            ],
                    },
                    "familyName": {
                        "display": [
                            {"name": "Family Name", "locale": "en-US"},
                            {"name": "Nom", "locale": "fr-FR"}
                            ],
                    },
                    "dateOfBirth": {
                        "display": [
                            {"name": "Birth Date", "locale": "en-US"},
                            {"name": "Date de naissance", "locale": "fr-FR"},
                        ],
                    },
                },
            },
            {
                "format": "jwt_vc",
                "types": [
                    "VerifiableCredential",
                    "VerifiableAttestation",
                    "IndividualVerifiableAttestation",
                ],
                "cryptographic_binding_methods_supported": ["DID"],
                "cryptographic_suites_supported": ["ES256K", "ES256", "ES384", "RS256"],
                "display": [
                    {
                        "name": "Individual attestation",
                        "locale": "en-US",
                        "description": "This is the EBSI Individual Verifiable Attestation",
                        "background_color": "#3B6F6D",
                        "text_color": "#FFFFFF"
                    }
                ],
                "trust_framework": {
                    "name": "ebsi",
                    "type": "Accreditation",
                    "uri": "TIR link towards accreditation",
                },
                "credentialSubject": {
                    "firstName": {
                        "display": [
                            {"name": "First Name", "locale": "en-US"},
                            {"name": "Prénom", "locale": "fr-FR"}                    
                        ]
                    },
                    "familyName": {
                        "display": [
                            {"name": "Family Name", "locale": "en-US"},
                            {"name": "Nom", "locale": "fr-FR"}
                        ]
                    },
                    "dateOfBirth": {
                        "display": [
                            {"name": "Birth Date", "locale": "en-US"},
                            {"name": "Date de naissance", "locale": "fr-FR"},
                        ]
                    },
                    "placeOfBirth": {
                        "display": [
                            {"name": "Birth Place", "locale": "en-US"},
                            {"name": "Lieu de naissance", "locale": "fr-FR"},
                        ]
                    },
                    "issuing_country": {
                        "display": [
                            {"name": "Issued by", "locale": "en-US"},
                            {"name": "Délivré par", "locale": "fr-FR"},
                        ],
                    },
                },
            },
            {
                "format": "jwt_vc",
                "types": ["VerifiableCredential", "EmailPass"],
                "cryptographic_binding_methods_supported": ["DID"],
                "cryptographic_suites_supported": ["ES256K", "ES256", "ES384", "RS256"],
                "display": [
                    {
                        "name": "Email proof",
                        "description": "This is a verifiable credential",
                        "locale": "en-GB",
                    }
                ],
                "trust_framework": {
                    "name": "ebsi",
                    "type": "Accreditation",
                    "uri": "TIR link towards accreditation",
                },
            },
            {
                "format": "jwt_vc",
                "types": [
                    "VerifiableCredential",
                    "VerifiableAttestation",
                    "VerifiableId",
                ],
                "cryptographic_binding_methods_supported": ["DID"],
                "cryptographic_suites_supported": ["ES256K", "ES256", "ES384", "RS256"],
                "display": [
                    {
                        "name": "Verifiable Id",
                        "description": "This is a verifiable credential",
                        "locale": "en-GB",
                    }
                ],
                "trust_framework": {
                    "name": "ebsi",
                    "type": "Accreditation",
                    "uri": "TIR link towards accreditation",
                },
            },
        ],
        "grant_types_supported": [
            "authorization_code",
            "urn:ietf:params:oauth:grant-type:pre-authorized_code",
        ],
        "trust_framework": {
            "name": "ebsi",
            "type": "Accreditation",
            "uri": "TIR link towards accreditation",
        },
    },
    "DEFAULT": {
        "oidc4vciDraft": "11",
        "siopv2Draft": "12",
        "oidc4vpDraft": "18",
        "vc_format": "ldp_vc",
        "verifier_vp_type": "ldp_vp",
        "oidc4vci_prefix": "openid-credential-offer://",
        "authorization_server_support": False,
        "credentials_as_json_object_array": False,
        "schema_for_type": False,
        "credential_manifest_support": False,
        "siopv2_prefix": "openid-vc://",
        "oidc4vp_prefix": "openid-vc://",
        "credentials_types_supported": [
            "Over18",
            "Over15",
            "Over13",
            "Over21",
            "Over65",
            "Over50",
            "VerifiableId",
            "EmailPass",
            "PhoneProof",
            "Liveness",
        ],
        "trust_framework": {"name": "default", "type": "Accreditation"},
        "credentials_supported": [
            {
                "id": "Over18",
                "format": "ldp_vc",
                "types": ["VerifiableCredential", "Over18"],
                "cryptographic_binding_methods_supported": ["DID"],
                "cryptographic_suites_supported": ["ES256K", "ES256", "ES384", "RS256"],
                "display": [
                    {
                        "name": "Over 18",
                        "description": "This card is a proof that your are over 18 yo. You can use it when you need to prove your age with services that have already adopted the verifiable and decentralized identity system.",
                        "locale": "en-GB",
                    }
                ],
            },
            {
                "id": "Over15",
                "format": "ldp_vc",
                "types": ["VerifiableCredential", "Over15"],
                "cryptographic_binding_methods_supported": ["DID"],
                "cryptographic_suites_supported": ["ES256K", "ES256", "ES384", "RS256"],
                "display": [
                    {
                        "name": "Over 15",
                        "description": "This card is a proof that your are over 15 yo. You can use it when you need to prove your age with services that have already adopted the verifiable and decentralized identity system.",
                        "locale": "en-GB",
                    }
                ],
            },
            {
                "id": "Over13",
                "format": "ldp_vc",
                "types": ["VerifiableCredential", "Over13"],
                "cryptographic_binding_methods_supported": ["DID"],
                "cryptographic_suites_supported": ["ES256K", "ES256", "ES384", "RS256"],
                "display": [
                    {
                        "name": "Over 13",
                        "description": "This card is a proof that your are over 13 yo. You can use it when you need to prove your age with services that have already adopted the verifiable and decentralized identity system.",
                        "locale": "en-GB",
                    }
                ],
            },
            {
                "id": "Over21",
                "format": "ldp_vc",
                "types": ["VerifiableCredential", "Over21"],
                "cryptographic_binding_methods_supported": ["DID"],
                "cryptographic_suites_supported": ["ES256K", "ES256", "ES384", "RS256"],
                "display": [
                    {
                        "name": "Over 21",
                        "description": "This card is a proof that your are over 21 yo. You can use it when you need to prove your age with services that have already adopted the verifiable and decentralized identity system.",
                        "locale": "en-GB",
                    }
                ],
            },
            {
                "id": "Over50",
                "format": "ldp_vc",
                "types": ["VerifiableCredential", "Over50"],
                "cryptographic_binding_methods_supported": ["DID"],
                "cryptographic_suites_supported": ["ES256K", "ES256", "ES384", "RS256"],
                "display": [
                    {
                        "name": "Over 50",
                        "description": "This card is a proof that your are over 50 yo. You can use it when you need to prove your age with services that have already adopted the verifiable and decentralized identity system.",
                        "locale": "en-GB",
                    }
                ],
            },
            {
                "id": "Over65",
                "format": "ldp_vc",
                "types": ["VerifiableCredential", "Over65"],
                "cryptographic_binding_methods_supported": ["DID"],
                "cryptographic_suites_supported": ["ES256K", "ES256", "ES384", "RS256"],
                "display": [
                    {
                        "name": "Over 65",
                        "description": "This card is a proof that your are over 65 yo. You can use it when you need to prove your age with services that have already adopted the verifiable and decentralized identity system.",
                        "locale": "en-GB",
                    }
                ],
            },
            {
                "id": "Liveness",
                "format": "ldp_vc",
                "types": ["VerifiableCredential", "Liveness"],
                "cryptographic_binding_methods_supported": ["DID"],
                "cryptographic_suites_supported": ["ES256K", "ES256", "ES384", "RS256"],
                "display": [
                    {
                        "name": "Proof of humanity",
                        "description": "This card is a proof that your are a human being",
                        "locale": "en-GB",
                    }
                ],
            },
            {
                "id": "VerifiableId",
                "format": "ldp_vc",
                "types": ["VerifiableCredential", "VerifiableId"],
                "cryptographic_binding_methods_supported": ["DID"],
                "cryptographic_suites_supported": ["ES256K", "ES256", "ES384", "RS256"],
                "display": [
                    {
                        "name": "Verifiable Id",
                        "description": "This credential is a proof of your identity. You can use it when you need to prove your identity with services that have already adopted a decentralized identity system.",
                        "locale": "en-GB",
                    }
                ],
                "credentialSubject": {
                    "firstName": {
                        "mandatory": True,
                        "display": [{"name": "First Name", "locale": "en-US"}],
                    },
                    "familyName": {
                        "mandatory": True,
                        "display": [{"name": "Family Name", "locale": "en-US"}],
                    },
                    "gender": {
                        "mandatory": True,
                        "display": [{"name": "Gender", "locale": "en-US"}],
                    },
                    "dateOfBirth": {
                        "mandatory": True,
                        "display": [{"name": "Birth Date", "locale": "en-US"}],
                    },
                    "dateIssued": {
                        "mandatory": True,
                        "display": [{"name": "Issue Date", "locale": "en-US"}],
                    },
                },
            },
            {
                "id": "EmailPass",
                "format": "ldp_vc",
                "types": ["VerifiableCredential", "EmailPass"],
                "cryptographic_binding_methods_supported": ["DID"],
                "cryptographic_suites_supported": ["ES256K", "ES256", "ES384", "RS256"],
                "display": [
                    {
                        "name": "EmailPass",
                        "description": "This card is a proof of ownership of your email. You can use it when you need to prove your email ownership with services that have already adopted the verifiable and decentralized identity system.",
                        "locale": "en-GB"
                    }
                ],
            },
            {
                "id": "PhoneProof",
                "format": "ldp_vc",
                "types": ["VerifiableCredential", "PhoneProof"],
                "cryptographic_binding_methods_supported": ["DID"],
                "cryptographic_suites_supported": ["ES256K", "ES256", "ES384", "RS256"],
                "display": [
                    {
                        "name": "Proof of phone number",
                        "locale": "en-GB",
                        "description": "This card is a proof of ownership of your phone number. You can use it when you need to prove your email ownership with services that have already adopted the verifiable and decentralized identity system.",
                    }
                ],
            },
        ],
        "grant_types_supported": [
            "authorization_code",
            "urn:ietf:params:oauth:grant-type:pre-authorized_code",
        ],
    },
      "DEFAULT-DRAFT13": {
        "oidc4vciDraft": "13",
        "siopv2Draft": "12",
        "oidc4vpDraft": "20",
        "vc_format": "ldp_vc",
        "verifier_vp_type": "ldp_vp",
        "oidc4vci_prefix": "openid-credential-offer://",
        "authorization_server_support": False,
        "credentials_as_json_object_array": False,
        "schema_for_type": False,
        "credential_manifest_support": False,
        "siopv2_prefix": "openid-vc://",
        "oidc4vp_prefix": "openid-vc://",
        "credentials_types_supported": [
            "Over18",
            "EmailPass",
            "VerifiableId"
        ],
        "trust_framework": {"name": "default", "type": "Accreditation"},
        "credential_configurations_supported": {
            "EmailPass": {
                "format": "ldp_vc",
                "scope": "EmailPass_scope",
                "credential_definition": {
                    "type": ["VerifiableCredential", "EmailPass", "VerifiableId"]
                },
                "cryptographic_binding_methods_supported": ["DID", "jwk"],
                "credential_signing_alg_values_supported": [
                    "ES256K",
                    "ES256",
                    "ES384",
                    "RS256",
                ],
                "display": [{"name": "Proof of Email", "locale": "en-US"}],
                "credentialSubject": {
                        "email": {
                            "mandatory": True,
                            "display": [
                                {"name": "Email", "locale": "en-US"},
                                {"name": "Email", "locale": "fr-FR"}         
                            ],
                        }
                },
            },
            "VerifiableId" : {
                "format": "ldp_vc",
                "credential_definition": {
                    "type": ["VerifiableCredential", "VerifiableId"]
                },
                "cryptographic_binding_methods_supported": ["DID"],
                   "credential_signing_alg_values_supported": [
                    "ES256K",
                    "ES256",
                    "ES384",
                    "RS256",
                ],
                "display": [
                    {
                        "name": "Verifiable Id",
                        "description": "This credential is a proof of your identity. You can use it when you need to prove your identity with services that have already adopted a decentralized identity system.",
                        "locale": "en-GB",
                    }
                ],
                "credentialSubject": {
                    "firstName": {
                        "mandatory": True,
                        "display": [{"name": "First Name", "locale": "en-US"}],
                    },
                    "familyName": {
                        "mandatory": True,
                        "display": [{"name": "Family Name", "locale": "en-US"}],
                    },
                    "gender": {
                        "mandatory": True,
                        "display": [{"name": "Gender", "locale": "en-US"}],
                    },
                    "dateOfBirth": {
                        "mandatory": True,
                        "display": [{"name": "Birth Date", "locale": "en-US"}],
                    },
                    "dateIssued": {
                        "mandatory": True,
                        "display": [{"name": "Issue Date", "locale": "en-US"}],
                    },
                },
            },
             "Over18": {
                "format": "ldp_vc",
                "scope": "Over18_scope",
                "credential_definition": {
                    "type": ["VerifiableCredential", "Over18"]
                },
                "cryptographic_binding_methods_supported": ["DID", "jwk"],
                "credential_signing_alg_values_supported": [
                    "ES256K",
                    "ES256",
                    "ES384",
                    "RS256",
                ],
                "display": [
                    {"name": "Over 18yo proof", "locale": "en-US"}, 
                    {"name": "Preuve de majorité", "locale": "fr-US"}
                ],
            },
        },
        "grant_types_supported": [
            "authorization_code",
            "urn:ietf:params:oauth:grant-type:pre-authorized_code",
        ],
    },
    "DEFAULT-JWT": {
        "oidc4vciDraft": "11",
        "siopv2Draft": "12",
        "oidc4vpDraft": "18",
        "vc_format": "jwt_vc_json",
        "verifier_vp_type": "jwt_vp_json",
        "oidc4vci_prefix": "openid-credential-offer://",
        "authorization_server_support": False,
        "credentials_as_json_object_array": False,
        "schema_for_type": False,
        "credential_manifest_support": False,
        "siopv2_prefix": "openid-vc://",
        "oidc4vp_prefix": "openid-vc://",
        "credentials_types_supported": [
            "Over18",
            "Over15",
            "Over13",
            "Over21",
            "Over65",
            "Over50",
            "VerifiableId",
            "EmailPass",
            "PhoneProof",
            "Liveness",
        ],
        "credentials_supported": [
            {
                "id": "VerifiableId",
                "format": "jwt_vc_json",
                "types": ["VerifiableCredential", "VerifiableId"],
                "cryptographic_binding_methods_supported": ["DID"],
                "cryptographic_suites_supported": ["ES256K", "ES256", "ES384", "RS256"],
                "display": [
                    {
                        "name": "Verifiable Id",
                        "description": "This card is a proof of your identity. You can use it when you need to prove your email ownership with services that have already adopted the verifiable and decentralized identity system.",
                        "locale": "en-GB",
                    }
                ],
                "credentialSubject": {
                    "firstName": {
                        "mandatory": True,
                        "display": [{"name": "First Name", "locale": "en-US"}],
                    },
                    "familyName": {
                        "mandatory": True,
                        "display": [{"name": "Family Name", "locale": "en-US"}],
                    },
                    "dateOfBirth": {
                        "mandatory": True,
                        "display": [{"name": "Date of Birth", "locale": "en-US"}],
                    },
                    "gender": {
                        "mandatory": True,
                        "display": [{"name": "Gender", "locale": "en-US"}],
                    }
                }
            },
            {
                "id": "Over13",
                "format": "jwt_vc_json",
                "types": ["VerifiableCredential", "Over13"],
                "cryptographic_binding_methods_supported": ["DID"],
                "cryptographic_suites_supported": ["ES256K", "ES256", "ES384", "RS256"],
                "display": [
                    {
                        "name": "Over 13",
                        "description": "This card is a proof that your are over 13 yo. You can use it when you need to prove your age with services that have already adopted the verifiable and decentralized identity system.",
                        "locale": "en-GB",
                    }
                ],
            },
            {
                "id": "Over15",
                "format": "jwt_vc_json",
                "types": ["VerifiableCredential", "Over15"],
                "cryptographic_binding_methods_supported": ["DID"],
                "cryptographic_suites_supported": ["ES256K", "ES256", "ES384", "RS256"],
                "display": [
                    {
                        "name": "Over 15",
                        "description": "This card is a proof that your are over 15 yo. You can use it when you need to prove your age with services that have already adopted the verifiable and decentralized identity system.",
                        "locale": "en-GB",
                    }
                ],
            },
            {
                "id": "Over18",
                "format": "jwt_vc_json",
                "types": ["VerifiableCredential", "Over18"],
                "cryptographic_binding_methods_supported": ["DID"],
                "cryptographic_suites_supported": ["ES256K", "ES256", "ES384", "RS256"],
                "display": [
                    {
                        "name": "Over 18",
                        "description": "This card is a proof that your are over 18 yo. You can use it when you need to prove your age with services that have already adopted the verifiable and decentralized identity system.",
                        "locale": "en-GB",
                    }
                ],
            },
            {
                "id": "Over21",
                "format": "jwt_vc_json",
                "types": ["VerifiableCredential", "Over21"],
                "cryptographic_binding_methods_supported": ["DID"],
                "cryptographic_suites_supported": ["ES256K", "ES256", "ES384", "RS256"],
                "display": [
                    {
                        "name": "Over 21",
                        "description": "This card is a proof that your are over 21 yo. You can use it when you need to prove your age with services that have already adopted the verifiable and decentralized identity system.",
                        "locale": "en-GB",
                    }
                ],
            },
            {
                "id": "Over50",
                "format": "jwt_vc_json",
                "types": ["VerifiableCredential", "Over50"],
                "cryptographic_binding_methods_supported": ["DID"],
                "cryptographic_suites_supported": ["ES256K", "ES256", "ES384", "RS256"],
                "display": [
                    {
                        "name": "Over 50",
                        "description": "This card is a proof that your are over 50 yo. You can use it when you need to prove your age with services that have already adopted the verifiable and decentralized identity system.",
                        "locale": "en-GB",
                    }
                ],
            },
            {
                "id": "Over65",
                "format": "jwt_vc_json",
                "types": ["VerifiableCredential", "Over65"],
                "cryptographic_binding_methods_supported": ["DID"],
                "cryptographic_suites_supported": ["ES256K", "ES256", "ES384", "RS256"],
                "display": [
                    {
                        "name": "Over 65",
                        "description": "This card is a proof that your are over 65 yo. You can use it when you need to prove your age with services that have already adopted the verifiable and decentralized identity system.",
                        "locale": "en-GB",
                    }
                ],
            },
            {
                "id": "Liveness",
                "format": "jwt_vc_json",
                "types": ["VerifiableCredential", "Liveness"],
                "cryptographic_binding_methods_supported": ["DID"],
                "cryptographic_suites_supported": ["ES256K", "ES256", "ES384", "RS256"],
                "display": [
                    {
                        "name": "Proof of HUmanity",
                        "description": "This card is a proof that your are a human being.",
                        "locale": "en-GB",
                    }
                ],
            },
            {
                "id": "EmailPass",
                "format": "jwt_vc_json",
                "types": ["VerifiableCredential", "EmailPass"],
                "cryptographic_binding_methods_supported": ["DID"],
                "cryptographic_suites_supported": ["ES256K", "ES256", "ES384", "RS256"],
                "display": [
                    {
                        "name": "EmailPass",
                        "description": "This card is a proof of ownership of your email. You can use it when you need to prove your email ownership with services that have already adopted the verifiable and decentralized identity system.",
                        "locale": "en-GB",
                    }
                ]
            },
            {
                "id": "PhoneProof",
                "format": "jwt_vc_json",
                "types": ["VerifiableCredential", "PhoneProof"],
                "cryptographic_binding_methods_supported": ["DID"],
                "cryptographic_suites_supported": ["ES256K", "ES256", "ES384", "RS256"],
                "display": [
                    {
                        "name": "Proof of phone number",
                        "description": "This card is a proof of ownership of your phone number. You can use it when you need to prove your email ownership with services that have already adopted the verifiable and decentralized identity system.",
                        "locale": "en-GB",
                    }
                ],
            },
        ],
        "grant_types_supported": [
            "authorization_code",
            "urn:ietf:params:oauth:grant-type:pre-authorized_code",
        ],
    },
    "DEFAULT-VC-JWT-OIDC4VCI13": {
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
            "EmployeeCredential",
            "VerifiableId",
            "EmailPass",
            "PhoneProof",
            "Over18",
            "DBCGuest"
        ],
        "credential_configurations_supported": {
            "DBCGuest": {
                "display": [
                    {
                        "name": "DBC Guest (DIIP)",
                        "description": "The DBC Guest credential is a DIIP example.",
                        "background_color": "#3B6F6D",
                        "text_color": "#FFFFFF",
                        "logo": {
                            "url": "https://dutchblockchaincoalition.org/assets/images/icons/Logo-DBC.png",
                            "alt_text": "An orange block shape, with the text Dutch Blockchain Coalition next to it, portraying the logo of the Dutch Blockchain Coalition.",
                        },
                        "background_image": {
                            "url": "https://i.ibb.co/CHqjxrJ/dbc-card-hig-res.png",
                            "alt_text": "Connected open cubes in blue with one orange cube as a background of the card",
                        },
                    },
                    {
                        "locale": "en-US",
                        "name": "DBC Guest (DIIP)",
                        "description": "The DBC guest credential is a DIIP example.",
                        "background_color": "#3B6F6D",
                        "text_color": "#FFFFFF",
                        "logo": {
                            "url": "https://dutchblockchaincoalition.org/assets/images/icons/Logo-DBC.png",
                            "alt_text": "An orange block shape, with the text Dutch Blockchain Coalition next to it, portraying the logo of the Dutch Blockchain Coalition.",
                        },
                        "background_image": {
                            "url": "https://i.ibb.co/CHqjxrJ/dbc-card-hig-res.png",
                            "alt_text": "Connected open cubes in blue with one orange cube as a background of the card",
                        },
                    },
                    {
                        "locale": "nl-NL",
                        "name": "DBC gast (DIIP)",
                        "description": "De DBC gast credential is een DIIP voorbeeld.",
                        "background_color": "#3B6F6D",
                        "text_color": "#FFFFFF",
                        "logo": {
                            "url": "https://dutchblockchaincoalition.org/assets/images/icons/Logo-DBC.png",
                            "alt_text": "Aaneengesloten open blokken in de kleur blauw, met een blok in de kleur oranje, die tesamen de achtergrond van de kaart vormen.",
                        },
                        "background_image": {
                            "url": "https://i.ibb.co/CHqjxrJ/dbc-card-hig-res.png",
                            "alt_text": "Connected open cubes in blue with one orange cube as a background of the card",
                        },
                    },
                ],
                "format": "jwt_vc_json",
                "credential_definition": {
                    "type": ["VerifiableCredential", "DBCGuest"]
                },
                "scope": "DBCGuest_scope",
            },   
            "EmployeeCredential": {
                "format": "jwt_vc_json",
                "scope": "EmployeeCredential_scope",
                "credential_definition": {
                    "type": ["VerifiableCredential", "EmployeeCredential"]
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
                        "name": "Employee Credential",
                        "locale": "en-US",
                        "logo": {
                            "url": "https://exampleuniversity.com/public/logo.png",
                            "alt_text": "a square logo of a university",
                        },
                        "background_color": "#12107c",
                        "text_color": "#FFFFFF",
                    }
                ],
            },
            "VerifiableId": {
                "format": "jwt_vc_json",
                "scope": "VerifiableId_scope",
                "credential_definition": {
                    "type": ["VerifiableCredential", "VerifiableId"],
                    "order": [
                        "firstName",
                        "familyName",
                        "dateOfBirth",
                        "gender",
                        "dateIssued",
                        "issuing_country",
                        "email",
                        "phone_number"
                    ],
                    "credentialSubject": {
                        "firstName": {
                            "mandatory": True,
                            "display": [
                                {"name": "First name", "locale": "en-US"},
                                {"name": "Prénom(s)", "locale": "fr-FR"}         
                            ],
                        },
                        "familyName": {
                            "mandatory": True,
                            "display": [
                                {"name": "Family name", "locale": "en-US"},
                                {"name": "Nom", "locale": "fr-FR"}                                
                            ],
                        },
                        "dateOfBirth": {
                            "mandatory": True,
                            "display": [
                                {"name": "Date of birth", "locale": "en-US"},
                                {"name": "Né(e) le", "locale": "fr-FR"}
                            ],
                        },
                        "email": {
                            "mandatory": True,
                            "display": [
                                {"name": "Email", "locale": "en-US"},
                                {"name": "Email", "locale": "fr-FR"}
                            ],
                        },
                        "phone_number": {
                            "mandatory": True,
                            "display": [
                                {"name": "Phone number", "locale": "en-US"},
                                {"name": "Téléphone", "locale": "fr-FR"}
                            ],
                        },
                         "gender": {
                            "mandatory": True,
                            "display": [
                                {"name": "Gender", "locale": "en-US"},
                                {"name": "Sexe", "locale": "fr-FR"}
                            ],
                        },
                         "issuing_country": {
                            "mandatory": True,
                            "display": [
                                {"name": "Issuing country", "locale": "en-US"},
                                {"name": "Délivré par", "locale": "fr-FR"}
                            ],
                        },
                         "dateIssued": {
                            "mandatory": True,
                            "display": [
                                {"name": "Issuance date", "locale": "en-US"},
                                {"name": "Délivré le", "locale": "fr-FR"}
                            ],
                        },
                    },
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
                        "name": "Verifiable Id",
                        "locale": "en-US",
                        "background_color": "#12107c",
                        "text_color": "#FFFFFF",
                    }
                ],
            },
            "EmailPass": {
                "format": "jwt_vc_json",
                "scope": "EmailPass_scope",
                "credential_definition": {
                    "type": ["VerifiableCredential", "EmailPass"]
                },
                "cryptographic_binding_methods_supported": ["DID", "jwk"],
                "credential_signing_alg_values_supported": [
                    "ES256K",
                    "ES256",
                    "ES384",
                    "RS256",
                ],
                "display": [{"name": "Proof of Email", "locale": "en-GB"}],
            },
             "Over18": {
                "format": "jwt_vc_json",
                "scope": "Over18_scope",
                "credential_definition": {
                    "type": ["VerifiableCredential", "Over18"]
                },
                "cryptographic_binding_methods_supported": ["DID", "jwk"],
                "credential_signing_alg_values_supported": [
                    "ES256K",
                    "ES256",
                    "ES384",
                    "RS256",
                ],
                "display": [
                    {"name": "Over 18yo proof", "locale": "en-GB"}, 
                    {"name": "Preuve de majorité", "locale": "fr-GB"}
                ],
            },
            "PhoneProof": {
                "format": "jwt_vc_json",
                "scope": "PhoneProof_scope",
                "credential_definition": {
                    "type": ["VerifiableCredential", "PhoneProof"]
                },
                "cryptographic_binding_methods_supported": ["DID", "jwk"],
                "credential_signing_alg_values_supported": [
                    "ES256K",
                    "ES256",
                    "ES384",
                    "RS256",
                ],
                "display": [{"name": "Proof of phone number", "locale": "en-GB"}],
            },
        },
        "grant_types_supported": [
            "authorization_code",
            "urn:ietf:params:oauth:grant-type:pre-authorized_code",
        ],
        "schema_for_type": False,
        "credential_manifest_support": False,
    },
    "BASELINE": {
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
        "credentials_types_supported": ["IdentityCredential", "EudiPid"],
        "credential_configurations_supported": {
             "EudiPid": {
                "format": "vc+sd-jwt",
                "scope": "EudiPid_scope",
                "order": [
                    "given_name",
                    "family_name",
                    "birth_date",
                    "birth_place",
                    "nationality",
                    "age_over_18",
                    "issuing_country",
                    "age_birth_year"
                ],
                "claims": {
                        "given_name": {
                            "mandatory": True,
                            "value_type": "string",
                            "display": [{"name": "First name", "locale": "en-US"},
                                        {"name": "Prénom", "locale": "fr-FR"}],
                        },
                        "family_name": {
                            "mandatory": True,
                            "value_type": "string",
                            "display": [{"name": "Family name", "locale": "en-US"},
                                        {"name": "Nom", "locale": "fr-FR"}],
                        },
                        "birth_date": {
                            "mandatory": True,
                            "value_type": "string",
                            "display": [{"name": "Birth date", "locale": "en-US"},
                                        {"name": "Date de naissance", "locale": "fr-FR"}],
                        },
                         "birth_place": {
                            "mandatory": True,
                            "value_type": "string",
                            "display": [{"name": "Birth place", "locale": "en-US"},
                                        {"name": "Lieu de naissance", "locale": "fr-FR"}],
                        },
                        "issuing_country": {
                            "mandatory": True,
                            "value_type": "string",
                            "display": [{"name": "Issuing country", "locale": "en-US"},
                                        {"name": "Pays d'emission", "locale": "fr-FR"}],
                        },
                        "age_over_18": {
                            "mandatory": True,
                            "value_type": "bool",
                            "display": [{"name": "Aged over 18 yo", "locale": "en-US"},
                                        {"name": "Agé de plus de 18 ans", "locale": "fr-FR"}],
                        },
                        "age_over_65": {
                            "mandatory": True,
                            "value_type": "bool",
                            "display": [{"name": "Aged over 65 yo", "locale": "en-US"},
                                        {"name": "Agé de plus de 65 ans", "locale": "fr-FR"}],
                        },
                        "picture": {
                            "mandatory": True,
                            "value_type": "image/jpeg",
                            "display": [{"name": "Picture", "locale": "en-US"},
                                        {"name": "Portrait", "locale": "fr-FR"}],
                        },
                         "age_birth_year": {
                            "mandatory": True,
                            "value_type": "integer",
                            "display": [{"name": "Age birth year", "locale": "en-US"},
                                        {"name": "Année de naissance", "locale": "fr-FR"}],
                        },
                    },
                "cryptographic_binding_methods_supported": ["DID", "jwk"],
                "credential_signing_alg_values_supported": [
                    "ES256K",
                    "ES256",
                    "ES384",
                    "RS256",
                ],
                "vct": "EUDI_PID_rule_book_1_0_0",
                "display": [
                    {
                        "name": "EUDI PID",
                        "locale": "en-US",
                        "background_color": "#14107c",
                        "text_color": "#FFFFFF",
                    }
                ],
            },
            "IdentityCredential": {
                "format": "vc+sd-jwt",
                "scope": "IdentityCredential_scope",
                "display": [
                    {
                        "name": "Identity Credential",
                        "locale": "en-US",
                        "background_color": "#12107c",
                        "text_color": "#FFFFFF",
                    }
                ],
                "order": [
                    "given_name",
                    "family_name",
                    "birth_date",
                    "gender",
                    "birth_place",
                    "nationality",
                    "is_over_18",
                    "is_over_65",
                    "email",
                    "phone_number"
                    "issuing_country"
                ],
                "claims": {
                    "given_name": {
                        "mandatory": True,
                        "display": [
                            {"name": "First Name", "locale": "en-US"},
                            {"name": "Vorname", "locale": "de-DE"},
                            {"name": "Prenom", "locale": "fr-FR"},
                        ],
                    },
                    "family_name": {
                        "mandatory": True,
                        "display": [
                            {"name": "Last Name", "locale": "en-US"},
                            {"name": "Nachname", "locale": "de-DE"},
                            {"name": "Nom", "locale": "fr-FR"},
                        ],
                    },
                     "birth_date": {
                        "mandatory": True,
                        "display": [
                            {"name": "Birth date", "locale": "en-US"},
                            {"name": "Date de naissance", "locale": "fr-FR"},
                        ],
                    },
                    "gender": {
                        "mandatory": True,
                        "display": [
                            {"name": "Gender", "locale": "en-US"},
                            {"name": "Genre", "locale": "fr-FR"},
                        ],
                    },
                    "email": {
                        "mandatory": True,
                        "display": [
                            {"name": "Email", "locale": "en-US"},
                            {"name": "Email", "locale": "fr-FR"},
                        ],
                    },
                     "phone_number": {
                        "mandatory": True,
                        "display": [
                            {"name": "Phone number", "locale": "en-US"},
                            {"name": "Téléphone", "locale": "fr-FR"},
                        ],
                    },
                    "nationality": {
                        "mandatory": True,
                        "display": [
                            {"name": "Nationality", "locale": "en-US"},
                            {"name": "Nationalité", "locale": "fr-FR"},
                        ],
                    },
                     "issuing_country": {
                        "mandatory": True,
                        "display": [
                            {"name": "Issuing country", "locale": "en-US"},
                            {"name": "Pays d'émission", "locale": "fr-FR"},
                        ],
                    },
                    "street_address": {
                        "mandatory": True,
                        "display": [
                            {"name": "Street", "locale": "en-US"},
                            {"name": "Rue", "locale": "fr-FR"},
                        ],
                    },
                    "locality": {
                        "mandatory": True,
                        "display": [
                            {"name": "Locality", "locale": "en-US"},
                            {"name": "Ville", "locale": "fr-FR"},
                        ],
                    },
                    "region": {
                        "mandatory": True,
                        "display": [
                            {"name": "Region", "locale": "en-US"},
                            {"name": "Region", "locale": "fr-FR"},
                        ],
                    },
                    "country": {
                        "mandatory": True,
                        "display": [
                            {"name": "Country", "locale": "en-US"},
                            {"name": "Pays", "locale": "fr-FR"},
                        ],
                    },
                    "is_over_18":  {
                        "mandatory": True,
                        "display": [
                            {"name": "Aged over 18 yo", "locale": "en-US"},
                            {"name": "Agé de plus de 18 ans", "locale": "fr-FR"},
                        ],
                    },
                    "is_over_65":  {
                        "mandatory": True,
                        "display": [
                            {"name": "Aged over 65 yo", "locale": "en-US"},
                            {"name": "Agé de plus de 65 ans", "locale": "fr-FR"},
                        ],
                    }
                },
                "cryptographic_binding_methods_supported": ["jwk", "DID"],
                "credential_signing_alg_values_supported": [
                    "ES256",
                    "ES384",
                    "ES512",
                    "ES256K",
                ],
                "vct": "https://credentials.example.com/identity_credential",
                "proof_types_supported": ["jwt"],
            }
        },
        "grant_types_supported": [
            "authorization_code",
            "urn:ietf:params:oauth:grant-type:pre-authorized_code",
        ],
        "schema_for_type": False,
        "credential_manifest_support": False,
    },
    "GAIN-POC": {
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
        "credentials_types_supported": ["IdentityCredential"],
        "credential_configurations_supported": {
            "IdentityCredential": {
                "format": "vc+sd-jwt",
                "scope": "identityCredential_scope",
                "display": [
                    {
                        "name": "Identity Credential",
                        "locale": "en-US",
                        "background_color": "#12107c",
                        "text_color": "#FFFFFF",
                    }
                ],
                "claims": {
                    "iss": {
                        "mandatory": True,
                        "display": [
                            {"name": "Issuer", "locale": "en-US"},
                            {"name": "Emetteur", "locale": "fr-FR"},
                        ],
                    },
                    "given_name": {
                        "mandatory": True,
                        "display": [
                            {"name": "First Name", "locale": "en-US"},
                            {"name": "Vorname", "locale": "de-DE"},
                            {"name": "Prenom", "locale": "fr-FR"},
                        ],
                    },
                    "family_name": {
                        "mandatory": True,
                        "display": [
                            {"name": "Last Name", "locale": "en-US"},
                            {"name": "Nachname", "locale": "de-DE"},
                            {"name": "Nom", "locale": "fr-FR"},
                        ],
                    },
                    "email": {},
                    "phone_number": {},
                      "address": {
                        "street_address": {
                            "mandatory": True,
                            "display": [
                                {"name": "Street", "locale": "en-US"},
                                {"name": "Rue", "locale": "fr-FR"},
                            ],
                        },
                        "locality": {
                            "mandatory": True,
                            "display": [
                                {"name": "Locality", "locale": "en-US"},
                                {"name": "Ville", "locale": "fr-FR"},
                            ],
                        },
                        "region": {
                            "mandatory": True,
                            "display": [
                                {"name": "Region", "locale": "en-US"},
                                {"name": "Region", "locale": "fr-FR"},
                            ],
                        },
                        "country": {
                            "mandatory": True,
                            "display": [
                                {"name": "Country", "locale": "en-US"},
                                {"name": "Pays", "locale": "fr-FR"},
                            ],
                        },
                    },
                    "birthdate": {},
                    "is_over_18":  {
                        "mandatory": True,
                        "display": [
                            {"name": "Over 18", "locale": "en-US"},
                            {"name": "Majeur", "locale": "fr-FR"},
                        ],
                    },
                    "is_over_21": {},
                    "is_over_65": {},
                },
                "cryptographic_binding_methods_supported": ["jwk", "DID"],
                "credential_signing_alg_values_supported": [
                    "ES256",
                    "ES384",
                    "ES512",
                    "ES256K",
                ],
                "vct": "https://credentials.example.com/identity_credential",
                "proof_types_supported": ["jwt"],
            }
        },
        "grant_types_supported": [
            "authorization_code",
            "urn:ietf:params:oauth:grant-type:pre-authorized_code",
        ],
        "schema_for_type": False,
        "credential_manifest_support": False,
    },
    "HAIP": {
        "oidc4vciDraft": "13",
        "siopv2Draft": "12",
        "oidc4vpDraft": "20",
        "vc_format": "vc+sd-jwt",
        "verifier_vp_type": "vc+sd-jwt",
        "oidc4vci_prefix": "haip://",
        "authorization_server_support": False,
        "credentials_as_json_object_array": False,
        "siopv2_prefix": "haip://",
        "oidc4vp_prefix": "haip://",
        "credentials_types_supported": ["IdentityCredential", "EudiPid"],
        "credential_configurations_supported": {
            "EudiPid": {
                "format": "vc+sd-jwt",
                "scope": "EudiPid_scope",
                "order": [
                    "given_name",
                    "family_name",
                    "birth_date",
                    "birth_place",
                    "nationalities",
                    "address",
                    "age_equal_or_over", 
                    "age_birth_year",
                    "issuing_country",
                    "dateIssued"
                ],
                "claims": {
                        "given_name": {
                            "mandatory": True,
                            "value_type": "string",
                            "display": [{"name": "First Name", "locale": "en-US"},
                                        {"name": "Prénom", "locale": "fr-FR"}],
                        },
                        "family_name": {
                            "mandatory": True,
                            "value_type": "string",
                            "display": [{"name": "Family Name", "locale": "en-US"},
                                        {"name": "Nom", "locale": "fr-FR"}],
                        },
                         "birth_date": {
                            "mandatory": True,
                            "value_type": "string",
                            "display": [{"name": "Birth date", "locale": "en-US"},
                                        {"name": "Date de naissance", "locale": "fr-FR"}],
                        },
                         "birth_place": {
                            "mandatory": True,
                            "value_type": "string",
                            "display": [{"name": "Birth place", "locale": "en-US"},
                                        {"name": "Lieu de naissance", "locale": "fr-FR"}],
                        },
                        "nationalities": {
                            "mandatory": True,
                            "value_type": "string",
                            "display": [{"name": "Nationalities", "locale": "en-US"},
                                        {"name": "Nationalités", "locale": "fr-FR"}],
                        },
                        "address": {
                            "mandatory": True,
                            "value_type": "string",
                            "display": [
                                {"name": "Address", "locale": "en-US"},
                                {"name": "Adresse", "locale": "fr-FR"}
                            ],
                            "street_address": {
                                "mandatory": True,
                                "value_type": "string",
                                "display": [
                                    {"name": "Street address", "locale": "en-US"},
                                    {"name": "Rue", "locale": "fr-FR"}],
                                },
                            "locality": {
                                "mandatory": True,
                                "value_type": "string",
                                "display": [
                                    {"name": "Locality", "locale": "en-US"},
                                    {"name": "Ville", "locale": "fr-FR"}],
                                },
                            "region": {
                                "mandatory": True,
                                "value_type": "string",
                                "display": [
                                    {"name": "Region", "locale": "en-US"},
                                    {"name": "Région", "locale": "fr-FR"}],
                                },
                            "country": {
                                "mandatory": True,
                                "value_type": "string",
                                "display": [
                                    {"name": "Country", "locale": "en-US"},
                                    {"name": "Pays", "locale": "fr-FR"}],
                                },
                        },
                        "picture": {
                            "mandatory": True,
                            "value_type": "image/jpeg",
                            "display": [{"name": "Picture", "locale": "en-US"},
                                        {"name": "Portrait", "locale": "fr-FR"}],
                        },
                         "age_birth_year": {
                            "mandatory": True,
                            "value_type": "integer",
                            "display": [{"name": "Age birth year", "locale": "en-US"},
                                        {"name": "Année de naissance", "locale": "fr-FR"}],
                        },
                        "dateIssued": {
                            "mandatory": True,
                            "value_type": "string",
                            "display": [{"name": "Issuance date", "locale": "en-US"},
                                        {"name": "Délivré le", "locale": "fr-FR"}],
                        },
                        "expiry_date": {
                            "mandatory": True,
                            "value_type": "string",
                            "display": [{"name": "Expiry date", "locale": "en-US"},
                                        {"name": "Date d'expiration", "locale": "fr-FR"}],
                        },
                        "issuing_country": {
                            "mandatory": True,
                            "value_type": "string",
                            "display": [{"name": "Issuing country", "locale": "en-US"},
                                        {"name": "Pays d'emission", "locale": "fr-FR"}],
                        },
                         "issuing_authority": {
                            "mandatory": True,
                            "value_type": "string",
                            "display": [{"name": "Issuing autority", "locale": "en-US"},
                                        {"name": "Authorité d'emission", "locale": "fr-FR"}],
                        },
                    },
                "cryptographic_binding_methods_supported": ["DID", "jwk"],
                "credential_signing_alg_values_supported": [
                    "ES256K",
                    "ES256",
                    "ES384",
                    "RS256",
                ],
                "vct": "EUDI_PID_rule_book_1_0_0",
                "display": [
                    {
                        "name": "EUDI PID",
                        "locale": "en-US",
                        "background_color": "#14107c",
                        "text_color": "#FFFFFF",
                    }
                ],
            },
            "IdentityCredential": {
                "format": "vc+sd-jwt",
                "scope": "IdentityCredential_scope",
                "display": [
                    {
                        "name": "Identity Credential",
                        "locale": "en-US",
                        "background_color": "#12107c",
                        "text_color": "#FFFFFF",
                    }
                ],
                 "order": [
                    "given_name",
                    "family_name",
                    "birth_date",
                    "gender",
                    "email",
                    "phone_number",
                    "nationality",
                    "is_over_18",
                    "issuing_country",
                    "dateIssued"
                ],
                "claims": {
                    "given_name": {
                        "mandatory": True,
                        "display": [
                            {"name": "First Name", "locale": "en-US"},
                            {"name": "Vorname", "locale": "de-DE"},
                            {"name": "Prénom(s)", "locale": "fr-FR"},
                        ],
                    },
                    "family_name": {
                        "mandatory": True,
                        "display": [
                            {"name": "Last Name", "locale": "en-US"},
                            {"name": "Nachname", "locale": "de-DE"},
                            {"name": "Nom", "locale": "fr-FR"},
                        ],
                    },
                    "email": {
                        "mandatory": True,
                        "display": [
                            {"name": "Email", "locale": "en-US"},
                            {"name": "Email", "locale": "fr-FR"},
                        ],
                    },
                     "phone_number": {
                        "mandatory": True,
                        "display": [
                            {"name": "Phone number", "locale": "en-US"},
                            {"name": "Téléphone", "locale": "fr-FR"},
                        ],
                    },
                    "birth_date": {
                            "mandatory": True,
                            "display": [
                                {"name": "Birth date", "locale": "en-US"},
                                {"name": "Date de naissance", "locale": "fr-FR"},
                            ],
                        },
                    "is_over_18":  {
                        "mandatory": True,
                        "display": [
                            {"name": "Over 18", "locale": "en-US"},
                            {"name": "Majeur", "locale": "fr-FR"},
                        ],
                    },
                    "issuing_country": {
                            "mandatory": True,
                            "value_type": "string",
                            "display": [{"name": "Issuing country", "locale": "en-US"},
                                        {"name": "Pays d'emission", "locale": "fr-FR"}],
                        },
                     "dateIssued": {
                            "mandatory": True,
                            "value_type": "string",
                            "display": [{"name": "Issuance date", "locale": "en-US"},
                                        {"name": "Délivré le", "locale": "fr-FR"}],
                        },
                    "is_over_65":  {
                        "mandatory": True,
                        "display": [
                            {"name": "Aged over 65", "locale": "en-US"},
                            {"name": "Agé de plus de 65 ans", "locale": "fr-FR"},
                        ],
                    },
                      "gender":  {
                        "mandatory": True,
                        "display": [
                            {"name": "Gender", "locale": "en-US"},
                            {"name": "Sexe", "locale": "fr-FR"},
                        ],
                    },
                },
                "cryptographic_binding_methods_supported": ["jwk", "DID"],
                "credential_signing_alg_values_supported": [
                    "ES256",
                    "ES256K",
                ],
                "vct": "https://credentials.example.com/identity_credential",
                "proof_types_supported": ["jwt"],
            }
        },
        "grant_types_supported": [
            "authorization_code",
            "urn:ietf:params:oauth:grant-type:pre-authorized_code",
        ],
        "schema_for_type": False,
        "credential_manifest_support": False,
    },
    "POTENTIAL": {
        "oidc4vciDraft": "13",
        "siopv2Draft": "12",
        "oidc4vpDraft": "20",
        "vc_format": "vc+sd-jwt",
        "verifier_vp_type": "vc+sd-jwt",
        "oidc4vci_prefix": "haip://",
        "authorization_server_support": False,
        "credentials_as_json_object_array": False,
        "siopv2_prefix": "haip://",
        "oidc4vp_prefix": "haip://",
        "credentials_types_supported": ["Pid", "EudiPid"],
        "credential_configurations_supported": {
            "EudiPid": {
                "format": "vc+sd-jwt",
                "scope": "EudiPid_scope",
                "order": [
                    "given_name",
                    "family_name",
                    "birth_date",
                    "birth_place",
                    "nationalities",
                    "address",
                    "age_equal_or_over", 
                    "age_birth_year",
                    "issuing_country",
                    "issuing_authority",
                    "dateIssued"
                ],
                "claims": {
                        "given_name": {
                            "mandatory": True,
                            "value_type": "string",
                            "display": [{"name": "First Name", "locale": "en-US"},
                                        {"name": "Prénom", "locale": "fr-FR"}],
                        },
                        "family_name": {
                            "mandatory": True,
                            "value_type": "string",
                            "display": [{"name": "Family Name", "locale": "en-US"},
                                        {"name": "Nom", "locale": "fr-FR"}],
                        },
                        "birth_date": {
                            "mandatory": True,
                            "value_type": "string",
                            "display": [{"name": "Birth date", "locale": "en-US"},
                                        {"name": "Date de naissance", "locale": "fr-FR"}],
                        },
                        "birth_place": {
                            "mandatory": True,
                            "value_type": "string",
                            "display": [{"name": "Birth place", "locale": "en-US"},
                                        {"name": "Lieu de naissance", "locale": "fr-FR"}],
                        },
                        "nationalities": {
                            "mandatory": True,
                            "value_type": "string",
                            "display": [{"name": "Nationalities", "locale": "en-US"},
                                        {"name": "Nationalités", "locale": "fr-FR"}],
                        },
                        "age_equal_or_over": {
                            "mandatory": True,
                            "value_type": "bool",
                            "display": [{"name": "Age", "locale": "en-US"},
                                        {"name": "Age", "locale": "fr-FR"}],
                            "12": {
                                "mandatory": True,
                                "value_type": "string",
                                "display": [
                                    {"name": "Over 12", "locale": "en-US"},
                                    {"name": "Plus de 12 ans", "locale": "fr-FR"}],
                                },
                            "14": {
                                "mandatory": True,
                                "value_type": "string",
                                "display": [
                                    {"name": "Over 14", "locale": "en-US"},
                                    {"name": "Plus de 14 ans", "locale": "fr-FR"}],
                                },
                            "16": {
                                "mandatory": True,
                                "value_type": "string",
                                "display": [
                                    {"name": "Over 16", "locale": "en-US"},
                                    {"name": "Plus de 16 ans", "locale": "fr-FR"}],
                                },
                            "18": {
                                "mandatory": True,
                                "value_type": "string",
                                "display": [
                                    {"name": "Over 18", "locale": "en-US"},
                                    {"name": "Plus de 18 ans", "locale": "fr-FR"}],
                                },
                            "21": {
                                "mandatory": True,
                                "value_type": "string",
                                "display": [
                                    {"name": "Over 21", "locale": "en-US"},
                                    {"name": "Plus de 21 ans", "locale": "fr-FR"}],
                                },
                            "65": {
                                "mandatory": True,
                                "value_type": "string",
                                "display": [
                                    {"name": "Senior", "locale": "en-US"},
                                    {"name": "Senior", "locale": "fr-FR"}],
                                },
                        },
                        "address": {
                            "mandatory": True,
                            "value_type": "string",
                            "display": [
                                {"name": "Address", "locale": "en-US"},
                                {"name": "Adresse", "locale": "fr-FR"}
                            ],
                            "formatted": {
                                "mandatory": True,
                                "value_type": "string",
                                "display": [
                                    {"name": "Formatted", "locale": "en-US"},
                                    {"name": "Complete", "locale": "fr-FR"}],
                                },
                            "street_address": {
                                "mandatory": True,
                                "value_type": "string",
                                "display": [
                                    {"name": "Street address", "locale": "en-US"},
                                    {"name": "Rue", "locale": "fr-FR"}],
                                },
                            "locality": {
                                "mandatory": True,
                                "value_type": "string",
                                "display": [
                                    {"name": "Locality", "locale": "en-US"},
                                    {"name": "Ville", "locale": "fr-FR"}],
                                },
                            "region": {
                                "mandatory": True,
                                "value_type": "string",
                                "display": [
                                    {"name": "Region", "locale": "en-US"},
                                    {"name": "Région", "locale": "fr-FR"}],
                                },
                            "country": {
                                "mandatory": True,
                                "value_type": "string",
                                "display": [
                                    {"name": "Country", "locale": "en-US"},
                                    {"name": "Pays", "locale": "fr-FR"}],
                                },
                        },
                        "picture": {
                            "mandatory": True,
                            "value_type": "image/jpeg",
                            "display": [{"name": "Picture", "locale": "en-US"},
                                        {"name": "Portrait", "locale": "fr-FR"}],
                        },
                        "age_birth_year": {
                            "mandatory": True,
                            "value_type": "integer",
                            "display": [{"name": "Age birth year", "locale": "en-US"},
                                        {"name": "Année de naissance", "locale": "fr-FR"}],
                        },
                        "dateIssued": {
                            "mandatory": True,
                            "value_type": "string",
                            "display": [{"name": "Issuance date", "locale": "en-US"},
                                        {"name": "Délivré le", "locale": "fr-FR"}],
                        },
                        "expiry_date": {
                            "mandatory": True,
                            "value_type": "string",
                            "display": [{"name": "Expiry date", "locale": "en-US"},
                                        {"name": "Date d'expiration", "locale": "fr-FR"}],
                        },
                        "issuing_country": {
                            "mandatory": True,
                            "value_type": "string",
                            "display": [{"name": "Issuing country", "locale": "en-US"},
                                        {"name": "Pays d'emission", "locale": "fr-FR"}],
                        },
                        "issuing_authority": {
                            "mandatory": True,
                            "value_type": "string",
                            "display": [{"name": "Issuing autority", "locale": "en-US"},
                                        {"name": "Authorité d'emission", "locale": "fr-FR"}],
                        },
                    },
                "cryptographic_binding_methods_supported": ["DID", "jwk"],
                "credential_signing_alg_values_supported": [
                    "ES256K",
                    "ES256",
                    "ES384",
                    "RS256",
                ],
                "vct": "EUDI_PID_rule_book_1_0_0",
                "display": [
                    {
                        "name": "EUDI PID",
                        "locale": "en-US",
                        "background_color": "#14107c",
                        "text_color": "#FFFFFF",
                    }
                ],
            },
            "Pid": {
                "format": "vc+sd-jwt",
                "scope": "Pid_scope",
                "order": [
                    "given_name",
                    "family_name",
                    "birthdate",
                    "address",
                    "gender",
                    "place_of_birth",
                    "nationalities",
                    "age_equal_or_over", 
                ],
                "claims": {
                        "given_name": {
                            "mandatory": True,
                            "value_type": "string",
                            "display": [{"name": "First Name", "locale": "en-US"},
                                        {"name": "Prénom", "locale": "fr-FR"}],
                        },
                        "family_name": {
                            "mandatory": True,
                            "value_type": "string",
                            "display": [{"name": "Family Name", "locale": "en-US"},
                                        {"name": "Nom", "locale": "fr-FR"}],
                        },
                        "birthdate": {
                            "mandatory": True,
                            "value_type": "string",
                            "display": [{"name": "Birth date", "locale": "en-US"},
                                        {"name": "Date de naissance", "locale": "fr-FR"}],
                        },
                        "place_of_birth": {
                            "mandatory": True,
                            "value_type": "string",
                            "display": [{"name": "Birth place", "locale": "en-US"},
                                        {"name": "Lieu de naissance", "locale": "fr-FR"}],
                            "locality": {
                                "mandatory": True,
                                "value_type": "string",
                                "display": [
                                    {"name": "Locality", "locale": "en-US"},
                                    {"name": "Ville", "locale": "fr-FR"}],
                                },
                            "region": {
                                "mandatory": True,
                                "value_type": "string",
                                "display": [
                                    {"name": "Region", "locale": "en-US"},
                                    {"name": "Région", "locale": "fr-FR"}],
                                },
                            "country": {
                                "mandatory": True,
                                "value_type": "string",
                                "display": [
                                    {"name": "Country", "locale": "en-US"},
                                    {"name": "Pays", "locale": "fr-FR"}],
                                },
                            
                        },
                        "nationalities": {
                            "mandatory": True,
                            "value_type": "string",
                            "display": [{"name": "Nationalities", "locale": "en-US"},
                                        {"name": "Nationalités", "locale": "fr-FR"}],
                        },
                        "gender": {
                            "mandatory": True,
                            "value_type": "string",
                            "display": [{"name": "Gender", "locale": "en-US"},
                                        {"name": "Sexe", "locale": "fr-FR"}],
                        },
                        "address": {
                            "mandatory": True,
                            "value_type": "string",
                            "display": [
                                {"name": "Address", "locale": "en-US"},
                                {"name": "Adresse", "locale": "fr-FR"}
                            ],
                            "formatted": {
                                "mandatory": True,
                                "value_type": "string",
                                "display": [
                                    {"name": "Formatted", "locale": "en-US"},
                                    {"name": "Complete", "locale": "fr-FR"}],
                                },
                            "street_address": {
                                "mandatory": True,
                                "value_type": "string",
                                "display": [
                                    {"name": "Street address", "locale": "en-US"},
                                    {"name": "Rue", "locale": "fr-FR"}],
                                },
                            "locality": {
                                "mandatory": True,
                                "value_type": "string",
                                "display": [
                                    {"name": "Locality", "locale": "en-US"},
                                    {"name": "Ville", "locale": "fr-FR"}],
                                },
                            "region": {
                                "mandatory": True,
                                "value_type": "string",
                                "display": [
                                    {"name": "Region", "locale": "en-US"},
                                    {"name": "Région", "locale": "fr-FR"}],
                                },
                            "country": {
                                "mandatory": True,
                                "value_type": "string",
                                "display": [
                                    {"name": "Country", "locale": "en-US"},
                                    {"name": "Pays", "locale": "fr-FR"}],
                                },
                        },
                        "age_equal_or_over": {
                            "mandatory": True,
                            "value_type": "bool",
                            "display": [{"name": "Age", "locale": "en-US"},
                                        {"name": "Age", "locale": "fr-FR"}],
                            "12": {
                                "mandatory": True,
                                "value_type": "string",
                                "display": [
                                    {"name": "Over 12", "locale": "en-US"},
                                    {"name": "Plus de 12 ans", "locale": "fr-FR"}],
                                },
                            "14": {
                                "mandatory": True,
                                "value_type": "string",
                                "display": [
                                    {"name": "Over 14", "locale": "en-US"},
                                    {"name": "Plus de 14 ans", "locale": "fr-FR"}],
                                },
                            "16": {
                                "mandatory": True,
                                "value_type": "string",
                                "display": [
                                    {"name": "Over 16", "locale": "en-US"},
                                    {"name": "Plus de 16 ans", "locale": "fr-FR"}],
                                },
                            "18": {
                                "mandatory": True,
                                "value_type": "string",
                                "display": [
                                    {"name": "Over 18", "locale": "en-US"},
                                    {"name": "Plus de 18 ans", "locale": "fr-FR"}],
                                },
                            "21": {
                                "mandatory": True,
                                "value_type": "string",
                                "display": [
                                    {"name": "Over 21", "locale": "en-US"},
                                    {"name": "Plus de 21 ans", "locale": "fr-FR"}],
                                },
                            "65": {
                                "mandatory": True,
                                "value_type": "string",
                                "display": [
                                    {"name": "Senior", "locale": "en-US"},
                                    {"name": "Senior", "locale": "fr-FR"}],
                                },
                        },
                        "picture": {
                            "mandatory": True,
                            "value_type": "image/jpeg",
                            "display": [{"name": "Picture", "locale": "en-US"},
                                        {"name": "Portrait", "locale": "fr-FR"}],
                        },
                        "dateIssued": {
                            "mandatory": True,
                            "value_type": "string",
                            "display": [{"name": "Issuance date", "locale": "en-US"},
                                        {"name": "Délivré le", "locale": "fr-FR"}],
                        },
                        "expiry_date": {
                            "mandatory": True,
                            "value_type": "string",
                            "display": [{"name": "Expiry date", "locale": "en-US"},
                                        {"name": "Date d'expiration", "locale": "fr-FR"}],
                        },
                        "issuing_country": {
                            "mandatory": True,
                            "value_type": "string",
                            "display": [{"name": "Issuing country", "locale": "en-US"},
                                        {"name": "Pays d'emission", "locale": "fr-FR"}],
                        },
                         "issuing_authority": {
                            "mandatory": True,
                            "value_type": "string",
                            "display": [{"name": "Issuing autority", "locale": "en-US"},
                                        {"name": "Authorité d'emission", "locale": "fr-FR"}],
                        },
                    },
                "cryptographic_binding_methods_supported": ["DID", "jwk"],
                "credential_signing_alg_values_supported": [
                    "ES256K",
                    "ES256",
                    "ES384",
                    "RS256",
                ],
                "vct": "urn:eu.europa.ec.eudi:pid:1",
                "display": [
                    {
                        "name": "PID",
                        "locale": "en-US",
                        "background_color": "#14107c",
                        "text_color": "#FFFFFF",
                    },
                    {
                        "name": "PID",
                        "locale": "fr-FR",
                        "background_color": "#14107c",
                        "text_color": "#FFFFFF",
                    }
                ],
            },
        },
        "grant_types_supported": [
            "authorization_code",
            "urn:ietf:params:oauth:grant-type:pre-authorized_code",
        ],
        "schema_for_type": False,
        "credential_manifest_support": False,
    },
     "VERIFIER-ALL": {
        "oidc4vciDraft": "13",
        "siopv2Draft": "12",
        "oidc4vpDraft": "20",
        "vc_format": "all_vc",
        "verifier_vp_type": "all_vp",
        "oidc4vci_prefix": "haip://",
        "authorization_server_support": False,
        "credentials_as_json_object_array": False,
        "siopv2_prefix": "haip://",
        "oidc4vp_prefix": "openid-vc://",
        "grant_types_supported": [
            "authorization_code",
            "urn:ietf:params:oauth:grant-type:pre-authorized_code",
        ],
        "schema_for_type": False,
        "credential_manifest_support": False,
    }
}
