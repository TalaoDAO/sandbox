from profiles import insurer, bank, gouv, test, talao_issuer_jwt_vc_json, talao_issuer_vc_sd_jwt, talao_issuer_jwt_vc_json_ld, documentation

profile = {
    "INSURER": insurer.INSURER,
    "DOCUMENTATION": documentation.DOCUMENTATION,
    "BANK": bank.BANK,
    "GOUV": gouv.GOUV,
    "TEST": test.TEST,
    "TALAO_ISSUER_JWT_VC_JSON": talao_issuer_jwt_vc_json.TALAO_ISSUER,
    "TALAO_ISSUER_JWT_VC_JSON_LD": talao_issuer_jwt_vc_json_ld.TALAO_ISSUER,
    "TALAO_ISSUER_SD_JWT_VC": talao_issuer_vc_sd_jwt.TALAO_ISSUER,
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
                            "uri": "https://dutchblockchaincoalition.org/assets/images/icons/Logo-DBC.png",
                            "alt_text": "An orange block shape, with the text Dutch Blockchain Coalition next to it, portraying the logo of the Dutch Blockchain Coalition.",
                        },
                        "background_image": {
                            "uri": "https://i.ibb.co/CHqjxrJ/dbc-card-hig-res.png",
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
                "credential_signing_alg_values_supported": [
                    "Ed25519Signature2018"
                ],
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
                "credential_signing_alg_values_supported": [
                    "Ed25519Signature2018"
                ],
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
                "credential_signing_alg_values_supported": [
                    "Ed25519Signature2018"
                ],
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
                "credential_signing_alg_values_supported": [
                    "Ed25519Signature2018"
                ],
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
                "credential_signing_alg_values_supported": [
                    "Ed25519Signature2018"
                ],
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
                "credential_signing_alg_values_supported": [
                    "Ed25519Signature2018"
                ],
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
                "credential_signing_alg_values_supported": [
                    "Ed25519Signature2018"
                ],
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
                "types": [
                    "VerifiableCredential",
                    "VerifiableId"
                ],
                "cryptographic_binding_methods_supported": ["DID"],
                "credential_signing_alg_values_supported": [
                    "Ed25519Signature2018"
                ],
                "display": [
                    {
                        "name": "Verifiable Id",
                        "description": "This credential is a proof of your identity. You can use it when you need to prove your identity with services that have already adopted a decentralized identity system.",
                        "locale": "en-GB",
                    }
                ],
                "credentialSubject": {
                    "given_name": {
                        "mandatory": True,
                        "display": [
                            {
                                "name": "First Name",
                                "locale": "en-US"
                            }
                        ],
                    },
                    "family_name": {
                        "mandatory": True,
                        "display": [
                            {
                                "name": "Family Name",
                                "locale": "en-US"
                            }
                        ],
                    },
                    "gender": {
                        "mandatory": True,
                        "display": [{"name": "Gender", "locale": "en-US"}],
                    },
                    "birth_date": {
                        "mandatory": True,
                        "display": [{"name": "Birth Date", "locale": "en-US"}],
                    },
                    "issuance_date": {
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
                "credential_signing_alg_values_supported": [
                    "Ed25519Signature2018"
                ],
                "display": [
                    {
                        "name": "EmailPass",
                        "description": "This card is a proof of ownership of your email. You can use it when you need to prove your email ownership with services that have already adopted the verifiable and decentralized identity system.",
                        "locale": "en-GB"
                    }
                ],
                "credentialSubject": {
                    "email": {
                        "mandatory": True,
                        "value_type": "email",
                        "display": [{"name": "email", "locale": "en-US"}],
                    }
                }
            },
            {
                "id": "PhoneProof",
                "format": "ldp_vc",
                "types": ["VerifiableCredential", "PhoneProof"],
                "cryptographic_binding_methods_supported": ["DID"],
                "credential_signing_alg_values_supported": [
                    "Ed25519Signature2018"
                ],
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
                    "type": ["VerifiableCredential", "EmailPass"],
                    "@context": [
                        "https://www.w3.org/2018/credentials/v1",
                        {
                            "EmailPass": {
                                "@id": "https://github.com/TalaoDAO/context#emailpass",
                                "@context": {
                                    "@version": 1.1,
                                    "@protected": True,
                                    "schema": "https://schema.org/",
                                    "id": "@id",
                                    "type": "@type",
                                    "email": "schema:email",
                                    "issuedBy": {
                                        "@id": "schema:issuedBy",
                                        "@context": {
                                            "@version": 1.1,
                                            "@protected": True,
                                            "logo": {"@id": "schema:image", "@type": "@id"},
                                            "name": "schema:name"
                                        }
                                    }

                                }
                            }
                        }
                    ],
                },
                "cryptographic_binding_methods_supported": ["DID", "jwk"],
                "credential_signing_alg_values_supported": [
                    "Ed25519Signature2018"
                ],
                "display": [{"name": "Proof of Email", "locale": "en-US"}],
                "credentialSubject": {
                        "email": {
                            "value_type": "email",
                            "mandatory": True,
                            "display": [
                                {"name": "Email", "locale": "en-US"},
                                {"name": "Email", "locale": "fr-FR"}         
                            ],
                        }
                },
            },
            "VerifiableId": {
                "format": "ldp_vc",
                "credential_definition": {
                    "type": ["VerifiableCredential", "VerifiableId"],
                    "@context": [
                        "https://www.w3.org/2018/credentials/v1",
                        {
                            "VerifiableId": {
                                "@id": "urn:employeecredential",
                                "@context": {
                                    "@version": 1.1,
                                    "@protected": True,
                                    "id": "@id",
                                    "type": "@type",
                                    "schema": "https://schema.org/",
                                    "familyName": "schema:lastName",
                                    "firstName": "schema:firstName",
                                    "dateOfBirth": "schema:birthDate",
                                    "gender": "schema:gender",
                                    "idRecto": "schema:image",
                                    "dateIssued": "schema:dateIssued",
                                    "idVerso": "schema:image"
                                }
                            }
                        }
                    ],
                },
                "cryptographic_binding_methods_supported": ["DID"],
                "credential_signing_alg_values_supported": [
                    "Ed25519Signature2018"
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
                    "type": ["VerifiableCredential", "Over18"],
                    "@context": [
                        "https://www.w3.org/2018/credentials/v1",
                        {
                            "Over18": {
                                "@id": "https://github.com/TalaoDAO/context#over18",
                                "@context": {
                                    "@version": 1.1,
                                    "@protected": True,
                                    "schema": "https://schema.org/",
                                    "id": "@id",
                                    "type": "@type",
                                    "kycProvider": "schema:legalName",
                                    "kycMethod": "schema:identifier",
                                    "ageOver": "schema:suggestedMinAge",
                                    "kycId": "schema:identifier",
                                    "issuedBy": {
                                        "@id": "schema:issuedBy",
                                        "@context": {
                                            "@protected": True,
                                            "logo": {"@id": "schema:image", "@type": "@id"},
                                            "name": "schema:legalName"
                                        }
                                    }

                                }
                            }
                        }
                    ],
                },
                "cryptographic_binding_methods_supported": ["DID", "jwk"],
                "credential_signing_alg_values_supported": [
                    "Ed25519Signature2018"
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
                "credential_signing_alg_values_supported": [
                    "ES256"
                ],
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
                "credential_signing_alg_values_supported": [
                    "ES256"
                ],
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
                "credential_signing_alg_values_supported": [
                    "ES256"
                ],
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
                "credential_signing_alg_values_supported": [
                    "ES256"
                ],
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
                "credential_signing_alg_values_supported": [
                    "ES256"
                ],
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
                "credential_signing_alg_values_supported": [
                    "ES256"
                ],
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
                "credential_signing_alg_values_supported": [
                    "ES256"
                ],
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
                "credential_signing_alg_values_supported": [
                    "ES256"
                ],
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
                "credential_signing_alg_values_supported": [
                    "ES256"
                ],
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
                "credential_signing_alg_values_supported": [
                    "ES256"
                ],
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
    "DEFAULT-VC-JWT-OIDC4VCI13": {   # DIIP v2.1
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
            "TestCredential",
            "VerifiableId",
            "EmailPass",
            "PhoneProof",
            "Over18",
            "DBCGuest",
            "IBANLegalPerson",
            "InsuranceLegalPerson"
        ],
        "credential_configurations_supported": {
            "IBANLegalPerson": {
                "scope": "IBANLegalPerson_scope",
                "display": [
                    {
                        "name": "Company IBAN",
                        "description": "IBAN",
                        "text_color": "#FBFBFB",
                        "logo": {
                            "uri": "https://i.ibb.co/ZdVm5Bg/abn-logo.png",
                            "alt_text": "ABN Amro logo"
                        },
                        "background_image": {
                            "uri": "https://i.ibb.co/kcb9XQ4/abncard-iban-lp.png",
                            "alt_text": "ABN Amro Card"
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
                ],
            },
            "InsuranceLegalPerson": {
                "scope": "InsuranceLegalPerson_scope",
                "display": [
                    {
                        "name": "Insurance contract",
                        "description": "Insurance for liability risks",
                        "text_color": "#FBFBFB",
                        "logo": {
                            "uri": "data:image/png;base64,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",
                            "alt_text": "AXA International"
                        },
                        "background_image": {
                            "uri": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAASwAAACoCAMAAABt9SM9AAABUFBMVEX///8gNoL///4gNYT///wiNn8RJn0gNoOUn7MNImoOKn2Eja57hqf//f////v8///o7/qdpb7aKCSttMgVLHQiNIYgN37++/8iNIj///ckNXy7MTsgN3zcKCEAF2wAHHMAHW7aJyo8LG4AAGMAF2LWKyIIJnq0v9Hr9PgAEnEAFnAAHmnP2eUAEXHByNwIIH1teKIAJXh2f5kHJWgzDVCcJC62Jim9IBu3JSHAHyPAIRq1JxdwMEkAFF6EMVDSLSzlIyGzMEQyMGUhL4hqLlrMLzRJLGaPL0meLEx2L1laK2DXKzciMG/aKhhlLFTXKC5PLmC9MUCfM0eCLVc7K3iGkb2UoMJbZoxNVYIsPnhOWonZ4+e8xc5ZYZNhbJJ7gbA/SX84RYcvP2qqsMxdbZAAAEkAAGxPVZBFSmuqrbmLla/f4/TP0dtdZZ+ptde/zuoyrESkAAAbLUlEQVR4nO1d62PbxpFfYHe5FiRgKZELAjJEUnFM0SRFivZdm95dmweTXNLKfV5lPSxHrnP1xXLv/v9vN7MgSGJBRYBEyZLLae1YAond/WFmdp4LQpa0pCUtaUlLWtKSlrSkJS1pSUuaS7b9oWfw82QjfehJjIl5HvvQc/g5Ysy1PW/8g+0x1yWLgq7wM2D4BXdBo98ISSnTP8kLP1qQbMa8MPQu/+CYWMxV9l0mSWpuOJ6vC5IArLYYivEqKFdeePlnPhjZYQjLkd6E7A8pB4xJuaBHdRMkpWeTiejhP2y2oFszpEJ6C7C6gSewSGIhs73x+hbOVdLOL4Y2gb3w6acrd5GerXSfrTz7l3/9xS8/++xXv/q3z37575/96pf/0YXfL2yEXz8lBVjFJsBYaw69iySoxRX9zecbX2xtbWx8sbGxtfXFl1+pwFcLG6G1egWwrDtJIrJGX38OIG08hv9tbH+x8c23wuKRWNT9LeejAYtbVHz1zRaw1ePHW1vbG4+3Pv86EiPu8wUN8DGBRaPRJ19uAFKPHwNzbT/e+MN/8ogGUaToYgb4mMDiwf53GxuIVvz39pebkRX4PlcLksOPBizQ7n7w/eNt4Cn8//bj7S8efiuoinhAowXJ4ccBFhUgbtz67e+QqR6DCG6B1vrdbyO+IPkb00cBFlWUW7745CEw1NZGrN63t37jW8Jf6DgfBVgCiIr977Yeg3GFuyAy1nf7SixKsyfjfBRg+REI4V82tp8DVNrC2nj+cHPErUVp9mScjwEsMNz96Pe/29h6/gcwGlAGv/jmj1YQWdZSDDMkwBH59uEW7IDbgNTjre3n298LDgpLLDlrlihFYRO8+iUao+gOgjG6vfXnKhWW4EudNUvAOr4PG2Hw3ecbCW093nj4yWJZKhntfoNloY3FLfH9hjZFNW2D+xzwRfmDs3TPwfLBRqcq+OPnsYuj3Zytz38vghsZ7Z6DxQNrk/uf/Amgep5I4cZvxOICDSm652CBnxzRr/68gRZDwlrfVX0R8ZtQWvcdLOqr0V/Ae976fDuWxK2H31qRUAveB2O652DRSNHf/2FrTM+/2H7+zdc3shFquu9gUbr/3Z/+9DChX/zie2sJ1gUEJgL95KtPYvov/Fekbm60+w2WUJsRHfljD1AAo1lqCdZF5FMwSgMLc12KRhTM+YWlcubQPQdLBMriNNDxLEGtSAX+5g2OdttgcaW4CMRs6tJCn8USvgrAKaazlywOvEPpHGbhPip3/MMncZgA7jxSvhUAm/HUCHGG9No8d/uchcszjCBw5IA3LCUipdIRKNBAwVywqMLAXtpOj2+MSPmmlcUtugDD6/bBAqlxnFKKWsMhrEUIvzoopS61Si2ntTIv3kmF7/vUuIvTagHXAipVZ2BeAn/72i7QrYMFojU8WD9YN+iVQ7lw/mr+WtMPc4YTlq+qa5mPHgSUU+7sZQY4WJnHnwXp1sEKlP+CMPOm5KcW9SlMZV4NYr+ZXSf8ZlRvpz/HiDxGfc/3y8YIcOXXmuWuR7fPWbT53qhJxSqqSkn4IuiW7VrqCgtt5s0Dy4qiIGob1Ve1Q8f3BXXWiFFEZbu1lQV4i7cKFiomy3khPS81Iq5sZ4AbIizTIOYS77yB8b30rYIgctbkpCjZRVaSZ4A4VUG9HdrpJXlMHi1Aw98iWJzDCint9G2z1FDapLcLCp5Tp40s4aWFsb2iIkHTOxzYn51eImyM1Ugo5bEjwDoVpVX4vTGCTfYWYNnfHlhgMggR+c4LXEgaDdsm7ScW5tqH6xqApOAc/8OkPAt8odIRKtgNXkwRYYzU5AsHHwhXR23imlqRkXfOfVLwgsLeza1OD8v40+XOCFZEfQW7+6b0ZtCC/9gABIxnguUHuycsdBMo4Et7Q7AOfEt0KqSWaRNgZKd5/YzrbeosDiZWaw3UkCkl+NOp8gPqW4MdzXVsAhbK5MsGOMjGzQbrk09hyS1ZbaAbQKlzCoo+NItkGTnpqntlZwmugmdtrOg3NQr8/NQBCx6sh1eEeSmwgLPaTeUbZhJsEzNboSTrdYHWuxLPyqTGzAFQmI+Ca6enbxMsYI7mOnFdz9QoyFo7DXQFA79ZliFJOA/Bwr3yH7AzpMCiESgmT46l1SOVpkIpV7RbgS+FJDMCIz840T0CC7aq6pmMF5J68rYtbXbepSinVmndNJKAKoOIJl5jwCMr6PZIDIiUIajA3grVXqHlHMNvsWHEsLPg537jPoEFnKXXmL2nLWF9R9o0oPQoyxak3dH+d0w8Cnb7yRUpAav2Pg0EetF0s3zRvJns3CsxFMPVLA6a0FBadWJDqvnezjg98i14SWM59H3VWU+mDNqpRtqHNACwwEybgpiZtkdOrx2Fu02w6Gt5QfuZ59VYv6E/xFurxDYaqRhZHdAkuC7EYG3CfDZuB6+GoNhBYfEBbrVzhwDZ9NYH9wmsZu+iRkXgrLBdjT8VHLWzYL0ciGickqejQznlz5pNHjQUZqCpom9hId7cRiTwr8Lz1nUNrVs0SofvCMlYi+Ob4o62V9VqBx1taV6XXW4lYFXPyaSBCeyHfldRHdyjn5bZRc2mHhoaZ9f1Dm8JLGHxEeyETCatjdqQsic3RbF6M/R1KBkmRAzv0SWnnOpyGYt2XqIzORY2xs4bAXZWgFNY72sTDVlLzxL+ngwAP6JWBC/gOoDdClgUqz5BCNGw1mgBZriatHopr4B9AJjQqimt0rXfrAhKN8HwRJU2NQ2YPBzhNglIwu6hCTwf+ACTNVd7QTPUb/hgF991sKyA8nqFaBuLxXdpv8/2Z5/Ckn2Qqfp7MypB7HJdIOgULHcZOzPgGboh2Wv5YJwJ6juHk4/rztyfCHBfmkEluId3HyweBM6LGCimW3LBN97J2p6VAXZJUF5aNXAEDpSvqZa2bluGsf/sMfhPpa50LoIH1WnYlJHQ7v2NAJTGCHuj6xXG3wZYQnDY4piWCTCMJGiW3qMsWKzcENxXgNdbmQELxhRWREGW9RVgHg9u0OvAFxSW0jzpz7pIoTw8Q+1lcOibAb2WM307Ost/1Es2dc9Gxjoc7MwJo5xSHyOitJEx9F2y0xSW33wznkXcq9zeH/lRgLtk44C4Y2i0oFc6b1F6DbfqpCEyabi7B1ZjndSYdopdjcr60FknWUN9feiriIOuXjdxZKQ9tNAa9dzYEAUK0SYXWClJSz+Cfz5ZhcfKK+A1xUPNknwbe5B3EyxB0TwSpT1Y5NhWkOCfnFQVRtszSqs35EEklK+OJ6NpckNpk7MAjA/bdfWRJRr1A5AqwDZQmM7RjBSf0AE2/YhvSkAvbc67GC69jmF6w5wF7m9ER0eSTWweCTv6sWOpFyRjoTIwGxXYWpzWDX/YA5t9vVUtx1aDDqUy0q9T+HgUCIzGezqgGJtYpNKk1vAEluWmHodLeh1dKXA3wQKHzTpSrZ49E0hm5OAJ2IZH7YxPDS5gCTY3QUVzh6QPUIAfev/9EvRSaAMswF5gTFQ5pwo8Hat5QLwwsb2A68pNuMmwjwAaYMld6zqdmjcKFpa2CKu+g0HyyXkndq8TRNRqAILGbsW8fodi3Mty9lCH29NBPZdJjCMzDMm7eB6PPHYUflZEpdP4sAnm6bgq2Kl4BRO2pk60yZ7jXyPXeqNgoTqhjVXCat40Kt4+ohHlvPQOcDPyxkxWYULwP7A0dKZiZlhkE9fTzp/L4G6rQzR1sUJrRfOotFHt27ABrDYssGzpmcyA5cGeeh2r9GbFkArqHEsPFO103q8cjjFi+jqT3QOlvVaFvQ28nub7lP6HO4RJMDrOYcCqUSFyHf9yk7kR+BSqMrTt6r15UcTmdSytGwMLz6TAvXC/DdLBYlcZ5eQBKF88q8LfPbdNDe+SfpNrsKqa7yaXAeoQz4LRLgxMQpZXYCcAzeTTJ+sYaR3rdvA+2/uUq02wP5x3GbDcmnwbXCO4fENgcXSIqQJV/d6eMBXa8P261q80iFrrxmIQ03I1Xos4kq6p0ibEiPybwkcBXiG6UROvGv86TuZGz3RuJP1FcuBco5r5hsBCdy3yuQKTuzYRJ5g5bGExWMAYp5liGmClcexXPCnPxBaMj9lkraTPUvHRjSLuLKbvBmMsOO2WTeMEbtlr3j2jFMTMBylpPQXlnugapk3oMVhYYGQaD5gvrIwXW3qD0M07pwsjX40Ay0iAHvVmAIUv6ITa+HkNKpnJw/1W7p67Q62Iq8A5k4wlcV4GenhtkHQg0SgA99AEyw3Lf4+vB6eI3bx4Onrhgc8xva0a6BdNglYhOf+7mlSY0tELaSpFAGvvGmmLmwKL+yKgz8oA0cyCdxrTrYgrMKZMGIBN3sZPXlQvihFLcJ+xChUs0uordACnEfv20QgGHi9M0W4766trh/yOgYWZePpp3wP3NjmdC2zwJ8Ifq1e4LHi9ZpgOaEKtD/UH/GaFzJVCQg5HIsIyPmH9TaJNP9VMoNx9OrajYAtpvMk6CW67eufAEiAkjQeTbcr2wFhsHyn4dZL9C2jU6WOA2dDCJ01foGmBfBca4WUwU0Py1xbVVcqBtqTG+W1pezVy0LRmggrKF6fpr8PmCKrgGIvE6JXMrRuzs7jzKslYafEi8riqphV8AEc0WtMboLHnnSl9lXZrhspiNkYsKo34DtwCBZ6ACcyLV6wZsDDYbBSdupgRIwcltNCuVFJzcxY8bOoJWAwjK6vNIJhGdQVGRI+0R2KcZYmbP5b8N/pmFS2TNik/isWM8tZU5Wnr9rw7lvAELC4aO5m4BvF6DQHTuFOcxUu9aYAEfeKdOuayJmKIdR5B4z0LM2nR3q5eiCqZ+p9hWlmOfTs+eittd2zjM/Cz2yK9fuAsOjJuwfRusA/O950Sw2j3zUw+q+aGJw7sYP600QEMMapg6NCVppU9pAiIAkfJtPClF5LVsdW6UrYn6UUGXuULJx0wxjwj5Wk59LQ/DrPHIsO7AxbGWGbkC8tCx2nj8Qeo8APLei1DQMBQ42stvKT8VsW0s/CjcZ23qPfJ9MxkGGdVZ2hnp6BgR26kC0UYpjLAgBFWcKWDVxYOltDdR1EbYzLjtbqhfLE7HAxKpcFMl8hw0BpiHkOaTk+/4Y8wydHIgMWkS8ooQnzwjtjupH5bysqjUivdgYJjDXef6jtOQbU9aWM0X1l3g7MEPNPxpp4oePvkp8p8ep+pbGOsHPmYkR+uIhtk6ZQG6FemQbzo/j/NziNZwSkozys5PYsGSwB/C/BCtGiNJ+nWXHJBSYjMnIENltArcJExDmYGDWJaX6HBZjs95Vqmdj5FBlhvWldM8SyeszgW0abnivl0tOUzxMJsqaxLKkMwaY/aYG/MizqcPME6G2Z8h3msNmeAOSuzWa/J74aCx5hwlPHJvFAHhHU97eyfJFGTXkx5lwbYPnHBIf30ScWoHAGLQkqZvrudraVI7i+PrhhbXjhYgjd68Vwn5Lruz5wHncnie+StqldSu2mKVl+ZfpD2A7xM8fucmyN5On14FTlc/G4Im1gNmGIGLXtczj7vduA1ZtpsyINdcIRqsMnN+4583yaZfhYcb+4A2RPJMQLY8cVVeGtxYHGO5xHy0iud58TE1OWHgWeLsIkOS/2PjBd58dnrthayPBOX5lskYMDX/Eqp1sWBhWUEvh+cteNKhFynpiM/ZDRTyGptOYkY/sxMcs0Xk/3pETA+cbWup8WBhS0OvtU8kZP6vpyU3rI0eJMEa7wDzAXhgguZz8G9jObDGgFn+gPrLMr9UaeCy9BvRiBhePnrEMCrq6WZUJeFejOOzFwlracSht6l9/dsc3OxPTD9z65kaC1QZ4EaGOxpBaHLbL2871xhqYConYXnAllkoZdv4nbamMPc7oHzYcESFlWHsa6RsYYn/bXVHNQ2QLXtWQGrXZQQw/jWuzz3X5XpDRcfxfnuFbBaEFiYmFKcPjkJ3bigA8MppPdr5xIqwZ9HZgvJuPQ0znT0f5o/D7i9TSpPLhvAaZWcR2YdoUdc+VpYxauPFgEWnqmKf3V3JikGl0nWPrt8dGFFzl/nKnBM2Lt2u3M8py8VEcW+6u6l5UN4ffAu/VUXO4XetbAeqqAsLgIsCqrd57pzppZoU88leyuXPjg8gYZWyby3JGk9I4+dTnu+ggeb9XWOMyMFFfTMWJ9kNbvX0GmPYmgtBCzL50JUj4mHzyyeD2FvOpdvz9jwQOu9OWih2yjJ6kBl88qaMKg/uHyxPlUiMut5JXM9eRTgeSsfACyfqyDYP8GyBpbMp1yll4OFDflCt2PO2fEY2dkFLF/N7Y5yycum5V9aIYppxKj0wLgvlv6uOXCloCG/EJ3lW4Eax3kTpdU+ov7lE6EwW+6cYohlTvL4ZCXgFl9pm3PQVN6n0eVLBRfM0j3mMyvw0CO1+00KD/n2wQIGUt0HJJV6OC1ZmVM+5oJF/QDhMOUQfqydUd9SojlfDn90FM1zKjflAW+WZ916rA6XnnxGlVUwYLoAsEAt+M4rOY4fwWVwWA4a+R8Zltu6xGiqCGGDaGGLuBUcm0hiVel6MxA5XxFDrWEFCwNmetDwrx+qlEbFqnEXY2eN9pOCFdy6XNJ7VGQSmKln0gzVvexQ5FlhmXXeuh6nMgysHGIYUxyyNyon+kOaOQDhEloAWDwKGr1x10NM7aNC7C26xDUjdy47bwBXoW3hHJhzYNhvF1i5mwep0/Yy/cDtiBat8l6IztqtTB0422XktFUswt3pkUwsHuOlUYDJ4+As04Rj4wkjIne9ghjsYNeC2SOGVfSF5rkAsERp2uCtG3IfDIqlA0TpXaZsDdTUugPPXkVKNftzQg+VrsgvQyjo5tEbdqUpVLFU6yIU/LG0pzxuE9iUixW5CnUss8dWkJM67Oxg4QfNn2Z3y/G/2l08sC7vEJvS5F1GynWrYI7nWmDpI2ep3vn1GnTQs72vcr87Ak+RxCLw7knG8vSIfKu4rygfAZQzGZDkny9gmNxrbfZTSpXoovtTq+BB6NfkLKW9lfEVdH2ZPCwQV9OmGMVecNs88srDoJNuvezOPwXkzTB/tBNPEyTpmgqmO9hv0XTwKeeNpDdQv9+akdVukL+QAI1KznVRs23E4jGq0Aho5D8x63THdDIs4AfTI9NYAyVYHhbcDq8nhr4Y7E0ECLtOyE5HBbQIWCCECrc7M6uAptfRKIiqP8yfiEve5rVKMYrb6Jk+AjDa6egWFbzwR69n45y2V9Zl5iJvCyQo2GCkVsrZF1OH44466ssLjhlh68PcYPlq8CBzhCV2sN8mWHh6R22Kli2PR9h8lHtPxxNk1Kc76NwYdhY23JNe3ccO8rlg2d55PXeIhQf0rcxkD1n5SSGsrgyWhkPtvpzpTY7PkkOjO78qgc20uwoS4dpGegMzqDUZYbf0/NkxV77OLe488DvGQa/gM9nktNgrZ64IFjwqakVdzAXYscWITcs7nYKxRzz04jTOJ2SqONAleHqIv58XKcXKyHcruTlL8UyTOpo7lQZ2ZIm8oF8RLBWBs+EcSxlOyhhsdrKiCta1KstaKV+QK0Ww3p/IC0ppENteM6+8w8fEW9PslYS1q3jaiMhrQ18RLBqB3V3F0ztIUm7M2kdKjYp18wnRueh4sDgrLbOqPyGwWs9ySpHAMF+jnK1Qla90/jCvZXhVMVRUoe7FhzWu95F7Jb+os+UPDkC5X8A7OjB/cbEDoLhayjkOxf3QLIpH46FSErcAVqCeVJJF6eQwOehgj2ExjVnFQvWLEtdJQH9+dgdPMurV8267yqdmXxVCF7brVgE1e9XdkA7XYkHRK8Ls8yN8cZdfqOyJnrVtJuefpZYMZ19QY2JL25b7ue0sbGJPB/Nhi/A8clrVhVI3AxZ2uQNY/uhQyvFRVXjYBClXqW/lyOckwyqMGXTPQcyYLlnDo9Mq7anhmETHdN4H69dJLV7hFCzP06f55GEubLxG9ajj3smtdTN/pWkFuf3p4mARBAvPsJi2BICtVSw2iqaYEPWJ16dbkE4evcTU6ZwxPVbzesfxv2Z+G2IHATaW5FsrnvTgmlxcpmCDZV55sSCwXM1ZpcbJbADKJmuDotW/kRgkB3Hi6U41PM19j8w3qqRHTp5V27MCqU9dJjV9yntOfqb7eKyzidaP+HaLnHMuDBbuUWuPtIeSzB0EaLdgRSuIBSj3JPBuewDWjyU6bNv2XHUflqsYL/XsGfnUOh54nGfOqL6I6ie2mzHb+g2Uw5sBC7v+yNNVnWGZPGlwn4tGhpRzJidlZjXgrTcNyhv9+Qaqi+fiO2tkxpaI027gPWLDVM61lirgyJrlvrKavyj+CjpLkpfxCcnJni7PnKjoK4BoVPamHjKeP6Q2BUxlfoRhD7Zf+lrqYWdYC6A9A51Dc1rCOuVmnlJCVqu5mw+vABboCs+djdK+awUBLyaGurtnapyHtQiUrArO5o1ok0p9BNxTP0e5naRKNWrg3Vm5wcLjaWzDzLXJeSOvfi8Oli7iGBO6zy5538kdv0Lyfdju8eBWLJOJb4PHAUf4qq9h2SazJaHEDe2ad97UiRyUIpK6DKSrQ3O+HswfgsfjGoWu6PLkVSGFjdLxBqYrpj30/QtaDfhyKvWoT1wXQWeaSK9LsbgElBbe12Ms+aPPEDuMB3D24h6d6VX8amVAaV4X8QkemTGe+PhGns3ed2hOJ60wWLHTHHcR6crWd8MiWOGrvEb1yriQP+lGOtTN0xwPgyepPiUPHkulG39TnY2d6xnCZ8XzlneIQUV3tqd7rRg5zuujFRdD9AQn1ZA1cr5bzMKKIvr3N7Pny4Eg9ztgYNOIW85TU8O7pL2ZHKq8Dyszw6bw5Xrel4CJ0oOMGSdBNnq7eVmzOFiM4fPAYvzQDsnxqBBWlhV09UltUyFk5BDf8KXwXYXHMvllPAILyYPBmHFEE8/vZCkK4dv/yNsugZlvgl+ZGWB8BupNgQUDtMsT2unmqFlLDej8b9mgSlO/yREP1aLn5sXys6SdmQ/7mYtI/zfMqXL86uqcr8NizqN8glxYZ6Hb+3SlmpBDi9Zl8k2nahAGMql+q7jaN69Vp9FQVc1eBdoP8j4uquZ9verkfdmmBovl7IVAkpptZ99HWZQyr7Qc34P+3MULvllwChfcIO8tKGa25c9ElDJgoW9Y5f+URLWP8TONphmwdBjpwkf0cRMvKoaeJGtFd8CPhGIxzA+WVvBrzdI/JbWcRmFHmu08+Kell14RMSR5G24/UsocrrqkJS1pSUta0pKWtKQlLWlJS1rSkpa0pCUtaUlLGtP/A79Ipc+FMiPmAAAAAElFTkSuQmCC",
                            "alt_text": "AXA International"
                        }
                    },
                ],
                "id": "InsuranceLegalPerson",
                "credential_definition": {
                    "type": [
                        "VerifiableCredential",
                        "InsuranceLegalPerson"
                    ],
                    "credentialSubject": {
                        "insurerName": {
                            "display": [
                                {
                                    "name": "Insurer name",
                                    "locale": "en-US"
                                }
                            ]
                        },
                        "leiCodeInsurer": {
                            "display": [
                                {
                                    "name": "LEI code",
                                    "locale": "en-US"
                                }
                            ]
                        },
                        "contractId": {
                            "display": [
                                {
                                    "name": "Contract Identifier",
                                    "locale": "en-US"
                                }
                            ]
                        }
                    }
                },
                "format": "jwt_vc_json",
                "cryptographic_binding_methods_supported": [
                    "did:jwk",
                    "did:key"
                ],
                "proof_types_supported": {
                    "jwt": {
                        "proof_signing_alg_values_supported": ["ES256", "ES256K"]
                    }
                },
                "credential_signing_alg_values_supported": [
                    "ES256"
                ],
            },
            "DBCGuest": {
                "display": [
                    {
                        "name": "DBC Guest (DIIP)",
                        "description": "The DBC Guest credential is a DIIP example.",
                        "background_color": "#3B6F6D",
                        "text_color": "#FFFFFF",
                        "logo": {
                            "uri": "https://dutchblockchaincoalition.org/assets/images/icons/Logo-DBC.png",
                            "alt_text": "An orange block shape, with the text Dutch Blockchain Coalition next to it, portraying the logo of the Dutch Blockchain Coalition.",
                        },
                        "background_image": {
                            "uri": "https://i.ibb.co/CHqjxrJ/dbc-card-hig-res.png",
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
                            "uri": "https://dutchblockchaincoalition.org/assets/images/icons/Logo-DBC.png",
                            "alt_text": "An orange block shape, with the text Dutch Blockchain Coalition next to it, portraying the logo of the Dutch Blockchain Coalition.",
                        },
                        "background_image": {
                            "uri": "https://i.ibb.co/CHqjxrJ/dbc-card-hig-res.png",
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
                            "uri": "https://dutchblockchaincoalition.org/assets/images/icons/Logo-DBC.png",
                            "alt_text": "Aaneengesloten open blokken in de kleur blauw, met een blok in de kleur oranje, die tesamen de achtergrond van de kaart vormen.",
                        },
                        "background_image": {
                            "uri": "https://i.ibb.co/CHqjxrJ/dbc-card-hig-res.png",
                            "alt_text": "Connected open cubes in blue with one orange cube as a background of the card",
                        },
                    },
                ],
                "format": "jwt_vc_json",
                "credential_signing_alg_values_supported": [
                    "ES256"
                ],
                "credential_definition": {
                    "type": ["VerifiableCredential", "DBCGuest"],
                    "credentialSubject": {
                        "firstName": {
                            "mandatory": True,
                            "display": [
                                {"name": "First name", "locale": "en-US"},
                                {"name": "Prénom(s)", "locale": "fr-FR"}         
                            ],
                        },
                        "lastName": {
                            "mandatory": True,
                            "display": [
                                {"name": "Last name", "locale": "en-US"},
                                {"name": "Nom", "locale": "fr-FR"}         
                            ],
                        },
                        "email": {
                            "mandatory": True,
                            "value_type": "email",
                            "display": [
                                {"name": "email", "locale": "en-US"},
                                {"name": "email", "locale": "fr-FR"}         
                            ],
                        },
                        "amount": {
                            "mandatory": True,
                            "value_type": "integer",
                            "display": [
                                {"name": "Amount", "locale": "en-US"},
                                {"name": "Nombre", "locale": "fr-FR"}         
                            ],
                        }
                    }
                },
                "scope": "DBCGuest_scope",
            },   
            "TestCredential": {
                "format": "jwt_vc_json",
                "scope": "TestCredential_scope",
                "credential_definition": {
                    "type": ["VerifiableCredential", "TestCredential"]
                },
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
                    "ES256K",
                    "ES256",
                    "ES384",
                    "RS256",
                ],
                "display": [
                    {
                        "name": "Test Credential",
                        "description": "For testing purpose",
                        "locale": "en-US",
                        "background_image": {
                            "uri": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAPcAAACUCAMAAAB4Mk+VAAAACVBMVEX///94qff///xmEYKgAAAArUlEQVR4nO3PAQEAAAiAoOr/6IYgD5i9IfW29Lb0tvS29Lb0tvS29Lb0tvS29Lb0tvS29Lb0tvS29Lb0tvS29Lb0tvS29Lb0tvS29Lb0tvS29Lb0tvS29Lb0tvS29Lb0tvS29Lb0tvS29Lb0tvS29Lb0tvS29Lb0tvS29Lb0tvS29Lb0tvS29Lb0tvS29Lb0tvS29Lb0tvS29Lb0tvS29Lb0tvS29Lb0tvS2oO8HwB8BvTnVwPgAAAAASUVORK5CYII=",
                            "alt_text": "ABN Amro Card"
                        },
                        "background_color": "#FFFFFF",
                        "text_color": "#000000",
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
                        "email": {},
                        "phone_number": {}, 
                        "gender": {},
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
                    "ES256K",
                    "ES256",
                    "ES384",
                    "RS256",
                ],
                "display": [
                    {
                        "name": "Verifiable Id",
                        "decription": "Personal ID",
                        "locale": "en-US",
                        "background_color": "#12107c",
                        "text_color": "#FFFFFF",
                    }
                ],
            },
            "EmailPass": {
                "format": "jwt_vc_json",
                "scope": "EmailPass_scope",
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
                    }
                ],
                "cryptographic_binding_methods_supported": [
                    "did:jwk",
                    "did:key"
                ],
                "proof_types_supported": {
                    "jwt": {
                        "proof_signing_alg_values_supported": ["ES256"]
                    }
                },
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
            "Over18": {
                "format": "jwt_vc_json",
                "scope": "Over18_scope",
                "credential_definition": {
                    "type": ["VerifiableCredential", "Over18"]
                },
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
                    "ES256K",
                    "ES256",
                    "ES384",
                    "RS256",
                ],
                "display": [
                    {
                        "name": "Over 18yo proof",
                        "locale": "en-GB",
                        "description": "Proof of majority",
                    }, 
                    {"name": "Preuve de majorité", "locale": "fr-GB"}
                ],
            },
            "PhoneProof": {
                "format": "jwt_vc_json",
                "scope": "PhoneProof_scope",
                "credential_definition": {
                    "type": ["VerifiableCredential", "PhoneProof"],
                    "credentialSubject": {
                        "phone": {}
                    }
                },
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
    "BASELINE": {  # DIIP V3.0
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
        "credentials_types_supported": ["IdentityCredential", "EudiPid", "Pid", "EmployeeBadge", "AdminBadge", "LegalRepresentativeBadge", "ManagerBadge"],
        "credential_configurations_supported": {
            "EmployeeBadge": {
                "format": "vc+sd-jwt",
                "scope": "EmployeeBadge_scope",
                "order": [
                    "given_name",
                    "family_name",
                    "role",
                    "organization",
                    "website"
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
                        "role": {
                            "mandatory": True,
                            "value_type": "string",
                            "display": [{"name": "Role", "locale": "en-US"},
                                        {"name": "Rôle", "locale": "fr-FR"}],
                        },
                        "organization": {
                            "mandatory": True,
                            "value_type": "string",
                            "display": [{"name": "Organization", "locale": "en-US"},
                                        {"name": "Organisation", "locale": "fr-FR"}]
                        },
                        "website": {
                            "mandatory": True,
                            "value_type": "uri",
                            "display": [{"name": "Website", "locale": "en-US"},
                                        {"name": "Website", "locale": "fr-FR"}]
                        }
                    },
                "cryptographic_binding_methods_supported": ["DID", "jwk"],
                "credential_signing_alg_values_supported": [
                    "ES256K",
                    "ES256",
                    "ES384",
                    "RS256",
                ],
                "vct": "urn:eu.europa.ec.eudi:employee_badge:1",
                "display": [
                    {
                        "name": "Company Badge",
                        "locale": "en-US",
                        "background_color": "#ed7b76",
                        "text_color": "#FFFFFF",
                    },
                    {
                        "name": "Badge Entreprise",
                        "locale": "fr-FR",
                        "background_color": "#ed7b76",
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
                    "issuing_country",
                    "issuing_authority"
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
                        "gender": {},
                        "address": {
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
                            "12": {},
                            "14": {},
                            "16": {},
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
                        "name": "Personal ID",
                        "locale": "en-US",
                        "background_color": "#14107c",
                        "text_color": "#FFFFFF",
                    },
                    {
                        "name": "Personal ID",
                        "locale": "fr-FR",
                        "background_color": "#14107c",
                        "text_color": "#FFFFFF",
                    }
                ],
            },
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
                                        {"name": "Picture", "locale": "fr-FR"}],
                        },
                        "portrait": {
                            "mandatory": True,
                            "value_type": "image/jpeg",
                            "display": [{"name": "Portrait", "locale": "en-US"},
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
                        "name": "EU Person ID",
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
                    "portrait",
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
                        ]
                    },
                    "portrait": {
                        "value_type": "image/jpeg"
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
                        "value_type": "email",
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
        "credentials_types_supported": ["IdentityCredential", "EudiPid", "Pid"],
        "credential_configurations_supported": {
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
                    "issuing_country",
                    "issuing_authority"
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
                        "name": "Person ID",
                        "locale": "en-US",
                        "background_color": "#14107c",
                        "text_color": "#FFFFFF",
                    },
                    {
                        "name": "Person ID",
                        "locale": "fr-FR",
                        "background_color": "#14107c",
                        "text_color": "#FFFFFF",
                    }
                ],
            },
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
                        "name": "EU Person ID",
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
        "authorization_server_support": True,
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
                        "name": "EU Person ID",
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
                    "issuing_country",
                    "issuing_authority"
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
                        "name": "Person ID",
                        "locale": "en-US",
                        "background_color": "#14107c",
                        "text_color": "#FFFFFF",
                    },
                    {
                        "name": "Person ID",
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
    "ISSUER-ALL": {
        "oidc4vciDraft": "13",
        "siopv2Draft": "12",
        "oidc4vpDraft": "20",
        "vc_format": "auto",
        "verifier_vp_type": "vc+sd-jwt",
        "oidc4vci_prefix": "haip://",
        "authorization_server_support": True,
        "credentials_as_json_object_array": False,
        "siopv2_prefix": "haip://",
        "oidc4vp_prefix": "haip://",
        "credentials_types_supported": ["Pid", "DBCGuest", "EmailPass"],
        "credential_configurations_supported": {
            "EmailPass": {
                "format": "ldp_vc",
                "scope": "EmailPass_scope",
                "credential_definition": {
                    "@context": [
                        "https://www.w3.org/2018/credentials/v1",
                        {
                            "EmailPass": {
                                "@id": "https://github.com/TalaoDAO/context#emailpass",
                                "@context": {
                                    "@version": 1.1,
                                    "@protected": True,
                                    "schema" : "https://schema.org/",
                                    "id": "@id",
                                    "type": "@type",
                                    "email": "schema:email"
                                }
                            }
                        }
                    ],
                    "type": [
                        "VerifiableCredential",
                        "EmailPass"
                    ]
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
            "DBCGuest": {
                "display": [
                    {
                        "name": "DBC Guest (DIIP)",
                        "description": "The DBC Guest credential is a DIIP example.",
                        "background_color": "#3B6F6D",
                        "text_color": "#FFFFFF",
                        "logo": {
                            "uri": "https://dutchblockchaincoalition.org/assets/images/icons/Logo-DBC.png",
                            "alt_text": "An orange block shape, with the text Dutch Blockchain Coalition next to it, portraying the logo of the Dutch Blockchain Coalition.",
                        },
                        "background_image": {
                            "uri": "https://i.ibb.co/CHqjxrJ/dbc-card-hig-res.png",
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
                            "uri": "https://dutchblockchaincoalition.org/assets/images/icons/Logo-DBC.png",
                            "alt_text": "An orange block shape, with the text Dutch Blockchain Coalition next to it, portraying the logo of the Dutch Blockchain Coalition.",
                        },
                        "background_image": {
                            "uri": "https://i.ibb.co/CHqjxrJ/dbc-card-hig-res.png",
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
                            "uri": "https://dutchblockchaincoalition.org/assets/images/icons/Logo-DBC.png",
                            "alt_text": "Aaneengesloten open blokken in de kleur blauw, met een blok in de kleur oranje, die tesamen de achtergrond van de kaart vormen.",
                        },
                        "background_image": {
                            "uri": "https://i.ibb.co/CHqjxrJ/dbc-card-hig-res.png",
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
                    "issuing_country",
                    "issuing_authority"
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
                        "name": "Person ID",
                        "locale": "en-US",
                        "background_color": "#14107c",
                        "text_color": "#FFFFFF",
                    },
                    {
                        "name": "Person ID",
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
