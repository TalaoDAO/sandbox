TALAO_ISSUER = {   # draft 13 with ldp_vc
        "oidc4vciDraft": "13",
        "siopv2Draft": "12",
        "oidc4vpDraft": "18",
        "vc_format": "ldp_vc",
        "verifier_vp_type": "ldp_vp",
        "oidc4vci_prefix": "openid-credential-offer://",
        "authorization_server_support": False,
        "credentials_as_json_object_array": False,
        "siopv2_prefix": "openid-vc://",
        "oidc4vp_prefix": "openid-vc://",
        "credentials_types_supported": [
            "EmailPass",
            "PhoneProof",
            "VerifiableId",
            "Mosip"
        ],
        "credential_configurations_supported": {
            "Mosip": {
                "format": "ldp_vc",
                "scope": "Mosip_scope",
                "credential_definition": {
                    "@context":[
                        "https://www.w3.org/2018/credentials/v1",
                        "https://mosip.github.io/inji-config/collab/contexts/university.json",
                        "https://w3id.org/security/suites/ed25519-2020/v1"
                    ],
                    "type": ["VerifiableCredential","UniversityCredential"],
                },
                "cryptographic_binding_methods_supported": ["did"],
                "credential_signing_alg_values_supported": [
                    "Ed25519Signature2020"
                ],
                "display": [{
                    "name": "Graduation Certificate",
                    "locale": "en",
                    "logo": {
                        "url": "https://mosip.github.io/inji-config/logos/mosipid-logo.png",
                        "alt_text": "Certificate logo"
                    },
                    "background_color": "#f8efea",
                    "background_image": {
                        "uri": "https://mosip.github.io/inji-config/logos/mosipid-logo.png"
                    },
                    "text_color": "#000000"
                }],
                "credentialSubject": {
                    "studentName": {
                        "display": [
                            {
                                "name": "Student Name",
                                "locale": "en"
                            }
                        ]
                    },
                    "rollNumber": {
                        "display": [
                            {
                                "name": "Roll Number",
                                "locale": "en"
                            }
                        ]
                    },
                    "dateOfBirth": {
                        "display": [
                            {
                                "name": "Date of Birth",
                                "locale": "en"
                            }
                        ]
                    },
                    "gender": {
                        "display": [
                            {
                                "name": "Gender",
                                "locale": "en"
                            }
                        ]
                    },
                    "courseName": {
                        "display": [
                            {
                                "name": "Course Name",
                                "locale": "en"
                            }
                        ]
                    },
                    "courseDivisionName": {
                        "display": [
                            {
                                "name": "Course Division Name",
                                "locale": "en"
                            }
                        ]
                    },
                    "courseDuration": {
                        "display": [
                            {
                                "name": "Course Duration",
                                "locale": "en"
                            }
                        ]
                    },
                    "result": {
                            "display": [
                            {
                                "name": "Result",
                                "locale": "en"
                            }
                        ]
                    },
                    "startDate": {
                        "display": [
                            {
                                "name": "Start Date",
                                "locale": "en"
                            }
                        ]
                    },
                    "completionDate": {
                        "display": [
                            {
                                "name": "Completion Date",
                                "locale": "en"
                            }
                        ]
                    },
                    "face": {
                            "value_type": "image/jpeg"
                    }
                }
            },
            "VerifiableId": {
                "format": "ldp_vc",
                "scope": "VerifiableId_scope",
                "credential_definition": {
                    "type": ["VerifiableCredential", "VerifiableId"],
                    "@context": [
                        "https://www.w3.org/2018/credentials/v1",
                        {
                            "@vocab": "https://schema.org/",
                            "VerifiableId": {
                                "@id": "urn:employeecredential",
                                "@context": {
                                    "@version": 1.1,
                                    "@protected": True,
                                    "id": "@id",
                                    "type": "@type",
                                    "schema": "https://schema.org/",
                                    "family_name": "schema:lastName",
                                    "given_name": "schema:firstName",
                                    "birth_date": "schema:birthDate",
                                    "gender": "schema:gender",
                                    "issuance_date": "schema:dateIssued",
                                }
                            }
                        }
                    ],
                },
                "cryptographic_binding_methods_supported": ["did"],
                "credential_signing_alg_values_supported": [
                    "Ed25519Signature2020"
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
                        "display": [{"name": "First Name", "locale": "en-US"}],
                    },
                    "family_name": {
                        "mandatory": True,
                        "display": [{"name": "Family Name", "locale": "en-US"}],
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
                    }
                }
            },
            "EmailPass": {
                "format": "ldp_vc",
                "scope": "EmailPass_scope",
                "cryptographic_binding_methods_supported": ["did", "jwk"],
                "credential_signing_alg_values_supported": [
                    "Ed25519Signature2020"
                ],
                "display": [
                    {
                        "name": "Proof of Email",
                        "description": "Proof of email",
                        "locale": "en-GB"
                    },
                    {
                        "name": "Preuve d'adresse email",
                        "description": "Preuve d'adresse email",
                        "locale": "fr-FR"
                    }
                ],
                "credential_definition": {
                    "type": ["VerifiableCredential", "EmailPass"],
                    "@context": [
                        "https://www.w3.org/2018/credentials/v1",
                        {
                            "EmailPass": "https://doc.wallet-provider.io/wallet/vc_type/#EmailPass",
                            "@vocab": "https://schema.org/"
                        }
                    ],
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
            "PhoneProof": {
                "format": "ldp_vc",
                "scope": "PhoneProof_scope",
                "credential_definition": {
                    "type": ["VerifiableCredential", "PhoneProof"],
                    "@context": [
                        "https://www.w3.org/2018/credentials/v1",
                        {
                            "PhoneProof": "https://doc.wallet-provider.io/wallet/vc_type/#PhoneProof",
                            "@vocab": "https://schema.org/"
                        }
                    ],
                    "credentialSubject": {
                        "phone": {
                            "mandatory": True,
                            "value_type": "email",
                            "display": [
                                {
                                    "name": "Phone number",
                                    "locale": "en-US"
                                },
                                {
                                    "name": "Numéro de téléphone",
                                    "locale": "fr-FR"
                                }         
                            ]
                        }
                    }
                },
                "cryptographic_binding_methods_supported": ["did", "jwk"],
                "credential_signing_alg_values_supported": [
                    "Ed25519Signature2020"
                ],
                "display": [
                    {
                        "name": "Proof of phone number",
                        "locale": "en-GB"
                    },
                    {
                        "name": "Preuve de numéro de téléphone",
                        "locale": "fr-FR"
                    }
                ],
            },
        },
        "grant_types_supported": [
            "authorization_code",
            "urn:ietf:params:oauth:grant-type:pre-authorized_code",
        ]
    }