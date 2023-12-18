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
                    "id": "VerifiableId",
                        "display": [
                            {
                            "name": "Verifiable Id",
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
            },
            "schema_for_type": False,
            "credential_manifest_support": False
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
            "siopv2_prefix": "openid-vc://",
            "oidc4vp_prefix": "openid-vc://",
            "credentials_types_supported": ["EmployeeCredential",  "EthereumAssociatedAddress", "VerifiableId", "EmailPass", "PhoneProof"],
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
                            "name": "EmployeeCredential",
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
                            "name": "EthereumAssociatedAddress",
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
            ],
            "schema_for_type": False,
            "credential_manifest_support": True
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
            "credentials_types_supported": ["EmployeeCredential",  "EthereumAssociatedAddress", "VerifiableId", "EmailPass", "PhoneProof"],
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
            "credentials_types_supported": ["EmployeeCredential",  "EthereumAssociatedAddress", "VerifiableId", "EmailPass", "PhoneProof"],
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
                            "name": "EmployeeCredential",
                            "locale": "en-GB"
                        }
                    ]
                },
                "EthereumAssociatedAddress": {
                    "format": "jwt_vc_json",
                    "credential_definition" : {
                        "types": [
                            "VerifiableCredential",
                            "EthereumAssociatedAddress"
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
                            "name": "EthereumAssociatedAddress",
                            "locale": "en-GB"
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
                            "locale": "en-GB"
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
                },
                "PhoneProof": {
                    "format": "jwt_vc_json",
                    "credential_definition": {
                        "type": [
                            "VerifiableCredential",
                            "PhoneProof"
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
                            "name": "Proof of phone number",
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
            "credentials_types_supported": ["EmployeeCredential",  "EthereumAssociatedAddress", "VerifiableId", "EmailPass", "PhoneProof"],
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
                      
                        "ES256"
                    ],
                    "display": [
                        {
                            "name": "EmployeeCredential",
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
                        "ES256",
                    ],
                    "display": [
                        {
                            "name": "EthereumAssociatedAddress",
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
                        "ES256",
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
                    "format": "jwt_vc_json",
                    "types": [
                        "VerifiableCredential",
                        "EmailPass"
                    ],
                    "cryptographic_binding_methods_supported": [
                        "DID"
                    ],
                    "cryptographic_suites_supported": [
                        "ES256",
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
                    "format": "jwt_vc_json",
                    "types": [
                        "VerifiableCredential",
                        "PhoneProof"
                    ],
                    "cryptographic_binding_methods_supported": [
                        "DID"
                    ],
                    "cryptographic_suites_supported": [
                        "ES256",
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
                    "vc_format": "jwt_vc_json",
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
