profile = {
    'EBSI-V3':
        {
            'oidc4vciDraft' : "10",
            'siopv2Draft': "12",
            'oidc4vpDraft': "13",
            'vc_format': "jwt_vc_json-ld",
            'verifier_vp_type': 'jwt_vp',
            'authorization_server_support': True,
            'credentials_as_json_object_array': True,
            'pre-authorized_code_as_jwt': True,
            'oidc4vci_prefix': 'openid-credential-offer://',
            'siopv2_prefix': 'openid-vc://',
            'oidc4vp_prefix': 'openid-vc://',
            'credentials_types_supported': ['VerifiableDiploma',  'VerifiableId', 'EmailPass'],
            'credentials_supported': [
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
            'grant_types_supported': [
                'authorization_code',
                'urn:ietf:params:oauth:grant-type:pre-authorized_code'
            ],
            'trust_framework': {
                'name': 'ebsi',
                'type': 'Accreditation',
                'uri': 'TIR link towards accreditation'
            },
            'schema_for_type': False,
            'credential_manifest_support': False,
            'service_documentation': 'New environment for V3 compliance test, use specific did:key'
        },
    'DEFAULT':
        {
            'oidc4vciDraft' : "11",
            'siopv2Draft': "12",
            'oidc4vpDraft': "18",
            'vc_format': "ldp_vc",
            'verifier_vp_type': 'ldp_vp',
            'oidc4vci_prefix': 'openid-credential-offer://' ,
            'authorization_server_support': False,
            'credentials_as_json_object_array': False,
            'siopv2_prefix': 'openid-vc://',
            'oidc4vp_prefix': 'openid-vc://',
            'credentials_types_supported': ['EmployeeCredential',  'EthereumAssociatedAddress', 'VerifiableId', 'EmailPass', 'PhoneProof'],
            'trust_framework': {
                'name': 'default',
                'type': 'Accredition'
            },
            'credentials_supported': [
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
            'grant_types_supported': [
                'authorization_code',
                'urn:ietf:params:oauth:grant-type:pre-authorized_code'
            ],
            'schema_for_type': False,
            'credential_manifest_support': True,
            'service_documentation': 'We use JSON-LD VC and VP and last release of the specs.',
        },
    'DEFAULT-JWT':
        {
            'oidc4vciDraft' : "11",
            'siopv2Draft': "12",
            'oidc4vpDraft': "18",
            'vc_format': "jwt_vc_json-ld",
            'verifier_vp_type': 'jwt_vp',
            'oidc4vci_prefix': 'openid-credential-offer://' ,
            'authorization_server_support': False,
            'credentials_as_json_object_array': False,
            'siopv2_prefix': 'openid-vc://',
            'oidc4vp_prefix': 'openid-vc://',
            'credentials_types_supported': ['EmployeeCredential',  'EthereumAssociatedAddress', 'VerifiableId', 'EmailPass', 'PhoneProof'],
            'trust_framework': {
                'name': 'default',
                'type': 'Accredition'
            },
            'credentials_supported': [
                {
                    "id": "EmployeeCredential",
                    "format": "jwt_vc",
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
                    "format": "jwt_vc",
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
                    "format": "jwt_vc",
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
                            "name": "EmailPass",
                            "locale": "en-GB"
                        }
                    ]
                },
                {
                    "id": "PhoneProof",
                    "format": "jwt_vc",
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
            'grant_types_supported': [
                'authorization_code',
                'urn:ietf:params:oauth:grant-type:pre-authorized_code'
            ],
            'schema_for_type': False,
            'credential_manifest_support': True,
            'service_documentation': 'We use JSON-LD VC and VP and last release of the specs.',
        },
    'DEFAULT-VC-JWT-OIDC4VCI12':
        {
            'oidc4vciDraft' : "12",
            'siopv2Draft': "12",
            'oidc4vpDraft': "18",
            'vc_format': "jwt_vc_json-ld",
            'verifier_vp_type': 'jwt_vp',
            'oidc4vci_prefix': 'openid-credential-offer://' ,
            'authorization_server_support': False,
            'credentials_as_json_object_array': False,
            'siopv2_prefix': 'openid-vc://',
            'oidc4vp_prefix': 'openid-vc://',
            'credentials_types_supported': ['EmployeeCredential',  'EthereumAssociatedAddress', 'VerifiableId', 'EmailPass', 'PhoneProof'],
            'trust_framework': {
                'name': 'default',
                'type': 'Accredition'
            },
            'credentials_supported': [
                {
                    "id": "EmployeeCredential",
                    "format": "jwt_vc",
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
                    "format": "jwt_vc",
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
                    "format": "jwt_vc",
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
                            "name": "EmailPass",
                            "locale": "en-GB"
                        }
                    ]
                },
                {
                    "id": "PhoneProof",
                    "format": "jwt_vc",
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
            'grant_types_supported': [
                'authorization_code',
                'urn:ietf:params:oauth:grant-type:pre-authorized_code'
            ],
            'schema_for_type': False,
            'credential_manifest_support': True,
            'service_documentation': 'We use JSON-LD VC and VP and last release of the specs.',
        },
     'DIIP':
        {
            'oidc4vciDraft' : "11",
            'siopv2Draft': "12",
            'oidc4vpDraft': "18",
            'vc_format': "jwt_vc_json-ld",
            'verifier_vp_type': 'jwt_vp',
            'oidc4vci_prefix': 'openid-credential-offer://' ,
            'authorization_server_support': False,
            'credentials_as_json_object_array': False,
            'siopv2_prefix': 'openid-vc://',
            'oidc4vp_prefix': 'openid-vc://',
            'credentials_types_supported': ['EmployeeCredential',  'EthereumAssociatedAddress', 'VerifiableId', 'EmailPass', 'PhoneProof'],
            'credentials_supported': [
                {
                    "id": "EmployeeCredential",
                    "format": "jwt_vc",
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
                    "format": "jwt_vc",
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
                    "format": "jwt_vc",
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
                    "format": "jwt_vc",
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
                    "format": "jwt_vc",
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
            'grant_types_supported': [
                'authorization_code',
                'urn:ietf:params:oauth:grant-type:pre-authorized_code'
            ],
            'schema_for_type': False,
            'credential_manifest_support': False,
            'service_documentation': 'We use JSON-LD VC and VP and last release of the specs.',
        },
    'GAIA-X':
        {
            'oidc4vciDraft' : "8",
            'siopv2Draft': "12",
            'oidc4vpDraft': "10",
            'vc_format': "jwt_vc_json-ld",
            'verifier_vp_type': 'ldp_vp',
            'oidc4vci_prefix': 'openid-initiate-issuance://' ,
            'siopv2_prefix': 'openid://',
            'oidc4vp_prefix': 'openid://',
            'authorization_server_support': False,
            'credentials_as_json_object_array': False,
            'credentials_types_supported':  ['EmployeeCredential',  'VerifiableId',  'EmailPass'],
            'credentials_supported': [
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
            'grant_types_supported': [
                'authorization_code',
                'urn:ietf:params:oauth:grant-type:pre-authorized_code'
            ],
            'schema_for_type': False,
            'credential_manifest_support': True,
            'service_documentation': 'THIS PROFILE OF OIDC4VCI IS DEPRECATED. ',
        },
        'HEDERA':
        {   
            'oidc4vciDraft' : "11",
            'siopv2Draft': "12",
            'oidc4vpDraft': "18",
            'verifier_vp_type': 'jwt_vp',
            'vc_format': "jwt_vc_json-ld",
            'oidc4vci_prefix': 'openid-credential-offer-hedera://',
            'authorization_server_support': False,
            'credentials_as_json_object_array': False,
            'siopv2_prefix': 'openid-hedera://',
            'oidc4vp_prefix': 'openid-hedera://',
            'credentials_types_supported':  [
                'CetProject',
                'GntProject',
                'Gnt+Project',
                'SdgtProject',
                'RetProject',
                'HotProject',
                'XctProject',
                'GreencypherPass',
                'VerifiableId'
            ],
            'trust_framework': {
                'name': 'greencypher'
            },
            'credentials_supported': [
                {
                    "id": "CetProject",
                    "format": "jwt_vc",
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
                    "format": "jwt_vc",
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
                    "format": "jwt_vc",
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
                    "format": "jwt_vc",
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
                    "format": "jwt_vc",
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
                    "format": "jwt_vc",
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
                    "format": "jwt_vc",
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
                    "format": "jwt_vc",
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
                    "format": "jwt_vc",
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
            'grant_types_supported': [
                'urn:ietf:params:oauth:grant-type:pre-authorized_code'
            ],
            'schema_for_type': False,
            'credential_manifest_support': True,
            'service_documentation': 'WORK IN PROGRESS EON project. last release of the specs.'
        }

}
