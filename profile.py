profile = {

    'EBSI-V2' :
        {
            'issuer_vc_type' : 'jwt_vc', ## jwt_vc_json, jwt_vc_json-ld, ldp_vc
            'verifier_vp_type' : 'jwt_vp',
            'authorization_server_support' : False,
            'oidc4vci_prefix' : 'openid://initiate_issuance',
            'siopv2_prefix' : 'openid://',
            'oidc4vp_prefix' : 'openid://',
            'grant_types_supported': [
                'authorization_code',
                'urn:ietf:params:oauth:grant-type:pre-authorized_code'
            ],
            'credentials_types_supported' : ['VerifiableDiploma', 'VerifiableId'],
            'credentials_supported' : [
                {
                    "id" : "VerifiableDiploma",
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
                    ]
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
                        ]
                }
            ],
            'schema_for_type' : True,
            'credential_manifest_support' : False,
            'service_documentation' : 'THIS PROFILE OF OIDC4VCI IS DEPRECATED. EBSI V2 COMPLIANCE. It is the profile of the EBSI V2 compliant test. DID for natural person is did:ebsi. \
                The schema url is used as the VC type in the credential offer QR code. \
                The prefix openid_initiate_issuance:// \
                oidc4vci_draft : https://openid.net/specs/openid-connect-4-verifiable-credential-issuance-1_0-05.html#abstract',
        }, 
    'EBSI-V3' : # TODO completed
        {
            'issuer_vc_type' : 'jwt_vc',
            'verifier_vp_type' : 'jwt_vp',
            'authorization_server_support' : True,
            'credentials_as_json_object_array' : True,
            'pre-authorized_code_as_jwt' : True,
            'oidc4vci_prefix' : 'openid-credential-offer://',
            'siopv2_prefix' : 'openid-vc://',
            'oidc4vp_prefix' : 'openid-vc://',
            'credentials_types_supported' : ['VerifiableDiploma', 'VerifiableId'],
            'credentials_supported' : [
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
                #'authorization_code',
                'urn:ietf:params:oauth:grant-type:pre-authorized_code'
            ],
            'trust_framework': {
                'name': 'ebsi',
                'type': 'Accreditation',
                'uri': 'TIR link towards accreditation'
            },
            'schema_for_type' : False,
            'credential_manifest_support' : False,
            'service_documentation' : 'New environment for V3 compliance test, use specific did:key'
        },
     'DEFAULT' :
        {
            'issuer_vc_type' : 'ldp_vc',
            'verifier_vp_type' : 'ldp_vp',
            'oidc4vci_prefix' : 'openid-credential-offer://' ,
            'authorization_server_support' : False,
            'siopv2_prefix' : 'openid-vc://',
            'oidc4vp_prefix' : 'openid-vc://',
            'credentials_types_supported' : ['EmployeeCredential',  'EthereumAssociatedAddress', 'VerifiableId', 'EmailPass', 'PhoneProof'],
             'trust_framework': {
                'name': 'default',
                'type': 'Accredition'
            },
            'credentials_supported' : [
                {
                    "id" : "EmployeeCredential",
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
                    "id" : "EthereumAssociatedAddress",
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
                    "id" : "VerifiableId",
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
                    "id" : "EmailPass",
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
                    "id" : "PhoneProof",
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
                #'authorization_code',
                'urn:ietf:params:oauth:grant-type:pre-authorized_code'
            ],
            'schema_for_type' : False,
            'credential_manifest_support' : True,
            'service_documentation' : 'We use JSON-LD VC and VP and last release of the specs. \
                oidc4vci_draft : https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html \
                siopv2_draft : https://openid.net/specs/openid-connect-self-issued-v2-1_0.html \
                oidc4vp_draft : https://openid.net/specs/openid-4-verifiable-presentations-1_0.html  ',
        },
         'GAIA-X' :
        {
            'issuer_vc_type' : 'ldp_vc',
            'verifier_vp_type' : 'ldp_vp',
            'oidc4vci_prefix' : 'openid-initiate-issuance://' ,
            'siopv2_prefix' : 'openid://',
            'oidc4vp_prefix' : 'openid://',
            'authorization_server_support' : False,
            'credentials_types_supported' :  ['EmployeeCredential',  'VerifiableId',  'EmailPass'],
            'credentials_supported' : [
                {
                    "id" : "EmployeeCredential",
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
                    "id" : "VerifiableId",
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
                    "id" : "EmailPass",
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
                #'authorization_code',
                'urn:ietf:params:oauth:grant-type:pre-authorized_code'
            ],
            'schema_for_type' : False,
            'credential_manifest_support' : True,
            'service_documentation' : 'THIS PROFILE OF OIDC4VCI IS DEPRECATED. \
                oidc4vci_draft : https://openid.net/specs/openid-connect-4-verifiable-credential-issuance-1_0-05.html#name-credential-endpoint \
                siopv2_draft : https://openid.net/specs/openid-connect-self-issued-v2-1_0.html \
                oidc4vp_draft : https://openid.net/specs/openid-4-verifiable-presentations-1_0.html  ',
        },
        'HEDERA' :
        {
            'issuer_vc_type' : 'jwt_vc',
            'verifier_vp_type' : 'jwt_vp',
            'oidc4vci_prefix' : 'openid-credential-offer-hedera://' ,
            'authorization_server_support' : False,
            'siopv2_prefix' : 'openid-hedera://',
            'oidc4vp_prefix' : 'openid-hedera://',
            'credentials_types_supported' :  ['CetProject', 'EmailPass', 'GreencypherPass', 'VerifiableId'],
            'trust_framework': {
                'name': 'greencypher',
                'type': 'Accredition'
            },
            'credentials_supported' : [
                {
                    "id" : "CetProject",
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
                        "ES384",
                        "RS256"
                    ],
                    "display": [
                        {
                            "name": "CET projects",
                            "locale": "en-GB"
                        }
                    ]
                },
                {
                    "id" : "VerifiableId",
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
                            "name": "VerifiableId",
                            "locale": "en-GB"
                        }
                    ]
                },
                {
                    "id" : "EmailPass",
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
                    "id" : "GreencypherPass",
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
                        "ES384",
                        "RS256"
                    ],
                    "display": [
                        {
                            "name": "GreenCypher Pass",
                            "locale": "en-GB"
                        }
                    ]
                }
            ],
            'grant_types_supported': [
                #'authorization_code',
                'urn:ietf:params:oauth:grant-type:pre-authorized_code'
            ],
            'schema_for_type' : False,
            'credential_manifest_support' : True,
            'service_documentation' : 'WORK IN PROGRESS EON project. last release of the specs. \
                oidc4vci_draft : https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html \
                siopv2_draft : https://openid.net/specs/openid-connect-self-issued-v2-1_0.html \
                oidc4vp_draft : https://openid.net/specs/openid-4-verifiable-presentations-1_0.html  \
                 Issuer and verifier for marjetplace and WCM'
        },
    
    'JWT-VC' :
        {
            'verifier_vp_type' : 'jwt_vp',
            'siopv2_prefix' : 'openid-vc://',
            'credentials_types_supported' : ['EmployeeCredential', 'VerifiableId', 'EmailPass'],
            'schema_for_type' : False,
            'authorization_server_support' : False,
            'credential_manifest_support' : False,
            'service_documentation' : 'https://identity.foundation/jwt-vc-presentation-profile/'

        },
    'DBC' :
        {
            'verifier_vp_type' : 'jwt_vp',
            'siopv2_prefix' : 'openid-vc://',
            'oidc4vp_prefix' : 'openid://',
            'credentials_types_supported' : ['EmployeeCredential', 'VerifiableId', 'EmailPass'],
            'schema_for_type' : False,
            'authorization_server_support' : False,
            'credential_manifest_support' : False,
            'service_documentation' : 'https://identity.foundation/jwt-vc-presentation-profile/'

        },

}
