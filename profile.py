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
            'credentials_supported' : ['VerifiableDiploma', 'VerifiableId'],
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
            'credentials_supported' : ['VerifiableDiploma', 'VerifiableId', 'GreencypherPass', 'ListOfProjects'],
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
            'credentials_supported' : ['EmployeeCredential',  'EthereumAssociatedAddress', 'VerifiableId', 'EmailPass', 'PhoneProof', 'GreencypherPass'],
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
            'credentials_supported' :  ['EmployeeCredential',  'VerifiableId',  'GreencypherPass', 'EmailPass'],
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
            'credentials_supported' :  ['EmployeeCredential', 'VerifiableId', 'GreencypherPass', 'ListOfProjects', 'PhoneProof', 'EmailPass', 'Over18'],
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
            'credential_supported' : ['EmployeeCredential', 'VerifiableId', 'EmailPass'],
            'schema_for_type' : False,
            'authorization_server_support' : False,
            'credential_manifest_support' : False,
            'service_documentation' : 'https://identity.foundation/jwt-vc-presentation-profile/'

        },
    'DBC' :
        {
            'verifier_vp_type' : 'jwt_vp',
            'siopv2_prefix' : 'openid-vc://',
            'credential_supported' : ['EmployeeCredential', 'VerifiableId', 'EmailPass'],
            'schema_for_type' : False,
            'authorization_server_support' : False,
            'credential_manifest_support' : False,
            'service_documentation' : 'https://identity.foundation/jwt-vc-presentation-profile/'

        },

}
