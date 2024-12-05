user = {
    "login_name": "",
    "did": "",
    "client_id": []
}

vc_format = {
    "jwt_vc_json-ld": "jwt_vc_json-ld",
    "jwt_vc_json": "jwt_vc_json",
    "ldp_vc": "ldp_vc",
    "vc+sd-jwt": "vc+sd-jwt"
}

oidc4vci_draft = {
    "11": "draft 11",
    "13": "draft 13"
}

oidc4vp_draft = {
    "18": "draft 18",
    "20": "draft 20",
    "21": "draft 21"
}

siopv2_draft = {
    "12": "draft 12",
}

client_id_scheme_list = {
    "none": "none",
    "did": "did",
    "redirect_uri": "redirect_uri",
    "verifier_attestation": "verifier_attestation",
    "x509_san_dns": "x509_san_dns"
}


predefined_presentation_uri_list = {
    'None' : 'None',
    'presentation_definition/netcetera_1': 'Netcetera 1',
    'presentation_definition/netcetera_2': 'Netcetera 2',
    'presentation_definition/email_without_filter_jwt': 'Email without filter jwt',
    'presentation_definition/email_without_format': 'Email without format',
    'presentation_definition/age_without_filter_sdjwt': 'Age without filter sd-jwt',
    'presentation_definition/email_without_filter_ldp': 'Email without filter ldp',
    'presentation_definition/pid': 'PID through vct',
    'presentation_definition/pid_without_vct': 'PID without vct',
    'presentation_definition/pid_with_required': 'PID with limited disclosure',
    'presentation_definition/pension_credential': 'Pension credential',
    'presentation_definition/insurancenaturalperson': 'Insurance Natural Person',
    'presentation_definition/sicpa': 'Sicpa',
    'presentation_definition/two_sd_jwt': 'Present 2 sd_jwt',
    'presentation_definition/employee_badge': 'Employee Badge',
    'presentation_definition/custom_employee': 'Employee Dentsu',
    'presentation_definition/pid_with_nested_claim': 'PID with nested claim '

}

oidc4vc_profile_list = {
    'DEFAULT': 'DEFAULT ldp_vc OIDC4VCI draft 11',
    'DEFAULT-DRAFT13': 'DEFAULT ldp_vc OIDC4VCI draft 13',
    'DEFAULT-JWT': 'DEFAULT jwt_vc_json OIDC4VCI draft 11',
    'EBSI-V3': 'EBSI OIDC4VCI Draft 11',
    'DEFAULT-VC-JWT-OIDC4VCI13': 'jwt_vc_json with OIDC4VCI draft 13 / DIIP V2.1',
    'CUSTOM': 'CUSTOM profile',
    'BASELINE': 'OWF Baseline Profile / DIIP V3.0',
    'HAIP': 'HAIP-EUDI Wallet',
    'POTENTIAL': 'LSP POTENTIAL',
    'VERIFIER-ALL': 'VERIFIER ALL',
    'ISSUER-ALL': 'Mix of VC format with OIDC4VCI Draft 13',
    'BANK': "Bank for company - Legal Person - DIIP V 2.1",
    'INSURER': "Insurer for company - Legal Person - DIIP V 2.1",
    'DOCUMENTATION': "Example for documentation",
    'GOUV': "Gouvernment body for company - Legal Person - DIIP V 2.1",
    'TEST': "Test for PID, DIIP V3.0",
    "TALAO_ISSUER_JWT_VC_JSON": "Official Talao Issuer in jwt_vc_json",
    "TALAO_ISSUER_JWT_VC_JSON_LD": "Official Talao Issuer in jwt_vc_json_ld",
    "TALAO_ISSUER_SD_JWT_VC": "Official Talao Issuer in sd-jwt",
    "TALAO_ISSUER_LDP_VC": "Official Talao Issuer in ldp_vc"

}

#OIDC4VC Verifier for admin
oidc4vc_verifier_credential_list = {
    #"DID": "Authentication",
    "None": "None",
    "$.age_equal_or_over.18": "PID with age over 18",
    "$.nationalities": "PID with nationalities IT",
    'https://credentials.openid.net/gain-poc-simple-identity-credential': 'IdentityCredential sd-jwt',
    'urn:eu.europa.ec.eudi:pid:1': 'PID urn:eu.europa.ec.eudi:pid:1',
    'VerifiableId':  'Verifiable ID',
    'AscsUserCredential' : 'ASCS credential for DENIM',
    'EUDI_PID_rule_book_1_0_0': 'PID for EUDI wallet',
    'VerifiableDiploma': 'EBSI Diploma',
    'EmployeeCredential': 'Employee Credential',
    'EmailPass': 'Email proof',
    'DBCGuest': 'DBC Guest (jwt_vc_json)',
    'PhoneProof': 'Phone proof',
    'WalletCredential': 'Device information',
    "Over18": "Over18",
}

#OIDC4VC Verifier for guest
guest_oidc4vc_verifier_credential_list = {
    "None": "None",
    'VerifiableId':  'Verifiable ID',
    'EmailPass': 'Email proof',
    'PhoneProof': 'Phone proof',
    'WalletCredential': 'Device information',
    "Over18": "Over 18",
    "Over15": "Over 15",
    "Over13": "Over 13",
    "DefiCompliance": "DeFi compliance",
    "Liveness": "Proof of humanity"
}


# issuer qrcode page for admin
landing_page_style_list = {
    "./issuer_oidc/issuer_qrcode.html": "Style",
    "./issuer_oidc/issuer_qrcode_test.html": "Test",
    "./issuer_oidc/issuer_qrcode_id360.html": "Id360",
    "./issuer_oidc/wallet_link_issuer_qrcode.html": "Wallet link",
    "./issuer_oidc/issuer_qrcode_emailpass.html": "Emailpass",
    "./issuer_oidc/issuer_qrcode_web_test.html": "Test pour web wallet"
}

# issuer qrcode page for guest
guest_landing_page_style_list = {
    "./issuer_oidc/issuer_qrcode.html": "Style",
    "./issuer_oidc/issuer_qrcode_test.html": "Test",
}


# verifier qrcode page for amdin
oidc4vc_verifier_landing_page_style_list = {
    "./verifier_oidc/verifier_qrcode_2.html": "Style",
    "./verifier_oidc/verifier_qrcode_wallet_provider.html": "Wallet provider",
    "./verifier_oidc/verifier_qrcode_only.html": "QR code only",
    "./verifier_oidc/verifier_qrcode_test.html": "Test",
    "./verifier_oidc/diploma_verifier.html": "Diplome Tezos Ebsi"
}

# verifier qrcode page for guest
guest_oidc4vc_verifier_landing_page_style_list = {
    "./verifier_oidc/verifier_qrcode_2.html": "Style",
    "./verifier_oidc/verifier_qrcode_test.html": "Test",
}

"""
pre_authorized_code_list = {
    'none': "None",
    'pac': 'Pre authorized code',
    'pac_pin': 'Pre authorized code + PIN code'
}
"""

client_data_pattern_oidc4vc = {
    "profile": "DEFAULT",
    "oidc4vciDraft" : "11",
    "siopv2Draft": "12",
    "oidc4vpDraft": "18",
    "vc_format": "ldp_vc",
    "jarm": None,
    "pkce": None,
    "id_token": "on",
    "client_id_scheme": "did",  # for OIDC4VP draft 13
    "client_id_as_DID": "on",  # for siopv2 request
    "issuer_id_as_url": None,  # for OIDV4CI  issuer
    "vp_token": None,
    "group": None,
    "group_B": None,
    "request_parameter_supported": None, 
    "request_uri_parameter_supported": 'on',
    "credential_offer_uri": None,
    "client_metadata_uri": None,
    "presentation_definition_uri": None,
    "predefined_presentation_definition": 'None',
    "filter_type_array": None,
    "deferred_flow": None,
    "vc": "DID",
    "vc_1": "DID",
    "vc_2": "DID",
    "vc_3": "DID",
    "vc_4": "DID",
    "vc_5": "DID",
    "vc_6": "DID",
    "vc_7": "DID",
    "vc_8": "DID",
    "vc_9": "DID",
    "vc_10": "DID",
    "vc_11": "DID",
    "vc_12": "DID",
    "user": "guest",
    "client_id":  "",
    "client_secret": "",
    "callback": "https://altme.io",
    "jwk": "",
    "did": "did:web:app.altme.io:issuer",
    "verification_method": "did:web:app.altme.io:issuer#key-1",
    "issuer_landing_page": "./issuer_oidc/issuer_qrcode_test.html",     
    "application_name": "Application name",
    "reason": "This purpose 1",
    "reason_1": "This is purpose 1 ",
    "reason_2": "This is purpose 2 ",
    "reason_3": "This is purpose 3 ",
    "reason_4": "This is purpose 4",
    "reason_5": "This is purpose 5",
    "reason_6": "This is purpose 6",
    "reason_7": "This is purpose 7",
    "reason_8": "This is purpose 8",
    "credential_requested": "DID",
    "credential_requested_2": "DID",
    "credential_requested_3": "DID",
    "credential_requested_4": "DID",
    "landing_page_style": "./issuer_oidc/issuer_qrcode_test.html",
    "verifier_landing_page_style": "./verifier_oidc/verifier_qrcode_test.html",
    "page_title": "Page title",
    "page_subtitle": "Page subtitle",
    "credential_duration": "365",
    "landing_page_url": "https://talao.io",
}