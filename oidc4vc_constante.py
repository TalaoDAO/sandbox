
user = {
    "login_name": "",
    "did": "",
    "client_id": []
}

vc_format = {
    "jwt_vc_json-ld": "jwt_vc_json-ld",
    "ldp_vc": "ldp_vc",
    "vc+sd-jwt": "vc+sd-jwt implementation in progress"
}

oidc4vci_draft = {
    "8": "draft 8",
    "11": "draft 11",
    "12": "draft 12 implementation in progress",
    "13": "draft 13 implementation in progress"
}

oidc4vp_draft = {
    "10": "draft 10",
    "13": "draft 13",
     "18": "draft 18"
}

siopv2_draft = {
    "12": "draft 12",
}


oidc4vc_profile_list = {
    'DEFAULT': 'DEFAULT ldp_vc OIDC4VCI draft 11',
    'DEFAULT-JWT': 'DEFAULT jwt_vc_json OIDC4VCI draft 11',
    'EBSI-V3': 'EBSI OIDC4VCI Draft 11',
    #'HEDERA': 'Greencypher project',
    'GAIN-POC': 'GAIN POC openid, SD-JWT implementation in progress',
    'DIIP': 'Decentrtalized Identity Interop Profile (DIIP)',
    'DEFAULT-VC-JWT-OIDC4VCI12': 'jwt_vc_json with OIDC4VCI draft 12',
    'DEFAULT-VC-JWT-OIDC4VCI13': 'jwt_vc_json with OIDC4VCI draft 13',
    'CUSTOM': 'CUSTOM profile',
    'BASELINE': 'Baseline Profile'
}


#OIDC4VC Verifier for admin
oidc4vc_verifier_credential_list = {
    #"DID": "Authentication",
    "None": "None",
    'https://credentials.openid.net/gain-poc-simple-identity-credential': 'vct = https://credentials.openid.net/gain-poc-simple-identity-credential',
    'VerifiableId':  'Verifiable ID',
    'VerifiableDiploma': 'EBSI Diploma',
    'EmployeeCredential': 'Employee Credential',
    'EmailPass': 'Email proof',
    'PhoneProof': 'Phone proof',
    'WalletCredential': 'Device information',
    "GreencypherPass": "Pass GreenCypher",
    "CetProject": "ACX CET project",
    "GntProject": "ACX GNT project",
    "Gnt+Project": "ACX GNT+ project",
    "SdgtProject": "ACX SDGT project",
    "RetProject": "ACX RET project",
    "HotProject": "ACX HOT project",
    "XctProject": "ACX XCT project",
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
    "./issuer_oidc/issuer_qrcode_emailpass.html": "Emailpass"
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
    "credential_manifest_support": 'on',
    "pkce": None,
    "id_token": "on",
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
    "note": "",
    "company_name": "New company",
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
    "page_description": "Add here a credential description as you would like to see it displayed on the landing page of your app.",
    "credential_duration": "365",
    "qrcode_message": "Scan with your wallet",
    "mobile_message": "Open your wallet",
    "contact_email": "support@altme.io",
    "contact_name": "",
    "landing_page_url": "https://talao.io",
    "title": "Get it !" # QR code title
}