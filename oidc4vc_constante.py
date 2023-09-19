


user = {
        "login_name": "",
        "did": "",
        "client_id": []
}



oidc4vc_profile_list = {
    'DEFAULT': 'DEFAULT',
    'GAIA-X': 'GAIA-X projects',
    'EBSI-V3': 'EBSI V3 compliance',
    'JWT-VC': 'JWT-VC presentation profile',
    'HEDERA': 'Greencypher project'
}



#OIDC4VC Verifier
ebsi_verifier_credential_list = {
    #"DID": "Authentication",
    "None": "None",
    'VerifiableId':  'Verifiable ID',
    'VerifiableDiploma': 'EBSI Diploma',
    'EmployeeCredential': 'Employee Credential',
    'ProofOfAsset': 'Carbon credit projects',
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



# issuer
landing_page_style_list = {
    "./issuer_oidc/issuer_qrcode.html": "Style",
    "./issuer_oidc/issuer_qrcode_test.html": "Test",
    "./issuer_oidc/wallet_link_issuer_qrcode.html": "Wallet link"
}


# verifier
ebsi_verifier_landing_page_style_list = {
                    "./verifier_oidc/verifier_qrcode_2.html": "Style 2",
                    "./verifier_oidc/verifier_qrcode_test.html": "Test",
                    "./verifier_oidc/diploma_verifier.html": "Diplome Tezos Ebsi"

}


pre_authorized_code_list = {'none': "None",
                'pac': 'Pre authorized code',
                'pac_pin': 'Pre authorized code + PIN code'
}


client_data_pattern_ebsi = {
    "profile": "DEFAULT",
    "pkce": None,
    "id_token": "on",
    "client_id_as_DID": "on",  # for siopv2 request
    "vp_token": None,
    "group": None,
    "group_B": None,
    "request_parameter_supported": None, 
    "request_uri_parameter_supported": 'on',
    "credential_offer_uri": None,
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
    "verifier_landing_page_style": "./issuer_oidc/verifier_qrcode_test.html",
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

