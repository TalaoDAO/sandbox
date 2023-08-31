


user = {
        "login_name" : "",
        "did" : "",
        "client_id" : []
}



oidc4vc_profile_list = {
    'EBSI-V2' : 'EBSI V2 compliance',
    'DEFAULT' : 'DEFAULT',
    'GAIA-X' : 'GAIA-X projects',
    'EBSI-V3' : 'EBSI V3 compliance',
    'JWT-VC' : 'JWT-VC presentation profile',
    'HEDERA' : 'HEDERA projects',
    'DBC' : 'Deutch Blockchain Coalition'
}



#OIDC4VC Verifier
ebsi_verifier_credential_list = {
    #"DID" : "Authentication",
    "None" : "None",
    'VerifiableId' :  'Verifiable ID',
    'VerifiableDiploma' : 'EBSI Diploma',
    'EmployeeCredential' : 'Employee Credential',
    'ProofOfAsset' : 'Carbon credit projects',
    'EmailPass' : 'Email proof',
    'PhoneProof' : 'Phone proof',
    'WalletCredential' : 'Device information',
    "GreencypherPass" : "Pass GreenCypher",
    "ListOfProjects" : "ACX list of Projects",
    "Over18" : "Over18"
}


type_2_schema = {
    'VerifiableId' : 'https://api-conformance.ebsi.eu/trusted-schemas-registry/v2/schemas/z22ZAMdQtNLwi51T2vdZXGGZaYyjrsuP1yzWyXZirCAHv',
    'VerifiableDiploma'  : 'https://api.preprod.ebsi.eu/trusted-schemas-registry/v1/schemas/0xbf78fc08a7a9f28f5479f58dea269d3657f54f13ca37d380cd4e92237fb691dd' 
} 



# OIDC4VC issuer
ebsi_credential_requested_list = {
                    'https://api-conformance.ebsi.eu/trusted-schemas-registry/v2/schemas/z22ZAMdQtNLwi51T2vdZXGGZaYyjrsuP1yzWyXZirCAHv' : 'VerifiableId',
                    'https://api.preprod.ebsi.eu/trusted-schemas-registry/v1/schemas/0xbf78fc08a7a9f28f5479f58dea269d3657f54f13ca37d380cd4e92237fb691dd' : 'VerifiableDiploma',
                    'DID' : "None"
                }


# issuer
landing_page_style_list = {
                    "./issuer_oidc/issuer_qrcode.html" : "Style",
                    "./issuer_oidc/issuer_qrcode_test.html" : "Test"
                }


# verifier
ebsi_verifier_landing_page_style_list = {
                    "./verifier_oidc/verifier_qrcode_2.html" : "Style 2",
                    "./verifier_oidc/verifier_qrcode_test.html" : "Test",
                    "./verifier_oidc/diploma_verifier.html" : "Diplome Tezos Ebsi"

}


pre_authorized_code_list = {'none' : "None",
                 'pac' : 'Pre authorized code',
                  'pac_pin' : 'Pre authorized code + PIN code'
                 }



client_data_pattern_ebsi = {
                "profile" : "DEFAULT",
                "pkce" : None,
                "id_token" : 'on',
                "vp_token" : None,
                "group" : None,
                "group_B" : None,
                "request_parameter_supported" : None, 
                "request_uri_parameter_supported" : None,
                "credential_offer_uri" : None,
                "presentation_definition_uri" : None,
                "deferred_flow" : None,
                "vc" : "DID",
                "vc_1" : "DID",
                "vc_2" : "DID",
                "vc_3" : "DID",
                "vc_4" : "DID",
                "vc_5" : "DID",
                "vc_6" : "DID",
                "vc_7" : "DID",
                "vc_8" : "DID",
                "vc_9" : "DID",
                "vc_10" : "DID",
                "vc_11" : "DID",
                "vc_12" : "DID",
                "user" : "guest",
                "client_id" :  "",
                "client_secret" : "",
                "callback" : "https://altme.io",
                "jwk" : "",
                "did": "did:web:app.altme.io:issuer",
                "verification_method" : "did:web:app.altme.io:issuer#key-1",
                "issuer_landing_page" : "./issuer_oidc/issuer_qrcode_test.html",     
                "note" : "",
                "company_name" : "New company",
                "application_name" : "Application name",
                "reason" : "This purpose 1",
                "reason_1" : "This is purpose 1 ",
                "reason_2" : "This is purpose 2 ",
                "reason_3" : "This is purpose 3 ",
                "reason_4" : "This is purpose 4",
                "reason_5" : "This is purpose 5",
                "reason_6" : "This is purpose 6",
                "reason_7" : "This is purpose 7",
                "reason_8" : "This is purpose 8",
                "credential_requested" : "DID",
                "credential_requested_2" : "DID",
                "credential_requested_3" : "DID",
                "credential_requested_4" : "DID",
                "landing_page_style" : "./issuer_oidc/issuer_qrcode_test.html",
                "verifier_landing_page_style" : "./issuer_oidc/verifier_qrcode_test.html",
                "page_title" : "Page title",
                "page_subtitle" : "Page subtitle",
                "page_description" : "Add here a credential description as you would like to see it displayed on the landing page of your app.",
                "credential_duration" : "365",
                "qrcode_message" : "Scan with your wallet",
                "mobile_message" : "Open your wallet",
                "contact_email" : "support@altme.io",
                "contact_name" : "",
                "landing_page_url" : "https://talao.io",
                "title" : "Get it !" # QR code title
                }

