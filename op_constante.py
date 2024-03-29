
user = {
        "login_name" : "",
        "did" : "",
        "client_id" : []
}


sbt_network_list = {
    'none' : 'None',
    #'tezos' : 'Tezos Mainnet',
    'ghostnet' : 'Tezos Ghostnet',
    #'ethereum' : 'Ethereum Mainet',
    #'rinkeby' : 'Ethereum Rinkeby'
}




tezid_network_list = {
    'none' : 'None',
    'tezos' : 'Tezos Mainnet',
    'ghostnet' : 'Tezos Ghostnet',
}

# for issuer with webhook
method_list = {
                    "relay" : "Relay (external issuer)",
                    "ethr" : "did:ethr",
                    "key" : "did:key",
                    "tz": "did:tz",
                    "pkh:tz" : "did:pkh:tz",
                }

# for verifier admin
credential_list = {
                    'Pass' : 'Pass',
                    'EmailPass' : 'EmailPass',
                    'PhoneProof' : 'PhoneProof',
                    'AgeRange' : 'AgeRange',
                    'Nationality' : 'Nationality',
                    'Gender' : 'Gender',
                    'VerifiableId' : 'VerifiableId',
                    'Over18' : 'Over18',
                    'Over13' : 'Over13',
                    'Over15' : 'Over15',
                    'PassportNumber' : 'PassportNumber',
                    'Liveness' : 'Liveness',
                    'DefiCompliance' : 'DefiCompliance',
                    'TezosAssociatedAddress' : 'Proof of Tezos blockchain account',
                    'EthereumAssociatedAddress' : 'Proof of Ethereum blockchain account',
                    'PolygonAssociatedAddress' : 'Proof of Polygon blockchain account',
                    "BinanceAssociatedAddress" : 'Proof of Binance blockchain account',
                    "FantomAssociatedAddress" : 'Proof of Fantom blockchain account',
                    "WalletCredential" : "Wallet credential",
                    'Tez_Voucher_1' : "Voucher Tezotopia",
                    'VerifiableDiploma' : 'EBSI VerifiableDiploma',
                    'LearningAchievement' : 'Diploma',
                    'StudentCard' : 'StudentCard',
                    'AragoPass' : 'AragoPass',
                    'DID' : "None",
                    'ANY' : 'Any'
                }

# for verifier  guest
credential_list_for_guest = {
                    'TezosAssociatedAddress' : 'Tezos Account ownership',
                    'EthereumAssociatedAddress' : 'Ethereum Account ownership',
                    'PolygonAssociatedAddress' : 'Polygon Account ownership',
                    "BinanceAssociatedAddress" : 'Binance Account ownership',
                    "FantomAssociatedAddress" : 'Fantom Account ownership',
                    'WalletCredential' : 'Wallet credential',
                    'EmailPass' : 'Proof of email',
                    'DeFiCompliance' : 'Defi compliance',
                    'PhoneProof' : 'Proof of phone No.',
                    'TwitterAccountProof' : 'Twitter Account',
                    'AgeRange' : 'Proof of Age Range',
                    'VerifiableId' : 'Verifiable ID',
                    'Over18' : 'Proof of Over 18',
                    'Over13' : 'Proof of Over 13',
                    'Over15' : 'Proof  of Over 15',
                    'AragoPass' : 'Arago Pass',
                    'DID' : "None",
                    'ANY' : 'Any'
                }


# for beacon verifier for guest
beacon_verifier_credential_list = {
                    'Pass' : 'Pass',
                    'GamerPass' : 'Gamer Pass',
                    'TezosAssociatedAddress' : 'Proof of Tezos blockchain account',
                    'EthereumAssociatedAddress' : 'Proof of Ethereum blockchain account',
                    'EmailPass' : 'Proof of email',
                    #'PassportNumber' : 'Passport footprint',
                    #'PhoneProof' : 'Proof of phone',
                    #'AgeRange' : 'Age range',
                    #'Nationality' : 'Nationality',
                    #'Gender' : 'Gender',
                    'TalaoCommunity' : 'Talao loyalty card',
                    'LearningAchievement' : 'Diploma',
                    'BloometaPass' : 'Bloometa gaming card',
                    'IdCard' : 'Identity card',
                    'Over18' : 'Over 18',
                    'Over13' : 'Over 13',
                    'AragoPass' : 'Arago Pass',
                    'DID' : 'None',
                    'ANY' : 'Any'
                }


# issuer webhook
credential_to_issue_list = {
                    'Pass' : 'Pass',
                   'AragoPass' : 'Pass Arago',
                   'InfrachainPass' : 'Pass Infrachain',
                    'BloometaPass' : 'Bloometa card',
                    'TezVoucher_1' : 'Tezotopia 10% voucher (fake)',
                    'LearningAchievement' : 'Diploma (Learning achievement)',
                    'VerifiableDiploma' : 'Diploma EBSI (Verifiable Diploma)',
                    'PCDSAgentCertificate' : 'PCDS Auditor',
                    'StudentCard' : 'Student card',
                    'CertificateOfEmployment' : 'Certificate of employment',
                    'TalaoCommunity' : 'Talao Community card',
                    "VotersCard" : "Voter Card",
                    'PhoneProof' : 'PhoneProof',
                }


# issuer webhook for guest
credential_to_issue_list_for_guest = {
                    'Pass' : 'Pass',
                }


# for issuer
credential_requested_list = {
                    'EmailPass' : 'Proof of email',
                    'AgeRange' : 'Age range',
                    'Nationality' : 'Nationality',
                    'Gender' : 'Gender card',
                    'PhoneProof' : 'Proof of phone number',
                    'IdCard' : 'Identity card',
                    'VerifiableId' : 'EBSI Verifiable ID',
                    'VerifiableDiploma' : 'EBSI Verifiable Diploma',
                    'Over18' : 'Proof of majority (Over 18)',
                    'Over13' : 'Over 13',
                    'PassportNumber' : 'Passport footprint',                  
                    "TezosAssociatedAddress" : "Proof of Tezos blockchain account",
                    "EthereumAssociatedAddress" : "Proof of Ethereum blockchain account",
                    "AllAddress" : "Proof of blockchain crypto account",
                    "AragoPass" : "Arago Pass",
                    "DeviceInfo" : "Device Info",
                    "login" : "Login and password",
                    "secret" : "Secret",
                    "totp" : "Time-based OTP",
                    'DID' : "None"
                }

# for issuer for 2, 3 and 4th credential
credential_requested_list_2 = {
                    'EmailPass' : 'Proof of email',
                    'AgeRange' : 'Age range',
                    'Nationality' : 'Nationality',
                    'Gender' : 'Gender card',
                    'PhoneProof' : 'Proof of phone number',
                    'IdCard' : 'Identity card',
                    'VerifiableId' : 'EBSI Verifiable ID',
                    'VerifiableDiploma' : 'EBSI Verifiable Diploma',
                    'DeviceInfo' : 'Device Info',
                    'Over18' : 'Proof of majority (Over 18)',
                    'Over13' : 'Over 13',
                    'PassportNumber' : 'Passport footprint',                  
                    "TezosAssociatedAddress" : "Proof of Tezos blockchain account",
                    "EthereumAssociatedAddress" : "Proof of Ethereum blockchain account",
                    "AllAddress" : "Proof of blockchain account",
                    "AragoPass" : "Arago Pass",
                    'DID' : "None",
                }


# issuer
landing_page_style_list = {
                    "op_issuer_qrcode_1.html" : "Style 1",
                    "op_issuer_qrcode_2.html" : "Style 2",
                    "op_issuer_qrcode_emailpass.html" : "EmailPass card",
                    "op_issuer_qrcode_phoneproof.html" : "PhoneProof card",
                    "op_issuer_qrcode_bloometa.html" : "Bloometa pass"
                }

# verifier
verifier_landing_page_style_list = {
                    "op_verifier_qrcode.html" : "Style 1",
                    "op_verifier_qrcode_2.html" : "Style 2",
                    "op_ebsi_verifier_qrcode_2.html" : "Style 2 with large QRcode",
                    "op_verifier_qrcode_3.html" : "Style 3",
                    "op_verifier_qrcode_4.html" : "Altme landing page",
                    "op_verifier_qrcode_5.html" : "Style 2 with counter",
                    "op_verifier_qrcode_6.html" : "Style 2 with html",
                    "op_verifier_qrcode_7.html" : "Altme style with html",
                    "arago_verifier_qrcode.html" : "Arago landing page",
                    "verifier_qrcode_test.html" : "Test",
                    "altme_connect.html" : "Altme Connect"
                }

# verifier
ebsi_verifier_landing_page_style_list = {
                    "ebsi/ebsi_verifier_qrcode_1.html" : "EBSI - Style 1 ",
                    "ebsi/ebsi_verifier_qrcode_2.html" : "EBSI - Style 2",
                    "ebsi/ebsi_verifier_qrcode_2.html" : "EBSI - Large QRcode",
                    "ebsi/ebsi_verifier_qrcode_3.html" : "EBSI - Style 3",
                    "ebsi/ebsi_verifier_qrcode_4.html" : "EBSI - Altme landing page",
                    "ebsi/ebsi_verifier_qrcode_5.html" : "EBSI - Style 2 with counter",
                    "ebsi/ebsi_verifier_qrcode_6.html" : "EBSI - Style 2 with html",
                    "ebsi/ebsi_verifier_qrcode_7.html" : "EBSI - Altme style with html",
                    "ebsi/ebsi_test.html" : "EBSI test"
}


protocol_list = {'w3cpr' : "W3C Presentation Request ",
                 'siopv2' : 'Siop V2 EBSI implementation',
                  'siopv2_openid' : 'Siop V2 OpenID implementation'
                 }

pre_authorized_code_list = {'none' : "None",
                 'pac' : 'Pre authorized code',
                  'pac_pin' : 'Pre authorized code + PIN code'
                 }

model = {
            "type": "VerifiablePresentationRequest",
            "query": [
                {
                    "type": "QueryByExample",
                    "credentialQuery": []
                }
            ],
            "challenge": "",
            "domain" : ""
}


model_one = {
            "type": "VerifiablePresentationRequest",
            "query": [
                {
                    "type": "QueryByExample",
                    "credentialQuery": [
                        {
                            "example" : {
                                "type" : "",
                            },
                            "reason": ""
                        }
                    ]   
                }
            ],
            "challenge": "",
            "domain" : ""
            }

model_two = {
            "type": "VerifiablePresentationRequest",
            "query": [
                {
                    "type": "QueryByExample",
                    "credentialQuery": [
                        {
                            "example" : {"type" : ""},
                            "reason": ""
                        },
                        {
                            "example" : {"type" : ""},
                            "reason": ""
                        }
                    ]
                }
            ],
            "challenge": "",
            "domain" : ""
            }

model_three = {
            "type": "VerifiablePresentationRequest",
            "query": [
                {
                    "type": "QueryByExample",
                    "credentialQuery": [
                        {
                            "example" : {"type" : ""},
                            "reason": ""
                        },
                        {
                            "example" : {"type" : ""},
                            "reason": ""
                        },
                        {
                            "example" : {"type" : ""},
                            "reason": ""
                        }
                    ]
                }
            ],
            "challenge": "",
            "domain" : ""
            }

model_DIDAuth = {
           "type": "VerifiablePresentationRequest",
           "query": [{
               "type": "DIDAuth"
               }],
           "challenge": "",
           "domain" : ""
    }

model_any = {
            "type": "VerifiablePresentationRequest",
            "query": [
                {
                    "type": "QueryByExample",
                    "credentialQuery": list()
                }
            ],
            "challenge": "",
            "domain" : ""
            }


client_data_pattern = {
                "sbt_name" : "",
                "sbt_description" : "",
                "sbt_display_uri" : "",
                "sbt_thumbnail_uri" : "",
                "sbt_artifact_uri" : "",
                "sbt_network" : "none",
                "ebsi_vp_type" : "jwt_vp",
                "ebsi_issuer_vc_type" : "jwt_vc",
                "beacon_mode" : "issuer",
                "pre_authorized_code" : "no",
                "beacon_payload_message" : "Any string for a message to display",
                "pkce" : None,
                "tezid_proof_type" : "",
                "tezid_network" : "none",
                "vc" : "DID",
                "vc_issuer_id" : "",
                "vc_2" : "DID",
                "totp_interval" : "30", 
                "standalone" : None, # data are NOT transfered to application by default
                "user" : "guest",
                "client_id" :  "",
                "client_secret" : "",
                "callback" : "https://altme.io",
                "webhook" : "https://altme.io",
                "jwk" : "",
                "method" : "",
                "did_ebsi": "",
                "issuer_landing_page" : "",     
                "note" : "",
                "company_name" : "New company",
                "application_name" : "Application name",
                "reason" : " ",
                "reason_2" : " ",
                "reason_3" : " ",
                "reason_4" : " ",
                "credential_requested" : "DID",
                "credential_requested_2" : "DID",
                "credential_requested_3" : "DID",
                "credential_requested_4" : "DID",
                "credential_to_issue" : "Pass",
                "credential_to_issue_2" : "None",
                "protocol" : "w3cpr",
                "landing_page_style" : "op_issuer_qrcode.html",
                "verifier_landing_page_style" : "op_verifier_qrcode_2.html",
                "page_title" : "Page title",
                "page_subtitle" : "Page subtitle",
                "page_description" : "Add here a credential description as you would like to see it displayed on the landing page of your app.",
                "page_background_color" : "#ffffff",
                "page_text_color" : "#000000",
                "card_title" : "Card title",
                "card_subtitle" : "Card subtitle",
                "card_description" : "Add here a credential description as you would like to see it displayed in the wallet.",
                "card_background_color" : "#ec6f6f",
                "card_text_color" : "#ffffff",
                "credential_duration" : "365",
                "qrcode_background_color" :"#ffffff",
                "qrcode_message" : "Qrcode text",
                "mobile_message" : "Message for smartphone",
                "contact_email" : "support@altme.io",
                "contact_name" : "",
                "secret" : "", # static or OTP
                "landing_page_url" : "https://talao.io",
                "privacy_url" : "https://altme.io/privacy",
                "terms_url" : "https://altme.io/cgu", 
                "title" : "Page subtitle for smartphone" # QR code title
                }

ebsi_verifier_claims = {
    "id_token":{
        "email": None
    },
    "vp_token":{
        "presentation_definition": {
            "id":"",
            "input_descriptors":[],
            "format":""
        }
    }
}

input_descriptor = {
                    "id":"",
                    "name":"",
                    "purpose":"",
                    "constraints":{
                        "fields":[
                            {
                                "path":["$.vc.credentialSchema"],
                                "filter": ""
                            }
                        ]
                    }
                }

filter = {
            "allOf":[
                {
                    "type":"array",
                    "contains":{
                        "type":"object",
                        "properties":{
                            "id":{
                                "type":"string",
                                "pattern":""
                            }
                        },
                        "required":["id"]
                    }
                }
            ]
        }


