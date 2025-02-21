TEST = { 
        "oidc4vciDraft": "13",
        "siopv2Draft": "12",
        "oidc4vpDraft": "18",
        "vc_format": "vc+sd-jwt",
        "verifier_vp_type": "vc+sd-jwt",
        "oidc4vci_prefix": "openid-credential-offer://",
        "authorization_server_support": False,
        "credentials_as_json_object_array": False,
        "siopv2_prefix": "openid-vc://",
        "oidc4vp_prefix": "openid-vc://",
        "credentials_types_supported": ["Pid"],
        "credential_configurations_supported": {
            "Pid": {
                "format": "vc+sd-jwt",
                "scope": "Pid_scope",
                "order": [
                    "given_name",
                    "family_name",
                    #"birthdate",
                    "address",
                    "gender",
                    "place_of_birth",
                    "nationalities",
                    "age_equal_or_over", 
                    "issuing_country",
                    "issuing_authority"
                ],
                "claims": {
                        "given_name": {
                            "mandatory": True,
                            "value_type": "string",
                            "display": [{"name": "First Name", "locale": "en-US"},
                                        {"name": "Prénom", "locale": "fr-FR"}],
                        },
                        "family_name": {
                            "mandatory": True,
                            "value_type": "string",
                            "display": [{"name": "Family Name", "locale": "en-US"},
                                        {"name": "Nom", "locale": "fr-FR"}],
                        },
                        #"birthdate": {
                        #    "mandatory": True,
                        #    "value_type": "string",
                        #    "display": [{"name": "Birth date", "locale": "en-US"},
                        #                {"name": "Date de naissance", "locale": "fr-FR"}],
                        #},
                        "place_of_birth": {
                            "mandatory": True,
                            "value_type": "string",
                            "display": [{"name": "Birth place", "locale": "en-US"},
                                        {"name": "Lieu de naissance", "locale": "fr-FR"}],
                            "locality": {
                                "mandatory": True,
                                "value_type": "string",
                                "display": [
                                    {"name": "Locality", "locale": "en-US"},
                                    {"name": "Ville", "locale": "fr-FR"}],
                                },
                            "region": {
                                "mandatory": True,
                                "value_type": "string",
                                "display": [
                                    {"name": "Region", "locale": "en-US"},
                                    {"name": "Région", "locale": "fr-FR"}],
                                },
                            "country": {
                                "mandatory": True,
                                "value_type": "string",
                                "display": [
                                    {"name": "Country", "locale": "en-US"},
                                    {"name": "Pays", "locale": "fr-FR"}],
                                },
                            
                        },
                        "nationalities": {
                            "mandatory": True,
                            "value_type": "string",
                            "display": [{"name": "Nationalities", "locale": "en-US"},
                                        {"name": "Nationalités", "locale": "fr-FR"}],
                        },
                        "gender": {
                            "mandatory": True,
                            "value_type": "string",
                            "display": [{"name": "Gender", "locale": "en-US"},
                                        {"name": "Sexe", "locale": "fr-FR"}],
                        },
                        "address": {
                            "mandatory": True,
                            "value_type": "string",
                            "display": [
                                {"name": "Address", "locale": "en-US"},
                                {"name": "Adresse", "locale": "fr-FR"}
                            ],
                            "formatted": {
                                "mandatory": True,
                                "value_type": "string",
                                "display": [
                                    {"name": "Formatted", "locale": "en-US"},
                                    {"name": "Complete", "locale": "fr-FR"}],
                                },
                        #    "street_address": {
                        #        "mandatory": True,
                        #        "value_type": "string",
                        #        "display": [
                        #            {"name": "Street address", "locale": "en-US"},
                        #            {"name": "Rue", "locale": "fr-FR"}],
                        #        },
                            "locality": {
                                "mandatory": True,
                                "value_type": "string",
                                "display": [
                                    {"name": "Locality", "locale": "en-US"},
                                    {"name": "Ville", "locale": "fr-FR"}],
                                },
                            "region": {
                                "mandatory": True,
                                "value_type": "string",
                                "display": [
                                    {"name": "Region", "locale": "en-US"},
                                    {"name": "Région", "locale": "fr-FR"}],
                                },
                            "country": {
                                "mandatory": True,
                                "value_type": "string",
                                "display": [
                                    {"name": "Country", "locale": "en-US"},
                                    {"name": "Pays", "locale": "fr-FR"}],
                                },
                        },
                        "age_equal_or_over": {
                            "mandatory": True,
                            "value_type": "bool",
                            "display": [{"name": "Age", "locale": "en-US"},
                                        {"name": "Age", "locale": "fr-FR"}],
                            "12": {
                                "mandatory": True,
                                "value_type": "string",
                                "display": [
                                    {"name": "Over 12", "locale": "en-US"},
                                    {"name": "Plus de 12 ans", "locale": "fr-FR"}],
                                },
                            "14": {
                                "mandatory": True,
                                "value_type": "string",
                                "display": [
                                    {"name": "Over 14", "locale": "en-US"},
                                    {"name": "Plus de 14 ans", "locale": "fr-FR"}],
                                },
                            "16": {
                                "mandatory": True,
                                "value_type": "string",
                                "display": [
                                    {"name": "Over 16", "locale": "en-US"},
                                    {"name": "Plus de 16 ans", "locale": "fr-FR"}],
                                },
                            #"18": {
                            #    "mandatory": True,
                            #    "value_type": "string",
                            #    "display": [
                            #        {"name": "Over 18", "locale": "en-US"},
                            #        {"name": "Plus de 18 ans", "locale": "fr-FR"}],
                            #    },
                            "21": {
                                "mandatory": True,
                                "value_type": "string",
                                "display": [
                                    {"name": "Over 21", "locale": "en-US"},
                                    {"name": "Plus de 21 ans", "locale": "fr-FR"}],
                                },
                            "65": {
                                "mandatory": True,
                                "value_type": "string",
                                "display": [
                                    {"name": "Senior", "locale": "en-US"},
                                    {"name": "Senior", "locale": "fr-FR"}],
                                },
                        },
                        "dateIssued": {
                            "mandatory": True,
                            "value_type": "string",
                            "display": [{"name": "Issuance date", "locale": "en-US"},
                                        {"name": "Délivré le", "locale": "fr-FR"}],
                        },
                        "expiry_date": {
                            "mandatory": True,
                            "value_type": "string",
                            "display": [{"name": "Expiry date", "locale": "en-US"},
                                        {"name": "Date d'expiration", "locale": "fr-FR"}],
                        },
                        "issuing_country": {
                            "mandatory": True,
                            "value_type": "string",
                            "display": [{"name": "Issuing country", "locale": "en-US"},
                                        {"name": "Pays d'emission", "locale": "fr-FR"}],
                        },
                        "issuing_authority": {
                            "mandatory": True,
                            "value_type": "string",
                            "display": [{"name": "Issuing autority", "locale": "en-US"},
                                        {"name": "Authorité d'emission", "locale": "fr-FR"}],
                        },
                    },
                "cryptographic_binding_methods_supported": ["DID", "jwk"],
                "credential_signing_alg_values_supported": [
                    "ES256K",
                    "ES256",
                    "EdDSA",
                ],
                "vct": "urn:eu.europa.ec.eudi.pid.1",
                "display": [
                    {
                        "name": "Person ID",
                        "locale": "en-US",
                        "background_color": "#14107c",
                        "text_color": "#FFFFFF",
                    },
                    {
                        "name": "Person ID",
                        "locale": "fr-FR",
                        "background_color": "#14107c",
                        "text_color": "#FFFFFF",
                    }
                ],
            }
        },
        "grant_types_supported": [
            "authorization_code",
            "urn:ietf:params:oauth:grant-type:pre-authorized_code",
        ],
        "schema_for_type": False,
        "credential_manifest_support": False,
    }