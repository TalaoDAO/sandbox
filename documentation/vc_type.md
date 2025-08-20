# Talao Verifiable Credentials

Updated the 25th of November 2024.

This is the description of the Verifiable Credentials issued by Talao issuers and available through a link in the wallets (Discover screen).

## EthereumAssociatedAddress

This VC is issued to the user by the wallet itself but signed with the key of the crypto account. It is a proof of the ownership of the crypto account. With this VC the user can proove he is the owner of a blockchain account and he can build a trust link between another identity claim (given_name, fammily_name, age over, bank acciount number ...) and the crypto account.

```json
{
	"@context": [ "https://www.w3.org/2018/credentials/v1", 
		{
			"@vocab": "https://schema.org",
			"associatedAddress" : "https://w3id.org/security#blockchainAccountId",
			"EthereumAssociatedAddress" : "https://doc.wallet-provider.io/vc_type/#ethereumassociatedadress"
		}
	],
	"id" : "",
	"type": [
		"VerifiableCredential",
		"EthereumAssociatedAddress"
	],
	"issuer" : {
		"id": "",
		"name": "My Wallet"
	},
	"credentialSubject" : {
		"id" : "",
		"type" : "EthereumAssociatedAddress",
		"associatedAddress" : ""
	}
}

```

## EtherlinkAssociatedAddress

Same as above with the Etherlink blockchain.

## TezosAssociatedAddress

Same as above with the Tezos blockchain.

## PolygonAssociatedAddress

Same as above with the Polygon blockchain.

## BinanceAssociatedAddress

Same as above with the BnB blockchain.

## FantomAssociatedAddress

Same as above with the Fantom blockchain.

## EmailPass

This VC is issued after the verification of the user email through a secret code verification. 3 trials are allowed. This VC is available in all formats (SD-JWT, JSON-LD and JWT VC)

Example W3C JSON-LD 1.1 format (ldp_vc):

```json
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    {
      "EmailPass": "https://doc.wallet-provider.io/wallet/vc_type/#EmailPass",
      "@vocab": "https://schema.org/"
    }
  ],
  "id": "urn:uuid:3f404f3c-ee20-42c7-9381-f318b461387c",
  "type": [
    "VerifiableCredential",
    "EmailPass"
  ],
  "credentialSubject": {
    "id": "did:key:zQ3shuCH4atYWSjWvBhat5hkS98p4QzBeeXJtBRf22aAbW4vP",
    "type": "EmailPass",
    "email": "john.doe@example.com"
  },
  "issuer": {
    "id": "did:key:zQ3shPyHAZTwTTD4JFHvm7Q2tTKUeAep8mrt2Rp48wK4A2YME",
    "name": "Talao",
    "description": "See https://talao.io"
  },
  "issuanceDate": "2024-11-16T14:15:18Z",
  "proof": {
    "type": "EcdsaSecp256k1Signature2019",
    "proofPurpose": "assertionMethod",
    "verificationMethod": "did:key:zQ3shPyHAZTwTTD4JFHvm7Q2tTKUeAep8mrt2Rp48wK4A2YME#zQ3shPyHAZTwTTD4JFHvm7Q2tTKUeAep8mrt2Rp48wK4A2YME",
    "created": "2024-11-16T13:15:18.978Z",
    "jws": "eyJhbGciOiJFUzI1NksiLCJjcml0IjpbImI2NCJdLCJiNjQiOmZhbHNlfQ..W0DVDdVwayLjISE9oS7bAzcsI11vgLgl0K_9GX_6SsN-e-J2WnO7arGPgwieEU7NSlpod7z2Zg6riLVsmk7zfg"
  }
}
```

Example of a presentation definition to request this VC:

```json
{
    "id": "5188cgfe-3b8d-11ef-9c7e-31a372359459",
    "input_descriptors": [
        {
            "id": "email_1",
            "name": "Input descriptor for email credential",
            "constraints": {
                "fields": [
                    {
                        "path": [
                            "$.credentialSubject.email"
                        ]
                    }
                ]
            }
        }
    ],
    "name": "Test #6",
    "format": {
        "ldp_vp": {
            "proof_type": [
                "JsonWebSignature2020",
                "Ed25519Signature2018",
                "EcdsaSecp256k1Signature2019",
                "RsaSignature2018"
            ]
        },
        "ldp_vc": {
            "proof_type": [
                "JsonWebSignature2020",
                "Ed25519Signature2018",
                "EcdsaSecp256k1Signature2019",
                "RsaSignature2018"
            ]
        }
    }
}
```

## PhoneProof

This VC is issued after the verification of the user phone number through a secret code verification sent by SMS. 3 trials are allowed.

Example W3C JSON-LD 1.1 format (ldp_vc):

```json
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    {
      "@vocab": "https://schema.org/",
      "PhoneProof": "https://doc.wallet-provider.io/wallet/vc_type/#PhoneProof"
    }
  ],
  "id": "urn:uuid:37947b60-90da-43c4-950a-afc2ebc9594f",
  "type": [
    "VerifiableCredential",
    "PhoneProof"
  ],
  "credentialSubject": {
    "id": "did:key:zQ3shuCH4atYWSjWvBhat5hkS98p4QzBeeXJtBRf22aAbW4vP",
    "phone": "+33606060606",
    "type": "PhoneProof"
  },
  "issuer": {
    "id": "did:key:zQ3shPyHAZTwTTD4JFHvm7Q2tTKUeAep8mrt2Rp48wK4A2YME",
    "description": "See https://talao.io",
    "name": "Talao"
  },
  "issuanceDate": "2024-11-16T14:21:04Z",
  "proof": {
    "type": "EcdsaSecp256k1Signature2019",
    "proofPurpose": "assertionMethod",
    "verificationMethod": "did:key:zQ3shPyHAZTwTTD4JFHvm7Q2tTKUeAep8mrt2Rp48wK4A2YME#zQ3shPyHAZTwTTD4JFHvm7Q2tTKUeAep8mrt2Rp48wK4A2YME",
    "created": "2024-11-16T13:21:04.751Z",
    "jws": "eyJhbGciOiJFUzI1NksiLCJjcml0IjpbImI2NCJdLCJiNjQiOmZhbHNlfQ..MAJeW8XW3ly7d8a8slZvWvhKK-p2k_hT1uUcG4J8D5gEEFqnLoQAGPb8LDEtswXC7fsuxcmrHzEvLzEDX7FSYA"
  }
}
```

## Personal ID (PID)

This VC is issued through the [ID360 solution published by Docaposte/La Poste](https://www.docaposte.com/en/solutions/id360).

Example in SD-JWT format:

```json
{
  "alg": "ES256",
  "kid": "U6N9AzyVvjl1jLAtR64IETwWWUQzCb1bClHj2-7U3nA",
  "typ": "vc+sd-jwt"
}

{
  "_sd": [
    "aUZfFU1_Vh0kiLziBAnXq7wxe1YT1G0-XGAbHFlO_jE",
    "PQk4YZ1jxXa6cRJ91lk64h3V_5Wui5h-kT9p-By6flg",
    "aJ3OX7aIXBSpqEkaHlPb5saUIgsIKToSB3HFbN-p0uA",
    "lg4oqoJ9XlDL-8SPPVt5oV1penxGgPrJi-ACOUSPCA4",
    "My_tUpde8uiHC8_UY6H_4W8uLukOXhw3ZunH-f6XRSk"
  ],
  "_sd_alg": "sha-256",
  "address": {
    "_sd": [
      "mCJktZLZZRdFTe0sZX-PnXp7aKAJJ4oEz_oam4ZhVlQ",
      "nclmyedFf1buI-d1Yf9F00kC6VLdgSVwDYfhEq4aUaI",
      "9dYF8st7HOmJ2Nu94Vkkf8AmQ3_RsuGvPM6Qr5lTWNc",
      "fGgjfG2caKH1gE_84gvnKRH-K2MNs4sXxXWKSQtOido"
    ],
    "country": "IT",
    "region": "Lazio"
  },
  "age_equal_or_over": {
    "65": false,
    "_sd": [
      "Z8SCaRtpa2cADnuW81Xb35ljTeZHARqGNrXtI7oaDO4",
      "0zz69pXaWfP-ElTi93CNRD60jP3bEOJHioBBeglCX-g",
      "7BovrwU2XDEFoAz_sn8Zv_QyhRXhXfsCPEO8ncL4dWw",
      "Hta0eXUWwz7zBDoA3ulsyS6R-A3KiXy4Qo7GFrnvKxE",
      "ZLHDiDVWsg-4a3KlaspQtECEB9Q1i5aS9VmL1n2VJeA"
    ]
  },
  "cnf": {
    "kid": "did:jwk:eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6IkFSOE1Mb3R2NjVDT0lWQldlNmRZRVBxeEp2YkdoRjUzYTIzX2dXdmhiTHciLCJ5IjoiY1lCRFJUZ3ZJeHFpeWNmZk1yOXRsMU1SQWZTV3gxSGRFcVl4Z2EzYThhcyJ9"
  },
  "exp": 1763330649,
  "gender": "male",
  "iat": 1731794649,
  "iss": "https://talao.co/issuer/grlvzckofy",
  "nationalities": [
    {
      "...": "0z0Z7nkFh446ZXQYzNelItr7fQzW7Pp5BuaYfeRUSTM"
    },
    {
      "...": "Cd-oHRF3D8j8KNidW8c14loxPAlY9b0liB-xnTwvsow"
    }
  ],
  "place_of_birth": {
    "_sd": [
      "EeKdw6w7Qtqhkms0Cu8p858K9dfRHZKqd9x7wmLaTCY",
      "ADozYr5_YMd2lOre7XlFh_rbBJwrMKIIT6N3cZd1Xnc"
    ],
    "country": "DE"
  },
  "status": {
    "status_list": {
      "idx": 5467,
      "uri": "https://talao.co/sandbox/issuer/statuslist/1"
    }
  },
  "vct": "urn:eu.europa.ec.eudi:pid:1"
}
```

Example of a presentation definition to request the PID:

```json
{
  "id": "pid",
  "input_descriptors": [
    {
      "id": "pid_credential",
      "format": {
        "vc+sd-jwt": {
          "sd-jwt_alg_values": [
            "ES256",
            "ES256K",
            "EdDSA"
          ],
          "kb-jwt_alg_values": [
            "ES256",
            "ES256K",
            "EdDSA"
          ]
        }
      },
      "constraints": {
        "fields": [
          {
            "path": [
              "$.vct"
            ],
            "filter": {
              "type": "string",
              "const": "urn:eu.europa.ec.eudi:pid:1"
            }
          }
        ]
      }
    }
  ]
}

```

## VerifiableId

This VC is issued through the [ID360 solution published by Docaposte/La Poste](https://www.docaposte.com/en/solutions/id360).

Example in W3C JSON-LD format (ldp_vc):

```json
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    {
      "VerifiableId": {
        "@context": {
          "@protected": true,
          "@version": 1.1,
          "age_over_12": "schema:requiredMinAge",
          "age_over_14": "schema:requiredMinAge",
          "age_over_16": "schema:requiredMinAge",
          "age_over_18": "schema:requiredMinAge",
          "age_over_21": "schema:requiredMinAge",
          "age_over_65": "schema:requiredMinAge",
          "birth_date": "schema:birthDate",
          "family_name": "schema:familyName",
          "gender": "schema:gender",
          "given_name": "schema:givenName",
          "id": "@id",
          "issuance_date": "schema:dateIssued",
          "issuing_country": "schema:country",
          "schema": "https://schema.org/",
          "type": "@type"
        },
        "@id": "https://doc.wallet-provider.io/wallet/vc_type/#VerifiableId"
      }
    }
  ],
  "id": "urn:uuid:37f7cf25-a409-11ef-a455-0a1628958560",
  "type": [
    "VerifiableCredential",
    "VerifiableId"
  ],
  "credentialSubject": {
    "id": "did:key:z6MkuLap6dd9Epsg3emfnrXd4Zm6nbtyaKDKkq9VwwULe8oD",
    "age_over_12": true,
    "age_over_14": true,
    "age_over_16": true,
    "age_over_18": true,
    "age_over_21": true,
    "age_over_65": false,
    "type": "VerifiableId",
    "gender": 1,
    "birth_date": "1961-10-01",
    "issuance_date": "2024-11-16",
    "issuing_country": "US",
    "given_name": "John",
    "family_name": "DOE",
   
  },
  "issuer": {
    "id": "did:web:app.altme.io:issuer",
    "name": "Talao",
    "description": "See https://talao.io"
  },
  "issuanceDate": "2024-11-16T10:54:57Z",
  "proof": {
    "type": "EcdsaSecp256k1Signature2019",
    "proofPurpose": "assertionMethod",
    "verificationMethod": "did:web:app.altme.io:issuer#key-3",
    "created": "2024-11-16T10:54:57.275Z",
    "jws": "eyJhbGciOiJFUzI1NksiLCJjcml0IjpbImI2NCJdLCJiNjQiOmZhbHNlfQ..YbNFlRTO4bGkj9bBn1sTzzFQkzu88gLV0PQ5ClsEbsVFOZddqLqHNV-cT81G5-o95qhqnbkdMEnuKP3sYpQZOw"
  },
  "expirationDate": "2025-11-16T10:54:57.242356Z"
}

```

## AgeOver

Age is estimated with a [Yoti Artificial Intelligence](https://www.yoti.com/business/age-verification/) engine. For interoperability several claims are defined.

It is a SD-JWT VC with `vct` as `urn:talao:age_over`. Example:

```json
{
  "alg": "EdDSA",
  "kid": "did:web:app.altme.io:issuer#key-1",
  "typ": "vc+sd-jwt"
}

{
  "_sd": [
    "rK8MW2sCvbwR75SFwa_hceWgdm5r5nLzaoBqJpjd0zk",
    "izfTKt90TiGyJAW-8zd_IOasBkILw7Nk5CSF759cWtk",
    "GnxLCsrO91_cMxGdO7IgIhiphbRkqpmbflr_BOcZUQI",
    "TNaGCmac9uKF_Pi2PhbxqSyD1R4BtfgjR9qvPDv7hhM",
    "WFm7N7JKTR7azlmQXZJaxSOLz2cxJKjPD9qFo6UMjT4",
    "Ceoem87LjybhLFTaKbVKZWUmNGGY2hOVdffUTT4fMy4",
    "GQufuqcZ2vnau01RVBfvHliJa2pUhpKQDzvFdKVoRHY"
  ],
  "_sd_alg": "sha-256",
  "cnf": {
    "kid": "did:key:z6MkpbW3uBjLZn27BUDn83P89ut8xB3cxLj7sm9CNw7dkjac"
  },
  "exp": 1763369312,
  "iat": 1731833312,
  "iss": "did:web:app.altme.io:issuer",
  "vct": "urn:talao:age_over"
}


{
  "cnf": {
    "kid": "did:key:z6MkpbW3uBjLZn27BUDn83P89ut8xB3cxLj7sm9CNw7dkjac"
  },
  "exp": 1763369312,
  "iat": 1731833312,
  "iss": "did:web:app.altme.io:issuer",
  "vct": "urn:talao:age_over",
  "age_over_12": true,
  "age_over_14": true,
  "age_over_16": true,
  "age_over_18": true,
  "age_over_21": true,
  "age_over_50": false,
  "age_over_65": false
}
```

## Over18

Age is estimated with a [Yoti Artificial Intelligence](https://www.yoti.com/business/age-verification/) engine. For interoperability several claims are defined.

Examaple in W3C JSON-LD 1.1 format (ldp_vc)

```json
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    {
      "age_over_18": "https://eu-digital-identity-wallet.github.io/eudi-doc-architecture-and-reference-framework/1.4.0/annexes/annex-3/annex-3.01-pid-rulebook/",
      "@vocab": "https://schema.org",
      "Over18": "https://doc.wallet-provider.io/wallet/vc_type/#Over18"
    }
  ],
  "id": "urn:uuid:be78158b-a43b-11ef-af5b-0a5bad1dad00",
  "type": [
    "VerifiableCredential",
    "Over18"
  ],
  "credentialSubject": {
    "id": "did:key:z6MkpbW3uBjLZn27BUDn83P89ut8xB3cxLj7sm9CNw7dkjac",
    "ageOver": "18",
    "age_over_18": true,
    "type": "Over18"
  },
  "issuer": {
    "id": "did:web:app.altme.io:issuer",
    "name": "Talao",
    "description": "See htts://talao.io, age is estimated with a YOTI Artificial Intelligence engine."
  },
  "issuanceDate": "2024-11-16T16:56:37Z",
  "proof": {
    "type": "Ed25519Signature2018",
    "proofPurpose": "assertionMethod",
    "verificationMethod": "did:web:app.altme.io:issuer#key-1",
    "created": "2024-11-16T16:56:37.777Z",
    "jws": "eyJhbGciOiJFZERTQSIsImNyaXQiOlsiYjY0Il0sImI2NCI6ZmFsc2V9..Sm0GxH1TPioK1tpADfXj7YRix4YW_yYmAIQqq4BR069aH84Ewzfrml5_4rzLJJEcC1y_gJVFYil5RwtzWsbtCg"
  },
  "expirationDate": "2025-11-15T16:56:37Z"
}
```

## Over13

Same as above.

## Over15

Same as above.

## Over21

Same as above.

## Over50

Same as above.

## Over65

Same as above.
