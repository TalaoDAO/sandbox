# Wallet profiles

Updated the 12th of December 2024.

Users can access to wallet profiles through Settings/Wallet Profiles. This feature feature can be hidden in case of a specific wallet configuration through the Wallet Provider Backend.

Talao and Altme wallets can be directly downloaded from the Google or Apple stores and used as is. In that scenario users can choose between a list of 5 standards profiles and advances users can define their specific custom profile.

## Embedded standard wallet profiles

As any smartphone app users can download either Altme or Talao wallet for their Apple smartphone or Android device. In this case users can only access the predefined embedded configurations. Right now there are 5 predefined configuration named "Profiles" and one named "Custom" to allow manual settings. Below the main features of the 4 embedded profiles of the wallet:


| Profiles  | VC format                                      | OIDC4VCI | OIDC4VP | key                   | DID                            | Embedded issuer links                                                  |
| :---------- | ------------------------------------------------ | ---------- | --------- | ----------------------- | -------------------------------- | ------------------------------------------------------------------------ |
| Default   | ldp_vc, jwt_vc_json, jwt_vc_json-ld, vc+sd-jwt | 13       | 20      | EdDSA                 | did:key                        | VerifiableId (ldp_vc), EmailPass (ldp_vc), PhoneProof, Over18 (ldp_vc) |
| EBSI V3.x | jwt_vc                                         | 11       | 18      | P-256                 | did:key(EBSI)                  | IndividualVerifiableAttestation(jwt_vc)                                |
| EBSI V4.0 | ldp_vc, jwt_vc_json, jwt_vc_json-ld, vc+sd-jwt | 13       | 20      | P-256                 | did:key(EBSI)                  | VerifiableId (jwt_vc_json)                                             |
| DIIP V3.0 | jwt_vc_json, jwt_vc_json-ld, vc+sd-jwt         | 13       | 20      | P-256                 | did:jwk                        | Personal ID (vc+sd-jwt), Emailpass (vc+sd-jwt), Over18 (vc+sd-jwt)     |
| Custom    | Any                                            | 11/13    | 20      | EdDSA/P-256/seckp256k | did:key/did:jwk/JWK thumbprint | None                                                                   |

Advanced users can switch between the different profiles and even create their own custom profile. The wallets propose a lots of technical options for advanced users and developers.

At initialization the wallet profile is DIIP V3.0.

## Custom profile

To define a custom profile of the wallet:

1. Go to "Settings",
2. Choose profile "Custom",
3. Select the options you want to use.

This section allows an advanced user to specify manually the ecosystem technical options of his wallet. Custom profile can only support one VC format at a time.

## Wallet setup with the wallet provider backend

**These features require a Wallet Provider Backend account.**

### Download the wallet and configure it with a QR code to get a specific configuration

In this case users must first download the wallet from the store then scan the QR code provided to install the wallet to your device with a specific configuration defined in the wallet provider backend. The QR code could be displayed on website or could be sent by email or SMS as a deeplink. There are 2 types of users:

* standard users : they have a login/password and they are managed through the wallet provider backend. They can be suspended or even revoked if needed. They also have a personal access to the wallet provider backend to manage their own account,
* guest: they have no login/password, it is a public access to your onboard unknown users

**It is the best solution to deploy your wallet to a group of known people.**

### Download and configure the wallet in one step with an installation link

In this case the link allowed your users to install the wallet to their device with a specific configuration defined in the wallet provider backend. The installation link is in the form of:

* `https://app.talao.co/install?password=guest&login=guest@identinet&wallet-provider=https://wallet-provider.talao.co `or
* `https://app.altme.io/install?password=guest&login=guest@identinet&wallet-provider=https://wallet-provider.talao.co`

The installation link is only available for guests.

**It is the best solution to deploy your wallet to a wide public**.
