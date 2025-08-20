# Developer Mode

Updated the 8th of March 2025.

The developer mode allow any developers to get internal information about the wallet data and logic. It includes breakpoint in the code flow for debugging purposes and modifies the display of verifiable credentials.

The developer mode can be removed from the settings menu of the wallet through the wallet provider backend.

Below are all the wallet features which are enhanced or modified in the developer mode.

## Verifiable credentials in raw

Verifiable credentials are displayed in their original form as json-ld or jwt. For jwt users have an access to the header and payload of the credentials. For sd-jwt vc, jwt are displayed with all disclosures decoded.

## Wallet instance attestation

If the wallet is used with the wallet provider backend the developer mode gives access to the wallet instance attestation which is displayed on the main screen of the wallet in grey with a jwt format.

## Verifiable credentials status and validity details

In case of signature failure or invalid status, the reasons of the failure are provided in details.

## Issuance flow

After scanning an OIDC4VC QR code a popup proposes to users to:

* display:

  * the credential offer,
  * the credential issuer metadata (from /.well-known/openid-credential-issuer),
  * the authorization server metadata (from /.well-known/oauth-authorization-server),
* download this information as a text file,
* skip to bypass.

Within the OIDC4VCI flow, the wallet proposes to display or download the data sent and received from:

- the authorization endpoint and PAR endpoint: authorization request sent by the wallet and redirect of the authorization server
- the token endpoint: data sent to the issuer and token endpoint response
- the credential endpoint: data sent to the issuer with key proof decoded and credential endpoint response

## Presentation flow

After scanning an OIDC4VP or SIOPV2 QR code a popup proposes to users to:

* display:
  * the authorization request of the verifier,
  * the client metadata,
  * the presenttaion definition
* download this information as a text file,
* skip to bypass.

Within the OIDC4VP flow, the wallet proposes to display or download the data sent to:

- the respone_uri endpoint.

## Display of errors details

In case of an error response from issuers or verifiers, users have an access to the `error_description` data returned.
