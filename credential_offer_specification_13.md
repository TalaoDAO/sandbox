


## Credential Offer {#credential-offer}

The Credential Issuer sends Credential Offer using an HTTP GET request or an HTTP redirect to the Wallet's Credential Offer Endpoint defined in (#client-metadata).

The Credential Offer object, which is a JSON-encoded object with the Credential Offer parameters, can be sent by value or by reference.

The Credential Offer contains a single URI query parameter, either `credential_offer` or `credential_offer_uri`:

* `credential_offer`: Object with the Credential Offer parameters. This MUST NOT be present when the `credential_offer_uri` parameter is present.
* `credential_offer_uri`: String that is a URL using the `https` scheme referencing a resource containing a JSON object with the Credential Offer parameters. This MUST NOT be present when the `credential_offer` parameter is present.

The Credential Issuer MAY render a QR code containing the Credential Offer that can be scanned by the End-User using a Wallet, or a link that the End-User can click.

For security considerations, see (#credential-offer-security).

### Credential Offer Parameters {#credential-offer-parameters}

This specification defines the following parameters for the JSON-encoded Credential Offer object:

* `credential_issuer`: REQUIRED. The URL of the Credential Issuer, as defined in (#credential-issuer-identifier), from which the Wallet is requested to obtain one or more Credentials. The Wallet uses it to obtain the Credential Issuer's Metadata following the steps defined in (#credential-issuer-wellknown).
* `credential_configuration_ids`: REQUIRED. Array of unique strings that each identify one of the keys in the name/value pairs stored in the `credential_configurations_supported` Credential Issuer metadata. The Wallet uses these string values to obtain the respective object that contains information about the Credential being offered as defined in (#credential-issuer-parameters). For example, these string values can be used to obtain `scope` values to be used in the Authorization Request.
* `grants`: OPTIONAL. Object indicating to the Wallet the Grant Types the Credential Issuer's Authorization Server is prepared to process for this Credential Offer. Every grant is represented by a name/value pair. The name is the Grant Type identifier; the value is an object that contains parameters either determining the way the Wallet MUST use the particular grant and/or parameters the Wallet MUST send with the respective request(s). If `grants` is not present or is empty, the Wallet MUST determine the Grant Types the Credential Issuer's Authorization Server supports using the respective metadata. When multiple grants are present, it is at the Wallet's discretion which one to use.

The following values are defined by this specification: 

* Grant Type `authorization_code`:
  * `issuer_state`: OPTIONAL. String value created by the Credential Issuer and opaque to the Wallet that is used to bind the subsequent Authorization Request with the Credential Issuer to a context set up during previous steps. If the Wallet decides to use the Authorization Code Flow and received a value for this parameter, it MUST include it in the subsequent Authorization Request to the Credential Issuer as the `issuer_state` parameter value.
  * `authorization_server`: OPTIONAL string that the Wallet can use to identify the Authorization Server to use with this grant type when `authorization_servers` parameter in the Credential Issuer metadata has multiple entries. It MUST NOT be used otherwise. The value of this parameter MUST match with one of the values in the `authorization_servers` array obtained from the Credential Issuer metadata.
* Grant Type `urn:ietf:params:oauth:grant-type:pre-authorized_code`:
  * `pre-authorized_code`: REQUIRED. The code representing the Credential Issuer's authorization for the Wallet to obtain Credentials of a certain type. This code MUST be short lived and single use. If the Wallet decides to use the Pre-Authorized Code Flow, this parameter value MUST be included in the subsequent Token Request with the Pre-Authorized Code Flow.
  * `tx_code`: OPTIONAL. Object specifying whether the Authorization Server expects presentation of a Transaction Code by the End-User along with the Token Request in a Pre-Authorized Code Flow. If the Authorization Server does not expect a Transaction Code, this object is absent; this is the default. The Transaction Code is intended to bind the Pre-Authorized Code to a certain transaction to prevent replay of this code by an attacker that, for example, scanned the QR code while standing behind the legitimate End-User. It is RECOMMENDED to send the Transaction Code via a separate channel. If the Wallet decides to use the Pre-Authorized Code Flow, the Transaction Code value MUST be sent in the `tx_code` parameter with the respective Token Request as defined in (#token-request). If no `length` or `description` is given, this object may be empty, indicating that a Transaction Code is required.
    * `input_mode` : OPTIONAL. String specifying the input character set. Possible values are `numeric` (only digits) and `text` (any characters). The default is `numeric`.
    * `length`: OPTIONAL. Integer specifying the length of the Transaction Code. This helps the Wallet to render the input screen and improve the user experience.
    * `description`: OPTIONAL. String containing guidance for the Holder of the Wallet on how to obtain the Transaction Code, e.g., describing over which communication channel it is delivered. The Wallet is RECOMMENDED to display this description next to the Transaction Code input screen to improve the user experience. The length of the string MUST NOT exceed 300 characters. The `description` does not support internationalization, however the Issuer MAY detect the Holder's language by previous communication or an HTTP Accept-Language header within an HTTP GET request for a Credential Offer URI.
  * `interval`: OPTIONAL. The minimum amount of time in seconds that the Wallet SHOULD wait between polling requests to the token endpoint (in case the Authorization Server responds with error code `authorization_pending` - see (#token-error-response)). If no value is provided, Wallets MUST use `5` as the default.
  * `authorization_server`: OPTIONAL string that the Wallet can use to identify the Authorization Server to use with this grant type when `authorization_servers` parameter in the Credential Issuer metadata has multiple entries. It MUST NOT be used otherwise. The value of this parameter MUST match with one of the values in the `authorization_servers` array obtained from the Credential Issuer metadata.
  
The following non-normative example shows a Credential Offer object where the Credential Issuer can offer the issuance of two different Credentials (which may even be of different formats):

<{{examples/credential_offer_multiple_credentials.json}}

### Sending Credential Offer by Value Using `credential_offer` Parameter

Below is a non-normative example of a Credential Offer passed by value:

```
GET /credential_offer?credential_offer=%7B%22credential_issuer%22:%22https://credential-issuer.example.com%22,%22credentials%22:%5B%22UniversityDegree_JWT%22,%22org.iso.18013.5.1.mDL%22%5D,%22grants%22:%7B%22urn:ietf:params:oauth:grant-type:pre-authorized_code%22:%7B%22pre-authorized_code%22:%22oaKazRN8I0IbtZ0C7JuMn5%22,%22tx_code%22:%7B%7D%7D%7D%7D
```

The following is a non-normative example of a Credential Offer that can be included in a QR code or a link used to invoke a Wallet deployed as a native app:

```
openid-credential-offer://?credential_offer=%7B%22credential_issuer%22:%22https://credential-issuer.example.com%22,%22credentials%22:%5B%22org.iso.18013.5.1.mDL%22%5D,%22grants%22:%7B%22urn:ietf:params:oauth:grant-type:pre-authorized_code%22:%7B%22pre-authorized_code%22:%22oaKazRN8I0IbtZ0C7JuMn5%22,%22tx_code%22:%7B%22input_mode%22:%22text%22,%22description%22:%22Please%20enter%20the%20serial%20number%20of%20your%20physical%20drivers%20license%22%7D%7D%7D%7D
```

### Sending Credential Offer by Reference Using `credential_offer_uri` Parameter

Upon receipt of the `credential_offer_uri`, the Wallet MUST send an HTTP GET request to URI to retrieve the referenced Credential Offer Object, unless it is already cached, and parse it to recreate the Credential Offer parameters.

Note: The Credential Issuer SHOULD use a unique URI for each Credential Offer utilizing distinct parameters, or otherwise prevent the Credential Issuer from caching the `credential_offer_uri`.

Below is a non-normative example of this fetch process:

```
GET /credential_offer HTTP/1.1
Host: server.example.com
```

The response from the Credential Issuer that contains a Credential Offer Object MUST use the media type `application/json`.

This ability to pass the Credential Offer by reference is particularly useful for large requests.

Below is a non-normative example of the Credential Offer displayed by the Credential Issuer as a QR code when the Credential Offer is passed by reference:

```
openid-credential-offer://?
  credential_offer_uri=https%3A%2F%2Fserver%2Eexample%2Ecom%2Fcredential-offer.json
```

Below is a non-normative example of a response from the Credential Issuer that contains a Credential Offer Object used to encourage the Wallet to start an Authorization Code Flow:

<{{examples/credential_offer_authz_code.txt}}

Below is a non-normative example of a Credential Offer Object for a Pre-Authorized Code Flow (with a Credential type reference):

<{{examples/credential_offer_by_reference.json}}

When retrieving the Credential Offer from the Credential Offer URL, the `application/json` media type MUST be used. The Credential Offer cannot be signed and MUST NOT use `application/jwt` with `"alg": "none"`.

## Credential Offer Response

The Wallet does not create a response. UX control stays with the Wallet after completion of the process. 

