

# Metadata

## Client Metadata {#client-metadata}

This specification defines the following new Client Metadata parameter in addition to those defined by [@!RFC7591] for Wallets acting as OAuth 2.0 Client:

* `credential_offer_endpoint`: OPTIONAL. Credential Offer Endpoint of a Wallet.

### Client Metadata Retrieval {#client-metadata-retrieval}

How to obtain Client Metadata is out of scope of this specification. Profiles of this specification MAY also define static sets of Client Metadata values to be used.

If the Credential Issuer is unable to perform discovery of the Wallet's Credential Offer Endpoint, the following custom URL scheme is used: `openid-credential-offer://`.

## Credential Issuer Metadata {#credential-issuer-metadata}

The Credential Issuer Metadata contains information on the Credential Issuer's technical capabilities, supported Credentials, and (internationalized) display information.

### Credential Issuer Identifier {#credential-issuer-identifier}

A Credential Issuer is identified by a case sensitive URL using the `https` scheme that contains scheme, host and, optionally, port number and path components, but no query or fragment components. 

### Credential Issuer Metadata Retrieval {#credential-issuer-wellknown}

The Credential Issuer's configuration can be retrieved using the Credential Issuer Identifier.

Credential Issuers publishing metadata MUST make a JSON document available at the path formed by concatenating the string `/.well-known/openid-credential-issuer` to the Credential Issuer Identifier. If the Credential Issuer value contains a path component, any terminating `/` MUST be removed before appending `/.well-known/openid-credential-issuer`.

Communication with the Credential Issuer Metadata Endpoint MUST utilize TLS.

To fetch the Credential Issuer Metadata, the requester MUST send an HTTP request using the GET method and the path formed following the steps above. The Credential Issuer MUST return a JSON document compliant with this specification using the `application/json` media type and the HTTP Status Code 200.

The Wallet is RECOMMENDED to send an `Accept-Language` Header in the HTTP GET request to indicate the language(s) preferred for display. It is up to the Credential Issuer whether to:

* send a subset the metadata containing internationalized display data for one or all of the requested languages and indicate returned languages using the HTTP `Content-Language` Header, or
* ignore the `Accept-Language` Header and send all supported languages or any chosen subset.

The language(s) in HTTP `Accept-Language` and `Content-Language` Headers MUST use the values defined in [@!RFC3066]. 

Below is a non-normative example of a Credential Issuer Metadata request:

```
GET /.well-known/openid-credential-issuer HTTP/1.1
Host: server.example.com
Accept-Language: fr-ch, fr;q=0.9, en;q=0.8, de;q=0.7, *;q=0.5
```

### Credential Issuer Metadata Parameters {#credential-issuer-parameters}

This specification defines the following Credential Issuer Metadata parameters:

* `credential_issuer`: REQUIRED. The Credential Issuer's identifier, as defined in (#credential-issuer-identifier).
* `authorization_servers`: OPTIONAL. Array of strings, where each string is an identifier of the OAuth 2.0 Authorization Server (as defined in [@!RFC8414]) the Credential Issuer relies on for authorization. If this parameter is omitted, the entity providing the Credential Issuer is also acting as the Authorization Server, i.e., the Credential Issuer's identifier is used to obtain the Authorization Server metadata. The actual OAuth 2.0 Authorization Server metadata is obtained from the `oauth-authorization-server` well-known location as defined in Section 3 of [@!RFC8414]. When there are multiple entries in the array, the Wallet may be able to determine which Authorization Server to use by querying the metadata; for example, by examining the `grant_types_supported` values, the Wallet can filter the server to use based on the grant type it plans to use. When the Wallet is using `authorization_server` parameter in the Credential Offer as a hint to determine which Authorization Server to use out of multiple, the Wallet MUST NOT proceed with the flow if the `authorization_server` Credential Offer parameter value does not match any of the entries in the `authorization_servers` array.
* `credential_endpoint`: REQUIRED. URL of the Credential Issuer's Credential Endpoint, as defined in (#credential-request). This URL MUST use the `https` scheme and MAY contain port, path, and query parameter components.
* `batch_credential_endpoint`: OPTIONAL. URL of the Credential Issuer's Batch Credential Endpoint, as defined in (#batch-credential-endpoint). This URL MUST use the `https` scheme and MAY contain port, path, and query parameter components. If omitted, the Credential Issuer does not support the Batch Credential Endpoint.
* `deferred_credential_endpoint`: OPTIONAL. URL of the Credential Issuer's Deferred Credential Endpoint, as defined in (#deferred-credential-issuance). This URL MUST use the `https` scheme and MAY contain port, path, and query parameter components. If omitted, the Credential Issuer does not support the Deferred Credential Endpoint.
* `notification_endpoint`: OPTIONAL. URL of the Credential Issuer's Notification Endpoint, as defined in (#notification-endpoint). This URL MUST use the `https` scheme and MAY contain port, path, and query parameter components. If omitted, the Credential Issuer does not support the Notification Endpoint.
* `credential_response_encryption`: OPTIONAL. Object containing information about whether the Credential Issuer supports encryption of the Credential and Batch Credential Response on top of TLS.
  * `alg_values_supported`: REQUIRED. Array containing a list of the JWE [@!RFC7516] encryption algorithms (`alg` values) [@!RFC7518] supported by the Credential and Batch Credential Endpoint to encode the Credential or Batch Credential Response in a JWT [@!RFC7519].
  * `enc_values_supported`: REQUIRED. Array containing a list of the JWE [@!RFC7516] encryption algorithms (`enc` values) [@!RFC7518] supported by the Credential and Batch Credential Endpoint to encode the Credential or Batch Credential Response in a JWT [@!RFC7519].
  * `encryption_required`: REQUIRED. Boolean value specifying whether the Credential Issuer requires the additional encryption on top of TLS for the Credential Response. If the value is `true`, the Credential Issuer requires encryption for every Credential Response and therefore the Wallet MUST provide encryption keys in the Credential Request. If the value is `false`, the Wallet MAY chose whether it provides encryption keys or not.
* `credential_identifiers_supported`: OPTIONAL. Boolean value specifying whether the Credential Issuer supports returning `credential_identifiers` parameter in the `authorization_details` Token Response parameter, with `true` indicating support. If omitted, the default value is `false`.
* `signed_metadata`: OPTIONAL. String that is a signed JWT. This JWT contains Credential Issuer metadata parameters as claims. The signed metadata MUST be secured using JSON Web Signature (JWS) [@!RFC7515] and MUST contain an `iat` (Issued At) claim, an `iss` (Issuer) claim denoting the party attesting to the claims in the signed metadata, and `sub` (Subject) claim matching the Credential Issuer identifier. If the Wallet supports signed metadata, metadata values conveyed in the signed JWT MUST take precedence over the corresponding values conveyed using plain JSON elements. If the Credential Issuer wants to enforce use of signed metadata, it omits the respective metadata parameters from the unsigned part of the Credential Issuer metadata. A `signed_metadata` metadata value MUST NOT appear as a claim in the JWT. The Wallet MUST establish trust in the signer of the metadata, and obtain the keys to validate the signature before processing the metadata. The concrete mechanism how to do that is out of scope of this specification and MAY be defined in the profiles of this specification.
* `display`: OPTIONAL. Array of objects, where each object contains display properties of a Credential Issuer for a certain language. Below is a non-exhaustive list of valid parameters that MAY be included:
  * `name`: OPTIONAL. String value of a display name for the Credential Issuer.
  * `locale`: OPTIONAL. String value that identifies the language of this object represented as a language tag taken from values defined in BCP47 [@!RFC5646]. There MUST be only one object for each language identifier.
  * `logo`: OPTIONAL. Object with information about the logo of the Credential Issuer. Below is a non-exhaustive list of parameters that MAY be included:
    * `uri`: REQUIRED. String value that contains a URI where the Wallet can obtain the logo of the Credential Issuer. The Wallet needs to determine the scheme, since the URI value could use the `https:` scheme, the `data:` scheme, etc.
    * `alt_text`: OPTIONAL. String value of the alternative text for the logo image.
* `credential_configurations_supported`: REQUIRED. Object that describes specifics of the Credential that the Credential Issuer supports issuance of. This object contains a list of name/value pairs, where each name is a unique identifier of the supported Credential being described. This identifier is used in the Credential Offer as defined in (#credential-offer-parameters) to communicate to the Wallet which Credential is being offered. The value is an object that contains metadata about a specific Credential and contains the following parameters defined by this specification:
  * `format`: REQUIRED. A JSON string identifying the format of this Credential, i.e., `jwt_vc_json` or `ldp_vc`. Depending on the format value, the object contains further elements defining the type and (optionally) particular claims the Credential MAY contain and information about how to display the Credential. (#format-profiles) contains Credential Format Profiles introduced by this specification.
  * `scope`: OPTIONAL. A JSON string identifying the scope value that this Credential Issuer supports for this particular Credential. The value can be the same across multiple `credential_configurations_supported` objects. The Authorization Server MUST be able to uniquely identify the Credential Issuer based on the scope value. The Wallet can use this value in the Authorization Request as defined in (#credential-request-using-type-specific-scope). Scope values in this Credential Issuer metadata MAY duplicate those in the `scopes_supported` parameter of the Authorization Server.
  * `cryptographic_binding_methods_supported`: OPTIONAL. Array of case sensitive strings that identify the representation of the cryptographic key material that the issued Credential is bound to, as defined in (#credential-binding). Support for keys in JWK format [@!RFC7517] is indicated by the value `jwk`. Support for keys expressed as a COSE Key object [@!RFC8152] (for example, used in [@!ISO.18013-5]) is indicated by the value `cose_key`. When the Cryptographic Binding Method is a DID, valid values are a `did:` prefix followed by a method-name using a syntax as defined in Section 3.1 of [@!DID-Core], but without a `:`and method-specific-id. For example, support for the DID method with a method-name "example" would be represented by `did:example`.
  * `credential_signing_alg_values_supported`: OPTIONAL. Array of case sensitive strings that identify the algorithms that the Issuer uses to sign the issued Credential. Algorithm names used are determined by the Credential format and are defined in (#format-profiles).
  * `proof_types_supported`: OPTIONAL. Object that describes specifics of the key proof(s) that the Credential Issuer supports. This object contains a list of name/value pairs, where each name is a unique identifier of the supported proof type(s). Valid values are defined in (#proof-types), other values MAY be used. This identifier is also used by the Wallet in the Credential Request as defined in (#credential-request). The value in the name/value pair is an object that contains metadata about the key proof and contains the following parameters defined by this specification:
    * `proof_signing_alg_values_supported`: REQUIRED. Array of case sensitive strings that identify the algorithms that the Issuer supports for this proof type. The Wallet uses one of them to sign the proof. Algorithm names used are determined by the key proof type and are defined in (#proof-types).
  * `display`: OPTIONAL. Array of objects, where each object contains the display properties of the supported Credential for a certain language. Below is a non-exhaustive list of parameters that MAY be included.
      * `name`: REQUIRED. String value of a display name for the Credential.
      * `locale`: OPTIONAL. String value that identifies the language of this object represented as a language tag taken from values defined in BCP47 [@!RFC5646]. Multiple `display` objects MAY be included for separate languages. There MUST be only one object for each language identifier.
      * `logo`: OPTIONAL. Object with information about the logo of the Credential. The following non-exhaustive set of parameters MAY be included:
          * `uri`: REQUIRED. String value that contains a URI where the Wallet can obtain the logo of the Credential from the Credential Issuer. The Wallet needs to determine the scheme, since the URI value could use the `https:` scheme, the `data:` scheme, etc.
          * `alt_text`: OPTIONAL. String value of the alternative text for the logo image.
      * `description`: OPTIONAL. String value of a description of the Credential.
      * `background_color`: OPTIONAL. String value of a background color of the Credential represented as numerical color values defined in CSS Color Module Level 37 [@!CSS-Color].
      * `background_image`: OPTIONAL. Object with information about the background image of the Credential. At least the following parameter MUST be included:
          * `uri`: REQUIRED. String value that contains a URI where the Wallet can obtain the background image of the Credential from the Credential Issuer. The Wallet needs to determine the scheme, since the URI value could use the `https:` scheme, the `data:` scheme, etc.
      * `text_color`: OPTIONAL. String value of a text color of the Credential represented as numerical color values defined in CSS Color Module Level 37 [@!CSS-Color].

An Authorization Server that only supports the Pre-Authorized Code grant type MAY omit the `response_types_supported` parameter in its metadata despite [@!RFC8414] mandating it.

Note: It can be challenging for a Credential Issuer that accepts tokens from multiple Authorization Servers to introspect an Access Token to check the validity and determine the permissions granted. Some ways to achieve this are relying on Authorization Servers that use [@!RFC9068] or by the Credential Issuer understanding the proprietary Access Token structures of the Authorization Servers.

Depending on the Credential format, additional parameters might be present in the `credential_configurations_supported` object values, such as information about claims in the Credential. For Credential format specific claims, see the "Credential Issuer Metadata" subsections in (#format-profiles).

The Authorization Server MUST be able to determine from the Issuer metadata what claims are disclosed by the requested Credentials to be able to render meaningful End-User consent.

The following is a non-normative example of Credential Issuer metadata:

<{{examples/credential_issuer_metadata_jwt_vc_json.json}}

Note: The Client MAY use other mechanisms to obtain information about the Verifiable Credentials that a Credential Issuer can issue.

## OAuth 2.0 Authorization Server Metadata

This specification also defines a new OAuth 2.0 Authorization Server metadata [@!RFC8414] parameter to publish whether the Authorization Server that the Credential Issuer relies on for authorization supports anonymous Token Requests with the Pre-Authorized Grant Type. It is defined as follows:

* `pre-authorized_grant_anonymous_access_supported`: OPTIONAL. A boolean indicating whether the Credential Issuer accepts a Token Request with a Pre-Authorized Code but without a `client_id`. The default is `false`. 

