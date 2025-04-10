
# Authorization Request {#vp_token_request}

The Authorization Request follows the definition given in [@!RFC6749] taking into account the recommendations given in [@!I-D.ietf-oauth-security-topics].

The Verifier may send an Authorization Request as Request Object by value or by reference as defined in JWT-Secured Authorization Request (JAR) [@RFC9101].

The Verifier articulates requirements of the Credential(s) that are requested using `presentation_definition` and `presentation_definition_uri` parameters that contain a Presentation Definition JSON object as defined in Section 5 of [@!DIF.PresentationExchange]. Wallet implementations MUST process Presentation Definition JSON object and select candidate Verifiable Credential(s) using the evaluation process described in Section 8 of [@!DIF.PresentationExchange].

The Verifier communicates a Client Identifier Scheme that indicate how the Wallet is supposed to interpret the Client Identifier and associated data in the process of Client identification, authentication, and authorization using `client_id_scheme` parameter. This parameter enables deployments of this specification to use different mechanisms to obtain and validate Client metadata beyond the scope of [@!RFC6749]. A certain Client Identifier Scheme MAY require the Verifier to sign the Authorization Request as means of authentication and/or pass additional parameters and require the Wallet to process them.

Depending on the Client Identifier Scheme, the Verifier can communicate a JSON object with its metadata using `client_metadata` and `client_metadata_uri` parameters that contain name/value pairs defined in Section 4.3 and Section 2.1 of the OpenID Connect Dynamic Client Registration 1.0 [@!OpenID.Registration] specification as well as [@!RFC7591]. The parameter names include a term `client` since the Verifier is acting as an OAuth 2.0 Client.

This specification enables the Verifier to send both Presentation Definition JSON object and Client Metadata JSON object by value or by reference.

This specification defines the following new parameters:

`presentation_definition`:
: A string containing a Presentation Definition JSON object. See (#request_presentation_definition) for more details. This parameter MUST be present when `presentation_definition_uri` parameter, or a `scope` value representing a Presentation Definition is not present.

`presentation_definition_uri`:
: A string containing an HTTPS URL pointing to a resource where a Presentation Definition JSON object can be retrieved. This parameter MUST be present when `presentation_definition` parameter, or a `scope` value representing a Presentation Definition is not present. See (#request_presentation_definition_uri) for more details.

`client_id_scheme`: 
: OPTIONAL. A string identifying the scheme of the value in the `client_id` Authorization Request parameter (Client Identifier scheme). The `client_id_scheme` parameter namespaces the respective Client Identifier. If an Authorization Request uses the `client_id_scheme` parameter, the Wallet MUST interpret the Client Identifier of the Verifier in the context of the Client Identifier scheme. If the parameter is not present, the Wallet MUST behave as specified in [@!RFC6749]. See (#client_metadata_management) for the values defined by this specification. If the same Client Identifier is used with different Client Identifier schemes, those occurrences MUST be treated as different Verifiers. Note that the Verifier needs to determine which Client Identifier schemes the Wallet supports prior to sending the Authorization Request in order to choose a supported scheme.

`client_metadata`:
: OPTIONAL. A JSON object containing the Verifier metadata values. It MUST be UTF-8 encoded. It MUST NOT be present if `client_metadata_uri` parameter is present.

`client_metadata_uri`: 
: OPTIONAL. A string containing an HTTPS URL pointing to a resource where a JSON object with the Verifier metadata can be retrieved. The scheme used in the `client_metadata_uri` value MUST be `https`. The `client_metadata_uri` value MUST be reachable by the Wallet. It MUST NOT be present if `client_metadata` parameter is present.

A public key to be used by the Wallet as an input to the key agreement to encrypt Authorization Response (see (#jarm)). It MAY be passed by the Verifier using the `jwks` or the `jwks_uri` claim within the `client_metadata` or `client_metadata_uri` request parameter.

The following additional considerations are given for pre-existing Authorization Request parameters:

`nonce`:
: REQUIRED. Defined in [@!OpenID.Core]. It is used to securely bind the Verifiable Presentation(s) provided by the Wallet to the particular transaction. See (#preventing-replay) for details. 

`scope`:
: OPTIONAL. Defined in [@!RFC6749]. The Wallet MAY allow Verifiers to request presentation of Verifiable Credentials by utilizing a pre-defined scope value. See (#request_scope) for more details.

`response_mode`:
: OPTIONAL. Defined in [@!OAuth.Responses]. This parameter is used (through the new Response Mode `direct_post`) to ask the Wallet to send the response to the Verifier via an HTTPS connection (see (#response_mode_post) for more details). It is also used to request signing and encrypting (see (#jarm) for more details). If the parameter is not present, the default value is `fragment`. 

The following is a non-normative example of an Authorization Request: 

```
  GET /authorize?
    response_type=vp_token
    &client_id=https%3A%2F%2Fclient.example.org%2Fcb
    &redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb
    &presentation_definition=...
    &nonce=n-0S6_WzA2Mj HTTP/1.1
```

## `presentation_definition` Parameter {#request_presentation_definition}

This parameter contains a Presentation Definition JSON object conforming to the syntax defined in Section 5 of [@!DIF.PresentationExchange].

The following is a non-normative example how `presentation_definition` parameter can simply be used to request the presentation of a Credential of a certain type:

<{{examples/request/vp_token_type_only.json}}

The following non-normative example shows how the Verifier can request selective disclosure or certain claims from a Credential of a particular type.

<{{examples/request/vp_token_type_and_claims.json}}

The following non-normative example shows how the Verifiers can also ask for alternative Verifiable Credentials being presented:

<{{examples/request/vp_token_alternative_credentials.json}}

The Verifiable Credential and Verifiable Presentation formats supported by the Wallet should be published in its metadata using the metadata parameter `vp_formats_supported` (see (#as_metadata_parameters)). 

The formats supported by a Verifier may be set up using the metadata parameter `vp_formats` (see (#client_metadata_parameters)). The Wallet MUST ignore any `format` property inside a `presentation_definition` object if that `format` was not included in the `vp_formats` property of the metadata.

Note: When a Verifier is requesting the presentation of a Verifiable Presentation containing a Verifiable Credential, the Verifier MUST indicate in the `vp_formats` parameter the supported formats of both Verifiable Credential and Verifiable Presentation.

## `presentation_definition_uri` Parameter {#request_presentation_definition_uri}

`presentation_definition_uri` is used to retrieve the Presentation Definition from the resource at the specified URL, rather than being passed by value. The Wallet MUST send an HTTPS GET request without additional parameters. The resource MUST be exposed without further need to authenticate or authorize. 

The protocol for the `presentation_definition_uri` MUST be HTTPS.

The following is a non-normative example of an HTTPS GET request sent after the Wallet received `presentation_definition_uri` parameter with the value `https://server.example.com/presentationdefs?ref=idcard_presentation_request`:

```
  GET /presentationdefs?ref=idcard_presentation_request HTTP/1.1
  Host: server.example.com
```

The following is a non-normative example of an HTTPS GET response sent by the Verifier in response to the above HTTPS GET request:

```
HTTP/1.1 200 OK
...
Content-Type: application/json

{
    "id": "vp token example",
    "input_descriptors": [
        {
            "id": "id card credential",
            "format": {
                "ldp_vc": {
                    "proof_type": [
                        "Ed25519Signature2018"
                    ]
                }
            },
            "constraints": {
                "fields": [
                    {
                        "path": [
                            "$.type"
                        ],
                        "filter": {
                            "type": "string",
                            "pattern": "IDCardCredential"
                        }
                    }
                ]
            }
        }
    ]
}
```

## Using `scope` Parameter to Request Verifiable Credential(s) {#request_scope}

Wallets MAY support requesting presentation of Verifiable Credentials using OAuth 2.0 scope values.

Such a scope value MUST be an alias for a well-defined Presentation Definition that will be 
referred to in the `presentation_submission` response parameter. 

The specific scope values, and the mapping between a certain scope value and the respective 
Presentation Definition is out of scope of this specification. 

Possible options include normative text in a separate specification defining scope values along with a description of their
semantics or machine readable definitions in the Wallet's server metadata, mapping a scope value to an equivalent 
Presentation Definition JSON object. 

Such definition of a scope value MUST allow the Verifier to determine the identifiers of the Presentation Definition and Input Descriptor(s) in the `presentation_submission` response parameter (`definition_id` and `descriptor_map.id` respectively) as well as the Credential formats and types in the `vp_token` response parameter defined in (#response-parameters).  

It is RECOMMENDED to use collision-resistant scopes values.

The following is a non-normative example of an Authorization Request using the scope value `com.example.IDCardCredential_presentation`, 
which is an alias for the first Presentation Definition example given in (#request_presentation_definition):

```
  GET /authorize?
    response_type=vp_token
    &client_id=https%3A%2F%2Fclient.example.org%2Fcb
    &redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb
    &scope=com.example.healthCardCredential_presentation
    &nonce=n-0S6_WzA2Mj HTTP/1.1
```

## Response Type `vp_token` {#response_type_vp_token}

This specification defines the Response Type `vp_token`.

`vp_token`:
:  When supplied as the `response_type` parameter in an Authorization Request, a successful response MUST include the `vp_token` parameter. The Wallet SHOULD NOT return an OAuth 2.0 Authorization Code, Access Token, or Access Token Type in a successful response to the grant request. The default Response Mode for this Response Type is `fragment`, i.e., the Authorization Response parameters are encoded in the fragment added to the `redirect_uri` when redirecting back to the Verifier. The Response Type `vp_token` can be used with other Response Modes as defined in [@!OAuth.Responses]. Both successful and error responses SHOULD be returned using the supplied Response Mode, or if none is supplied, using the default Response Mode.

See (#response) on how the `response_type` value determines the response used to return a VP Token.

## Passing Authorization Request Across Devices

There are use-cases when the Authorization Request is being displayed on a device different from a device on which the requested Credential is stored. In those cases, an Authorization Request can be passed across devices by being rendered as a QR Code. 

The usage of the Response Mode `direct_post` (see (#response_mode_post)) in conjunction with `request_uri` is RECOMMENDED, since Authorization Request size might be large and might not fit in a QR code.

## `aud` of a Request Object

When the Verifier is sending a Request Object as defined in [@!RFC9101], the `aud` Claim value depends on whether the recipient of the request can be identified by the Verifier or not:

- the `aud` Claim MUST equal to the `issuer` Claim value, when Dynamic Discovery is performed.
- the `aud` Claim MUST be "https://self-issued.me/v2", when Static Discovery metadata is used.

Note: "https://self-issued.me/v2" is a symbolic string and can be used as an `aud` Claim value even when this specification is used standalone, without SIOPv2. 

## Verifier Metadata Management {#client_metadata_management}

The `client_id_scheme` enables deployments of this specification to use different mechanisms to obtain and validate metadata of the Verifier beyond the scope of [@!RFC6749]. The term `client_id_scheme` is used since the Verifier is acting as an OAuth 2.0 Client.

This specification defines the following values for the `client_id_scheme` parameter, followed by the examples where applicable: 

* `pre-registered`: This value represents the [@!RFC6749] default behavior, i.e., the Client Identifier needs to be known to the Wallet in advance of the Authorization Request. The Verifier metadata is obtained using [@!RFC7591] or through out-of-band mechanisms.

* `redirect_uri`: This value indicates that the Verifier's redirect URI is also the value of the Client Identifier. In this case, the Authorization Request MUST NOT be signed, the Verifier MAY omit the `redirect_uri` Authorization Request parameter, and all Verifier metadata parameters MUST be passed using the `client_metadata` or `client_metadata_uri` parameter defined in (#vp_token_request). 

The following is a non-normative example of a request when `client_id` equals `redirect_uri`.

```
  HTTP/1.1 302 Found
  Location: https://client.example.org/universal-link?
    response_type=vp_token
    &client_id=https%3A%2F%2Fclient.example.org%2Fcb
    &client_id_scheme=redirect_uri
    &redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb
    &presentation_definition=...
    &nonce=n-0S6_WzA2Mj
    &client_metadata=%7B%22vp_formats%22:%7B%22jwt_vp%22:%
    7B%22alg%22:%5B%22EdDSA%22,%22ES256K%22%5D%7D,%22ldp
    _vp%22:%7B%22proof_type%22:%5B%22Ed25519Signature201
    8%22%5D%7D%7D%7D
```

* `entity_id`: This value indicates that the Client Identifier is an Entity Identifier defined in OpenID Federation [@!OpenID.Federation]. Processing rules given in [@!OpenID.Federation] MUST be followed. Automatic Registration as defined in [@!OpenID.Federation] MUST be used. The Authorization Request MAY also contain a `trust_chain` parameter. The final Verifier metadata is obtained from the Trust Chain after applying the policies, according to [@!OpenID.Federation]. The `client_metadata` or `client_metadata_uri` parameter, if present in the Authorization Request, MUST be ignored when this Client Identifier scheme is used.

* `did`: This value indicates that the Client Identifier is a DID defined in [@!DID-Core]. The request MUST be signed with a private key associated with the DID. A public key to verify the signature MUST be obtained from the `verificationMethod` property of a DID Document. Since DID Document may include multiple public keys, a particular public key used to sign the request in question MUST be identified by the `kid` in the JOSE Header. To obtain the DID Document, the Wallet MUST use DID Resolution defined by the DID method used by the Verifier. All Verifier metadata other than the public key MUST be obtained from the `client_metadata` or the `client_metadata_uri` parameter as defined in (#vp_token_request). 

The following is a non-normative example of a header and a body of a signed Request Object when Client Identifier scheme is a `did`:

Header

<{{examples/request/request_header_client_id_did.json}}

Body

<{{examples/request/request_object_client_id_did.json}}

* `verifier_attestation`: This Client Identifier Scheme allows the Verifier to authenticate using a JWT that is bound to a certain public key as defined in (#verifier_attestation_jwt). When the Client Identifier Scheme is `verifier_attestation`, the Client Identifier MUST equal the `sub` claim value in the Verifier attestation JWT. The request MUST be signed with the private key corresponding to the public key in the `cnf` claim in the Verifier attestation JWT. This serves as proof of possesion of this key. The Verifier attestation JWT MUST be added to the `jwt` JOSE Header of the request object (see (#verifier_attestation_jwt)). The Wallet MUST validate the signature on the Verifier attestation JWT. The `iss` claim value of the Verifier Attestation JWT MUST identify a party the Wallet trusts for issuing Verifier Attestation JWTs. If the Wallet cannot establish trust, it MUST refuse the request. If the issuer of the Verifier Attestation JWT adds a `redirect_uris` claim to the attestation, the Wallet MUST ensure the `redirect_uri` request parameter value exactly matches one of the `redirect_uris` claim entries. All Verifier metadata other than the public key MUST be obtained from the `client_metadata` or or the `client_metadata_uri` parameter.

* `x509_san_dns`: When the Client Identifier Scheme is `x509_san_dns`, the Client Identifier MUST be a DNS name and match a `dNSName` Subject Alternative Name (SAN) [@!RFC5280] entry in the leaf certificate passed with the request. The request MUST be signed with the private key corresponding to the public key in the leaf X.509 certificate of the certificate chain added to the request in the `x5c` JOSE header [@!RFC7515] of the signed request object. The Wallet MUST validate the signature and the trust chain of the X.509 certificate. All Verifier metadata other than the public key MUST be obtained from the `client_metadata` parameter. If the Wallet can establish trust in the Client Identifier authenticated through the certificate, e.g. because the Client Identifier is contained in a list of trusted Client Identifiers, it may allow the client to freely choose the `redirect_uri` value. If not, the FQDN of the `redirect_uri` value MUST match the Client Identifier.

* `x509_san_uri`: When the Client Identifier Scheme is `x509_san_uri`, the Client Identifier MUST be a URI and match a `uniformResourceIdentifier` Subject Alternative Name (SAN) [@!RFC5280] entry in the leaf certificate passed with the request. The request MUST be signed with the private key corresponding to the public key in the leaf X.509 certificate of the certificate chain added to the request in the `x5c` JOSE header [@!RFC7515] of the signed request object. The Wallet MUST validate the signature and the trust chain of the X.509 certificate. All Verifier metadata other than the public key MUST be obtained from the `client_metadata` parameter. If the Wallet can establish trust in the Client Identifier authenticated through the certificate, e.g. because the Client Identifier is contained in a list of trusted Client Identifiers, it may allow the client to freely choose the `redirect_uri` value. If not, the `redirect_uri` value MUST match the Client Identifier.

To use `client_id_scheme` values `entity_id`, `did`, `verifier_attestation`, `x509_san_dns`, and `x509_san_uri`, Verifiers MUST be confidential clients. This might require changes to the technical design of native apps as such apps are typically public clients.

Other specifications can define further values for the `client_id_scheme` parameter. It is RECOMMENDED to use collision-resistant names for such values.

