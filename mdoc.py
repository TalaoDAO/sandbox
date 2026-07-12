"""Minimal ISO/IEC 18013-5 IssuerSigned builder for OIDC4VCI mso_mdoc.

Dependency: cbor2>=5.6
Supported issuer/device keys: EC P-256 JWK, COSE algorithm ES256 (-7).
The returned string is base64url(CBOR(IssuerSigned)), without padding.
"""
from __future__ import annotations

import base64
import hashlib
import logging
import json
import os
from jwcrypto import jwk, jwt

import uuid
import x509_attestation
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Mapping, Optional
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)
from cryptography.exceptions import InvalidSignature
import cbor2
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

COSE_ALG = 1
COSE_KID = 4
COSE_X5CHAIN = 33
COSE_ES256 = -7
COSE_KTY_EC2 = 2
COSE_CRV_P256 = 1
COSE_KEY_KTY = 1
COSE_KEY_CRV = -1
COSE_KEY_X = -2
COSE_KEY_Y = -3

P256_ORDER = int(
    "FFFFFFFF00000000FFFFFFFFFFFFFFFF"
    "BCE6FAADA7179E84F3B9CAC2FC632551",
    16
)


def _b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * ((4 - len(value) % 4) % 4))


def _b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _load_jwk(value: Any) -> Dict[str, Any]:
    return json.loads(value) if isinstance(value, str) else dict(value)


def _require_p256(jwk: Mapping[str, Any], role: str) -> None:
    if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
        raise ValueError(f"{role} key must be an EC P-256 JWK for ES256")
    if not jwk.get("x") or not jwk.get("y"):
        raise ValueError(f"{role} JWK is missing x/y")


def thumbprint(key):
    if isinstance(key, str):
        key = json.loads(key)
    signer_key = jwk.JWK(**key)
    return signer_key.thumbprint()


def jwk_to_cose_key(public_jwk: Any) -> Dict[int, Any]:
    jwk = _load_jwk(public_jwk)
    _require_p256(jwk, "device")
    return {
        COSE_KEY_KTY: COSE_KTY_EC2,
        COSE_KEY_CRV: COSE_CRV_P256,
        COSE_KEY_X: _b64url_decode(jwk["x"]),
        COSE_KEY_Y: _b64url_decode(jwk["y"]),
    }


def _private_key_from_jwk(private_jwk: Any) -> ec.EllipticCurvePrivateKey:
    jwk = _load_jwk(private_jwk)
    _require_p256(jwk, "issuer")
    if not jwk.get("d"):
        raise ValueError("issuer JWK is missing private parameter d")
    return ec.derive_private_key(int.from_bytes(_b64url_decode(jwk["d"]), "big"), ec.SECP256R1())


def _tagged_datetime(value: datetime) -> cbor2.CBORTag:
    value = value.astimezone(timezone.utc).replace(microsecond=0)
    return cbor2.CBORTag(0, value.isoformat().replace("+00:00", "Z"))


def normalize_mdoc_payload(
    credential: Mapping[str, Any]
) -> tuple[str, Dict[str, Dict[str, Any]]]:

    if not isinstance(credential, Mapping):
        raise ValueError(
            "mdoc credential must be a JSON object"
        )

    doc_type = credential.get("docType")

    if not isinstance(doc_type, str) or not doc_type:
        raise ValueError(
            "mdoc credential is missing docType"
        )

    namespaces = credential.get("nameSpaces")

    if not isinstance(namespaces, Mapping) or not namespaces:
        raise ValueError(
            "mdoc credential is missing nameSpaces"
        )

    normalized_namespaces = {}

    for namespace, elements in namespaces.items():
        if not isinstance(namespace, str) or not namespace:
            raise ValueError(
                "mdoc namespace must be a non-empty string"
            )

        if not isinstance(elements, Mapping):
            raise ValueError(
                f"namespace {namespace} must contain an object"
            )

        normalized_namespaces[namespace] = dict(elements)

    return doc_type, normalized_namespaces



def _issuer_signed_items(namespaces: Mapping[str, Mapping[str, Any]]) -> tuple[Dict[str, List[Any]], Dict[str, Dict[int, bytes]]]:
    issuer_namespaces: Dict[str, List[Any]] = {}
    value_digests: Dict[str, Dict[int, bytes]] = {}
    digest_id = 0
    for namespace, elements in namespaces.items():
        issuer_namespaces[namespace] = []
        value_digests[namespace] = {}
        for element_identifier, element_value in elements.items():
            item = {
                "digestID": digest_id,
                "random": os.urandom(32),
                "elementIdentifier": element_identifier,
                "elementValue": element_value,
            }
            item_bytes = cbor2.dumps(item, canonical=True)
            tagged_item = cbor2.CBORTag(24, item_bytes)
            issuer_namespaces[namespace].append(tagged_item)
            # Digest is over the encoded IssuerSignedItemBytes, including tag 24.
            value_digests[namespace][digest_id] = hashlib.sha256(
                cbor2.dumps(tagged_item, canonical=True)
            ).digest()
            digest_id += 1
    return issuer_namespaces, value_digests


def _decode_x5chain(x5chain: Optional[Iterable[str]]) -> List[bytes]:
    result: List[bytes] = []
    for cert in x5chain or []:
        try:
            result.append(base64.b64decode(cert, validate=True))
        except Exception:
            # Also accept PEM strings for convenient configuration.
            result.append(x509.load_pem_x509_certificate(cert.encode()).public_bytes(
                encoding=__import__("cryptography.hazmat.primitives.serialization", fromlist=["Encoding"]).Encoding.DER
            ))
    return result


def _check_leaf_matches_key(
    leaf_der: bytes,
    signer: ec.EllipticCurvePrivateKey
) -> None:

    cert = x509.load_der_x509_certificate(
        leaf_der
    )

    cert_numbers = cert.public_key().public_numbers()
    key_numbers = signer.public_key().public_numbers()

    logging.info(
        "Certificate public key x=%s y=%s",
        format(cert_numbers.x, "064x"),
        format(cert_numbers.y, "064x")
    )

    logging.info(
        "Signer public key x=%s y=%s",
        format(key_numbers.x, "064x"),
        format(key_numbers.y, "064x")
    )

    if cert_numbers != key_numbers:
        raise ValueError(
            "mdoc document signer certificate "
            "does not match issuer JWK"
        )

def _cose_sign1(
    payload: bytes,
    private_jwk: Any,
    x5chain: Optional[Iterable[str]],
    kid: Optional[str]
) -> cbor2.CBORTag:

    signer = _private_key_from_jwk(private_jwk)

    protected_headers = {
        COSE_ALG: COSE_ES256
    }

    if kid:
        protected_headers[COSE_KID] = kid.encode("utf-8")

    protected = cbor2.dumps(
        protected_headers,
        canonical=True
    )

    unprotected: Dict[int, Any] = {}

    chain = _decode_x5chain(x5chain)

    if chain:
        _check_leaf_matches_key(
            chain[0],
            signer
        )

        # Only embed the Document Signer certificate.
        unprotected[COSE_X5CHAIN] = chain[0]

    sig_structure = [
        "Signature1",
        protected,
        b"",
        payload
    ]

    to_sign = cbor2.dumps(
        sig_structure,
        canonical=True
    )

    der_signature = signer.sign(
        to_sign,
        ec.ECDSA(hashes.SHA256())
    )

    r, s = decode_dss_signature(
        der_signature
    )

    signature = (
        r.to_bytes(32, "big")
        + s.to_bytes(32, "big")
    )

    return cbor2.CBORTag(
        18,
        [
            protected,
            unprotected,
            payload,
            signature
        ]
    )


def _verify_cose_sign1(
    cose_sign1: cbor2.CBORTag
) -> None:
    """
    Verify the generated COSE_Sign1 with the leaf certificate
    embedded in x5chain.
    """

    if not isinstance(cose_sign1, cbor2.CBORTag):
        raise ValueError(
            "issuerAuth is not a tagged COSE_Sign1"
        )

    if cose_sign1.tag != 18:
        raise ValueError(
            f"unexpected COSE tag: {cose_sign1.tag}"
        )

    protected, unprotected, payload, signature = (
        cose_sign1.value
    )

    chain = unprotected.get(COSE_X5CHAIN)

    if not chain:
        raise ValueError(
            "COSE_Sign1 does not contain x5chain"
        )

    if isinstance(chain, bytes):
        leaf_der = chain
    else:
        leaf_der = chain[0]

    certificate = x509.load_der_x509_certificate(
        leaf_der
    )

    public_key = certificate.public_key()

    if not isinstance(
        public_key,
        ec.EllipticCurvePublicKey
    ):
        raise ValueError(
            "Document Signer certificate is not EC"
        )

    if len(signature) != 64:
        raise ValueError(
            f"invalid ES256 signature length: "
            f"{len(signature)}"
        )

    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")

    der_signature = encode_dss_signature(r, s)

    sig_structure = [
        "Signature1",
        protected,
        b"",
        payload,
    ]

    to_verify = cbor2.dumps(
        sig_structure,
        canonical=True
    )

    try:
        public_key.verify(
            der_signature,
            to_verify,
            ec.ECDSA(hashes.SHA256())
        )
    except InvalidSignature as exc:
        raise ValueError(
            "Generated mdoc COSE signature is invalid"
        ) from exc

def sign_mdoc(
    credential: Mapping[str, Any],
    issuer_private_jwk: Any,
    device_public_jwk: Any,
    *,
    validity_days: int = 365,
    x5chain: Optional[Iterable[str]] = None,
    kid: Optional[str] = None,
    require_x5chain: bool = False
) -> str:
    """
    Create base64url(CBOR(IssuerSigned))
    for an OIDC4VCI mso_mdoc credential response.
    """

    # The mdoc must be signed with the private key corresponding
    # to the Document Signer certificate.
    
    mdoc_signer_key = x509_attestation.SIGNER_KEY

    # Use the kid already present in the signer JWK.
    # Otherwise compute the RFC 7638 JWK thumbprint.
    if kid is None:
        signer_jwk = _load_jwk(mdoc_signer_key)

        kid = (
            signer_jwk.get("kid")
            or thumbprint(signer_jwk)
        )

    logging.info(
        "mdoc COSE signer kid = %s",
        kid
    )

    if x5chain is None:
        x5chain = x509_attestation.build_x509_san_dns()

    if not x5chain:
        raise ValueError(
            "x509_attestation.build_x509_san_dns() "
            "did not return a certificate chain"
        )

    now = datetime.now(timezone.utc).replace(microsecond=0)

    doc_type, namespaces = normalize_mdoc_payload(credential)
    issuer_namespaces, value_digests = _issuer_signed_items(
        namespaces
    )

    mso = {
        "version": "1.0",
        "digestAlgorithm": "SHA-256",
        "valueDigests": value_digests,
        "deviceKeyInfo": {
            "deviceKey": jwk_to_cose_key(
                device_public_jwk
            )
        },
        "docType": doc_type,
        "validityInfo": {
            "signed": _tagged_datetime(now),
            "validFrom": _tagged_datetime(now),
            "validUntil": _tagged_datetime(
                now + timedelta(days=validity_days)
            ),
        },
    }

    mso_bytes = cbor2.dumps(
        mso,
        canonical=True
    )

    mobile_security_object_bytes = cbor2.dumps(
        cbor2.CBORTag(24, mso_bytes),
        canonical=True
    )
    

    issuer_auth = _cose_sign1(
        mobile_security_object_bytes,
        mdoc_signer_key,
        x5chain,
        kid
    )
    
    _verify_cose_sign1(issuer_auth)

    issuer_signed = {
        "nameSpaces": issuer_namespaces,
        "issuerAuth": issuer_auth
    }

    issuer_signed_cbor = cbor2.dumps(
        issuer_signed,
        canonical=True
    )

    return _b64url_encode(issuer_signed_cbor)
