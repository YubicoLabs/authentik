"""Helpers to build WebAuthn responses signed with a software key.

These construct the same CBOR structures a CTAP2 authenticator would return, using python-fido2's
encoders and a key from cryptography. They cover algorithms no fixture can: ML-DSA (FIPS 204),
which no shipping authenticator implements yet, and Ed25519, which authentik cannot verify under
the validated OpenSSL FIPS provider."""

from hashlib import sha256
from json import dumps
from os import urandom

from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDSA,
    SECP256R1,
    EllipticCurvePrivateKey,
    generate_private_key,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA44PrivateKey
from cryptography.hazmat.primitives.hashes import SHA256
from fido2 import cbor
from fido2.cose import ES256, MLDSA44, CoseKey, EdDSA
from fido2.webauthn import AttestationObject, AttestedCredentialData, AuthenticatorData
from webauthn.helpers.bytes_to_base64url import bytes_to_base64url
from webauthn.helpers.cose import COSEAlgorithmIdentifier

from authentik.stages.authenticator_webauthn.models import UNKNOWN_DEVICE_TYPE_AAGUID

_KEY_CLASSES: dict[COSEAlgorithmIdentifier, tuple[type, type[CoseKey]]] = {
    COSEAlgorithmIdentifier.EDDSA: (Ed25519PrivateKey, EdDSA),
    COSEAlgorithmIdentifier.ML_DSA_44: (MLDSA44PrivateKey, MLDSA44),
}


def _client_data(webauthn_type: str, challenge: bytes, origin: str) -> bytes:
    return dumps(
        {
            "type": webauthn_type,
            "challenge": bytes_to_base64url(challenge),
            "origin": origin,
            "crossOrigin": False,
        }
    ).encode("utf-8")


class SoftwareCredential:
    """A software credential that can produce registration and assertion responses"""

    def __init__(
        self,
        rp_id: str,
        origin: str,
        alg: COSEAlgorithmIdentifier = COSEAlgorithmIdentifier.ML_DSA_44,
    ):
        self.rp_id = rp_id
        self.origin = origin
        self.cose_class: type[CoseKey]
        if alg == COSEAlgorithmIdentifier.ECDSA_SHA_256:
            self.cose_class = ES256
            self.private_key = generate_private_key(SECP256R1())
        else:
            private_key_class, self.cose_class = _KEY_CLASSES[alg]
            self.private_key = private_key_class.generate()
        self.credential_id = urandom(32)
        self.sign_count = 0

    @property
    def cose_public_key(self) -> bytes:
        """CBOR-encoded COSE public key, as stored on a WebAuthnDevice"""
        return cbor.encode(self.cose_class.from_cryptography_key(self.private_key.public_key()))

    def registration_response(self, challenge: bytes) -> dict:
        """Build a `navigator.credentials.create()` response with a `none` attestation"""
        credential_data = AttestedCredentialData.create(
            bytes.fromhex(UNKNOWN_DEVICE_TYPE_AAGUID.replace("-", "")),
            self.credential_id,
            self.cose_class.from_cryptography_key(self.private_key.public_key()),
        )
        auth_data = AuthenticatorData.create(
            sha256(self.rp_id.encode("utf-8")).digest(),
            AuthenticatorData.FLAG.UP | AuthenticatorData.FLAG.UV | AuthenticatorData.FLAG.AT,
            self.sign_count,
            credential_data,
        )
        attestation = AttestationObject.create("none", auth_data, {})
        return {
            "id": bytes_to_base64url(self.credential_id),
            "rawId": bytes_to_base64url(self.credential_id),
            "type": "public-key",
            "registrationClientExtensions": "{}",
            "response": {
                "clientDataJSON": bytes_to_base64url(
                    _client_data("webauthn.create", challenge, self.origin)
                ),
                "attestationObject": bytes_to_base64url(bytes(attestation)),
            },
        }

    def assertion_response(self, challenge: bytes) -> dict:
        """Build a `navigator.credentials.get()` response signed with the software key"""
        self.sign_count += 1
        auth_data = AuthenticatorData.create(
            sha256(self.rp_id.encode("utf-8")).digest(),
            AuthenticatorData.FLAG.UP | AuthenticatorData.FLAG.UV,
            self.sign_count,
        )
        client_data = _client_data("webauthn.get", challenge, self.origin)
        signed_data = bytes(auth_data) + sha256(client_data).digest()
        if isinstance(self.private_key, EllipticCurvePrivateKey):
            signature = self.private_key.sign(signed_data, ECDSA(SHA256()))
        else:
            signature = self.private_key.sign(signed_data)
        return {
            "id": bytes_to_base64url(self.credential_id),
            "rawId": bytes_to_base64url(self.credential_id),
            "type": "public-key",
            "assertionClientExtensions": "{}",
            "response": {
                "clientDataJSON": bytes_to_base64url(client_data),
                "authenticatorData": bytes_to_base64url(bytes(auth_data)),
                "signature": bytes_to_base64url(signature),
                "userHandle": None,
            },
        }
