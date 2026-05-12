import Foundation

/// Errors thrown by the WebAuthn core parsing and verification routines.
///
/// Callers are expected to map these to their own transport-level error type
/// (e.g. a Vapor `AbortError`) — this enum intentionally has no HTTP coupling.
public enum WebAuthnError: Error, Sendable {
    /// The bytes did not decode as valid CBOR, or the CBOR structure was not
    /// what WebAuthn expects (missing fields, wrong types, etc.).
    case invalidAttestationObject

    /// The authenticator data buffer was too short or its flag/length fields
    /// did not match the spec.
    case invalidAuthenticatorData

    /// The stored public key did not parse into a usable key for the named
    /// algorithm.
    case invalidPublicKey

    /// The signature bytes did not parse into a valid DER signature.
    case invalidSignatureFormat

    /// The COSE algorithm identifier is not implemented (notably RS256 today).
    case unsupportedAlgorithm

    /// Signature parsed correctly but did not verify against the public key
    /// and signed data.
    case signatureVerificationFailed
}
