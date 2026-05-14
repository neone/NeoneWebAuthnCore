import Foundation
import Crypto
import Testing
@testable import NeoneWebAuthnCore

@Suite("ES256 sign/verify round-trip")
struct SignatureVerifierTests {

    @Test("Valid signature verifies against original message")
    func validSignature() throws {
        let key = P256.Signing.PrivateKey()
        let publicKey = key.publicKey
        let message = Data("hello passkey".utf8)

        let signature = try key.signature(for: message)
        // Store the public key the same way `parseES256Key` stores it:
        // base64 of the uncompressed x9.63 representation.
        let stored = publicKey.x963Representation.base64EncodedString()

        let valid = try WebAuthn.verifySignature(
            signature.derRepresentation,
            over: message,
            publicKey: stored,
            algorithm: COSEAlgorithm.es256
        )
        #expect(valid)
    }

    @Test("Tampered message fails verification (returns false)")
    func tamperedMessage() throws {
        let key = P256.Signing.PrivateKey()
        let stored = key.publicKey.x963Representation.base64EncodedString()
        let signature = try key.signature(for: Data("hello".utf8))

        // Same signature, different message — should *return false*, not throw.
        let valid = try WebAuthn.verifySignature(
            signature.derRepresentation,
            over: Data("world".utf8),
            publicKey: stored,
            algorithm: COSEAlgorithm.es256
        )
        #expect(valid == false)
    }

    @Test("Signature from a different key fails verification")
    func wrongKey() throws {
        let signingKey = P256.Signing.PrivateKey()
        let otherKey = P256.Signing.PrivateKey()
        let message = Data("hello".utf8)

        let signature = try signingKey.signature(for: message)
        let storedOther = otherKey.publicKey.x963Representation.base64EncodedString()

        let valid = try WebAuthn.verifySignature(
            signature.derRepresentation,
            over: message,
            publicKey: storedOther,
            algorithm: COSEAlgorithm.es256
        )
        #expect(valid == false)
    }

    @Test("Malformed public key throws invalidPublicKey")
    func malformedPublicKey() throws {
        let key = P256.Signing.PrivateKey()
        let message = Data("hi".utf8)
        let signature = try key.signature(for: message)

        #expect(throws: WebAuthnError.invalidPublicKey) {
            _ = try WebAuthn.verifySignature(
                signature.derRepresentation,
                over: message,
                publicKey: "not-base64-data!",
                algorithm: COSEAlgorithm.es256
            )
        }
    }

    @Test("Malformed signature bytes throw invalidSignatureFormat")
    func malformedSignature() throws {
        let key = P256.Signing.PrivateKey()
        let stored = key.publicKey.x963Representation.base64EncodedString()

        #expect(throws: WebAuthnError.invalidSignatureFormat) {
            _ = try WebAuthn.verifySignature(
                Data([0xAB, 0xCD]), // way too short to be a valid DER ECDSA signature
                over: Data("hi".utf8),
                publicKey: stored,
                algorithm: COSEAlgorithm.es256
            )
        }
    }

    @Test("RS256 is not yet implemented — throws unsupportedAlgorithm")
    func rs256Unsupported() throws {
        // Until NEO-1191 lands an RSA verifier, RS256 is a fail-fast stub.
        // This test pins that behavior so we know to remove it when the
        // upgrade lands.
        #expect(throws: WebAuthnError.unsupportedAlgorithm) {
            _ = try WebAuthn.verifySignature(
                Data([0x00]),
                over: Data([0x00]),
                publicKey: "ignored.ignored",
                algorithm: COSEAlgorithm.rs256
            )
        }
    }

    @Test("Unknown algorithm throws unsupportedAlgorithm")
    func unknownAlgorithm() throws {
        #expect(throws: WebAuthnError.unsupportedAlgorithm) {
            _ = try WebAuthn.verifySignature(
                Data([0x00]),
                over: Data([0x00]),
                publicKey: "ignored",
                algorithm: -999
            )
        }
    }
}
