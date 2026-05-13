import Foundation
import Crypto
import _CryptoExtras
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

// MARK: - RS256

@Suite("RS256 sign/verify round-trip")
struct RS256SignatureVerifierTests {

    /// Produce a stored-key string in the format `parseRS256Key` writes:
    /// `"base64(n).base64(e)"`. Uses `getKeyPrimitives()` from swift-crypto
    /// _CryptoExtras to extract the modulus and exponent.
    private func storedKeyString(for publicKey: _RSA.Signing.PublicKey) throws -> String {
        let primitives = try publicKey.getKeyPrimitives()
        return primitives.modulus.base64EncodedString() + "." + primitives.publicExponent.base64EncodedString()
    }

    @Test("Valid PKCS1-v1_5 signature verifies against original message")
    func validSignature() throws {
        let privateKey = try _RSA.Signing.PrivateKey(keySize: .bits2048)
        let message = Data("hello rs256 passkey".utf8)

        // WebAuthn RS256 = RSASSA-PKCS1-v1_5 over the SHA256 digest.
        let digest = SHA256.hash(data: message)
        let signature = try privateKey.signature(for: digest, padding: .insecurePKCS1v1_5)

        let stored = try storedKeyString(for: privateKey.publicKey)
        let valid = try WebAuthn.verifySignature(
            signature.rawRepresentation,
            over: message,
            publicKey: stored,
            algorithm: COSEAlgorithm.rs256
        )
        #expect(valid)
    }

    @Test("Tampered message returns false (doesn't throw)")
    func tamperedMessage() throws {
        let privateKey = try _RSA.Signing.PrivateKey(keySize: .bits2048)
        let stored = try storedKeyString(for: privateKey.publicKey)
        let signature = try privateKey.signature(
            for: SHA256.hash(data: Data("hello".utf8)),
            padding: .insecurePKCS1v1_5
        )

        let valid = try WebAuthn.verifySignature(
            signature.rawRepresentation,
            over: Data("world".utf8),
            publicKey: stored,
            algorithm: COSEAlgorithm.rs256
        )
        #expect(valid == false)
    }

    @Test("Signature from a different key returns false")
    func wrongKey() throws {
        let signingKey = try _RSA.Signing.PrivateKey(keySize: .bits2048)
        let otherKey = try _RSA.Signing.PrivateKey(keySize: .bits2048)
        let message = Data("hello".utf8)

        let signature = try signingKey.signature(
            for: SHA256.hash(data: message),
            padding: .insecurePKCS1v1_5
        )
        let storedOther = try storedKeyString(for: otherKey.publicKey)

        let valid = try WebAuthn.verifySignature(
            signature.rawRepresentation,
            over: message,
            publicKey: storedOther,
            algorithm: COSEAlgorithm.rs256
        )
        #expect(valid == false)
    }

    @Test("Malformed stored key (no dot separator) throws invalidPublicKey")
    func malformedStoredKey_noDot() throws {
        #expect(throws: WebAuthnError.invalidPublicKey) {
            _ = try WebAuthn.verifySignature(
                Data([0xAB]),
                over: Data("x".utf8),
                publicKey: "no-dot-here",
                algorithm: COSEAlgorithm.rs256
            )
        }
    }

    @Test("Malformed stored key (empty modulus) throws invalidPublicKey")
    func malformedStoredKey_emptyModulus() throws {
        #expect(throws: WebAuthnError.invalidPublicKey) {
            _ = try WebAuthn.verifySignature(
                Data([0xAB]),
                over: Data("x".utf8),
                publicKey: ".AQAB", // empty modulus before dot, "AQAB" = exponent 65537
                algorithm: COSEAlgorithm.rs256
            )
        }
    }

    @Test("Malformed stored key (non-base64 bytes) throws invalidPublicKey")
    func malformedStoredKey_nonBase64() throws {
        #expect(throws: WebAuthnError.invalidPublicKey) {
            _ = try WebAuthn.verifySignature(
                Data([0xAB]),
                over: Data("x".utf8),
                publicKey: "!!!.???",
                algorithm: COSEAlgorithm.rs256
            )
        }
    }
}
