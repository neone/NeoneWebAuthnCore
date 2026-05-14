import Foundation
import Crypto
import _CryptoExtras

extension WebAuthn {

    /// Verify a WebAuthn assertion signature.
    ///
    /// - Parameters:
    ///   - signature: The raw signature bytes from the assertion response.
    ///   - signedData: `authenticatorData || SHA256(clientDataJSON)`.
    ///   - publicKey: The stored public key, in the format produced by
    ///     `parseAttestationObject` (algorithm-dependent — see
    ///     `CredentialData`).
    ///   - algorithm: COSE algorithm identifier (e.g.
    ///     `COSEAlgorithm.es256`).
    /// - Returns: `true` if the signature verifies; `false` if it parsed but
    ///   did not match.
    /// - Throws: `WebAuthnError.unsupportedAlgorithm` for algorithms not
    ///   implemented; `WebAuthnError.invalidPublicKey` or
    ///   `.invalidSignatureFormat` if the inputs could not be parsed.
    public static func verifySignature(
        _ signature: Data,
        over signedData: Data,
        publicKey: String,
        algorithm: Int
    ) throws -> Bool {
        switch algorithm {
        case COSEAlgorithm.es256:
            return try verifyES256Signature(signature, over: signedData, publicKey: publicKey)
        case COSEAlgorithm.rs256:
            return try verifyRS256Signature(signature, over: signedData, publicKey: publicKey)
        default:
            throw WebAuthnError.unsupportedAlgorithm
        }
    }

    private static func verifyES256Signature(
        _ signature: Data,
        over signedData: Data,
        publicKey: String
    ) throws -> Bool {
        guard let keyData = Data(base64Encoded: publicKey) else {
            throw WebAuthnError.invalidPublicKey
        }

        let ecPublicKey: P256.Signing.PublicKey
        do {
            ecPublicKey = try P256.Signing.PublicKey(x963Representation: keyData)
        } catch {
            throw WebAuthnError.invalidPublicKey
        }

        // WebAuthn ES256 signatures are DER-encoded (ASN.1).
        let ecdsaSignature: P256.Signing.ECDSASignature
        do {
            ecdsaSignature = try P256.Signing.ECDSASignature(derRepresentation: signature)
        } catch {
            throw WebAuthnError.invalidSignatureFormat
        }

        return ecPublicKey.isValidSignature(ecdsaSignature, for: signedData)
    }

    /// Verify an RS256 (RSASSA-PKCS1-v1_5 with SHA-256) signature.
    ///
    /// The stored public key is `"base64(n).base64(e)"` — the format
    /// `parseRS256Key` writes after extracting the COSE modulus and
    /// exponent. The signature is the raw RSA signature bytes (not DER-
    /// wrapped). Padding is PKCS1-v1_5 per RFC 8017 / WebAuthn §6.5.6.
    ///
    /// Uses swift-crypto's `_CryptoExtras._RSA.Signing.PublicKey(n:e:)` —
    /// the API is underscore-prefixed but ships and works on Linux via
    /// BoringSSL.
    private static func verifyRS256Signature(
        _ signature: Data,
        over signedData: Data,
        publicKey: String
    ) throws -> Bool {
        // Stored as `base64(n).base64(e)`.
        let parts = publicKey.split(separator: ".", maxSplits: 1, omittingEmptySubsequences: false)
        guard parts.count == 2,
              let n = Data(base64Encoded: String(parts[0])),
              let e = Data(base64Encoded: String(parts[1])),
              !n.isEmpty, !e.isEmpty
        else {
            throw WebAuthnError.invalidPublicKey
        }

        let rsaKey: _RSA.Signing.PublicKey
        do {
            rsaKey = try _RSA.Signing.PublicKey(n: n, e: e)
        } catch {
            throw WebAuthnError.invalidPublicKey
        }

        let rsaSignature = _RSA.Signing.RSASignature(rawRepresentation: signature)

        // WebAuthn RS256 = RSASSA-PKCS1-v1_5 + SHA-256.
        return rsaKey.isValidSignature(
            rsaSignature,
            for: SHA256.hash(data: signedData),
            padding: .insecurePKCS1v1_5
        )
    }
}
