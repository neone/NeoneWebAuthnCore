import Foundation
import Crypto

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
    /// - Throws: `WebAuthnError.unsupportedAlgorithm` for algorithms not yet
    ///   implemented (notably RS256); `WebAuthnError.invalidPublicKey` or
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
            // RS256 verification requires RSA primitives not exposed by
            // swift-crypto's public API. Registration extracts and stores the
            // RS256 public key correctly, but authentication rejects RS256
            // assertions until RSA support is added. Tracked: NEO-1191.
            throw WebAuthnError.unsupportedAlgorithm
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
}
