import Foundation

/// COSE algorithm identifiers used by WebAuthn. Negative values per RFC 8152.
public enum COSEAlgorithm {
    /// ECDSA with P-256 curve and SHA-256.
    public static let es256: Int = -7
    /// RSASSA-PKCS1-v1_5 with SHA-256.
    public static let rs256: Int = -257
}

/// The credential material extracted from a verified attestation object.
///
/// `publicKey` is the encoded public key as it should be persisted by the
/// relying party — format depends on `algorithm`:
///   - ES256: base64-encoded uncompressed EC point (`0x04 || x || y`, 65 bytes).
///   - RS256: `"base64(n).base64(e)"` (modulus and exponent joined by a `.`).
public struct CredentialData: Sendable {
    public let publicKey: String
    public let algorithm: Int
    public let aaguid: String?

    public init(publicKey: String, algorithm: Int, aaguid: String?) {
        self.publicKey = publicKey
        self.algorithm = algorithm
        self.aaguid = aaguid
    }
}
