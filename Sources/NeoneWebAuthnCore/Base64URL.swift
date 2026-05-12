import Foundation
import Crypto

extension Data {
    /// Encodes the data as Base64URL (RFC 4648 §5): standard base64 with `-`/`_`
    /// substituted for `+`/`/` and trailing `=` padding stripped.
    public func base64URLEncodedString() -> String {
        return base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    /// Decodes a Base64URL-encoded string back into `Data`. Padding is re-added
    /// before delegating to the standard base64 decoder.
    public init?(base64URLEncoded string: String) {
        var base64 = string
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")

        let paddingLength = (4 - base64.count % 4) % 4
        base64 += String(repeating: "=", count: paddingLength)

        self.init(base64Encoded: base64)
    }
}

/// Generates a cryptographically secure random Base64URL-encoded challenge.
///
/// Length defaults to 32 bytes (256 bits), which is the WebAuthn spec's
/// recommended minimum. Returns a Base64URL string suitable for use as the
/// `challenge` field in `PublicKeyCredentialCreationOptions` /
/// `PublicKeyCredentialRequestOptions`.
public func generateWebAuthnChallenge(byteCount: Int = 32) -> String {
    let key = SymmetricKey(size: .init(bitCount: byteCount * 8))
    let bytes = key.withUnsafeBytes { Array($0) }
    return Data(bytes).base64URLEncodedString()
}
