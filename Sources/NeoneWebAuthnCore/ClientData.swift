import Foundation

/// The decoded JSON contents of a WebAuthn `clientDataJSON` field.
///
/// Spec: https://www.w3.org/TR/webauthn-2/#dictionary-client-data
public struct ClientData: Codable, Sendable {
    public let type: String
    public let challenge: String
    public let origin: String
    public let crossOrigin: Bool?

    public init(type: String, challenge: String, origin: String, crossOrigin: Bool? = nil) {
        self.type = type
        self.challenge = challenge
        self.origin = origin
        self.crossOrigin = crossOrigin
    }
}
