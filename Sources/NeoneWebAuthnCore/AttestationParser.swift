import Foundation
import Crypto

/// Namespace for WebAuthn core parsing and verification operations.
public enum WebAuthn {

    // MARK: - Attestation Object Parsing

    /// Parse a CBOR-encoded WebAuthn attestation object and extract the
    /// credential public key data.
    ///
    /// The attestation object is a CBOR map containing `fmt`, `attStmt`, and
    /// `authData`. This routine ignores the attestation statement (we use
    /// "none" attestation) and parses the embedded authenticator data to
    /// extract the credential ID and COSE public key.
    public static func parseAttestationObject(_ data: Data) throws -> CredentialData {
        var decoder = WebAuthnCBORDecoder(data: data)
        let cbor: CBORValue
        do {
            cbor = try decoder.decode()
        } catch {
            throw WebAuthnError.invalidAttestationObject
        }

        guard let authData = cbor[text: "authData"]?.byteStringValue else {
            throw WebAuthnError.invalidAttestationObject
        }

        return try parseAuthenticatorData(authData, requireAttestedCredential: true)
    }

    /// Parse WebAuthn authenticator data to extract credential information.
    ///
    /// Authenticator data layout (§6.1 of WebAuthn spec):
    /// - bytes 0-31:  rpIdHash (SHA-256 hash of RP ID)
    /// - byte 32:     flags (UP, UV, AT, ED, etc.)
    /// - bytes 33-36: signCount (big-endian uint32)
    /// - if AT flag set: attested credential data
    ///   - bytes 37-52:             AAGUID (16 bytes)
    ///   - bytes 53-54:             credentialIdLength (big-endian uint16)
    ///   - bytes 55..<55+L:         credentialId
    ///   - bytes 55+L...:           COSE public key (CBOR-encoded)
    public static func parseAuthenticatorData(
        _ authData: Data,
        requireAttestedCredential: Bool
    ) throws -> CredentialData {
        guard authData.count >= 37 else {
            throw WebAuthnError.invalidAuthenticatorData
        }

        let flags = authData[authData.startIndex + 32]
        let attestedCredentialDataPresent = (flags & 0x40) != 0

        guard !requireAttestedCredential || attestedCredentialDataPresent else {
            throw WebAuthnError.invalidAttestationObject
        }

        guard attestedCredentialDataPresent else {
            throw WebAuthnError.invalidAttestationObject
        }

        guard authData.count >= 55 else {
            throw WebAuthnError.invalidAttestationObject
        }

        // AAGUID: 16 bytes at offset 37
        let base = authData.startIndex
        let aaguidBytes = authData[(base + 37)..<(base + 53)]
        let aaguidHex = aaguidBytes.map { String(format: "%02x", $0) }.joined()
        let h = aaguidHex
        let part1 = String(h[h.startIndex..<h.index(h.startIndex, offsetBy: 8)])
        let part2 = String(h[h.index(h.startIndex, offsetBy: 8)..<h.index(h.startIndex, offsetBy: 12)])
        let part3 = String(h[h.index(h.startIndex, offsetBy: 12)..<h.index(h.startIndex, offsetBy: 16)])
        let part4 = String(h[h.index(h.startIndex, offsetBy: 16)..<h.index(h.startIndex, offsetBy: 20)])
        let part5 = String(h[h.index(h.startIndex, offsetBy: 20)...])
        let formattedAAGUID = "\(part1)-\(part2)-\(part3)-\(part4)-\(part5)"

        // Credential ID length: 2 bytes big-endian at offset 53
        let credIdLength = Int(authData[base + 53]) << 8 | Int(authData[base + 54])
        guard authData.count >= 55 + credIdLength + 1 else {
            throw WebAuthnError.invalidAttestationObject
        }

        // COSE public key starts after the credential ID
        let coseKeyData = Data(authData[(base + 55 + credIdLength)...])

        var coseDecoder = WebAuthnCBORDecoder(data: coseKeyData)
        let coseKey: CBORValue
        do {
            coseKey = try coseDecoder.decode()
        } catch {
            throw WebAuthnError.invalidAttestationObject
        }

        // COSE key integer labels:
        //  1: kty (key type) — 2 = EC2, 3 = RSA
        //  3: alg (algorithm) — -7 = ES256, -257 = RS256
        // -1: crv (curve for EC) / n (modulus for RSA) — P-256 = 1
        // -2: x (EC) / e (RSA)
        // -3: y (EC)
        guard let algValue = coseKey[int: 3]?.intValue else {
            throw WebAuthnError.invalidAttestationObject
        }
        let algorithm = Int(algValue)

        switch algorithm {
        case COSEAlgorithm.es256:
            return try parseES256Key(coseKey, algorithm: algorithm, aaguid: formattedAAGUID)
        case COSEAlgorithm.rs256:
            return try parseRS256Key(coseKey, algorithm: algorithm, aaguid: formattedAAGUID)
        default:
            throw WebAuthnError.unsupportedAlgorithm
        }
    }

    // MARK: - COSE Key Parsers

    /// Extract an ES256 (P-256) public key from a COSE key.
    /// Stored as base64-encoded uncompressed EC point: `0x04 || x (32) || y (32)`.
    private static func parseES256Key(
        _ coseKey: CBORValue,
        algorithm: Int,
        aaguid: String
    ) throws -> CredentialData {
        guard let x = coseKey[int: -2]?.byteStringValue,
              let y = coseKey[int: -3]?.byteStringValue,
              x.count == 32, y.count == 32 else {
            throw WebAuthnError.invalidAttestationObject
        }

        var uncompressedKey = Data([0x04])
        uncompressedKey.append(x)
        uncompressedKey.append(y)

        // Validate that swift-crypto accepts the encoded key.
        do {
            _ = try P256.Signing.PublicKey(x963Representation: uncompressedKey)
        } catch {
            throw WebAuthnError.invalidAttestationObject
        }

        return CredentialData(
            publicKey: uncompressedKey.base64EncodedString(),
            algorithm: algorithm,
            aaguid: aaguid
        )
    }

    /// Extract an RS256 public key from a COSE key.
    /// Stored as `"base64(n).base64(e)"`.
    private static func parseRS256Key(
        _ coseKey: CBORValue,
        algorithm: Int,
        aaguid: String
    ) throws -> CredentialData {
        guard let n = coseKey[int: -1]?.byteStringValue,
              let e = coseKey[int: -2]?.byteStringValue,
              !n.isEmpty, !e.isEmpty else {
            throw WebAuthnError.invalidAttestationObject
        }

        let publicKeyString = n.base64EncodedString() + "." + e.base64EncodedString()

        return CredentialData(
            publicKey: publicKeyString,
            algorithm: algorithm,
            aaguid: aaguid
        )
    }

    // MARK: - Sign Count

    /// Extract the sign count from authenticator data (bytes 33-36, big-endian uint32).
    public static func extractSignCount(from authenticatorData: Data) -> Int {
        guard authenticatorData.count >= 37 else { return 0 }
        let base = authenticatorData.startIndex
        let signCount = Int(authenticatorData[base + 33]) << 24
                      | Int(authenticatorData[base + 34]) << 16
                      | Int(authenticatorData[base + 35]) << 8
                      | Int(authenticatorData[base + 36])
        return signCount
    }
}
