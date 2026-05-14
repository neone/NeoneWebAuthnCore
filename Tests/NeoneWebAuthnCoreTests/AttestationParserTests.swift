import Foundation
import Crypto
import Testing
@testable import NeoneWebAuthnCore

@Suite("Attestation object + authenticator data parsing")
struct AttestationParserTests {

    // MARK: - extractSignCount

    @Test("Sign count is read as big-endian uint32 at bytes 33-36")
    func extractSignCount() {
        var data = Data(repeating: 0, count: 37)
        // Set bytes 33-36 to 0x00000539 = 1337
        data[33] = 0x00
        data[34] = 0x00
        data[35] = 0x05
        data[36] = 0x39
        #expect(WebAuthn.extractSignCount(from: data) == 1337)
    }

    @Test("Sign count returns 0 for too-short data rather than throwing")
    func extractSignCountTooShort() {
        // Deliberately graceful: short auth data shouldn't crash; the
        // higher-level verify path handles the failure.
        #expect(WebAuthn.extractSignCount(from: Data(count: 10)) == 0)
    }

    // MARK: - parseAuthenticatorData

    @Test("Parses a synthetic authenticator data buffer with ES256 COSE key")
    func parseAuthenticatorDataES256() throws {
        let key = P256.Signing.PrivateKey()
        let authData = TestVectors.authenticatorData(
            forES256Key: key.publicKey,
            credentialID: Data("credential-id".utf8),
            signCount: 0,
            aaguidSuffix: 0x42
        )

        let credentialData = try WebAuthn.parseAuthenticatorData(
            authData,
            requireAttestedCredential: true
        )

        #expect(credentialData.algorithm == COSEAlgorithm.es256)

        // The stored public key is base64 of the uncompressed EC point.
        // Decoding it back should equal the original x9.63 representation.
        let stored = try #require(Data(base64Encoded: credentialData.publicKey))
        #expect(stored == key.publicKey.x963Representation)

        // AAGUID is rendered as canonical 8-4-4-4-12 hex.
        let aaguid = try #require(credentialData.aaguid)
        #expect(aaguid.count == 36)
        #expect(aaguid.filter { $0 == "-" }.count == 4)
    }

    @Test("Rejects auth data with AT flag clear when attested credential is required")
    func rejectsMissingAttestedCredential() throws {
        var authData = Data(repeating: 0, count: 37)
        authData[32] = 0x00 // flags: AT bit (0x40) NOT set

        #expect(throws: WebAuthnError.invalidAttestationObject) {
            _ = try WebAuthn.parseAuthenticatorData(authData, requireAttestedCredential: true)
        }
    }

    @Test("Rejects auth data shorter than the fixed header (37 bytes)")
    func rejectsTruncatedHeader() throws {
        #expect(throws: WebAuthnError.invalidAuthenticatorData) {
            _ = try WebAuthn.parseAuthenticatorData(Data(count: 10), requireAttestedCredential: true)
        }
    }

    // MARK: - parseAttestationObject

    @Test("Parses a synthetic attestation object end-to-end")
    func parseAttestationObjectFullRoundtrip() throws {
        let key = P256.Signing.PrivateKey()
        let authData = TestVectors.authenticatorData(
            forES256Key: key.publicKey,
            credentialID: Data("abc".utf8),
            signCount: 7,
            aaguidSuffix: 0xAA
        )

        // attestationObject = CBOR({fmt: "none", attStmt: {}, authData: <bytes>})
        let attestationObject = TestVectors.attestationObject(authData: authData)

        let credentialData = try WebAuthn.parseAttestationObject(attestationObject)
        #expect(credentialData.algorithm == COSEAlgorithm.es256)
        let stored = try #require(Data(base64Encoded: credentialData.publicKey))
        #expect(stored == key.publicKey.x963Representation)
    }

    @Test("Rejects attestation object missing the authData field")
    func rejectsMissingAuthData() throws {
        // Map of one entry: {"fmt": "none"} — no authData key.
        // 0xa1 63 666d74 64 6e6f6e65
        let bytes: [UInt8] = [
            0xa1,
            0x63, 0x66, 0x6d, 0x74, // "fmt"
            0x64, 0x6e, 0x6f, 0x6e, 0x65, // "none"
        ]
        #expect(throws: WebAuthnError.invalidAttestationObject) {
            _ = try WebAuthn.parseAttestationObject(Data(bytes))
        }
    }

    @Test("Rejects RS256-like key with insufficient material in authData")
    func rejectsMalformedRS256Key() throws {
        // Construct a COSE map declaring alg = -257 (RS256) but with empty
        // modulus & exponent — parser should refuse.
        var cose = Data()
        cose.append(0xa3) // map of 3
        cose.append(0x03); cose.append(0x39); cose.append(0x01); cose.append(0x00) // alg: -257 (= -1 - 256, 2-byte additionalInfo)
        cose.append(0x20); cose.append(0x40) // -1 (n): byte string len 0
        cose.append(0x21); cose.append(0x40) // -2 (e): byte string len 0

        var authData = Data(repeating: 0, count: 32) // rpIdHash
        authData.append(0x40) // flags: AT set
        authData.append(contentsOf: [0, 0, 0, 0]) // signCount
        authData.append(Data(repeating: 0x11, count: 16)) // aaguid
        authData.append(contentsOf: [0, 1]) // credIdLen=1
        authData.append(0xCC) // credId
        authData.append(cose)

        #expect(throws: WebAuthnError.invalidAttestationObject) {
            _ = try WebAuthn.parseAuthenticatorData(authData, requireAttestedCredential: true)
        }
    }
}

// MARK: - Test vector builders

private enum TestVectors {

    /// Build a synthetic authenticator data buffer carrying an ES256 COSE key.
    static func authenticatorData(
        forES256Key publicKey: P256.Signing.PublicKey,
        credentialID: Data,
        signCount: UInt32,
        aaguidSuffix: UInt8
    ) -> Data {
        var data = Data()

        // rpIdHash (32 bytes — value irrelevant for these tests, but must be 32)
        data.append(Data(repeating: 0xAB, count: 32))

        // flags: AT (0x40) + UP (0x01)
        data.append(0x41)

        // signCount big-endian
        data.append(UInt8((signCount >> 24) & 0xff))
        data.append(UInt8((signCount >> 16) & 0xff))
        data.append(UInt8((signCount >> 8) & 0xff))
        data.append(UInt8(signCount & 0xff))

        // AAGUID (16 bytes — last byte is the caller-supplied marker so tests
        // can assert it survives the round-trip)
        var aaguid = Data(repeating: 0xCD, count: 15)
        aaguid.append(aaguidSuffix)
        data.append(aaguid)

        // credentialIdLength + credentialId
        let credIdLen = UInt16(credentialID.count)
        data.append(UInt8((credIdLen >> 8) & 0xff))
        data.append(UInt8(credIdLen & 0xff))
        data.append(credentialID)

        // COSE key
        data.append(es256CoseKey(publicKey: publicKey))
        return data
    }

    /// Build an `attestationObject` CBOR map: `{fmt: "none", attStmt: {}, authData: <bytes>}`.
    static func attestationObject(authData: Data) -> Data {
        var data = Data()

        data.append(0xa3) // map of 3

        // "fmt": "none"
        data.append(textString("fmt"))
        data.append(textString("none"))

        // "attStmt": {} (empty map)
        data.append(textString("attStmt"))
        data.append(0xa0)

        // "authData": <byte string of authData>
        data.append(textString("authData"))
        data.append(byteString(authData))

        return data
    }

    // MARK: COSE key encoding

    private static func es256CoseKey(publicKey: P256.Signing.PublicKey) -> Data {
        let x963 = publicKey.x963Representation
        // x963: 0x04 || x (32) || y (32). Strip the 0x04 prefix.
        let x = x963.subdata(in: 1..<33)
        let y = x963.subdata(in: 33..<65)

        var cose = Data()
        cose.append(0xa5) // map of 5

        // kty (1) = 2 (EC2)
        cose.append(0x01)
        cose.append(0x02)

        // alg (3) = -7 (ES256)
        cose.append(0x03)
        cose.append(0x26) // negative int with additionalInfo 6 → -7

        // crv (-1) = 1 (P-256)
        cose.append(0x20) // negative int -1
        cose.append(0x01)

        // x (-2)
        cose.append(0x21) // negative int -2
        cose.append(byteString(x))

        // y (-3)
        cose.append(0x22) // negative int -3
        cose.append(byteString(y))

        return cose
    }

    // MARK: CBOR primitive encoders

    private static func textString(_ s: String) -> Data {
        let utf8 = Data(s.utf8)
        var out = Data()
        let length = utf8.count
        if length <= 23 {
            out.append(UInt8(0x60 | length))
        } else if length <= 0xff {
            out.append(0x78)
            out.append(UInt8(length))
        } else {
            out.append(0x79)
            out.append(UInt8((length >> 8) & 0xff))
            out.append(UInt8(length & 0xff))
        }
        out.append(utf8)
        return out
    }

    private static func byteString(_ bytes: Data) -> Data {
        var out = Data()
        let length = bytes.count
        if length <= 23 {
            out.append(UInt8(0x40 | length))
        } else if length <= 0xff {
            out.append(0x58)
            out.append(UInt8(length))
        } else if length <= 0xffff {
            out.append(0x59)
            out.append(UInt8((length >> 8) & 0xff))
            out.append(UInt8(length & 0xff))
        } else {
            // Shouldn't happen in tests
            fatalError("byteString length too large for test encoder")
        }
        out.append(bytes)
        return out
    }
}
