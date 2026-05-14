import Foundation
import Testing
@testable import NeoneWebAuthnCore

@Suite("Base64URL round-trip")
struct Base64URLTests {

    @Test("Empty data round-trips to empty string and back")
    func emptyData() {
        let data = Data()
        #expect(data.base64URLEncodedString() == "")
        #expect(Data(base64URLEncoded: "") == Data())
    }

    @Test("Round-trips arbitrary bytes (no padding)")
    func roundTripNoPadding() throws {
        // 3 bytes encode to 4 base64 chars with no padding.
        let data = Data([0xFF, 0xEE, 0xDD])
        let encoded = data.base64URLEncodedString()
        #expect(encoded == "_-7d", "expected '_-7d' for 0xFFEEDD, got \(encoded)")
        let decoded = try #require(Data(base64URLEncoded: encoded))
        #expect(decoded == data)
    }

    @Test("Round-trips bytes with 1-byte padding")
    func roundTripOnePadding() throws {
        // 2 bytes encode to 3 base64 chars, normally padded with one '='
        // Base64URL strips padding; the decoder re-adds it.
        let data = Data([0xFB, 0xEF])
        let encoded = data.base64URLEncodedString()
        #expect(!encoded.contains("="), "padding should be stripped: \(encoded)")
        let decoded = try #require(Data(base64URLEncoded: encoded))
        #expect(decoded == data)
    }

    @Test("Round-trips bytes with 2-byte padding")
    func roundTripTwoPadding() throws {
        // 1 byte encodes to 2 base64 chars normally padded with two '=' chars.
        let data = Data([0xAA])
        let encoded = data.base64URLEncodedString()
        #expect(!encoded.contains("="))
        let decoded = try #require(Data(base64URLEncoded: encoded))
        #expect(decoded == data)
    }

    @Test("Substitutes + and / with - and _")
    func urlSafeAlphabet() throws {
        // Bytes whose standard base64 contains both '+' and '/':
        // 0xFB 0xFF 0xFE → "+//+"
        let data = Data([0xFB, 0xFF, 0xFE])
        let encoded = data.base64URLEncodedString()
        #expect(!encoded.contains("+"))
        #expect(!encoded.contains("/"))
        #expect(encoded.contains("-") || encoded.contains("_"))
        let decoded = try #require(Data(base64URLEncoded: encoded))
        #expect(decoded == data)
    }

    @Test("Rejects bogus input")
    func rejectsBogusInput() {
        // The decoder relies on Foundation's base64 decoder under the hood;
        // garbage with invalid chars should fail to decode.
        #expect(Data(base64URLEncoded: "!!! not base64 !!!") == nil)
    }

    @Test("Challenge generator produces 32 bytes by default")
    func challengeLength() throws {
        let challenge = generateWebAuthnChallenge()
        let decoded = try #require(Data(base64URLEncoded: challenge))
        #expect(decoded.count == 32)
    }

    @Test("Challenge generator honors custom length")
    func customChallengeLength() throws {
        let challenge = generateWebAuthnChallenge(byteCount: 64)
        let decoded = try #require(Data(base64URLEncoded: challenge))
        #expect(decoded.count == 64)
    }

    @Test("Two challenge calls produce different output")
    func challengeUniqueness() {
        let a = generateWebAuthnChallenge()
        let b = generateWebAuthnChallenge()
        #expect(a != b, "32 random bytes colliding would imply broken RNG")
    }
}
