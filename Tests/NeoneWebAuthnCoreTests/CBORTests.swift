import Foundation
import Testing
@testable import NeoneWebAuthnCore

/// Vectors drawn from RFC 7049 Appendix A. The library implements major
/// types 0-5 and 7 — these tests pin that subset.
@Suite("CBOR decoder — RFC 7049 vectors")
struct CBORTests {

    private func decode(_ hex: String) throws -> CBORValue {
        let data = try #require(Data(hex: hex))
        var decoder = WebAuthnCBORDecoder(data: data)
        return try decoder.decode()
    }

    // MARK: - Major type 0: unsigned integer

    @Test("Single-byte unsigned ints")
    func unsignedIntSingleByte() throws {
        #expect(try decode("00").intValue == 0)
        #expect(try decode("01").intValue == 1)
        #expect(try decode("0a").intValue == 10)
        #expect(try decode("17").intValue == 23)
    }

    @Test("1-byte length unsigned ints")
    func unsignedInt1ByteLength() throws {
        #expect(try decode("1818").intValue == 24)
        #expect(try decode("1864").intValue == 100)
    }

    @Test("2-byte length unsigned ints")
    func unsignedInt2ByteLength() throws {
        #expect(try decode("1903e8").intValue == 1_000)
    }

    @Test("4-byte length unsigned ints")
    func unsignedInt4ByteLength() throws {
        #expect(try decode("1a000f4240").intValue == 1_000_000)
    }

    // MARK: - Major type 1: negative integer

    @Test("Negative ints")
    func negativeInts() throws {
        #expect(try decode("20").intValue == -1)
        #expect(try decode("29").intValue == -10)
        #expect(try decode("3863").intValue == -100)
    }

    // MARK: - Major type 2: byte string

    @Test("Byte string")
    func byteString() throws {
        // 0x44 = byte string, length 4
        let value = try decode("4401020304")
        let bytes = try #require(value.byteStringValue)
        #expect(bytes == Data([0x01, 0x02, 0x03, 0x04]))
    }

    @Test("Empty byte string")
    func emptyByteString() throws {
        let value = try decode("40")
        let bytes = try #require(value.byteStringValue)
        #expect(bytes.isEmpty)
    }

    // MARK: - Major type 3: text string

    @Test("Text strings")
    func textStrings() throws {
        #expect(try decode("60").textStringValue == "") // empty
        #expect(try decode("6161").textStringValue == "a")
        #expect(try decode("6449455446").textStringValue == "IETF")
    }

    // MARK: - Major type 4: array

    @Test("Small array")
    func smallArray() throws {
        // 0x83 010203 = [1, 2, 3]
        let value = try decode("83010203")
        if case .array(let items) = value {
            #expect(items.count == 3)
            #expect(items[0].intValue == 1)
            #expect(items[1].intValue == 2)
            #expect(items[2].intValue == 3)
        } else {
            Issue.record("expected .array, got \(value)")
        }
    }

    // MARK: - Major type 5: map

    @Test("Map with text keys (subscript text:)")
    func mapTextKeys() throws {
        // 0xa2 6161 01 6162 02 = {"a": 1, "b": 2}
        let value = try decode("a2616101616202")
        #expect(value[text: "a"]?.intValue == 1)
        #expect(value[text: "b"]?.intValue == 2)
        #expect(value[text: "missing"] == nil)
    }

    @Test("Map with integer keys (subscript int:)")
    func mapIntegerKeys() throws {
        // 0xa2 01 02 03 04 = {1: 2, 3: 4}
        let value = try decode("a201020304")
        #expect(value[int: 1]?.intValue == 2)
        #expect(value[int: 3]?.intValue == 4)
        #expect(value[int: 99] == nil)
    }

    @Test("Map with negative integer keys (COSE labels)")
    func mapNegativeKeys() throws {
        // 0xa1 20 17 = {-1: 23} — what COSE uses for `crv` (-1 = curve)
        let value = try decode("a12017")
        #expect(value[int: -1]?.intValue == 23)
    }

    // MARK: - Major type 7: simple/floats

    @Test("Simple values: false, true, null, undefined")
    func simpleValues() throws {
        if case .bool(let b) = try decode("f4") { #expect(b == false) } else { Issue.record("expected false") }
        if case .bool(let b) = try decode("f5") { #expect(b == true) } else { Issue.record("expected true") }
        if case .null = try decode("f6") { } else { Issue.record("expected null") }
        if case .undefined = try decode("f7") { } else { Issue.record("expected undefined") }
    }

    // MARK: - Error paths

    @Test("Truncated input raises unexpectedEndOfData")
    func truncatedInput() {
        #expect(throws: CBORDecodingError.self) {
            var decoder = WebAuthnCBORDecoder(data: Data([0x18])) // 1-byte uint header w/o body
            _ = try decoder.decode()
        }
    }

    @Test("Unsupported major type (6) raises unsupportedMajorType")
    func unsupportedMajorType() {
        // 0xc0 = major type 6 (tag) which we don't decode
        #expect(throws: CBORDecodingError.self) {
            var decoder = WebAuthnCBORDecoder(data: Data([0xc0]))
            _ = try decoder.decode()
        }
    }
}

// MARK: - Hex helper for fixtures

extension Data {
    /// Init from a hex string (no spaces, even length). Returns nil on bad input.
    init?(hex: String) {
        let chars = Array(hex)
        guard chars.count % 2 == 0 else { return nil }
        var bytes = [UInt8]()
        bytes.reserveCapacity(chars.count / 2)
        for i in stride(from: 0, to: chars.count, by: 2) {
            guard let byte = UInt8(String(chars[i..<i+2]), radix: 16) else { return nil }
            bytes.append(byte)
        }
        self.init(bytes)
    }
}
