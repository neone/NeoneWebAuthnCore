import Foundation

/// Represents a decoded CBOR value (minimal subset for WebAuthn).
public enum CBORValue: Sendable {
    case unsignedInt(UInt64)
    case negativeInt(Int64)
    case byteString(Data)
    case textString(String)
    case array([CBORValue])
    case map([(CBORValue, CBORValue)])
    case bool(Bool)
    case null
    case undefined
    case float(Double)

    // MARK: - Convenience Accessors

    public var mapValue: [(CBORValue, CBORValue)]? {
        if case .map(let pairs) = self { return pairs }
        return nil
    }

    public var byteStringValue: Data? {
        if case .byteString(let data) = self { return data }
        return nil
    }

    public var textStringValue: String? {
        if case .textString(let str) = self { return str }
        return nil
    }

    public var intValue: Int64? {
        switch self {
        case .unsignedInt(let v): return Int64(v)
        case .negativeInt(let v): return v
        default: return nil
        }
    }

    /// Look up a text key in a CBOR map.
    public subscript(text key: String) -> CBORValue? {
        guard let pairs = mapValue else { return nil }
        for (k, v) in pairs {
            if case .textString(let s) = k, s == key {
                return v
            }
        }
        return nil
    }

    /// Look up an integer key in a CBOR map (used for COSE key labels).
    public subscript(int key: Int) -> CBORValue? {
        guard let pairs = mapValue else { return nil }
        let target = Int64(key)
        for (k, v) in pairs {
            if let kInt = k.intValue, kInt == target {
                return v
            }
        }
        return nil
    }
}

// MARK: - CBOR Decoder

/// Minimal CBOR decoder sufficient for WebAuthn attestation object and COSE
/// key parsing. Supports RFC 7049 major types 0-5 and 7 (simple values/floats).
public struct WebAuthnCBORDecoder: Sendable {
    private let data: Data
    private var offset: Int

    public init(data: Data) {
        self.data = data
        self.offset = 0
    }

    /// The number of bytes consumed so far.
    public var bytesRead: Int { offset }

    public mutating func decode() throws -> CBORValue {
        guard offset < data.count else {
            throw CBORDecodingError.unexpectedEndOfData
        }

        let byte = data[data.startIndex + offset]
        offset += 1

        let majorType = byte >> 5
        let additionalInfo = byte & 0x1F

        switch majorType {
        case 0: // Unsigned integer
            let value = try readLength(additionalInfo)
            return .unsignedInt(value)

        case 1: // Negative integer
            let value = try readLength(additionalInfo)
            return .negativeInt(-1 - Int64(value))

        case 2: // Byte string
            let length = try readLength(additionalInfo)
            let bytes = try readBytes(Int(length))
            return .byteString(bytes)

        case 3: // Text string
            let length = try readLength(additionalInfo)
            let bytes = try readBytes(Int(length))
            guard let string = String(data: bytes, encoding: .utf8) else {
                throw CBORDecodingError.invalidUTF8
            }
            return .textString(string)

        case 4: // Array
            let count = try readLength(additionalInfo)
            var items: [CBORValue] = []
            items.reserveCapacity(Int(count))
            for _ in 0..<Int(count) {
                items.append(try decode())
            }
            return .array(items)

        case 5: // Map
            let count = try readLength(additionalInfo)
            var pairs: [(CBORValue, CBORValue)] = []
            pairs.reserveCapacity(Int(count))
            for _ in 0..<Int(count) {
                let key = try decode()
                let value = try decode()
                pairs.append((key, value))
            }
            return .map(pairs)

        case 7: // Simple values and floats
            switch additionalInfo {
            case 20: return .bool(false)
            case 21: return .bool(true)
            case 22: return .null
            case 23: return .undefined
            case 25: // float16
                let bytes = try readBytes(2)
                return .float(Double(decodeFloat16(bytes)))
            case 26: // float32
                let bytes = try readBytes(4)
                let bits = UInt32(bytes[0]) << 24 | UInt32(bytes[1]) << 16
                       | UInt32(bytes[2]) << 8  | UInt32(bytes[3])
                return .float(Double(Float(bitPattern: bits)))
            case 27: // float64
                let bytes = try readBytes(8)
                let hi: UInt64 = UInt64(bytes[0]) << 56 | UInt64(bytes[1]) << 48
                               | UInt64(bytes[2]) << 40 | UInt64(bytes[3]) << 32
                let lo: UInt64 = UInt64(bytes[4]) << 24 | UInt64(bytes[5]) << 16
                               | UInt64(bytes[6]) << 8  | UInt64(bytes[7])
                return .float(Double(bitPattern: hi | lo))
            default:
                return .unsignedInt(UInt64(additionalInfo))
            }

        default:
            throw CBORDecodingError.unsupportedMajorType(majorType)
        }
    }

    // MARK: - Private Helpers

    private mutating func readLength(_ additionalInfo: UInt8) throws -> UInt64 {
        switch additionalInfo {
        case 0...23:
            return UInt64(additionalInfo)
        case 24:
            let bytes = try readBytes(1)
            return UInt64(bytes[0])
        case 25:
            let bytes = try readBytes(2)
            return UInt64(bytes[0]) << 8 | UInt64(bytes[1])
        case 26:
            let bytes = try readBytes(4)
            return UInt64(bytes[0]) << 24 | UInt64(bytes[1]) << 16
                 | UInt64(bytes[2]) << 8  | UInt64(bytes[3])
        case 27:
            let bytes = try readBytes(8)
            let hi: UInt64 = UInt64(bytes[0]) << 56 | UInt64(bytes[1]) << 48
                           | UInt64(bytes[2]) << 40 | UInt64(bytes[3]) << 32
            let lo: UInt64 = UInt64(bytes[4]) << 24 | UInt64(bytes[5]) << 16
                           | UInt64(bytes[6]) << 8  | UInt64(bytes[7])
            return hi | lo
        default:
            throw CBORDecodingError.unsupportedAdditionalInfo(additionalInfo)
        }
    }

    private mutating func readBytes(_ count: Int) throws -> Data {
        guard offset + count <= data.count else {
            throw CBORDecodingError.unexpectedEndOfData
        }
        let start = data.startIndex + offset
        let bytes = data[start..<(start + count)]
        offset += count
        return Data(bytes)
    }

    /// Decode IEEE 754 half-precision float (binary16) to Float.
    private func decodeFloat16(_ bytes: Data) -> Float {
        let halfBits = UInt16(bytes[0]) << 8 | UInt16(bytes[1])
        let sign = UInt32((halfBits >> 15) & 0x1)
        let exponent = UInt32((halfBits >> 10) & 0x1F)
        let mantissa = UInt32(halfBits & 0x3FF)

        let floatBits: UInt32
        if exponent == 0 {
            if mantissa == 0 {
                floatBits = sign << 31 // ±0
            } else {
                // Subnormal: convert to normalized float32
                var m = mantissa
                var e: UInt32 = 127 - 15 + 1
                while (m & 0x400) == 0 {
                    m <<= 1
                    e -= 1
                }
                m &= 0x3FF
                floatBits = (sign << 31) | (e << 23) | (m << 13)
            }
        } else if exponent == 31 {
            // Inf or NaN
            floatBits = (sign << 31) | (0xFF << 23) | (mantissa << 13)
        } else {
            // Normalized
            floatBits = (sign << 31) | ((exponent + 127 - 15) << 23) | (mantissa << 13)
        }

        return Float(bitPattern: floatBits)
    }
}

// MARK: - Errors

public enum CBORDecodingError: Error, Sendable {
    case unexpectedEndOfData
    case invalidUTF8
    case unsupportedMajorType(UInt8)
    case unsupportedAdditionalInfo(UInt8)
}
