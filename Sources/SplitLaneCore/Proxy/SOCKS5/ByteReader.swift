import Foundation

/// A bounds-checked forward cursor over a byte buffer.
///
/// Every byte the SOCKS5 layer reads from the upstream goes through this type. Nothing in that
/// layer subscripts a received buffer directly, and that is a security requirement rather than a
/// style preference: Swift *traps* on out-of-range slicing, and a trap inside the system extension
/// kills the provider, which fails every selected application open until it restarts. A malformed
/// reply from a hostile or MITM'd proxy must produce an error, never a crash. See F-7 in
/// docs/THREAT_MODEL.md.
///
/// Reads are transactional at the call site: a read that cannot be satisfied throws
/// ``SOCKS5Error/incompleteResponse`` and leaves the cursor untouched, so a caller parsing a
/// partially arrived message can retry against the same reader once more bytes land.
struct ByteReader {

    private let bytes: [UInt8]
    private(set) var offset: Int

    init(_ data: Data) {
        self.bytes = [UInt8](data)
        self.offset = 0
    }

    init(_ bytes: [UInt8]) {
        self.bytes = bytes
        self.offset = 0
    }

    /// Bytes not yet consumed.
    var remaining: Int { bytes.count - offset }

    var isAtEnd: Bool { remaining == 0 }

    /// Reads one byte.
    mutating func readUInt8() throws -> UInt8 {
        guard remaining >= 1 else { throw SOCKS5Error.incompleteResponse }
        defer { offset += 1 }
        return bytes[offset]
    }

    /// Reads a big-endian (network byte order) 16-bit value.
    mutating func readUInt16() throws -> UInt16 {
        guard remaining >= 2 else { throw SOCKS5Error.incompleteResponse }
        defer { offset += 2 }
        return UInt16(bytes[offset]) << 8 | UInt16(bytes[offset + 1])
    }

    /// Reads exactly `count` bytes.
    ///
    /// `count` is frequently attacker-influenced — the `DOMAIN` length byte of a reply is a value
    /// the upstream chooses — so the length check is the whole point of this method.
    mutating func readBytes(_ count: Int) throws -> [UInt8] {
        guard count >= 0 else { throw SOCKS5Error.malformedResponse("negative length") }
        guard remaining >= count else { throw SOCKS5Error.incompleteResponse }
        defer { offset += count }
        return Array(bytes[offset..<(offset + count)])
    }

    /// Reads a length-prefixed byte string (one length byte followed by that many bytes).
    mutating func readLengthPrefixedBytes() throws -> [UInt8] {
        let length = try readUInt8()
        return try readBytes(Int(length))
    }

    /// Peeks without consuming.
    func peekUInt8(at index: Int = 0) -> UInt8? {
        let position = offset + index
        guard position >= 0, position < bytes.count else { return nil }
        return bytes[position]
    }
}
