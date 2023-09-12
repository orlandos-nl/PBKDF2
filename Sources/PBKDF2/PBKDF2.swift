import Crypto

import Foundation

/// The requested amount of output bytes from the key derivation
///
/// In circumstances with low iterations the amount of output bytes may not be met.
///
/// `digest.digestSize * iterations` is the amount of bytes stored in PBKDF2's buffer.
/// Any data added beyond this limit
///
/// WARNING: Do not switch these key sizes, new sizes may be added
public enum PBKDF2KeySize: ExpressibleByIntegerLiteral {
    case digestSize
    case fixed(Int)
    
    public init(integerLiteral value: Int) {
        self = .fixed(value)
    }
    
    fileprivate func size<HF: HashFunction>(for digest: HF) -> Int {
        switch self {
        case .digestSize:
            return HF.Digest.byteCount
        case .fixed(let size):
            return size
        }
    }
}

/// PBKDF2 derives a fixed or custom length key from a password and salt.
///
/// It accepts a customizable amount of iterations to increase the algorithm weight and security.
///
/// Unlike BCrypt, the salt does not get stored in the final result,
/// meaning it needs to be generated and stored manually.
///
///     let passwordHasher = PBKDF2(digest: SHA1)
///     let salt = try CryptoRandom().generateData(count: 64) // Data
///     let hash = try passwordHasher.deriveKey(fromPassword: "secret", salt: salt, iterations: 15_000) // Data
///     print(hash.hexEncodedString()) // 8e55fa3015da583bb51b706371aa418afc8a0a44
///
/// PBKDF2 leans on HMAC for each iteration and can use all hash functions supported in Crypto
///
/// https://en.wikipedia.org/wiki/PBKDF2
public final class PBKDF2<HF: HashFunction> {
    private var hash: HF
    private let chunkSize: Int
    private let digestSize: Int
    
    /// Creates a new PBKDF2 derivator based on a hashing algorithm
    public init() {
        self.hash = HF()
        self.chunkSize = HF.blockByteCount
        self.digestSize = HF.Digest.byteCount
    }
    
    /// Derives a key with up to `keySize` of bytes
    public func hash(
        _ password: [UInt8],
        salt: [UInt8],
        iterations: Int32,
        keySize: PBKDF2KeySize = .digestSize
    ) -> [UInt8] {
        precondition(iterations > 0, "You must iterate in PBKDF2 at least once")
        precondition(!password.isEmpty, "You cannot hash an empty password")
        precondition(!salt.isEmpty, "You cannot hash with an empty salt")
        
        let keySize = keySize.size(for: hash)
        
        precondition(keySize <= Int(Int32.max) * chunkSize)
        
        let saltSize = salt.count
        var salt = salt + [0, 0, 0, 0]
        
        var password = password
        
        if password.count > chunkSize {
            password = Array(HF.hash(data: password))
        }
        
        if password.count < chunkSize {
            password = password + [UInt8](repeating: 0, count: chunkSize - password.count)
        }
        
        var outerPadding = [UInt8](repeating: 0x5c, count: chunkSize)
        var innerPadding = [UInt8](repeating: 0x36, count: chunkSize)
        
        xor(&innerPadding, password, count: chunkSize)
        xor(&outerPadding, password, count: chunkSize)
        
        func authenticate(message: UnsafeRawBufferPointer) -> HF.Digest {
            var hasher = HF()
            hasher.update(data: innerPadding)
            hasher.update(data: message)
            let innerPaddingHash = hasher.finalize()

            hasher = HF()
            hasher.update(data: outerPadding)
            innerPaddingHash.withUnsafeBytes { bytes in
                hasher.update(bufferPointer: bytes)
            }
            return hasher.finalize()
        }
        
        var output = [UInt8]()
        output.reserveCapacity(keySize)
        
        func calculate(block: UInt32) {
            salt.withUnsafeMutableBytes { salt in
                salt.baseAddress!.advanced(by: saltSize).assumingMemoryBound(to: UInt32.self).pointee = block.bigEndian
            }
            
            var ui: HF.Digest = salt.withUnsafeBytes { buffer in
                authenticate(message: buffer)
            }
            var u1 = Array(ui)
            
            if iterations > 1 {
                for _ in 1..<iterations {
                    ui = ui.withUnsafeBytes { buffer in
                        authenticate(message: buffer)
                    }
                    xor(&u1, ui, count: digestSize)
                }
            }
            
            output.append(contentsOf: u1)
        }
        
        for block in 1...UInt32((keySize + digestSize - 1) / digestSize) {
            calculate(block: block)
        }
        
        let extra = output.count &- keySize
        
        if extra >= 0 {
            output.removeLast(extra)
            return output
        }
        
        return output
    }
}

/// XORs the lhs bytes with the rhs bytes on the same index
///
/// Requires lhs and rhs to have an equal count
@_transparent
public func xor<D: Digest>(_ lhs: inout [UInt8], _ rhs: D, count: Int) {
    rhs.withUnsafeBytes { rhs in
        var i = 0; while i < count {
            lhs[i] ^= rhs[i]
            i &+= 1
        }
    }
}


/// XORs the lhs bytes with the rhs bytes on the same index
///
/// Requires lhs and rhs to have an equal count
@_transparent
public func xor(_ lhs: inout [UInt8], _ rhs: [UInt8], count: Int) {
    var i = 0; while i < count {
        lhs[i] ^= rhs[i]
        i &+= 1
    }
}
