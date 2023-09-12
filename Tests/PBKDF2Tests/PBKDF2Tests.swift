import XCTest
import PBKDF2
import Crypto
import Foundation

class CryptoTests: XCTestCase {
    func testPBKDF2_MD5() throws {
        let pbkdf2 = PBKDF2<Insecure.MD5>()
        
        func test(password: String, salt: String, match: String) {
            let hash = pbkdf2.hash(Array(password.utf8), salt: Array(salt.utf8), iterations: 1_000).hexString
            XCTAssertEqual(hash, match)
        }
        
        let passes: [(String, String, String)] = [
            ("password", "longsalt", "95d6567274c3ed283041d5135c798823"),
            ("password2", "othersalt", "78e4d28875d6f3b92a01dbddc07370f1"),
            ("somewhatlongpasswordstringthatIwanttotest", "1", "c91a23ffd2a352f0f49c6ce64146fc0a"),
            ("p", "somewhatlongsaltstringthatIwanttotest", "4d0297fc7c9afd51038a0235926582bc"),
        ]
        passes.forEach(test)
    }

    func testPBKDF2_SHA1() throws {
        let pbkdf2 = PBKDF2<Insecure.SHA1>()
        
        func test(password: String, salt: String, match: String) {
            let hash = pbkdf2.hash(Array(password.utf8), salt: Array(salt.utf8), iterations: 1_000).hexString
            XCTAssertEqual(hash, match)
        }
        
        let passes: [(String, String, String)] = [
            ("password", "longsalt", "1712d0a135d5fcd98f00bb25407035c41f01086a"),
            ("password2", "othersalt", "7a0363dd39e51c2cf86218038ad55f6fbbff6291"),
            ("somewhatlongpasswordstringthatIwanttotest", "1", "8cba8dd99a165833c8d7e3530641c0ecddc6e48c"),
            ("p", "somewhatlongsaltstringthatIwanttotest", "31593b82b859877ea36dc474503d073e6d56a33d"),
        ]
        passes.forEach(test)
    }

    func testPBKDF2_SHA256() throws {
        let pbkdf2 = PBKDF2<SHA256>()
        
        func test(password: String, salt: String, match: String) {
            let hash = pbkdf2.hash(Array(password.utf8), salt: Array(salt.utf8), iterations: 1_000).hexString
            XCTAssertEqual(hash, match)
        }
        
        let passes: [(String, String, String)] = [
            ("password", "longsalt", "336dbd3932740eae2eb9fa05026393d8387c9aff4d6129be20916b8c0674bbf4"),
            ("password2", "othersalt", "c9597f2a77eda210ee76eac7cbcc743e6aaedd4112cc6b4f9bfd65dcf69e8d3d"),
            ("somewhatlongpasswordstringthatIwanttotest", "1", "676d11668e5613a7c6efef37aa5fc5740d8f3c0717782e1327c6a3db36c47f62"),
            ("p", "somewhatlongsaltstringthatIwanttotest", "f60f3189ff23aa8e5ba355383bddf8c99a761c4107263ce798352c31e3cf2bac"),
        ]
        passes.forEach(test)
    }
}

extension Array where Element == UInt8 {
    /// The 12 bytes represented as 24-character hex-string
    public var hexString: String {
        var data = Data()
        data.reserveCapacity(self.count * 2)
        
        for byte in self {
            data.append(radix16table[Int(byte / 16)])
            data.append(radix16table[Int(byte % 16)])
        }
        
        return String(data: data, encoding: .utf8)!
    }
}

fileprivate let radix16table: [UInt8] = [0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66]
