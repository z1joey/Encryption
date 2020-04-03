//
//  RSA_Copy.swift
//  RSA
//
//  Created by joey on 4/3/20.
//  Copyright © 2020 z1joey. All rights reserved.
//

import Foundation

@available(*, deprecated)
struct RSA_Copy {
    static func encrypt(string: String, publicKey: String?) -> String? {
        guard let publicKey = publicKey else { return nil }
        guard let data = Data(base64Encoded: publicKey) else { return nil }

        var attributes: CFDictionary {
            return [
                kSecAttrKeyType            : kSecAttrKeyTypeRSA,
                kSecAttrKeyClass           : kSecAttrKeyClassPublic,
                kSecAttrKeySizeInBits     : 1024,
                // kSecReturnPersistentRef : kCFBooleanTrue
                ] as CFDictionary
        }

        var error: Unmanaged<CFError>? = nil
        guard let secKey = SecKeyCreateWithData(data as CFData, attributes, &error) else {
            print(error.debugDescription)
            return nil
        }
        return encrypt(string: string, publicKey: secKey)
    }

    static func decrypt(string: String, privateKey: String?) -> String? {
        guard let privateKey = privateKey else { return nil }
        guard let data = Data(base64Encoded: privateKey, options: .init(rawValue: 0)) else { return nil }

        var attributes: CFDictionary {
            return [
                kSecAttrKeyType            : kSecAttrKeyTypeRSA,
                kSecAttrKeyClass           : kSecAttrKeyClassPrivate,
                kSecAttrKeySizeInBits     : 1024] as CFDictionary
        }

        var error: Unmanaged<CFError>? = nil
        guard let secKey = SecKeyCreateWithData(data as CFData, attributes, &error) else {
            print(error.debugDescription)
            return nil
        }
        return decrypt(string: string, privateKey: secKey)
    }
}

// MARK: - Helper
@available(*, deprecated)
private extension RSA_Copy {
    static func encrypt(string: String, publicKey: SecKey) -> String? {
        let buffer = [UInt8](string.utf8)

        var keySize   = SecKeyGetBlockSize(publicKey)
        var keyBuffer = [UInt8](repeating: 0, count: keySize)

        // Encrypto  should less than key length
        guard SecKeyEncrypt(publicKey, SecPadding.PKCS1, buffer, buffer.count, &keyBuffer, &keySize) == errSecSuccess else { return nil }
        return Data(bytes: keyBuffer, count: keySize).base64EncodedString()
    }

    static func decrypt(string: String, privateKey: SecKey) -> String? {
        let buffer = [UInt8](string.utf8)

        var keySize   = SecKeyGetBlockSize(privateKey)
        var keyBuffer = [UInt8](repeating: 0, count: keySize)

        guard SecKeyDecrypt(privateKey, .PKCS1, buffer, buffer.count, &keyBuffer, &keySize) == errSecSuccess else { return nil }
        return String(bytes: Data(bytes: keyBuffer, count: keySize), encoding: .utf8)
    }
}
