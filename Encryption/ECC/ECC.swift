//
//  ECC.swift
//  ECC
//
//  Created by joey on 4/7/20.
//  Copyright © 2020 z1joey. All rights reserved.
//

import Foundation

struct ECC {
    static func encrypt(_ string: String, shared: SecKey, padding: SecPadding = .PKCS1) -> String? {
        var keySize   = SecKeyGetBlockSize(shared)
        var keyBuffer = [UInt8](repeating: 0, count: keySize)

        // Encrypto  should less than key length
        guard SecKeyEncrypt(shared, padding, string, string.count, &keyBuffer, &keySize) == errSecSuccess else {
            debugPrint("Error: failed to encrypt")
            return nil
        }

        return Data(bytes: keyBuffer, count: keySize).base64EncodedString()
    }

    static func decrypt(_ base64String: String, key: SecKey, padding: SecPadding = .PKCS1) -> String? {
        let buffer = [UInt8](base64String.utf8)

        var keySize   = SecKeyGetBlockSize(key)
        var keyBuffer = [UInt8](repeating: 0, count: keySize)

        guard SecKeyDecrypt(key, padding, buffer, buffer.count, &keyBuffer, &keySize) == errSecSuccess else {
            debugPrint("Error: failed to decrypt")
            return nil
        }

        return String(bytes: Data(bytes: keyBuffer, count: keySize), encoding: .utf8)
    }

    static func generateKeyPair(keySize: KeySize = .bits256) -> KeyPair? {
        var error: Unmanaged<CFError>?
        var attributes: CFDictionary {
            return [
                kSecAttrKeyType: kSecAttrKeyTypeEC,
                kSecPrivateKeyAttrs: [kSecAttrIsPermanent: false],
                kSecAttrKeySizeInBits: keySize.rawValue] as CFDictionary
        }

        guard let privateKey = SecKeyCreateRandomKey(attributes, &error) else {
            debugPrint("Error: failed to generate private key")
            return nil
        }
        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            debugPrint("Error: failed to generate public key")
            return nil
        }

        return KeyPair(privateKey: privateKey, publicKey: publicKey)
    }

    static func generateSharedSecrect(privateKey: SecKey, publicKey: SecKey, keySize: KeySize = .bits256) -> CFData? {
        var error: Unmanaged<CFError>?
        var attributes: CFDictionary {
            return [kSecAttrKeyType: kSecAttrKeyTypeEC,
                kSecPrivateKeyAttrs: [kSecAttrIsPermanent: false],
                kSecPublicKeyAttrs: [kSecAttrIsPermanent: false],
                SecKeyKeyExchangeParameter.requestedSize.rawValue: 32,
                kSecAttrKeySizeInBits: keySize.rawValue] as CFDictionary
        }
        let algorithm:SecKeyAlgorithm = SecKeyAlgorithm.ecdhKeyExchangeStandardX963SHA256

        guard let secrect = SecKeyCopyKeyExchangeResult(privateKey, algorithm, publicKey, attributes, &error) else {
            debugPrint("Error: failed to generate shared secrect")
            return nil
        }

        return secrect
    }
}

extension CFData {
    func generateSecurityKey(keySize: Int = 256) -> SecKey? {
        var error: Unmanaged<CFError>?
        var attributes: CFDictionary {
            return [kSecAttrKeyType: kSecAttrKeyTypeEC,
                kSecAttrKeyClass: kSecAttrKeyClassPrivate,
                kSecAttrKeySizeInBits: keySize] as CFDictionary
        }

//        let base64Key = (self as Data).base64EncodedString()
//        guard let data = Data(base64Encoded: base64Key) else { return nil }
        guard let key = SecKeyCreateWithData(self, attributes, &error) else {
            debugPrint(error.debugDescription)
            return nil
        }

        return key
    }
}

// MARK: - Define
extension ECC {
    struct KeyPair {
        let privateKey: SecKey
        let publicKey: SecKey
    }

    enum KeySize: Int {
        case bits256 = 256
        case bits2048 = 2048
        case bits3072 = 3072
        case bits4096 = 4096
    }
}
