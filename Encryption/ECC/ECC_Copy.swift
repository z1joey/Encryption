//
//  ECC.swift
//  ECC
//
//  Created by joey on 4/8/20.
//  Copyright © 2020 z1joey. All rights reserved.
//

import Foundation

struct ECC {
    static func encrypt(_ string: String, publicKey: String, sizeInBits size: KeySize = .bits256) -> String? {
        guard let secKey = generateSecureKey(publicKey) else { return nil }

        return encrypt(string, publicKey: secKey)
    }

    static func decrypt(_ base64String: String, privateKey: String, sizeInBits size: KeySize = .bits256) -> String? {
        guard let secKey = generateSecureKey(privateKey) else { return nil }

        return decrypt(base64String, privateKey: secKey)
    }

    static func encrypt(_ string: String, publicKey: SecKey, padding: SecPadding = .PKCS1) -> String? {
          var keySize   = SecKeyGetBlockSize(publicKey)
          var keyBuffer = [UInt8](repeating: 0, count: keySize)

          // Encrypto  should less than key length
          guard SecKeyEncrypt(publicKey, padding, string, string.count, &keyBuffer, &keySize) == errSecSuccess else {
              debugPrint("Error: failed to encrypt")
              return nil
          }

          return Data(bytes: keyBuffer, count: keySize).base64EncodedString()
      }

    static func decrypt(_ base64String: String, privateKey: SecKey, padding: SecPadding = .PKCS1) -> String? {
          let buffer = [UInt8](base64String.utf8)

          var keySize   = SecKeyGetBlockSize(privateKey)
          var keyBuffer = [UInt8](repeating: 0, count: keySize)

          guard SecKeyDecrypt(privateKey, padding, buffer, buffer.count, &keyBuffer, &keySize) == errSecSuccess else {
              debugPrint("Error: failed to decrypt")
              return nil
          }

          return String(bytes: Data(bytes: keyBuffer, count: keySize), encoding: .utf8)
      }
}

// MARK: - Factory
extension ECC {
    private static func generateSecureKey(_ string: String) -> SecKey? {
        guard let data = Data(base64Encoded: string) else { return nil }

        var attributes: CFDictionary {
            return [kSecAttrKeyType: kSecAttrKeyTypeEC,
                    kSecAttrKeyClass: kSecAttrKeyClassPrivate] as CFDictionary
        }

        var error: Unmanaged<CFError>? = nil
        guard let secKey = SecKeyCreateWithData(data as CFData, attributes, &error) else {
            print(error.debugDescription)
            return nil
        }

        return secKey
    }

    static func generateKeyPair(keySize: KeySize = .bits256) -> KeyPair? {
        var publicKeyBuffer, privateKeyBuffer: SecKey?

        var parameters: CFDictionary {
            return [kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
                kSecAttrKeySizeInBits: keySize.rawValue] as CFDictionary
        }

        guard SecKeyGeneratePair(parameters, &publicKeyBuffer, &privateKeyBuffer) == errSecSuccess else {
            debugPrint("Error: failed to generate ECC key pair")
            return nil
        }
        guard let publicKey = publicKeyBuffer, let privateKey = privateKeyBuffer else {
            debugPrint("Error: failed to generate ECC key pair")
            return nil
        }

        return KeyPair(privateKey: privateKey, publicKey: publicKey)
    }

//    static func generateRandomSecureKey(sizeInBits size: KeySize = .bits256) -> SecKey? {
//        var attributes: CFDictionary {
//            return [kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
//                    kSecAttrKeySizeInBits: size.rawValue] as CFDictionary
//        }
//
//        var error: Unmanaged<CFError>? = nil
//        guard let secKey = SecKeyCreateRandomKey(attributes, &error) else {
//            print(error.debugDescription)
//            return nil
//        }
//
//        return secKey
//    }
}

extension SecKey {
    func toString() -> String? {
        var error:Unmanaged<CFError>?
        if let cfdata = SecKeyCopyExternalRepresentation(self, &error) {
           let data:Data = cfdata as Data
           return data.base64EncodedString()
        }
        return nil
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
    }
}
