//
//  RSA.swift
//  RSA
//
//  Created by joey on 4/3/20.
//  Copyright © 2020 z1joey. All rights reserved.
//

import Foundation
import SwiftyRSA

struct RSA {
    private var padding: Padding = .PKCS1

    init(padding: Padding = .PKCS1) {
        self.padding = padding
    }

    func encrypt(string: String, publicKey: String) -> String? {
        if let encryptedData: Data = encrypt(string: string, publicKey: publicKey) {
            return encryptedData.base64EncodedString()
        }
        return nil
    }

    func decrypt(base64String: String, privateKey: String) -> String? {
        if let decryptedData: Data = decrypt(base64String: base64String, privateKey: privateKey) {
            return String(bytes: decryptedData, encoding: .utf8)
        }
        return nil
    }

    func generateKeyPair(keySize: KeySize) -> KeyPair? {
        do {
            let keyPair = try SwiftyRSA.generateRSAKeyPair(sizeInBits: keySize.rawValue)
            let privateKey = try keyPair.privateKey.pemString()
            let publicKey = try keyPair.publicKey.pemString()

            return KeyPair(privateKey: privateKey, publicKey: publicKey)
        } catch let error {
            debugPrint(error.localizedDescription)
            return nil
        }
    }
}

// MARK: - Crypt
private extension RSA {
    func encrypt(string: String, publicKey: String) -> Data? {
        do {
            let publicKey = try PublicKey(pemEncoded: publicKey)
            let clear = try ClearMessage(string: string, using: .utf8)
            let encrypted = try clear.encrypted(with: publicKey, padding: padding)

            return encrypted.data
        } catch let error {
            debugPrint(error.localizedDescription)
            return nil
        }
    }

    func decrypt(base64String: String, privateKey: String) -> Data? {
        do {
            let encrypted = try EncryptedMessage(base64Encoded: base64String)
            let privateKey = try PrivateKey(pemEncoded: privateKey)
            let clear = try encrypted.decrypted(with: privateKey, padding: padding)

            return clear.data
        } catch let error {
            print(error.localizedDescription)
            return nil
        }
    }
}

// MARK: - Define
extension RSA {
    struct KeyPair {
        let privateKey: String
        let publicKey: String
    }

    enum KeySize: Int {
        case bits515 = 515
        case bits2048 = 2048
        case bits3072 = 3072
        case bits4096 = 4096
    }
}
