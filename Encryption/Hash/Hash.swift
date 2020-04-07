//
//  Hash.swift
//  Hash
//
//  Created by joey on 4/7/20.
//  Copyright © 2020 z1joey. All rights reserved.
//

import Foundation
import CryptoKit

extension String {
    func sha1() -> String {
        let digest = Insecure.SHA1.hash(data: Data(self.utf8))
        return digest.map { String(format: "%02x", $0) }.joined()
    }

    func sha256() -> String {
        let digest = SHA256.hash(data: Data(self.utf8))
        return digest.compactMap { String(format: "%02x", $0) }.joined()
    }

    func sha384() -> String {
        let digest = SHA384.hash(data: Data(self.utf8))
        return digest.compactMap { String(format: "%02x", $0) }.joined()
    }

    func sha512() -> String {
        let digest = SHA512.hash(data: Data(self.utf8))
        return digest.compactMap { String(format: "%02x", $0) }.joined()
    }

    func md5() -> String {
        let digest = Insecure.MD5.hash(data: Data(self.utf8))
        return digest.map { String(format: "%02x", $0) }.joined()
    }
}

