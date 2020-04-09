//
//  AES.swift
//  AESDemo
//
//  Created by joey on 4/2/20.
//  Copyright © 2020 TGI Technology. All rights reserved.
//

import Foundation
import CommonCrypto

struct AES {
    private let key: Data
    private let iv: Data?

    private var options: CCOptions = CCOptions(kCCOptionPKCS7Padding)
    private var output: Output = .base64

    var keySize: Int { return key.count }
    let ivSize: Int = kCCBlockSizeAES128

    init?(key: String, iv: String? = nil) {
        guard key.isValidKeySize(), let keyData = key.data(using: .utf8) else {
            debugPrint("Error: Invalid Key.")
            return nil
        }

        if let iv = iv {
            if iv.count == ivSize, let ivData = iv.data(using: .utf8) {
                self.iv = ivData
            } else {
                debugPrint("Error: Invalid IV.")
                return nil
            }
        } else {
            self.iv = nil
        }

        self.key = keyData
    }

    mutating func setup(options: Options) {
        self.options = options.rawValue
    }

    mutating func setup(output: Output) {
        self.output = output
    }

    func encrypt(string: String) -> Data? {
        let utf8Data = string.data(using: .utf8)
        return process(data: utf8Data, operation: .encrypt)
    }

    func decrypt(data: Data?) -> String? {
        guard let decryptedData = process(data: data, operation: .decrypt) else { return nil }
        switch output {
        case .base64:
            return decryptedData.base64EncodedString()
        case .utf8:
            return String(bytes: decryptedData, encoding: .utf8)
        }
    }
}

// MARK: - Helper
private extension AES {
    func process(data: Data?, operation: CCOperation) -> Data? {
        guard let data = data else { return nil }

        let bufferSize = data.count + kCCBlockSizeAES128

        var buffer = Data(count: bufferSize)
        var bytesCount = Int(0)
        var unsafeStatus: CCCryptorStatus?

        if let iv = iv {
            unsafeStatus = buffer.withUnsafeMutableBytes { cryptBytes in
                data.withUnsafeBytes { dataBytes in
                    iv.withUnsafeBytes { ivBytes in
                        key.withUnsafeBytes { keyBytes in
                            CCCrypt(operation, CCAlgorithm(kCCAlgorithmAES), options, keyBytes.baseAddress, keySize, ivBytes.baseAddress, dataBytes.baseAddress, data.count, cryptBytes.baseAddress, bufferSize, &bytesCount)
                        }
                    }
                }
            }
        } else {
            unsafeStatus = buffer.withUnsafeMutableBytes { cryptBytes in
                data.withUnsafeBytes { dataBytes in
                    key.withUnsafeBytes { keyBytes in
                        CCCrypt(operation, CCAlgorithm(kCCAlgorithmAES), options, keyBytes.baseAddress, keySize, nil, dataBytes.baseAddress, data.count, cryptBytes.baseAddress, bufferSize, &bytesCount)
                    }
                }
            }
        }

        guard let status = unsafeStatus, UInt32(status) == UInt32(kCCSuccess) else {
            debugPrint("Error: Failed to process data.")
            return nil
        }

        buffer.removeSubrange(bytesCount..<buffer.count)
        return buffer
    }
}

// MARK: - Define
extension AES {
    enum Options: CCOptions {
        case pkcs7
        case ecb

        init(rawValue: CCOptions) {
            switch rawValue {
            case CCOptions(kCCOptionPKCS7Padding): self = .pkcs7
            case CCOptions(kCCOptionECBMode): self = .ecb
            default: self = .pkcs7
            }
        }
    }

    enum Output: Int {
        case base64, utf8
    }
}

private extension String {
    func isValidKeySize() -> Bool {
        return count == kCCKeySizeAES128 || count == kCCKeySizeAES192 || count == kCCKeySizeAES256
    }
}

private extension CCOperation {
    static let encrypt = CCOperation(kCCEncrypt)
    static let decrypt = CCOperation(kCCDecrypt)
}



