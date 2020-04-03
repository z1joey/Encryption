//
//  AESTests.swift
//  AESTests
//
//  Created by joey on 4/3/20.
//  Copyright © 2020 z1joey. All rights reserved.
//

import XCTest
import CommonCrypto

@testable import AES

class AESTests: XCTestCase {
    let utf8string = "Today is Friday"
    let base64String = "VG9kYXkgaXMgRnJpZGF5"
    let key128 = "passwordpassword"
    let key256 = "passwordpasswordpasswordpassword"
    let iv = "hahahahahahahaha"

    var aesWithoutIV: AES?
    var aesWithIV: AES?

    override func setUp() {
        aesWithoutIV = AES(key: key128)
        aesWithIV = AES(key: key128, iv: iv)
    }

    func testValidAES() {
        let aesWithInvalidKey = AES(key: "??", iv: iv)
        XCTAssert(aesWithInvalidKey == nil)
        let aesWithInvalidIV = AES(key: key128, iv: "??")
        XCTAssert(aesWithInvalidIV == nil)
        let aesWithKey256 = AES(key: key256)
        XCTAssert(aesWithKey256 != nil)
        let aesWithValidIV = AES(key: key256, iv: iv)
        XCTAssert(aesWithValidIV?.ivSize == kCCBlockSizeAES128)
    }

    func testDecryptAsBase64WithoutIV() {
        aesWithoutIV?.setup(output: .base64)
        let data = aesWithoutIV?.encrypt(string: utf8string)
        let decryptedString = aesWithoutIV?.decrypt(data: data)
        XCTAssert(decryptedString == base64String)
    }

    func testDecryptAsUTF8WithoutIV() {
        aesWithoutIV?.setup(output: .utf8)
        let data = aesWithoutIV?.encrypt(string: utf8string)
        let decryptedString = aesWithoutIV?.decrypt(data: data)
        XCTAssert(decryptedString == utf8string)
    }

    func testDecryptAsBase64WithIV() {
        aesWithIV?.setup(output: .base64)
        let data = aesWithIV?.encrypt(string: utf8string)
        let decryptedString = aesWithIV?.decrypt(data: data)
        XCTAssert(decryptedString == base64String)
    }

    func testDecryptAsUTF8WithIV() {
        aesWithIV?.setup(output: .utf8)
        let data = aesWithIV?.encrypt(string: utf8string)
        let decryptedString = aesWithIV?.decrypt(data: data)
        XCTAssert(decryptedString == utf8string)
    }

    func testConvertUTF8IntoBase64() {
        let utf8Data = utf8string.data(using: .utf8)
        let base64Result = utf8Data?.base64EncodedString()
        XCTAssert(base64Result == base64String)
    }

    func testConvertBase64IntoUTF8() {
        guard let base64Data = Data(base64Encoded: base64String) else { return }
        let utf8Result = String(data: base64Data, encoding: .utf8)
        XCTAssert(utf8Result == utf8string)
    }
}
