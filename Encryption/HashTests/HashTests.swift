//
//  HashTests.swift
//  HashTests
//
//  Created by joey on 4/7/20.
//  Copyright © 2020 z1joey. All rights reserved.
//

import XCTest
@testable import Hash

class HashTests: XCTestCase {
    private let testedString = "This is a secret"

    func testSHA1() {
        XCTAssertEqual(testedString.sha1(), sha1)
    }

    func testSHA256() {
        XCTAssertEqual(testedString.sha256(), sha256)
    }

    func testSHA384() {
        XCTAssertEqual(testedString.sha384(), sha384)
    }

    func testSHA512() {
        XCTAssertEqual(testedString.sha512(), sha512)
    }

    func testMD5() {
        XCTAssertEqual(testedString.md5(), md5)
    }
}

// MARK: - Expected Results
private let sha1 = "71800b4c97bcccbe286bcde42701be53f4852de8"
private let sha256 = "f2d9ad12c972f3f76c37268514de20f74d70603cd369f55f70b52472c1de1065"
private let sha384 = "6b354e0ccdbc95b615043e25de3ca8ba6be381d730d9a4e169ddb53374a46f89be8ccfd18ebef44b4289dc321de23cc6"
private let sha512 = "62903b7945623403247e858b74b87d2a19ad752d871f89794b50f122b1d3e1921ff6852c131a3fe76c1ee42d981ba9d1a17f120a21f2f031b31897c0a437f833"
private let md5 = "f8158b240153f4dec10ff3852e7e9c17"
