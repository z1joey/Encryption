//
//  ECCTests.swift
//  ECCTests
//
//  Created by joey on 4/7/20.
//  Copyright © 2020 z1joey. All rights reserved.
//

import XCTest
@testable import ECC

class ECCTests: XCTestCase {
    var bobKeyPair: ECC.KeyPair?
    var aliceKeyPair: ECC.KeyPair?

    var bobSharedSecrect: CFData?
    var aliceSharedSecrect: CFData?

    override func setUp() {
        bobKeyPair = ECC.generateKeyPair()
        aliceKeyPair = ECC.generateKeyPair()

        guard  let bob = bobKeyPair, let alice = aliceKeyPair else {
            preconditionFailure("Error: failed to setup key paris")
        }

        bobSharedSecrect = ECC.generateSharedSecrect(privateKey: bob.privateKey, publicKey: alice.publicKey)
        aliceSharedSecrect = ECC.generateSharedSecrect(privateKey: alice.privateKey, publicKey: bob.publicKey)
    }

    func testSharedSecrect() {
        XCTAssert(bobSharedSecrect != nil && aliceSharedSecrect != nil)
        XCTAssertEqual(bobSharedSecrect, aliceSharedSecrect)
    }

    func testEncryption() {

    }
}
