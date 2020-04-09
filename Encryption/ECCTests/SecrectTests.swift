//
//  SignatureTests.swift
//  ECCTests
//
//  Created by joey on 4/8/20.
//  Copyright © 2020 z1joey. All rights reserved.
//

import XCTest
@testable import ECC

class SignatureTests: XCTestCase {
    var bobKeyPair: Secrect.KeyPair?
    var aliceKeyPair: Secrect.KeyPair?

    var bobSharedSecrect: CFData?
    var aliceSharedSecrect: CFData?

    override func setUp() {
        setupBobAndAlice()
    }

    func testSharedSecrect() {
        XCTAssert(bobSharedSecrect != nil && aliceSharedSecrect != nil)
        XCTAssertEqual(bobSharedSecrect, aliceSharedSecrect)
    }
}

extension SignatureTests {
    private func setupBobAndAlice() {
        bobKeyPair = Secrect.generateKeyPair()
        aliceKeyPair = Secrect.generateKeyPair()

        guard  let bob = bobKeyPair, let alice = aliceKeyPair else {
            preconditionFailure("Error: failed to setup key paris")
        }

        bobSharedSecrect = Secrect.generateSharedSecrect(privateKey: bob.privateKey, publicKey: alice.publicKey)
        aliceSharedSecrect = Secrect.generateSharedSecrect(privateKey: alice.privateKey, publicKey: bob.publicKey)
    }
}
