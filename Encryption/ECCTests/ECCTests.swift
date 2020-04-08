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
    let testedString = "weekend is coming!"

    var storedECCPrivateKey: String = "BDQgLBzxlDLJzp75a5FLxzJGTxlE04ZcoiMTCsf7NOOelMDr6RJKCy0iBn0U4KPVssgZcn2hC+qA6SKxjhlDODU="
    var storedECCPublicKey: String = "BDQgLBzxlDLJzp75a5FLxzJGTxlE04ZcoiMTCsf7NOOelMDr6RJKCy0iBn0U4KPVssgZcn2hC+qA6SKxjhlDODXIiIa507hpf5G6ETLL+cJ2zdAKA03gO7YZRK7/so0e5Q=="

    var privateKey: String? = ""
    var publicKey: String? = ""

    override func setUp() {
        guard  let randomKeyPair = ECC.generateKeyPair() else { return }
        publicKey = randomKeyPair.publicKey.toString()
        privateKey = randomKeyPair.privateKey.toString()

        guard publicKey != nil, privateKey != nil else {
            preconditionFailure("Error: failed to setup key pairs")
        }
    }

    func testEncryption() {
        guard let encryptedString: String = ECC.encrypt(testedString, publicKey: storedECCPublicKey) else { return }
        guard let decryptedString: String = ECC.decrypt(encryptedString, privateKey: storedECCPrivateKey) else { return }

        XCTAssert(decryptedString == testedString)
    }

    func testKeyPairs() {
        guard let keyPair = ECC.generateKeyPair() else { return }
        let someString = "today is tuesday"

        guard let encryptedString: String = ECC.encrypt(someString, publicKey: keyPair.publicKey) else { return }
        guard let decryptedString: String = ECC.decrypt(encryptedString, privateKey: keyPair.privateKey) else { return }

        XCTAssert(decryptedString == someString)
    }

    func testSignature() {
        guard let alice = ECC.generateKeyPair(), let bob = ECC.generateKeyPair() else { return }

        let aliceSecrect = alice.privateKey.shareSecrect(withPublic: bob.publicKey)
        let bobSecrect = bob.privateKey.shareSecrect(withPublic: alice.publicKey)

        XCTAssert(aliceSecrect != nil && bobSecrect != nil)
        XCTAssertEqual(aliceSecrect, bobSecrect)
    }
}
