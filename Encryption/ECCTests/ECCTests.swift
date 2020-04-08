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

    var privateKey: String? = ""
    var publicKey: String? = ""

    var storedPrivateKey: String = "BDQgLBzxlDLJzp75a5FLxzJGTxlE04ZcoiMTCsf7NOOelMDr6RJKCy0iBn0U4KPVssgZcn2hC+qA6SKxjhlDODU="
    var storedPublicKey: String = "BDQgLBzxlDLJzp75a5FLxzJGTxlE04ZcoiMTCsf7NOOelMDr6RJKCy0iBn0U4KPVssgZcn2hC+qA6SKxjhlDODXIiIa507hpf5G6ETLL+cJ2zdAKA03gO7YZRK7/so0e5Q=="

    override func setUp() {
        setupKeyPairs()
    }

    func testEncryption() {
        guard let encryptedString: String = ECC.encrypt(testedString, publicKey: storedPublicKey) else { return }
        guard let decryptedString: String = ECC.decrypt(encryptedString, privateKey: storedPrivateKey) else { return }

        XCTAssert(decryptedString == testedString)
    }

    func testGenerateKeyPairs() {
        guard let keyPair = ECC.generateKeyPair() else { return }
        let someString = "today is tuesday"

        guard let encryptedString: String = ECC.encrypt(someString, publicKey: keyPair.publicKey) else { return }
        guard let decryptedString: String = ECC.decrypt(encryptedString, privateKey: keyPair.privateKey) else { return }

        XCTAssert(decryptedString == someString)
    }
}

extension ECCTests {
    private func setupKeyPairs() {
        guard  let randomKeyPair = ECC.generateKeyPair() else { return }
        publicKey = randomKeyPair.publicKey.toString()
        privateKey = randomKeyPair.privateKey.toString()

        guard publicKey != nil, privateKey != nil else {
            preconditionFailure("Error: failed to setup key pairs")
        }
    }
}
