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

    func testECCKeyPairs() {
        guard let keyPair = ECC.generateKeyPair() else { return }
        let someString = "today is tuesday"

        guard let encryptedString: String = ECC.encrypt(someString, publicKey: keyPair.publicKey) else { return }
        guard let decryptedString: String = ECC.decrypt(encryptedString, privateKey: keyPair.privateKey) else { return }

        XCTAssert(decryptedString == someString)
    }

    func testECCEncryption() {
        guard let encryptedString: String = ECC.encrypt(testedString, publicKey: storedECCPublicKey) else { return }
        guard let decryptedString: String = ECC.decrypt(encryptedString, privateKey: storedECCPrivateKey) else { return }

        XCTAssert(decryptedString == testedString)
    }

    func testECCSignature() {
        guard let alice = ECC.generateKeyPair(), let bob = ECC.generateKeyPair() else { return }

        XCTAssert(alice.verify(keyPair: bob))
        XCTAssert(bob.verify(keyPair: alice))

        let aliceSecrect = alice.privateKey.shareSecrect(withPublic: bob.publicKey)
        let bobSecrect = bob.privateKey.shareSecrect(withPublic: alice.publicKey)

        XCTAssert(aliceSecrect != nil && bobSecrect != nil)
        XCTAssertEqual(aliceSecrect, bobSecrect)
    }

    func testRSAKeyPairs() {
        guard let encryptedString: String = ECC.encrypt(testedString, publicKey: storedRSAPublicKey, keyType: .RSA) else { return }
        guard let decryptedString: String = ECC.decrypt(encryptedString, privateKey: storedECCPrivateKey, keyType: .RSA) else { return }

        XCTAssert(decryptedString == testedString)
    }

    func testRSAEncryption() {
        guard let encryptedString: String = ECC.encrypt(testedString, publicKey: storedRSAPublicKey, keyType: .RSA) else { return }
        guard let decryptedString: String = ECC.decrypt(encryptedString, privateKey: storedRSAPrivateKey, keyType: .RSA) else { return }

        XCTAssert(decryptedString == testedString)
    }
}

/// Unblock the following to generate stored keys

//    var eccPrivateKey: String? = ""
//    var eccPublicKey: String? = ""
//    var rsaPrivateKey: String? = ""
//    var rsaPublicKey: String? = ""
//
//    override func setUp() {
//         setupECCKeyPairs()
//         setupRSAKeyPairs()
//    }

//private extension ECCTests {
//    func setupRSAKeyPairs() {
//        guard  let randomRSAKeyPair = ECC.generateKeyPair(keyType: .RSA) else { return }
//        rsaPublicKey = randomRSAKeyPair.publicKey.toString()
//        rsaPrivateKey = randomRSAKeyPair.privateKey.toString()
//
//        guard rsaPrivateKey != nil, rsaPublicKey != nil else {
//            preconditionFailure("Error: failed to setup RSA key pairs")
//        }
//    }
//
//    func setupECCKeyPairs() {
//        guard  let randomECCKeyPair = ECC.generateKeyPair(keyType: .EC) else { return }
//        eccPublicKey = randomECCKeyPair.publicKey.toString()
//        eccPrivateKey = randomECCKeyPair.privateKey.toString()
//
//        guard eccPublicKey != nil, eccPrivateKey != nil else {
//            preconditionFailure("Error: failed to setup ECC key pairs")
//        }
//    }
//}

let storedECCPublicKey = "BDQgLBzxlDLJzp75a5FLxzJGTxlE04ZcoiMTCsf7NOOelMDr6RJKCy0iBn0U4KPVssgZcn2hC+qA6SKxjhlDODXIiIa507hpf5G6ETLL+cJ2zdAKA03gO7YZRK7/so0e5Q=="
let storedECCPrivateKey = "BDQgLBzxlDLJzp75a5FLxzJGTxlE04ZcoiMTCsf7NOOelMDr6RJKCy0iBn0U4KPVssgZcn2hC+qA6SKxjhlDODU="

let storedRSAPublicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCYiLkrrQp+hWIGIgFrWU882cHwe4NM6KQ7y6q3iRBWKZts+SD+O3Cl83sxMKv5JzWM81ni019NCQU1trzw/2EI2NGOda6n75A9jv1GDpnmwRm8WRgfictfuz+9E22HKDNm2e6+nssZ+JCbKZv9InzP25hIPTk+JRt2dyV64ahFTwIDAQAB"
let storedRSAPrivateKey = "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAJiIuSutCn6FYgYiAWtZTzzZwfB7g0zopDvLqreJEFYpm2z5IP47cKXzezEwq/knNYzzWeLTX00JBTW2vPD/YQjY0Y51rqfvkD2O/UYOmebBGbxZGB+Jy1+7P70TbYcoM2bZ7r6eyxn4kJspm/0ifM/bmEg9OT4lG3Z3JXrhqEVPAgMBAAECgYEAjfqlsXvOStpI1cCNZaip0tA2b2voWYwqYuY+r7vLEwiDfbme9kXJow6x2qWdTbsrY1mYj0OEb6Y3zTmdQQ3U+P6rVoMuCMHGYCOJkB1733bMb/KwCwJWLWx2DjhsUaR5U/R1et0NXIlJKqgS0dSWh1GaUo8kts/C48gcenaifpECQQDenzCNIuqMGE+hurPmx+TeO+YfmWOM0YqSLZEvXOmyvnDz/zIJHI3alHzAO+6X1wiW9Og6qrHSg7l/owaLor2zAkEAr2dhqpXP1mh8gHxgSY+Yvf7rZ3szu16z524h7Roh9Vs1YGlFDCipR9nokpik2VLYjJGyxvoOcJ3IfIgkgQHj9QJAMB7MydUgScP/gn/u3xWaPQdJiM8JG6k3gL1kwo4c3cwYckVZNWr8pqCuDodl3WBXtPmfMP8wjMZ4VESS55/3zQJAeTu6PH5ZbbdAPko4/v76Mm/sYtS7t8jIDbCIUGnciMomxWFdMP81qYzKe/B3GCJzvAzEBVU1/85+kNxEZspYtQJBAIOO8/Q6PjzitjHDR9ZMmMarggrdn+rGYrjlEH2+ryopuCO9AQP2Aq1x5b91I++v5fMJqoQ6MODZPlk/3XmR1Uc="
