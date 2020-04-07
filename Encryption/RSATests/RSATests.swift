//
//  RSATests.swift
//  RSATests
//
//  Created by joey on 4/3/20.
//  Copyright © 2020 z1joey. All rights reserved.
//

import XCTest
@testable import RSA

class RSATests: XCTestCase {
    func testRSA() {
        guard let encryptedString: String = RSA.encrypt(testedString, publicKey: publicKey, sizeInBits: .bits2048) else { return }
        guard let decryptedString: String = RSA.decrypt(encryptedString, privateKey: privateKey, sizeInBits: .bits2048) else { return }

        XCTAssert(decryptedString == testedString)
    }

    func testRSAGenerateKeyPairs() {
        guard let keyPair = RSA.generateKeyPair(keySize: .bits2048) else { return }
        let someString = "today is tuesday"

        guard let encryptedString: String = RSA.encrypt(someString, publicKey: keyPair.publicKey) else { return }
        guard let decryptedString: String = RSA.decrypt(encryptedString, privateKey: keyPair.privateKey) else { return }

        XCTAssert(decryptedString == someString)
    }

    func testRSA3rd() {
        guard let encryptedString: String = RSA3rd.encrypt(testedString, publicKey: publicKey) else { return }
        guard let decryptedString: String = RSA3rd.decrypt(encryptedString, privateKey: privateKey) else { return }
        XCTAssert(decryptedString == testedString)
    }

    func testRSA3rdGenerateKeyPair() {
        guard let keyPair = RSA3rd.generateKeyPair(sizeInBits: .bits2048) else { return }
        let someString = "today is tuesday"

        guard let encryptedString: String = RSA3rd.encrypt(someString, publicKey: keyPair.publicKey) else { return }
        guard let decryptedString: String = RSA3rd.decrypt(encryptedString, privateKey: keyPair.privateKey) else { return }

        XCTAssert(decryptedString == someString)
    }
}

// MARK: - Testing Information

private let testedString = "weekend is coming!"

private let publicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCYiLkrrQp+hWIGIgFrWU882cHwe4NM6KQ7y6q3iRBWKZts+SD+O3Cl83sxMKv5JzWM81ni019NCQU1trzw/2EI2NGOda6n75A9jv1GDpnmwRm8WRgfictfuz+9E22HKDNm2e6+nssZ+JCbKZv9InzP25hIPTk+JRt2dyV64ahFTwIDAQAB"

private let privateKey = "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAJiIuSutCn6FYgYiAWtZTzzZwfB7g0zopDvLqreJEFYpm2z5IP47cKXzezEwq/knNYzzWeLTX00JBTW2vPD/YQjY0Y51rqfvkD2O/UYOmebBGbxZGB+Jy1+7P70TbYcoM2bZ7r6eyxn4kJspm/0ifM/bmEg9OT4lG3Z3JXrhqEVPAgMBAAECgYEAjfqlsXvOStpI1cCNZaip0tA2b2voWYwqYuY+r7vLEwiDfbme9kXJow6x2qWdTbsrY1mYj0OEb6Y3zTmdQQ3U+P6rVoMuCMHGYCOJkB1733bMb/KwCwJWLWx2DjhsUaR5U/R1et0NXIlJKqgS0dSWh1GaUo8kts/C48gcenaifpECQQDenzCNIuqMGE+hurPmx+TeO+YfmWOM0YqSLZEvXOmyvnDz/zIJHI3alHzAO+6X1wiW9Og6qrHSg7l/owaLor2zAkEAr2dhqpXP1mh8gHxgSY+Yvf7rZ3szu16z524h7Roh9Vs1YGlFDCipR9nokpik2VLYjJGyxvoOcJ3IfIgkgQHj9QJAMB7MydUgScP/gn/u3xWaPQdJiM8JG6k3gL1kwo4c3cwYckVZNWr8pqCuDodl3WBXtPmfMP8wjMZ4VESS55/3zQJAeTu6PH5ZbbdAPko4/v76Mm/sYtS7t8jIDbCIUGnciMomxWFdMP81qYzKe/B3GCJzvAzEBVU1/85+kNxEZspYtQJBAIOO8/Q6PjzitjHDR9ZMmMarggrdn+rGYrjlEH2+ryopuCO9AQP2Aq1x5b91I++v5fMJqoQ6MODZPlk/3XmR1Uc="
