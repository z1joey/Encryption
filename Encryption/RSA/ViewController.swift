//
//  ViewController.swift
//  RSA
//
//  Created by joey on 4/3/20.
//  Copyright © 2020 z1joey. All rights reserved.
//

import UIKit
import SwiftyRSA

class ViewController: UIViewController {
    var buffer: String = ""

    override func viewDidLoad() {
        super.viewDidLoad()
        // Do any additional setup after loading the view.
        testEncryption()
        testDecryption()
    }

    func testEncryption() {
        do {
            let publicKey = try PublicKey(pemEncoded: publicKeyString)
            let clear = try ClearMessage(string: testedString, using: .utf8)
            let encrypted = try clear.encrypted(with: publicKey, padding: .PKCS1)

            // Then you can use:
            let data = encrypted.data
            let base64String = encrypted.base64String
            buffer = base64String
            print("buffer: " + buffer)
        } catch let error {
            print(error.localizedDescription)
        }
    }

    func testDecryption() {
        do {
            let encrypted = try EncryptedMessage(base64Encoded: buffer)
            let privateKey = try PrivateKey(pemEncoded: privateKeyString)
            let clear = try encrypted.decrypted(with: privateKey, padding: .PKCS1)

            let data = clear.data
            let string = try clear.string(encoding: .utf8)
            print(string)
        } catch let error {
            print(error.localizedDescription)
        }
    }
}

private let publicKeyString = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCYiLkrrQp+hWIGIgFrWU882cHwe4NM6KQ7y6q3iRBWKZts+SD+O3Cl83sxMKv5JzWM81ni019NCQU1trzw/2EI2NGOda6n75A9jv1GDpnmwRm8WRgfictfuz+9E22HKDNm2e6+nssZ+JCbKZv9InzP25hIPTk+JRt2dyV64ahFTwIDAQAB"
private let privateKeyString = "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAJiIuSutCn6FYgYiAWtZTzzZwfB7g0zopDvLqreJEFYpm2z5IP47cKXzezEwq/knNYzzWeLTX00JBTW2vPD/YQjY0Y51rqfvkD2O/UYOmebBGbxZGB+Jy1+7P70TbYcoM2bZ7r6eyxn4kJspm/0ifM/bmEg9OT4lG3Z3JXrhqEVPAgMBAAECgYEAjfqlsXvOStpI1cCNZaip0tA2b2voWYwqYuY+r7vLEwiDfbme9kXJow6x2qWdTbsrY1mYj0OEb6Y3zTmdQQ3U+P6rVoMuCMHGYCOJkB1733bMb/KwCwJWLWx2DjhsUaR5U/R1et0NXIlJKqgS0dSWh1GaUo8kts/C48gcenaifpECQQDenzCNIuqMGE+hurPmx+TeO+YfmWOM0YqSLZEvXOmyvnDz/zIJHI3alHzAO+6X1wiW9Og6qrHSg7l/owaLor2zAkEAr2dhqpXP1mh8gHxgSY+Yvf7rZ3szu16z524h7Roh9Vs1YGlFDCipR9nokpik2VLYjJGyxvoOcJ3IfIgkgQHj9QJAMB7MydUgScP/gn/u3xWaPQdJiM8JG6k3gL1kwo4c3cwYckVZNWr8pqCuDodl3WBXtPmfMP8wjMZ4VESS55/3zQJAeTu6PH5ZbbdAPko4/v76Mm/sYtS7t8jIDbCIUGnciMomxWFdMP81qYzKe/B3GCJzvAzEBVU1/85+kNxEZspYtQJBAIOO8/Q6PjzitjHDR9ZMmMarggrdn+rGYrjlEH2+ryopuCO9AQP2Aq1x5b91I++v5fMJqoQ6MODZPlk/3XmR1Uc="

private let testedString = "weekend is coming!"
