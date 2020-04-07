//
//  ViewController.swift
//  Hash
//
//  Created by joey on 4/7/20.
//  Copyright © 2020 z1joey. All rights reserved.
//

import UIKit

class ViewController: UIViewController {
    override func viewDidLoad() {
        super.viewDidLoad()
        // Do any additional setup after loading the view.
        let someText = "This is a secret"
        print("SHA256: " + someText.sha256())
        print("SHA384: " + someText.sha384())
        print("SHA512: " + someText.sha512())
        print("MD5: " + someText.md5())
    }
}

