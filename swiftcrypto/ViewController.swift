//
//  ViewController.swift
//  swiftcrypto
//
//  Created by Satyam Tyagi on 11/9/16.
//  Copyright © 2016 Satyam Tyagi. All rights reserved.
//

import UIKit

class ViewController: UIViewController {

    @IBOutlet weak var enteredText: UITextField!
    @IBOutlet weak var encryptedText: UITextView!
    @IBOutlet weak var decryptedText: UITextField!
    @IBOutlet weak var verificationResult: UITextField!
    var pubEncKey = ""
    var pubSignKey = ""
    
    @IBAction func encryptAndSign(_ sender: UIButton) {
        //take entered text
        //encrypt with public key
        guard let clearText = enteredText.text else {
            print("no clear text")
            return
        }
        let encryptedString =
            CryptoSingleton.sharedInstance.encryptECCPubKeySupplied(
                message: clearText,
                externalKeyB64String: pubEncKey)
        print("encryptedString:", encryptedString)
        //take the encrypted output
        //sign with private key (Requires TouchId)
        let signString =
            CryptoSingleton.sharedInstance.signECCPrivKey(message: encryptedString)
        print("signString", signString)
        //concat ":" separator and assign to encrypted text
        encryptedText.text = encryptedString + ":" + signString
    }
    
    
    @IBAction func decryptAndVerify(_ sender: UIButton) {
        //take the encyrpted signed text
        guard let encryptText = encryptedText.text else {
            print("no encryption text")
            return
        }
        //parse with ":" separator
        let encryptArray = encryptText.components(separatedBy: ":")
        if encryptArray.count == 2 {
            let encryptString = encryptArray[0]
            let signString = encryptArray[1]
            //verify the signature
            //assign result to verify Result
            if CryptoSingleton.sharedInstance.verifySignECCPubKeySupplied(
                message: encryptString,
                signatueString: signString,
                externalKeyB64String: pubSignKey) {
                verificationResult.text = "Success!"
            }
            else {
                verificationResult.text = "Failure!"
            }
            //decrypt with private key (Require TouchId)
            CryptoSingleton.sharedInstance.decryptECCPrivKey(encryptedString: encryptString)
        }
        else {
            print("failed to parse", encryptArray.count, encryptText)
            for stringElem in encryptArray {
                print(stringElem)
            }
        }
    }
    
    func encryptionComplete() {
        //assign decryption result to decryptedText
        decryptedText.text = CryptoSingleton.sharedInstance.decryptedMessage
    }
    
    override func viewDidLoad() {
        super.viewDidLoad()
        // Do any additional setup after loading the view, typically from a nib.
        pubEncKey = CryptoSingleton.sharedInstance.generateECCKeys()
        pubSignKey = CryptoSingleton.sharedInstance.generateECCSignKeys()
        
        NotificationCenter.default.addObserver(forName: NSNotification.Name(rawValue: "encryptionComplete"), object: nil, queue: nil) { _ in self.encryptionComplete()}
    }

    override func didReceiveMemoryWarning() {
        super.didReceiveMemoryWarning()
        // Dispose of any resources that can be recreated.
    }


}

