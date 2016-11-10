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
    
    
    @IBAction func encryptAndSign(_ sender: UIButton) {
        //take entered text
        //get the encryption public key
        let pubKey = CryptoSingleton.sharedInstance.generateECCKeys()
        //encrypt with public key
        guard let clearText = enteredText.text else {
            return
        }
        let encryptedString =
            CryptoSingleton.sharedInstance.encryptECCPubKeySupplied(
                message: clearText,
                externalKeyB64String: pubKey)
        
        //take the encrypted output
        //sign with private key (Requires TouchId)
        let signString =
            CryptoSingleton.sharedInstance.signECCPrivKey(message: encryptedString)
        //concat ":" separator and assign to encrypted text
        encryptedText.text = encryptedString + ":" + signString
    }
    
    
    @IBAction func decryptAndVerify(_ sender: UIButton) {
        //take the encyrpted signed text
        guard let encryptText = encryptedText.text else {
            return
        }
        //parse with ":" separator
        let encryptArray = encryptText.components(separatedBy: ":")
        if encryptArray.count == 3 {
            let encryptString = encryptArray[0]
            let signString = encryptArray[1]
            //get the signature public key
            let signPubKey = CryptoSingleton.sharedInstance.generateECCSignKeys()
            //verify the signature
            //assign result to verify Result
            if CryptoSingleton.sharedInstance.verifySignECCPubKeySupplied(
                message: encryptString,
                signatueString: signString,
                externalKeyB64String: signPubKey) {
                verificationResult.text = "Success!"
            }
            else {
                verificationResult.text = "Failure!"
            }
            //decrypt with private key (Require TouchId)
            CryptoSingleton.sharedInstance.decryptECCPrivKey(encryptedString: encryptString)
        }
    }
    
    func encryptionComplete() {
        //assign decryption result to decryptedText
        decryptedText.text = CryptoSingleton.sharedInstance.decryptedMessage
    }
    
    override func viewDidLoad() {
        super.viewDidLoad()
        // Do any additional setup after loading the view, typically from a nib.
        NotificationCenter.default.addObserver(forName: NSNotification.Name(rawValue: "encryptionComplete"), object: nil, queue: nil) { _ in self.encryptionComplete()}
    }

    override func didReceiveMemoryWarning() {
        super.didReceiveMemoryWarning()
        // Dispose of any resources that can be recreated.
    }


}

