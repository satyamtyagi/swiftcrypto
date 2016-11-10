//
//  DataSingleton.swift
//  secmess
//
//  Created by Satyam Tyagi on 10/19/16.
//  Copyright © 2016 Satyam Tyagi. All rights reserved.
//

import Foundation
import Security
import LocalAuthentication

private let kSecMessECCApplicationTag = "com.secmessecc.key"
private let kSecMessECCKeySize = 256
private let kSecMessECCKeyType = kSecAttrKeyTypeECSECPrimeRandom
private let kSecMessECCLabel = "notouch.secmessdecry.ecckey"
private let kSecMessECCSignLabel = "touchid.secmesssign.ecckey"


final class CryptoSingleton {
    var decryptedMessage = "none"
    
    var eCCKeyExists = false
    var eCCPrivateKey, eCCPublicKey: SecKey?
    var eCCSignKeyExists = false
    var eCCSignPrivateKey, eCCSignPublicKey: SecKey?

    static let sharedInstance: CryptoSingleton = CryptoSingleton()
    
    // Can't init is singleton
    private init() {
        if let (tempECCPrivateKey, tempECCPublicKey) = getECCKeysRef() {
            eCCPrivateKey = tempECCPrivateKey
            eCCPublicKey = tempECCPublicKey
            eCCKeyExists = true
        }
        if let (tempECCSignPrivateKey, tempECCSignPublicKey) = getECCSignKeysRef() {
            eCCSignPrivateKey = tempECCSignPrivateKey
            eCCSignPublicKey = tempECCSignPublicKey
            eCCSignKeyExists = true
        }
    }
    
    
    /*!
     @function SecKeyCreateSignature
     @abstract Given a private key and data to sign, generate a digital signature.
     @param key Private key with which to sign.
     @param algorithm One of SecKeyAlgorithm constants suitable to generate signature with this key.
     @param dataToSign The data to be signed, typically the digest of the actual data.
     @param error On error, will be populated with an error object describing the failure.
     See "Security Error Codes" (SecBase.h).
     @result The signature over dataToSign represented as a CFData, or NULL on failure.
     @discussion Computes digital signature using specified key over input data.  The operation algorithm
     further defines the exact format of input data, operation to be performed and output signature.
     */
    //@available(iOS 10.0, *)
    //public func SecKeyCreateSignature(_ key: SecKey, _ algorithm: SecKeyAlgorithm, _ dataToSign: CFData, _ error: UnsafeMutablePointer<Unmanaged<CFError>?>?) -> CFData?
 
    func signECCPrivKey(message: String) -> String {
        print("signing with private key")
        if !eCCKeyExists {
            print("priv ECC key not found")
            return ""
        }
        guard let messageData = message.data(using: String.Encoding.utf8) else {
            print("bad message to sign")
            return ""
        }
        //finger print proteted SHA256 X 96
        guard let signData = SecKeyCreateSignature(eCCSignPrivateKey!, SecKeyAlgorithm.ecdsaSignatureMessageX962SHA256, messageData as CFData, nil) else {
            print("priv ECC error signing")
            return ""
        }
        
        //convert signed to base64 string
        let signedData = signData as Data
        let signedString = signedData.base64EncodedString(options: [])
        print("priv signed string", signedString)
        return signedString
    }

    
    /*!
     @function SecKeyVerifySignature
     @abstract Given a public key, data which has been signed, and a signature, verify the signature.
     @param key Public key with which to verify the signature.
     @param algorithm One of SecKeyAlgorithm constants suitable to verify signature with this key.
     @param signedData The data over which sig is being verified, typically the digest of the actual data.
     @param signature The signature to verify.
     @param error On error, will be populated with an error object describing the failure.
     See "Security Error Codes" (SecBase.h).
     @result True if the signature was valid, False otherwise.
     @discussion Verifies digital signature operation using specified key and signed data.  The operation algorithm
     further defines the exact format of input data, signature and operation to be performed.
     */
    //@available(iOS 10.0, *)
    //public func SecKeyVerifySignature(_ key: SecKey, _ algorithm: SecKeyAlgorithm, _ signedData: CFData, _ signature: CFData, _ error: UnsafeMutablePointer<Unmanaged<CFError>?>?) -> Bool
    func verifySignECCPubKeySupplied(message: String, signatueString: String, externalKeyB64String:String) -> Bool {
        //convert b64 key back to usable key
        let newPublicKeyData = Data(base64Encoded: externalKeyB64String, options: [])
        let newPublicParams: [String: Any] = [
            kSecAttrKeyType as String: kSecMessECCKeyType,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits as String: kSecMessECCKeySize as AnyObject
        ]
        guard let newPublicKey = SecKeyCreateWithData(newPublicKeyData as! CFData, newPublicParams as CFDictionary, nil) else {
            print("ECC verify failed to create pub key")
            return false
        }
        print("ecc verify pub key", newPublicKey)
        
        guard let messageData = message.data(using: String.Encoding.utf8) else {
            print("ECC bad message to verify")
            return false
        }
        
        guard let signatureData = Data(base64Encoded: signatueString, options: []) else {
            print("ECC bad signature to verify")
            return false
        }
        
        let verify = SecKeyVerifySignature(newPublicKey, SecKeyAlgorithm.ecdsaSignatureMessageX962SHA256, messageData as CFData, signatureData as CFData, nil)
        return verify
    }

    /*!
     @function SecKeyCreateEncryptedData
     @abstract Encrypt a block of plaintext.
     @param key Public key with which to encrypt the data.
     @param algorithm One of SecKeyAlgorithm constants suitable to perform encryption with this key.
     @param plaintext The data to encrypt. The length and format of the data must conform to chosen algorithm,
     typically be less or equal to the value returned by SecKeyGetBlockSize().
     @param error On error, will be populated with an error object describing the failure.
     See "Security Error Codes" (SecBase.h).
     @result The ciphertext represented as a CFData, or NULL on failure.
     @discussion Encrypts plaintext data using specified key.  The exact type of the operation including the format
     of input and output data is specified by encryption algorithm.
     */
    //@available(iOS 10.0, *)
    //public func SecKeyCreateEncryptedData(_ key: SecKey, _ algorithm: SecKeyAlgorithm, _ plaintext: CFData, _ error: UnsafeMutablePointer<Unmanaged<CFError>?>?) -> CFData?
    
    func encryptECCPubKeySupplied(message: String, externalKeyB64String: String) -> String {
        //convert b64 key back to usable key
        print("recvd b64 key", externalKeyB64String)
        let newPublicKeyData = Data(base64Encoded: externalKeyB64String, options: [])
        let newPublicParams: [String: Any] = [
            kSecAttrKeyType as String: kSecMessECCKeyType,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits as String: kSecMessECCKeySize as AnyObject
        ]
        guard let newPublicKey = SecKeyCreateWithData(newPublicKeyData as! CFData, newPublicParams as CFDictionary, nil) else {
            print("ECC encrypt could not create pub key")
            return ""
        }
        print("ecc encrypt pub key", newPublicKey)
        guard let messageData = message.data(using: String.Encoding.utf8) else {
            print("ECC bad message to encrypt")
            return ""
        }
        
        guard let encryptData = SecKeyCreateEncryptedData(newPublicKey, SecKeyAlgorithm.eciesEncryptionStandardX963SHA256AESGCM, messageData as CFData, nil) else {
            print("pub ECC error encrypting")
            return ""
        }
        
        let encryptedData = encryptData as Data
        let encryptedString = encryptedData.base64EncodedString(options: [])
        print("pub encrypted string", encryptedString)
        return encryptedString
    }

    
    /*!
     @function SecKeyCreateDecryptedData
     @abstract Decrypt a block of ciphertext.
     @param key Private key with which to decrypt the data.
     @param algorithm One of SecKeyAlgorithm constants suitable to perform decryption with this key.
     @param ciphertext The data to decrypt. The length and format of the data must conform to chosen algorithm,
     typically be less or equal to the value returned by SecKeyGetBlockSize().
     @param error On error, will be populated with an error object describing the failure.
     See "Security Error Codes" (SecBase.h).
     @result The plaintext represented as a CFData, or NULL on failure.
     @discussion Decrypts ciphertext data using specified key.  The exact type of the operation including the format
     of input and output data is specified by decryption algorithm.
     */
    //@available(iOS 10.0, *)
    //public func SecKeyCreateDecryptedData(_ key: SecKey, _ algorithm: SecKeyAlgorithm, _ ciphertext: CFData, _ error: UnsafeMutablePointer<Unmanaged<CFError>?>?) -> CFData?
    func decryptOnAuthECCPrivKey(encryptedString: String) -> String {
        if !eCCKeyExists {
            print("ECC priv key not found")
            return ""
        }
        
        //convert base64 back to encrypted bytes
        guard let messageData = Data(base64Encoded: encryptedString, options: []) else {
            print("ECC bad message to decrypt")
            return ""
        }
        if SecKeyIsAlgorithmSupported(eCCPrivateKey!, SecKeyOperationType.decrypt, SecKeyAlgorithm.eciesEncryptionStandardX963SHA256AESGCM) {
            print("ECC Decrypt Supported")
        }
        else {
            print("ECC Decrypt Unsupported")
            
        }
        let attrib = SecKeyCopyAttributes(eCCPrivateKey!)
        print("private key attributes are", attrib!)
        
        guard let decryptData = SecKeyCreateDecryptedData(eCCPrivateKey!, SecKeyAlgorithm.eciesEncryptionStandardX963SHA256AESGCM, messageData as CFData, nil) else {
            print("priv ECC error decrypting")
            return ""
        }
        
        
        let decryptedData = decryptData as Data
        guard let decryptedString = String(data: decryptedData, encoding: String.Encoding.utf8) else {
            print("ECC decrypt could not get string")
            return ""
        }
        
        print("priv ECC decrypted string", decryptedString)
        return decryptedString
    }
    
    
    func decryptECCPrivKey(encryptedString: String) {
        //force authenticate here
        let context = LAContext()
        guard context.canEvaluatePolicy(LAPolicy.deviceOwnerAuthenticationWithBiometrics, error: nil) else {
            print("failed to authenticate")
            return
        }
        print("decrypting")
        context.evaluatePolicy(
            LAPolicy.deviceOwnerAuthenticationWithBiometrics,
            localizedReason: "Private Key Decryption Requires Authentication",
            reply: { (status: Bool, error: Error? ) -> Void in
                if status {
                    print("success")
                    DispatchQueue.main.async {
                        self.decryptedMessage = self.decryptOnAuthECCPrivKey(encryptedString: encryptedString)
                        print(self.decryptedMessage)
                        NotificationCenter.default.post(
                            name: NSNotification.Name(rawValue: "encryptionComplete"),
                            object: nil
                        )
                    }
                }
                else {
                    print("failure")
                    DispatchQueue.main.async {
                        self.decryptedMessage = ""
                    }
                }
        }
        )
    }

    
    //kSecAttrAccessControl as String:    aclObject as AnyObject
    /*
     We will need to add secure enclave and use ECC
     kSecAttrKeyTypeECSECPrimeRandom
     @enum kSecAttrKeyType Value Constants
     @discussion Predefined item attribute constants used to get or set values
     in a dictionary. The kSecAttrKeyType constant is the key
     and its value is one of the constants defined here.
     @constant kSecAttrKeyTypeRSA.
     @constant kSecAttrKeyTypeECSECPrimeRandom.
     @constant kSecAttrKeyTypeEC This is legacy name for kSecAttrKeyTypeECSECPrimeRandom, new applications should not use it.
     
     @enum kSecAttrTokenID Value Constants
     @discussion Predefined item attribute constant used to get or set values
     in a dictionary. The kSecAttrTokenID constant is the key and its value
     can be kSecAttrTokenIDSecureEnclave.
     @constant kSecAttrTokenIDSecureEnclave Specifies well-known identifier of the
     token implemented using device's Secure Enclave. The only keychain items
     supported by the Secure Enclave token are 256-bit elliptic curve keys
     (kSecAttrKeyTypeEC).  Keys must be generated on the secure enclave using
     SecKeyGenerateKeyPair call with kSecAttrTokenID set to
     kSecAttrTokenIDSecureEnclave in the parameters dictionary, it is not
     possible to import pregenerated keys to kSecAttrTokenIDSecureEnclave token.
     */
    //generate keys
    func generateECCSignKeys() -> String {
        if eCCSignKeyExists {
            let externalKey = SecKeyCopyExternalRepresentation(eCCSignPublicKey!, nil)
            let externalKeyData = externalKey as! Data
            let externalKeyB64String = externalKeyData.base64EncodedString(options: [])
            print("found existing external ECC key b64", externalKeyB64String)
            
            return externalKeyB64String
            
        }
        //retrieve from keychain
        if let (tempPrivateKey, tempPublicKey) = getECCSignKeysRef() {
            eCCSignPrivateKey = tempPrivateKey
            eCCSignPublicKey = tempPublicKey
            eCCSignKeyExists = true
            let externalKey = SecKeyCopyExternalRepresentation(eCCSignPublicKey!, nil)
            let externalKeyData = externalKey as! Data
            let externalKeyB64String = externalKeyData.base64EncodedString(options: [])
            print("found existing keychain external ECC key b64", externalKeyB64String)
            
            return externalKeyB64String
        }
        guard let aclObject = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
            [.privateKeyUsage,.touchIDAny],
            nil
            ) else {
                print("could not create ACL error")
                return ""
        }
        print("ACL", aclObject)
        // ok generate keys
        // private key parameters
        let privateKeyParams: [String: AnyObject] = [
            kSecAttrAccessControl as String:    aclObject as AnyObject, //protect with touch id
            kSecAttrIsPermanent as String:      true as AnyObject,
        ]
        print("priv params", privateKeyParams)
        
        // global parameters for our key generation
        let parameters: [String: AnyObject] = [
            kSecAttrTokenID as String:          kSecAttrTokenIDSecureEnclave,
            kSecAttrKeyType as String:          kSecMessECCKeyType,
            kSecAttrKeySizeInBits as String:    kSecMessECCKeySize as AnyObject,
            kSecAttrLabel as String:            kSecMessECCSignLabel as AnyObject,
            kSecPrivateKeyAttrs as String:      privateKeyParams as AnyObject
        ]
        print("params", parameters)
        //let status = SecKeyGeneratePair(parameters as CFDictionary, &pubKey, &privKey)
        guard let eCCPrivKey = SecKeyCreateRandomKey(parameters as CFDictionary, nil) else {
            print("ECC KeyGen Error!")
            return ""
        }
        guard let eCCPubKey = SecKeyCopyPublicKey(eCCPrivKey) else {
            print("ECC Pub KeyGen Error")
            return ""
        }
        print("ECC keys", eCCPubKey, eCCPrivKey)
        
        //serialize b64 to share public key
        let externalKey = SecKeyCopyExternalRepresentation(eCCPubKey, nil)
        let externalKeyData = externalKey as! Data
        let externalKeyB64String = externalKeyData.base64EncodedString(options: [])
        print("ECC external key b64", externalKeyB64String)
        
        eCCSignPublicKey = eCCPubKey
        eCCSignPrivateKey = eCCPrivKey
        eCCKeyExists = true

        return externalKeyB64String
    }
    
    private func getECCSignKeysRef() -> (SecKey, SecKey)? {
        guard let eCCPrivKey = getECCSignPrivateKeyRef() else {
            print("ECC Pub Priv KeyGet Error")
            return nil
        }
        guard let eCCPubKey = SecKeyCopyPublicKey(eCCPrivKey) else {
            print("ECC Pub KeyGet Error")
            return nil
        }
        print("found ECC pub key in keychain", eCCPubKey, eCCPrivKey)
        return (eCCPrivKey, eCCPubKey)
    }
    
    private func getECCSignPrivateKeyRef() -> SecKey? {
        let parameters: [String: AnyObject] = [
            kSecClass as String:                kSecClassKey,
            kSecAttrKeyType as String:          kSecMessECCKeyType,
            kSecAttrKeySizeInBits as String:    kSecMessECCKeySize as AnyObject,
            kSecAttrLabel as String:            kSecMessECCSignLabel as AnyObject,
            kSecReturnRef as String:            true as AnyObject,
            kSecUseOperationPrompt as String:   "Authenticate to access keys" as AnyObject
        ]
        var eCCPrivKey: AnyObject?
        let status = SecItemCopyMatching(parameters as CFDictionary, &eCCPrivKey)
        if status != noErr {
            print("ECC Priv KeyGet Error!", status)
            return nil
        }
        print("found ECC priv key in keychain", eCCPrivKey as! SecKey)
        return (eCCPrivKey as! SecKey)
    }

    //generate keys
    func generateECCKeys() -> String {
        if eCCKeyExists {
            let externalKey = SecKeyCopyExternalRepresentation(eCCPublicKey!, nil)
            let externalKeyData = externalKey as! Data
            let externalKeyB64String = externalKeyData.base64EncodedString(options: [])
            print("found existing external ECC key b64", externalKeyB64String)
            
            return externalKeyB64String
            
        }
        //retrieve from keychain
        if let (tempPrivateKey, tempPublicKey) = getECCKeysRef() {
            eCCPrivateKey = tempPrivateKey
            eCCPublicKey = tempPublicKey
            eCCKeyExists = true
            let externalKey = SecKeyCopyExternalRepresentation(eCCPublicKey!, nil)
            let externalKeyData = externalKey as! Data
            let externalKeyB64String = externalKeyData.base64EncodedString(options: [])
            print("found existing keychain external ECC key b64", externalKeyB64String)
            
            return externalKeyB64String
        }
        guard let aclObject = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
            [.privateKeyUsage,.touchIDAny],
            nil
            ) else {
                print("could not create ACL error")
                return ""
        }
        print("ACL", aclObject)
        // ok generate keys
        // private key parameters
        let privateKeyParams: [String: AnyObject] = [
            kSecAttrCanDecrypt as String:       true as AnyObject,
            kSecAttrIsPermanent as String:      true as AnyObject,
            ]
        print("priv params", privateKeyParams)
        
        // global parameters for our key generation
        let parameters: [String: AnyObject] = [
            kSecAttrKeyType as String:          kSecMessECCKeyType,
            kSecAttrKeySizeInBits as String:    kSecMessECCKeySize as AnyObject,
            kSecAttrLabel as String:            kSecMessECCLabel as AnyObject,
            kSecPrivateKeyAttrs as String:      privateKeyParams as AnyObject
        ]
        print("params", parameters)
        //let status = SecKeyGeneratePair(parameters as CFDictionary, &pubKey, &privKey)
        guard let eCCPrivKey = SecKeyCreateRandomKey(parameters as CFDictionary, nil) else {
            print("ECC KeyGen Error!")
            return ""
        }
        guard let eCCPubKey = SecKeyCopyPublicKey(eCCPrivKey) else {
            print("ECC Pub KeyGen Error")
            return ""
        }
        print("ECC keys", eCCPubKey, eCCPrivKey)
        
        //serialize b64 to share public key
        let externalKey = SecKeyCopyExternalRepresentation(eCCPubKey, nil)
        let externalKeyData = externalKey as! Data
        let externalKeyB64String = externalKeyData.base64EncodedString(options: [])
        print("ECC external key b64", externalKeyB64String)
        
        eCCPublicKey = eCCPubKey
        eCCPrivateKey = eCCPrivKey
        eCCKeyExists = true
        
        return externalKeyB64String
    }
    
    private func getECCKeysRef() -> (SecKey, SecKey)? {
        guard let eCCPrivKey = getECCPrivateKeyRef() else {
            print("ECC Pub Priv KeyGet Error")
            return nil
        }
        guard let eCCPubKey = SecKeyCopyPublicKey(eCCPrivKey) else {
            print("ECC Pub KeyGet Error")
            return nil
        }
        print("found ECC pub key in keychain", eCCPubKey, eCCPrivKey)
        return (eCCPrivKey, eCCPubKey)
    }
    
    private func getECCPrivateKeyRef() -> SecKey? {
        let parameters: [String: AnyObject] = [
            kSecClass as String:                kSecClassKey,
            kSecAttrKeyType as String:          kSecMessECCKeyType,
            kSecAttrKeySizeInBits as String:    kSecMessECCKeySize as AnyObject,
            kSecAttrLabel as String:            kSecMessECCLabel as AnyObject,
            kSecReturnRef as String:            true as AnyObject,
            kSecUseOperationPrompt as String:   "Authenticate to access keys" as AnyObject
        ]
        var eCCPrivKey: AnyObject?
        let status = SecItemCopyMatching(parameters as CFDictionary, &eCCPrivKey)
        if status != noErr {
            print("ECC Priv KeyGet Error!", status)
            return nil
        }
        print("found ECC priv key in keychain", eCCPrivKey as! SecKey)
        return (eCCPrivKey as! SecKey)
    }


}





