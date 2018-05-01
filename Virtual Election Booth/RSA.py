import Crypto
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Signature import PKCS1_v1_5 
from Crypto.Hash import SHA256 
import ast


class Rsa:
    def __init__(self):
        self.random_generator = Random.new().read
        self.key = RSA.generate(1024, self.random_generator) #generate pub and priv key
        self.message = b'hello world'
        self.publickey = self.key.publickey() # pub key export for exchange
    
    def getPublicKey(self):
        f = open ('VF_PubKey1.der', 'wb')
        f.write((self.publickey.exportKey())) #write ciphertext to file
        f.close()
        #print(self.publickey.exportKey())
        return self.publickey.exportKey()
    
    def getPrivateKey(self):
        f = open ('VF_PrivKey1.der', 'wb')
        f.write((self.key.exportKey())) #write ciphertext to file
        f.close()
        return self.key.exportKey()
    
    def encryptMessage(self,publickey, plainText):
        encryptor = PKCS1_OAEP.new(publickey)
        plainText = plainText.encode("utf-8")
        encrypted = encryptor.encrypt(plainText)
        print(encrypted)
        return encrypted
        
    #message to encrypt is in the above line 'encrypt this message'
    
    #digitalSignature
    
    
   # private_key=key.exportKey()
    #print (private_key)
    def DigitalSig(self,private_key, plainText):
        h = SHA256.new(plainText)
        priv_key = RSA.importKey(private_key)
        signer = PKCS1_v1_5.new(priv_key)
        signature = signer.sign(h)
        return signature,h,signer
    #print (signature)
    def keySignature(self):
        print (self.encrypted + self.signature)
    
    #print ('encrypted message:', encrypted) #ciphertext
    def CipherTextToFile(self,encrypted):
        f = open ('encryption.txt', 'w')
        f.write(str(encrypted)) #write ciphertext to file
        f.close()
        
    
    def verifyingSignature(self, h, signature):
        if (self.signer.verify(h, signature)):
            print("Verified")
        else:
            print("not verified")
    
    
    #decrypted code below
    def decryptMessage(self, encrypted):
        f = open('encryption.txt', 'r')
        self.encrypted = f.read()
        decryptor = PKCS1_OAEP.new(self.key)
        decrypted = decryptor.decrypt(ast.literal_eval(str(encrypted)))
        return decrypted
    
    def PlanTextToFile(self, decrypted):
            f = open ('encryption.txt', 'w')
            f.write(str(self.message))
            f.write(str(decrypted))
            f.close()
