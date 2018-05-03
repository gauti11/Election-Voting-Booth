from RSA import Rsa


class KeyGeneration:
    def __init__(self):
            self.R = Rsa()
             
    def generate(self):
            self.R = Rsa()
            self.R.getPublicKey
            print(self.R.getPublicKey())
            self.R.getPrivateKey
            print(self.R.getPrivateKey())

    
        
    #def Encryption(self):   
            #self.R.encryptMessage(publickey, plainText)
            
testinstance = KeyGeneration()
testinstance.generate()
