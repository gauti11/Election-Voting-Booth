import Crypto
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Signature import PKCS1_v1_5 
from Crypto.Hash import SHA256 
import ast



random_generator = Random.new().read
key = RSA.generate(1024, random_generator) #generate pub and priv key
message = b'hello world'
publickey = key.publickey() # pub key export for exchange
encryptor = PKCS1_OAEP.new(publickey)
encrypted = encryptor.encrypt(message)
#message to encrypt is in the above line 'encrypt this message'

#digitalSignature


private_key=key.exportKey()
#print (private_key)
h = SHA256.new(message)
priv_key = RSA.importKey(private_key)
signer = PKCS1_v1_5.new(priv_key)
signature = signer.sign(h)
#print (signature)

print (encrypted + signature)

#print ('encrypted message:', encrypted) #ciphertext
f = open ('encryption.txt', 'w')
f.write(str(encrypted)) #write ciphertext to file
f.close()


#verifying Signature
if (signer.verify(h, signature)):
    print("Verified")
else:
    print("not verified")


#decrypted code below

f = open('encryption.txt', 'r')
message = f.read()


decryptor = PKCS1_OAEP.new(key)
decrypted = decryptor.decrypt(ast.literal_eval(str(encrypted)))




print ('decrypted', decrypted)

f = open ('encryption.txt', 'w')
f.write(str(message))
f.write(str(decrypted))
f.close()
