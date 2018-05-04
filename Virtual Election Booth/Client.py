"Client"

#socket_echo_client.py
import socket
import sys
from RSA import Rsa
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import PKCS1_v1_5 
from Crypto.Hash import SHA256 



class DataCheck:
    def printMenu(self, userName):
        print("Welcome,"+ userName)
        print("    Main Menu")
        print("Please Enter a Number (1-4")
        print("1. Vote")
        print("2. My vote history")
        print("3. Election result")
        print("4. Quit")
    
    def choice(self,x):
        return {
            '1' : sock.sendall(x)
            
            }.get(x)

f = open('serv_pub.der', 'rb') 
public_key = RSA.importKey(f.read())
print(public_key)
f.close

f = open('cli_priv.der', 'rb') 
private_key_dsign = RSA.importKey(f.read())
print(private_key_dsign)
f.close

# Create a TCP/IP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Connect the socket to the port where the server is listening
R = Rsa()
server_address = ('localhost', 2244)
print('connecting to {} port {}'.format(*server_address))
sock.connect(server_address)

try:

    # Send data
    voterName = input("Enter VoterName: ")
    regNum = input("Enter RegNum: ")
    message = voterName + regNum
    
    Voting_details =str.encode(message)
    type(Voting_details)
    #message = b'This is the message.  It will be repeated.'
    encryptor = PKCS1_OAEP.new(public_key)
    encrypted = encryptor.encrypt(Voting_details)
    #print("length of string: ", len(encrypted))

    #Digital Signature
    h = SHA256.new(Voting_details)
    #priv_key = RSA.importKey(private_key_dsign)
    signer = PKCS1_v1_5.new(private_key_dsign)
    signature = signer.sign(h)
    #print(signature)
    #print(Voting_details)
    encryp_sign = encrypted + signature
    
    
    #print('sending {!r}'.format(message))
    
    sock.sendall(encryp_sign)

    # Look for the response
    amount_received = 0
    amount_expected = len(message)
    data = sock.recv(16)
    Test = DataCheck()
    if(data==b'1'):
        while True:
            print("Welcome, {}" .format(voterName)  )
            print("    Main Menu")
            print("Please Enter a Number (1-4")
            print("1. Vote")
            print("2. My vote history")
            print("3. Election result")
            print("4. Quit")
            voterChoice = input("Enter VoterChoice: ")
            try:
                int(voterChoice)
            except ValueError:
                print ("This is not a number")
            if(voterChoice=="1" or voterChoice=="2" or voterChoice=="3" or voterChoice=="4"):
                if(voterChoice =="4"):
                    sock.close()
                    sys.exit()
                if(voterChoice=="1"):
                    voter_choice = str.encode(voterChoice)
                    type(voter_choice)
                    sock.sendall(voter_choice)
                    voting_eligible = sock.recv(16)
                    if(voting_eligible == b'0'):
                        print("Already Voted")
                    elif(voting_eligible == b'1'):
                        print("Please enter a number (1-2)")
                        print("1.Tim")
                        print("2.Linda")
                        candidChoice = input("Enter the CandidateChoice: ")
                        try:
                            int(candidChoice)
                        except ValueError:
                            print ("This is not a number")
                        candid_Choice = str.encode(candidChoice)
                        type(candid_Choice)    
                        encryptor_candChoice = PKCS1_OAEP.new(public_key)
                        encrypted_candChoice = encryptor_candChoice.encrypt(candid_Choice)
                        sock.sendall(encrypted_candChoice)
                        test = sock.recv(16)
                        
        amount_received += len(data)
        print('received {!r}'.format(data))

finally:
    print('closing socket')
    sock.close()


