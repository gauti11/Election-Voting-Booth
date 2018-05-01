import socket
import sys
import traceback
from threading import Thread
from Crypto.PublicKey import RSA
from base64 import b64decode
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import PKCS1_v1_5 
from Crypto.Hash import SHA256 
import ast


def main():
    start_server()


def start_server():
    host = 'localhost'
    port = 2244         # arbitrary non-privileged port
    
    soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)   # SO_REUSEADDR flag tells the kernel to reuse a local socket in TIME_WAIT state, without waiting for its natural timeout to expire
    print("Socket created")

    try:
        soc.bind((host, port))
    except:
        print("Bind failed. Error : " + str(sys.exc_info()))
        sys.exit()

    soc.listen(5)       # queue up to 5 requests
    print("Socket now listening")

    # infinite loop- do not reset for every requests
    while True:
        connection, address = soc.accept()
        ip, port = str(address[0]), str(address[1])
        print("Connected with " + ip + ":" + port)

        try:
            Thread(target=client_thread, args=(connection, ip, port)).start()
        except:
            print("Thread did not start.")
            traceback.print_exc()

    soc.close()

def read_theFile():
    fr = open('VF_PrivKey.der', 'rb') 
    private_key = RSA.importKey(fr.read())
    print(private_key)
    return private_key

def client_thread(connection, ip, port, max_buffer_size = 10000):
    is_active = True

    while is_active:
        client_input = receive_input(connection, max_buffer_size)

        if "--QUIT--" in client_input:
            print("Client is requesting to quit")
            connection.close()
            print("Connection " + ip + ":" + port + " closed")
            is_active = False
        else:
            print("Processed result: {}".format(client_input))
            connection.sendall("-".encode("utf8"))


def receive_input(connection, max_buffer_size):
    
    data_recieved = connection.recv(max_buffer_size)
    client_input = data_recieved[0:128]
    digi_Sign = data_recieved[129:]
    print(digi_Sign)
    #verifySig(digi_Sign)
    decryptor = PKCS1_OAEP.new(read_theFile())
    decrypted = decryptor.decrypt(ast.literal_eval(str(client_input)))
    decryptor_asStr = decrypted.decode()
    type(decryptor_asStr)
    print(decryptor_asStr)
        
    client_input_size = sys.getsizeof(client_input)
    if client_input_size > max_buffer_size:
            print("The input size is greater than expected {}".format(client_input_size))
    result = process_input(client_input)
    
    return result


def process_input(input_str):
    print("Processing the input received from client")

    return "Hello " + str(input_str).upper()

def openFile(filename):
    f = open(filename, 'rb') 
    key = RSA.importKey(f.read())
    #print(key)
    f.close
    return key

def verifySig(data):
        digest = SHA256.new(data)
        signer = PKCS1_v1_5.new('VF_PrivKey1')
        sig = signer.sign(digest)
        verifier = PKCS1_v1_5.new(openFile('VF_PubKey.der'))
        verified = verifier.verify(digest, sig) 
        assert verified, 'Signature verification failed'
        print ('Successfully verified message')       
        return True

if __name__ == "__main__":
    main()