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
import re
from time import gmtime, strftime
import os
global is_active
tim_votes =0;
linda_votes =0;
with open('VotingList') as f:
    for i, l in enumerate(f):
        pass
    i + 1
totalVoters = i+1


def main():
    start_server()


def start_server():
    host = 'localhost'
    port = 2244         # arbitrary non-privileged port
    
    #sys.argv[0] = input('Enter host: ')
    #sys.argv[1] = input('Enter port: ')
    
    
    soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)   # SO_REUSEADDR flag tells the kernel to reuse a local socket in TIME_WAIT state, without waiting for its natural timeout to expire
    print("Socket created")
    
     
    try:
        soc.bind((host, port))
    except:
        print("Bind failed. Error : " + str(sys.exc_info()))
        sys.exit()

    soc.listen(10)       # queue up to 5 requests
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
    fr = open('serv_priv.der', 'rb') 
    private_key = RSA.importKey(fr.read())
    #print(private_key)
    return private_key

def client_thread(connection, ip, port, max_buffer_size = 10000):

        client_input = receive_input(connection, max_buffer_size)


def receive_input(connection, max_buffer_size):
    
    data_recieved = connection.recv(max_buffer_size)
    client_input = data_recieved[0:128]
    digi_Sign = data_recieved[128:]
    decryptor = PKCS1_OAEP.new(read_theFile())
    decrypted = decryptor.decrypt(client_input)
    decryptor_vinfo = decrypted.decode()
    verifySig(decryptor_vinfo, digi_Sign)  
    vinfo_split = []
    vinfo_split = mysplit(decryptor_vinfo)
    vname_split = vinfo_split[0]
    vreg_split = vinfo_split[1]
    #print(vname_split)
    #print(vreg_split)
    global tim_votes;
    global linda_votes;
    RegExist(vreg_split)
    
    if VnameExist(vname_split)>=0 and RegExist(vreg_split)>=0: 
        print("VnameExist")
        connection.sendall("1".encode(encoding='utf_8', errors='strict'))
        while True:
            voter_choiceRecv = connection.recv(max_buffer_size)
            if(voter_choiceRecv == b'1' or voter_choiceRecv==b'2' or voter_choiceRecv==b'3'):
                if(voter_choiceRecv==b'1'):
                    if(RegExist_inHistory(vreg_split))>=0:
                        connection.sendall("0".encode(encoding='utf_8', errors='strict'))
                    else:
                        connection.sendall("1".encode(encoding='utf_8', errors='strict'))
                        voting_recieved = connection.recv(max_buffer_size)
                        decryptor = PKCS1_OAEP.new(read_theFile())
                        decrypted = decryptor.decrypt(voting_recieved)
                        dec_votrecv = decrypted.decode()
                        print(dec_votrecv)
                        if(dec_votrecv == "1"):
                            with open("Result") as f:
                                lines = f.readlines()
                            tim_votes += 1
                            lines[0] = "Tim\t%d\n" % tim_votes
                            with open("Result", "w") as f:
                                f.writelines(lines)
                            update_History(vreg_split)
                           
                            
                            
                        if(dec_votrecv == "2"):
                            with open("Result") as f:
                                lines = f.readlines()
                            linda_votes += 1
                            lines[1] = "Linda\t%d\n" % linda_votes
                            with open("Result", "w") as f:
                                f.writelines(lines)
                            update_History(vreg_split)
                        with open('HistoryFile') as f:
                            for i, l in enumerate(f):
                                pass
                            i + 1
                        totalVoted = i+1
                                    
                        if(totalVoters==totalVoted):
                                if(tim_votes>linda_votes):
                                    print("Tim Wins:%d " % tim_votes)
                                else:
                                    print("Linda Wins:%d " % linda_votes)
                            
                if(voter_choiceRecv==b'2'):
                    if (os.stat('HistoryFile').st_size == 0):
                        connection.sendall("1".encode(encoding='utf_8', errors='strict'))
                    else:
                        if (RegHistory_Exist(vreg_split)>=0):
                            votedInfo = Time_Voted(vreg_split)
                            print(votedInfo)
                            connection.sendall(votedInfo.encode(encoding='utf_8', errors='strict'))
                        else:
                            connection.sendall("0".encode(encoding='utf_8', errors='strict'))
                
                if(voter_choiceRecv==b'3'):
                    if (os.stat('HistoryFile').st_size == 0):
                        connection.sendall("1".encode(encoding='utf_8', errors='strict'))
                    else:    
                        with open('HistoryFile') as f:
                            for i, l in enumerate(f):
                                pass
                            i + 1
                        totalVoted = i+1
                        if(totalVoters==totalVoted):
                            if(tim_votes>linda_votes):
                                str = "Tim Wins:%d " % tim_votes
                                connection.sendall(str.encode(encoding='utf_8', errors='strict'))
                            else:
                                str1 = "Linda Wins:%d " % linda_votes
                                connection.sendall(str1.encode(encoding='utf_8', errors='strict'))
                        else:
                            connection.sendall("0".encode(encoding='utf_8', errors='strict'))
                            
                        
                    
    else:
        print("VnameorRegDoesntExist")
        connection.sendall("0".encode(encoding='utf_8', errors='strict'))
        is_active = False
   



def process_input(input_str):
    print("Processing the input received from client")

    return "Hello " + str(input_str).upper()

def update_History(regNum):
    with open('HistoryFile', 'a') as outfile:
        outfile.write(str((regNum)+(strftime("\t%Y-%m-%d %H:%M:%S", gmtime()))+("\n")))
    
    #myfile = open('HistoryFile','a')
    #myfile.write(str((regNum)+(strftime("\t%Y-%m-%d %H:%M:%S", gmtime()))))
    outfile.close()
    

def openFile(filename):
    f = open(filename, 'rb') 
    key = RSA.importKey(f.read())
    #print(key)
    #f.close
    return key

def VnameExist(vname):
    fr = open('VotingList', 'r')
    lines=fr.readlines()
    result=[]
    for x in lines:
        result.append(x.split()[0])
    for xd, x in enumerate(result):
        if x==vname:
            return 1;   
    return -1 
    print("VnameExist = {}" .format(result))
    fr.close()

def mysplit(decryptedText):
    head = decryptedText.rstrip('0123456789')
    tail = decryptedText[len(head):]
    return head, tail


def RegExist(vreg):
    fr = open('VotingList', 'r')
    lines=fr.readlines()
    result=[]
    for x in lines:
        result.append(x.split()[1])
    for xd, x in enumerate(result):
        if x==vreg:
            return 1; 
    return -1
    print("RegNum = {}"  .format(result))
    fr.close() 
    
def RegHistory_Exist(vreg):
    fr = open('HistoryFile', 'r')
    lines=fr.readlines()
    result=[]
    for x in lines:
        result.append(x.split()[0])
    for xd, x in enumerate(result):
        if x==vreg:
            return 1; 
    return -1
    print("RegNum = {}"  .format(result))
    fr.close() 

def Time_Voted(vreg):
    fr = open('HistoryFile', 'r')
    lines=fr.readlines()
    result=[]
    time=[]
    for x in lines:
        result.append(x.split()[0])
        time.append(x.split()[1])
    for xd, x in enumerate(result):
        if x==vreg:
            print(time[xd])
            return time[xd]
    return -1
    print("RegNum = {}"  .format(result))
    fr.close()


def RegExist_inHistory(vreg):
    fr = open('HistoryFile', 'r')
    lines=fr.readlines()
    result=[]
    for x in lines:
        result.append(x.split()[0])
    for xd, x in enumerate(result):
        if x==vreg:
            return 1; 
    return -1
    print("RegNum = {}"  .format(result))
    fr.close()    
    

def verifySig(data, signedData):
        my_data_asBytes =str.encode(data)
        print(my_data_asBytes)
        digest = SHA256.new()
        digest.update(my_data_asBytes)
        verifier = PKCS1_v1_5.new(openFile('cli_pub.der'))
        if (verifier.verify(digest, signedData)):
            print("Verified")
        else:
            print("not verified")
                   
        #return True

if __name__ == "__main__":
    main()