1. Gautam Beri and gberi1@binghamton.edu
2. Python
3. Eclipse. My bingsuns and Linux Not working. Worked in PyDev environment on eclipse.
4. Have to run Seperate Server and then the respective Clients. For now Maximum 5 clients can be connected but number can be increased.
5.  Code for Encryp/Decryption
	ncryptor = PKCS1_OAEP.new(public_key)
	encrypted = encryptor.encrypt(Voting_details)
	h = SHA256.new(Voting_details)
	signer = PKCS1_v1_5.new(private_key_dsign)
       signature = signer.sign(h)
       encryp_sign = encrypted + signature
	decryptor = PKCS1_OAEP.new(read_theFile())
       decrypted = decryptor.decrypt(client_input)
       decryptor_vinfo = decrypted.decode()
       verifySig(decryptor_vinfo, digi_Sign)  
6. Code For Concurrent
	soc.listen(10) 
print("Socket now listening")
while True:
       connection, address = soc.accept()
	ip, port = str(address[0]), str(address[1])
       print("Connected with " + ip + ":" + port)
 try:
         Thread(target=client_thread, args=(connection, ip, port)).start()
except:  
print("Thread did not start.")           
traceback.print_exc()
7. Everytime The code is to be run, empty the historyFile and make the result to 0. The code is entitled as per the specifications. 2 Candidates. But voterlist can be added and expanded as per the need.Corner Cases has been handled as far as possible. This code can be expanded as per the needs.
