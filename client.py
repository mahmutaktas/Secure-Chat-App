import socket
import pickle
import numpy as np
import sys
import errno
import random
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_pem_public_key
import os
from Cryptodome.Protocol.KDF import PBKDF2
from Cryptodome.Hash import SHA512
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
#
##
import hmac
import hashlib
##

HEADERSIZE = 10




def pad(s):
    padding_size = 16 - len(s) % 16
    return s + b"\0" * padding_size, padding_size

def create_nonce():
    nonce = ''.join(map(str,np.random.randint(0,9,8)))
    return nonce

with open("server_public.pem", "rb") as key_file:
    server_public_key = serialization.load_pem_public_key(
    key_file.read(),
    backend=default_backend()
)

my_username = input("enter a username: ")

#Create log file
log_file = open(f"{my_username}_log.txt", "w")

#Create line indicator to seperate line more clearly
line_indicator = "\n\n------------------------------------------------------------\n\n"

if True:
    #Getting server public key from file
    server_pem = server_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    #Creating this client's private-public set of keys
    alice_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    alice_public_key = alice_private_key.public_key()


    alice_pem = alice_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    alice_pub_key_bytes = str.encode(alice_pem.decode("utf-8"))

if True:
    clientSocket = socket.socket()
    host = socket.gethostname()
    port = 1233

    print('Waiting for connection')
    try:
        clientSocket.connect((host, port))      #Connecting to the server
    except socket.error as e:
        print(str(e))



    #sending initial msg to the server
    client_init_msg = {
        'name': "alice",
        'public_key': alice_pem
    }

    log_file.write(f"Initial msg sent by client to server: {client_init_msg} {line_indicator}")
    clientSocket.send(pickle.dumps(client_init_msg))

    #recving cert from the server
    response = clientSocket.recv(1024)
    signed_cert = pickle.loads(response)
    server_sign = signed_cert['public_key']

    log_file.write(f"Received signed cert from server: {signed_cert} {line_indicator}")

    # verifying cert from server

    server_public_key.verify(
        server_sign,
        alice_pub_key_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    log_file.write(f"Certificate has been verified {line_indicator}")
    print("USER CERTIFICATE HAS BEEN VERIFIED")

    #Getting answer for establishing connection to the other user
    answer = input('Do you wanna text other user: ')
    # send yes msg to the server
    msg_dict = {
        'msg': answer
    }
    log_file.write(f"Answer for wanting connection to other client: {answer} {line_indicator}")
    clientSocket.send(pickle.dumps(msg_dict))

    if answer == "yes":

        #recive nonce from other user
        nonce_pkl = clientSocket.recv(2048)
        nonce = pickle.loads(nonce_pkl)['nonce']
        bytes_nonce = str.encode(nonce)
        #
        other_User_Public_Key_Pem = pickle.loads(nonce_pkl)['public_key']                   #get other user public key perm
        other_User_Public_Key = load_pem_public_key(other_User_Public_Key_Pem,
                                                    backend=default_backend())              # convert perm to public key
        #

        #sign nonce and send to other user
        cipher_nonce = alice_private_key.sign(
            bytes_nonce,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        log_file.write(f"Received nonce: {nonce} -- Received other client pub key: {other_User_Public_Key} {line_indicator}")
        clientSocket.send(pickle.dumps(cipher_nonce))


        #recieve acked msg
        ack_msg_pkl= clientSocket.recv(2048)
        ack_msg = pickle.loads(ack_msg_pkl)
        log_file.write(f"Acked messsage: {ack_msg} {line_indicator}")
        print(f"ACKED MSG: {ack_msg}")

        #GENERATE MASTER KEY SEND TO OTHER USER
        #
        random.seed(nonce)                                                                  # using nonce as seed
        master_Key = random.randrange(1e47, 1e48 - 1)                                       # creation of master key based on seed value as nonce
        # print(master_Key)

        master_Key_String = str(master_Key)                                                 # transform into string
        master_Key_Byte = bytes(master_Key_String, 'utf-8')                                 # transform into byte
        # print(master_Key_Byte)
        cipher_Master_Key = other_User_Public_Key.encrypt(
            master_Key_Byte,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        #Creating keys for file encryption
        key = os.urandom(32)
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        file_encryptor = cipher.encryptor()
        file_decryptor = cipher.decryptor()
        file_keys = key + iv        #Combining file key and iv

        #Encrypting file keys
        file_keys_enc = other_User_Public_Key.encrypt(
            file_keys,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )


        master_Key_dict = {                                                                 # create dictionary to use send to sw
            'master_key': cipher_Master_Key,
            'file_keys_enc': file_keys_enc
        }

        log_file.write(f"Master key and file encryption key to sent server: {master_Key_dict} {line_indicator}")
        clientSocket.send(pickle.dumps(master_Key_dict))                                    # send sw with pickle

        salt = b'Hello'
        final_Key = PBKDF2(master_Key_Byte, salt, 48, count=1000000, hmac_hash_module=SHA512)
        Encryption_Key = final_Key[:32]                                                             #32bit AES key for encryption
        IV_key = final_Key[32:48]                                                                   # 16bit IV vector key
        Hash_Key = final_Key[16:48]                                                                 # 32bit Hash Key for MAC
        #print(str(IV_key))
        #

    else:
        print("waiting for someone to connect...")

        #get other user pem public key
        requested_connection_pickle = clientSocket.recv(2048)
        requested_connection = pickle.loads(requested_connection_pickle)
        other_pub_key_pem = requested_connection['public_key']
        other_pub_key_byte = str.encode(other_pub_key_pem)
        #print(f"other public key {other_pub_key_byte}")

        log_file.write(f"Connection request message with client's public key': {requested_connection} {line_indicator}")

        #convert other user pem public key to public key
        other_pub_key = load_pem_public_key(other_pub_key_byte, backend=default_backend())

        #create nonce and send to other user
        nonce = create_nonce()
        response_dict = {
            'nonce': nonce,
            'public_key': alice_pem
        }

        log_file.write(f"Responsing with nonce and publick key: {response_dict} {line_indicator}")
        clientSocket.send(pickle.dumps(response_dict))

        #recieve signed nonce and compare with the self nonce
        encrypt_nonce_pkl = clientSocket.recv(2048)


        encrypt_nonce = pickle.loads(encrypt_nonce_pkl)
        log_file.write(f"Received encrpyted nonce: {encrypt_nonce} {line_indicator}")
        #print(f"ENCRYPT NONCE: {encrypt_nonce}")
        byte_nonce = str.encode(nonce)
        #print(f"BYTES NONCE: {byte_nonce}")

        other_pub_key.verify(
            encrypt_nonce,
            byte_nonce,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        #if verifying successful send ack msg
        print("SUCCESFULLY HANDSHAKED")
        ack_msg = "acked"
        log_file.write(f"Ack message: {ack_msg} {line_indicator}")
        clientSocket.send(pickle.dumps(ack_msg))

        #Extracting master key and file keys
        encrypted_Master_Key_pkl = clientSocket.recv(16384)
        encrypted_Master_Key_dict = pickle.loads(encrypted_Master_Key_pkl)
        encrypted_Master_Key = encrypted_Master_Key_dict['master_key']
        encrypted_file_keys = encrypted_Master_Key_dict['file_keys_enc']

        log_file.write(f"Received master key: {encrypted_Master_Key}\nReceived file key: {encrypted_file_keys} {line_indicator}")

        #Decrypting file keys
        decrypted_file_keys = alice_private_key.decrypt(
            encrypted_file_keys,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        #Seperating key and iv and creating encryptor and decryptor
        file_key = decrypted_file_keys[0:32]
        file_iv = decrypted_file_keys[32:len(decrypted_file_keys)]

        cipher = Cipher(algorithms.AES(file_key), modes.CBC(file_iv), backend=default_backend())
        file_encryptor = cipher.encryptor()
        file_decryptor = cipher.decryptor()


        #Decrypting master key
        decrypted_Master_Key = alice_private_key.decrypt(
            encrypted_Master_Key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )


        salt = b'Hello'
        final_Key = PBKDF2(decrypted_Master_Key, salt, 48, count=1000000, hmac_hash_module=SHA512)              #create KDF function for more randomness
        Encryption_Key = final_Key[:32]                                                                         #32 bit encrytion key for AES
        IV_key = final_Key[32:48]                                                                               #16bit key for IV vector
        Hash_Key = final_Key[16:48]                                                                             #32bit Hash Key for MAC
        #print(keys)
        #

        print("TEXT PHASE: ")


while True:

    filename = ""
    enc_file = b""

    message = input(f'{my_username} > ')
    clientSocket.setblocking(False) #Removing blocking in order to avoid sockets' recv and send block

    if len(message)>0:

        #Detect if client wants to send file
        if message.split()[0] == "sendfile":
            filename = message.split()[1]
            print(f"FİLE NMAME: {filename}")        #Fetch file name

        #Detect if client wants to exit
        if message == "sysexit":
            log_file.close()                        #Save log file
            sys.exit()

    backend = default_backend()
    block_Cipher = Cipher(algorithms.AES(Encryption_Key), modes.CBC(IV_key), backend=backend)               # create cipher
    AES_encryptor = block_Cipher.encryptor()                                                                # create the encryptor of the block
    AES_decryptor = block_Cipher.decryptor()                                                                #create the decryptor for AES

    while len(message) % 16 != 0:                                                                           #make the message length as multiplicity of 16 for the cipher blocks
        message = message + " "

    block_number = len(message) / 16                                                                        # calculate how many block will need for the operation
    final_Encrypted_Message = b''                                                                           # create initialy empty byte variable to hold the final encrypted message

    for i in range(0, int(block_number)):                                                                   #for every block of the message
        S = 16 * i                                                                                          #first index
        E = 16 * i + 16                                                                                     #second index
        block = message[S:E]                                                                                #take 16 string each times
        block_Byte = bytes(block, 'utf-8')                                                                  #convert string to byte
        encrypted_block = AES_encryptor.update(block_Byte)                                                  #encrypt 16bytes of block with AES
        #print(block_Byte)
        #print(encrypted_block)
        # print(len(encrpted_block))
        final_Encrypted_Message = b"".join([final_Encrypted_Message, encrypted_block])                      #add it up for to send just one message
    #print(final_Encrypted_Message)

    ##
    MAC = hmac.new(Hash_Key, final_Encrypted_Message, hashlib.sha256)                                       # MAC code for authentication
    MAC_send = MAC.digest()
    ##
    #FILE ENCRYPTING
    MAC_signed_file = ""
    if len(filename) > 0:
        fsz = os.path.getsize(filename)

        with open(filename, 'rb') as fo:
            plaintext = fo.read()

        fo.close()

        #Encrypt file and add padding to make it divisible by 16
        plaintext, padding_size = pad(plaintext)
        enc_file = file_encryptor.update(plaintext) + file_encryptor.finalize()

        enc_file += bytes([padding_size])

        MAC = hmac.new(Hash_Key, enc_file, hashlib.sha256)  # MAC code for file authentication
        MAC_signed_file = MAC.digest()



    if message:
        #make message as final_Encrypted_Message
        ## add mac field
        msg_dict = {
            'name': my_username,
            'message': final_Encrypted_Message,
            'mac': MAC_send,
            'filename': filename,
            'enc_file': enc_file,
            'signed_file': MAC_signed_file
        }

        msg_dict_pkl = pickle.dumps(msg_dict)
        msg_dict_pkl = bytes(f"{len(msg_dict_pkl):<{HEADERSIZE}}", 'utf-8')+ msg_dict_pkl

        log_file.write(f"Sent Msg: \n>>>>>>>>plain: {message}\n>>>>>>>>encrypted: {final_Encrypted_Message}")
        clientSocket.send(msg_dict_pkl)

        #
    try:

        while True:
            #
            full_msg = b''
            new_msg = True
            while True:
                incoming_msg_pkl = clientSocket.recv(2048)                          #Recieve incoming message from server
                if new_msg:
                    msglen = int(incoming_msg_pkl[:HEADERSIZE])                     #Get message size and put it a pickle until
                    new_msg = False                                                 #all bytes of the message receives
                full_msg += incoming_msg_pkl

                if len(full_msg) - HEADERSIZE == msglen:
                    print("full msg recvd")
                    new_msg = True
                    incoming_msg_dict = pickle.loads(full_msg[HEADERSIZE:])         #Load full message from the pickle
                    full_msg = b""

                    user_Name = incoming_msg_dict['name']                             #load the name from pickle
                    message = incoming_msg_dict['message']                            #load the message from server

                    ##
                    MAC_received = incoming_msg_dict['mac']                           # load the MAC from server
                    ##
                    backend = default_backend()
                    block_Cipher = Cipher(algorithms.AES(Encryption_Key), modes.CBC(IV_key), backend=backend)           # create cipher
                    AES_encryptor = block_Cipher.encryptor()                                                            # create the encryptor of the block
                    AES_decryptor = block_Cipher.decryptor()                                                            # create the decryptor for AES

                    block_number2 = len(message) / 16                                                                   #find how many block is needed for the decrpyting
                    final_Decrpyted_Message = b''                                                                       #create initially empty byte variable for decrypting message

                    #Check if any incoming file
                    if len(incoming_msg_dict['filename']) > 0:

                        enc_file = incoming_msg_dict['enc_file']                #Exract the encrypted file and its MAC
                        filename = incoming_msg_dict['filename']
                        MAC_recv_file = incoming_msg_dict['signed_file']

                        MAC = hmac.new(Hash_Key, enc_file, hashlib.sha256)      #Create MAC with encrypted file
                        MAC_created_file = MAC.digest()

                        if MAC_recv_file != MAC_created_file:                   #Check if incoming MAC and created MAC same
                            print("     This file has been captured         X X X")


                        #----->File decrypting
                        pad_size = enc_file[-1] * (-1)

                        file_ext = filename.split('.')[1]
                        filename_recv = filename.split('.', 1)[0]
                        filename_recv += "_recv"

                        #Creating new file
                        with open(f"{filename_recv}.{file_ext}", 'wb') as ff:
                            dec_text = file_decryptor.update(enc_file[:-1]) + file_decryptor.finalize()
                            ff.write(dec_text[:pad_size])
                        ff.close()
                        new_msg = True

                    for i in range(0, int(block_number2)):
                        S = 16 * i                                                                                      #first index
                        E = 16 * i + 16                                                                                 #second index
                        block = message[S:E]                                                                            #take from message the 16 bytes
                        decrypted_block = AES_decryptor.update(block)                                                   #decrypt the message with AES
                        #print(block)
                        #print(decrypted_block)
                        final_Decrpyted_Message = b"".join([final_Decrpyted_Message, decrypted_block])                  #add it up to the final message

                    ##
                    #print(MAC_received)
                    MAC = hmac.new(Hash_Key, message, hashlib.sha256)                                           # MAC code for authentication
                    MAC_created = MAC.digest()
                    #print(MAC_created)
                    ##

                    log_file.write(f"Received Msg from {user_Name}: \n>>>>>>>>Encrypted message: {message} \n\nDecrypted: {final_Decrpyted_Message} {line_indicator}")
                    if(MAC_received==MAC_created):
                        print("    "+user_Name+" > "+ str(final_Decrpyted_Message, 'utf-8')+"   (✓✓✓ message reach succesfully)")   # print the decrypted message to the console
                    else:
                        print("    "+user_Name+" > "+ str(final_Decrpyted_Message, 'utf-8')+"   (X X X message has been captured)")  # print the decrypted message to the console

            #print(str(user_Name)+"     "+str(message))
            #print(f'{incoming_msg_dict["name"]} > {incoming_msg_dict["message"]}')
            #
    except IOError as e:
        # This is normal on non blocking connections - when there are no incoming data error is going to be raised
        # Some operating systems will indicate that using AGAIN, and some using WOULDBLOCK error code
        # We are going to check for both - if one of them - that's expected, means no incoming data, continue as normal
        # If we got different error code - something happened
        if e.errno != errno.EAGAIN and e.errno != errno.EWOULDBLOCK:
            print('Reading error: {}'.format(str(e)))
            sys.exit()

        # We just did not receive anything
        continue

    except Exception as e:
        # Any other exception - something happened, exit
        print('Reading error: '.format(str(e)))
        sys.exit()



clientSocket.close()