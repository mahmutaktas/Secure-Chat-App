import socket
import os
import pickle
import re
import select
from _thread import *
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_pem_public_key

HEADERSIZE = 10

log_file = open(f"server_log.txt", "a")

line_indicator = "\n\n------------------------------------------------------------\n\n"

def save_key(pk, filename):
    pem = pk.public_bytes(
		encoding=serialization.Encoding.PEM,
		format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(filename, 'wb') as pem_out:
        pem_out.write(pem)

def send_msg(msg):
    if msg == None:
        return False


def threaded_client(connection):
    log_file = open(f"server_log.txt", "a")

    #getting client name and public key
    init_msg = connection.recv(2048)


    client_init_dict = pickle.loads(init_msg)

    client_name = client_init_dict['name']
    client_pub_key_byte = client_init_dict['public_key']
    client_pub_key_pem = client_pub_key_byte.decode("utf-8")
    client_pub_key = load_pem_public_key(client_pub_key_byte, backend=default_backend())
    print(f"CLIENT POUB KEY: {client_pub_key_pem}")

    log_file.write(f"Received initial msg from {client_name}: {client_init_dict} {line_indicator}")

    #Creating signature for received client's public key
    signature = server_private_key.sign(
        client_pub_key_byte,
        padding.PSS(
            mgf = padding.MGF1(hashes.SHA256()),
            salt_length = padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )


    client_cert_signed = {
        'name': client_name,
        'public_key': signature
    }

    certificate_list.append(client_cert_signed)

    log_file.write(f"Signed certiface to send: {client_cert_signed} {line_indicator}")

    #Send client certificate to the client
    send_init_msg = pickle.dumps(client_cert_signed)
    connection.send(send_init_msg)

    #Receive answer fo requested connection
    want_connection_other = connection.recv(2048)
    answer = pickle.loads(want_connection_other)

    log_file.write(f"Connection request answer: {answer} {line_indicator}")


    if answer['msg'] == "yes":



        #Get other user's socket
        self_index = sockets_list.index(connection)
        print(f"SELF INDEX: {self_index}")
        print(sockets_list)
        if self_index == 0:
            other_client = sockets_list[1]
        elif self_index == 1:
            other_client = sockets_list[0]

        #send self public key to the other user
        client_cert = {
            'name': client_name,
            'msg': "hello",
            'public_key': client_pub_key_pem
        }

        log_file.write(f"{client_name}'s certificate with her/his public key: {client_cert} {line_indicator}")

        other_client.send(pickle.dumps(client_cert))

        #recieve nonce from other user
        response = other_client.recv(2048)
        response_dict = pickle.loads(response)
        #send nonce to the self

        log_file.write(f"Received nonce: {response_dict} {line_indicator}")
        connection.send(response)


        #recieve signed nonce from self and send to the other user
        encrypted_nonce_pkl = connection.recv(2048)
        encrypted_nonce = pickle.loads(encrypted_nonce_pkl)
        log_file.write(f"Send encrypted nonce: {encrypted_nonce} {line_indicator}")

        other_client.send(encrypted_nonce_pkl)

        #get ack msg from other and send to the self
        ack_msg = pickle.loads(other_client.recv(2048))

        log_file.write(f"Ack msg: {ack_msg} {line_indicator}")
        print(f"ACK MSG : {ack_msg}")
        connection.send(pickle.dumps(ack_msg))

        print("smt")


        #take from user and send it to another user
        #
        encrypted_Master_Key_pkl = connection.recv(2048)
        encrypted_Master_Key = pickle.loads(encrypted_Master_Key_pkl)['master_key']
        encrypted_file_keys = pickle.loads(encrypted_Master_Key_pkl)['file_keys_enc']
        print(encrypted_Master_Key)
        encrypted_Master_Key_dict = {
            'master_key': encrypted_Master_Key,
            'file_keys_enc': encrypted_file_keys
        }

        log_file.write(f"Encrypted master key and file key {encrypted_Master_Key_dict} {line_indicator}")

        other_client.send(pickle.dumps(encrypted_Master_Key_dict))
        #
        #

        while True:

                #Get first client's messages and send it to the second client
                full_msg = b""
                new_msg = True
                while_cond = True
                while while_cond:
                    incoming_msg_pkl = connection.recv(2048)
                    if new_msg:
                        msglen = int(incoming_msg_pkl[:HEADERSIZE])
                        print(f"HEADER SIZE1: {msglen}")
                        new_msg = False

                    full_msg += incoming_msg_pkl

                    if len(full_msg) - HEADERSIZE == msglen:
                        print("full msg recvd1")

                        log_file.write(f"First user msg: {full_msg} {line_indicator}")
                        other_client.send(full_msg)
                        new_msg = True
                        full_msg = b""
                        while_cond = False

                # Get second client's messages and send it to the first client
                full_msg2 = b""
                new_msg2 = True
                while_cond2 = True
                while while_cond2:
                    incoming_msg_pkl2 = other_client.recv(2048)
                    if new_msg2:
                        msglen2 = int(incoming_msg_pkl2[:HEADERSIZE])
                        print(f"HEADER SIZE2: {msglen2}")
                        new_msg2 = False

                    full_msg2 += incoming_msg_pkl2

                    if len(full_msg2) - HEADERSIZE == msglen2:
                        print("full msg recvd2")
                        log_file.write(f"Second user msg: {full_msg} {line_indicator}")
                        connection.send(full_msg2)
                        new_msg2 = True
                        full_msg2 = b""
                        while_cond2 = False
    log_file.close()



certificate_list = []

serverSocket = socket.socket()
serverSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
host = socket.gethostname()
port = 1233
ThreadCount = 0
try:
    serverSocket.bind((host, port))
except socket.error as e:
    print(str(e))

print('Waitiing for a Connection..')
serverSocket.listen(5)

# List of sockets
sockets_list = []


#Creating server's key pair and storing public key
if True:
    # ---SERVER KEYS---
    server_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    server_public_key = server_private_key.public_key()
    server_pem = server_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    print(f"SERVER PEM: {server_pem}")
    save_key(server_public_key, "server_public.pem")


# -------MAIN------
while True:
    client, address = serverSocket.accept()
    sockets_list.append(client)
    print('Connected to: ' + address[0] + ':' + str(address[1]))
    start_new_thread(threaded_client, (client, ))
    ThreadCount += 1
    print('Thread Number: ' + str(ThreadCount))

serverSocket.close()