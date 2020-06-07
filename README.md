# Secure-Chat-App
A secure chat app with Cryptography library in Python.  
Developed By: **Deniz Arda GÜRZİHİN & Mahmut AKTAŞ** 

## Work Done
**Deniz Arda GÜRZİHİN**: 3, 4, 5  
**Mahmut AKTAŞ**: 1, 2, 6

![Demo Gif](https://github.com/mahmutaktas/Secure-Chat-App/blob/master/gif.gif)

## Properties


**1. Public Key Certification**  
Each user should generate a public-private key pair once and register the server with her username and public key. Server signs this key and creates a certificate, stores the certificate and also sends a copy to the user. When user receives the certificate, she verifies that the certificate is correct and the public key is correctly received by the server.  


**2. Handshaking**   
A handshaking mechanism without SSL libraries.


**3. Key Generation**  
Both user1 and user2 generates necessary keys for encryption and Message Authentication Code (MAC), as well as initialization vector(s) (IV).  


**4. Message Encryption**  
All the messages between pairs must be encrypted using a block cipher.  


**5. Integrity Check** 
Every message going over the network have a MAC, to enable detection of a malicious attacker tampering with the messages en route.  


**6. Sending Files**  
User1 can send a file (an image, a pdf, etc) to user2. The file is encrypted with another key and stored somewhere in the server together with a digital signature (to provide authentication and integrity of the file).

