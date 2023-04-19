import base64
import os
import sys
import time

import tinyec
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from tinyec import registry
import socket
import src.EllipticCurves.ECIES as OurECIES
import src.EllipticCurves.ECDSA as OurECDSA
import src.Logger.LogUtils as LogUtils
import secrets
import pickle

# Main script for client Bob

def compressStr(pubKey):
    return str(pubKey.x) + "," + str(pubKey.y)


# Define the password, log filename, max wait time in delayed transfer etc...
key_password = b"bob password"
log_file = "ECC-log"
wait_time = 60

LogUtils.create_file(log_file)

# Derive a key from the password
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=b"bobsalt",
    iterations=100000,
)
key = kdf.derive(key_password)
key = base64.urlsafe_b64encode(key)

fernet = Fernet(key)

# Generate bob's keypair for ECDSA signing
if not os.path.exists('CryptoKeys/Bob-ECDSA-private') and not os.path.exists('CryptoKeys/Bob-ECDSA-public'):
    LogUtils.log_algorithm(log_file, "Creating ECDSA key pair for Bob", "SECP256k1")
    OurECDSA.generate_ECDSA_keys("Bob-ECDSA-private", "Bob-ECDSA-public")

    # Encrypt the private key file using the key derived from password
    with open('CryptoKeys/Bob-ECDSA-private', 'rb') as file:
        non_encrypted_key = file.read()

    # Encrypt the private key with fernet and rewrite the original non encrypted one
    with open('CryptoKeys/Bob-ECDSA-private', 'wb') as encrypted_file:
        LogUtils.log_algorithm(log_file, "Encrypting Bob's ECDSA private key with password derived key", "PBKDF2HMAC")
        encrypted_key = fernet.encrypt(non_encrypted_key)
        encrypted_file.write(encrypted_key)
else:
    LogUtils.log_algorithm(log_file, "Key pair for Bob already exists", "SECP256k1")

# Decrypt the private key file using the key
with open('CryptoKeys/Bob-ECDSA-private', 'rb') as encrypted_file:
    encrypted = encrypted_file.read()

LogUtils.log_algorithm(log_file, "Decrypting Bob's ECDSA private key with password derived key", "PBKDF2HMAC")
decrypted = fernet.decrypt(encrypted).decode()
print(decrypted)

# Message to be sent over network
with open('ResourceFiles/LikeReallySecretStuff', 'rb') as f:
    plain_message = f.read()
    LogUtils.log_displayed_text(log_file, "Message before encrypting", plain_message, sys.getsizeof(plain_message))

# Use secp256r1 curve
curve = registry.get_curve('secp256r1')

# Generate bobs keypair for ECDH + ECIES
LogUtils.log_algorithm(log_file, "Generating Bob's temporary key pair for ECDH + ECIES purposes", "SECP256k1")
bobPrivKey = secrets.randbelow(curve.field.n)
bobPubKey = bobPrivKey * curve.g

# Open tcp connection on localhost:9999 link for data sending to alice
clientSender = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

connection_establisted = False
file_secured = False
while(wait_time > 0):
    try:
        clientSender.connect(("localhost", 9999))
        connection_establisted = True
        LogUtils.log_message(log_file, "Bob established connection with Alice")
        break;
    except ConnectionRefusedError:
        LogUtils.log_message(log_file, "Alice is unavailable ! wait for 5 seconds then try again.")
        time.sleep(5)
        wait_time = wait_time - 5
        if not file_secured:
            LogUtils.log_algorithm(log_file, "Bob temporarily encrypting the file with password derived key until Alice becomes available", "PBKDF2HMAC")
            encrypted_signed_msg_obj = fernet.encrypt(plain_message)
            with open("ResourceFiles/temporarily-secured-file", 'wb') as file:
                file.write(encrypted_signed_msg_obj)
            file_secured = True

if not connection_establisted:
    LogUtils.log_message(log_file, "The time has expired and Alice couldn't be reached")
    LogUtils.log_message(log_file, "Bob closing application without transferring files")
    exit(-1)

if connection_establisted and file_secured:
    with open('ResourceFiles/temporarily-secured-file', 'rb') as temporarily_encrypted_message:
        LogUtils.log_algorithm(log_file, "Bob decrypting temporarily encrypted message with password derived key as Alice became available", "PBKDF2HMAC")
        tmp = temporarily_encrypted_message.read()
        LogUtils.log_displayed_text(log_file, "Message after temporarily encrypting", tmp, sys.getsizeof(tmp))
        plain_message = fernet.decrypt(tmp)

# Create message signature
LogUtils.log_algorithm(log_file, "Signing file with Bob's ECDSA private key", "SECP256k1")
signature = OurECDSA.sign_message(plain_message, decrypted)
if not OurECDSA.verify_message(plain_message, signature, "CryptoKeys/Bob-ECDSA-public"):
    LogUtils.log_message(log_file, "Something went wrong with ECDSA signing on Bob's side")

# Create object containing message + signature
signed_msg_obj = {
     'plainmsg': plain_message,
     'signature': signature
 }
LogUtils.log_file(log_file, "Creating object with message + signature to be sent over network", sys.getsizeof(signed_msg_obj))

# Serialize the object so it can be transferred via network
pickled_signed_msg_obj = pickle.dumps(signed_msg_obj)

# Send alice bob's public key
LogUtils.log_all(log_file, "Sending Bob's public key to Alice for ECDH", sys.getsizeof(str(compressStr(bobPubKey)).encode()), "SECP256k1")
clientSender.send(str(compressStr(bobPubKey)).encode())

# Listen for tcp connection from alice on endpoint localhost:9998
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(("localhost", 9998))
server.listen(5)

# Receive alice's public key
clientReceiver, addr = server.accept()
alicePubKey = clientReceiver.recv(1024).decode()
LogUtils.log_all(log_file, "Bob receiving Alice's public key for ECDH", sys.getsizeof(alicePubKey), "SECP256k1")

# Reconstruct the point on secp256r1 curve
alicePubKey = alicePubKey.split(",")
y = int(alicePubKey.pop())
x = int(alicePubKey.pop())
alicePubKey = tinyec.ec.Point(curve, x, y)

# Calculate sharedKey
LogUtils.log_algorithm(log_file, "Bob calculating the shared ECDH key", "SECP256k1")
bobSharedKey = bobPrivKey * alicePubKey
clientSender.send(str(bobSharedKey).encode())

# Receive alice's sharedKey
LogUtils.log_algorithm(log_file, "Bob receiving Alice's shared ECDH key", "SECP256k1")
aliceSharedKey = clientReceiver.recv(1024).decode()

# Verify sharedKey is the same
LogUtils.log_algorithm(log_file, "Bob verifying alice has same shared key", "SECP256k1")
if (str(aliceSharedKey) == str(bobSharedKey)):
    LogUtils.log_message(log_file, "Keys acquired from ECDH are same... continuing...")
else:
    LogUtils.log_message(log_file, "Keys acquired from ECDH are different... ending the application")
    exit(-1)

# Encrypt message + signature object with alice's public key
LogUtils.log_algorithm(log_file, "Encrypting message with ECIES(sharedKey + Alice's public key)", "AES-GCM and SECP256k1")
encrypted_msg = OurECIES.encrypt(pickled_signed_msg_obj, alicePubKey)
encrypted_msg_obj = {
    'ciphertext': encrypted_msg[0],
    'nonce': encrypted_msg[1],
    'authTag': encrypted_msg[2],
    'ciphertextPubKey': str(encrypted_msg[3].x) + ',' + str(encrypted_msg[3].y)
}

# Serialize encrypted message object so it can be send via network and send it
LogUtils.log_file(log_file, "Bob sending encrypted message to Alice", sys.getsizeof(encrypted_msg_obj))
pickled_msg_obj = pickle.dumps(encrypted_msg_obj)
clientSender.send(pickled_msg_obj)

confirm_file_transfer = clientReceiver.recv(1024).decode()
if confirm_file_transfer == "File accepted":
    LogUtils.log_message(log_file, "Bob receiving confirmation Alice has received a file")
else:
    LogUtils.log_message(log_file, "Bob missing confirmation Alice has received a file")

# Close all connections
LogUtils.log_message(log_file, "Bob closing connection")
clientReceiver.close()
clientSender.close()
server.close()