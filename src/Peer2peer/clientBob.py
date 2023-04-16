import base64
import tinyec
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from tinyec import registry
import socket
import src.EllipticCurves.ECIES as OurECIES
import src.EllipticCurves.ECDSA as OurECDSA
import secrets
import pickle

# Main script for client Bob

def compressStr(pubKey):
    return str(pubKey.x) + "," + str(pubKey.y)


# Generate bob's keypair for ECDSA signing
OurECDSA.generate_ECDSA_keys("Bob-ECDSA-private", "Bob-ECDSA-public")

# Define the password
key_password = b"bob password"

# Derive a key from the password
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=b"bobsalt",
    iterations=100000,
)
key = kdf.derive(key_password)
key = base64.urlsafe_b64encode(key)

# Encrypt the private key file using the key derived from password
with open('Bob-ECDSA-private', 'rb') as file:
    non_encrypted_key = file.read()

# Encrypt the private key with fernet and rewrite the original non encrypted one
fernet = Fernet(key)
encrypted_key = fernet.encrypt(non_encrypted_key)
with open('Bob-ECDSA-private', 'wb') as encrypted_file:
    encrypted_file.write(encrypted_key)

# Decrypt the private key file using the key
fernet = Fernet(key)
with open('Bob-ECDSA-private', 'rb') as encrypted_file:
    encrypted = encrypted_file.read()
decrypted = fernet.decrypt(encrypted).decode()
print(decrypted)

# Message to be sent over network
plain_message = b"Does it work?"

# Create message signature
signature = OurECDSA.sign_message(plain_message, decrypted)
if not OurECDSA.verify_message(plain_message, signature, "Bob-ECDSA-public"):
    print("Something went wrong with ECDSA signing")

# Create object containing message + signature
signed_msg_obj = {
     'plainmsg': plain_message,
     'signature': signature
 }

# Serialize the object so it can be transferred via network
pickled_signed_msg_obj = pickle.dumps(signed_msg_obj)

# Use secp256r1 curve
curve = registry.get_curve('secp256r1')

# Generate bobs keypair for ECDH + ECIES
bobPrivKey = secrets.randbelow(curve.field.n)
bobPubKey = bobPrivKey * curve.g

# Listen for tcp connection from alice on endpoint localhost:9998
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(("localhost", 9998))
server.listen()

# Receive alice's public key
clientReceiver, addr = server.accept()
alicePubKey = clientReceiver.recv(1024).decode()

# Reconstruct the point on secp256r1 curve
alicePubKey = alicePubKey.split(",")
y = int(alicePubKey.pop())
x = int(alicePubKey.pop())
alicePubKey = tinyec.ec.Point(curve, x, y)

# Open tcp connection on localhost:9999 link for data sending to alice
clientSender = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
clientSender.connect(("localhost", 9999))

# Send alice bob's public key
clientSender.send(str(compressStr(bobPubKey)).encode())

# Calculate sharedKey
bobSharedKey = bobPrivKey * alicePubKey
clientSender.send(str(bobSharedKey).encode())

# Receive alice's sharedKey
aliceSharedKey = clientReceiver.recv(1024).decode()

# Verify sharedKey is the same
if (str(aliceSharedKey) == str(bobSharedKey)):
    print("Successful ECDH")
else:
    print("Alice shared key:", aliceSharedKey)
    print("Bob shared key:", bobSharedKey)
    print("Keys are not equal")

# Encrypt message + signature object with alice's public key
encrypted_msg = OurECIES.encrypt(pickled_signed_msg_obj, alicePubKey)
encrypted_msg_obj = {
    'ciphertext': encrypted_msg[0],
    'nonce': encrypted_msg[1],
    'authTag': encrypted_msg[2],
    'ciphertextPubKey': str(encrypted_msg[3].x) + ',' + str(encrypted_msg[3].y)
}

# Serialize encrypted message object so it can be send via network and send it
pickled_msg_obj = pickle.dumps(encrypted_msg_obj)
clientSender.send(pickled_msg_obj)

# Close all connections
clientReceiver.close()
clientSender.close()
server.close()