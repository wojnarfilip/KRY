import base64
import sys

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from tinyec.ec import Point
from tinyec import registry
import socket
import src.EllipticCurves.ECIES as OurECIES
import src.EllipticCurves.ECDSA as OurECDSA
import src.Logger.LogUtils as LogUtils
import secrets
import pickle
import os


def process_messages(file_name, private_key):
    if not os.path.exists(file_name):
        print("No messages to process.")
        return []

    decrypted_messages = []
    with open(file_name, 'rb') as file:
        while True:
            try:
                encrypted_msg_obj = pickle.load(file)
                unpickled_msg_obj = pickle.loads(encrypted_msg_obj)

                pickled_decrypted_msg = OurECIES.decrypt(dict(unpickled_msg_obj).values(), private_key)

                unpickled_decrypted_msg = pickle.loads(pickled_decrypted_msg)

                plain_message, signature = dict(unpickled_decrypted_msg).values()
                if not OurECDSA.verify_message(plain_message, signature, "Bob-ECDSA-public"):
                    print("Wrong file signature")

                decrypted_messages.append(plain_message)

            except EOFError:
                break

    return decrypted_messages


# save location of file from hold off communication
# counter = 0
# while True:
#     messages_file = f"hold-off_{counter}.txt"
#     if not os.path.exists(messages_file):
#         break
#     counter += 1


# Main script for client Alice

def compressStr(pubKey):
    return str(pubKey.x) + "," + str(pubKey.y)




# Define the password, log filename
key_password = b"alice password"
log_file = "ECC-log"

# Derive a key from the password
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=b"alice salt",
    iterations=100000,
)
key = kdf.derive(key_password)
key = base64.urlsafe_b64encode(key)

fernet = Fernet(key)

# plain_message = b'does it work?'

# Generate alice's keypair for ECDSA signing
if not os.path.exists('CryptoKeys/Alice-ECDSA-private') and not os.path.exists('CryptoKeys/Alice-ECDSA-public'):
    LogUtils.log_algorithm(log_file, "Creating ECDSA key pair for Alice", "SECP256k1")
    OurECDSA.generate_ECDSA_keys("Alice-ECDSA-private", "Alice-ECDSA-public")

    # Encrypt the private key file using the key derived from password
    with open('CryptoKeys/Alice-ECDSA-private', 'rb') as file:
        non_encrypted_key = file.read()

    # Encrypt the private key with fernet and rewrite the original non encrypted one
    with open('CryptoKeys/Alice-ECDSA-private', 'wb') as encrypted_file:
        LogUtils.log_algorithm(log_file, "Encrypting Alice's ECDSA private key with password derived key", "PBKDF2HMAC")
        encrypted_key = fernet.encrypt(non_encrypted_key)
        encrypted_file.write(encrypted_key)
else:
    LogUtils.log_algorithm(log_file, "Key pair for Alice already exists", "SECP256k1")

# Decrypt the private key file using the key
with open('CryptoKeys/Alice-ECDSA-private', 'rb') as encrypted_file:
    encrypted = encrypted_file.read()

decrypted = fernet.decrypt(encrypted).decode()
print(decrypted)

# Choose secp256r1 curve
curve = registry.get_curve('secp256r1')

# Generate keypair for ECDH and ECIES
alicePrivKey = secrets.randbelow(curve.field.n)
alicePubKey = alicePrivKey * curve.g

# Start listening for tcp connections on localhost:9999 link for receiving from bob
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(("localhost", 9999))
server.listen(5)

# Accept bob's public key
clientReceiver, addr = server.accept()
bobPubKey = clientReceiver.recv(1024).decode()
LogUtils.log_all(log_file, "Alice receiving Bob's public key for ECDH", sys.getsizeof(bobPubKey), "SECP256k1")

# Open tcp connection to localhost:9998 link for sending data to bob
clientSender = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
clientSender.connect(("localhost", 9998))

# Send public key to bob for ECDH and ECIES purposes
clientSender.send(str(compressStr(alicePubKey)).encode())
LogUtils.log_all(log_file, "Sending Alice's public key to Bob for ECDH", sys.getsizeof(str(compressStr(alicePubKey)).encode()), "SECP256k1")

# Reconstruct point on secp256r1 curve
bobPubKey = bobPubKey.split(",")
y = int(bobPubKey.pop())
x = int(bobPubKey.pop())
bobPubKey = Point(curve, x, y)

# Calculated shared key
LogUtils.log_algorithm(log_file, "Alice calculating the shared ECDH key", "SECP256k1")
aliceSharedKey = alicePrivKey * bobPubKey
clientSender.send(str(aliceSharedKey).encode())

# Accept bob's shared key
bobSharedKey = clientReceiver.recv(1024).decode()
LogUtils.log_algorithm(log_file, "Alice receiving bob's shared ECDH key", "SECP256k1")

# Verify keys are the same
LogUtils.log_algorithm(log_file, "Alice verifying bob has same shared key", "SECP256k1")
if (str(bobSharedKey) == str(aliceSharedKey)):
    print("Keys acquired from ECDH are same... continuing...")
else:
    print("Keys acquired from ECDH are different... ending the application")
    exit(-1)

# Receive encrypted message from bob
encrypted_msg_obj = clientReceiver.recv(1024)
unpickled_msg_obj = pickle.loads(encrypted_msg_obj)
LogUtils.log_file(log_file, "Alice receiving encrypted message from bob", sys.getsizeof(unpickled_msg_obj))
LogUtils.log_displayed_text(log_file, "Message before decrypting", unpickled_msg_obj, sys.getsizeof(unpickled_msg_obj))

# Decrypt the message with alice private key
LogUtils.log_algorithm(log_file, "Alice decrypting the message from bob with her private key", "AES-GCM and SECP256k1")
pickled_decrypted_msg = OurECIES.decrypt(dict(unpickled_msg_obj).values(), alicePrivKey)

unpickled_decrypted_msg = pickle.loads(pickled_decrypted_msg)

# Verify message was signed by bob
plain_message, signature = dict(unpickled_decrypted_msg).values()
LogUtils.log_displayed_text(log_file, "Message after decrypting", plain_message, sys.getsizeof(plain_message))
LogUtils.log_algorithm(log_file, "Alice verifying the message is from Bob based on signature and Bob's public ECDSA key", "SECP256k1")
if not OurECDSA.verify_message(plain_message, signature, "CryptoKeys/Bob-ECDSA-public"):
    LogUtils.log_message(log_file, "Signature on received file from bob is invalid !")
else:
    LogUtils.log_algorithm(log_file, "The signature is valid... message is from Bob", "SECP256k1")

with open("ResourceFiles/LikeReallySecretStuffReceived", 'w') as f:
    f.write(plain_message.decode())

with open('ResourceFiles/LikeReallySecretStuffReceived', 'rb') as f:
    decrypted_message = f.read()

LogUtils.log_message(log_file, "Alice sending confirmation to Bob that she received a file")
clientSender.send(str("File accepted").encode())

# Close all connections
LogUtils.log_message(log_file, "Alice closes connection")
clientReceiver.close()
clientSender.close()
server.close()
