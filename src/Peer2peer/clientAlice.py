from tinyec.ec import Point
from tinyec import registry
import socket
import src.EllipticCurves.ECIES as OurECIES
import src.EllipticCurves.ECDSA as OurECDSA
import secrets
import pickle


# Main script for client Alice

def compressStr(pubKey):
    return str(pubKey.x) + "," + str(pubKey.y)


# Generate alice's keypair for ECDSA signing
OurECDSA.generate_ECDSA_keys("Alice-ECDSA-private", "Alice-ECDSA-public")

# Choose secp256r1 curve
curve = registry.get_curve('secp256r1')

# Generate keypair for ECDH and ECIES
alicePrivKey = secrets.randbelow(curve.field.n)
alicePubKey = alicePrivKey * curve.g

# Open tcp connection to localhost:9998 link for sending data to bob
clientSender = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
clientSender.connect(("localhost", 9998))

# Send public key to bob for ECDH and ECIES purposes
clientSender.send(str(compressStr(alicePubKey)).encode())

# Start listening for tcp connections on localhost:9999 link for receiving from bob
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(("localhost", 9999))
server.listen()

# Accept bob's public key
clientReceiver, addr = server.accept()
bobPubKey = clientReceiver.recv(1024).decode()

# Reconstruct point on secp256r1 curve
bobPubKey = bobPubKey.split(",")
y = int(bobPubKey.pop())
x = int(bobPubKey.pop())
bobPubKey = Point(curve, x, y)

# Calculated shared key
aliceSharedKey = alicePrivKey * bobPubKey
clientSender.send(str(aliceSharedKey).encode())

# Accept bob's shared key
bobSharedKey = clientReceiver.recv(1024).decode()

# Verify keys are the same
if (str(bobSharedKey) == str(aliceSharedKey)):
    print("Successful ECDH")
else:
    print("Alice shared key:", aliceSharedKey)
    print("Bob shared key:", bobSharedKey)
    print("Keys are not equal")

# Receive encrypted message from bob
encrypted_msg_obj = clientReceiver.recv(1024)
unpickled_msg_obj = pickle.loads(encrypted_msg_obj)

# Decrypt the message with alice private key
pickled_decrypted_msg = OurECIES.decrypt(dict(unpickled_msg_obj).values(), alicePrivKey)

unpickled_decrypted_msg = pickle.loads(pickled_decrypted_msg)

# Verify message was signed by bob
plain_message, signature = dict(unpickled_decrypted_msg).values()
if not OurECDSA.verify_message(plain_message, signature, "Bob-ECDSA-public"):
    print("Wrong file signature")

print(plain_message)
print(signature)

# Close all connections
clientReceiver.close()
clientSender.close()
server.close()
