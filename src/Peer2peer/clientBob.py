from tinyec.ec import Point
from tinyec import registry
import socket
import secrets

def compress(pubKey):
    return hex(pubKey.x) + hex(pubKey.y % 2)[2:]


curve = registry.get_curve('secp256r1')

bobPrivKey = secrets.randbelow(curve.field.n)
bobPubKey = bobPrivKey * curve.g
print(curve.g)
print(bobPubKey)

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(("localhost", 9998))
server.listen()

client, addr = server.accept()
alicePubKey = client.recv(1024).decode()
print(alicePubKey)
alicePubKey = Point(alicePubKey)

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(("localhost", 9999))

client.send(str(bobPubKey).encode())

bobSharedKey = bobPrivKey * alicePubKey
client.send(str(compress(bobSharedKey).encode()))

aliceSharedKey = client.recv(1024)

if(aliceSharedKey == bobSharedKey):
    print("Alice shared key:", compress(aliceSharedKey))
    print("Bob shared key:", compress(bobSharedKey))
    print("Successful ECDH")
else:
    print("Alice shared key:", compress(aliceSharedKey))
    print("Bob shared key:", compress(bobSharedKey))
    print("Keys are not equal")

client.close()
server.close()
