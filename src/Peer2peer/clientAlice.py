from tinyec.ec import Point
from tinyec import registry
import socket
import secrets

def compress(pubKey):
    return hex(pubKey.x) + hex(pubKey.y % 2)[2:]


curve = registry.get_curve('secp256r1')

alicePrivKey = secrets.randbelow(curve.field.n)
alicePubKey = alicePrivKey * curve.g
print(curve.g)
print(alicePubKey)

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(("localhost", 9998))

client.send(str(alicePubKey).encode())

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(("localhost", 9999))
server.listen()

client, addr = server.accept()
bobPubKey = client.recv(1024).decode()
print(bobPubKey)
alicePubKey = Point(bobPubKey)

aliceSharedKey = alicePrivKey * bobPubKey
client.send(str(compress(aliceSharedKey).encode()))

bobSharedKey = client.recv(1024)

if(bobSharedKey == aliceSharedKey):
    print("Alice shared key:", compress(aliceSharedKey))
    print("Bob shared key:", compress(bobSharedKey))
    print("Successful ECDH")
else:
    print("Alice shared key:", compress(aliceSharedKey))
    print("Bob shared key:", compress(bobSharedKey))
    print("Keys are not equal")

client.close()
server.close()
