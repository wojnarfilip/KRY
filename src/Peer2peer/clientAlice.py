from tinyec.ec import Point
from tinyec import registry
import socket
import secrets


def compressStr(pubKey):
    return str(pubKey.x) + "," + str(pubKey.y)


def toHex(pubKey):
    return hex(pubKey.x) + hex(pubKey.y % 2)[2:]


curve = registry.get_curve('secp256r1')

alicePrivKey = secrets.randbelow(curve.field.n)
alicePubKey = alicePrivKey * curve.g

clientSender = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
clientSender.connect(("localhost", 9998))

clientSender.send(str(compressStr(alicePubKey)).encode())

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(("localhost", 9999))
server.listen()

clientReceiver, addr = server.accept()
bobPubKey = clientReceiver.recv(1024).decode()

bobPubKey = bobPubKey.split(",")
y = int(bobPubKey.pop())
x = int(bobPubKey.pop())
bobPubKey = Point(curve, x, y)

aliceSharedKey = alicePrivKey * bobPubKey
clientSender.send(str(aliceSharedKey).encode())

bobSharedKey = clientReceiver.recv(1024).decode()

if(str(bobSharedKey) == str(aliceSharedKey)):
    print("Alice shared key:", aliceSharedKey)
    print("Bob shared key:", bobSharedKey)
    print("Successful ECDH")
else:
    print("Alice shared key:", aliceSharedKey)
    print("Bob shared key:", bobSharedKey)
    print("Keys are not equal")

clientSender.close()
server.close()
