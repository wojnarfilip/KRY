import tinyec
from tinyec import registry
import socket
import secrets


def compressStr(pubKey):
    return str(pubKey.x) + "," + str(pubKey.y)


def toHex(pubKey):
    return hex(pubKey.x) + hex(pubKey.y % 2)[2:]


curve = registry.get_curve('secp256r1')

bobPrivKey = secrets.randbelow(curve.field.n)
bobPubKey = bobPrivKey * curve.g

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(("localhost", 9998))
server.listen()

clientReceiver, addr = server.accept()
alicePubKey = clientReceiver.recv(1024).decode()

alicePubKey = alicePubKey.split(",")
y = int(alicePubKey.pop())
x = int(alicePubKey.pop())
alicePubKey = tinyec.ec.Point(curve, x, y)

clientSender = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
clientSender.connect(("localhost", 9999))

clientSender.send(str(compressStr(bobPubKey)).encode())

bobSharedKey = bobPrivKey * alicePubKey
clientSender.send(str(bobSharedKey).encode())

aliceSharedKey = clientReceiver.recv(1024).decode()

if(str(aliceSharedKey) == str(bobSharedKey)):
    print("Alice shared key:", aliceSharedKey)
    print("Bob shared key:", bobSharedKey)
    print("Successful ECDH")
else:
    print("Alice shared key:", aliceSharedKey)
    print("Bob shared key:", bobSharedKey)
    print("Keys are not equal")

clientSender.close()
server.close()
