import tinyec.ec
from tinyec import registry
import secrets

def compress(pubKey):
    return hex(pubKey.x) + "," + hex(pubKey.y)


curve = registry.get_curve('brainpoolP256r1')
print("Point is this---- " + str(tinyec.ec.Point(curve, 76104097148571068473215853672191726493418512119945135895954376117030304989461, 74405427339741648523423341699878831345980022617109126761606103772749492182354)))


alicePrivKey = secrets.randbelow(curve.field.n)
alicePubKey = alicePrivKey * curve.g
print(type(alicePubKey))
print("Alice public key:", compress(alicePubKey))

bobPrivKey = secrets.randbelow(curve.field.n)
bobPubKey = bobPrivKey * curve.g
print("Bob public key:", bobPubKey)
print("Now exchange the public keys (e.g. through Internet)")

aliceSharedKey = alicePrivKey * bobPubKey
print("x = ", bobPubKey.x)
print("y = ", bobPubKey.y)
print("Alice priv key:", alicePrivKey)
print("Bob pub key:", bobPubKey)
print("Alice shared key:", compress(aliceSharedKey))

bobSharedKey = bobPrivKey * alicePubKey
print("Bob shared key:", compress(bobSharedKey))

print("Equal shared keys:", aliceSharedKey == bobSharedKey)