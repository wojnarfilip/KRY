from cryptography.fernet import Fernet

from src.Peer2peer.clientAlice import alicePrivKey, key
from src.Peer2peer.clientAlice import process_messages

messages_file = f"hold-off_0.txt"
# Decrypt the private key file using the key
fernet = Fernet(key)
with open('CryptoKeys/Alice-ECDSA-private', 'rb') as encrypted_file:
    encrypted = encrypted_file.read()
decrypted_key = fernet.decrypt(encrypted)

# call the process_messages() function to get the decrypted messages
decrypted_messages = process_messages(messages_file, alicePrivKey)

# print the decrypted messages
print(decrypted_messages)