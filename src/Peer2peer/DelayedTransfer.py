from cryptography.fernet import Fernet

from clientAlice import alicePrivKey, key

from clientAlice import process_messages
messages_file = "hold-off_0.txt"

# Decrypt the private key file using the key
fernet = Fernet(key)
with open('Alice-ECDSA-private', 'rb') as encrypted_file:
    encrypted = encrypted_file.read()
decrypted_key = fernet.decrypt(encrypted)

# call the process_messages() function to get the decrypted messages
decrypted_messages = process_messages(messages_file, alicePrivKey)

# print the decrypted messages
print(decrypted_messages)