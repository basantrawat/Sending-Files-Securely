from cryptography.fernet import Fernet
import hashlib

# # CREATING A RANDOM KEY
# key = Fernet.generate_key()
# file = open('key.key', 'wb')
# file.write(key)

keyfile = open('key.key', 'rb')
key = keyfile.read()

def encrypt(inFile, outFile):
    with open(inFile, 'rb') as f:
        data = f.read()
    fernet = Fernet(key)
    encrypted = fernet.encrypt(data)

    with open(outFile, 'wb') as f:
        f.write(encrypted)


def decrypt(inFile, outFile):
    f = open(inFile, 'rb')
    data = f.read()

    fernet = Fernet(key)
    decrypted = fernet.decrypt(data)
    
    d = open(outFile, 'wb')
    d.write(decrypted)


while True:
    option = input("Want To Encrypt OR Decrypt: ")
    if option.lower() == "encrypt":
        # Encrypting a Text File
        inFile = "Sample.txt"
        outFile = "EncryptedFile.txt"
        encrypt(inFile, outFile)
    elif option.lower() == "decrypt":
        # Decrypting a Text File
        inFile = "EncryptedFile.txt"
        outFile = "DecryptedFile.txt"
        decrypt(inFile, outFile)
    else:
        print("Wrong Choice, chose either Encrypt or Decrypt")