#!/usr/bin/python3

from Crypto import Random
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA512
import os
import time


class Encryptor:

    def AesKey(self, file_name):
        keys = get_random_bytes(32)
        file = open(file_name + '_AES.txt', 'wb')
        file.write(keys)
        file.close()
        return keys

    def RsaKey(self, file_name):
        key = RSA.generate(2048)
        private_key = key.export_key()
        file_out = open(file_name + ".private.pem", "wb")
        file_out.write(private_key)
        file_out.close()

        public_key = key.publickey().export_key()
        file_out = open(file_name + ".pubilc.pem", "wb")
        file_out.write(public_key)
        file_out.close()

    def Signature_RSA(self, file_name, message):
        key = RSA.import_key(open(file_name + ".private.pem").read())
        hash = SHA512.new(message)
        signature = pkcs1_15.new(key).sign(hash)
        with open(file_name + '.signature.txt', 'wb') as file:
            file.write(signature)

    def Verify_Signature(self, file_name, message):
        key = RSA.import_key(open(file_name + ".pubilc.pem").read())
        with open(file_name + '.signature.txt', 'rb') as file:
            signature = file.read()
        hash = SHA512.new(message)
        
        try:
            pkcs1_15.new(key).verify(hash, signature)
            print("The signature is valid.")
            return True
        except (ValueError, TypeError):
            print("The signature is not valid.")
            return False

    def pad(self, s):
        return s + b"\0" * (AES.block_size - len(s) % AES.block_size)

    def encrypt(self, message, key, key_size=256):
        message = self.pad(message)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return iv + cipher.encrypt(message)

    def encrypt_file(self, file_name):
        name_split = file_name.split('.')

        key = self.AesKey(file_name)
        with open(file_name, 'rb') as fo:
            plaintext = fo.read()

        enc = self.encrypt(plaintext, key)

        if name_split[1] == 'txt':
            self.RsaKey(name_split[0])
            self.Signature_RSA(name_split[0], enc)

        with open(file_name + ".enc", 'wb') as fo:
            fo.write(enc)

        print("Encrypt file ->", file_name, ' Successful.')

    def decrypt(self, ciphertext, key):
        iv = ciphertext[:AES.block_size]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext = cipher.decrypt(ciphertext[AES.block_size:])
        return plaintext.rstrip(b"\0")

    def decrypt_file(self, file_name):
        name_split = file_name.split('.')
        file_open = open(name_split[0] + '.' +
                         name_split[1] + '_AES.txt', 'rb')
        key = file_open.read()
        file_open.close()

        with open(file_name, 'rb') as fo:
            ciphertext = fo.read()

        if name_split[1] == 'txt':
            if not self.Verify_Signature(name_split[0], ciphertext):
                print("Can't Decrypt file please use file signature correct.")
                time.sleep(3)
                return

        dec = self.decrypt(ciphertext, key)
        with open(name_split[0] + '.dec.' + name_split[1], 'wb') as fo:
            fo.write(dec)
        print("Decrypt file ->", file_name, ' Successful.')


enc = Encryptor()
def clear(): return os.system('cls')


while True:
    clear()
    choice = int(input(
        "Please select the mode you want\n\n1. Select '1' to encrypt file.\n2. Select '2' to decrypt file.\n3. Select '3' to exit.\n"))
    clear()

    if choice == 1:
        enc.encrypt_file(str(input("Select File to Encrypt: ")))
        time.sleep(3)

    elif choice == 2:
        enc.decrypt_file(str(input("Select File to Decrypt: ")))
        time.sleep(3)

    elif choice == 3:
        exit()
    else:
        print("Please select a valid option!")
        continue
