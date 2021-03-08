from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import ECC
from tinyec import registry
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import Crypto.Hash.MD5 as MD5
import random
import binascii
import secrets
from cryptography.hazmat.primitives import serialization


from cryptography.hazmat.primitives.asymmetric import rsa
#generate key and save to pem made with help from https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa.html
private_keyA = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
f = open('alice_key.pem','wb')
f.write(private_keyA.private_bytes(encoding=serialization.Encoding.PEM,format=serialization.PrivateFormat.PKCS8,encryption_algorithm=serialization.BestAvailableEncryption(b'temp')))
f.close()
private_keyB = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
f = open('bob_key.pem','wb')
f.write(private_keyB.private_bytes(encoding=serialization.Encoding.PEM,format=serialization.PrivateFormat.PKCS8,encryption_algorithm=serialization.BestAvailableEncryption(b'temp')))
f.close()

with open("alice_key.pem", "rb") as key_file:
    alice_key = serialization.load_pem_private_key(
        key_file.read(),
        password=b'temp',
    )
with open("bob_key.pem", "rb") as key_file:
    bob_key = serialization.load_pem_private_key(
        key_file.read(),
        password=b'temp',
    )
message = b"Cryptography is interesting"
smsg = b"CrypTography is interesting"
print("Signed message: ", smsg)
print("Raw message: ", message)
signature = alice_key.sign(
    smsg,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)
ciphertext = bob_key.public_key().encrypt(
    message,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
print("Ciphertext: ", ciphertext)
plaintext = bob_key.decrypt(
    ciphertext,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
try:
    alice_key.public_key().verify(signature,
    message,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
    )
    print("Signature valid! Decrypted message: ", plaintext)
except:
  print("Invalid signature")
