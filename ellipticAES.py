from elliptic import make_keypair, hash_message, sign_message, verify_signature, point_add, scalar_mult,point_neg,is_on_curve, inverse_mod, curve
from Crypto.Cipher import AES
from tinyec import registry
import random
import binascii
import secrets
#Written by Jacob Swift but with reference to: https://github.com/andreacorbellini/ecc/blob/master/scripts/ecdsa.py

private0, public0 = make_keypair()
private1, public1 = make_keypair()
print("Private key 0:", hex(private1))
print("Public key 0: (0x{:x}, 0x{:x})".format(*public1))#format figured out from the source, displays values as we need them displayed
print("Private key 1:", hex(private1))
print("Public key 1: (0x{:x}, 0x{:x})".format(*public1))

print(public1)
shared_key0 = scalar_mult(private0, public1)
shared_key1 = scalar_mult(private1, public0)
print("\nShared key 1: \n")
print(shared_key0)
print("\nShared key 2: \n")
print(shared_key1)
aes_key = bytes(str(shared_key0[0]),encoding='utf8')#use shared key as AES encryption key

cipher = AES.new((aes_key)[0:16], AES.MODE_EAX)
nonce = cipher.nonce
#encrypt using AES encryption with key made from shared key of elliptic curve
ciphertext, tag = cipher.encrypt_and_digest(b"Cryptography is lit! :^)")
print("Ciphertext: ", ciphertext)
#to show that we can use ECC here the other shared key is used to construct the decryption key
aes_key = bytes(str(shared_key1[0]),encoding='utf8')
cipher2 = AES.new((aes_key)[0:16], AES.MODE_EAX, nonce=nonce)
plaintext = cipher2.decrypt(ciphertext)
print("Plaintext: ", plaintext)


curve1 = registry.get_curve('brainpoolP256r1')
curve2 = registry.get_curve('brainpoolP256r1')
prk1 = secrets.randbelow(curve1.field.n)
prk2 = secrets.randbelow(curve2.field.n)
puk1 = prk1*curve1.g

puk2 = prk2*curve2.g;
print("Private key 0:", hex(prk1))
print("Public key 0: ",puk1)
print("Private key 1:", hex(prk2))
print("Public key 1: ",puk2)
sk1 = prk1*puk2
sk2 = prk2*puk1
comp1 = hex(sk1.x) + hex(sk1.y % 2)[2:]

comp2 = hex(sk2.x) + hex(sk2.y % 2)[2:]
aes_key = bytes(str(comp1),encoding='utf8')#use shared key as AES encryption key
cipher = AES.new((aes_key)[0:16], AES.MODE_EAX)
nonce = cipher.nonce
#encrypt using AES encryption with key made from shared key of elliptic curve
ciphertext, tag = cipher.encrypt_and_digest(b"Cryptography is lit! :^)")

nonce = cipher.nonce

print("Ciphertext: ", ciphertext)
aes_key = bytes(str(comp2),encoding='utf8')
cipher2 = AES.new((aes_key)[0:16], AES.MODE_EAX, nonce=nonce)
plaintext = cipher2.decrypt(ciphertext)
print("Decrypted message: ", plaintext)
