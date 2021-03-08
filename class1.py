


alice_key = RSA.generate(2048)
f = open('alice_key.pem','wb')
f.write(alice_key.export_key('PEM'))
f.close();
print("Alice public key: ",alice_key.publickey)

bob_key = RSA.generate(2048)
f = open('bob_key.pem','wb')
print("Bob public key: ",bob_key.publickey)
f.write(bob_key.export_key('PEM'))
f.close();


alice = open('alice_key.pem','r')
bob = open('bob_key.pem', 'r')
a_key = RSA.import_key(alice.read())
b_key = RSA.import_key(bob.read())

#end content sourced from documentation

dkey = DesKey(b'FirstKey')

e_msg =dkey.encrypt(b'ECE690 is very interesting',padding=True)
print("\nEncrypted message\n")
print(e_msg)
d_msg = dkey.decrypt(e_msg, padding= True)
print("\nDecrypted message\n")
print(d_msg)
#encrypt message based on resource https://cryptobook.nakov.com/asymmetric-key-ciphers/rsa-encrypt-decrypt-examples
msg = b'ECE690 is very interesting'

encryptor = PKCS1_OAEP.new(b_key.publickey())

encrypted = encryptor.encrypt(msg)
print("Encrypted text: ", encrypted)
decryptor = PKCS1_OAEP.new(a_key)
decrypted = decryptor.decrypt(encrypted)
print('Decrypted:', decrypted)
#end content sourced from nakov


curve1 = registry.get_curve('brainpoolP256r1')
curve2 = registry.get_curve('brainpoolP256r1')
prk1 = secrets.randbelow(curve1.field.n)
prk2 = secrets.randbelow(curve2.field.n)
puk1 = prk1*curve1.g

puk2 = prk2*curve2.g;
sk1 = prk1*puk2
sk2 = prk2*puk1
comp1 = hex(sk1.x) + hex(sk1.y % 2)[2:]

comp2 = hex(sk2.x) + hex(sk2.y % 2)[2:]
print('equal? ', comp1==comp2)

from elliptic import make_keypair, hash_message, sign_message, verify_signature, point_add, scalar_mult,point_neg,is_on_curve, inverse_mod, curve


