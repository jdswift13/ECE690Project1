from des import DesKey

dkey = DesKey(b'FirstKey')

e_msg =dkey.encrypt(b'ECE690 is very interesting',padding=True)
print("\nEncrypted message\n")
print(e_msg)
d_msg = dkey.decrypt(e_msg, padding= True)
print("\nDecrypted message\n")
print(d_msg)