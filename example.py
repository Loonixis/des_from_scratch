from des_cipher import encrypt, decrypt

# Using the classic known test vectors for DES
# Key:        133457799BBCDFF1
# Plaintext:  0123456789ABCDEF
# Ciphertext: 85E813540F0AB405

key = bytes.fromhex("133457799BBCDFF1")
plaintext = bytes.fromhex("0123456789ABCDEF")

ciphertext = encrypt(plaintext,key)
decrypted_pt = decrypt(ciphertext,key)

print("Ciphertext: ",ciphertext.hex().upper())
print("Decrypted: ",decrypted_pt.hex().upper())