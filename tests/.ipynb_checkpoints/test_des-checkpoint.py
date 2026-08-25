import unittest

from des_cipher import encrypt, decrypt


class TestDES(unittest.TestCase):

    def test_standard_des_vector(self):
        key = bytes.fromhex("133457799BBCDFF1")
        plaintext = bytes.fromhex("0123456789ABCDEF")
        expected_ciphertext = bytes.fromhex("85E813540F0AB405")

        ciphertext = encrypt(plaintext, key)

        self.assertEqual(ciphertext, expected_ciphertext)
        self.assertEqual(decrypt(ciphertext, key), plaintext)

    def test_encrypt_then_decrypt(self):
        key = b"12345678"
        plaintext = b"ABCDEFGH"

        ciphertext = encrypt(plaintext, key)

        self.assertNotEqual(ciphertext, plaintext)
        self.assertEqual(decrypt(ciphertext, key), plaintext)

    def test_invalid_key_length(self):
        with self.assertRaises(ValueError):
            encrypt(b"ABCDEFGH", b"short")

    def test_invalid_block_length(self):
        with self.assertRaises(ValueError):
            encrypt(b"short", b"12345678")


if __name__ == "__main__":
    unittest.main()
