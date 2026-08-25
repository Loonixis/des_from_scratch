# DES From Scratch

A small implementation of the Data Encryption Standard written in Python.

I made this project to understand how DES works internally instead of relying on an existing cryptography library. The implementation includes the initial and final permutations, key scheduling, Feistel rounds, expansion, S-box substitution, and P-box permutation.

This is mainly a learning project. It should be noted that DES is outdated and should not be used to protect real data.

## Implementations

- 64-bit data blocks
- 64-bit keys, including parity bits
- 16 Feistel rounds
- DES key schedule
- Encryption and decryption of a single block
- A standard DES test vector
- Basic tests using Python's `unittest` module

## Structure 

```text
des-from-scratch/
├── des\_cipher.py
├── constants.py
├── example.py
├── tests/
│   └── test\_des.py
├── README.md
└── .gitignore

