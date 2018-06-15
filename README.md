Encryption of any file using symmetrycal (ECB/CBC/CFB/OFB) AES encrypting and RSA for encrypting AES key.
After encrypting creates easy-to-parse .XML file, that contains information about used algorithm, key length, type of encryption.
During RSA encryption it also encrypts private key using hash of user's password for AES algoritm as initializing vector, and adds it to encryptedPrivate folder, leaving public key unchanged.
Removes original file after encrypting or decrypting.

Uses java swing for graphical interface.

All code is in src/bsk1/mainForm.java.
Unit tests are in test/bsk1/mainFormTest.java