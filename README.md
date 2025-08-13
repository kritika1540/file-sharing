How it works:

1-Key Generation – The recipient generates an RSA key pair (public and private keys).

2-File Encryption –

A random symmetric key (e.g., AES) is generated for encrypting the file.

The file is encrypted using this symmetric key.

The symmetric key is then encrypted with the recipient’s RSA public key.

3-File Transfer – The encrypted file and the encrypted key are sent to the recipient.

Decryption –

The recipient uses their RSA private key to decrypt the symmetric key.

The symmetric key is used to decrypt the file.


<img width="665" height="306" alt="image" src="https://github.com/user-attachments/assets/470f185a-76b2-48bc-add8-4298043e996c" />


<img width="704" height="584" alt="image" src="https://github.com/user-attachments/assets/d02288ba-b15f-4158-90d3-74f8d2c348c2" />

