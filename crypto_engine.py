from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from kybercffi import Kyber512
import os

class PQCUser:

    def __init__(self):

        self.kem = Kyber512()
        self.public_key, self.secret_key = self.kem.generate_keypair()
        self.shared_key = None
        self.aes = None

    def encapsulate(self, peer_public_key):

        ciphertext_kem, shared_key = self.kem.encapsulate(peer_public_key)
        self.shared_key = shared_key
        self.aes = AESGCM(shared_key)

        return ciphertext_kem

    def decapsulate(self, ciphertext_kem):

        shared_key = self.kem.decapsulate(ciphertext_kem, self.secret_key)
        self.shared_key = shared_key
        self.aes = AESGCM(shared_key)

    def encrypt(self, message: str):

        nonce = os.urandom(12)
        ciphertext = self.aes.encrypt(nonce, message.encode(), None)
        tag = ciphertext[-16:]
        combined = nonce + ciphertext

        print(f'\nEncrypted Message: {message}')    # Remove this line for production use, it exposes the plaintext message before it's encrypted - Useful for testing and debugging only!
        print('Nonce Bytes:', ' '.join(str(b) for b in nonce))
        print('Nonce Hex:', nonce.hex())
        print('Ciphertext Bytes:', ' '.join(str(b) for b in ciphertext))
        print('Ciphertext Hex:', ciphertext.hex())
        print('Auth Tag Bytes:', ' '.join(str(b) for b in tag))
        print('Auth Tag Hex:', tag.hex(), '\n')

        return combined

    def decrypt(self, combined: bytes):

        nonce = combined[:12]
        ciphertext = combined[12:]
        plaintext = self.aes.decrypt(nonce, ciphertext, None)

        print('Decrypted Bytes:', ' '.join(str(b) for b in plaintext))
        print('Decrypted Hex:', plaintext.hex())

        return plaintext.decode()