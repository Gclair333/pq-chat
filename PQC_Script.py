from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from kybercffi import Kyber512
import os

# Temporary symmetric key (32 bytes = AES-256)
# KEY = AESGCM.generate_key(bit_length = 256)
# aesgcm = AESGCM(KEY)

# Generate Kyber Key (Post-Quantum NIST Standard)
kem = Kyber512()
public_key, secret_key = kem.generate_keypair()

ciphertext_kem, shared_key = kem.encapsulate(public_key)
shared_key_recv = kem.decapsulate(ciphertext_kem, secret_key)

aesgcm = AESGCM(shared_key_recv)

def encrypt(message: str) -> tuple:

    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, message.encode(), None)
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

def decrypt(combined: bytes) -> str:

    nonce = combined[:12]
    ciphertext = combined[12:]
    
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)

    print('Decrypted Bytes:', ' '.join(str(b) for b in plaintext))
    print(f'Decrypted Hex: {plaintext.hex()}')

    return plaintext.decode()

if __name__ == "__main__":

    user_input = str(input('\nEnter message to encrypt: '))

    combined = encrypt(user_input)
    
    print(f'Decrypted Message: {decrypt(combined)}\n')