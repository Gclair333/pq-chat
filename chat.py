from Alice import alice
from Bob import bob

# Step 1: Alice and Bob perform key exchange
ciphertext_kem = alice.encapsulate(bob.public_key)
bob.decapsulate(ciphertext_kem)
print('\nShared keys match:', alice.shared_key == bob.shared_key)

# Step 2: Alice sends a message to Bob
msg_a = input('\nAlice → Bob: ')
encrypted_a = alice.encrypt(msg_a)
print('Bob decrypted:', bob.decrypt(encrypted_a))

# Step 3: Bob sends a message to Alice
msg_b = input('\n\nBob → Alice: ')
encrypted_b = bob.encrypt(msg_b)
print('Alice decrypted:', alice.decrypt(encrypted_b) + '\n')