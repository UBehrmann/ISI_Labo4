#!/usr/bin/env python3

from isi_labo4_functions import *

# KEYS
print("Generate private keys for Alice, Bob and Charlie")
# TODO : Generate the private keys for Alice, Bob and Charlie

privkey_alice = gen_privkey()
privkey_bob = gen_privkey()
privkey_charlie = gen_privkey()

save_privkey("./applied-crypto/output/alice/privkey.pem", privkey_alice)
save_privkey("./applied-crypto/output/bob/privkey.pem", privkey_bob)
save_privkey("./applied-crypto/output/charlie/privkey.pem", privkey_charlie)

############################################
# CERTIFICATES

# Create certificate for Alice, Bob and Charlie

identity_alice = create_identity("Alice")
identity_bob = create_identity("Bob")
identity_charlie = create_identity("Charlie")

############################################
# Root certificate
# Remark : Use 'Alice', 'Bob' and 'Charlie' as COMMON_NAME for their identity

# Charlie creates a self-signed certificate to be used for his root CA
print("Charlie creates a root certificate for his own CA")
# Certificate must be valid for 10 years
# TODO : Create a self-signed certificate for Charlie

# Date + 10 years
ten_years = datetime.datetime.now() + datetime.timedelta(days=3650)

cert_charlie = create_root_certificate(privkey_charlie, ten_years, identity_charlie)

save_cert("./applied-crypto/output/charlie/cert.pem", cert_charlie)


############################################
# CSR
# Alice and Bob create a certificate request to be submitted to Charlie's CA
print("Alice and Bob create their Certificate Signing Request")
# Alice
# TODO : Create a CSR for Alice

csr_alice = create_server_csr(privkey_alice, identity_alice)

save_csr("./applied-crypto/output/alice/cert.csr", csr_alice)

# Bob
# TODO : Create a CSR for Bob

csr_bob = create_server_csr(privkey_bob, identity_bob)

save_csr("./applied-crypto/output/bob/cert.csr", csr_bob)


############################################
# Sign CSRs
# Charlie's CA sign the CSRs to issue certificates
print("Charlie signs the CSR")
# Certificates must be valid for 3 months, each

# TODO : Sign the CSRs or Alice and Bob with the certificate of Charlie as root
# TODO : they must be valid for 3 months

tree_months = datetime.datetime.now() + datetime.timedelta(days=90)

cert_alice = sign_csr(csr_alice, tree_months, cert_charlie, privkey_charlie)
cert_bob = sign_csr(csr_bob, tree_months, cert_charlie, privkey_charlie)

save_cert("./applied-crypto/output/alice/cert.pem", cert_alice)
save_cert("./applied-crypto/output/bob/cert.pem", cert_bob)

# Verify certificates
print("We stop there in case a certificate is not valid")
assert verify_root_cert(cert_charlie), "Charlie's certificate is invalid !"
assert verify_cert(cert_charlie, cert_alice, "Alice"), "Alice's certificate is invalid !"
assert verify_cert(cert_charlie, cert_bob, "Bob"), "Bob's certificate is invalid !"

############################################
# Sign data

# Alice writes a text message and signs it with her private key
print("Alice signs a text message with her private key")
# TODO : Sign a message with Alice's private key
msg = "Hello Bob, this is Alice"
msg = msg.encode('utf-8')  # Convert the message to bytes
signature = sign(privkey_alice, msg)

# Verify Alice's signature (using assert)
assert verify_cert(cert_charlie, cert_alice, "Alice"), "Alice's certificate is invalid !"
assert verify_signature(cert_alice, signature, msg), "Signature is invalid !"

save_signature("./applied-crypto/output/alice/signature.txt", msg, signature)


############################################
# Send encrypted data
# Alice writes a text message and encrypts it so that only Bob can read it
print("Alice writes an encrypted message for Bob")

# TODO : Encrypt a message with a symmetric key
msg = "Hello Bob, this is Alice"
msg = msg.encode('utf-8')  # Convert the message to bytes
key = gen_sym_key()
cipher = encrypt(key, msg)

# TODO : Wrap the key with Bob's public key
boxed_key = wrap_key(get_pubkey(privkey_bob), key)

save_hybrid_encryption("./applied-crypto/output/bob/hybrid_encryption.txt", boxed_key, cipher)

# Here, Alice sends boxed_key and cipher to Bob through the network

# Bob's side
print("Bob decrypts the data")
# TODO : Unwrap the key
unboxed_key = unwrap_key(privkey_bob, boxed_key)
assert unboxed_key == key, "Unwrapping of key failed"

# TODO : Decrypt the message
plain_msg = decrypt(unboxed_key, cipher)
assert plain_msg == msg, "Decryption of message failed"
