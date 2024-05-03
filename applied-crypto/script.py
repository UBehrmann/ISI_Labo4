#!/usr/bin/env python3

from isi_labo4_functions import *

# KEYS
print("Generate private keys for Alice, Bob and Charlie")
# TODO : Generate the private keys for Alice, Bob and Charlie
save_privkey("./output/alice/privkey.pem", privkey_alice)
save_privkey("./output/bob/privkey.pem", privkey_bob)
save_privkey("./output/charlie/privkey.pem", privkey_charlie)

############################################
# CERTIFICATES

############################################
# Root certificate
# Remark : Use 'Alice', 'Bob' and 'Charlie' as COMMON_NAME for their identity

# Charlie creates a self-signed certificate to be used for his root CA
print("Charlie creates a root certificate for his own CA")
# Certificate must be valid for 10 years
# TODO : Create a self-signed certificate for Charlie
save_cert("./output/charlie/cert.pem", cert_charlie)


############################################
# CSR
# Alice and Bob create a certificate request to be submitted to Charlie's CA
print("Alice and Bob create their Certificate Signing Request")
# Alice
# TODO : Create a CSR for Alice
save_csr("./output/alice/cert.csr", csr_alice)

# Bob
# TODO : Create a CSR for Bob
save_csr("./output/bob/cert.csr", csr_bob)


############################################
# Sign CSRs
# Charlie's CA sign the CSRs to issue certificates
print("Charlie signs the CSR")
# Certificates must be valid for 3 months, each

# TODO : Sign the CSRs or Alice and Bob with the certificate of Charlie as root
# TODO : they must be valid for 3 months

save_cert("./output/alice/cert.pem", cert_alice)
save_cert("./output/bob/cert.pem", cert_bob)

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
# msg = ...
# signature = ...

# Verify Alice's signature (using assert)
assert verify_cert(cert_charlie, cert_alice, "Alice"), "Alice's certificate is invalid !"
assert verify_signature(cert_alice, signature, msg), "Signature is invalid !"

save_signature("./output/alice/signature.txt", msg, signature)


############################################
# Send encrypted data
# Alice writes a text message and encrypts it so that only Bob can read it
print("Alice writes an encrypted message for Bob")

# TODO : Encrypt a message with a symmetric key
# msg = ...
# key = ...
# cipher = ...
# TODO : Wrap the key with Bob's public key
# boxed_key = ...

save_hybrid_encryption("./output/bob/hybrid_encryption.txt", boxed_key, cipher)

# Here, Alice sends boxed_key and cipher to Bob through the network

# Bob's side
print("Bob decrypts the data")
# TODO : Unwrap the key
# unboxed_key = ...
assert unboxed_key == key, "Unwrapping of key failed"

# TODO : Decrypt the message
# plain_msg = ...
assert plain_msg == msg, "Decryption of message failed"
