from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.x509 import DNSName
from cryptography.x509.verification import PolicyBuilder, Store

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV

from base64 import b64encode, b64decode
import os
import datetime


# configuration de RSA
# - l'algorithme de hash est SHA256
hash = hashes.SHA256()
sign_alg = hashes.SHA256()
pad = padding.PSS(
    mgf=padding.MGF1(hashes.SHA256()),
    salt_length=padding.PSS.MAX_LENGTH
)
# - le padding à utiliser est OAEP
encrypt_alg = padding.OAEP(
    mgf=padding.MGF1(algorithm=hash),
    algorithm=hash,
    label=None
)
SYM_KEY_SIZE = 128  # Could be 256
ASYM_KEY_SIZE = 2048  # Could be 4096


####################################################################################################
# Clés
# Génération d'une clé privée RSA
def gen_privkey():
    return rsa.generate_private_key(public_exponent=65537, key_size=ASYM_KEY_SIZE)


# Génération d'une clé de chiffrement symétrique
def gen_sym_key():
    return AESGCMSIV.generate_key(SYM_KEY_SIZE)


# Récupération de la clé publique associée à une clé privée RSA
def get_pubkey(privkey):
    return privkey.public_key()


####################################################################################################
# Certificats
# génération de la structure x.509 nécessaire pour un certificat
def create_identity(COMMON_NAME, COUNTRY_NAME="CH", STATE="Vaud", LOCALITY="Yverdon-Les-Bains", ORGANIZATION="HEIG-VD"):
    return x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, COUNTRY_NAME),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, STATE),
        x509.NameAttribute(NameOID.LOCALITY_NAME, LOCALITY),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, ORGANIZATION),
        x509.NameAttribute(NameOID.COMMON_NAME, COMMON_NAME),
    ])


# création de la structure définissant la durée de validité d'un certificat
def get_duration(days=0, weeks=0):
    return datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=days, weeks=weeks)


# Création d'un certificat racine pour une autorité de certification
# 'privkey' est la clé privée de l'autorité
# 'duration' fixe la durée de validité du certificat
# 'identity' contient les informations d'identité pour le certificat x.509
def create_root_certificate(privkey, duration, identity):
    return x509.CertificateBuilder().subject_name(
        identity
    ).issuer_name(
        identity
    ).public_key(
        privkey.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.now(datetime.timezone.utc)
    ).not_valid_after(
        duration
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None),
        critical=True,
    ).add_extension(
        x509.KeyUsage(digital_signature=False, content_commitment=False, key_encipherment=False,
                      data_encipherment=False, key_agreement=True, key_cert_sign=True, crl_sign=False,
                      encipher_only=False, decipher_only=False),
        critical=True,
    ).add_extension(
        x509.SubjectKeyIdentifier.from_public_key(privkey.public_key()),
        critical=False,
    ).add_extension(
        x509.SubjectAlternativeName(
            [x509.DNSName(identity.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value)]
        ),
        critical=False,
    ).sign(privkey, algorithm=hash)


# Création d'un CSR (Certificate Signing Request) pour un serveur
# 'privkey' est la clé privée associée au certificat
# 'identity' contient les informations d'identité pour le certificat x.509
def create_server_csr(privkey, identity):
    return x509.CertificateSigningRequestBuilder().subject_name(
        identity
    ).add_extension(
        x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False, data_encipherment=False,
                      key_agreement=True, key_cert_sign=False, crl_sign=False, encipher_only=False,
                      decipher_only=False),
        critical=True,
    ).add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True,
    ).add_extension(
        x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
        critical=False,
    ).add_extension(
        x509.SubjectAlternativeName(
            [x509.DNSName(identity.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value)]
        ),
        critical=False,
    ).sign(privkey, algorithm=hash)


# Signe un CSR pour créer le certificat du serveur
# 'csr' est la demande de signature de certificat (sortie de create_csr)
# 'duration' est la durée de validité du certificat (sortie de get_duration)
# 'cert_ca' est le certificat parent
# 'privkey' est la clé privée associée au certificat parent
def sign_csr(csr, duration, cert_ca, privkey):
    """
    Sign a server CSR to create the certificate for the server

    Parameters :
    ------------
    csr : Certificate Signing Request to sign (create_csr)
    duration : Validity duration of the certificate (get_duration)
    cert_ca : Root of the certificate, will be the parent of the new certificate
    privkey : Private key associated to the root certificate
    """

    cert = x509.CertificateBuilder().subject_name(
        x509.Name(csr.subject)
    ).public_key(
        csr.public_key()
    ).issuer_name(
        x509.Name(cert_ca.subject)
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.now(datetime.timezone.utc)
    ).not_valid_after(
        duration
    ).add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(cert_ca.public_key()),
        critical=False,
    ).add_extension(
        x509.SubjectKeyIdentifier.from_public_key(csr.public_key()),
        critical=False,
    )

    for ext in csr.extensions:
        cert = cert.add_extension(ext.value, ext.critical)

    return cert.sign(privkey, algorithm=hash)


# Vérifie la validité d'un certificat serveur
# Vérifie que le COMMON_NAME du certificat est bien celui attendu
# Vérifie que le certificat est bien signé par le certificat racine
# 'ca' est le certificat racine qui certifie le certificat
# 'cert' est le certificat certifié par le certificat racine
# 'name' est le nom attendu dans le certificat
def verify_cert(ca, cert, name):
    """
    Verify the validity of a COMMON_NAME in a certificate against a root certificate

    Parameters :
    ------------
    ca : Root certificate that certifies the certificate
    cert : Certificate certified by the root certificate
    name : Name expected to be in the certificate
    """

    builder = PolicyBuilder().store(Store([ca]))
    verifier = builder.build_server_verifier(DNSName(name))
    try:
        verifier.verify(cert, [])
        return True
    except:
        return False


# Vérifie la validité d'un certificat racine
# 'cert' est le certificat racine à vérifier
# 'COMMON_NAME' est le nom attendu dans le certificat
def verify_root_cert(cert) -> bool:
    try:
        cert.public_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm,
        )
        return True
    except:
        return False


####################################################################################################
# Signature
# Signe des données avec une clé privée
# 'privkey' est la clé privée utilisée pour signer
# 'data' est les données à signer
def sign(privkey, data):
    """ Sign some data with a private key """
    return b64encode(privkey.sign(data, pad, sign_alg))


# Vérifie la signature de données avec un certificat
# 'cert' est le certificat utilisé pour vérifier la signature
# 'signature' est la signature à vérifier
def verify_signature(cert, signature, data):
    """ Verify the signature of some data using a certificate """
    signature = b64decode(signature)
    try:
        cert.public_key().verify(signature, data, pad, sign_alg)
        return True
    except:
        return False


####################################################################################################
# AEAD
# Chiffre un message avec une clé symétrique
# 'key' est la clé symétrique de chiffrement
# 'msg' est le message à chiffrer
# Retourne le message chiffré (nonce, cipher)
def encrypt(key, msg):
    nonce = os.urandom(12)
    boxed_msg = AESGCMSIV(key).encrypt(nonce, msg, None)
    return b64encode(nonce), b64encode(boxed_msg)


# Déchiffre un message avec une clé symétrique
# 'key' est la clé symétrique de chiffrement
# 'cipher' est le message chiffré (nonce, cipher)
def decrypt(key, cipher):
    nonce, cipher = cipher
    nonce = b64decode(nonce)
    cipher = b64decode(cipher)
    return AESGCMSIV(key).decrypt(nonce, cipher, None)


# Chiffre une clé symétrique avec une clé publique
# 'pubkey' est la clé publique de chiffrement
# 'key' est la clé symétrique à chiffrer
def wrap_key(pubkey, key):
    return pubkey.encrypt(key, encrypt_alg)


# Déchiffre une clé symétrique avec une clé privée
# 'privkey' est la clé privée de chiffrement
# 'boxed_key' est la clé symétrique chiffrée
def unwrap_key(privkey, boxed_key):
    return privkey.decrypt(boxed_key, encrypt_alg)


####################################################################################################
# IO
# Sauvegarde 'data' dans un fichier binaire
# le chemin est spécifié avec 'path'
def save_bin(path, data):
    with open(path, 'wb') as f:
        f.writelines(data)


# Récupère le stream obtenu en lisant un fichier binaire
# le chemin est spécifié avec 'path'
def read_bin(path):
    with open(path, 'rb') as f:
        return f.read()


# Exporte la clé privée 'privkey' en format PKCS#8
# le chemin du fichier cible est spécifié avec 'path'
# le contenu est encodé au format PEM
def save_privkey(path, privkey):
    pem = privkey.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    save_bin(path, [pem])


# Récupère une structure contenant une clé privée depuis un fichier binaire
# le contenu doit être encodé au format PEM
# le chemin est spécifié avec 'path'
def read_privkey(path):
    return serialization.load_pem_private_key(read_bin(path), password=None)


# Exporte la clé publique 'pubkey'
# le chemin du fichier cible est spécifié avec 'path'
# le contenu est encodé au format PEM
def save_pubkey(path, pubkey):
    pem = pubkey.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    save_bin(path, [pem])


# récupère une clé publique depuis un fichier binaire
# le contenu doit être encodé au format PEM
# le chemin est spécifié avec 'path'
def read_pubkey(path):
    return serialization.load_pem_public_key(read_bin(path))


# Exporte la demande de certification 'csr'
# le chemin du fichier cible est spécifié avec 'path'
# le contenu est encodé au format PEM
def save_csr(path, csr):
    pem = csr.public_bytes(serialization.Encoding.PEM)
    save_bin(path, [pem])


# Récupère une demande de certification depuis un fichier binaire
# le contenu doit être encodé au format PEM
# le chemin est spécifié avec 'path'
def read_csr(path):
    return x509.load_pem_x509_csr(read_bin(path))


# Exporte la demande le certificat x.509 'cert'
# le chemin du fichier cible est spécifié avec 'path'
# le contenu est encodé au format PEM
def save_cert(path, cert):
    pem = cert.public_bytes(serialization.Encoding.PEM)
    save_bin(path, [pem])


# Récupère un certificat x.509 depuis un fichier binaire
# le contenu doit être encodé au format PEM
# le chemin est spécifié avec 'path'
def read_cert(path):
    return x509.load_pem_x509_certificate(read_bin(path))


# Exporte la signature 'signature'
# la signature est appliquée à 'data'
# le chemin du fichier cible est spécifié avec 'path'
# le contenu est encodé au format base64
def save_signature(path, data, signature):
    data = b64encode(data)
    save_bin(path, [data, b"\n", signature, b"\n"])


# Récupère une signature depuis un fichier binaire
# le chemin est spécifié avec 'path'
# Retourne les données signées et la signature
def read_signature(path):
    data = read_bin(path).splitlines()
    assert len(data) == 2, "Unexpected format for signature file"
    return b64decode(data[0]), data[1]


# Exporte un message chiffré 'cipher' et le nécessaire pour déchiffrer
# 'boxed_key' contient la clé de chiffrement symétrique, chiffrée
# le chemin du fichier cible est spécifié avec 'path'
def save_hybrid_encryption(path, boxed_key, cipher):
    boxed_key = b64encode(boxed_key)
    nonce, cipher = cipher
    save_bin(path, [boxed_key, b"\n", nonce, b"\n", cipher, b"\n"])


# Récupère un message chiffré et le nécessaire pour déchiffrer depuis un fichier binaire
# le chemin est spécifié avec 'path'
# Retourne : boxed_key, (nonce, cipher)
def read_hybrid_encryption(path):
    data = read_bin(path).splitlines()
    assert len(data) == 3, f"Unexpected format for hybrid encryption file : {len(data)} instead of 3"
    return b64decode(data[0]), (data[1], data[2])
