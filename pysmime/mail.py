# pysmime/mail.py
# Lorenzo Gaggini <lg@libersoft.it>
# Libersoft <tech@libersoft.it>
# http://www.libersoft.it
# License: http://www.gnu.org/licenses/gpl.txt

"""
Functions to verify, sign, encrypt and decrypt SMIME mail entity, build on top
of pysmime/core.
"""

from M2Crypto import SMIME
from pysmime.core import encrypt, sign, decrypt, verify
from pysmime.util import BIO_from_buffer


def mail_encrypt(mail, recipient_cert, keyring_source='file',
                 cypher='des_ede3_cbc'):
    """
    Encrypts the input mail data with public key of input certificate.

    @type mail: str
    @param mail: mail text to encrypt.
    @type recipient_cert: filepath or M2Crypto.BIO or M2Crypto.X509.X509
    @param recipient_cert: the recipient certificate reference from filepath,
        could be from file, from memory or from pkcs11 smartcard, based on
        keyring_source input parameter.
    @type keyring_source: str
    @keyword keyring_source: the type of the source for input certificate, used
        to recall the appropriate method for encrypter settings. Ammitted
        values are: file, memory, pkcs11.
    @type cypher: str
    @keyword cypher: the cypher to use for encryption of the data, run
        "openssl enc -help" for supported cyphers, you have to choose a public
        key cypher from availables.
    @rtype: str
    @return: the encrypted data in PEM format with MIME header.
    """
    p7 = encrypt(BIO_from_buffer(mail), recipient_cert, keyring_source, cypher)
    encrypted_mail = BIO_from_buffer()
    SMIME.SMIME().write(encrypted_mail, p7)
    return encrypted_mail.read()


def mail_decrypt(encrypted_mail, recipient_private_key, recipient_cert,
                 keyring_source='file', type='PEM'):
    """
    Decrypts the input mail data with input private key and input certificate.

    @type encrypted_mail: str
    @param encrypted_mail: encrypted mail body to decrypt.
    @type recipient_private_key: filepath or M2Crypto.BIO or M2Crypto.EVP.PKey
    @param recipient_private_key: recipient private key reference, could be
        from file, from memory or from pkcs11 smartcard, based on
        keyring_source input parameter.
    @type recipient_cert: filepath or M2Crypto.BIO or M2Crypto.X509.X509
    @param recipient_cert: recipient certificate, could be from filepath, from
        memory or from pkcs11 smartcard, based on keyring_source input
        parameter.
    @type keyring_source: str
    @keyword keyring_source: the type of the source for input certificate, used
        to recall the appropriate method for decrypter settings. Ammitted
        values are: file, memory, pkcs11.
    @type type: str
    @keyword type: specifies the type of input PKCS#7 data: PEM or DER
    @rtype: str
    @return: the decrypted data in plain form.
    """
    decrypted_mail = decrypt(BIO_from_buffer(encrypted_mail),
                             recipient_private_key, recipient_cert,
                             keyring_source, type)
    return decrypted_mail


def mail_sign(mail, sender_private_key, sender_cert, keyring_source='file',
              type='PEM', algo='sha256'):
    """
    Signs the input mail data with input private key and input certificate.

    @type mail: str
    @param mail: mail text to sign.
    @type sender_private_key: filepath or M2Crypto.BIO or M2Crypto.EVP.PKey
    @param sender_private_key: recipient private key reference, could be from
        file, from memory or from pkcs11 smartcard, based on keyring_source
        input parameter.
    @type sender_cert: filepath or M2Crypto.BIO or M2Crypto.X509.X509
    @param sender_cert: recipient certificate, could be from filepath, from
        memory or from pkcs11 smartcard, based on keyring_source input
        parameter.
    @type keyring_source: str
    @keyword keyring_source: the type of the source for input certificate, used
        to recall the appropriate method for decrypter settings. Ammitted
        values are: file, memory, pkcs11.
    @type type: str
    @keyword type: specifies the type of output PKCS#7 data: PEM or DER
    @type algo: str
    @keyword algo: specifies message digest algorithm (micalg), e.g. sha256
    @rtype: str
    @return: the signed data in PEM format with MIME header.
    """
    p7 = sign(BIO_from_buffer(mail), sender_private_key, sender_cert,
              keyring_source, type, algo)
    signed_mail = BIO_from_buffer()
    SMIME.SMIME().write(signed_mail, p7, BIO_from_buffer(mail))
    return signed_mail.read()


def mail_verify(signed_mail, certstore_path, AUTO_SIGNED_CERT=False,
                type='PEM'):
    """
    Verifies the input mail data against the certificates stored in file at
    certstore path.

    @type signed_mail: str
    @parameter signed_mail: the signed mail text to verify.
    @type certstore_path: filepath
    @parameter certstore_path: path to the file of the trusted certificates,
        for example /etc/ssl/certs/ca-certificats.crt.
    @type AUTO_SIGNED_CERT: boolean
    @parameter AUTO_SIGNED_CERT: to accept or not auto signed certificates as
        valid for verification.
    @type type: str
    @keyword type: specifies the type of input PKCS#7 data: PEM or DER
    @rtype: list
    @return: list of the certificate of the signers verified.
    """
    signed_certs = []
    signed_certs = verify(BIO_from_buffer(signed_mail), certstore_path,
                          AUTO_SIGNED_CERT, type)
    if signed_certs:
        return signed_certs
    else:
        return False
