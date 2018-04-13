# pysmime/core.py
# Lorenzo Gaggini <lg@libersoft.it>
# Libersoft <tech@libersoft.it>
# http://www.libersoft.it
# License: http://www.gnu.org/licenses/gpl.txt

"""
Core functions to verify, sign, encrypt and decrypt SMIME data, build just on
top of M2Crypto library wrapper to OpenSSL.
"""

import os
import base64
import logging

from M2Crypto import SMIME, X509, m2
from pysmime.util import (BIO_from_buffer, set_keyring, set_certificate,
                          seed_prng)


class BadPKCS7Type(BaseException):
    """
    Exception raised if requested PKCS#7 type is not valid.
    Ammitted values are PEM and DER.
    """
    pass


class CertStoreNotAvailable(BaseException):
    """
    Exception raised if the reference certstore for verification is not
    available.
    """
    pass


class MissingSignerCertificate(BaseException):
    """
    Exception raised if the input PKCS#7 is not a signed PKCS#7.
    """
    pass


def encrypt(input_bio, cert, keyring_source, cypher):
    """
    Encrypts the input data with the public key in the certificate from keyring
    source with selected cypher.

    @type input_bio: M2Crypto.BIO
    @param input_bio: input data to encrypt.
    @type cert:  filepath or M2Crypto.BIO or M2Crypto.X509.X509
    @param cert: the recipient certificate reference from filepath, could be
        from file, from memory or from pkcs11 smartcard, based on
        keyring_soruce input parameter.
    @type keyring_source: str
    @keyword keyring_source: the type of the source for input certificate, used
        to recall the appropriate method for encrypter settings. Ammitted
        values are: file, memory, pkcs11.
    @type cypher: str
    @keyword cypher: the cypher to use for encryption of the data, run
        "openssl enc -help" for supported cyphers, you have to choose a public
        key cypher from availables.
    @rtype: M2Crypto.SMIME.PKCS7
    @return: the PKCS#7 encrypted data in PEM format.
    """
    encrypter = SMIME.SMIME()
    x509 = set_certificate(cert, keyring_source)
    sk = X509.X509_Stack()
    sk.push(x509)
    encrypter.set_x509_stack(sk)
    encrypter.set_cipher(SMIME.Cipher(cypher))
    seed_prng()
    try:
        p7 = encrypter.encrypt(input_bio)
    except SMIME.SMIME_Error as e:
        logging.error('smime error: ' + str(e))
        raise
    except SMIME.PKCS7_Error as e:
        logging.error('pkcs7 error: ' + str(e))
        raise
    return p7


def decrypt(input_bio, private_key, cert, keyring_source, type):
    """
    Decrypts the input data with the private key and the certificate from
    keyring source.

    @type input_bio: M2Crypto.BIO
    @param input_bio: input data to sign.
    @type private_key: filepath or M2Crypto.BIO or M2Crypto.EVP.PKey
    @param private_key: recipient private key reference, could be from file,
        from memory or from pkcs11 smartcard, based on keyring_soruce input
        parameter.
    @type cert: filepath or M2Crypto.BIO or M2Crypto.X509.X509
    @param cert: recipient certificate, could be from filepath, from memory or
        from pkcs11 smartcard, based on keyring_soruce input parameter.
    @type keyring_source: str
    @keyword keyring_source: the type of the source for input certificate, used
        to recall the appropriate method for decrypter settings. Ammitted
        values are: file, memory, pkcs11.
    @type type: str
    @keyword type: specifies the type of input PKCS#7 data: PEM or DER
    @rtype: str
    @return: the decrypted data in plain form.
    @raise BadPKCS7Type: The requested PKCS#7 type is not valid. Ammitted
        values are PEM and DER.
    """
    decrypter = SMIME.SMIME()
    set_keyring(decrypter, private_key, cert, keyring_source)
    try:
        if type == 'PEM':
            p7, data_bio = SMIME.smime_load_pkcs7_bio(input_bio)
        elif type == 'DER':
            p7 = SMIME.PKCS7(m2.pkcs7_read_bio_der(input_bio._ptr()), 1)
        else:
            logging.error('pkcs7 type error: unknown type')
            raise BadPKCS7Type('unknown type: ' + type +
                               '; possible values: PEM, DER')
    except SMIME.SMIME_Error as e:
        logging.error('load pkcs7 error: ' + str(e))
        pass
    try:
        decrypted_data = decrypter.decrypt(p7)
    except SMIME.SMIME_Error as e:
        logging.error('smime error: ' + str(e))
        raise
    except SMIME.PKCS7_Error as e:
        logging.error('pkcs7 error: ' + str(e))
        raise
    return decrypted_data.replace(b'\r', b'')


def sign(input_bio, private_key, cert, keyring_source, type, algo):
    """
    Signs the input data with the private key and the certificate from keyring
    source.

    @type input_bio: M2Crypto.BIO
    @param input_bio: input data to sign.
    @type private_key: filepath or M2Crypto.BIO or M2Crypto.EVP.PKey
    @param private_key: sender private key reference, could be from file,
        from memory or from pkcs11 smartcard, based on keyring_soruce input
        parameter.
    @type cert: filepath or M2Crypto.BIO or M2Crypto.X509.X509
    @param cert: sender certificate, could be from filepath, from memory or
        from pkcs11 smartcard, based on keyring_soruce input parameter.
    @type keyring_source: str
    @keyword keyring_source: the type of the source for input certificate, used
        to recall the appropriate method for signer settings. Ammitted
        values are: file, memory, pkcs11.
    @type type: str
    @keyword type: specifies the type of output PKCS#7 data: PEM or DER
    @type algo: str
    @keyword algo: specifies message digest algorithm, e.g. sha256
    @rtype: M2Crypto.SMIME.PKCS7
    @return: the PKCS#7 signed data in PEM or DER format.
    """
    signer = SMIME.SMIME()
    set_keyring(signer, private_key, cert, keyring_source)
    seed_prng()
    try:
        if type == 'PEM':
            p7 = signer.sign(input_bio, flags=SMIME.PKCS7_DETACHED, algo=algo)
        elif type == 'DER':
            p7 = signer.sign(input_bio, algo=algo)
        else:
            logging.error('pkcs7 type error: unknown type')
            raise BadPKCS7Type('unknown type: ' + type +
                               '; possible values: PEM, DER')
    except SMIME.SMIME_Error as e:
        logging.error('smime error: ' + str(e))
        raise
    except SMIME.PKCS7_Error as e:
        logging.error('pkcs7 error: ' + str(e))
        raise
    return p7


def verify(input_bio, certstore_path, AUTO_SIGNED_CERT, type):
    """
    Retrieves X.509 certificate from input data and verifies signed message
    using as certificate store input certstore, inspired by:
    U{http://code.activestate.com/recipes/285211/}.

    @type input_bio: M2Crypto.BIO
    @param input_bio: input data to verify
    @type certstore_path: filepath
    @param certstore_path: path to the file of the trusted certificates,
        for example /etc/ssl/certs/ca-certificats.crt.
    @type type: str
    @keyword type: specifies the type of input PKCS#7 data: PEM or DER
    @type AUTO_SIGNED_CERT: boolean
    @keyword AUTOSIGNED_CERT: to accept or not auto signed certificates as
        valid for verification.
    @rtype: list or None
    @return: a list of verified certificates retrieved from the original data
        if verification success, else None.
    @raise CertStoreNotAvailable: the reference certstore for verification is
        not available.
    @raise MissingSignerCertificate: the input PKCS#7 is not a signed PKCS#7.
    """
    signer = SMIME.SMIME()
    cert_store = X509.X509_Store()
    if not os.access(certstore_path, os.R_OK):
        logging.error('certstore not available for verify')
        raise CertStoreNotAvailable('certstore not available %' %
                                    (certstore_path))
    cert_store.load_info(certstore_path)
    signer.set_x509_store(cert_store)
    data_bio = None
    try:
        if type == 'PEM':
            p7, data_bio = SMIME.smime_load_pkcs7_bio(input_bio)
        elif type == 'DER':
            p7 = SMIME.PKCS7(m2.pkcs7_read_bio_der(input_bio._ptr()), 1)
        else:
            logging.error('pkcs7 type error: unknown type')
            raise BadPKCS7Type('unknown type: ' + type +
                               '; possible values: PEM, DER')
    except SMIME.SMIME_Error as e:
        logging.error('load pkcs7 error: ' + str(e))
        raise
    if data_bio is not None:
        data = data_bio.read()
        data_bio = BIO_from_buffer(data)
    sk3 = p7.get0_signers(X509.X509_Stack())
    if len(sk3) == 0:
        logging.error('missing certificate')
        raise MissingSignerCertificate('missing certificate')
    signer_certs = []
    for cert in sk3:
        signer_certs.append(
            "-----BEGIN CERTIFICATE-----\n{}-----END CERTIFICATE-----\n"
            .format(base64.encodestring(cert.as_der()).decode('ascii')))
    signer.set_x509_stack(sk3)
    v = None
    try:
            if AUTO_SIGNED_CERT:
                v = signer.verify(p7, data_bio, flags=SMIME.PKCS7_NOVERIFY)
            else:
                v = signer.verify(p7, data_bio)
    except SMIME.SMIME_Error as e:
        logging.error('smime error: ' + str(e))
        raise
    except SMIME.PKCS7_Error as e:
        logging.error('pkcs7 error: ' + str(e))
        raise
    if data_bio is not None and data != v and v is not None:
        return
    return signer_certs
