# pysmime/file.py
# Lorenzo Gaggini <lg@libersoft.it>
# Libersoft <tech@libersoft.it>
# http://www.libersoft.it
# License: http://www.gnu.org/licenses/gpl.txt

"""
Functions to verify, sign, encrypt and decrypt SMIME files, build on top of
pysmime/core.
"""

import logging

from pysmime.core import encrypt, sign, decrypt, verify
from pysmime.util import BIO_from_buffer, BIO_from_file_path


def file_encrypt(input_file_path, recipient_cert, output_file_path=None,
                 keyring_source='file', cypher='des_ede3_cbc'):
    """
    Encrypts the input file data with public key of input certificate. If an
    output file path is present, the encrypted data is also written to that
    file.

    @type input_file_path: filepath
    @param input_file_path: the filepath from where retrieve the data to
        encrypt
    @type recipient_cert: filepath or M2Crypto.BIO or M2Crypto.X509.X509
    @param recipient_cert: the recipient certificate reference from filepath,
        could be from file, from memory or from pkcs11 smartcard, based on
        keyring_source input parameter.
    @type output_file_path: filepath
    @param output_file_path: if present, the filepath where to write the
        encrypted data.
    @type keyring_source: str
    @keyword keyring_source: the type of the source for input certificate, used
        to recall the appropriate method for encrypter settings. Ammitted
        values are: file, memory, pkcs11.
    @type cypher: str
    @keyword cypher: the cypher to use for encryption of the data, run
        "openssl enc -help" for supported cyphers, you have to choose a public
        key cypher from availables.
    @rtype: M2Crypto.SMIME.PKCS7
    @return: the PKCS#7 encrypted data in DER format.
    """
    file_bio = BIO_from_file_path(input_file_path)
    p7 = encrypt(file_bio, recipient_cert, keyring_source, cypher)
    encrypted_data = BIO_from_buffer()
    p7.write_der(encrypted_data)
    if output_file_path:
        try:
            with open(output_file_path, 'wb') as fd:
                fd.write(encrypted_data.read())
        except IOError as e:
            logging.error('IOError in writing encrypted file ' + str(e))
            raise
    return encrypted_data


def file_decrypt(input_file_path, recipient_private_key, recipient_cert,
                 output_file_path=None, keyring_source='file', type='DER'):
    """
    Decrypts the input file data with input private key and input certificate.
    If an output file path is present, the decrypted data is also written to
    that file.

    @type input_file_path: filepath
    @param input_file_path: the filepath from where retrieve the data to
        decrypt
    @type recipient_private_key: filepath or M2Crypto.BIO or M2Crypto.EVP.PKey
    @param recipient_private_key: recipient private key reference, could be
        from file, from memory or from pkcs11 smartcard, based on
        keyring_source input parameter.
    @type recipient_cert: filepath or M2Crypto.BIO or M2Crypto.X509.X509
    @param recipient_cert: recipient certificate, could be from filepath, from
        memory or from pkcs11 smartcard, based on keyring_source input
        parameter.
    @type output_file_path: filepath
    @param output_file_path: if present, the filepath where to write the
        decrypted data.
    @type keyring_source: str
    @keyword keyring_source: the type of the source for input certificate, used
        to recall the appropriate method for decrypter settings. Ammitted
        values are: file, memory, pkcs11.
    @type type: str
    @keyword type: specifies the type of input PKCS#7 data: PEM or DER
    @rtype: str
    @return: the decrypted data in plain form.
    """
    file_bio = BIO_from_file_path(input_file_path)
    decrypted_data = decrypt(file_bio, recipient_private_key, recipient_cert,
                             keyring_source, type)
    if output_file_path:
        try:
            with open(output_file_path, 'wb') as fd:
                fd.write(decrypted_data)
        except IOError as e:
            logging.error('IOError in writing decrypted file ' + str(e))
            raise
    return decrypted_data


def file_sign(input_file_path, sender_private_key, sender_cert,
              output_file_path=None, keyring_source='file', type='DER',
              algo='sha512'):
    """
    Signs the input file data with input private key and input certificate.
    If an output file path is present, the signed data is also written to that
    file.

    @type input_file_path: filepath
    @param input_file_path: the filepath from where retrieve the data to
        sign.
    @type sender_private_key: filepath or M2Crypto.BIO or M2Crypto.EVP.PKey
    @param sender_private_key: recipient private key reference, could be from
        file, from memory or from pkcs11 smartcard, based on keyring_source
        input parameter.
    @type sender_cert: filepath or M2Crypto.BIO or M2Crypto.X509.X509
    @param sender_cert: recipient certificate, could be from filepath, from
        memory or from pkcs11 smartcard, based on keyring_source input
        parameter.
    @type output_file_path: filepath
    @param output_file_path: if present, the filepath where to write the
        signed data.
    @type keyring_source: str
    @keyword keyring_source: the type of the source for input certificate, used
        to recall the appropriate method for decrypter settings. Ammitted
        values are: file, memory, pkcs11.
    @type type: str
    @keyword type: specifies the type of output PKCS#7 data: PEM or DER
    @type algo: str
    @keyword algo: specifies message digest algorithm, e.g. sha512
    @rtype: M2Crypto.SMIME.PKCS7
    @return: the PKCS#7 signed data in DER format.
    """
    file_bio = BIO_from_file_path(input_file_path)
    p7 = sign(file_bio, sender_private_key, sender_cert, keyring_source, type,
              algo)
    signed_data = BIO_from_buffer()
    p7.write_der(signed_data)
    if output_file_path:
        try:
            with open(output_file_path, 'wb') as fd:
                fd.write(signed_data.read())
        except IOError as e:
            logging.error('IOError in writing signed files ' + str(e))
            raise
    return signed_data


def file_verify(input_file_path, certstore_path, AUTO_SIGNED_CERT=False,
                type='DER'):
    """
    Verifies the input file data against the certificates stored in file at
    certstore path.

    @type input_file_path: filepath
    @parameter input_file_path: the filepath from where retrieve the data to
        verify.
    @type certstore_path: filepath
    @parameter certstore_path: path to the file of the trusted certificates,
        for example /etc/ssl/certs/ca-certificats.crt.
    @type AUTO_SIGNED_CERT: boolean
    @parameter AUTO_SIGNED_CERT: to accept or not auto signed certificates as
        valid for verification.
    @type type: str
    @keyword type: specifies the type of input PKCS#7 data: PEM or DER
    @rtype: list
    @return: list of the certificate of the signer verified.
    """
    signed_certs = []
    file_bio = BIO_from_file_path(input_file_path)
    signed_certs = verify(file_bio, certstore_path, AUTO_SIGNED_CERT, type)
    return signed_certs
