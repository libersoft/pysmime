# pysmime/util.py
# Lorenzo Gaggini <lg@libersoft.it>
# Libersoft <tech@libersoft.it>
# http://www.libersoft.it
# License: http://www.gnu.org/licenses/gpl.txt

"""
Some useful functions.
"""

import logging
import psutil

from M2Crypto import BIO, X509, Rand


class BadKeyringSource(BaseException):
    """
    Exception raised if selected Keyring source is not valid. Ammitted values
    are file, memory and pkcs11.
    """
    pass


def BIO_from_buffer(data=None):
    """
    Returns a BIO oject for OpenSSL from input memory buffer
    """
    if not data or isinstance(data, bytes):
        return BIO.MemoryBuffer(data)
    else:
        return BIO.MemoryBuffer(bytes(data))


def BIO_from_file(fd):
    """
    Returns a BIO object for OpenSSL from input file descriptor
    """
    return BIO.File(fd)


def BIO_from_file_path(file_path):
    """
    Returns a BIO object for OpenSSL from input file path
    """
    try:
        fd = open(file_path, 'rb')
        file_bio = BIO_from_file(fd)
    except IOError as e:
        logging.error('input file not found ' + str(e))
    return file_bio


def set_keyring(smime, private_key, cert, keyring_source):
    """
    Sets private key and certificate for input smime object based on keyring
    source.

    @type smime: M2Crypto.SMIME
    @param smime: the smime object to update with key and certificate data
    @type private_key: filepath or M2Crypto.BIO or M2Crypto.EVP.PKey
    @param private_key: private key reference, could be from file, from memory
        or from pkcs11 smartcard, based on keyring_soruce input parameter
    @type cert: filepath or M2Crypto.BIO or M2Crypto.X509.X509
    @param cert: certificate, could be from filepath, from memory or from
        pkcs11 smartcard, based on keyring_soruce input parameter
    @type keyring_source: str
    @keyword keyring_source: the type of the source for input certificate, used
        to recall the appropriate method for SMIME settings. Ammitted
        values are: file, memory, pkcs11.
    @rtype: boolean
    @return: True if a valid keyring source, else False
    @raise BadKeyringSource: the selected Keyring source is not valid. Ammitted
        values are file, memory and pkcs11.
    """
    if keyring_source == 'file':
        smime.load_key(private_key, cert)
        return True
    elif keyring_source == 'memory':
        smime.load_key_bio(private_key, cert)
        return True
    elif keyring_source == 'pkcs11':
        smime.pkey = private_key
        smime.x509 = cert
        return True
    else:
        logging.error('unknown keyring source: ' + keyring_source +
                      '; possible values: file, memory, pkcs11')
        raise BadKeyringSource('unknown keyring source: ' + keyring_source +
                               '; possible values: file, memory, pkcs11')


def set_certificate(cert, keyring_source):
    """
    Sets certificate for input x509 object based on keyring source.

    @type cert: filepath or M2Crypto.BIO or M2Crypto.X509.X509
    @param cert: certificate, could be from filepath, from memory or from
        pkcs11 smartcard, based on keyring_soruce input parameter
    @type keyring_source: str
    @keyword keyring_source: the type of the source for input certificate, used
        to recall the appropriate method for X509 settings. Ammitted
        values are: file, memory, pkcs11.
    @rtype: M2Crypto.X509.X509 or None
    @return: the new X509 certificate if a valid keyring source, else False
    @raise BadKeyringSource: the selected Keyring source is not valid. Ammitted
        values are file, memory and pkcs11.
    """
    if keyring_source == 'file':
        x509 = X509.load_cert(cert)
        return x509
    elif keyring_source == 'memory':
        x509 = X509.load_cert_bio(cert)
        return x509
    elif keyring_source == 'pkcs11':
        x509.cert = cert
        return x509
    else:
        logging.error('unknown keyring source: ' + keyring_source +
                      '; possible values: file, memory, pkcs11')
        raise BadKeyringSource('unknown keyring source: ' + keyring_source +
                               '; possible values: file, memory, pkcs11')


def seed_prng():
    """
    Seed the pseudorandom number generator
    """
    sources = ['sensors_temperatures', 'users', 'virtual_memory',
               'net_connections', 'pids', 'disk_partitions']
    try:
        # Python 3
        Rand.rand_seed(bytes(''.join([str(getattr(psutil, a, str)())
                       for a in sources]), 'utf-8'))
    except TypeError:
        # Python 2
        Rand.rand_seed(str([getattr(psutil, a, str)()
                       for a in sources]))

    return True
