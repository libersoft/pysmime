# pysmime/pkcs11.py
# Lorenzo Gaggini <lg@libersoft.it>
# Libersoft <tech@libersoft.it>
# http://www.libersoft.it
# License: http://www.gnu.org/licenses/gpl.txt

"""
Interact with OpenSSL by M2Crypto library wrapper and OpenSC pkcs11 engine to
access smart cards and retrieve private keys and certificates reference.
"""

from M2Crypto import Engine


def pkcs11_init(pkcs11_engine, pkcs11_driver):
    """
    Initializes Openssl pkcs11 engine with pkcs11 driver module and returns
    initialized engine for operations.
    """
    # loading Dynamic engine to load the PKCS#11 engine
    Engine.load_dynamic_engine("pkcs11", pkcs11_engine)
    # loading pkcs#11 module
    pkcs11 = Engine.Engine("pkcs11")
    pkcs11.ctrl_cmd_string("MODULE_PATH", pkcs11_driver)
    pkcs11.init()
    return pkcs11


def pkcs11_login(pkcs11, pin):
    """
    Performs authentication by PIN on the smart card.
    """
    # logging in"
    pkcs11.ctrl_cmd_string("PIN", pin)


def pkcs11_get_data(pkcs11, slot_id):
    """
    Returns references to private key and certificate stored on the slot_id of
    the smart card.
    """
    # grab private key and certificate reference from smart card
    private_key = pkcs11.load_private_key(slot_id)
    cert = pkcs11.load_certificate(slot_id)
    return private_key, cert
