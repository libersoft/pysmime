# pysmime/test/PySmimeTest.py
# Lorenzo Gaggini <lg@libersoft.it>
# Libersoft <tech@libersoft.it>
# http://www.libersoft.it
# License: http://www.gnu.org/licenses/gpl.txt

"""
Basic test class to test basic function of the package. At the moment there
are no PKCS11 test cases.
"""

import unittest
import sys
sys.path.append("..")

import mail
import file


class PySmimeTest(unittest.TestCase):

    def setUp(self):
        self.mail = "This is a mail messagge text."
        self.file = "test_file"
        self.file_out = "test_file.p7m"
        self.sender_cert_path = "certs/sender.pem"
        self.sender_key_path = "certs/sender_key.pem"
        self.recipient_cert_path = "certs/recipient.pem"
        self.recipient_key_path = "certs/recipient_key.pem"
        self.certstore_path = "/etc/ssl/certs/ca-certificates.crt"

    def test_mail_encryption(self):
        encrypted_mail = mail.mail_encrypt(self.mail, self.recipient_cert_path)
        decrypted_mail = mail.mail_decrypt(encrypted_mail,
                            self.recipient_key_path, self.recipient_cert_path)
        self.assertEqual(self.mail, decrypted_mail)

    def test_mail_sign(self):
        signed_mail = mail.mail_sign(self.mail, self.sender_key_path,
                                    self.sender_cert_path)
        signed_certs = mail.mail_verify(signed_mail, self.certstore_path, True)
        original_certificate = open(self.sender_cert_path, 'rb').read()
        certificate = signed_certs[0]
        self.assertEqual(original_certificate.replace('\n', ''),
                        certificate.replace('\n', ''))

    def test_file_encryption(self):
        encrypted_file = file.file_encrypt(self.file, self.recipient_cert_path,
                                           self.file_out)
        decrypted_file = file.file_decrypt(self.file_out,
                            self.recipient_key_path, self.recipient_cert_path)
        original_file_data = open(self.file, 'rb').read()
        self.assertEqual(original_file_data, decrypted_file)

    def test_file_sign(self):
        signed_file = file.file_sign(self.file, self.sender_key_path,
                                    self.sender_cert_path, self.file_out)
        signed_certs = file.file_verify(self.file_out, self.certstore_path,
                                        True)
        original_certificate = open(self.sender_cert_path, 'rb').read()
        certificate = signed_certs[0]
        self.assertEqual(original_certificate.replace('\n', ''),
                        certificate.replace('\n', ''))


if __name__ == '__main__':
    unittest.main()
