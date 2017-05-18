"""
Encryption keys management module
Creates, updates and retrieves public/private keys for any user
Returns them in handy text format to put to the DCP or the database
Provides helpers for messages encryption

it's not much ausdigital, just some helpers which provide and read keys in ausdigital format
"""
import os
import logging
import shutil
import pprint  # NOQA
import uuid

import gnupg

logger = logging.getLogger(__name__)


class KeysException(Exception):
    pass


class GpgException(KeysException):
    pass


class CryptoProvider(object):
    """
    Helper to encrypt/decrypt and sign files
    Requires user to init, so loads user-related keys from database or another storage
    So, we keep our keys in the database, and then just init this object to work with them:

    * create key
    * return private/public keypair dump to save in the database
    * load key from the provided dump to this object (to use for futher encryption)
    * return public key to push to DCP

    Let's assume we have only single key here, for simplicity
    """

    DEFAULT_KEY_LEN = 1024

    TMP_DIR = '/tmp/uledger'

    def __init__(self):
        # first we need to create unique GPG directory, because GPG python library
        # works with files, so it's natural approach. we should delete this directory
        # after we do everything we need (so it lives just for single request or task)
        self.transaction_id = uuid.uuid4()
        self.home_dir = os.path.join(
            self.TMP_DIR,
            'uledger-gpg-{}'.format(
                self.transaction_id
            )
        )
        self.gpg = gnupg.GPG(homedir=self.home_dir)
        self.gpg.encoding = 'utf-8'

        self._public_keys = []
        self._private_keys = []

    def cleanup(self):
        """
        Remove the GPG directory, so nobody can use it if they stole our HDD
        """
        # TODO: always ensure it's called (use `finally` or whatever)
        shutil.rmtree(self.home_dir)

    def create_key(self, name_real, name_email, name_comment=None):
        """
        Generate new key
        Return dict with keys: private_key, public_key, fingerprint
        Assumes that you save the created key to the database immediately and
        then just pass it to this object on init

        https://pythonhosted.org/python-gnupg/#generating-keys
        https://pythonhosted.org/python-gnupg/#exporting-keys
        """
        input_data = self.gpg.gen_key_input(
            key_type="RSA",
            key_length=self.DEFAULT_KEY_LEN,
            name_real=name_real,
            name_comment=name_comment,
            name_email=name_email
        )
        key_resp = self.gpg.gen_key(input_data)

        result = {
            'fingerprint': key_resp.fingerprint,
        }
        # expore newly generated key
        exported_private = self.gpg.export_keys(
            [key_resp.fingerprint],
            True  # private
        )
        exported_public = self.gpg.export_keys(
            [key_resp.fingerprint],
            False  # public
        )
        result['private_key'] = exported_private
        result['public_key'] = exported_public
        return result

    def load_private_key(self, key_data):
        """
        Import private keys from given string to GPG keyring
        Or raise exception if nothing can be parsed
        """
        res = self.gpg.import_keys(key_data)
        if not res.fingerprints:
            raise KeysException("No private keys to import")
        private_keys = self.gpg.list_keys(True)
        if len(private_keys) == 0:
            raise KeysException("No private keys to import")
        self._private_keys += private_keys

    def load_public_key(self, key_data):
        """
        Import public keys from given string  to GPG keyring
        Or raise exception if nothing can be parsed
        may contain several keys; it's expected that you have the key you want
        to encrypt for in this list
        """
        res = self.gpg.import_keys(key_data)
        if not res.fingerprints:
            raise KeysException("No public keys to import")
        keys = self.gpg.list_keys(False)
        if len(keys) == 0:
            raise KeysException("No public keys to import")
        self._public_keys += keys

    def encypher(self, document, encypher_for):
        """
        Encrypt the document body for desired key and return the cyphertext
        Potentially memory-intensive, but okay for small files (up to 100 MB)
        """
        encrypt_result = self.gpg.encrypt(
            document,
            encypher_for,
            always_trust=True,
            armor=True,
        )
        if not encrypt_result.ok:
            logger.error(encrypt_result)
            raise GpgException("Can't encrypt the file", encrypt_result.status, encrypt_result)
        logger.debug("Successfully encrypted the file, cyphertext len is {}".format(len(str(encrypt_result))))
        return str(encrypt_result)

    def sign(self, document, sign_with, detached=True, binary=False):
        """
        Return signature body for given document and given key to use
        """
        return self.gpg.sign(
            document,
            default_key=sign_with,
            detach=detached,
            binary=binary,  # can be False for text output and True for binary .sig file
            clearsign=not detached,  # can't be True if detached
        ).data

    def decypher(self, cyphertext):
        result = self.gpg.decrypt(cyphertext, always_trust=True)
        if not result.ok:
            # there is a problem.
            # whole content of this IF block - try to determine the problem from gpg output
            # and some other kings of magic.
            # most likely it will break, but works for now.
            errors = [result.status.capitalize()]
            if 'secret key not available' in result.stderr:
                msg = 'Unknown secret key'
                output = result.stderr.splitlines()
                for oline in output:
                    if 'ENC_TO' in oline:
                        oline = oline.replace('[GNUPG:]', '').replace('ENC_TO', '').strip()
                        oline = oline.split()
                        oline = ' '.join([x for x in oline if len(x) > 5]).strip()
                        if oline:
                            msg += ". The key used to encrypt is {}".format(oline)
                            break
                errors.append(msg)
            raise GpgException('. '.join(errors))
        return str(result)

    def verify(self, data):
        """
        Check the signature of the data (attached, cleartext or not)
        Return:
            (is_valid, fingerprint_used, cleartext)
        """
        result = self.gpg.decrypt(data)
        return (result.valid, result.fingerprint or result.key_id, result.data.decode("utf-8"))
