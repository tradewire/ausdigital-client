"""
TAP message composers
Requires crypto module and dcp client
Input: plaintext document
Output: signed tap message

Usage:
    MessageProvider.create(
        "wow such invoice",
        "urn:senderpid::xxx",
        "sender private key in GPG format",
        "urn:receiverpid::yyy"
    )
"""
import json
import hashlib
import logging

from ausdigital.crypto import CryptoProvider
from ausdigital.dcp import DcpClient

logger = logging.getLogger(__name__)


class TapMessageError(Exception):
    pass


class MessageProvider(object):
    """
    Class to create new message
    * get message plaintext
    * sign it
    * encrypt it
    * get hashes on the way going
    * create message finally
    """

    def __init__(self, sender_pid, crypt, sign_with, encypher_for):
        self.sender_pid = sender_pid
        self.crypt = crypt
        self.sign_with = sign_with  # fingerprint of private key
        self.encypher_for = encypher_for  # fingerprint of public key

    @classmethod
    def create(cls, document, sender_pid, sender_private_key, receiver_pid, reference=''):
        """
        Helper function, which accepts document and both sender and receiver info
        and returns message body and message signature

        Use this one if you don't want where to start.

        Parameters:
            * document - cleartext document, str
            * sender_pid - sender participant ID, used for message.json creation, str
            * sender_private_key - dict with 2 fields: 'private_key' and 'fingerprint',
                                   and containing private key of the sender
            * receiver_pid - receiver participant ID, used for key retrieval,
                             encyphering and so on. str
        """
        crypt = CryptoProvider()
        crypt.load_private_key(sender_private_key['private_key'])

        receiver_key_info = DcpClient.fetch_participant_key(receiver_pid)

        if receiver_key_info is None:
            raise TapMessageError(
                "Can't retrieve receiver public key from the DCP - check participant ID"
            )

        # load receiver public key into crypto provider
        crypt.load_public_key(receiver_key_info['pubKey'])

        logger.info(
            "We are going to compose message with private key %s and public key %s",
            sender_private_key['fingerprint'],
            receiver_key_info['fingerprint']
        )

        # just helper object, put whatever you want here
        message_info = {
            'sign_with': sender_private_key['fingerprint'],
            'encypher_for': receiver_key_info['fingerprint'],
            'sender_pid': sender_pid,
        }

        prov = cls(
            sender_pid=sender_pid,
            crypt=crypt,
            sign_with=sender_private_key['fingerprint'],
            encypher_for=receiver_key_info['fingerprint']
        )
        message_body = prov.compose_message(document, reference=reference)
        message_signature = prov._get_signed_document(message_body, detached=True)
        crypt.cleanup()
        return (message_body, message_signature, message_info)

    def _get_signed_document(self, document, detached):
        return self.crypt.sign(document, sign_with=self.sign_with, detached=detached)

    def _encypher(self, document):
        return self.crypt.encypher(document, encypher_for=self.encypher_for)

    def _get_hash(self, document):
        """
        Return document SHA256 hash in HEX representation by document content
        """
        return hashlib.sha256(document).hexdigest()

    def compose_message(self, document, reference='', indent=2):
        """
        Create JSON message file, making field content on fly
        """
        signed_document = self._get_signed_document(document, detached=False)
        cyphertext = self._encypher(signed_document)
        doc_hash = self._get_hash(signed_document)
        message = {
            'cyphertext': cyphertext,
            'hash': doc_hash,
            'reference': reference,
            'sender': self.sender_pid,
        }
        return json.dumps(message, indent=indent)
