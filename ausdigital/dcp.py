"""
DCP Client
assumes that DCP we already have some JWT to talk to given DCP
"""
import datetime
import json
import logging
import urllib.parse

import dateutil.parser
import requests
from django.utils import timezone

from .dcl import DclClient

logger = logging.getLogger(__name__)

SIMPLEUBL_SCHEME = 'urn:apec.org:simpleUBL:v1'
SIMPLEUBL_DOCID = 'urn:apec.org:invoice'

DBC_SCHEME = 'dbc'
DBC_DOCID = "urn:www.digitalbusinesscouncil.com.au:dbc:einvoicing:doctype:core-invoice:xsd::core-invoice-1##urn:www.digitalbusinesscouncil.com.au:dbc:einvoicing:process:einvoicing01:ver1.0"

# full list of DBC-based participant IDs, which we support
# to send and receive our small invoices
# Warning: real business applications would be quite confused by some
# text documents coming with UBL protocol, but test installations shall handle
# such cases fine
SUPPORTED_DOCUMENTS = (
    (SIMPLEUBL_SCHEME, SIMPLEUBL_DOCID),
    (DBC_SCHEME, DBC_DOCID),
    (DBC_SCHEME, 'urn:oasis:names:specification:ubl:schema:xsd:Invoice-2'),
    (DBC_SCHEME, 'urn:www.digitalbusinesscouncil.com.au:dbc:einvoicing:doctype:core-invoice:xsd::core-invoice-1'),
    (DBC_SCHEME, 'invoice'),
    (DBC_SCHEME, 'core-invoice'),
    (DBC_SCHEME, 'taxes'),
)

DEFAULT_SCHEME = SIMPLEUBL_SCHEME
DEFAULT_DOCID = SIMPLEUBL_DOCID

# also worth investigaion:
# bdx-docid-qns::urn:oasis:names:specification:ubl:schema:xsd:Order-2::Order##UBL-2.0
# urn:example.org:services:SupplierOrderProcessing
# urn:un:unece:uncefact:data:standard:CrossIndustryInvoice:2


class DcpError(Exception):
    pass


def get_metadata_template(participant_id, service_scheme, document_id, tap_url):
    """
    Return complete service metadata to put to the DCP
    tap_url is something like "https://tap-gw.testpoint.io/api/endpoints/xxx/message/"
    participant_id is rendered, with :: as delemiter
    TODO: consult the spec and put less demo values here
    """
    pid_scheme, pid_value = participant_id.split("::")
    template = {
        "ProcessList": [],
        "DocumentIdentifier": {
            "scheme": service_scheme,
            "value": document_id
        },
        "id": "{}::{}".format(service_scheme, document_id),
        "ParticipantIdentifier": {
            "scheme": pid_scheme,
            "value": pid_value
        }
    }

    # I have some suspicions that it's wrong to have that document types
    # hardcoded here, and they shall depend on service_scheme and document_id somehow
    documents = ['invoice', 'adjustment', 'taxes']
    for document_type in documents:
        template['ProcessList'].append({
            "ProcessIdentifier": {
                "scheme": service_scheme,
                "value": document_type
            },
            "ServiceEndpointList": [
                {
                    # "ServiceActivationDate": "2017-04-13",
                    # "Certificate": "123",
                    "EndpointURI": tap_url,
                    "transportProfile": "TBD",
                    # "ServiceExpirationDate": "2017-04-17",
                    # "RequireBusinessLevelSignature": "false",
                    # "TechnicalInformationUrl": "123",
                    # "MinimumAuthenticationLevel": "0",
                    "ServiceDescription": "uLedger document receiver"
                }
            ]
        })
    return template.copy()


def crawl_tap_urls_from_metadata(metadata_dict):
    urls = []
    for process in metadata_dict['ProcessList']:
        try:
            process_scheme, process_id = process['ProcessIdentifier']['scheme'], process['ProcessIdentifier']['value']
            for service_endpoint in process['ServiceEndpointList']:
                urls.append(
                    (
                        process_scheme,
                        process_id,
                        service_endpoint['transportProfile'].lower(),
                        service_endpoint['EndpointURI']
                    )
                )
        except IndexError:
            # wrong row, which is fine
            pass
    return urls


class DcpClient(object):
    service_scheme = DEFAULT_SCHEME
    service_id = DEFAULT_DOCID

    def __init__(self, dcp_host, jwt=None):
        self.dcp_host = dcp_host
        if self.dcp_host.endswith('/'):
            self.dcp_host = self.dcp_host[:-1]
        self.jwt = jwt  # used only for writing requests, okay to have empty
        logger.info("Created DCP client for host %s", self.dcp_host)
        return

    # Update area

    def service_metadata_delete(self, participant_id, service_id):
        resp = requests.delete(
            "{}/{}/service/{}".format(
                self.dcp_host,
                urllib.parse.quote(participant_id),
                urllib.parse.quote(service_id)
            ),
            headers={
                'Content-type': 'application/json',
                'Accept': 'application/json',
                'Authorization': 'JWT {}'.format(self.jwt)
            }
        )
        if resp.status_code not in (404, 204):
            logger.error(
                "Trying to delete service metadata %s from %s, result %s %s",
                service_id,
                participant_id,
                resp.status_code,
                resp.content[:1000]
            )
            return False
        return True

    def service_metadata_put(self, participant_id, tap_url):
        """
        Update participant ID service metadata to the given host
        """
        logger.info("Updating DCP metadata for PID %s to %s", participant_id, tap_url)

        # we support sending to many formats, but accept only to our default
        shall_update = (
            (DEFAULT_SCHEME, DEFAULT_DOCID),
        )
        for service_scheme, document_id in shall_update:
            metadata = get_metadata_template(
                participant_id,
                service_scheme, document_id,
                tap_url
            )
            service_id = "{}::{}".format(service_scheme, document_id)
            resp = requests.put(
                "{}/{}/service/{}".format(
                    self.dcp_host,
                    participant_id,
                    urllib.parse.quote(service_id)
                ),
                data=json.dumps(metadata),
                headers={
                    'Content-type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': 'JWT {}'.format(self.jwt)
                }
            )
            if resp.status_code != 200:
                # ignore errors, we have all other service metadatas to set
                # raise DcpError(str(resp.content))
                logger.error(resp.content)
        pass

    def public_key_put(self, pid, key_fingerprint, key_data):
        logger.info("Pushing DCP key %s for %s", key_fingerprint, pid)
        resp = requests.post(
            "{}/{}/keys/".format(
                self.dcp_host,
                pid,
            ),
            data=json.dumps({
                "pubKey": key_data,
                # "revoked": None,
                "fingerprint": key_fingerprint,
            }),
            headers={
                'Content-type': 'application/json',
                'Accept': 'application/json',
                'Authorization': 'JWT {}'.format(self.jwt)
            }
        )
        if resp.status_code not in (201, 200):
            raise DcpError(str(resp.content))
            # logger.error(resp.content)
        logger.info(
            "Pushined DCP key %s for %s successfully, output %s",
            key_fingerprint,
            pid,
            resp.json()
        )

    # Readonly area, classmethods, don't require client initialization with JWT and stuff

    @classmethod
    def fetch_participant_key(cls, participant_id, all_of_them=False):
        """
        Return first not-revoked public key for the participant by ID
        or None if no keys may be found
        Result used to encrypt something for the recipient participant_id
        """
        logger.info("Trying to fetch public keys for %s", participant_id)
        expiration_duetime = timezone.now() + datetime.timedelta(minutes=10)

        # determine DCP host from DCL protocol, may be cached for some considerable time
        dcp_host = DclClient.fetch_dcp_url(participant_id)

        get_resp = requests.get(
            "{}/{}/keys/".format(
                dcp_host,
                participant_id,
            ),
            headers={
                'Accept': 'application/json'
            }
        )
        if get_resp.status_code != 200:
            logger.info("Non-200 response for public keys list for %s", participant_id)
            # TODO: would be better to raise exception if status != 404 and return None if 404
            # so client can try request or go check participant ID validity
            return None

        keys = []
        for possible_key_info in get_resp.json():
            expires_at = possible_key_info['revoked'] or None
            if expires_at:
                expires_at = dateutil.parser.parse(expires_at)
            if expires_at and expires_at < expiration_duetime:
                # almost expired, try next one
                continue
            # looks legit
            keys.append(possible_key_info)
            if not all_of_them:
                break  # first one is fine
        if not keys:
            logger.info("No valid public keys for %s have been found", participant_id)
        if all_of_them:
            if keys:
                logger.info("%s public keys for %s have been found", len(keys), participant_id)
            return keys
        else:
            return keys[0] if len(keys) > 0 else None

    @classmethod
    def fetch_participant_tap_url(cls, participant_id, desired_document):
        """
        For given participant_id and desired_document (invoice, for example)
        return first appropriate tap url to send message to
        Bunch of TODOs
        TODO: currently it returnst first fit tap_url and service_id. It's better
              to return all supported tap_urls, so they can be tried one by one
              untill first works.
        """
        logger.info(
            "Trying to fetch tap-gw url for PID %s and document %s",
            participant_id,
            desired_document
        )

        all_capabilities = cls.fetch_participant_capabilities(participant_id)

        service_row = None
        for service_row in all_capabilities:
            if service_row in SUPPORTED_DOCUMENTS:
                # for every supported entity
                # try get metadata
                metadata = cls.fetch_metadata(participant_id, "{}::{}".format(*service_row))
                if metadata:
                    # if metadata is not none - try to crawl tap_urls from it...
                    all_tap_urls = crawl_tap_urls_from_metadata(metadata)
                    for scheme, doc, proto, url in all_tap_urls:
                        if doc == desired_document:
                            return url, "{}::{}".format(scheme, doc)
        # once we reach this line we can say that nothing have been found
        return None, None

    @classmethod
    def fetch_participant_capabilities(cls, participant_id):
        """
        By participant_id returns all service metadata ids, supported by this
        business.
        Output format:
            [
                ('dbc', 'taxreceipt'),
                ('ubl-xml-2', 'invoice'),
                ...
            ]
        Empty list if nothing found
        """
        result = []

        dcp_host = DclClient.fetch_dcp_url(participant_id)

        get_resp = requests.get(
            "{}/{}".format(
                dcp_host,
                urllib.parse.quote(participant_id),
            ),
            headers={
                'Accept': 'application/json'
            }
        )
        if get_resp.status_code == 200:
            # if found
            for service_id in get_resp.json().get('ServiceMetadataReferenceCollection', []):
                if '::' not in service_id:
                    result.append(('unknown', service_id))
                service_scheme, service_value = service_id.split('::', maxsplit=1)
                result.append((service_scheme, service_value))
        return result

    @classmethod
    def fetch_metadata(cls, participant_id, service_id):
        """
        By participant_id and service_id returns the metadata
        Metadata usually is a huge dict with a lot of supported documents and processes
        Examples in ausdigital-dcp spec http://ausdigital.org/specs/ausdigital-dcp/2.0/#response-formats
        """
        dcp_host = DclClient.fetch_dcp_url(participant_id)

        resp = requests.get(
            "{}/{}/service/{}".format(
                dcp_host,
                urllib.parse.quote(participant_id),
                urllib.parse.quote(service_id),
            ),
            headers={
                'Accept': 'application/json'
            }
        )
        if resp.status_code == 200:
            return resp.json()
        return None
