import json
import logging
import requests


logger = logging.getLogger(__name__)


class TapError(Exception):
    pass


class TapGwError(Exception):
    pass


def send_tap_message(tap_url, message_body, message_signature):
    # http://ausdigital.org/ausdigital-tap/
    logger.info("Trying to send TAP message to %s", tap_url)
    resp = requests.post(
        tap_url,  # or 'https://httpbin.org/post',
        files={
            'message': message_body,
            'signature': message_signature
        }
    )
    if resp.status_code not in (200, 201, 202):
        logger.error(
            "TAP URL %s returns %s status code (%s)",
            tap_url,
            resp.status_code,
            resp.content[:1000],
        )
        raise TapError("TAP URL returns {} status code".format(resp.status_code), tap_url)
    return resp.json()


class TapGwClient(object):
    """
    Helper to create/retrieve TAP endpoints for the participant
    where participant is our user, not just random receiver

    Usage:
        tap_client = TapGwClient(
            self.tap_host,
            self.tap_base_url,
            participant_id=user.profile.ibr_participant_id,
            jwt=tap_jwt
        )
        new_messages = tap_client.fetch_new_messages()
    """

    def __init__(self, tap_host, tap_base_url, participant_id, jwt):
        self.tap_host = tap_host
        self.tap_base_url = tap_base_url
        self.participant_id = participant_id
        self.jwt = jwt

    def get_or_create_endpoint(self):
        endp_uuid = self.get_tap_endpoint()
        if endp_uuid is None:
            endp_uuid = self.create_tap_endpoint()
        return '{}{}endpoints/{}/message/'.format(
            self.tap_host,
            self.tap_base_url,
            endp_uuid
        )

    def get_tap_endpoint(self):
        """
        Return {tap_url} value at tap-gw.testpoint.io or whatever installation do we use
        If no endpoint has been created yet - create some
        """
        # it's fine when we have endpoint-per-client, not all-endpoints-at-ledger
        # but if we want we can create endpoint-per-ledger - it doesn't matter for the protocol
        logger.info("Trying to get tap-gw endpoint for %s", self.participant_id)
        resp = requests.get(
            "{}{}endpoints/".format(
                self.tap_host,
                self.tap_base_url
            ),
            headers={
                'Content-type': 'application/json',
                'Accept': 'application/json',
                'Authorization': 'JWT {}'.format(self.jwt)
            }
        )

        if resp.status_code != 200:
            raise TapGwError(resp.status_code, resp.content.decode("utf-8"))
        rj = resp.json()
        try:
            first_endpoint = rj['data'][0]['id']
        except IndexError:
            # just empty list
            return None
        except Exception as e:
            logger.error(rj)
            logger.exception(e)
            return None

        if 'data' not in rj:
            raise TapGwError()
        return first_endpoint

    def create_tap_endpoint(self):
        logger.info("Trying to create tap-gw endpoint for %s", self.participant_id)

        resp = requests.post(
            "{}{}endpoints/".format(
                self.tap_host,
                self.tap_base_url
            ),
            data=json.dumps({
                "participantId": self.participant_id,
                "source": "uLedger",
            }),
            headers={
                'Content-type': 'application/json',
                'Accept': 'application/json',
                'Authorization': 'JWT {}'.format(self.jwt)
            }
        )
        if resp.status_code not in (200, 201) or 'data' not in resp.json():
            raise TapGwError('Unable to create endpoint', resp.status_code, resp.content.decode('utf-8'))
        return resp.json()['data']['id']

    def fetch_new_messages(self):
        """
        Return plain list of dicts about the messages, received by participant_id
        and haven't been updated as 'read' yet
        """
        resp = requests.get(
            "{}{}messages/?status=new".format(
                self.tap_host,
                self.tap_base_url
            ),
            headers={
                'Content-type': 'application/json',
                'Accept': 'application/json',
                'Authorization': 'JWT {}'.format(self.jwt)
            }
        )
        if resp.status_code != 200:
            raise TapGwError(resp.status_code, resp.content[:1000])
        return resp.json()['data']

    def fetch_message_body(self, message_id):
        logger.info("Trying to fetch message %s body", message_id)
        resp = requests.get(
            "{}{}messages/{}/body/".format(
                self.tap_host,
                self.tap_base_url,
                message_id
            ),
            headers={
                'Content-type': 'application/json',
                'Accept': 'application/json',
                'Authorization': 'JWT {}'.format(self.jwt)
            }
        )
        if resp.status_code != 200:
            raise TapGwError(resp.status_code, resp.content[:1000])
        return resp.content.decode('utf-8') or ''

    def mark_message_as_read(self, message_id):
        logger.info("Trying to mark message %s as read", message_id)
        resp = requests.patch(
            "{}{}messages/{}/metadata/".format(
                self.tap_host,
                self.tap_base_url,
                message_id
            ),
            data=json.dumps({
                "status": "read",
            }),
            headers={
                'Content-type': 'application/json',
                'Accept': 'application/json',
                'Authorization': 'JWT {}'.format(self.jwt)
            }
        )
        if resp.status_code != 200:
            raise TapGwError(resp.status_code, resp.content[:1000])
        return True
