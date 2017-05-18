import os

TEST_DEFAULT_DCP = os.environ.get(
    'AUSDIGITAL_DEFAULT_DCP_URL',
    'https://dcp.testpoint.io'
)


class DclClient(object):
    """
    DCL allows to discover DCP for participant ID using the spec
    docs.oasis-open.org/bdxr/BDX-Location/v1.0/cos01/BDX-Location-v1.0-cos01.html

    But, while we use testpoint, we most likely use dcp.testpoint.io,
    so this object implementation has low priority.
    """

    @classmethod
    def fetch_dcp_hostname(cls, participant_id):
        """
        Make DNS NAPTR lookup to given participant ID DCL and return retrieved
        DCP hostname(s)
        TODO: implement it.
        """
        dcp = TEST_DEFAULT_DCP
        if dcp.startswith('https://'):
            dcp = dcp[len('https://'):]
        if dcp.startswith('http://'):
            dcp = dcp[len('http://'):]
        return dcp

    @classmethod
    def fetch_dcp_url(cls, participant_id):
        return TEST_DEFAULT_DCP
        # return "https://{}".format(
        #     cls.fetch_dcp_hostname(participant_id)
        # )
