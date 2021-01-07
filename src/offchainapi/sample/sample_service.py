# Copyright (c) The Libra Core Contributors
# SPDX-License-Identifier: Apache-2.0

from ..business import BusinessContext, BusinessForceAbort, \
    BusinessValidationFailure, VASPInfo
from ..protocol import OffChainVASP
from ..libra_address import LibraAddress
from ..protocol_messages import CommandRequestObject, OffChainProtocolError, \
    OffChainException
from ..payment_logic import PaymentCommand, PaymentProcessor
from ..status_logic import Status, KYCResult
from ..storage import StorableFactory
from ..crypto import ComplianceKey
from ..errors import OffChainErrorCode
from .sample_db import SampleDB
from ..payment import KYCData
import json

business_config = """[
    {
        "account": "xxxxxxxx",
        "balance": 10.0,
        "entity": false,
        "kyc_data" : "{ 'name' : 'Alice' }",
        "pending_transactions" : {}
    },
    {
        "account": "bbbbbbbb",
        "balance": 10.0,
        "entity": false,
        "kyc_data" : "{ 'name' : 'Alice' }",
        "pending_transactions" : {}
    },
    {
        "account": "2",
        "balance": 100.0,
        "entity": true,
        "kyc_data" : "{ 'name' : 'Bob' }",
        "pending_transactions" : {}
    }
]"""


class sample_vasp_info(VASPInfo):
    def __init__(self):
        peerA_addr = LibraAddress.from_bytes("lbr", b'A'*16).as_str()
        each_peer_base_url = {
            peerA_addr: 'https://peerA.com',
        }
        self.each_peer_base_url = each_peer_base_url
        self.my_key = ComplianceKey.generate()
        self.other_key = ComplianceKey.from_str(self.my_key.export_pub())

    def get_peer_base_url(self, other_addr):
        assert other_addr.as_str() in self.each_peer_base_url
        return self.each_peer_base_url[other_addr.as_str()]

    def get_peer_compliance_verification_key(self, other_addr):
        assert not self.other_key._key.has_private
        return self.other_key

    def get_my_compliance_signature_key(self, my_addr):
        return self.my_key


class sample_business(BusinessContext):
    def __init__(self, my_addr):
        self.my_addr = my_addr
        self.accounts_db = json.loads(business_config)

    # Helper functions for the business

    def get_my_address(self):
        return self.my_addr.as_str()

    def get_account(self, subaddress):
        for acc in self.accounts_db:
            if acc['account'] == subaddress:
                return acc
        raise BusinessValidationFailure(f'Account {subaddress} does not exist')

    async def sender_ready_to_settle(self, payment, ctx):
        if "recipient_signature" not in payment.data:
            return (False, "recipient signature is not present")
        return (True, "")

    def assert_payment_for_vasp(self, payment):
        sender = payment.sender
        receiver = payment.receiver

        if sender.get_onchain_address_encoded_str() == self.get_my_address() or \
            receiver.get_onchain_address_encoded_str() == self.get_my_address():
            return
        raise BusinessValidationFailure()

    def has_sig(self, payment):
            # Checks if the payment has the signature necessary
            return 'recipient_signature' in payment.data

    # Implement the business logic interface

    def open_channel_to(self, other_vasp_info):
        return

    def close_channel_to(self, other_vasp_info):
        return

    async def check_account_existence(self, payment, ctx=None):
        self.assert_payment_for_vasp(payment)
        accounts = {acc['account'] for acc in self.accounts_db}

        if self.is_sender(payment):
            sub = LibraAddress.from_encoded_str(payment.sender.address).subaddress_bytes.decode('ascii')
            if sub in accounts:
                return
        else:
            sub = LibraAddress.from_encoded_str(payment.receiver.address).subaddress_bytes.decode('ascii')
            if sub in accounts:
                return
        raise BusinessForceAbort(OffChainErrorCode.payment_invalid_libra_subaddress, 'Subaccount does not exist.')

    def is_sender(self, payment, ctx=None):
        self.assert_payment_for_vasp(payment)
        return payment.sender.get_onchain_address_encoded_str() == self.get_my_address()


    def validate_recipient_signature(self, payment, ctx=None):
        if 'recipient_signature' in payment.data:
            if payment.recipient_signature == 'VALID':
                return
            sig = payment.data.get('recipient_signature', 'Not present')
            raise BusinessValidationFailure(f'Invalid signature: {sig}')

    async def get_recipient_signature(self, payment, ctx=None):
        return 'VALID'

    def get_my_role(self, payment):
        my_role = ['receiver', 'sender'][self.is_sender(payment)]
        return my_role

    def get_other_role(self, payment):
        other_role = ['sender', 'receiver'][self.is_sender(payment)]
        return other_role

    async def evaluate_kyc(self, payment, ctx=None) -> KYCResult:
        if "kyc_data" in payment.sender.data and "given_name" in payment.sender.kyc_data.data:
            if payment.sender.kyc_data.given_name == "kyc_to_fail":
                return KYCResult.FAIL
            if payment.sender.kyc_data.given_name == "kyc_to_softmatch":
                return KYCResult.SOFT_MATCH
        return KYCResult.PASS


    async def get_extended_kyc(self, payment, ctx=None):
        ''' Gets the extended KYC information for this payment.

            Can raise:
                   BusinessNotAuthorized.
        '''
        return KYCData({
            "payload_type": "KYC_DATA",
            "payload_version": 1,
            "type": "individual",
        })


class sample_vasp:

    def __init__(self, my_addr):
        self.my_addr = my_addr
        self.bc = sample_business(self.my_addr)
        self.store        = StorableFactory(SampleDB())
        self.info_context = sample_vasp_info()

        self.pp = PaymentProcessor(self.bc, self.store)
        self.vasp = OffChainVASP(
            self.my_addr, self.pp, self.store, self.info_context
        )

    def get_channel(self, other_vasp):
        channel = self.vasp.get_channel(other_vasp)
        return channel

    async def process_request(self, other_vasp, request_json):
        # Get the channel
        channel = self.get_channel(other_vasp)
        resp = await channel.parse_handle_request(request_json)
        return resp

    def insert_local_command(self, other_vasp, command):
        channel = self.get_channel(other_vasp)
        req = channel.sequence_command_local(command)
        return req

    async def process_response(self, other_vasp, response_json):
        channel = self.get_channel(other_vasp)
        try:
            await channel.parse_handle_response(response_json)
        except OffChainProtocolError:
            pass
        except OffChainException:
            pass
