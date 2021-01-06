# Copyright (c) The Libra Core Contributors
# SPDX-License-Identifier: Apache-2.0

from ..business import BusinessContext, BusinessValidationFailure
from ..payment import KYCData
from ..status_logic import Status, KYCResult


class TestBusinessContext(BusinessContext):
    __test__ = False

    def __init__(self, my_addr, reliable=True):
        self.my_addr = my_addr

        # Option to make the contect unreliable to
        # help test error handling.
        self.reliable = reliable
        self.reliable_count = 0

    def get_my_address(self):
        return self.my_addr.as_str()

    def cause_error(self):
        self.reliable_count += 1
        fail = (self.reliable_count % 5 == 0)
        if fail:
            e = BusinessValidationFailure(
                'Artifical error caused for '
                'testing error handling')
            raise e

    async def evaluate_kyc(self, payment, ctx=None):
        return KYCResult.PASS

    def open_channel_to(self, other_vasp_info):
        return True

    async def payment_pre_processing(self, other_address, seq, command, payment):
        return {'settle': False}

    # ----- Actors -----

    def is_sender(self, payment, ctx=None):
        myself = self.my_addr.as_str()
        return myself == payment.sender.get_onchain_address_encoded_str()

    def is_recipient(self, payment, ctx=None):
        return not self.is_sender(payment)

    async def check_account_existence(self, payment, ctx=None):
        return True

# ----- VASP Signature -----

    def validate_recipient_signature(self, payment, ctx=None):
        assert 'recipient_signature' in payment
        recepient = payment.receiver.get_onchain_address_encoded_str()
        ref_id = payment.reference_id
        expected_signature = f'{recepient}.{ref_id}.SIGNED'

        if not self.reliable:
            self.cause_error()

        return payment.recipient_signature == expected_signature

    async def get_recipient_signature(self, payment, ctx=None):
        myself = self.my_addr.as_str()
        ref_id = payment.reference_id
        return f'{myself}.{ref_id}.SIGNED'

# ----- KYC/Compliance checks -----

    async def get_extended_kyc(self, payment, ctx=None):
        ''' Returns the extended KYC information for this payment.
        '''
        return KYCData({
                    "payload_type": "KYC_DATA",
                    "payload_version": 1,
                    "type": "individual",
                })

    async def get_additional_kyc(self, payment, ctx=None):
        ''' Returns the extended KYC information for this payment.
        '''
        return KYCData({
                    "payload_type": "KYC_DATA",
                    "payload_version": 1,
                    "type": "individual",
                    "given_name": "John",
                    "surname": "Smith",
                    "dob": "1973-07-08"
                })

    # # ----- Settlement -----

    # async def ready_for_settlement(self, payment, ctx=None):
    #     if not self.reliable:
    #         self.cause_error()

    #     return ctx['settle']
