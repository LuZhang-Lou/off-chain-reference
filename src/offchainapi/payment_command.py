# Copyright (c) The Libra Core Contributors
# SPDX-License-Identifier: Apache-2.0

from .protocol_command import ProtocolCommand
from .payment import PaymentObject
from .utils import JSONSerializable
from .command_processor import CommandValidationError
from .errors import OffChainErrorCode
from .status_logic import State


# Functions to check incoming diffs
class PaymentLogicError(CommandValidationError):
    """ Indicates a payment processing error. """
    pass


# Note: ProtocolCommand is JSONSerializable, so no need to extend again.
@JSONSerializable.register
class PaymentCommand(ProtocolCommand):
    ''' Creates a new ``PaymentCommand`` based on a given payment.

        The command creates the object version of the payment given
        and depends on any previous versions of the given payment.

        Args:
            payment (PaymentObject): The payment from which to build the command.
    '''

    def __init__(self, payment_object):
        ProtocolCommand.__init__(self)
        self.payment_dict = payment_object.get_full_diff_record()

    def __eq__(self, other):
        return ProtocolCommand.__eq__(self, other) \
            and self.payment_dict == other.payment_dict

    def get_payment(self):
        # TODO more simplification for get_full_diff_record & create_from_record
        payment = PaymentObject.create_from_record(self.payment_dict)
        return payment

    def get_json_data_dict(self, flag):
        ''' Get a data dictionary compatible with JSON serilization
            (json.dumps).

            Args:
                flag (utils.JSONFlag): whether the JSON is intended
                    for network transmission (NET) to another party or local
                    storage (STORE).

            Returns:
                dict: A data dictionary compatible with JSON serilization.
        '''
        data_dict = ProtocolCommand.get_json_data_dict(self, flag)
        data_dict['payment'] = self.payment_dict
        return data_dict

    @classmethod
    def from_json_data_dict(cls, data, flag):
        """ Construct the object from a serlialized JSON
            data dictionary (from json.loads).

        Args:
            data (dict): A JSON data dictionary.
            flag (utils.JSONFlag): whether the JSON is intended
                    for network transmission (NET) to another party or local
                    storage (STORE).

        Raises:
            PaymentLogicError: If there is an error while creating the payment.

        Returns:
            PaymentCommand: A PaymentCommand from the input data.
        """
        self = super().from_json_data_dict(data, flag)
        # Thus super() is magic, but do not worry we get the right type:
        assert isinstance(self, PaymentCommand)
        self.payment_dict = data['payment']

        return self
