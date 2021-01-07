# Copyright (c) The Libra Core Contributors
# SPDX-License-Identifier: Apache-2.0

""" Define the 'business logic' for the Off-chain protocols """

# ---------------------------------------------------------------------------

from .errors import OffChainErrorCode
from .status_logic import KYCResult

# A model for VASP business environment

class BusinessNotAuthorized(Exception):
    ''' Indicates that the VASP requesting some information is
        not authorized to receive it. '''
    pass


class BusinessValidationFailure(Exception):
    ''' Indicates a business check that has failed. '''
    pass


class BusinessForceAbort(Exception):
    ''' Request an abort with given code and message.

    Params:
        * code (str): an error code on abort.
        * message (str): a message explaining the reason for abort.
    '''

    def __init__(self, code, message):
        assert isinstance(code, OffChainErrorCode)
        self.code = code.value
        self.message = message


class BusinessContext:
    """ The interface a VASP should define to drive the Off-chain protocol. """

    def get_my_address(self):
        """Returns this VASP's str Libra address encoded in bech32"""
        raise NotImplementedError()  # pragma: no cover

    def open_channel_to(self, other_vasp_addr):
        """Requests authorization to open a channel to another VASP.
        If it is authorized nothing is returned. If not an exception is
        raised.

        Args:
            other_vasp_info (LibraAddress): The Libra Blockchain address of the other VASP.

        Raises:
            BusinessNotAuthorized: If the current VASP is not authorised
                    to connect with the other VASP.
        """
        raise NotImplementedError()  # pragma: no cover

    # ----- Actors -----

    def is_sender(self, payment, ctx=None):
        """Returns true if the VASP is the sender of a payment.

        Args:
            payment (PaymentCommand): The concerned payment.
            ctx (Any): Optional context object that business can store custom data

        Returns:
            bool: Whether the VASP is the sender of the payment.
        """
        raise NotImplementedError()  # pragma: no cover

    def is_recipient(self, payment):
        """ Returns true if the VASP is the recipient of a payment.

        Args:
            payment (PaymentCommand): The concerned payment.

        Returns:
            bool: Whether the VASP is the recipient of the payment.
        """
        return not self.is_sender(payment)

    async def check_account_existence(self, payment, ctx=None):
        """ Checks that the actor (sub-account / sub-address) on this VASP
            exists. This may be either the recipient or the sender, since VASPs
            can initiate payments in both directions. If not throw an exception.

        Args:
            payment (PaymentCommand): The payment command containing the actors
                to check.
            ctx (Any): Optional context object that business can store custom data

        Raises:
            BusinessValidationFailure: If the account does not exist.
        """
        raise NotImplementedError()  # pragma: no cover

# ----- VASP Signature -----

    def validate_recipient_signature(self, payment, ctx=None):
        """ Validates the recipient signature is correct. Raise an
            exception if the signature is invalid or not present.
            If the signature is valid do nothing.

        Args:
            payment (PaymentCommand): The payment command containing the
                signature to check.
            ctx (Any): Optional context object that business can store custom data

        Raises:
            BusinessValidationFailure: If the signature is invalid
                    or not present.
        """
        raise NotImplementedError()  # pragma: no cover

    async def get_recipient_signature(self, payment, ctx=None):
        """ Gets a recipient signature on the payment ID.

        Args:
            payment (PaymentCommand): The payment to sign.
            ctx (Any): Optional context object that business can store custom data
        """
        raise NotImplementedError()  # pragma: no cover

# ----- KYC/Compliance checks -----


    async def evaluate_kyc(self, payment, ctx=None) -> KYCResult:
        raise NotImplementedError()  # pragma: no cover


    async def get_extended_kyc(self, payment, ctx=None):
        ''' Provides the extended KYC information for this payment.

            Args:
                payment (PaymentCommand): The concerned payment.
                ctx (Any): Optional context object that business can store custom data

            Raises:
                   BusinessNotAuthorized: If the other VASP is not authorized to
                    receive extended KYC data for this payment.

            Returns:
                KYCData: Returns the extended KYC information for
                this payment.
        '''
        raise NotImplementedError()  # pragma: no cover


    async def get_additional_kyc(self, payment, ctx=None):
        ''' Provides the additional KYC information for this payment.

            The additional information is requested or may be provided in case
            of a `soft_match` state from the other VASP indicating more
            information is required to disambiguate an individual.

            Args:
                payment (PaymentCommand): The concerned payment.

            Raises:
                   BusinessNotAuthorized: If the other VASP is not authorized to
                    receive extended KYC data for this payment.

            Returns:
                KYCData: Returns the extended KYC information for
                this payment.
        '''
        raise NotImplementedError()  # pragma: no cover

# ----- Payment Processing -----

    async def payment_pre_processing(self, other_address, seq, command, payment):
        ''' An async method to let VASP perform custom business logic to a
        successsful (sequenced & ACKed) command prior to normal processing.
        For example it can be used to check whether the payment is in terminal
        status. The command could have originated either from the other VASP
        or this VASP (see `command.origin` to determine this).

        Args:
            other_address (str): the encoded Libra Blockchain address of the other VASP.
            seq (int): the sequence number into the shared command sequence.
            command (ProtocolCommand): the command that lead to the new or
                updated payment.
            payment (PaymentObject): the payment resulting from this command.

        Returns None or a context objext that will be passed on the
        other business context functions.
        '''
        pass

    async def generate_payment_context(self, payment):
        """ Generate and return related payment context """
        pass


    async def check_travel_rule_requirement(self, payment, ctx) -> None:
        """
        Check if Travel Rule is required for this payment
        Raise BusinessForceAbort if not, and the payment will be aborted
        """
        pass

    async def sender_ready_to_settle(self, payment, ctx=None):
        """
        called on RSEND or RSOFTSEND by sender.
        Return Tuple[bool, str], a tuple of whether to settle and reason to abort
        (only when the first element is False). When the first element
        is True, we settle the payment, False to abort it and populate
        the abort reason
        """
        pass

    async def payment_post_processing(self, payment, ctx=None):
        """
        called at the end of command processing. note that at this point
        the command is not fully committed yet (by the other side)
        """
        pass


class VASPInfo:
    """Contains information about VASPs"""

    def get_base_url(self):
        """ Get the base URL that manages off-chain communications.

            Returns:
                str: The base url of the VASP.

        """
        raise NotImplementedError()  # pragma: no cover

    def get_peer_base_url(self, other_addr):
        """ Get the base URL that manages off-chain communications of the other
            VASP.

            Args:
                other_addr (LibraAddress): The Libra Blockchain address of the other VASP.

            Returns:
                str: The base url of the other VASP.
        """
        raise NotImplementedError()  # pragma: no cover

    # --- The functions below are currently unused ---

    def get_libra_address(self):
        """ The settlement Libra Blockchain address for this channel.

            Returns:
                LibraAddress: The Libra Blockchain address.

        """
        raise NotImplementedError()  # pragma: no cover

    def get_parent_address(self):
        """ The VASP Parent address for this channel. High level logic is common
        to all Libra Blockchain addresses under a parent to ensure consistency and
        compliance.

        Returns:
            LibraAddress: The Libra Blockchain address of the parent VASP.

        """
        raise NotImplementedError()  # pragma: no cover

    def is_unhosted(self, other_addr):
        """ Returns True if the other party is an unhosted wallet.

            Args:
                other_addr (LibraAddress): The Libra Blockchain address of the other VASP.

            Returns:
                bool: Whether the other VASP is an unhosted wallet.

        """
        raise NotImplementedError()  # pragma: no cover

    def get_peer_compliance_verification_key(self, other_addr):
        """ Returns the compliance verfication key of the other VASP.

        Args:
            other_addr (LibraAddress): The Libra Blockchain address of the other VASP.

        Returns:
            ComplianceKey: The compliance verification key of the other VASP.
        """
        raise NotImplementedError()  # pragma: no cover

    def get_my_compliance_signature_key(self, my_addr):
        """ Returns the compliance signature (secret) key of the VASP.

        Args:
            my_addr (LibraAddress): The Libra Blockchain address of the VASP.

        Returns:
            ComplianceKey: The compliance key of the VASP.
        """
        raise NotImplementedError()  # pragma: no cover
