# Copyright (c) The Libra Core Contributors
# SPDX-License-Identifier: Apache-2.0

from .business import BusinessForceAbort, BusinessValidationFailure
from .protocol_command import ProtocolCommand
from .errors import OffChainErrorCode
from .command_processor import CommandProcessor
from .payment import Status, PaymentObject, StatusObject
from .payment_command import PaymentCommand, PaymentLogicError
from .status_logic import State, KYCResult, InvalidStateException
from .asyncnet import NetworkException
from .shared_object import SharedObject
from .libra_address import LibraAddress, LibraAddressError
from .utils import get_unique_string

import asyncio
import logging
import json




class PaymentProcessorNoProgress(Exception):
    pass


class PaymentProcessorRemoteError(Exception):
    pass


class PaymentStateMachine:

    TERMINAL_STATES = {State.RABORT, State.SABORT, State.READY}

    STATE_MACHINE = {
        State.SINIT: {State.RSEND, State.RSOFT, State.RABORT},
        State.RSEND: {State.READY, State.SABORT, State.SSOFT},
        State.RSOFT: {State.SSOFTSEND},
        State.SSOFT: {State.RSOFTSEND},
        State.SSOFTSEND: {State.RABORT, State.RSEND},
        State.RSOFTSEND: {State.SABORT, State.READY},
    }

    @staticmethod
    def is_terminal_state(state: State) -> bool:
        return state in PaymentStateMachine.TERMINAL_STATES

    @staticmethod
    def can_transition(old_state: State, new_state: State) -> bool:
        if PaymentStateMachine.is_terminal_state(old_state):
          return False  # terminal states can't change
        if old_state not in PaymentStateMachine.STATE_MACHINE:
          return False  # invalid state
        if new_state not in PaymentStateMachine.STATE_MACHINE[old_state]:
          return False  # invalid new state
        return True

logger = logging.getLogger(name='libra_off_chain_api.payment_logic')


class PaymentProcessor(CommandProcessor):
    ''' The logic to process a payment from either side.

    The processor checks commands as they are received from the other
    VASP. When a command from the other VASP is successful it is
    passed on to potentially lead to a further command. It is also
    notified of sequenced commands that failed, and the error that
    lead to that failure.

    Crash-recovery strategy: The processor must only process each
    command once. For this purpose the Executor passes commands
    in the order they have been sequenced by the lower-level
    protocol on each channel, and does so only once for each command
    in the sequence for each channel.

    The Processor must store those commands, and ensure they have
    all been suitably processed upon a potential crash and recovery.
    '''

    def __init__(self, business, storage_factory, loop=None):
        self.business = business

        # Asyncio support
        self.loop = loop
        self.net = None

        # The processor state -- only access through event loop to prevent
        # mutlithreading bugs.
        self.storage_factory = storage_factory

        root = storage_factory.make_dir(self.business.get_my_address())
        processor_dir = storage_factory.make_dir('processor', root=root)

        # This is the primary store of shared objects.
        # It maps reference id -> objects.
        self.object_store = storage_factory.make_dict(
            'object_store', PaymentObject, root=processor_dir)

        # Storage for debug futures list
        self.futs = []

    def set_network(self, net):
        ''' Assigns a concrete network for this command processor to use. '''
        assert self.net is None
        self.net = net

    # ------ Machinery for supporting async Business context ------

    async def process_command_failure_async(
            self, other_address, command, cid, error):
        ''' Process any command failures from either ends of a channel.'''
        logger.error(
            f'(other:{other_address.as_str()}) Command #{cid} Failure: {error} ({error.message})'
        )

        # If this is our own command, that just failed, we should update
        # the outcome:
        try:
            if command.origin != other_address:
                logger.error(
                    f'Command with {other_address.as_str()}.#{cid}'
                    f' Trigger outcome.')

                # try to construct a payment.
                payment = command.get_payment()
            else:
                logger.error(
                    f'Command with {other_address.as_str()}.#{cid}'
                    f' Error on other VASPs command.')
        except Exception:
            logger.error(
                f'Command with {other_address.as_str()}.#{cid}'
                f' Cannot recover payment or reference_id'
            )

        return

    async def process_command_success_async(self, other_address, command, cid):
        """ The asyncronous command processing logic.

        Checks all incomming commands from the other VASP, and determines if
        any new commands need to be issued from this VASP in response.

        Args:
            other_address (LibraAddress):  The other VASP address in the
                channel that received this command.
            command (PaymentCommand): The current payment command.
            cid (str): cid of the related request.
        """
        # To process commands we should have set a network
        if self.net is None:
            raise RuntimeError(
                'Setup a processor network to process commands.'
            )

        payment = command.get_payment()

        other_address_str = other_address.as_str()

        logger.info(f'(other:{other_address_str}) Process Command #{cid}')

        try:
            # Only respond to commands by other side.
            if command.origin == other_address:

                # Determine if we should inject a new command.
                new_payment = await self.payment_process_async(payment)

                if new_payment.has_changed():
                    new_cmd = PaymentCommand(new_payment)

                    request = await self.net.sequence_command(
                        other_address, new_cmd
                    )

                    # Attempt to send it to the other VASP.
                    await self.net.send_request(other_address, request)
                else:
                    is_receiver = self.business.is_recipient(new_payment)
                    role = ['sender', 'receiver'][is_receiver]

                    logger.debug(
                        f'(me: {role} other:{other_address_str}) No more commands '
                        f'created for Payment lastly with cid #{cid}'
                        f' {new_payment}'
                    )

        except NetworkException as e:
            logger.warning(
                f'(other:{other_address_str}) Network error: cid #{cid}: {e}'
            )
        except Exception as e:
            logger.error(
                f'(other:{other_address_str}) '
                f'Payment processing error: cid #{cid}: {e}',
                exc_info=True,
            )

    # -------- Implements CommandProcessor interface ---------

    def business_context(self):
        ''' Overrides CommandProcessor. '''
        return self.business

    def check_command(self, my_address, other_address, command):
        ''' Overrides CommandProcessor. '''

        new_payment = command.get_payment()

        # Ensure that the two parties involved are in the VASP channel
        parties = {
            new_payment.sender.get_onchain_address_encoded_str(),
            new_payment.receiver.get_onchain_address_encoded_str()
        }

        other_addr_str = other_address.as_str()

        needed_parties = {
            my_address.as_str(),
            other_addr_str
        }

        if parties != needed_parties:
            raise PaymentLogicError(
                OffChainErrorCode.payment_wrong_actor,
                f'Wrong Parties: expected {needed_parties} '
                f'but got {str(parties)}'
            )


        # Ensure the originator is one of the VASPs in the channel.
        origin_str = command.get_origin().as_str()
        if origin_str not in parties:
            raise PaymentLogicError(
                OffChainErrorCode.payment_wrong_actor,
                f'Command originates from {origin_str} wrong party')

        # Only check the commands we get from others.
        if origin_str == other_addr_str:
            state = State.from_payment_object(new_payment)
            if state == State.SINIT:

                # Check that the reference_id is correct
                # Only do this for the definition of new payments, after that
                # the ref id stays the same.

                ref_id_structure = new_payment.reference_id.split('_')
                if not (len(ref_id_structure) > 1 and ref_id_structure[0] == origin_str):
                    raise PaymentLogicError(
                        OffChainErrorCode.payment_wrong_structure,
                        f'Expected reference_id of the form {origin_str}_XYZ, got: '
                        f'{new_payment.reference_id}'
                    )

                self.check_initial_payment(new_payment)
            else:
                old_payment = self.object_store[new_payment.reference_id]
                self.check_new_update(old_payment, new_payment)

    def process_command(self, other_addr, command,
                        cid, status_success, error=None):
        ''' Overrides CommandProcessor. '''

        other_str = other_addr.as_str()

        # If failue, call the failure handler and exit.
        if not status_success:
            fut = self.loop.create_task(self.process_command_failure_async(
                other_addr, command, cid, error)
            )
            if __debug__:
                self.futs += [fut]
            return fut

        # If success, create and record new objects
        payment = command.get_payment()
        self.object_store[payment.reference_id] = payment

        # Update the Index of Reference ID -> Payment.

        # Spin further command processing in its own task.
        logger.debug(f'(other:{other_str}) Schedule cmd {cid}')
        fut = self.loop.create_task(self.process_command_success_async(
            other_addr, command, cid))

        # Log the futures here to execute them inidividually
        # when testing.
        if __debug__:
            self.futs += [fut]

        return fut

    # ----------- END of CommandProcessor interface ---------

    def check_signatures(self, payment):
        ''' Utility function that checks all signatures present for validity.

        Throws a BusinessValidationFailure exception if the recipient signature is present but incorrect.
        '''
        self.business.validate_recipient_signature(payment)

    def check_initial_payment(self, payment: PaymentObject):
        ''' Checks the initial PaymentObject for a payment.
            Raises PaymentLogicError when check fials

            NOTE: this function assumes that the VASP is the RECEIVER of the
            new payment, for example for person to person payment initiated
            by the sender.

            The only real check is that that status for the VASP that has
            not created the payment must be none, to allow for checks and
            potential aborts. However, KYC information on both sides may
            be included by the other party, and should be checked.
        '''
        business = self.business
        is_recipient = business.is_recipient(payment)
        assert is_recipient, "Actor must be recipient of this payment"

        try:
            state = State.from_payment_object(payment)
            if state != State.SINIT:
                raise PaymentLogicError(
                    OffChainErrorCode.payment_wrong_status,
                    f'Initial payment object is not in SINIT state, but {state}'
                )

        except InvalidStateException as e:
            raise PaymentLogicError(
                OffChainErrorCode.payment_wrong_status,
                f'Invalid state in payment: {e}')

        # Check that the subaddresses are present
        # TODO: catch exceptions into Payment errors

        try:
            send_addr = LibraAddress.from_encoded_str(payment.sender.address)
            receiver_addr = LibraAddress.from_encoded_str(payment.receiver.address)
        except LibraAddressError as e:
            raise PaymentLogicError(
                OffChainErrorCode.payment_invalid_libra_address,
                str(e)
            )


    def check_new_update(self, payment, new_payment) -> None:
        ''' check the updates to a payment are valid. Three things to check:
            1. the other side did not touch myself's PaymentActor object
            2. state machine transition is valid
            3. when recipient_signature is populated, sender validates the signature
            Raises PaymentLogicError upon errors
        '''
        business = self.business
        is_receiver = business.is_recipient(new_payment)

        role = ['sender', 'receiver'][is_receiver]
        myself_actor = payment.data[role]
        myself_actor_new = new_payment.data[role]

        # Ensure nothing on our side was changed by this update.
        if myself_actor != myself_actor_new:
            raise PaymentLogicError(
                OffChainErrorCode.payment_changed_other_actor,
                f'Cannot change {role} information.')

        # Check the status transition is valid.
        try:
            new_state = State.from_payment_object(new_payment)
            if not self.can_change_status(payment, new_payment):
                old_state = State.from_payment_object(payment)
                raise PaymentLogicError(
                    OffChainErrorCode.payment_wrong_status,
                    f'Invalid state transition: {old_state} -> {new_state}')
        except InvalidStateException as e:
            raise PaymentLogicError(
                OffChainErrorCode.payment_wrong_status,
                f'Invalid state in payment: {e}')

        if new_state == State.RSEND:
            if not 'recipient_signature' in new_payment:
                raise PaymentLogicError(
                    OffChainErrorCode.payment_wrong_recipient_signature,
                    'Recipient signature is not included in the payment.'
                )
            try:
                self.check_signatures(new_payment)
            except BusinessValidationFailure:
                raise PaymentLogicError(
                    OffChainErrorCode.payment_wrong_recipient_signature,
                    'Recipient signature check failed.'
                )

    def payment_process(self, payment):
        ''' A syncronous version of payment processing -- largely
            used for pytests '''
        loop = self.loop
        if self.loop is None:
            loop = asyncio.new_event_loop()
        return loop.run_until_complete(self.payment_process_async(payment))

    def can_change_status(self, old_payment: PaymentObject, new_payment: PaymentObject) -> bool:
        """ Checks whether an actor can change the status in its PaymentActor
            to a new status accoding to our logic for valid state
            transitions.

        Parameters:
            * old_payment (PaymentObject): the old payment object.
            * new_payment (PaymentObject): the new payment object.

        Returns:
            * bool: True for valid transition and False otherwise.
        """
        old_sender_status = old_payment.sender.status.as_status()
        old_sender_additional_kyc = old_payment.sender.get_additional_kyc_data()
        old_receiver_status = old_payment.receiver.status.as_status()
        old_receiver_additional_kyc = old_payment.receiver.get_additional_kyc_data()

        new_sender_status = new_payment.sender.status.as_status()
        new_sender_additional_kyc = new_payment.sender.get_additional_kyc_data()
        new_receiver_status = new_payment.receiver.status.as_status()
        new_receiver_additional_kyc = new_payment.receiver.get_additional_kyc_data()

        old_state = State.from_status(
            old_sender_status,
            old_receiver_status,
            old_sender_additional_kyc,
            old_receiver_additional_kyc,
        )

        new_state = State.from_status(
            new_sender_status,
            new_receiver_status,
            new_sender_additional_kyc,
            new_receiver_additional_kyc,
        )
        return PaymentStateMachine.can_transition(old_state, new_state)

    def good_initial_status(self, payment, actor_is_sender):
        """ Checks whether a payment has a valid initial status, given
            the role of the actor that created it. Returns a bool set
            to true if it is valid."""

        if actor_is_sender:
            return payment.receiver.status.as_status() == Status.none
        return payment.sender.status.as_status() == Status.none

    async def payment_process_async(self, payment):
        ''' Processes a payment that was just updated, and returns a
            new payment with potential updates. This function may be
            called multiple times for the same payment to support
            async business operations and recovery.

            Must always return a new payment but,
            if there is no update to the new payment
            no new command will be emiited.
        '''
        business = self.business
        # payment is checked already, normally we don't need to worry about
        # InvalidStateException here
        current_state = State.from_payment_object(payment)

        is_receiver = business.is_recipient(payment)
        is_sender = not is_receiver
        role = ['sender', 'receiver'][is_receiver]

        new_payment = payment.new_version()

        ctx = None

        try:
            ctx = await business.generate_payment_context(payment)
            await business.check_travel_rule_requirement(payment, ctx)

            if PaymentStateMachine.is_terminal_state(current_state):
                # Nothing more to be done with this payment
                # Return a new payment version with no modification
                # To singnal no changes, and therefore no new command.
                return new_payment

            if current_state == State.SINIT:
                await business.check_account_existence(new_payment, ctx)

            # if SINIT or SSOFTSEND, receiver should provide kyc/signature
            if current_state == State.SINIT or current_state == State.SSOFTSEND:
                assert is_receiver, "Actor must be receiver to act on SINIT or SSOFTSEND"
                kyc_result = await business.evaluate_kyc(new_payment, ctx)

                if kyc_result == KYCResult.PASS:
                    # if pass, provide kyc and signature
                    extended_kyc = await business.get_extended_kyc(new_payment, ctx)
                    new_payment.data[role].add_kyc_data(extended_kyc)
                    signature = await business.get_recipient_signature(
                        new_payment, ctx)
                    new_payment.add_recipient_signature(signature)
                    new_payment.data[role].change_status(StatusObject(Status.ready_for_settlement))

                elif kyc_result == KYCResult.SOFT_MATCH and current_state == State.SINIT:
                    new_payment.data[role].change_status(StatusObject(Status.soft_match))

                # If fail or second time soft-match
                elif kyc_result == KYCResult.FAIL or kyc_result == KYCResult.SOFT_MATCH:
                    new_payment.data[role].change_status(
                        StatusObject(Status.abort, "rejected", "KYC fails")
                    )

            if current_state == State.SSOFT or current_state == State.RSOFT:
                if current_state == State.SSOFT:
                    assert is_receiver, "Actor must be receiver to act on SSOFT"
                else:
                    assert is_sender, "Actor must be sender to act on RSOFT"
                # TODO: first examine whether we've already provided additional kyc data
                # this is some protection logic that is not specified in DIP-1
                additional_kyc = await business.get_additional_kyc(new_payment, ctx)
                new_payment.data[role].add_additional_kyc_data(additional_kyc)

            if current_state == State.RSOFTSEND or current_state == State.RSEND:
                assert is_sender, "Actor must be sender to act on RSOFTSEND or RSEND"
                kyc_result = await business.evaluate_kyc(new_payment, ctx)
                if kyc_result == KYCResult.PASS:
                    # if pass, move to ready
                    sender_ready_to_settle, abort_reason = await business.sender_ready_to_settle(new_payment, ctx)
                    if not sender_ready_to_settle:
                        new_payment.data[role].change_status(
                            StatusObject(Status.abort, "rejected", abort_reason)
                        )
                    else:
                        new_payment.data[role].change_status(StatusObject(Status.ready_for_settlement))

                if kyc_result == KYCResult.SOFT_MATCH and current_state == State.RSEND:
                    new_payment.data[role].change_status(StatusObject(Status.soft_match))

                # If fail or second time soft-match
                if kyc_result == KYCResult.FAIL or kyc_result == KYCResult.SOFT_MATCH:
                    new_payment.data[role].change_status(
                        StatusObject(Status.abort, "rejected", "KYC fails")
                    )

        except BusinessForceAbort as e:
            new_payment.data[role].change_status(
                StatusObject(Status.abort, "rejected", str(e))
            )
        # if unseen exception happens, log it and scream
        except Exception as e:
            # update status to abort so that we can post process in the finally block
            # No new payment sent to the other side
            new_payment.data[role].change_status(
                # no need to hide internal error as this is not sent to the other side
                StatusObject(Status.abort, "rejected", str(e))
            )
            logger.error(
                f'Unexpected error while processing payment {payment.reference_id}'
                ' return error and abort, no message sent to the other: {e}')
            logger.exception(e)
            raise e
        finally:
            await business.payment_post_processing(new_payment, ctx)

        # Do an internal consistency check:
        try:
            if not self.can_change_status(payment, new_payment):
                new_state = State.from_payment_object(new_payment)
                raise RuntimeError(
                    f'Invalid status transition while processing '
                    f'payment {payment.get_version()}: '
                    f'{current_state} -> {new_state} SENDER={is_sender}'
                )
        except InvalidStateException as e:
            raise PaymentLogicError(
                OffChainErrorCode.payment_wrong_status,
                f'Invalid state in payment: {e}')


        return new_payment
