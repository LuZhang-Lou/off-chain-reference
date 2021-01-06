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
        # map from reference_id to latest version id
        self.reference_id_index = storage_factory.make_dict(
            'reference_id_index', str, processor_dir)

        # This is the primary store of shared objects.
        # It maps version numbers -> objects.
        self.object_store = storage_factory.make_dict(
            'object_store', PaymentObject, root=processor_dir)

        # Allow mapping a set of future to payment reference_id outcomes
        # Once a payment has an outcome (ready_for_settlement, abort, or command exception)
        # notify the appropriate futures of the result. These do not persist
        # crashes since they are run-time objects.

        # Mapping: payment reference_id -> List of futures.
        self.outcome_futures = {}

        # Storage for debug futures list
        self.futs = []

    def set_network(self, net):
        ''' Assigns a concrete network for this command processor to use. '''
        assert self.net is None
        self.net = net

    # ------ Machinery for supporting async Business context ------

    async def process_command_failure_async(
            self, other_address, command, seq, error):
        ''' Process any command failures from either ends of a channel.'''
        logger.error(
            f'(other:{other_address.as_str()}) Command #{seq} Failure: {error} ({error.message})'
        )

        # If this is our own command, that just failed, we should update
        # the outcome:
        try:
            if command.origin != other_address:
                logger.error(
                    f'Command with {other_address.as_str()}.#{seq}'
                    f' Trigger outcome.')

                # try to construct a payment.
                payment = command.get_payment(self.object_store)
                self.set_payment_outcome_exception(
                                payment.reference_id,
                                PaymentProcessorRemoteError(error))
            else:
                logger.error(
                    f'Command with {other_address.as_str()}.#{seq}'
                    f' Error on other VASPs command.')
        except Exception:
            logger.error(
                f'Command with {other_address.as_str()}.#{seq}'
                f' Cannot recover payment or reference_id'
            )

        return

    async def process_command_success_async(self, other_address, command, seq):
        """ The asyncronous command processing logic.

        Checks all incomming commands from the other VASP, and determines if
        any new commands need to be issued from this VASP in response.

        Args:
            other_address (LibraAddress):  The other VASP address in the
                channel that received this command.
            command (PaymentCommand): The current payment command.
            seq (int): The sequence number of the payment command.
        """
        # To process commands we should have set a network
        if self.net is None:
            raise RuntimeError(
                'Setup a processor network to process commands.'
            )

        # Update the outcome of the payment
        payment = command.get_payment(self.object_store)
        self.set_payment_outcome(payment)

        # If there is no registered obligation to process there is no
        # need to process this command. We log here an error, which
        # might be due to a bug.
        other_address_str = other_address.as_str()

        logger.info(f'(other:{other_address_str}) Process Command #{seq}')

        try:
            command_ctx = await self.business.payment_pre_processing(
                other_address, seq, command, payment)

            # Only respond to commands by other side.
            if command.origin == other_address:

                # Determine if we should inject a new command.
                new_payment = await self.payment_process_async(
                    payment, ctx=command_ctx)

                if new_payment.has_changed():
                    new_cmd = PaymentCommand(new_payment)

                    request = await self.net.sequence_command(
                        other_address, new_cmd
                    )

                    # Attempt to send it to the other VASP.
                    await self.net.send_request(other_address, request)
                else:
                    # Signal to anyone waiting that progress was not made
                    # despite being our turn to make progress. As a result
                    # some extra processing should be done until progress
                    # can be made. Note that if the payment is already done
                    # (as in ready_for_settlement/abort) we have set an outcome
                    # for it, and this will be a no-op.
                    self.set_payment_outcome_exception(
                        payment.reference_id,
                        PaymentProcessorNoProgress())

                    is_receiver = self.business.is_recipient(new_payment)
                    role = ['sender', 'receiver'][is_receiver]

                    logger.debug(
                        f'(me: {role} other:{other_address_str}) No more commands '
                        f'created for Payment lastly with seq num #{seq}'
                        f' {new_payment}'
                    )

        except NetworkException as e:
            logger.warning(
                f'(other:{other_address_str}) Network error: seq #{seq}: {e}'
            )
        except Exception as e:
            logger.error(
                f'(other:{other_address_str}) '
                f'Payment processing error: seq #{seq}: {e}',
                exc_info=True,
            )

    # -------- Machinery for notification for outcomes -------

    async def wait_for_payment_outcome(self, reference_id):
        ''' Returns the payment object with the given a reference_id once the
        object has the sender and/or receiver status set to either
        'ready_for_settlement' or 'abort'.
        '''
        fut = self.loop.create_future()

        if reference_id not in self.outcome_futures:
            self.outcome_futures[reference_id] = []

        # Register this future to call later.
        self.outcome_futures[reference_id] += [fut]

        # Check to see if the payment is already resolved.
        if reference_id in self.reference_id_index:
            payment = self.get_latest_payment_by_ref_id(reference_id)
            self.set_payment_outcome(payment)

        return (await fut)

    def set_payment_outcome(self, payment):
        ''' Updates the list of futures waiting for payment outcomes
            based on the new payment object provided. If sender or receiver
            of the payment object are in settled or abort states, then
            the result is passed on to any waiting futures.
        '''

        # Check if payment is in a final state
        if not ((payment.sender.status.as_status() == Status.ready_for_settlement and \
                payment.receiver.status.as_status() == Status.ready_for_settlement) or \
                payment.sender.status.as_status() == Status.abort or \
                payment.receiver.status.as_status() == Status.abort):
            return

        # Check if anyone is waiting for this payment.
        if payment.reference_id not in self.outcome_futures:
            return

        # Get the futures waiting for an outcome, and delete them
        # from the list of pending futures.
        outcome_futures = self.outcome_futures[payment.reference_id]
        del self.outcome_futures[payment.reference_id]

        # Update the outcome for each of the futures.
        for fut in outcome_futures:
            fut.set_result(payment)

    def set_payment_outcome_exception(self, reference_id, payment_exception):
        # Check if anyone is waiting for this payment.
        if reference_id not in self.outcome_futures:
            return

        # Get the futures waiting for an outcome, and delete them
        # from the list of pending futures.
        outcome_futures = self.outcome_futures[reference_id]
        del self.outcome_futures[reference_id]

        # Update the outcome for each of the futures.
        for fut in outcome_futures:
            fut.set_exception(payment_exception)

    # -------- Implements CommandProcessor interface ---------

    def business_context(self):
        ''' Overrides CommandProcessor. '''
        return self.business

    def check_command(self, my_address, other_address, command):
        ''' Overrides CommandProcessor. '''

        new_payment = command.get_payment(self.object_store)

        # Ensure that the two parties involved are in the VASP channel
        parties = set([
            new_payment.sender.get_onchain_address_encoded_str(),
            new_payment.receiver.get_onchain_address_encoded_str()
        ])

        other_addr_str = other_address.as_str()

        needed_parties = set([
            my_address.as_str(),
            other_addr_str
        ])

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
            if command.reads_version_map == []:

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

                # Ensure the payment ref_id stays the same
                old_ref_id, _ = command.reads_version_map[0]
                new_ref_id, _ = command.writes_version_map[0]
                if old_ref_id != new_ref_id:
                    raise PaymentLogicError(
                        OffChainErrorCode.payment_wrong_structure,
                        f'Expected the reference id to not change,'
                        f' got: {old_ref_id} and {new_ref_id}'
                    )

                old_version = command.get_previous_version_number()
                old_payment = self.object_store[old_version]
                self.check_new_update(old_payment, new_payment)

    def process_command(self, other_addr, command,
                        cid, status_success, error=None):
        ''' Overrides CommandProcessor. '''

        other_str = other_addr.as_str()

        # Call the failure handler and exit.
        if not status_success:
            fut = self.loop.create_task(self.process_command_failure_async(
                other_addr, command, cid, error)
            )
            if __debug__:
                self.futs += [fut]
            return fut

        # Creates new objects.
        new_versions = command.get_new_object_versions()
        for version in new_versions:
            obj = command.get_object(version, self.object_store)
            self.object_store[version] = obj

        # Update the Index of Reference ID -> Payment.
        self.store_latest_payment_by_ref_id(command)

        # Spin further command processing in its own task.
        logger.debug(f'(other:{other_str}) Schedule cmd {cid}')
        fut = self.loop.create_task(self.process_command_success_async(
            other_addr, command, cid))

        # Log the futures here to execute them inidividually
        # when testing.
        if __debug__:
            self.futs += [fut]

        return fut

    # -------- Get Payment API commands --------

    def get_latest_payment_by_ref_id(self, ref_id):
        ''' Returns the latest payment with the reference ID provided.'''
        version = self.reference_id_index.try_get(ref_id)
        if version is None:
            raise KeyError(ref_id)
        return self.object_store[version]

    def get_payment_history_by_ref_id(self, ref_id):
        ''' Generator that returns all versions of a
            payment with a given reference ID
            in reverse causal order (newest first). '''
        payment = self.get_latest_payment_by_ref_id(ref_id)
        yield payment

        if payment.previous_version is not None:
            p_version = payment.previous_version
            payment = self.object_store[p_version]
            yield payment

    def store_latest_payment_by_ref_id(self, command):
        ''' Internal command to update the payment index '''
        payment = command.get_payment(self.object_store)

        # Update the Index of Reference ID -> Payment.
        ref_id = payment.reference_id

        # Write the new payment to the index of payments by
        # reference ID to support they GetPaymentAPI.
        payment_version = self.reference_id_index.try_get(ref_id)
        if payment_version:
            # We check that the previous version is present.
            # If so we update it with the new one.
            dependencies_versions = command.get_dependencies()
            if payment_version in dependencies_versions:
                self.reference_id_index[ref_id] = payment.version
        else:
            self.reference_id_index[ref_id] = payment.version

    # ----------- END of CommandProcessor interface ---------

    # FIXME collapse functions
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
        other_role = ['sender', 'receiver'][role == 'sender']
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

    async def payment_process_async(self, payment, ctx=None):
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

        is_receiver = business.is_recipient(payment, ctx)
        is_sender = not is_receiver
        role = ['sender', 'receiver'][is_receiver]
        other_role = ['sender', 'receiver'][not is_receiver]

        status = payment.data[role].status.as_status()
        current_status = status
        other_status = payment.data[other_role].status.as_status()

        new_payment = payment.new_version(store=self.object_store)

        abort_code = None
        abort_msg = None

        try:
            await business.payment_initial_processing(payment, ctx)

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
                    if new_payment.get_recipient_signature() == None:
                        new_payment.data[role].change_status(
                            StatusObject(Status.abort, "rejected", "recipient signature not presented")
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

        # FIXME push down this layer of handlign to various business functions
        # FIXME when do we do this here?
        except BusinessForceAbort as e:
            new_payment = payment.new_version(new_payment.version, store=self.object_store)
            new_payment.data[role].change_status(
                StatusObject(Status.abort, "rejected", str(e))
            )
        # FIXME not sure we need this , but keep it for now
        # if unseen exception happens, log it and scream
        except Exception as e:
            # This is an unexpected error, so we need to track it.
            error_ref = get_unique_string()

            logger.error(
                f'[{error_ref}] Error while processing payment {payment.reference_id}'
                ' return error in metadata & abort.')
            logger.exception(e)
            raise e

        # Do an internal consistency check:
        try:
            if not self.can_change_status(payment, new_payment):
                sender_status = payment.sender.status.as_status()
                receiver_status = payment.receiver.status.as_status()
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
