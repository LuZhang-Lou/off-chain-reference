# Copyright (c) The Libra Core Contributors
# SPDX-License-Identifier: Apache-2.0

from .command_processor import CommandProcessor, CommandValidationError
from .payment_command import PaymentCommand
from .protocol_messages import CommandRequestObject, CommandResponseObject, \
    OffChainProtocolError, OffChainException, \
    make_success_response, make_protocol_error, \
    make_parsing_error, make_command_error
from .errors import OffChainErrorCode
from .utils import JSONParsingError, JSONFlag
from .libra_address import LibraAddress
from .crypto import OffChainInvalidSignature
from .status_logic import State

import json
from collections import namedtuple
import logging
from itertools import islice
import asyncio


""" A Class to store messages meant to be sent on a network. """
NetMessage = namedtuple('NetMessage',
    ['src',  # The libra address of the source (no subaddress)
     'dst',  # The libra address of the destination (no subaddress)
     'type', # The Python type CommandRequestObject or CommandResponseObject
     'content', # signed message (str) sent over in the POST request / response
     'raw',  # The Python CommandRequestObject or CommandResponseObject object
     ])


logger = logging.getLogger(name='libra_off_chain_api.protocol')


class OffChainVASP:
    """ Manages the off-chain protocol on behalf of one VASP.

    Args:
        vasp_addr (LibraAddress): The address of the VASP.
        processor (CommandProcessor): The command processor.
        storage_factory (StorableFactory): The storage factory.
        info_context (VASPInfo): The information context for the VASP
                                 implementing the VASPInfo interface.
    """

    def __init__(self, vasp_addr, processor, storage_factory, info_context):
        logger.debug(f'Creating VASP {vasp_addr.as_str()}')

        assert isinstance(processor, CommandProcessor)
        assert isinstance(vasp_addr, LibraAddress)

        # The LibraAddress of the VASP.
        self.vasp_addr = vasp_addr
        # The business context provided by the processor.
        self.business_context = processor.business_context()

        # The command processor that checks and processes commands.
        # We attach the notify member to this class to trigger
        # processing of resumed commands.
        self.processor = processor

        # The VASPInfo context that contains various network information
        # such as TLS certificates and keys.
        self.info_context = info_context

        # The dict of channels we already have.
        self.channel_store = {}

        # Manage storage.
        self.storage_factory = storage_factory

    def get_vasp_address(self):
        """Return our own VASP Libra Blockchain Address.

        Returns:
            LibraAddress: The VASP's Blockchain address.
        """
        return self.vasp_addr

    def get_channel(self, other_vasp_addr):
        ''' Returns a VASPPairChannel with the other VASP.

        Parameters:
            other_vasp_addr (LibraAddress): The Libra Blockchain address of the other VASP.

        Returns:
            VASPPairChannel: A channel with the other VASP.

        '''
        self.business_context.open_channel_to(other_vasp_addr)
        my_address = self.get_vasp_address()
        store_key = (my_address, other_vasp_addr)

        if store_key not in self.channel_store:
            channel = VASPPairChannel(
                my_address,
                other_vasp_addr,
                self,
                self.storage_factory,
                self.processor
            )
            self.channel_store[store_key] = channel

        return self.channel_store[store_key]


class VASPPairChannel:
    """ Represents the state of an off-chain bi-directional
        channel bewteen two VASPs.

    Args:
        myself (LibraAddress): The Libra Blockchain address of the current VASP.
        other (LibraAddress): The Libra Blockchain address of the other VASP.
        vasp (OffChainVASP): The OffChainVASP to which this channel
                             is attached.
        storage (StorageFactory): The storage factory.
        processor (CommandProcessor): A command processor.

    Raises:
        OffChainException: If the channel is not talking to another VASP.
    """

    def __init__(self, myself, other, vasp, storage, processor):

        assert isinstance(myself, LibraAddress)
        assert isinstance(other, LibraAddress)
        assert isinstance(processor, CommandProcessor)
        assert isinstance(vasp, OffChainVASP)

        # State that is given by constructor.
        self.myself = myself
        self.other = other
        self.other_address_str = self.other.as_str()
        self.processor = processor
        self.vasp = vasp
        self.storage = storage

        # Check we are not making a channel with ourselves.
        if self.myself.as_str() == self.other_address_str:
            raise OffChainException(
                'Must talk to another VASP:',
                self.myself.as_str(),
                self.other_address_str
            )

        root = self.storage.make_dir(self.myself.as_str())
        other_vasp = self.storage.make_dir(
            self.other_address_str, root=root
        )

        # The map of commited requests with their corresponding responses.
        # This is also used to ensure command responses are indempotent.
        # All requests in this store have response attached.
        self.committed_commands = self.storage.make_dict(
            'committed_commands', CommandRequestObject, root=other_vasp
        )

        self.my_pending_requests = self.storage.make_dict(
                'my_pending_requests', CommandRequestObject,
                root=other_vasp)

        logger.debug(f'(other:{self.other_address_str}) Created VASP channel')

    def get_my_address(self):
        """
        Returns:
            LibraAddress: The Libra Blockchain address of this VASP.
        """
        return self.myself

    def get_other_address(self):
        """
        Returns:
            LibraAddress: The Libra Blockchain address of the other VASP.
        """
        return self.other

    async def package_request(self, request):

        """ A hook to send a request to other VASP.

        Args:
            request (CommandRequestObject): The request object.

        Returns:
            NetMessage: The message to be sent on a network.
        """
        json_dict = request.get_json_data_dict(JSONFlag.NET)

        # Make signature.
        vasp = self.vasp
        my_key = vasp.info_context.get_my_compliance_signature_key(
            self.get_my_address().as_str()
        )
        signed_message = await my_key.sign_message(json.dumps(json_dict))

        net_message = NetMessage(
            self.myself,
            self.other,
            CommandRequestObject,
            signed_message,
            request
        )

        return net_message

    async def package_response(self, response):
        """ A hook to send a response to other VASP.

        Args:
            response (CommandResponseObject): The request object.

        Returns:
            NetMessage: The message to be sent on a network.
        """
        struct = response.get_json_data_dict(JSONFlag.NET)

        # Sign response
        info_context = self.vasp.info_context
        my_key = info_context.get_my_compliance_signature_key(
            self.get_my_address().as_str()
        )

        signed_response = await my_key.sign_message(json.dumps(struct))

        net_message = NetMessage(
            self.myself, self.other, CommandResponseObject, signed_response, response
        )

        return net_message

    def is_client(self):
        """
        Returns:
            bool: Whether the local VASP the client for this pair.
        """
        myself_address = self.myself
        other_address = self.other

        # Write out the logic, for clarity
        bit = myself_address.last_bit() ^ other_address.last_bit()
        if bit == 0:
            return myself_address.greater_than_or_equal(other_address)
        if bit == 1:
            return not myself_address.greater_than_or_equal(other_address)
        assert False  # Never reach this code

    def role(self):
        """ The role of the VASP as a string. For debug output.

        Returns:
            str: The role of the VASP.
        """
        return ['Server', 'Client'][self.is_client()]

    def is_server(self):
        """
         Returns:
             bool: Whether the local VASP the server for this pair.
         """
        return not self.is_client()

    def apply_response(self, request):
        """Updates all structures according to the success or failure of
        a given command. The given request must also contain a response
        (not None).

        Args:
            request (CommandRequestObject): The request object.
        """
        assert request.response is not None
        response = request.response

        other_addr = self.get_other_address()

        self.processor.process_command(
            other_addr=other_addr,
            command=request.command,
            cid=request.cid,
            status_success=request.is_success(),
            error=response.error if response.error else None
        )


    def sequence_command_local(self, off_chain_command):
        """The local VASP attempts to sequence a new off-chain command.

        Args:
            off_chain_command (PaymentCommand): The command to sequence.

        Returns:
            NetMessage: The message to be sent on a network.
        """

        off_chain_command.set_origin(self.get_my_address())
        request = CommandRequestObject(off_chain_command)

        self.processor.check_command(
            self.get_my_address(),
            self.get_other_address(),
            off_chain_command)

        # Add the request to those requiring a response.
        self.my_pending_requests[request.cid] = request

        # Send the requests outside the locks to allow
        # for an asyncronous implementation.
        return request

    async def parse_handle_request(self, json_command):
        """ Handles a request provided as a json string or dict.

        Args:
            json_command (str or dict): The json request.

        Returns:
            NetMessage: The message to be sent on a network.
        """
        try:
            # Check signature
            vasp = self.vasp
            other_key = vasp.info_context.get_peer_compliance_verification_key(
                self.other_address_str
            )

            message = await other_key.verify_message(json_command)
            request = json.loads(message)

            # Parse the request whoever necessary.
            request = CommandRequestObject.from_json_data_dict(
                request, JSONFlag.NET
            )

            # Going ahead to process the request.
            logger.debug(
                f'(other:{self.other_address_str}) '
                f'Processing request seq #{request.cid}',
            )
            response = self.handle_request(request)

        except OffChainInvalidSignature as e:
            logger.warning(
                f'(other:{self.other_address_str}) '
                f'Signature verification failed. OffChainInvalidSignature: {e}'
            )
            response = make_parsing_error(f'{e}', code=OffChainErrorCode.invalid_signature)

        except JSONParsingError as e:
            logger.error(
                f'(other:{self.other_address_str}) JSONParsingError: {e}',
                exc_info=True,
            )
            response = make_parsing_error()
        except Exception as e:
            logger.error(
                f'(other:{self.other_address_str}) exception: {e}',
                exc_info=True,
            )
            raise e

        # Prepare the response.
        full_response = await self.package_response(response)
        return full_response

    def handle_request(self, request):
        """ Handles a request provided as a dictionary.

        Args:
            request (CommandRequestObject): The request.

        Returns:
            CommandResponseObject: The response to the VASP's request.
        """
        command = request.command
        command.set_origin(self.other)

        # Always answer old requests.
        previous_request = self.committed_commands.try_get(request.cid)

        if previous_request:
            if previous_request == request:

                # Re-send the response.
                logger.debug(
                    f'(other:{self.other_address_str}) '
                    f'Handle request that alerady has a response: '
                    f'cid #{request.cid}.',
                )
                return previous_request.response
            else:
                # There is a conflict, and it will have to be resolved
                # TODO[issue 8]: How are conflicts meant to be resolved?
                # With only two participants we cannot tolerate errors.
                response = make_protocol_error(
                    request, code=OffChainErrorCode.conflict)

                response.previous_command = previous_request.command
                payment_specific_message = None
                if isinstance(command, PaymentCommand):
                    state = State.from_payment_object(command.get_payment())
                    reference_id = command.get_payment().reference_id
                    payment_specific_message = f"ref_id: {reference_id}, state: {state.value}"
                logger.error(
                    f'(other:{self.other_address_str}) '
                    f'Conflicting requests for cid: {request.cid}, {payment_specific_message}'
                )
                return response

        # never see this request before, try to check command's integrity
        try:
            my_address = self.get_my_address()
            other_address = self.get_other_address()

            self.processor.check_command(my_address, other_address, command)

            response = make_success_response(request)
        except CommandValidationError as e:
            response = make_command_error(
                request,
                code=e.error_code,
                message=e.error_message)

        # Write back to storage
        request.response = response

        self.committed_commands[request.cid] = request
        self.apply_response(request)

        return request.response

    async def parse_handle_response(self, json_response):
        """ Parses and handles a JWS signed response.

        Args:
            response_text (str): The response signed using JWS.

        Returns:
            bool: Whether the command was a success or not
        """
        try:
            vasp = self.vasp
            other_key = vasp.info_context.get_peer_compliance_verification_key(
                self.other_address_str
            )
            message = await other_key.verify_message(json_response)
            response = json.loads(message)
            response = CommandResponseObject.from_json_data_dict(
                response, JSONFlag.NET
            )

            return self.handle_response(response)

        except OffChainInvalidSignature as e:
            logger.warning(
                f'(other:{self.other_address_str}) '
                f'Signature verification failed. OffChainInvalidSignature: {e}'
            )
            raise e
        except JSONParsingError as e:
            logger.warning(
                f'(other:{self.other_address_str}) JSONParsingError: {e}'
            )
            raise e
        except OffChainException or OffChainProtocolError as e:
            logger.warning(
                f'(other:{self.other_address_str}) '
                f'OffChainException/OffChainProtocolError: {e}',
            )
            raise e

    def handle_response(self, response):
        """ Handles a response provided as a dictionary.

        Args:
            response (CommandResponseObject): The response.

        Raises:
            OffChainProtocolError: On protocol error.
            OffChainException: On an unrecoverabe error.

        Returns:
            bool: Whether the response is successfully sequenced.
        """
        assert isinstance(response, CommandResponseObject)

        # Is there was a protocol error return the error.
        if response.is_protocol_failure():
            raise OffChainProtocolError.make(response.error)

        request_cid = response.cid

        # If we have already processed the response.
        request = self.committed_commands.try_get(request_cid)
        if request and request.has_response():
            # Check the reponse is the same and log warning otherwise.
            if request.response != response:
                excp = OffChainException(
                    f'Got different responses with cid {request_cid}.'
                )
                excp.response1 = request.response
                excp.response2 = response
                raise excp
            # This request may have concurrent modification
            # read db to get latest status
            return self.committed_commands[request_cid].is_success()

        request = self.my_pending_requests.try_get(request_cid)
        if not request:
            raise OffChainException(
                f'Response for unknown cid {request_cid} received.'
            )

        # Read and write back response into request.
        request.response = response

        # Add the next command to the common sequence.
        self.committed_commands[request.cid] = request
        del self.my_pending_requests[request_cid]
        self.apply_response(request)
        return request.is_success()

    def get_retransmit(self, number=1):
        ''' Returns up to a `number` (int) of pending requests
        (CommandRequestObject)'''
        net_messages = []
        for next_retransmit in islice(self.my_pending_requests.keys(), number):
            request_to_send = self.my_pending_requests[next_retransmit]
            net_messages += [request_to_send]
        return net_messages

    async def package_retransmit(self, number=1):
        """ Packages up to a `number` (int) of earlier requests without a
        reply to send to the the  other party. Returns a list of `NetMessage`
        instances.
        """
        return await asyncio.gather(
            *[
                self.package_request(m) for m in self.get_retransmit(number)
            ]
        )

    def would_retransmit(self):
        """ Returns true if there are any pending re-transmits, namely
            requests for which the response has not yet been received.
        """
        return not self.my_pending_requests.is_empty()

    def pending_retransmit_number(self):
        '''
        Returns:
            the number of requests that are waiting to be
            retransmitted on this channel.
        '''
        return len(self.my_pending_requests)
