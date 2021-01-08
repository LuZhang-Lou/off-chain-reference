# Copyright (c) The Libra Core Contributors
# SPDX-License-Identifier: Apache-2.0

from ..protocol import VASPPairChannel, make_protocol_error
from ..protocol_messages import CommandRequestObject, CommandResponseObject, \
    OffChainProtocolError, OffChainException
from ..errors import OffChainErrorCode
from ..sample.sample_command import SampleCommand
from ..command_processor import CommandProcessor
from ..utils import JSONSerializable, JSONFlag
from ..storage import StorableFactory
from ..crypto import OffChainInvalidSignature

from copy import deepcopy
import random
from unittest.mock import MagicMock
import pytest
import json


def test_create_channel_to_myself(three_addresses, vasp):
    a0, _, _ = three_addresses
    command_processor = MagicMock(spec=CommandProcessor)
    store = MagicMock()
    with pytest.raises(OffChainException):
        channel = VASPPairChannel(a0, a0, vasp, store, command_processor)


def test_client_server_role_definition(three_addresses, vasp):
    a0, a1, a2 = three_addresses
    command_processor = MagicMock(spec=CommandProcessor)
    store = MagicMock()

    channel = VASPPairChannel(a0, a1, vasp, store, command_processor)
    assert channel.is_server()
    assert not channel.is_client()

    channel = VASPPairChannel(a1, a0, vasp, store, command_processor)
    assert not channel.is_server()
    assert channel.is_client()

    # Lower address is server (xor bit = 1)
    channel = VASPPairChannel(a0, a2, vasp, store, command_processor)
    assert not channel.is_server()
    assert channel.is_client()

    channel = VASPPairChannel(a2, a0, vasp, store, command_processor)
    assert channel.is_server()
    assert not channel.is_client()

def test_handle_seen_request(two_channels):
    server, client = two_channels

    # Create a server request for a command
    request = server.sequence_command_local(SampleCommand('Hello'))
    assert isinstance(request, CommandRequestObject)
    assert len(server.committed_commands) == 0
    assert len(server.my_pending_requests) == 1

    # Pass the request to the client
    len_before = len(client.processor.method_calls)
    assert len(client.committed_commands) == 0
    assert len(client.my_pending_requests) == 0
    reply = client.handle_request(request)
    assert isinstance(reply, CommandResponseObject)
    assert len(client.committed_commands) == 1
    assert len(client.my_pending_requests) == 0
    assert reply.status == 'success'
    assert client.processor.method_calls[-1][0] == 'process_command'
    len_after = len(client.processor.method_calls)
    assert len_before + 2 == len_after  # 2: check_command, process_command

    # handle old request
    reply = client.handle_request(request)
    assert isinstance(reply, CommandResponseObject)
    assert len(client.committed_commands) == 1
    assert len(client.my_pending_requests) == 0
    assert reply.status == 'success'

    latest_len = len(client.processor.method_calls)
    assert latest_len == len_after  # check_command, process_command are not called

    # test conflict request
    conflict_request = request
    conflict_request.command.command.item = "No Hello"
    reply = client.handle_request(conflict_request)
    assert reply.status == 'failure'


def test_protocol_server_client_benign(two_channels):
    server, client = two_channels

    # Create a server request for a command
    request = server.sequence_command_local(SampleCommand('Hello'))
    assert isinstance(request, CommandRequestObject)
    assert len(server.committed_commands) == 0
    assert len(server.my_pending_requests) == 1

    # Pass the request to the client
    assert len(client.committed_commands) == 0
    assert len(client.my_pending_requests) == 0
    reply = client.handle_request(request)
    assert isinstance(reply, CommandResponseObject)
    assert len(client.committed_commands) == 1
    assert len(client.my_pending_requests) == 0
    assert reply.status == 'success'
    assert client.committed_commands[request.cid].command.item() == 'Hello'

    # Pass the reply back to the server
    succ = server.handle_response(reply)
    assert succ
    assert len(server.committed_commands) == 1
    assert len(server.my_pending_requests) == 0

    assert server.processor.method_calls[-1][0] == 'process_command'
    len_before = len(server.processor.method_calls)

    # handle old response
    succ = server.handle_response(reply)
    assert succ
    assert len(server.committed_commands) == 1
    assert len(server.my_pending_requests) == 0
    len_after = len(server.processor.method_calls)
    assert len_before == len_after

    # test conflict response
    conflict_response = reply
    conflict_response.status = "failure"
    with pytest.raises(OffChainException):
        server.handle_response(conflict_response)

def test_protocol_server_conflicting_sequence(two_channels):
    server, client = two_channels

    # Create a server request for a command
    request = server.sequence_command_local(SampleCommand('Hello'))

    # Modilfy message to be a conflicting sequence number
    request_conflict = deepcopy(request)
    request_conflict.command = SampleCommand("Conflict")

    # Pass the request to the client
    reply = client.handle_request(request)
    reply_conflict = client.handle_request(request_conflict)

    # We only sequence one command.
    assert reply.status == 'success'

    # The response to the second command is a failure
    assert reply_conflict.status == 'failure'
    assert reply_conflict.error.code == OffChainErrorCode.conflict

    # Pass the reply back to the server
    assert len(server.committed_commands) == 0
    with pytest.raises(OffChainProtocolError):
        server.handle_response(reply_conflict)

    succ = server.handle_response(reply)
    assert succ
    assert len(server.committed_commands) == 1


def test_protocol_client_server_benign(two_channels):
    server, client = two_channels

    # Create a client request for a command
    request = client.sequence_command_local(SampleCommand('Hello'))
    assert isinstance(request, CommandRequestObject)
    assert len(client.my_pending_requests) == 1
    assert len(client.committed_commands) == 0

    # Send to server
    reply = server.handle_request(request)
    assert isinstance(reply, CommandResponseObject)
    assert len(server.committed_commands) == 1

    # Pass response back to client
    succ = client.handle_response(reply)
    assert succ
    assert len(client.committed_commands) == 1

    assert client.committed_commands[request.cid].response is not None
    assert client.committed_commands[request.cid].command.item() == 'Hello'


def test_protocol_server_client_interleaved_benign(two_channels):
    server, client = two_channels

    client_request = client.sequence_command_local(SampleCommand('Hello'))
    server_request = server.sequence_command_local(SampleCommand('World'))

    # The server waits until all own requests are done
    server_reply = server.handle_request(client_request)
    assert server_reply.status == 'success'

    client_reply = client.handle_request(server_request)
    server.handle_response(client_reply)
    server_reply = server.handle_request(client_request)
    client.handle_response(server_reply)

    assert len(client.my_pending_requests) == 0
    assert len(server.my_pending_requests) == 0
    assert len(client.committed_commands) == 2
    assert len(server.committed_commands) == 2

    assert client.committed_commands[client_request.cid].response is not None
    assert client.committed_commands[client_request.cid].command.item() == 'Hello'
    assert server.committed_commands[client_request.cid].response is not None
    assert server.committed_commands[client_request.cid].command.item() == 'Hello'

    assert client.committed_commands[server_request.cid].response is not None
    assert client.committed_commands[server_request.cid].command.item() == 'World'
    assert server.committed_commands[server_request.cid].response is not None
    assert server.committed_commands[server_request.cid].command.item() == 'World'


def test_protocol_server_client_handled_previously_seen_messages(two_channels):
    server, client = two_channels

    client_request = client.sequence_command_local(SampleCommand('Hello'))
    server_request = server.sequence_command_local(SampleCommand('World'))

    client_reply = client.handle_request(server_request)
    server_reply = server.handle_request(client_request)
    assert server_reply.status == 'success'
    assert client_reply.status == 'success'

    # Handle seen requests
    client_reply = client.handle_request(server_request)
    server_reply = server.handle_request(client_request)
    assert server_reply.status == 'success'
    assert client_reply.status == 'success'

    assert server.handle_response(client_reply)
    assert client.handle_response(server_reply)

    # Handle seen responses
    assert server.handle_response(client_reply)
    assert client.handle_response(server_reply)

    assert len(client.my_pending_requests) == 0
    assert len(server.my_pending_requests) == 0
    assert len(client.committed_commands) == 2
    assert len(server.committed_commands) == 2

    assert client.committed_commands[client_request.cid].response is not None
    assert client.committed_commands[client_request.cid].command.item() == 'Hello'
    assert server.committed_commands[client_request.cid].response is not None
    assert server.committed_commands[client_request.cid].command.item() == 'Hello'

    assert client.committed_commands[server_request.cid].response is not None
    assert client.committed_commands[server_request.cid].command.item() == 'World'
    assert server.committed_commands[server_request.cid].response is not None
    assert server.committed_commands[server_request.cid].command.item() == 'World'


async def test_handle_old_request(two_channels):
    server, client = two_channels


async def test_protocol_bad_signature(two_channels):
    server, client = two_channels

    msg = 'XRandomXJunk' # client.package_request(msg).content
    assert (await server.parse_handle_request(msg)).raw.is_failure()

    msg = '.Random.Junk' # client.package_request(msg).content
    assert (await server.parse_handle_request(msg)).raw.is_failure()


def test_json_serlialize():
    # Test Commands (to ensure correct debug)
    cmd = SampleCommand(1)
    cmd2 = SampleCommand(10)
    data = cmd.get_json_data_dict(JSONFlag.NET)
    cmd2 = SampleCommand.from_json_data_dict(data, JSONFlag.NET)
    assert cmd == cmd2

    # Test Request, Response
    req0 = CommandRequestObject(cmd, "10")
    req2 = CommandRequestObject(cmd2)
    req0.status = 'success'

    data = req0.get_json_data_dict(JSONFlag.STORE)
    assert data is not None
    req1 = CommandRequestObject.from_json_data_dict(data, JSONFlag.STORE)
    assert req0 == req1
    assert req1 != req2

    req0.response = make_protocol_error(req0, OffChainErrorCode.test_error_code)
    data_err = req0.get_json_data_dict(JSONFlag.STORE)
    assert data_err is not None
    assert data_err['response'] is not None
    req_err = CommandRequestObject.from_json_data_dict(
        data_err, JSONFlag.STORE)
    assert req0 == req_err


def test_VASProot(three_addresses, vasp):
    a0, a1, a2 = three_addresses

    # Check our own address is good
    assert vasp.get_vasp_address() == a0
    # Calling twice gives the same instance (use 'is')
    assert vasp.get_channel(a1) is vasp.get_channel(a1)
    # Different VASPs have different objects
    assert vasp.get_channel(a1) is not vasp.get_channel(a2)
    assert vasp.get_channel(a2).is_client()


def test_VASProot_diff_object(vasp, three_addresses):
    a0, _, b1 = three_addresses
    b2 = deepcopy(b1)

    # Check our own address is good
    assert vasp.get_vasp_address() == a0
    # Calling twice gives the same instance (use 'is')
    assert vasp.get_channel(b1) is vasp.get_channel(b2)


def test_real_address(three_addresses):
    from os import urandom
    A, _, B = three_addresses
    Ap = deepcopy(A)
    assert B.greater_than_or_equal(A)
    assert not A.greater_than_or_equal(B)
    assert A.greater_than_or_equal(A)
    assert A.greater_than_or_equal(Ap)
    assert A.equal(A)
    assert A.equal(Ap)
    assert not A.equal(B)
    assert not B.equal(Ap)
    assert A.last_bit() ^ B.last_bit() == 1
    assert A.last_bit() ^ A.last_bit() == 0

async def test_parse_handle_request_to_future(signed_json_request, channel, key):
    response = await channel.parse_handle_request(signed_json_request)
    res = await key.verify_message(response.content)

    res = json.loads(res)
    assert res['status'] == 'success'


async def test_parse_handle_request_to_future_out_of_order(
    json_request, channel, key
):
    json_request['cid'] = '100'
    json_request = await key.sign_message(json.dumps(json_request))
    fut = await channel.parse_handle_request(json_request)
    res = await key.verify_message(fut.content)
    res = json.loads(res)
    assert res['status']== 'success'


async def test_parse_handle_response_to_future_parsing_error(json_response, channel,
                                                       command, key):
    _ = channel.sequence_command_local(command)
    json_response['cid'] = '"'  # Trigger a parsing error.
    json_response = await key.sign_message(json.dumps(json_response))
    with pytest.raises(Exception):
        _ = await channel.parse_handle_response(json_response)


def test_role(channel):
    assert channel.role() == 'Client'


def test_pending_retransmit_number(channel):
    assert channel.pending_retransmit_number() == 0
