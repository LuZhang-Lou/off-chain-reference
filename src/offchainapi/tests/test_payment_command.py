# Copyright (c) The Libra Core Contributors
# SPDX-License-Identifier: Apache-2.0

from ..sample.sample_command import SampleCommand
from ..payment_command import PaymentCommand, PaymentLogicError
from ..payment import PaymentObject
from ..protocol_messages import CommandRequestObject, make_success_response
from ..utils import JSONFlag, JSONSerializable
from ..storage import StorableDict

import pytest

def test_payment_command_serialization_net(payment):
    cmd = PaymentCommand(payment)
    data = cmd.get_json_data_dict(JSONFlag.NET)
    cmd2 = PaymentCommand.from_json_data_dict(data, JSONFlag.NET)
    assert cmd == cmd2


def test_payment_command_serialization_parse(payment):
    cmd = PaymentCommand(payment)
    data = cmd.get_json_data_dict(JSONFlag.NET)
    obj = JSONSerializable.parse(data, JSONFlag.NET)
    assert obj == cmd

    cmd_s = SampleCommand('Hello')
    data2 = cmd_s.get_json_data_dict(JSONFlag.NET)
    cmd_s2 = JSONSerializable.parse(data2, JSONFlag.NET)
    assert cmd_s == cmd_s2


def test_payment_command_serialization_store(payment):
    cmd = PaymentCommand(payment)
    data = cmd.get_json_data_dict(JSONFlag.STORE)
    cmd2 = PaymentCommand.from_json_data_dict(data, JSONFlag.STORE)
    assert cmd == cmd2


def test_payment_end_to_end_serialization(payment):
    # Define a full request/reply with a Payment and test serialization
    cmd = PaymentCommand(payment)
    request = CommandRequestObject(cmd, "10")
    request.response = make_success_response(request)
    data = request.get_json_data_dict(JSONFlag.STORE)
    request2 = CommandRequestObject.from_json_data_dict(data, JSONFlag.STORE)
    assert request == request2


def test_payment_new_vesrion_identical(payment):
    new_payment = payment.new_version()
    assert new_payment == payment


def test_get_payment(payment, db):
    # Get a new payment -- no need for any dependency
    cmd = PaymentCommand(payment)
    payment_copy = cmd.get_payment() # Empty dependency store
    assert payment_copy == payment

    # A command that updates a payment to new version
    new_payment = payment.new_version()
    new_cmd = PaymentCommand(new_payment)
    assert new_cmd == cmd
    assert new_cmd.get_payment() == payment
