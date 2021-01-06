# Copyright (c) The Libra Core Contributors
# SPDX-License-Identifier: Apache-2.0

from ..protocol import VASPPairChannel
from ..status_logic import Status, KYCResult, State, InvalidStateException
from ..payment_command import PaymentCommand, PaymentLogicError
from ..business import BusinessForceAbort, BusinessValidationFailure
from os import urandom
from ..payment import PaymentObject, StatusObject, PaymentActor, PaymentAction
from ..libra_address import LibraAddress
from ..asyncnet import Aionet
from ..storage import StorableFactory
from ..payment_logic import PaymentProcessor
from ..utils import JSONFlag
from ..errors import OffChainErrorCode

from .basic_business_context import TestBusinessContext

from unittest.mock import MagicMock
from mock import AsyncMock
import pytest
import copy

@pytest.fixture
def payment():
    sender_addr = LibraAddress.from_bytes("lbr", b'B'*16, b'b'*8)
    sender =  PaymentActor(sender_addr.as_str(), StatusObject(Status.none), [])
    receiver_addr = LibraAddress.from_bytes("lbr", b'A'*16, b'a'*8)
    receiver =  PaymentActor(receiver_addr.as_str(), StatusObject(Status.none), [])
    action = PaymentAction(5, 'TIK', 'charge', 7784993)
    ref_id = f'{LibraAddress.from_encoded_str(sender_addr.get_onchain_encoded_str())}_{urandom(16).hex()}'
    return PaymentObject(
        sender, receiver, ref_id, None,
        'Human readable payment information.', action
    )


def test_SINIT(payment):
    payment.sender.change_status(StatusObject(Status.needs_kyc_data))
    assert State.from_payment_object(payment) == State.SINIT

    payment2 = payment.new_version()
    payment2.sender.add_additional_kyc_data("additional_kyc")
    with pytest.raises(InvalidStateException):
        State.from_payment_object(payment2)

    payment3 = payment.new_version()
    payment3.receiver.add_additional_kyc_data("additional_kyc")
    with pytest.raises(InvalidStateException):
        State.from_payment_object(payment3)


def test_RSEND(payment):
    payment.sender.change_status(StatusObject(Status.needs_kyc_data))
    payment.receiver.change_status(StatusObject(Status.ready_for_settlement))
    assert State.from_payment_object(payment) == State.RSEND

    payment2 = payment.new_version()
    payment2.sender.add_additional_kyc_data("additional_kyc")
    assert State.from_payment_object(payment2) == State.RSEND

    payment3 = payment.new_version()
    payment3.receiver.add_additional_kyc_data("additional_kyc")
    with pytest.raises(InvalidStateException):
        State.from_payment_object(payment3)

    payment4 = payment2.new_version()
    payment4.receiver.add_additional_kyc_data("additional_kyc")
    with pytest.raises(InvalidStateException):
        State.from_payment_object(payment4)

def test_RABORT(payment):
    payment.sender.change_status(StatusObject(Status.needs_kyc_data))
    payment.receiver.change_status(StatusObject(Status.abort, "", ""))
    assert State.from_payment_object(payment) == State.RABORT

    payment2 = payment.new_version()
    payment2.sender.add_additional_kyc_data("additional_kyc")
    assert State.from_payment_object(payment2) == State.RABORT

    payment3 = payment.new_version()
    payment3.receiver.add_additional_kyc_data("additional_kyc")
    with pytest.raises(InvalidStateException):
        State.from_payment_object(payment3)

def test_SABORT(payment):
    payment.sender.change_status(StatusObject(Status.abort, "", ""))
    payment.receiver.change_status(StatusObject(Status.ready_for_settlement))
    assert State.from_payment_object(payment) == State.SABORT

    payment2 = payment.new_version()
    payment2.sender.add_additional_kyc_data("additional_kyc")
    assert State.from_payment_object(payment2) == State.SABORT

    payment3 = payment.new_version()
    payment3.receiver.add_additional_kyc_data("additional_kyc")
    assert State.from_payment_object(payment3) == State.SABORT

def test_READY(payment):
    payment.sender.change_status(StatusObject(Status.ready_for_settlement))
    payment.receiver.change_status(StatusObject(Status.ready_for_settlement))
    assert State.from_payment_object(payment) == State.READY

    payment2 = payment.new_version()
    payment2.sender.add_additional_kyc_data("additional_kyc")
    assert State.from_payment_object(payment2) == State.READY

    payment3 = payment.new_version()
    payment3.receiver.add_additional_kyc_data("additional_kyc")
    assert State.from_payment_object(payment3) == State.READY

def test_RSOFT(payment):
    payment.sender.change_status(StatusObject(Status.needs_kyc_data))
    payment.receiver.change_status(StatusObject(Status.soft_match))
    assert State.from_payment_object(payment) == State.RSOFT


    payment3 = payment.new_version()
    payment3.receiver.add_additional_kyc_data("additional_kyc")
    with pytest.raises(InvalidStateException):
        State.from_payment_object(payment3)

def test_SSOFTSEND(payment):
    payment.sender.change_status(StatusObject(Status.needs_kyc_data))
    payment.receiver.change_status(StatusObject(Status.soft_match))

    payment.sender.add_additional_kyc_data("additional_kyc")
    assert State.from_payment_object(payment) == State.SSOFTSEND

    payment2 = payment.new_version()
    payment2.receiver.add_additional_kyc_data("additional_kyc")
    with pytest.raises(InvalidStateException):
        State.from_payment_object(payment2)

def test_SSOFT(payment):
    payment.sender.change_status(StatusObject(Status.soft_match))
    payment.receiver.change_status(StatusObject(Status.ready_for_settlement))
    assert State.from_payment_object(payment) == State.SSOFT

    payment2 = payment.new_version()
    payment2.sender.add_additional_kyc_data("additional_kyc")
    assert State.from_payment_object(payment) == State.SSOFT

def test_RSOFTSEND(payment):
    payment.sender.change_status(StatusObject(Status.soft_match))
    payment.receiver.change_status(StatusObject(Status.ready_for_settlement))
    payment.receiver.add_additional_kyc_data("additional_kyc")
    assert State.from_payment_object(payment) == State.RSOFTSEND

    payment2 = payment.new_version()
    payment2.sender.add_additional_kyc_data("additional_kyc")
    assert State.from_payment_object(payment) == State.RSOFTSEND
