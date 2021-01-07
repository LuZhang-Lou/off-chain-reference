# Copyright (c) The Libra Core Contributors
# SPDX-License-Identifier: Apache-2.0

from ..protocol import VASPPairChannel
from ..status_logic import Status, KYCResult, State
from ..payment_command import PaymentCommand, PaymentLogicError
from ..business import BusinessForceAbort, BusinessValidationFailure
from os import urandom
from ..payment import PaymentObject, StatusObject, PaymentActor, PaymentAction
from ..libra_address import LibraAddress
from ..asyncnet import Aionet
from ..storage import StorableFactory
from ..payment_logic import PaymentProcessor, PaymentStateMachine
from ..utils import JSONFlag
from ..errors import OffChainErrorCode

from .basic_business_context import TestBusinessContext

from unittest.mock import MagicMock
from mock import AsyncMock
import pytest
import copy


@pytest.fixture
def sender_actor():
    addr = LibraAddress.from_bytes("lbr", b'A'*16, b'a'*8).as_str()
    return PaymentActor(addr, StatusObject(Status.needs_kyc_data), [])


@pytest.fixture
def receiver_actor():
    addr = LibraAddress.from_bytes("lbr", b'B'*16, b'b'*8).as_str()
    return PaymentActor(addr, StatusObject(Status.none), [])


@pytest.fixture
def payment_action():
    return PaymentAction(5, 'TIK', 'charge', 7784993)


@pytest.fixture
def payment(sender_actor, receiver_actor, payment_action):
    ref_id = f'{LibraAddress.from_encoded_str(sender_actor.address).get_onchain_encoded_str()}_{urandom(16).hex()}'
    return PaymentObject(
        sender_actor, receiver_actor, ref_id, None,
        'Human readable payment information.', payment_action
    )

def test_check_initial_payment_from_receiver(payment, processor):
    bcm = processor.business_context()
    bcm.is_recipient.return_value = True
    payment.sender.change_status(StatusObject(Status.needs_kyc_data))
    payment.receiver.change_status(StatusObject(Status.none))
    processor.check_initial_payment(payment)


def test_check_initial_payment_bad_state(payment, processor):
    bcm = processor.business_context()
    bcm.is_recipient.return_value = True
    payment.sender.change_status(StatusObject(Status.abort, "", ""))
    payment.receiver.change_status(StatusObject(Status.abort, "", ""))
    with pytest.raises(PaymentLogicError) as e:
        processor.check_initial_payment(payment)
    assert "Invalid state in payment" in e.value.error_message


def test_check_initial_payment_bad_initial_state(payment, processor):
    bcm = processor.business_context()
    bcm.is_recipient.return_value = True
    payment.sender.change_status(StatusObject(Status.ready_for_settlement))
    payment.receiver.change_status(StatusObject(Status.ready_for_settlement))
    with pytest.raises(PaymentLogicError) as e:
        processor.check_initial_payment(payment)
    assert "Initial payment object is not in SINIT state" in e.value.error_message


def test_check_initial_payment_bad_sender_actor_address(payment, processor):
    snone = StatusObject(Status.needs_kyc_data)
    actor = PaymentActor('XYZ', snone, [])

    bcm = processor.business_context()
    bcm.is_recipient.return_value = True

    payment.sender = actor
    with pytest.raises(PaymentLogicError) as e:
        processor.check_initial_payment(payment)
    assert e.value.error_code == OffChainErrorCode.payment_invalid_libra_address

def test_check_initial_payment_allow_empty_sender_actor_subaddress(payment, processor):
    bcm = processor.business_context()
    bcm.is_recipient.return_value = True

    addr = LibraAddress.from_encoded_str(payment.sender.address)
    addr2 = LibraAddress.from_bytes("lbr", addr.onchain_address_bytes, None)
    payment.sender.address = addr2.as_str()

    processor.check_initial_payment(payment)

def test_check_initial_payment_bad_receiver_actor_address(payment, processor):
    snone = StatusObject(Status.none)
    actor = PaymentActor('XYZ', snone, [])

    bcm = processor.business_context()
    bcm.is_recipient.return_value = True

    payment.receiver = actor
    with pytest.raises(PaymentLogicError) as e:
        processor.check_initial_payment(payment)
    assert e.value.error_code == OffChainErrorCode.payment_invalid_libra_address

def test_check_initial_payment_allow_empty_actor_subaddress(payment, processor):
    bcm = processor.business_context()
    bcm.is_recipient.return_value = True

    addr = LibraAddress.from_encoded_str(payment.sender.address)
    addr2 = LibraAddress.from_bytes("lbr", addr.onchain_address_bytes, None)
    payment.receiver.address = addr2.as_str()

    processor.check_initial_payment(payment)

def test_check_new_update(payment, processor):
    bcm = processor.business_context()
    bcm.is_recipient.return_value = False
    payment.sender.change_status(StatusObject(Status.needs_kyc_data))
    payment.receiver.change_status(StatusObject(Status.none))
    new_payment = payment.new_version()
    new_payment.sender.change_status(StatusObject(Status.needs_kyc_data))
    new_payment.receiver.change_status(StatusObject(Status.ready_for_settlement))
    new_payment.add_recipient_signature("VALID")
    processor.check_new_update(payment, new_payment)

def test_check_new_update_no_signature(payment, processor):
    bcm = processor.business_context()
    bcm.is_recipient.return_value = False
    payment.sender.change_status(StatusObject(Status.needs_kyc_data))
    payment.receiver.change_status(StatusObject(Status.none))
    new_payment = payment.new_version()
    new_payment.sender.change_status(StatusObject(Status.needs_kyc_data))
    new_payment.receiver.change_status(StatusObject(Status.ready_for_settlement))
    with pytest.raises(PaymentLogicError) as e:
        processor.check_new_update(payment, new_payment)
    assert "Recipient signature is not included in " in e.value.error_message


def test_check_new_update_empty_payment_update_fail(payment, processor):
    bcm = processor.business_context()
    bcm.is_recipient.return_value = False
    diff = {}
    new_payment = payment.new_version()
    new_payment = PaymentObject.from_full_record(diff, base_instance=new_payment)
    # Can't transition to the same state
    with pytest.raises(PaymentLogicError):
        processor.check_new_update(payment, new_payment)


def test_check_new_update_bad_signature(payment, processor):
    bcm = processor.business_context()
    bcm.is_recipient.return_value = False
    bcm.validate_recipient_signature.side_effect = [BusinessValidationFailure('Bad signature')]
    # payment is SINIT

    # new_payment is RSEND
    new_payment = payment.new_version()
    new_payment.add_recipient_signature("XXX_BAD_SIGN")
    new_payment.receiver.change_status(StatusObject(Status.ready_for_settlement))

    with pytest.raises(PaymentLogicError) as e:
        processor.check_new_update(payment, new_payment)
    assert "signature" in e.value.error_message

def test_check_new_update_invalid_state(payment, processor):
    bcm = processor.business_context()
    # payment is RSOFT
    payment.sender.change_status(StatusObject(Status.needs_kyc_data))
    payment.receiver.change_status(StatusObject(Status.soft_match))

    new_payment = payment.new_version()
    # SABORT
    new_payment.sender.change_status(StatusObject(Status.abort, "", ""))
    new_payment.receiver.change_status(StatusObject(Status.soft_match))
    with pytest.raises(PaymentLogicError) as e:
        processor.check_new_update(payment, new_payment)
    assert "Invalid state in payment" in e.value.error_message


def test_check_new_update_sender_modify_receiver_state_fail(payment, processor):
    bcm = processor.business_context()
    bcm.is_recipient.return_value = True
    diff = {'receiver': {'status': { 'status': "ready_for_settlement"}}}
    new_payment = payment.new_version()
    new_payment = PaymentObject.from_full_record(diff, base_instance=new_payment)
    assert new_payment.receiver.data['status'] != payment.receiver.data['status']
    with pytest.raises(PaymentLogicError) as e:
        processor.check_new_update(payment, new_payment)
    assert "Cannot change" in e.value.error_message


def test_check_new_update_receiver_modify_sender_state_fail(payment, processor):
    bcm = processor.business_context()
    bcm.is_recipient.side_effect = [False]*5
    diff = {'sender': {'status': { 'status': "ready_for_settlement"}}}
    new_obj = payment.new_version()
    new_obj = PaymentObject.from_full_record(diff, base_instance=new_obj)
    assert new_obj.sender.data['status'] != payment.sender.data['status']
    with pytest.raises(PaymentLogicError) as e:
        processor.check_new_update(payment, new_obj)
    assert "Cannot change" in e.value.error_message


def test_check_command(three_addresses, payment, processor):
    states = [
        (b'AAAA', b'BBBB', b'AAAA', True),
        (b'BBBB', b'AAAA', b'AAAA', True),
        (b'CCCC', b'AAAA', b'AAAA', False),
        (b'BBBB', b'CCCC', b'AAAA', False),
        (b'DDDD', b'CCCC', b'AAAA', False),
        (b'AAAA', b'BBBB', b'BBBB', True),
        (b'BBBB', b'AAAA', b'DDDD', False),
    ]
    a0, _, a1 = three_addresses
    channel = MagicMock(spec=VASPPairChannel)
    channel.get_my_address.return_value = a0
    channel.get_other_address.return_value = a1

    for state in states:
        src_addr, dst_addr, origin_addr, res = state

        a0 = LibraAddress.from_bytes("lbr", src_addr*4)
        a1 = LibraAddress.from_bytes("lbr", dst_addr*4)
        origin = LibraAddress.from_bytes("lbr", origin_addr*4)

        channel.get_my_address.return_value = a0
        channel.get_other_address.return_value = a1

        payment.data['reference_id'] = f'{origin.as_str()}_XYZ'
        command = PaymentCommand(payment)
        command.set_origin(origin)

        if res:
            my_address = channel.get_my_address()
            other_address = channel.get_other_address()
            processor.check_command(my_address, other_address, command)
        else:
            with pytest.raises(PaymentLogicError):
                my_address = channel.get_my_address()
                other_address = channel.get_other_address()
                processor.check_command(my_address, other_address, command)

def test_check_command_bad_refid(three_addresses, payment, processor):
    a0, _, a1 = three_addresses
    channel = MagicMock(spec=VASPPairChannel)
    channel.get_my_address.return_value = a0
    channel.get_other_address.return_value = a1
    origin = a1 # Only check new commands from other side

    # Wrong origin ref_ID address
    payment.reference_id = f'{origin.as_str()[:-2]}ZZ_XYZ'
    command = PaymentCommand(payment)
    command.set_origin(origin)

    my_address = channel.get_my_address()
    other_address = channel.get_other_address()

    with pytest.raises(PaymentLogicError) as e:
        processor.check_command(my_address, other_address, command)
    assert e.value.error_code == OffChainErrorCode.payment_wrong_structure


def test_payment_process_SINIT_receiver_provide_kyc_and_signature(payment, processor, kyc_data, signature):
    bcm = processor.business_context()
    bcm.is_recipient.side_effect = [True]
    bcm.get_extended_kyc.side_effect = [kyc_data]
    bcm.get_recipient_signature.side_effect = [signature]
    bcm.evaluate_kyc.side_effect = [KYCResult.PASS]

    payment.sender.change_status(StatusObject(Status.needs_kyc_data))
    payment.receiver.change_status(StatusObject(Status.none))
    assert State.from_payment_object(payment), State.SINIT

    new_payment = processor.payment_process(payment)
    assert new_payment.receiver.kyc_data == kyc_data
    assert new_payment.recipient_signature == signature
    assert State.from_payment_object(new_payment), State.RSEND

def test_payment_process_SINIT_receiver_soft_match(payment, processor, kyc_data, signature):
    bcm = processor.business_context()
    bcm.is_recipient.side_effect = [True]
    bcm.get_extended_kyc.side_effect = [kyc_data]
    bcm.get_recipient_signature.side_effect = [signature]
    bcm.evaluate_kyc.side_effect = [KYCResult.SOFT_MATCH]

    payment.sender.change_status(StatusObject(Status.needs_kyc_data))
    payment.receiver.change_status(StatusObject(Status.none))
    assert State.from_payment_object(payment), State.SINIT

    new_payment = processor.payment_process(payment)
    assert "kyc_data" not in new_payment.receiver.data
    assert new_payment.get_recipient_signature() is None
    assert State.from_payment_object(new_payment), State.RSOFT

def test_payment_process_SINIT_receiver_abort(payment, processor, kyc_data, signature):
    bcm = processor.business_context()
    bcm.is_recipient.side_effect = [True]
    bcm.get_extended_kyc.side_effect = [kyc_data]
    bcm.get_recipient_signature.side_effect = [signature]
    bcm.evaluate_kyc.side_effect = [KYCResult.FAIL]

    payment.sender.change_status(StatusObject(Status.needs_kyc_data))
    payment.receiver.change_status(StatusObject(Status.none))
    assert State.from_payment_object(payment), State.SINIT

    new_payment = processor.payment_process(payment)
    assert "kyc_data" not in new_payment.receiver.data
    assert new_payment.get_recipient_signature() is None
    assert State.from_payment_object(new_payment), State.RABORT

def test_payment_process_RSEND_sender_ready(payment, processor, kyc_data, signature):
    payment.sender.change_status(StatusObject(Status.needs_kyc_data))
    payment.receiver.change_status(StatusObject(Status.ready_for_settlement))
    payment.recipient_signature = signature
    assert State.from_payment_object(payment), State.RSEND

    bcm = processor.business_context()
    bcm.is_recipient.side_effect = [False]
    bcm.evaluate_kyc.side_effect = [KYCResult.PASS]
    bcm.sender_ready_to_settle.side_effect = [(True, "")]

    new_payment = processor.payment_process(payment)
    assert State.from_payment_object(new_payment), State.READY

def test_payment_process_RSEND_sender_not_ready_and_abort(payment, processor, kyc_data, signature):
    payment.sender.change_status(StatusObject(Status.needs_kyc_data))
    payment.receiver.change_status(StatusObject(Status.ready_for_settlement))
    assert State.from_payment_object(payment), State.RSEND

    bcm = processor.business_context()
    bcm.is_recipient.side_effect = [False]
    bcm.evaluate_kyc.side_effect = [KYCResult.PASS]
    bcm.sender_ready_to_settle.side_effect = [(False, "no signture provided")]

    new_payment = processor.payment_process(payment)
    assert State.from_payment_object(new_payment), State.SABORT

def test_payment_process_RSEND_sender_softmatch(payment, processor, kyc_data, signature):
    payment.sender.change_status(StatusObject(Status.needs_kyc_data))
    payment.receiver.change_status(StatusObject(Status.ready_for_settlement))
    assert State.from_payment_object(payment), State.RSEND

    bcm = processor.business_context()
    bcm.is_recipient.side_effect = [False]
    bcm.evaluate_kyc.side_effect = [KYCResult.SOFT_MATCH]

    new_payment = processor.payment_process(payment)
    assert State.from_payment_object(new_payment), State.SSOFT

def test_payment_process_RSEND_sender_abort(payment, processor, kyc_data, signature):
    payment.sender.change_status(StatusObject(Status.needs_kyc_data))
    payment.receiver.change_status(StatusObject(Status.ready_for_settlement))
    assert State.from_payment_object(payment), State.RSEND

    bcm = processor.business_context()
    bcm.is_recipient.side_effect = [False]
    bcm.evaluate_kyc.side_effect = [KYCResult.FAIL]

    new_payment = processor.payment_process(payment)
    assert State.from_payment_object(new_payment), State.SABORT

def test_payment_process_RSOFT_sender_provide_additioal_kyc_data(payment, processor, kyc_data, signature, additional_kyc_data):
    payment.sender.change_status(StatusObject(Status.needs_kyc_data))
    payment.receiver.change_status(StatusObject(Status.soft_match))
    assert State.from_payment_object(payment), State.RSOFT

    bcm = processor.business_context()
    bcm.is_recipient.side_effect = [False]
    bcm.get_additional_kyc.side_effect = additional_kyc_data

    new_payment = processor.payment_process(payment)
    assert State.from_payment_object(new_payment), State.SSOFTSEND

def test_payment_process_SSOFTSEND_receiver_provide_kyc_and_signature(payment, processor, kyc_data, signature, additional_kyc_data):
    payment.sender.change_status(StatusObject(Status.needs_kyc_data))
    payment.sender.add_additional_kyc_data(additional_kyc_data)
    payment.receiver.change_status(StatusObject(Status.soft_match))
    assert State.from_payment_object(payment), State.SSOFTSEND

    bcm = processor.business_context()
    bcm.is_recipient.side_effect = [True]
    bcm.get_extended_kyc.side_effect = [kyc_data]
    bcm.get_recipient_signature.side_effect = [signature]
    bcm.evaluate_kyc.side_effect = [KYCResult.PASS]

    new_payment = processor.payment_process(payment)
    assert State.from_payment_object(new_payment), State.RSEND

def test_payment_process_SSOFTSEND_receiver_abort(payment, processor, kyc_data, signature, additional_kyc_data):
    payment.sender.change_status(StatusObject(Status.needs_kyc_data))
    payment.sender.add_additional_kyc_data(additional_kyc_data)
    payment.receiver.change_status(StatusObject(Status.soft_match))
    assert State.from_payment_object(payment), State.SSOFTSEND

    bcm = processor.business_context()
    bcm.is_recipient.side_effect = [True]
    bcm.evaluate_kyc.side_effect = [KYCResult.FAIL]

    new_payment = processor.payment_process(payment)
    assert State.from_payment_object(new_payment), State.RABORT

def test_payment_process_SSOFTSEND_receiver_abort_on_second_softmatch(payment, processor, kyc_data, signature, additional_kyc_data):
    payment.sender.change_status(StatusObject(Status.needs_kyc_data))
    payment.sender.add_additional_kyc_data(additional_kyc_data)
    payment.receiver.change_status(StatusObject(Status.soft_match))
    assert State.from_payment_object(payment), State.SSOFTSEND

    bcm = processor.business_context()
    bcm.is_recipient.side_effect = [True]
    bcm.evaluate_kyc.side_effect = [KYCResult.SOFT_MATCH]

    new_payment = processor.payment_process(payment)
    assert State.from_payment_object(new_payment), State.RABORT

def test_payment_process_SSOFT_receiver_provide_additional_kyc_data_without_RSOFT(payment, processor, kyc_data, signature, additional_kyc_data):
    payment.sender.change_status(StatusObject(Status.soft_match))
    payment.receiver.change_status(StatusObject(Status.ready_for_settlement))
    assert State.from_payment_object(payment), State.SSOFT

    bcm = processor.business_context()
    bcm.is_recipient.side_effect = [True]
    bcm.get_additional_kyc.side_effect = additional_kyc_data

    new_payment = processor.payment_process(payment)
    assert State.from_payment_object(new_payment), State.RSOFTSEND


def test_payment_process_SSOFT_receiver_provide_additional_kyc_data_after_RSOFT(payment, processor, kyc_data, signature, additional_kyc_data):
    payment.sender.change_status(StatusObject(Status.soft_match))
    payment.sender.add_additional_kyc_data(additional_kyc_data)
    payment.receiver.change_status(StatusObject(Status.ready_for_settlement))
    assert State.from_payment_object(payment), State.SSOFT

    bcm = processor.business_context()
    bcm.is_recipient.side_effect = [True]
    bcm.get_additional_kyc.side_effect = additional_kyc_data

    new_payment = processor.payment_process(payment)
    assert State.from_payment_object(new_payment), State.RSOFTSEND


def test_payment_process_RSOFTSEND_sender_ready_without_RSOFT(payment, processor, kyc_data, signature, additional_kyc_data):
    payment.sender.change_status(StatusObject(Status.soft_match))
    payment.receiver.change_status(StatusObject(Status.ready_for_settlement))
    payment.receiver.add_additional_kyc_data(additional_kyc_data)
    assert State.from_payment_object(payment), State.SSOFT

    bcm = processor.business_context()
    bcm.is_recipient.side_effect = [False]
    bcm.evaluate_kyc.side_effect = [KYCResult.PASS]
    bcm.sender_ready_to_settle.side_effect = [(True, "")]

    new_payment = processor.payment_process(payment)
    assert State.from_payment_object(new_payment), State.RSOFTSEND

def test_payment_process_RSOFTSEND_sender_ready_after_RSOFT(payment, processor, kyc_data, signature, additional_kyc_data):
    payment.sender.change_status(StatusObject(Status.soft_match))
    payment.sender.add_additional_kyc_data(additional_kyc_data)
    payment.receiver.change_status(StatusObject(Status.ready_for_settlement))
    payment.receiver.add_additional_kyc_data(additional_kyc_data)
    assert State.from_payment_object(payment), State.SSOFT

    bcm = processor.business_context()
    bcm.is_recipient.side_effect = [False]
    bcm.evaluate_kyc.side_effect = [KYCResult.PASS]
    bcm.sender_ready_to_settle.side_effect = [(True, "")]

    new_payment = processor.payment_process(payment)
    assert State.from_payment_object(new_payment), State.RSOFTSEND


def test_payment_process_RSOFTSEND_sender_abort_due_to_no_siganture(payment, processor, kyc_data, signature, additional_kyc_data):
    payment.sender.change_status(StatusObject(Status.soft_match))
    payment.receiver.change_status(StatusObject(Status.ready_for_settlement))
    payment.receiver.add_additional_kyc_data(additional_kyc_data)
    assert State.from_payment_object(payment), State.SSOFT

    bcm = processor.business_context()
    bcm.is_recipient.side_effect = [False]
    bcm.evaluate_kyc.side_effect = [KYCResult.PASS]
    bcm.sender_ready_to_settle.side_effect = [(False, "no signture provided")]

    new_payment = processor.payment_process(payment)
    assert State.from_payment_object(new_payment), State.SABORT

def test_payment_process_RSOFTSEND_sender_abort_after_second_softmatch(payment, processor, kyc_data, signature, additional_kyc_data):
    payment.sender.change_status(StatusObject(Status.soft_match))
    payment.receiver.change_status(StatusObject(Status.ready_for_settlement))
    payment.receiver.add_additional_kyc_data(additional_kyc_data)
    assert State.from_payment_object(payment), State.SSOFT

    bcm = processor.business_context()
    bcm.is_recipient.side_effect = [False]
    bcm.get_recipient_signature.side_effect = [signature]
    bcm.evaluate_kyc.side_effect = [KYCResult.SOFT_MATCH]

    new_payment = processor.payment_process(payment)
    assert State.from_payment_object(new_payment), State.SABORT


def test_payment_process_RSOFTSEND_sender_abort(payment, processor, kyc_data, signature, additional_kyc_data):
    payment.sender.change_status(StatusObject(Status.soft_match))
    payment.receiver.change_status(StatusObject(Status.ready_for_settlement))
    payment.receiver.add_additional_kyc_data(additional_kyc_data)
    assert State.from_payment_object(payment), State.SSOFT

    bcm = processor.business_context()
    bcm.is_recipient.side_effect = [False]
    bcm.get_recipient_signature.side_effect = [signature]
    bcm.evaluate_kyc.side_effect = [KYCResult.FAIL]

    new_payment = processor.payment_process(payment)
    assert State.from_payment_object(new_payment), State.SABORT


def test_payment_process_READY(payment, processor, kyc_data, signature, additional_kyc_data):
    payment.sender.change_status(StatusObject(Status.ready_for_settlement))
    payment.receiver.change_status(StatusObject(Status.ready_for_settlement))
    assert State.from_payment_object(payment), State.READY

    bcm = processor.business_context()
    bcm.is_recipient.side_effect = [False]
    new_payment = processor.payment_process(payment)

    assert State.from_payment_object(new_payment), State.READY
    assert not new_payment.has_changed()


def test_payment_process_RABORT(payment, processor, kyc_data, signature, additional_kyc_data):
    payment.sender.change_status(StatusObject(Status.needs_kyc_data))
    payment.receiver.change_status(StatusObject(Status.abort, "", ""))
    assert State.from_payment_object(payment), State.RABORT

    bcm = processor.business_context()
    bcm.is_recipient.side_effect = [False]

    new_payment = processor.payment_process(payment)

    assert State.from_payment_object(new_payment), State.RABORT
    assert not new_payment.has_changed()


def test_payment_process_SABORT(payment, processor, kyc_data, signature, additional_kyc_data):
    payment.sender.change_status(StatusObject(Status.abort, "", ""))
    payment.receiver.change_status(StatusObject(Status.ready_for_settlement))

    assert State.from_payment_object(payment), State.SABORT

    bcm = processor.business_context()
    bcm.is_recipient.side_effect = [False]

    new_payment = processor.payment_process(payment)

    assert State.from_payment_object(new_payment), State.SABORT
    assert not new_payment.has_changed()


def test_process_command_success_no_proc(payment, loop, db):
    store = StorableFactory(db)

    my_addr = LibraAddress.from_bytes("lbr", b'B'*16)
    other_addr = LibraAddress.from_bytes("lbr", b'A'*16)
    bcm = TestBusinessContext(my_addr)
    processor = PaymentProcessor(bcm, store, loop)

    net = AsyncMock(Aionet)
    processor.set_network(net)

    cmd = PaymentCommand(payment)
    cmd.set_origin(my_addr)

    # No obligation means no processing
    coro = processor.process_command_success_async(other_addr, cmd, seq=10)
    _ = loop.run_until_complete(coro)

def test_process_command_success_vanilla(payment, loop, db):
    store = StorableFactory(db)

    my_addr = LibraAddress.from_bytes("lbr", b'B'*16)
    other_addr = LibraAddress.from_bytes("lbr", b'A'*16)
    bcm = TestBusinessContext(my_addr)
    processor = PaymentProcessor(bcm, store, loop)

    net = AsyncMock(Aionet)
    processor.set_network(net)

    cmd = PaymentCommand(payment)
    cmd.set_origin(other_addr)

    # No obligation means no processing
    coro = processor.process_command_success_async(other_addr, cmd, seq=10)
    _ = loop.run_until_complete(coro)
    print(f"@@@@@@@@@@@@@ method calls: {net.method_calls}")

    assert [call[0] for call in net.method_calls] == [
        'sequence_command', 'send_request']

async def test_process_command_happy_path(payment, loop, db):
    store = StorableFactory(db)

    my_addr = LibraAddress.from_bytes("lbr", b'B'*16)
    other_addr = LibraAddress.from_bytes("lbr", b'A'*16)
    my_bcm = TestBusinessContext(my_addr)
    other_bcm = TestBusinessContext(other_addr)
    # Use the same store/DB backend
    my_processor = PaymentProcessor(my_bcm, store, loop)
    other_processor = PaymentProcessor(other_bcm, store, loop)
    net = AsyncMock(Aionet)
    my_processor.set_network(net)
    other_processor.set_network(net)

    other_cmd = PaymentCommand(payment)
    other_cmd.set_origin(other_addr)

    # me: process success command
    assert len(my_processor.object_store) == 0
    fut = my_processor.process_command(other_addr, other_cmd, other_cmd.get_request_cid(), True)

    assert len(my_processor.object_store) == 1
    other_cmd_new_vers = list(other_cmd.get_new_object_versions())
    assert len(other_cmd_new_vers) == 1
    assert my_processor.object_store[other_cmd_new_vers[0]] == payment

    assert my_processor.get_latest_payment_by_ref_id(payment.reference_id) == payment
    await fut

    # Make some differences, and test that commands are isolated per VASPs
    payment2 = copy.deepcopy(payment)
    payment2.update({
        'original_payment_reference_id': payment.reference_id
    })

    my_cmd = PaymentCommand(payment2)
    my_cmd.set_origin(my_addr)
    # other: process success command
    assert len(other_processor.object_store) == 0
    fut = other_processor.process_command(other_addr, my_cmd, my_cmd.get_request_cid(), True)

    assert len(other_processor.object_store) == 1
    my_cmd_new_vers = list(my_cmd.get_new_object_versions())
    assert len(my_cmd_new_vers) == 1

    # Even though payment and payment2 have the same version id and share
    # the db backend, they can distinguish the payments
    assert other_processor.object_store[my_cmd_new_vers[0]] == payment2
    assert my_processor.object_store[other_cmd_new_vers[0]] != payment2
    assert my_processor.object_store[other_cmd_new_vers[0]] == payment

    assert other_processor.get_latest_payment_by_ref_id(payment2.reference_id) == payment2
    await fut
