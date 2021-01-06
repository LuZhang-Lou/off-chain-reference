# Copyright (c) The Libra Core Contributors
# SPDX-License-Identifier: Apache-2.0

""" The Payment object status is defined by the status of both actors,
    senders and receivers, namely the tuple (sender_status, recipient_status).
    An actor status may have the following values:

V0 States
---------

    * none  -- denotes the status of an object that does not exist
      for the payment recipient.
    * needs_kyc_data -- requires the other VASP to provide KYC data.
    * soft_match -- indicates that the actor requires additional KYC information
      to disambiguate the individual involved in the payment.
    * ready_for_settlement -- signals that the party is ready to settle
      the transaction.
    * abort - signals that the transactions is to be aborted.

"""

from __future__ import annotations
from enum import Enum
import typing


class InvalidStateException(Exception):
    pass


class KYCResult(Enum):
    PASS = "pass"
    FAIL = "fail"
    SOFT_MATCH = "soft_match"


class Status(Enum):
    none = 'none'

    needs_kyc_data = 'needs_kyc_data'

    soft_match = 'soft_match'

    ready_for_settlement = 'ready_for_settlement'

    abort = 'abort'

    def __str__(self):
        return self.name

    def __repr__(self):
        return self.name

class State(Enum):
    # basic
    SINIT = "sinit"  # (need_kyc_data, none, _, _)
    RSEND = "rsend"  # (need_kyc_data, ready_for_settlement, *, _)
    RABORT = "rabort"  # (need_kyc_data, abort, *, *)
    SABORT = "sabort" # (abort, ready_for_settlement, *, *)
    READY = "ready"  # (ready_for_settlement, ready_for_settlement, *, *)

    # soft match
    RSOFT = "rsoft"  # (need_kyc_data, soft_match, _, _)
    SSOFTSEND = " ssoftsend"  # (need_kyc_data, soft_match, is-provided, _)
    SSOFT = "ssoft"  # (soft_match, ready_for_settlement, *, _)
    RSOFTSEND = "rsoftsend"  # (soft_match, ready_for_settlement, *, is-provided)

    @staticmethod
    def from_payment_object(payment: "PaymentObject") -> State:
        sender_status = payment.sender.status.as_status()
        sender_additional_kyc = payment.sender.get_additional_kyc_data()
        receiver_status = payment.receiver.status.as_status()
        receiver_additional_kyc = payment.receiver.get_additional_kyc_data()
        return State.from_status(
            sender_status,
            receiver_status,
            sender_additional_kyc,
            receiver_additional_kyc,
        )

    @staticmethod
    def from_status(
        sender_status: Status,
        receiver_status: Status,
        sender_additional_kyc: typing.Optional[str] = None,
        receiver_additional_kyc: typing.Optional[str] = None,
    ) -> State:
        """
        Raise InvalidStateException upon wrong state combination
        """
        if (
            sender_status == Status.needs_kyc_data
            and receiver_status == Status.none
            and sender_additional_kyc is None
            and receiver_additional_kyc is None
        ):
            return State.SINIT

        if (
            sender_status == Status.needs_kyc_data
            and receiver_status == Status.ready_for_settlement
            and receiver_additional_kyc is None
        ):
            return State.RSEND

        if (
            sender_status == Status.needs_kyc_data
            and receiver_status == Status.abort
            and receiver_additional_kyc is None
        ):
            return State.RABORT

        if (
            sender_status == Status.abort
            and receiver_status == Status.ready_for_settlement
        ):
            return State.SABORT

        if (
            sender_status == Status.ready_for_settlement
            and receiver_status == Status.ready_for_settlement
        ):
            return State.READY

        if (
            sender_status == Status.needs_kyc_data
            and receiver_status == Status.soft_match
            and sender_additional_kyc is None
            and receiver_additional_kyc is None
        ):
            return State.RSOFT

        if (
            sender_status == Status.needs_kyc_data
            and receiver_status == Status.soft_match
            and sender_additional_kyc is not None
            and receiver_additional_kyc is None
        ):
            return State.SSOFTSEND

        if (
            sender_status == Status.soft_match
            and receiver_status == Status.ready_for_settlement
            and receiver_additional_kyc is None
        ):
            return State.SSOFT

        if (
            sender_status == Status.soft_match
            and receiver_status == Status.ready_for_settlement
            and receiver_additional_kyc is not None
        ):
            return State.RSOFTSEND

        raise InvalidStateException(
            f"sender_status: {sender_status}, "
            f"receiver_status: {receiver_status}, "
            f"sender_additional_kyc: {sender_additional_kyc}, "
            f"receiver_additional_kyc: {receiver_additional_kyc}, "
        )
