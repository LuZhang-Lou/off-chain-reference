# Copyright (c) The Libra Core Contributors
# SPDX-License-Identifier: Apache-2.0

from .utils import get_unique_string, JSONSerializable, JSONFlag
from copy import deepcopy
import json


# Generic interface to a shared object
class SharedObject(JSONSerializable):
    """ Subclasses of Shared Objects define instances that are shared between
    VASPs. All shared objects must be JSONSerializable.
    """

    def get_json_data_dict(self, flag, update_dict=None):
        ''' Override JSONSerializable. '''
        if update_dict is None:
            update_dict = {}

        self.add_object_type(update_dict)
        return update_dict

    @classmethod
    def from_json_data_dict(cls, data, flag, self=None):
        ''' Override JSONSerializable. '''
        if self is None:
            self = cls.__new__(cls)
        return self
