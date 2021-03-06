# Copyright (c) The Libra Core Contributors
# SPDX-License-Identifier: Apache-2.0

from ..protocol_command import ProtocolCommand
from ..utils import JSONSerializable
from ..shared_object import SharedObject

@JSONSerializable.register
class SampleObject(SharedObject):
    def __init__(self, item):
        SharedObject.__init__(self)
        self.item = str(item)

@JSONSerializable.register
class SampleCommand(ProtocolCommand):
    def __init__(self, item):
        ProtocolCommand.__init__(self)
        command = SampleObject(item)
        self.command   = command
        self.always_happy = True

    def get_object(self):
        return self.command

    def item(self):
        return self.command.item

    def __eq__(self, other):
        return self.command.item == other.command.item

    def __str__(self):
        return 'CMD(%s)' % self.item()

    def get_json_data_dict(self, flag):
        data_dict = ProtocolCommand.get_json_data_dict(self, flag)
        data_dict["command"] = self.command.item
        return data_dict

    @classmethod
    def from_json_data_dict(cls, data, flag):
        ''' Construct the object from a serlialized JSON data dictionary (from json.loads). '''
        self = super().from_json_data_dict(data, flag)
        self.command = SampleObject(data['command'])
        assert type(self) == cls
        return self

    @classmethod
    def json_type(self):
        return "SampleCommand"
