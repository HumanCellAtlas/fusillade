from collections import namedtuple
from enum import Enum, auto


class UpdateActions(Enum):
    CREATE_OR_UPDATE = auto()
    DELETE = auto()


obj_type_path = dict(
    group='/group/',
    index='/index/',
    user='/user/',
    policy='/policy/',
    role='/role/',
    resource='/resource/'
)


class ValueTypes(Enum):
    StringValue = auto()
    BinaryValue = auto()
    BooleanValue = auto()
    NumberValue = auto()
    DatetimeValue = auto()


class ConsistencyLevel(Enum):
    """
    Use by clouddirectory for read and write function to control the consistency of responses from the directory.
    See https://docs.aws.amazon.com/clouddirectory/latest/developerguide/directory_objects_consistency_levels.html
    """
    SERIALIZABLE = auto()
    EVENTUAL = auto()


class UpdateObjectParams(namedtuple("UpdateObjectParams", ['facet', 'attribute', 'value_type', 'value', 'action'])):
    pass