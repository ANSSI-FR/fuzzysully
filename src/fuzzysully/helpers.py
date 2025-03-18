"""FuzzySully helpers module

This module provide some helpers for FuzzySully features.
"""

from copy import copy
from typing import Union
from uuid import uuid4

from fuzzowski.exception import FuzzowskiRuntimeError
from fuzzowski.mutants import Mutant
from fuzzowski.mutants import blocks, DWord, Request, BitField, primitives
from fuzzowski.mutants.blocks import Block
from fuzzowski.mutants.spike import get_name_if_not_chosen
from fuzzowski.session import Session


class BlockHelper:
    """Fuzzowski basic block helper.

    This class allows to navigate in a very convenient way in a block or any
    of its children block or primitive types.

    Given a Fuzzowski `Request` object `req` for instance, as used in a request
    callback, it is then easy to update a specific field:
    ```
    >>> _req = BlockHelper(req)
    >>> _req.get('a-body').set('channelID', b'test')
    ```
    If the child element retrieved through a call to `get()` is a block, then
    it is automatically wrapped in a `BlockHelper` object.
    """

    def __init__(self, block: Block):
        """Initialize block helper with the target root block."""
        self.__block = block

    def __getattr__(self, attr):
        """This method handles all access made to attributes that do not belong
        to the BlockHelper class and return the corresponding attribute of the
        underlying block.
        """
        if hasattr(self.__block, attr):
            return getattr(self.__block, attr)

        # Raise an AttributeError if not found
        raise AttributeError

    def has(self, name: str) -> bool:
        """Check if block has a child block named `name`."""
        # Check if name matches one of our children names
        names = map(lambda x: x.name, self.__block.stack)
        return name in names

    def get(self, name: str) -> Mutant :
        """Find a child block or primitive type from its name.

        Throws a ValueError exception if no child corresponds to the given
        name.

        Args:
            name (str): name of the block or primitive type to get

        Returns:
            Block or primitive instance if found
        """
        # Iterate over children
        for child in self.__block.stack:
            if child.name == name:
                if isinstance(child, Block):
                    return BlockHelper(child)
                return child

        # Not found, raise ValueError
        raise ValueError

    def set(self, name: str, value: Union[int, bytes]):
        """Set the value of a child mutant.

        Args:
            name (str): name of the target field to update
            value (int, bytes): value to set
        """
        # Iterate over children
        for child in self.__block.stack:
            if child.name == name:
                if isinstance(child, Mutant):
                    child._value = value
                    return
                raise ValueError

        # Not found, raise ValueError
        raise ValueError


class OPCUASession(Session):
    """OPCUA Session information holder."""

    def __init__(
        self,
        session_filename,
        sleep_time,
        new_connection_between_requests,
        transmit_full_path,
        receive_data_after_each_request,
        receive_data_after_fuzz,
        check_data_received_each_request,
        crash_threshold_request,
        crash_threshold_element,
        target,
        restarter,
        monitors,
    ):

        super().__init__(
            session_filename=session_filename,
            sleep_time=sleep_time,
            new_connection_between_requests=new_connection_between_requests,
            transmit_full_path=transmit_full_path,
            receive_data_after_each_request=receive_data_after_each_request,
            receive_data_after_fuzz=receive_data_after_fuzz,
            check_data_received_each_request=check_data_received_each_request,
            crash_threshold_request=crash_threshold_request,
            crash_threshold_element=crash_threshold_element,
            target=target,
            restarter=restarter,
            monitors=monitors,
        )

        # Variables used in callbacks
        self.id_num = None
        self.subs_id = None
        self.monitored_item_id = []
        self.time_to_fuzz = False


class ArraySize(DWord):
    """Dynamic array size field (32 bits)

    This mutant is based on `DWord` and generates all the possible values
    in a specified range that will be applied for a specific array (defined as
    a block or sub-block).
    """

    def __init__(self, name: str = None, min_size: int = 0, max_size: int = 25):
        """Defines a fuzzable array size field.

        Args:
            name (str): name of this size field
            min_size (int): minimal value for this size field
            max_size (int): maximal value for this size field
        """
        super().__init__(
            min_size, fuzzable=True, mutations=range(min_size, max_size + 1), name=name
        )


class OPCUARepeatBlock(Block):
    """OPCUA repeater block"""

    def __init__(
        self,
        name: str = None,
        request: "Request" = None,
        group: str = None,
        variable: str = None,
    ):
        """Initializes a repeat group"""
        super().__init__(name, request, group=group, encoder=None)

        self.variable = None

        # ensure the target variable_name exists.
        if variable is not None:
            if variable not in self.request.names:
                raise FuzzowskiRuntimeError(
                    f"Can't add repeater for non-existent variable: {variable}!"
                )
            self.variable = self.request.names[variable]  # Save target block to repeat

        # if a variable is specified, ensure it is an integer type.
        if self.variable and not isinstance(self.variable, BitField):
            print(self.variable)
            raise FuzzowskiRuntimeError(
                f"Attempt to bind the repeater for block {self.name} to a non-integer primitive!"
            )

        # Not disabled by default
        self._disabled = False

        # Save our initial state
        self._value = self.variable.value

        # Save our generator
        self._mutation_gen = self._mutation_generator()

        # Items override
        self._override = {}

    def set_array_item(self, index: int, name: str, value):
        """Override the value of a given field for the current request.

        Nested arrays can also be modified using this method:

        >> repeat_block.set_array_item(
           1, 'nested_repeat_block', {
            1: {
                'default_field': 0
            },
            2: {
                'default_field': 42
            }
           })

        Nested arrays values are represented as `dict`

        Args:
            index (int): index of the array item to set
            name (str): name of the item field to set
            value: value to set
        """
        if index not in self._override:
            self._override[index] = {}
        self._override[index][name] = value

    def set_array_size(self, size: int):
        """Override the current array size.

        Args:
            size (int): array size to override.
        """
        self.variable._value = size

    def size(self) -> int:
        """Retrieve the current size of this array block"""
        return self.variable.value

    def render(
        self,
        replace_node: str = None,
        replace_value: bytes = None,
        original: bool = False,
    ) -> bytes:
        """
        Step through every item on this blocks stack and render it. Subsequent
        blocks recursively render their stacks.
        """
        self._rendered = b""

        if (
            replace_node is not None
            and replace_value is not None
            and replace_node == self.name
        ):
            self._rendered = replace_value
            return self._rendered

        # Iterate over our block content
        for pos in range(self.variable.value):
            # Otherwise, render and encode as usual.
            for item in self.stack:
                # If item value needs to be overridden, duplicate and update
                # its value.
                override_item = None
                if pos in self._override:
                    if item.name in self._override[pos]:
                        # If target mutant is an instance of OPCUARepeatBlock
                        # and override value is an array, propagate the array values
                        if isinstance(item, OPCUARepeatBlock) and isinstance(
                            self._override[pos][item.name], dict
                        ):

                            # Duplicate repeat block
                            override_item = copy(item)

                            # Propagate nested array values
                            nested_values = self._override[pos][item.name]
                            for nested_pos in nested_values:
                                for nested_item in nested_values[nested_pos]:
                                    override_item.set_array_item(
                                        nested_pos,
                                        nested_item,
                                        nested_values[nested_pos][nested_item],
                                    )
                        else:
                            override_item = copy(item)
                            override_item._value = self._override[pos][item.name]

                # Override item value if requested.
                if override_item is not None:
                    self._rendered += override_item.render(
                        replace_node=replace_node,
                        replace_value=replace_value,
                        original=original,
                    )
                else:
                    self._rendered += item.render(
                        replace_node=replace_node,
                        replace_value=replace_value,
                        original=original,
                    )

        # if an encoder was attached to this block, call it.
        if self.encoder:
            self._rendered = self.encoder(self._rendered)

        return self._rendered


def _s_opcua_array_block_start(
    name: str, min_size: int, max_size: int, *args, **kwargs
):
    """
    OPCUA array block start
    """
    # generate an array size field with unique name and add it first
    uuid = uuid4()
    size_field_name = f"size-{uuid}"
    size_block = ArraySize(size_field_name, min_size, max_size)
    blocks.CURRENT.push(size_block)

    # Then generate an OPCUARepeatBlock and add it
    block_ = OPCUARepeatBlock(
        name, blocks.CURRENT, variable=size_field_name, *args, **kwargs
    )
    blocks.CURRENT.push(block_)

    return block_


def _s_opcua_array_block_end():
    """
    Close the last opened block.
    """
    blocks.CURRENT.pop()


def s_opcua_array(
    name: str = None, group: str = None, min_size: int = 0, max_size: int = 25
):
    """Defines a custom block repeater.

    :param name: name of this array block
    :param group: Name of group to associate this block with
    :param min_size: minimal size of the array
    :param max_size: maximal size of this array
    """

    class ScopedBlock:
        """Scoped block

        This block is used to provide __enter__ and __exit__ methods
        required by the `with` statement.
        """

        def __init__(self, block_val):
            super().__init__()
            self.block = block_val

        def __enter__(self):
            """
            Setup before entering the "with" statement body
            """
            return self.block

        def __exit__(self, exc_type, value, traceback):
            """
            Cleanup after executing the "with" statement body
            """
            # Automagically close the block when exiting the "with" statement
            _s_opcua_array_block_end()

    # Return a scoped block that handles __enter__ and __exit__ methods.
    block_ = _s_opcua_array_block_start(name, min_size, max_size, group=group)
    return ScopedBlock(block_)


def s_random(
    value: bytes,
    min_length: int,
    max_length: int,
    max_mutations: int = 25,
    fuzzable: bool = True,
    step: int = None,
    name: str = None,
):
    """
    Push a bytestring onto the current block stack.

    Args:
        value:         Original value
        min_length:    Minimum length of random block
        max_length:    Maximum length of random block
        max_mutations: (Optional, def=25) Max number of mutations to make
                       before reverting to default
        fuzzable:      (Optional, def=True) Enable/disable fuzzing of this primitive
        step:          (Optional, def=None) If not null, step count between min
                        and max reps, otherwise random
        name:          (Optional, def=None) Specifying a name gives you direct
                        access to a primitive
    """

    name = get_name_if_not_chosen(name, primitives.RandomData)
    random_data = primitives.RandomData(
        value,
        min_length=min_length,
        max_length=max_length,
        max_mutations=max_mutations,
        fuzzable=fuzzable,
        step=step,
        name=name,
    )
    blocks.CURRENT.push(random_data)
