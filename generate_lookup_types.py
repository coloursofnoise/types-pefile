#!/usr/bin/env python

"""Generate accurate type stubs for pefile lookup dicts.

Parsing the AST allows for automatically retrieving two_way_dict lookups based
on what variables were initialized with a call to `two_way_dict`.

This also allows for more accurate numeric literals, since the way the value is
formatted in the source is not preserved at runtime. If we also retrieve the
dictionary that was passed to the `two_way_dict` call, we can use the line and
column information in the AST to extract the source for each constant and use
that in the generated type stub. We can also use these string constants when
constructing the NAMES and VALUES Literal unions.
"""

import os
from typing import IO, Iterator, Any
import pefile
import ast


def find_source(code_lines: list[str], node: ast.expr):
    return code_lines[node.lineno - 1][node.col_offset : node.end_col_offset]


def format_value(val: Any, int_lookup: dict[int, str] | None = None):
    """Format a value to be used as a `Literal` type hint.

    :param val: Value to be formatted.
    :param hex_lookup: A lookup table for the `Literal` representation of an `int`.
    This allows for representing numeric literals accurately, as this information is
    not preserved after parsing.
    """
    int_lookup = int_lookup or dict()

    if isinstance(val, str):
        return f'Literal["{val}"]'
    if isinstance(val, bytes):
        val = val.replace(b"'", b'"')
        return f"Literal[{val}]"
    if isinstance(val, int):
        return f"Literal[{int_lookup.get(val, val)}]"
    if isinstance(val, (tuple, list)):
        return "tuple[" + ",".join([format_value(v, int_lookup) for v in val]) + "]"
    return repr(val)


def is_hex(val: str):
    """Attempt to determine whether a `string` is a hexadecimal literal."""
    try:
        int(val, 16)
        return val.startswith("0x")
    except ValueError:
        return False


def maybe_int(val: str):
    """Attempt to parse a `string` as an `int`.
    If parsing fails, the value is returned unchanged.
    """
    try:
        return int(val)
    except ValueError:
        return val


def write_header(file):
    file.write(
        f"""
#fmt: off
\"\"\"
THIS FILE WAS AUTOMATICALLY GENERATED BASED ON pefile {pefile.__version__}
\"\"\"

from typing import Literal, overload, TypeVar

_K = TypeVar("_K")
_V = TypeVar("_V")

class _NAME_LOOKUP(dict[_K | _V, _V | _K]):
    @overload
    def __getitem__(self, key: _K) -> _V: ...
    @overload
    def __getitem__(self, key: _V) -> _K: ...
    @overload
    def __getitem__(self, key: _K | _V) -> _K | _V: ...


"""
    )


def write_dict(
    file: IO[str],
    classname,
    dict_types: tuple[type, type],
    items: Iterator[tuple[str, str]],
):
    type_1, type_2 = (t.__qualname__ for t in dict_types)
    file.write(f"class {classname}(_NAME_LOOKUP[{type_1}, {type_2}]):")
    file.writelines(
        (
            f"""
    @overload
    def __getitem__(self, key: {arg}) -> {ret}:...
"""
            for arg, ret in items
        )
    )


def write_literals(file, classname, values):
    values_str = "\n".join(f"    {val}," for val in values)
    file.write(
        f"""{classname} = Literal[
{values_str}
]
"""
    )


if __name__ == "__main__":
    with open(pefile.__file__) as file:
        code = file.read()
    code_lines = code.splitlines()
    tree = ast.parse(code)

    # find all top-level assignments that use the result from a call to `two_way_dict`
    assignments = [node for node in tree.body if isinstance(node, ast.Assign)]
    two_way_dicts = [
        a
        for a in assignments
        if isinstance(a.value, ast.Call)
        and isinstance(a.value.func, ast.Name)
        and a.value.func.id == pefile.two_way_dict.__name__
    ]
    lookup_tables: list[tuple[str, ast.List]] = list()
    for assign in two_way_dicts:
        # find the names of the variables that were assigned to
        target_names = (
            target.id for target in assign.targets if isinstance(target, ast.Name)
        )

        # find the AST node that should correspond to the argument to `two_way_dict`
        assert isinstance(assign.value, ast.Call)
        arg = assign.value.args[0]
        assert isinstance(arg, ast.Name)
        source_list_name = arg.id
        source_list = next(
            a.value
            for a in assignments
            if isinstance(a.value, ast.List)
            for t in a.targets
            if isinstance(t, ast.Name) and t.id == source_list_name
        )
        lookup_tables.extend(((name, source_list) for name in target_names))

    working_dir = os.path.dirname(__file__)
    generated_dir = os.path.join(working_dir, "pefile-stubs", "_generated")
    os.makedirs(generated_dir, exist_ok=True)

    with open(os.path.join(generated_dir, "pefile_lookup.pyi"), "w") as file:
        write_header(file)

        for name, source in lookup_tables:
            # extract the source code for elements in the source list
            source_items = [e for e in source.elts if isinstance(e, ast.Tuple)]
            constants = [
                tuple((find_source(code_lines, c) for c in e.elts))
                for e in source_items
            ]

            hex_lookup = {int(c, 16): c for t in constants for c in t if is_hex(c)}
            items = (
                (format_value(key, hex_lookup), format_value(val, hex_lookup))
                for key, val in getattr(pefile, name).items()
            )
            write_dict(file, f"{name}_DICT", (int, str), items)

            all_keys, all_values = (
                sorted(set(const_list), key=maybe_int) for const_list in zip(*constants)
            )
            write_literals(file, f"{name.upper()}_DICT_NAMES", all_keys)
            write_literals(file, f"{name.upper()}_DICT_VALUES", all_values)

    for module in [pefile.ordlookup.oleaut32, pefile.ordlookup.ws2_32]:
        # take only the last portion of the module name
        module_name = module.__name__.split(".")[-1]
        with open(os.path.join(generated_dir, module_name + ".pyi"), "w") as file:
            write_header(file)
            # parsing the module source is not required here because there are no
            # special numeric literals.
            ord_dict = getattr(module, "ord_names")
            items = (
                (format_value(key), format_value(val)) for key, val in ord_dict.items()
            )
            write_dict(file, "ORD_NAMES_DICT", (int, bytes), items)

            write_literals(file, "ORD_NAMES_DICT_VALUES", ord_dict.keys())
            write_literals(file, "ORD_NAMES_DICT_NAMES", ord_dict.values())
