from typing import overload, Literal
from . import ws2_32 as ws2_32
from . import oleaut32 as oleaut32
from ._generated import oleaut32 as _gen_oleaut32, ws2_32 as _gen_ws2_32

ords: _ORDS_DICT = ...

class _ORDS_DICT:
    @overload
    def __getitem__(
        self, key: Literal[b"ws2_32.dll"]
    ) -> _gen_ws2_32.ORD_NAMES_DICT: ...
    @overload
    def __getitem__(
        self, key: Literal[b"wsock32.dll"]
    ) -> _gen_ws2_32.ORD_NAMES_DICT: ...
    @overload
    def __getitem__(
        self, key: Literal[b"oleaut32.dll"]
    ) -> _gen_oleaut32.ORD_NAMES_DICT: ...

def formatOrdString(ord_val: bytes) -> bytes: ...
@overload
def ordLookup(
    libname: Literal[b"ws2_32.dll", b"wsock23.dll"],
    ord_val: _gen_ws2_32.ORD_NAMES_DICT_VALUES,
    make_name: bool = ...,
) -> bytes: ...
@overload
def ordLookup(
    libname: Literal[b"oleaut32.dll"],
    ord_val: _gen_oleaut32.ORD_NAMES_DICT_VALUES,
    make_name: bool = ...,
) -> bytes: ...
@overload
def ordLookup(
    libname: Literal[b"ws2_32.dll", b"wsock23.dll", b"oleaut32.dll"],
    ord_val: bytes,
    make_name: Literal[True],
) -> bytes: ...
@overload
def ordLookup(
    libname: bytes, ord_val: bytes, make_name: bool = ...
) -> bytes | None: ...
