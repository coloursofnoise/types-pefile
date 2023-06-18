from contextlib import AbstractContextManager
from abc import ABC
import mmap
from types import TracebackType
from . import ordlookup as ordlookup
from typing import (
    Any,
    Callable,
    Generic,
    Literal,
    ParamSpec,
    Self,
    Sequence,
    TypeVar,
    TypedDict,
    overload,
)
from hashlib import _Hash

# TypeVars
_P = ParamSpec("_P")
_T = TypeVar("_T")
_K = TypeVar("_K")
_V = TypeVar("_V")
_Ptr = TypeVar("_Ptr", _UInt32, _UInt64)

# Primitive Types
class _char(bytes):  # c
    def __class_getitem__(cls, key: int) -> type[bytes]: ...  # [n]s

_UInt64 = int  # Q
_UInt32 = int  # I
_UInt16 = int  # H
_Int32 = int  # I
_byte = bytes  # B
_WORD = _UInt16
_DWORD = _UInt32
_QWORD = _UInt64

# Other TypeAliases
_DATA_TYPE = bytes | bytearray | mmap.mmap

__author__: str = ...
__version__: str = ...
__contact__: str = ...

long: type[int] = int

def lru_cache(
    maxsize: int = ..., typed: bool = ..., copy: bool = ...
) -> Callable[[Callable[_P, _T]], Callable[_P, _T]]: ...
@lru_cache(maxsize=2048)
def cache_adjust_FileAlignment(val: int, file_alignment: int): ...
@lru_cache(maxsize=2048)
def cache_adjust_SectionAlignment(
    val: int, section_alignment: int, file_alignment: int
): ...
def count_zeroes(data: list[int]) -> int: ...

fast_load: bool = ...
MAX_STRING_LENGTH: Literal[0x100000] = ...
MAX_IMPORT_SYMBOLS: Literal[0x2000] = ...
MAX_IMPORT_NAME_LENGTH: Literal[0x200] = ...
MAX_DLL_LENGTH: Literal[0x200] = ...
MAX_SYMBOL_NAME_LENGTH: Literal[0x200] = ...
MAX_SECTIONS: Literal[0x800] = ...
MAX_RESOURCE_ENTRIES: Literal[0x8000] = ...
MAX_RESOURCE_DEPTH: Literal[32] = ...
MAX_SYMBOL_EXPORT_COUNT: Literal[0x2000] = ...
IMAGE_DOS_SIGNATURE: Literal[0x5A4D] = ...
IMAGE_DOSZM_SIGNATURE: Literal[0x4D5A] = ...
IMAGE_NE_SIGNATURE: Literal[0x454E] = ...
IMAGE_LE_SIGNATURE: Literal[0x454C] = ...
IMAGE_LX_SIGNATURE: Literal[0x584C] = ...
IMAGE_TE_SIGNATURE: Literal[0x5A56] = ...
IMAGE_NT_SIGNATURE: Literal[0x00004550] = ...
IMAGE_NUMBEROF_DIRECTORY_ENTRIES: Literal[16] = ...
IMAGE_ORDINAL_FLAG: Literal[0x80000000] = ...
IMAGE_ORDINAL_FLAG64: Literal[0x8000000000000000] = ...
OPTIONAL_HEADER_MAGIC_PE: Literal[0x10B] = ...
OPTIONAL_HEADER_MAGIC_PE_PLUS: Literal[0x20B] = ...

class TwoWayDict(dict[_K | _V, _V | _K]):
    @overload
    def __getitem__(self, key: _K) -> _V: ...
    @overload
    def __getitem__(self, key: _V) -> _K: ...

def two_way_dict(pairs: list[tuple[_K, _V]]) -> TwoWayDict[_K, _V]: ...

_NAME_LOOKUP_LIST = list[tuple[str, bytes]]
_NAME_LOOKUP = TwoWayDict[str, bytes]

directory_entry_types: _NAME_LOOKUP_LIST = ...
DIRECTORY_ENTRY: _DIRECTORY_ENTRY_DICT = ...
_DIRECTORY_ENTRY_DICT = TypedDict(
    "_DIRECTORY_ENTRY_DICT",
    {
        "IMAGE_DIRECTORY_ENTRY_EXPORT": Literal[0],
        "IMAGE_DIRECTORY_ENTRY_IMPORT": Literal[1],
        "IMAGE_DIRECTORY_ENTRY_RESOURCE": Literal[2],
        "IMAGE_DIRECTORY_ENTRY_EXCEPTION": Literal[3],
        "IMAGE_DIRECTORY_ENTRY_SECURITY": Literal[4],
        "IMAGE_DIRECTORY_ENTRY_BASERELOC": Literal[5],
        "IMAGE_DIRECTORY_ENTRY_DEBUG": Literal[6],
        "IMAGE_DIRECTORY_ENTRY_COPYRIGHT": Literal[7],
        "IMAGE_DIRECTORY_ENTRY_GLOBALPTR": Literal[8],
        "IMAGE_DIRECTORY_ENTRY_TLS": Literal[9],
        "IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG": Literal[10],
        "IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT": Literal[11],
        "IMAGE_DIRECTORY_ENTRY_IAT": Literal[12],
        "IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT": Literal[13],
        "IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR": Literal[14],
        "IMAGE_DIRECTORY_ENTRY_RESERVED": Literal[15],
        "0": Literal["IMAGE_DIRECTORY_ENTRY_EXPORT"],
        "1": Literal["IMAGE_DIRECTORY_ENTRY_IMPORT"],
        "2": Literal["IMAGE_DIRECTORY_ENTRY_RESOURCE"],
        "3": Literal["IMAGE_DIRECTORY_ENTRY_EXCEPTION"],
        "4": Literal["IMAGE_DIRECTORY_ENTRY_SECURITY"],
        "5": Literal["IMAGE_DIRECTORY_ENTRY_BASERELOC"],
        "6": Literal["IMAGE_DIRECTORY_ENTRY_DEBUG"],
        "7": Literal["IMAGE_DIRECTORY_ENTRY_COPYRIGHT"],
        "8": Literal["IMAGE_DIRECTORY_ENTRY_GLOBALPTR"],
        "9": Literal["IMAGE_DIRECTORY_ENTRY_TLS"],
        "10": Literal["IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG"],
        "11": Literal["IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT"],
        "12": Literal["IMAGE_DIRECTORY_ENTRY_IAT"],
        "13": Literal["IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT"],
        "14": Literal["IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR"],
        "15": Literal["IMAGE_DIRECTORY_ENTRY_RESERVED"],
    },
)
_DIRECTORY_ENTRY_DICT_NAMES = Literal[
    "IMAGE_DIRECTORY_ENTRY_EXPORT",
    "IMAGE_DIRECTORY_ENTRY_IMPORT",
    "IMAGE_DIRECTORY_ENTRY_RESOURCE",
    "IMAGE_DIRECTORY_ENTRY_EXCEPTION",
    "IMAGE_DIRECTORY_ENTRY_SECURITY",
    "IMAGE_DIRECTORY_ENTRY_BASERELOC",
    "IMAGE_DIRECTORY_ENTRY_DEBUG",
    "IMAGE_DIRECTORY_ENTRY_COPYRIGHT",
    "IMAGE_DIRECTORY_ENTRY_GLOBALPTR",
    "IMAGE_DIRECTORY_ENTRY_TLS",
    "IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG",
    "IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT",
    "IMAGE_DIRECTORY_ENTRY_IAT",
    "IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT",
    "IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR",
    "IMAGE_DIRECTORY_ENTRY_RESERVED",
]
_DIRECTORY_ENTRY_DICT_VALUES = Literal[
    0,
    1,
    2,
    3,
    4,
    5,
    6,
    7,
    8,
    9,
    10,
    11,
    12,
    13,
    14,
    15,
]

image_characteristics: _NAME_LOOKUP_LIST = ...
IMAGE_CHARACTERISTICS: _IMAGE_CHARACTERISTICS_DICT = ...
_IMAGE_CHARACTERISTICS_DICT = TypedDict(
    "_IMAGE_CHARACTERISTICS_DICT",
    {
        "IMAGE_FILE_RELOCS_STRIPPED": Literal[0x0001],
        "0x0001": Literal["IMAGE_FILE_RELOCS_STRIPPED"],
        "IMAGE_FILE_EXECUTABLE_IMAGE": Literal[0x0002],
        "0x0002": Literal["IMAGE_FILE_EXECUTABLE_IMAGE"],
        "IMAGE_FILE_LINE_NUMS_STRIPPED": Literal[0x0004],
        "0x0004": Literal["IMAGE_FILE_LINE_NUMS_STRIPPED"],
        "IMAGE_FILE_LOCAL_SYMS_STRIPPED": Literal[0x0008],
        "0x0008": Literal["IMAGE_FILE_LOCAL_SYMS_STRIPPED"],
        "IMAGE_FILE_AGGRESIVE_WS_TRIM": Literal[0x0010],
        "0x0010": Literal["IMAGE_FILE_AGGRESIVE_WS_TRIM"],
        "IMAGE_FILE_LARGE_ADDRESS_AWARE": Literal[0x0020],
        "0x0020": Literal["IMAGE_FILE_LARGE_ADDRESS_AWARE"],
        "IMAGE_FILE_16BIT_MACHINE": Literal[0x0040],
        "0x0040": Literal["IMAGE_FILE_16BIT_MACHINE"],
        "IMAGE_FILE_BYTES_REVERSED_LO": Literal[0x0080],
        "0x0080": Literal["IMAGE_FILE_BYTES_REVERSED_LO"],
        "IMAGE_FILE_32BIT_MACHINE": Literal[0x0100],
        "0x0100": Literal["IMAGE_FILE_32BIT_MACHINE"],
        "IMAGE_FILE_DEBUG_STRIPPED": Literal[0x0200],
        "0x0200": Literal["IMAGE_FILE_DEBUG_STRIPPED"],
        "IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP": Literal[0x0400],
        "0x0400": Literal["IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP"],
        "IMAGE_FILE_NET_RUN_FROM_SWAP": Literal[0x0800],
        "0x0800": Literal["IMAGE_FILE_NET_RUN_FROM_SWAP"],
        "IMAGE_FILE_SYSTEM": Literal[0x1000],
        "0x1000": Literal["IMAGE_FILE_SYSTEM"],
        "IMAGE_FILE_DLL": Literal[0x2000],
        "0x2000": Literal["IMAGE_FILE_DLL"],
        "IMAGE_FILE_UP_SYSTEM_ONLY": Literal[0x4000],
        "0x4000": Literal["IMAGE_FILE_UP_SYSTEM_ONLY"],
        "IMAGE_FILE_BYTES_REVERSED_HI": Literal[0x8000],
        "0x8000": Literal["IMAGE_FILE_BYTES_REVERSED_HI"],
    },
)
_IMAGE_CHARACTERISTICS_DICT_NAMES = Literal[
    "IMAGE_FILE_RELOCS_STRIPPED",
    "IMAGE_FILE_EXECUTABLE_IMAGE",
    "IMAGE_FILE_LINE_NUMS_STRIPPED",
    "IMAGE_FILE_LOCAL_SYMS_STRIPPED",
    "IMAGE_FILE_AGGRESIVE_WS_TRIM",
    "IMAGE_FILE_LARGE_ADDRESS_AWARE",
    "IMAGE_FILE_16BIT_MACHINE",
    "IMAGE_FILE_BYTES_REVERSED_LO",
    "IMAGE_FILE_32BIT_MACHINE",
    "IMAGE_FILE_DEBUG_STRIPPED",
    "IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP",
    "IMAGE_FILE_NET_RUN_FROM_SWAP",
    "IMAGE_FILE_SYSTEM",
    "IMAGE_FILE_DLL",
    "IMAGE_FILE_UP_SYSTEM_ONLY",
    "IMAGE_FILE_BYTES_REVERSED_HI",
]
_IMAGE_CHARACTERISTICS_DICT_VALUES = Literal[
    0x0001,
    0x0002,
    0x0004,
    0x0008,
    0x0010,
    0x0020,
    0x0040,
    0x0080,
    0x0100,
    0x0200,
    0x0400,
    0x0800,
    0x1000,
    0x2000,
    0x4000,
    0x8000,
]

section_characteristics: _NAME_LOOKUP_LIST = ...
SECTION_CHARACTERISTICS: _SECTION_CHARACTERISTICS_DICT = ...
_SECTION_CHARACTERISTICS_DICT = TypedDict(
    "_SECTION_CHARACTERISTICS_DICT",
    {
        "IMAGE_SCN_TYPE_REG": Literal[0x00000000],
        "0x00000000": Literal["IMAGE_SCN_TYPE_REG"],  # reserved
        "IMAGE_SCN_TYPE_DSECT": Literal[0x00000001],
        "0x00000001": Literal["IMAGE_SCN_TYPE_DSECT"],  # reserved
        "IMAGE_SCN_TYPE_NOLOAD": Literal[0x00000002],
        "0x00000002": Literal["IMAGE_SCN_TYPE_NOLOAD"],  # reserved
        "IMAGE_SCN_TYPE_GROUP": Literal[0x00000004],
        "0x00000004": Literal["IMAGE_SCN_TYPE_GROUP"],  # reserved
        "IMAGE_SCN_TYPE_NO_PAD": Literal[0x00000008],
        "0x00000008": Literal["IMAGE_SCN_TYPE_NO_PAD"],  # reserved
        "IMAGE_SCN_TYPE_COPY": Literal[0x00000010],
        "0x00000010": Literal["IMAGE_SCN_TYPE_COPY"],  # reserved
        "IMAGE_SCN_CNT_CODE": Literal[0x00000020],
        "0x00000020": Literal["IMAGE_SCN_CNT_CODE"],
        "IMAGE_SCN_CNT_INITIALIZED_DATA": Literal[0x00000040],
        "0x00000040": Literal["IMAGE_SCN_CNT_INITIALIZED_DATA"],
        "IMAGE_SCN_CNT_UNINITIALIZED_DATA": Literal[0x00000080],
        "0x00000080": Literal["IMAGE_SCN_CNT_UNINITIALIZED_DATA"],
        "IMAGE_SCN_LNK_OTHER": Literal[0x00000100],
        "0x00000100": Literal["IMAGE_SCN_LNK_OTHER"],
        "IMAGE_SCN_LNK_INFO": Literal[0x00000200],
        "0x00000200": Literal["IMAGE_SCN_LNK_INFO"],
        "IMAGE_SCN_LNK_OVER": Literal[0x00000400],
        "0x00000400": Literal["IMAGE_SCN_LNK_OVER"],  # reserved
        "IMAGE_SCN_LNK_REMOVE": Literal[0x00000800],
        "0x00000800": Literal["IMAGE_SCN_LNK_REMOVE"],
        "IMAGE_SCN_LNK_COMDAT": Literal[0x00001000],
        "0x00001000": Literal["IMAGE_SCN_LNK_COMDAT"],
        "IMAGE_SCN_MEM_PROTECTED": Literal[0x00004000],
        # "0x00004000": Literal["IMAGE_SCN_MEM_PROTECTED"],  # obsolete, overwritten by IMAGE_SCN_NO_DEFER_SPEC_EXC
        "IMAGE_SCN_NO_DEFER_SPEC_EXC": Literal[0x00004000],
        "0x00004000": Literal["IMAGE_SCN_NO_DEFER_SPEC_EXC"],
        "IMAGE_SCN_GPREL": Literal[0x00008000],
        # "0x00008000": Literal["IMAGE_SCN_GPREL"], # overwritten by IMAGE_SCN_MEM_FARDATA
        "IMAGE_SCN_MEM_FARDATA": Literal[0x00008000],
        "0x00008000": Literal["IMAGE_SCN_MEM_FARDATA"],
        "IMAGE_SCN_MEM_SYSHEAP": Literal[0x00010000],
        "0x00010000": Literal["IMAGE_SCN_MEM_SYSHEAP"],  # obsolete
        "IMAGE_SCN_MEM_PURGEABLE": Literal[0x00020000],
        # "0x00020000": Literal["IMAGE_SCN_MEM_PURGEABLE"], # overwritten by IMAGE_SCN_MEM_16BIT
        "IMAGE_SCN_MEM_16BIT": Literal[0x00020000],
        "0x00020000": Literal["IMAGE_SCN_MEM_16BIT"],
        "IMAGE_SCN_MEM_LOCKED": Literal[0x00040000],
        "0x00040000": Literal["IMAGE_SCN_MEM_LOCKED"],
        "IMAGE_SCN_MEM_PRELOAD": Literal[0x00080000],
        "0x00080000": Literal["IMAGE_SCN_MEM_PRELOAD"],
        "IMAGE_SCN_ALIGN_1BYTES": Literal[0x00100000],
        "0x00100000": Literal["IMAGE_SCN_ALIGN_1BYTES"],
        "IMAGE_SCN_ALIGN_2BYTES": Literal[0x00200000],
        "0x00200000": Literal["IMAGE_SCN_ALIGN_2BYTES"],
        "IMAGE_SCN_ALIGN_4BYTES": Literal[0x00300000],
        "0x00300000": Literal["IMAGE_SCN_ALIGN_4BYTES"],
        "IMAGE_SCN_ALIGN_8BYTES": Literal[0x00400000],
        "0x00400000": Literal["IMAGE_SCN_ALIGN_8BYTES"],
        "IMAGE_SCN_ALIGN_16BYTES": Literal[0x00500000],
        "0x00500000": Literal["IMAGE_SCN_ALIGN_16BYTES"],  # default alignment
        "IMAGE_SCN_ALIGN_32BYTES": Literal[0x00600000],
        "0x00600000": Literal["IMAGE_SCN_ALIGN_32BYTES"],
        "IMAGE_SCN_ALIGN_64BYTES": Literal[0x00700000],
        "0x00700000": Literal["IMAGE_SCN_ALIGN_64BYTES"],
        "IMAGE_SCN_ALIGN_128BYTES": Literal[0x00800000],
        "0x00800000": Literal["IMAGE_SCN_ALIGN_128BYTES"],
        "IMAGE_SCN_ALIGN_256BYTES": Literal[0x00900000],
        "0x00900000": Literal["IMAGE_SCN_ALIGN_256BYTES"],
        "IMAGE_SCN_ALIGN_512BYTES": Literal[0x00A00000],
        "0x00A00000": Literal["IMAGE_SCN_ALIGN_512BYTES"],
        "IMAGE_SCN_ALIGN_1024BYTES": Literal[0x00B00000],
        "0x00B00000": Literal["IMAGE_SCN_ALIGN_1024BYTES"],
        "IMAGE_SCN_ALIGN_2048BYTES": Literal[0x00C00000],
        "0x00C00000": Literal["IMAGE_SCN_ALIGN_2048BYTES"],
        "IMAGE_SCN_ALIGN_4096BYTES": Literal[0x00D00000],
        "0x00D00000": Literal["IMAGE_SCN_ALIGN_4096BYTES"],
        "IMAGE_SCN_ALIGN_8192BYTES": Literal[0x00E00000],
        "0x00E00000": Literal["IMAGE_SCN_ALIGN_8192BYTES"],
        "IMAGE_SCN_ALIGN_MASK": Literal[0x00F00000],
        "0x00F00000": Literal["IMAGE_SCN_ALIGN_MASK"],
        "IMAGE_SCN_LNK_NRELOC_OVFL": Literal[0x01000000],
        "0x01000000": Literal["IMAGE_SCN_LNK_NRELOC_OVFL"],
        "IMAGE_SCN_MEM_DISCARDABLE": Literal[0x02000000],
        "0x02000000": Literal["IMAGE_SCN_MEM_DISCARDABLE"],
        "IMAGE_SCN_MEM_NOT_CACHED": Literal[0x04000000],
        "0x04000000": Literal["IMAGE_SCN_MEM_NOT_CACHED"],
        "IMAGE_SCN_MEM_NOT_PAGED": Literal[0x08000000],
        "0x08000000": Literal["IMAGE_SCN_MEM_NOT_PAGED"],
        "IMAGE_SCN_MEM_SHARED": Literal[0x10000000],
        "0x10000000": Literal["IMAGE_SCN_MEM_SHARED"],
        "IMAGE_SCN_MEM_EXECUTE": Literal[0x20000000],
        "0x20000000": Literal["IMAGE_SCN_MEM_EXECUTE"],
        "IMAGE_SCN_MEM_READ": Literal[0x40000000],
        "0x40000000": Literal["IMAGE_SCN_MEM_READ"],
        "IMAGE_SCN_MEM_WRITE": Literal[0x80000000],
        "0x80000000": Literal["IMAGE_SCN_MEM_WRITE"],
    },
)
_SECTION_CHARACTERISTICS_DICT_NAMES = Literal[
    "IMAGE_SCN_TYPE_REG",
    "IMAGE_SCN_TYPE_DSECT",
    "IMAGE_SCN_TYPE_NOLOAD",
    "IMAGE_SCN_TYPE_GROUP",
    "IMAGE_SCN_TYPE_NO_PAD",
    "IMAGE_SCN_TYPE_COPY",
    "IMAGE_SCN_CNT_CODE",
    "IMAGE_SCN_CNT_INITIALIZED_DATA",
    "IMAGE_SCN_CNT_UNINITIALIZED_DATA",
    "IMAGE_SCN_LNK_OTHER",
    "IMAGE_SCN_LNK_INFO",
    "IMAGE_SCN_LNK_OVER",
    "IMAGE_SCN_LNK_REMOVE",
    "IMAGE_SCN_LNK_COMDAT",
    "IMAGE_SCN_MEM_PROTECTED",
    "IMAGE_SCN_NO_DEFER_SPEC_EXC",
    "IMAGE_SCN_GPREL",
    "IMAGE_SCN_MEM_FARDATA",
    "IMAGE_SCN_MEM_SYSHEAP",
    "IMAGE_SCN_MEM_PURGEABLE",
    "IMAGE_SCN_MEM_16BIT",
    "IMAGE_SCN_MEM_LOCKED",
    "IMAGE_SCN_MEM_PRELOAD",
    "IMAGE_SCN_ALIGN_1BYTES",
    "IMAGE_SCN_ALIGN_2BYTES",
    "IMAGE_SCN_ALIGN_4BYTES",
    "IMAGE_SCN_ALIGN_8BYTES",
    "IMAGE_SCN_ALIGN_16BYTES",
    "IMAGE_SCN_ALIGN_32BYTES",
    "IMAGE_SCN_ALIGN_64BYTES",
    "IMAGE_SCN_ALIGN_128BYTES",
    "IMAGE_SCN_ALIGN_256BYTES",
    "IMAGE_SCN_ALIGN_512BYTES",
    "IMAGE_SCN_ALIGN_1024BYTES",
    "IMAGE_SCN_ALIGN_2048BYTES",
    "IMAGE_SCN_ALIGN_4096BYTES",
    "IMAGE_SCN_ALIGN_8192BYTES",
    "IMAGE_SCN_ALIGN_MASK",
    "IMAGE_SCN_LNK_NRELOC_OVFL",
    "IMAGE_SCN_MEM_DISCARDABLE",
    "IMAGE_SCN_MEM_NOT_CACHED",
    "IMAGE_SCN_MEM_NOT_PAGED",
    "IMAGE_SCN_MEM_SHARED",
    "IMAGE_SCN_MEM_EXECUTE",
    "IMAGE_SCN_MEM_READ",
    "IMAGE_SCN_MEM_WRITE",
]
_SECTION_CHARACTERISTICS_DICT_VALUES = Literal[
    0x00000000,
    0x00000001,
    0x00000002,
    0x00000004,
    0x00000008,
    0x00000010,
    0x00000020,
    0x00000040,
    0x00000080,
    0x00000100,
    0x00000200,
    0x00000400,
    0x00000800,
    0x00001000,
    0x00004000,
    0x00008000,
    0x00010000,
    0x00020000,
    0x00040000,
    0x00080000,
    0x00100000,
    0x00200000,
    0x00300000,
    0x00400000,
    0x00500000,
    0x00600000,
    0x00700000,
    0x00800000,
    0x00900000,
    0x00A00000,
    0x00B00000,
    0x00C00000,
    0x00D00000,
    0x00E00000,
    0x00F00000,
    0x01000000,
    0x02000000,
    0x04000000,
    0x08000000,
    0x10000000,
    0x20000000,
    0x40000000,
    0x80000000,
]

debug_types: _NAME_LOOKUP_LIST = ...
DEBUG_TYPE: _DEBUG_TYPE_DICT = ...
_DEBUG_TYPE_DICT = TypedDict(
    "_DEBUG_TYPE_DICT",
    {
        "IMAGE_DEBUG_TYPE_UNKNOWN": Literal[0],
        "0": Literal["IMAGE_DEBUG_TYPE_UNKNOWN"],
        "IMAGE_DEBUG_TYPE_COFF": Literal[1],
        "1": Literal["IMAGE_DEBUG_TYPE_COFF"],
        "IMAGE_DEBUG_TYPE_CODEVIEW": Literal[2],
        "2": Literal["IMAGE_DEBUG_TYPE_CODEVIEW"],
        "IMAGE_DEBUG_TYPE_FPO": Literal[3],
        "3": Literal["IMAGE_DEBUG_TYPE_FPO"],
        "IMAGE_DEBUG_TYPE_MISC": Literal[4],
        "4": Literal["IMAGE_DEBUG_TYPE_MISC"],
        "IMAGE_DEBUG_TYPE_EXCEPTION": Literal[5],
        "5": Literal["IMAGE_DEBUG_TYPE_EXCEPTION"],
        "IMAGE_DEBUG_TYPE_FIXUP": Literal[6],
        "6": Literal["IMAGE_DEBUG_TYPE_FIXUP"],
        "IMAGE_DEBUG_TYPE_OMAP_TO_SRC": Literal[7],
        "7": Literal["IMAGE_DEBUG_TYPE_OMAP_TO_SRC"],
        "IMAGE_DEBUG_TYPE_OMAP_FROM_SRC": Literal[8],
        "8": Literal["IMAGE_DEBUG_TYPE_OMAP_FROM_SRC"],
        "IMAGE_DEBUG_TYPE_BORLAND": Literal[9],
        "9": Literal["IMAGE_DEBUG_TYPE_BORLAND"],
        "IMAGE_DEBUG_TYPE_RESERVED10": Literal[10],
        "10": Literal["IMAGE_DEBUG_TYPE_RESERVED10"],
        "IMAGE_DEBUG_TYPE_CLSID": Literal[11],
        "11": Literal["IMAGE_DEBUG_TYPE_CLSID"],
        "IMAGE_DEBUG_TYPE_VC_FEATURE": Literal[12],
        "12": Literal["IMAGE_DEBUG_TYPE_VC_FEATURE"],
        "IMAGE_DEBUG_TYPE_POGO": Literal[13],
        "13": Literal["IMAGE_DEBUG_TYPE_POGO"],
        "IMAGE_DEBUG_TYPE_ILTCG": Literal[14],
        "14": Literal["IMAGE_DEBUG_TYPE_ILTCG"],
        "IMAGE_DEBUG_TYPE_MPX": Literal[15],
        "15": Literal["IMAGE_DEBUG_TYPE_MPX"],
        "IMAGE_DEBUG_TYPE_REPRO": Literal[16],
        "16": Literal["IMAGE_DEBUG_TYPE_REPRO"],
        "IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS": Literal[20],
        "20": Literal["IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS"],
    },
)
_DEBUG_TYPE_DICT_NAMES = Literal[
    "IMAGE_DEBUG_TYPE_UNKNOWN",
    "IMAGE_DEBUG_TYPE_COFF",
    "IMAGE_DEBUG_TYPE_CODEVIEW",
    "IMAGE_DEBUG_TYPE_FPO",
    "IMAGE_DEBUG_TYPE_MISC",
    "IMAGE_DEBUG_TYPE_EXCEPTION",
    "IMAGE_DEBUG_TYPE_FIXUP",
    "IMAGE_DEBUG_TYPE_OMAP_TO_SRC",
    "IMAGE_DEBUG_TYPE_OMAP_FROM_SRC",
    "IMAGE_DEBUG_TYPE_BORLAND",
    "IMAGE_DEBUG_TYPE_RESERVED10",
    "IMAGE_DEBUG_TYPE_CLSID",
    "IMAGE_DEBUG_TYPE_VC_FEATURE",
    "IMAGE_DEBUG_TYPE_POGO",
    "IMAGE_DEBUG_TYPE_ILTCG",
    "IMAGE_DEBUG_TYPE_MPX",
    "IMAGE_DEBUG_TYPE_REPRO",
    "IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS",
]
_DEBUG_TYPE_DICT_VALUES = Literal[
    0,
    1,
    2,
    3,
    4,
    5,
    6,
    7,
    8,
    9,
    10,
    11,
    12,
    13,
    14,
    15,
    16,
    20,
]

subsystem_types: _NAME_LOOKUP_LIST = ...
SUBSYSTEM_TYPE: _SUBSYSTEM_TYPE_DICT = ...
_SUBSYSTEM_TYPE_DICT = TypedDict(
    "_SUBSYSTEM_TYPE_DICT",
    {
        "IMAGE_SUBSYSTEM_UNKNOWN": Literal[0],
        "0": Literal["IMAGE_SUBSYSTEM_UNKNOWN"],
        "IMAGE_SUBSYSTEM_NATIVE": Literal[1],
        "1": Literal["IMAGE_SUBSYSTEM_NATIVE"],
        "IMAGE_SUBSYSTEM_WINDOWS_GUI": Literal[2],
        "2": Literal["IMAGE_SUBSYSTEM_WINDOWS_GUI"],
        "IMAGE_SUBSYSTEM_WINDOWS_CUI": Literal[3],
        "3": Literal["IMAGE_SUBSYSTEM_WINDOWS_CUI"],
        "IMAGE_SUBSYSTEM_OS2_CUI": Literal[5],
        "5": Literal["IMAGE_SUBSYSTEM_OS2_CUI"],
        "IMAGE_SUBSYSTEM_POSIX_CUI": Literal[7],
        "7": Literal["IMAGE_SUBSYSTEM_POSIX_CUI"],
        "IMAGE_SUBSYSTEM_NATIVE_WINDOWS": Literal[8],
        "8": Literal["IMAGE_SUBSYSTEM_NATIVE_WINDOWS"],
        "IMAGE_SUBSYSTEM_WINDOWS_CE_GUI": Literal[9],
        "9": Literal["IMAGE_SUBSYSTEM_WINDOWS_CE_GUI"],
        "IMAGE_SUBSYSTEM_EFI_APPLICATION": Literal[10],
        "10": Literal["IMAGE_SUBSYSTEM_EFI_APPLICATION"],
        "IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER": Literal[11],
        "11": Literal["IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER"],
        "IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER": Literal[12],
        "12": Literal["IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER"],
        "IMAGE_SUBSYSTEM_EFI_ROM": Literal[13],
        "13": Literal["IMAGE_SUBSYSTEM_EFI_ROM"],
        "IMAGE_SUBSYSTEM_XBOX": Literal[14],
        "14": Literal["IMAGE_SUBSYSTEM_XBOX"],
        "IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION": Literal[16],
        "16": Literal["IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION"],
    },
)
_SUBSYSTEM_TYPE_STR = Literal[
    "IMAGE_SUBSYSTEM_UNKNOWN",
    "IMAGE_SUBSYSTEM_NATIVE",
    "IMAGE_SUBSYSTEM_WINDOWS_GUI",
    "IMAGE_SUBSYSTEM_WINDOWS_CUI",
    "IMAGE_SUBSYSTEM_OS2_CUI",
    "IMAGE_SUBSYSTEM_POSIX_CUI",
    "IMAGE_SUBSYSTEM_NATIVE_WINDOWS",
    "IMAGE_SUBSYSTEM_WINDOWS_CE_GUI",
    "IMAGE_SUBSYSTEM_EFI_APPLICATION",
    "IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER",
    "IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER",
    "IMAGE_SUBSYSTEM_EFI_ROM",
    "IMAGE_SUBSYSTEM_XBOX",
    "IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION",
]
_SUBSYSTEM_TYPE_VAL = Literal[
    0,
    1,
    2,
    3,
    5,
    7,
    8,
    9,
    10,
    11,
    12,
    13,
    14,
    16,
]

machine_types: _NAME_LOOKUP_LIST = ...
MACHINE_TYPE: _MACHINE_TYPE_DICT = ...
_MACHINE_TYPE_DICT = TypedDict(
    "_MACHINE_TYPE_DICT",
    {
        "IMAGE_FILE_MACHINE_UNKNOWN": Literal[0x0],
        "0x0": Literal["IMAGE_FILE_MACHINE_UNKNOWN"],
        "IMAGE_FILE_MACHINE_I386": Literal[0x014C],
        "0x014C": Literal["IMAGE_FILE_MACHINE_I386"],
        "IMAGE_FILE_MACHINE_R3000": Literal[0x0162],
        "0x0162": Literal["IMAGE_FILE_MACHINE_R3000"],
        "IMAGE_FILE_MACHINE_R4000": Literal[0x0166],
        "0x0166": Literal["IMAGE_FILE_MACHINE_R4000"],
        "IMAGE_FILE_MACHINE_R10000": Literal[0x0168],
        "0x0168": Literal["IMAGE_FILE_MACHINE_R10000"],
        "IMAGE_FILE_MACHINE_WCEMIPSV2": Literal[0x0169],
        "0x0169": Literal["IMAGE_FILE_MACHINE_WCEMIPSV2"],
        "IMAGE_FILE_MACHINE_ALPHA": Literal[0x0184],
        "0x0184": Literal["IMAGE_FILE_MACHINE_ALPHA"],
        "IMAGE_FILE_MACHINE_SH3": Literal[0x01A2],
        "0x01A2": Literal["IMAGE_FILE_MACHINE_SH3"],
        "IMAGE_FILE_MACHINE_SH3DSP": Literal[0x01A3],
        "0x01A3": Literal["IMAGE_FILE_MACHINE_SH3DSP"],
        "IMAGE_FILE_MACHINE_SH3E": Literal[0x01A4],
        "0x01A4": Literal["IMAGE_FILE_MACHINE_SH3E"],
        "IMAGE_FILE_MACHINE_SH4": Literal[0x01A6],
        "0x01A6": Literal["IMAGE_FILE_MACHINE_SH4"],
        "IMAGE_FILE_MACHINE_SH5": Literal[0x01A8],
        "0x01A8": Literal["IMAGE_FILE_MACHINE_SH5"],
        "IMAGE_FILE_MACHINE_ARM": Literal[0x01C0],
        "0x01C0": Literal["IMAGE_FILE_MACHINE_ARM"],
        "IMAGE_FILE_MACHINE_THUMB": Literal[0x01C2],
        "0x01C2": Literal["IMAGE_FILE_MACHINE_THUMB"],
        "IMAGE_FILE_MACHINE_ARMNT": Literal[0x01C4],
        "0x01C4": Literal["IMAGE_FILE_MACHINE_ARMNT"],
        "IMAGE_FILE_MACHINE_AM33": Literal[0x01D3],
        "0x01D3": Literal["IMAGE_FILE_MACHINE_AM33"],
        "IMAGE_FILE_MACHINE_POWERPC": Literal[0x01F0],
        "0x01F0": Literal["IMAGE_FILE_MACHINE_POWERPC"],
        "IMAGE_FILE_MACHINE_POWERPCFP": Literal[0x01F1],
        "0x01F1": Literal["IMAGE_FILE_MACHINE_POWERPCFP"],
        "IMAGE_FILE_MACHINE_IA64": Literal[0x0200],
        "0x0200": Literal["IMAGE_FILE_MACHINE_IA64"],
        "IMAGE_FILE_MACHINE_MIPS16": Literal[0x0266],
        "0x0266": Literal["IMAGE_FILE_MACHINE_MIPS16"],
        "IMAGE_FILE_MACHINE_ALPHA64": Literal[0x0284],
        # "0x0284": Literal["IMAGE_FILE_MACHINE_ALPHA64"], # overwritten by IMAGE_FILE_MACHINE_AXP64
        "IMAGE_FILE_MACHINE_AXP64": Literal[0x0284],
        "0x0284": Literal["IMAGE_FILE_MACHINE_AXP64"],  # same
        "IMAGE_FILE_MACHINE_MIPSFPU": Literal[0x0366],
        "0x0366": Literal["IMAGE_FILE_MACHINE_MIPSFPU"],
        "IMAGE_FILE_MACHINE_MIPSFPU16": Literal[0x0466],
        "0x0466": Literal["IMAGE_FILE_MACHINE_MIPSFPU16"],
        "IMAGE_FILE_MACHINE_TRICORE": Literal[0x0520],
        "0x0520": Literal["IMAGE_FILE_MACHINE_TRICORE"],
        "IMAGE_FILE_MACHINE_CEF": Literal[0x0CEF],
        "0x0CEF": Literal["IMAGE_FILE_MACHINE_CEF"],
        "IMAGE_FILE_MACHINE_EBC": Literal[0x0EBC],
        "0x0EBC": Literal["IMAGE_FILE_MACHINE_EBC"],
        "IMAGE_FILE_MACHINE_RISCV32": Literal[0x5032],
        "0x5032": Literal["IMAGE_FILE_MACHINE_RISCV32"],
        "IMAGE_FILE_MACHINE_RISCV64": Literal[0x5064],
        "0x5064": Literal["IMAGE_FILE_MACHINE_RISCV64"],
        "IMAGE_FILE_MACHINE_RISCV128": Literal[0x5128],
        "0x5128": Literal["IMAGE_FILE_MACHINE_RISCV128"],
        "IMAGE_FILE_MACHINE_LOONGARCH32": Literal[0x6232],
        "0x6232": Literal["IMAGE_FILE_MACHINE_LOONGARCH32"],
        "IMAGE_FILE_MACHINE_LOONGARCH64": Literal[0x6264],
        "0x6264": Literal["IMAGE_FILE_MACHINE_LOONGARCH64"],
        "IMAGE_FILE_MACHINE_AMD64": Literal[0x8664],
        "0x8664": Literal["IMAGE_FILE_MACHINE_AMD64"],
        "IMAGE_FILE_MACHINE_M32R": Literal[0x9041],
        "0x9041": Literal["IMAGE_FILE_MACHINE_M32R"],
        "IMAGE_FILE_MACHINE_ARM64": Literal[0xAA64],
        "0xAA64": Literal["IMAGE_FILE_MACHINE_ARM64"],
        "IMAGE_FILE_MACHINE_CEE": Literal[0xC0EE],
        "0xC0EE": Literal["IMAGE_FILE_MACHINE_CEE"],
    },
)
_MACHINE_TYPE_DICT_NAMES = Literal[
    "IMAGE_FILE_MACHINE_UNKNOWN",
    "IMAGE_FILE_MACHINE_I386",
    "IMAGE_FILE_MACHINE_R3000",
    "IMAGE_FILE_MACHINE_R4000",
    "IMAGE_FILE_MACHINE_R10000",
    "IMAGE_FILE_MACHINE_WCEMIPSV2",
    "IMAGE_FILE_MACHINE_ALPHA",
    "IMAGE_FILE_MACHINE_SH3",
    "IMAGE_FILE_MACHINE_SH3DSP",
    "IMAGE_FILE_MACHINE_SH3E",
    "IMAGE_FILE_MACHINE_SH4",
    "IMAGE_FILE_MACHINE_SH5",
    "IMAGE_FILE_MACHINE_ARM",
    "IMAGE_FILE_MACHINE_THUMB",
    "IMAGE_FILE_MACHINE_ARMNT",
    "IMAGE_FILE_MACHINE_AM33",
    "IMAGE_FILE_MACHINE_POWERPC",
    "IMAGE_FILE_MACHINE_POWERPCFP",
    "IMAGE_FILE_MACHINE_IA64",
    "IMAGE_FILE_MACHINE_MIPS16",
    "IMAGE_FILE_MACHINE_ALPHA64",
    "IMAGE_FILE_MACHINE_AXP64",
    "IMAGE_FILE_MACHINE_MIPSFPU",
    "IMAGE_FILE_MACHINE_MIPSFPU16",
    "IMAGE_FILE_MACHINE_TRICORE",
    "IMAGE_FILE_MACHINE_CEF",
    "IMAGE_FILE_MACHINE_EBC",
    "IMAGE_FILE_MACHINE_RISCV32",
    "IMAGE_FILE_MACHINE_RISCV64",
    "IMAGE_FILE_MACHINE_RISCV128",
    "IMAGE_FILE_MACHINE_LOONGARCH32",
    "IMAGE_FILE_MACHINE_LOONGARCH64",
    "IMAGE_FILE_MACHINE_AMD64",
    "IMAGE_FILE_MACHINE_M32R",
    "IMAGE_FILE_MACHINE_ARM64",
    "IMAGE_FILE_MACHINE_CEE",
]
_MACHINE_TYPE_DICT_VALUES = Literal[
    0x0,
    0x014C,
    0x0162,
    0x0166,
    0x0168,
    0x0169,
    0x0184,
    0x01A2,
    0x01A3,
    0x01A4,
    0x01A6,
    0x01A8,
    0x01C0,
    0x01C2,
    0x01C4,
    0x01D3,
    0x01F0,
    0x01F1,
    0x0200,
    0x0266,
    0x0284,
    0x0366,
    0x0466,
    0x0520,
    0x0CEF,
    0x0EBC,
    0x5032,
    0x5064,
    0x5128,
    0x6232,
    0x6264,
    0x8664,
    0x9041,
    0xAA64,
    0xC0EE,
]

relocation_types: _NAME_LOOKUP_LIST = ...
RELOCATION_TYPE: _RELOCATION_TYPE_DICT = ...
_RELOCATION_TYPE_DICT = TypedDict(
    "_RELOCATION_TYPE_DICT",
    {
        "IMAGE_REL_BASED_ABSOLUTE": Literal[0],
        "0": Literal["IMAGE_REL_BASED_ABSOLUTE"],
        "IMAGE_REL_BASED_HIGH": Literal[1],
        "1": Literal["IMAGE_REL_BASED_HIGH"],
        "IMAGE_REL_BASED_LOW": Literal[2],
        "2": Literal["IMAGE_REL_BASED_LOW"],
        "IMAGE_REL_BASED_HIGHLOW": Literal[3],
        "3": Literal["IMAGE_REL_BASED_HIGHLOW"],
        "IMAGE_REL_BASED_HIGHADJ": Literal[4],
        "4": Literal["IMAGE_REL_BASED_HIGHADJ"],
        "IMAGE_REL_BASED_MIPS_JMPADDR": Literal[5],
        "5": Literal["IMAGE_REL_BASED_MIPS_JMPADDR"],
        "IMAGE_REL_BASED_SECTION": Literal[6],
        "6": Literal["IMAGE_REL_BASED_SECTION"],
        "IMAGE_REL_BASED_REL": Literal[7],
        "7": Literal["IMAGE_REL_BASED_REL"],
        "IMAGE_REL_BASED_MIPS_JMPADDR16": Literal[9],
        # "9": Literal["IMAGE_REL_BASED_MIPS_JMPADDR16"],  # overwritten by IMAGE_REL_BASED_IA64_IMM64
        "IMAGE_REL_BASED_IA64_IMM64": Literal[9],
        "9": Literal["IMAGE_REL_BASED_IA64_IMM64"],
        "IMAGE_REL_BASED_DIR64": Literal[10],
        "10": Literal["IMAGE_REL_BASED_DIR64"],
        "IMAGE_REL_BASED_HIGH3ADJ": Literal[11],
        "11": Literal["IMAGE_REL_BASED_HIGH3ADJ"],
    },
)
_RELOCATION_TYPE_DICT_NAMES = Literal[
    "IMAGE_REL_BASED_ABSOLUTE",
    "IMAGE_REL_BASED_HIGH",
    "IMAGE_REL_BASED_LOW",
    "IMAGE_REL_BASED_HIGHLOW",
    "IMAGE_REL_BASED_HIGHADJ",
    "IMAGE_REL_BASED_MIPS_JMPADDR",
    "IMAGE_REL_BASED_SECTION",
    "IMAGE_REL_BASED_REL",
    "IMAGE_REL_BASED_MIPS_JMPADDR16",
    "IMAGE_REL_BASED_IA64_IMM64",
    "IMAGE_REL_BASED_DIR64",
    "IMAGE_REL_BASED_HIGH3ADJ",
]
_RELOCATION_TYPE_DICT_VALUES = Literal[
    0,
    1,
    2,
    3,
    4,
    5,
    6,
    7,
    9,
    10,
    11,
]

dll_characteristics: _NAME_LOOKUP_LIST = ...
DLL_CHARACTERISTICS: _DLL_CHARACTERISTICS_DICT = ...
_DLL_CHARACTERISTICS_DICT = TypedDict(
    "_DLL_CHARACTERISTICS_DICT",
    {
        "IMAGE_LIBRARY_PROCESS_INIT": Literal[0x0001],
        "0x0001": Literal["IMAGE_LIBRARY_PROCESS_INIT"],  # reserved
        "IMAGE_LIBRARY_PROCESS_TERM": Literal[0x0002],
        "0x0002": Literal["IMAGE_LIBRARY_PROCESS_TERM"],  # reserved
        "IMAGE_LIBRARY_THREAD_INIT": Literal[0x0004],
        "0x0004": Literal["IMAGE_LIBRARY_THREAD_INIT"],  # reserved
        "IMAGE_LIBRARY_THREAD_TERM": Literal[0x0008],
        "0x0008": Literal["IMAGE_LIBRARY_THREAD_TERM"],  # reserved
        "IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA": Literal[0x0020],
        "0x0020": Literal["IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA"],
        "IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE": Literal[0x0040],
        "0x0040": Literal["IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE"],
        "IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY": Literal[0x0080],
        "0x0080": Literal["IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY"],
        "IMAGE_DLLCHARACTERISTICS_NX_COMPAT": Literal[0x0100],
        "0x0100": Literal["IMAGE_DLLCHARACTERISTICS_NX_COMPAT"],
        "IMAGE_DLLCHARACTERISTICS_NO_ISOLATION": Literal[0x0200],
        "0x0200": Literal["IMAGE_DLLCHARACTERISTICS_NO_ISOLATION"],
        "IMAGE_DLLCHARACTERISTICS_NO_SEH": Literal[0x0400],
        "0x0400": Literal["IMAGE_DLLCHARACTERISTICS_NO_SEH"],
        "IMAGE_DLLCHARACTERISTICS_NO_BIND": Literal[0x0800],
        "0x0800": Literal["IMAGE_DLLCHARACTERISTICS_NO_BIND"],
        "IMAGE_DLLCHARACTERISTICS_APPCONTAINER": Literal[0x1000],
        "0x1000": Literal["IMAGE_DLLCHARACTERISTICS_APPCONTAINER"],
        "IMAGE_DLLCHARACTERISTICS_WDM_DRIVER": Literal[0x2000],
        "0x2000": Literal["IMAGE_DLLCHARACTERISTICS_WDM_DRIVER"],
        "IMAGE_DLLCHARACTERISTICS_GUARD_CF": Literal[0x4000],
        "0x4000": Literal["IMAGE_DLLCHARACTERISTICS_GUARD_CF"],
        "IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE": Literal[0x8000],
        "0x8000": Literal["IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE"],
    },
)
_DLL_CHARACTERISTICS_NAMES = Literal[
    "IMAGE_LIBRARY_PROCESS_INIT",
    "IMAGE_LIBRARY_PROCESS_TERM",
    "IMAGE_LIBRARY_THREAD_INIT",
    "IMAGE_LIBRARY_THREAD_TERM",
    "IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA",
    "IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE",
    "IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY",
    "IMAGE_DLLCHARACTERISTICS_NX_COMPAT",
    "IMAGE_DLLCHARACTERISTICS_NO_ISOLATION",
    "IMAGE_DLLCHARACTERISTICS_NO_SEH",
    "IMAGE_DLLCHARACTERISTICS_NO_BIND",
    "IMAGE_DLLCHARACTERISTICS_APPCONTAINER",
    "IMAGE_DLLCHARACTERISTICS_WDM_DRIVER",
    "IMAGE_DLLCHARACTERISTICS_GUARD_CF",
    "IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE",
]
_DLL_CHARACTERISTICS_VALUES = Literal[
    0x0001,
    0x0002,
    0x0004,
    0x0008,
    0x0020,
    0x0040,
    0x0080,
    0x0100,
    0x0200,
    0x0400,
    0x0800,
    0x1000,
    0x2000,
    0x4000,
    0x8000,
]

FILE_ALIGNMENT_HARDCODED_VALUE: Literal[0x200] = ...

unwind_info_flags: _NAME_LOOKUP_LIST = ...
UNWIND_INFO_FLAGS: _UNWIND_INFO_FLAGS_DICT = ...
_UNWIND_INFO_FLAGS_DICT = TypedDict(
    "_UNWIND_INFO_FLAGS_DICT",
    {
        "UNW_FLAG_EHANDLER": Literal[0x01],
        "0x01": Literal["UNW_FLAG_EHANDLER"],
        "UNW_FLAG_UHANDLER": Literal[0x02],
        "0x02": Literal["UNW_FLAG_UHANDLER"],
        "UNW_FLAG_CHAININFO": Literal[0x04],
        "0x04": Literal["UNW_FLAG_CHAININFO"],
    },
)
_UNWIND_INFO_FLAGS_DICT_NAMES = Literal[
    "UNW_FLAG_EHANDLER",
    "UNW_FLAG_UHANDLER",
    "UNW_FLAG_CHAININFO",
]
_UNWIND_INFO_FLAGS_DICT_VALUES = Literal[
    0x01,
    0x02,
    0x04,
]

registers: _NAME_LOOKUP_LIST = ...
REGISTERS: _REGISTERS_DICT = ...
_REGISTERS_DICT = TypedDict(
    "_REGISTERS_DICT",
    {
        "RAX": Literal[0],
        "0": Literal["RAX"],
        "RCX": Literal[1],
        "1": Literal["RCX"],
        "RDX": Literal[2],
        "2": Literal["RDX"],
        "RBX": Literal[3],
        "3": Literal["RBX"],
        "RSP": Literal[4],
        "4": Literal["RSP"],
        "RBP": Literal[5],
        "5": Literal["RBP"],
        "RSI": Literal[6],
        "6": Literal["RSI"],
        "RDI": Literal[7],
        "7": Literal["RDI"],
        "R8": Literal[8],
        "8": Literal["R8"],
        "R9": Literal[9],
        "9": Literal["R9"],
        "R10": Literal[10],
        "10": Literal["R10"],
        "R11": Literal[11],
        "11": Literal["R11"],
        "R12": Literal[12],
        "12": Literal["R12"],
        "R13": Literal[13],
        "13": Literal["R13"],
        "R14": Literal[14],
        "14": Literal["R14"],
        "R15": Literal[15],
        "15": Literal["R15"],
    },
)
_REGISTERS_DICT_NAMES = Literal[
    "RAX",
    "RCX",
    "RDX",
    "RBX",
    "RSP",
    "RBP",
    "RSI",
    "RDI",
    "R8",
    "R9",
    "R10",
    "R11",
    "R12",
    "R13",
    "R14",
    "R15",
]
_REGISTERS_DICT_VALUES = Literal[
    0,
    1,
    2,
    3,
    4,
    5,
    6,
    7,
    8,
    9,
    10,
    11,
    12,
    13,
    14,
    15,
]

UWOP_PUSH_NONVOL: Literal[0] = ...
UWOP_ALLOC_LARGE: Literal[1] = ...
UWOP_ALLOC_SMALL: Literal[2] = ...
UWOP_SET_FPREG: Literal[3] = ...
UWOP_SAVE_NONVOL: Literal[4] = ...
UWOP_SAVE_NONVOL_FAR: Literal[5] = ...
UWOP_EPILOG: Literal[6] = ...
UWOP_SAVE_XMM128: Literal[8] = ...
UWOP_SAVE_XMM128_FAR: Literal[9] = ...
UWOP_PUSH_MACHFRAME: Literal[10] = ...

resource_type: _NAME_LOOKUP_LIST = ...
RESOURCE_TYPE: _RESOURCE_TYPE_DICT = ...
_RESOURCE_TYPE_DICT = TypedDict(
    "_RESOURCE_TYPE_DICT",
    {
        "RT_CURSOR": Literal[1],
        "1": Literal["RT_CURSOR"],
        "RT_BITMAP": Literal[2],
        "2": Literal["RT_BITMAP"],
        "RT_ICON": Literal[3],
        "3": Literal["RT_ICON"],
        "RT_MENU": Literal[4],
        "4": Literal["RT_MENU"],
        "RT_DIALOG": Literal[5],
        "5": Literal["RT_DIALOG"],
        "RT_STRING": Literal[6],
        "6": Literal["RT_STRING"],
        "RT_FONTDIR": Literal[7],
        "7": Literal["RT_FONTDIR"],
        "RT_FONT": Literal[8],
        "8": Literal["RT_FONT"],
        "RT_ACCELERATOR": Literal[9],
        "9": Literal["RT_ACCELERATOR"],
        "RT_RCDATA": Literal[10],
        "10": Literal["RT_RCDATA"],
        "RT_MESSAGETABLE": Literal[11],
        "11": Literal["RT_MESSAGETABLE"],
        "RT_GROUP_CURSOR": Literal[12],
        "12": Literal["RT_GROUP_CURSOR"],
        "RT_GROUP_ICON": Literal[14],
        "14": Literal["RT_GROUP_ICON"],
        "RT_VERSION": Literal[16],
        "16": Literal["RT_VERSION"],
        "RT_DLGINCLUDE": Literal[17],
        "17": Literal["RT_DLGINCLUDE"],
        "RT_PLUGPLAY": Literal[19],
        "19": Literal["RT_PLUGPLAY"],
        "RT_VXD": Literal[20],
        "20": Literal["RT_VXD"],
        "RT_ANICURSOR": Literal[21],
        "21": Literal["RT_ANICURSOR"],
        "RT_ANIICON": Literal[22],
        "22": Literal["RT_ANIICON"],
        "RT_HTML": Literal[23],
        "23": Literal["RT_HTML"],
        "RT_MANIFEST": Literal[24],
        "24": Literal["RT_MANIFEST"],
    },
)
_RESOURCE_TYPE_DICT_NAMES = Literal[
    "RT_CURSOR",
    "RT_BITMAP",
    "RT_ICON",
    "RT_MENU",
    "RT_DIALOG",
    "RT_STRING",
    "RT_FONTDIR",
    "RT_FONT",
    "RT_ACCELERATOR",
    "RT_RCDATA",
    "RT_MESSAGETABLE",
    "RT_GROUP_CURSOR",
    "RT_GROUP_ICON",
    "RT_VERSION",
    "RT_DLGINCLUDE",
    "RT_PLUGPLAY",
    "RT_VXD",
    "RT_ANICURSOR",
    "RT_ANIICON",
    "RT_HTML",
    "RT_MANIFEST",
]
_RESOURCE_TYPE_DICT_VALUES = Literal[
    1,
    2,
    3,
    4,
    5,
    6,
    7,
    8,
    9,
    10,
    11,
    12,
    14,
    16,
    17,
    19,
    20,
    21,
    22,
    23,
    24,
]

lang: _NAME_LOOKUP_LIST = ...
LANG: _LANG_DICT = ...
_LANG_DICT = TypedDict(
    "_LANG_DICT",
    {
        "LANG_NEUTRAL": Literal[0x00],
        "0x00": Literal["LANG_NEUTRAL"],
        "LANG_INVARIANT": Literal[0x7F],
        "0x7F": Literal["LANG_INVARIANT"],
        "LANG_AFRIKAANS": Literal[0x36],
        "0x36": Literal["LANG_AFRIKAANS"],
        "LANG_ALBANIAN": Literal[0x1C],
        "0x1C": Literal["LANG_ALBANIAN"],
        "LANG_ARABIC": Literal[0x01],
        "0x01": Literal["LANG_ARABIC"],
        "LANG_ARMENIAN": Literal[0x2B],
        "0x2B": Literal["LANG_ARMENIAN"],
        "LANG_ASSAMESE": Literal[0x4D],
        "0x4D": Literal["LANG_ASSAMESE"],
        "LANG_AZERI": Literal[0x2C],
        "0x2C": Literal["LANG_AZERI"],
        "LANG_BASQUE": Literal[0x2D],
        "0x2D": Literal["LANG_BASQUE"],
        "LANG_BELARUSIAN": Literal[0x23],
        "0x23": Literal["LANG_BELARUSIAN"],
        "LANG_BENGALI": Literal[0x45],
        "0x45": Literal["LANG_BENGALI"],
        "LANG_BULGARIAN": Literal[0x02],
        "0x02": Literal["LANG_BULGARIAN"],
        "LANG_CATALAN": Literal[0x03],
        "0x03": Literal["LANG_CATALAN"],
        "LANG_CHINESE": Literal[0x04],
        "0x04": Literal["LANG_CHINESE"],
        "LANG_CROATIAN": Literal[0x1A],
        # "0x1A": Literal["LANG_CROATIAN"],  # overwritten by LANG_SERBIAN
        "LANG_CZECH": Literal[0x05],
        "0x05": Literal["LANG_CZECH"],
        "LANG_DANISH": Literal[0x06],
        "0x06": Literal["LANG_DANISH"],
        "LANG_DIVEHI": Literal[0x65],
        "0x65": Literal["LANG_DIVEHI"],
        "LANG_DUTCH": Literal[0x13],
        "0x13": Literal["LANG_DUTCH"],
        "LANG_ENGLISH": Literal[0x09],
        "0x09": Literal["LANG_ENGLISH"],
        "LANG_ESTONIAN": Literal[0x25],
        "0x25": Literal["LANG_ESTONIAN"],
        "LANG_FAEROESE": Literal[0x38],
        "0x38": Literal["LANG_FAEROESE"],
        "LANG_FARSI": Literal[0x29],
        "0x29": Literal["LANG_FARSI"],
        "LANG_FINNISH": Literal[0x0B],
        "0x0B": Literal["LANG_FINNISH"],
        "LANG_FRENCH": Literal[0x0C],
        "0x0C": Literal["LANG_FRENCH"],
        "LANG_GALICIAN": Literal[0x56],
        "0x56": Literal["LANG_GALICIAN"],
        "LANG_GEORGIAN": Literal[0x37],
        "0x37": Literal["LANG_GEORGIAN"],
        "LANG_GERMAN": Literal[0x07],
        "0x07": Literal["LANG_GERMAN"],
        "LANG_GREEK": Literal[0x08],
        "0x08": Literal["LANG_GREEK"],
        "LANG_GUJARATI": Literal[0x47],
        "0x47": Literal["LANG_GUJARATI"],
        "LANG_HEBREW": Literal[0x0D],
        "0x0D": Literal["LANG_HEBREW"],
        "LANG_HINDI": Literal[0x39],
        "0x39": Literal["LANG_HINDI"],
        "LANG_HUNGARIAN": Literal[0x0E],
        "0x0E": Literal["LANG_HUNGARIAN"],
        "LANG_ICELANDIC": Literal[0x0F],
        "0x0F": Literal["LANG_ICELANDIC"],
        "LANG_INDONESIAN": Literal[0x21],
        "0x21": Literal["LANG_INDONESIAN"],
        "LANG_ITALIAN": Literal[0x10],
        "0x10": Literal["LANG_ITALIAN"],
        "LANG_JAPANESE": Literal[0x11],
        "0x11": Literal["LANG_JAPANESE"],
        "LANG_KANNADA": Literal[0x4B],
        "0x4B": Literal["LANG_KANNADA"],
        "LANG_KASHMIRI": Literal[0x60],
        "0x60": Literal["LANG_KASHMIRI"],
        "LANG_KAZAK": Literal[0x3F],
        "0x3F": Literal["LANG_KAZAK"],
        "LANG_KONKANI": Literal[0x57],
        "0x57": Literal["LANG_KONKANI"],
        "LANG_KOREAN": Literal[0x12],
        "0x12": Literal["LANG_KOREAN"],
        "LANG_KYRGYZ": Literal[0x40],
        "0x40": Literal["LANG_KYRGYZ"],
        "LANG_LATVIAN": Literal[0x26],
        "0x26": Literal["LANG_LATVIAN"],
        "LANG_LITHUANIAN": Literal[0x27],
        "0x27": Literal["LANG_LITHUANIAN"],
        "LANG_MACEDONIAN": Literal[0x2F],
        "0x2F": Literal["LANG_MACEDONIAN"],
        "LANG_MALAY": Literal[0x3E],
        "0x3E": Literal["LANG_MALAY"],
        "LANG_MALAYALAM": Literal[0x4C],
        "0x4C": Literal["LANG_MALAYALAM"],
        "LANG_MANIPURI": Literal[0x58],
        "0x58": Literal["LANG_MANIPURI"],
        "LANG_MARATHI": Literal[0x4E],
        "0x4E": Literal["LANG_MARATHI"],
        "LANG_MONGOLIAN": Literal[0x50],
        "0x50": Literal["LANG_MONGOLIAN"],
        "LANG_NEPALI": Literal[0x61],
        "0x61": Literal["LANG_NEPALI"],
        "LANG_NORWEGIAN": Literal[0x14],
        "0x14": Literal["LANG_NORWEGIAN"],
        "LANG_ORIYA": Literal[0x48],
        "0x48": Literal["LANG_ORIYA"],
        "LANG_POLISH": Literal[0x15],
        "0x15": Literal["LANG_POLISH"],
        "LANG_PORTUGUESE": Literal[0x16],
        "0x16": Literal["LANG_PORTUGUESE"],
        "LANG_PUNJABI": Literal[0x46],
        "0x46": Literal["LANG_PUNJABI"],
        "LANG_ROMANIAN": Literal[0x18],
        "0x18": Literal["LANG_ROMANIAN"],
        "LANG_RUSSIAN": Literal[0x19],
        "0x19": Literal["LANG_RUSSIAN"],
        "LANG_SANSKRIT": Literal[0x4F],
        "0x4F": Literal["LANG_SANSKRIT"],
        "LANG_SERBIAN": Literal[0x1A],
        "0x1A": Literal["LANG_SERBIAN"],
        "LANG_SINDHI": Literal[0x59],
        "0x59": Literal["LANG_SINDHI"],
        "LANG_SLOVAK": Literal[0x1B],
        "0x1B": Literal["LANG_SLOVAK"],
        "LANG_SLOVENIAN": Literal[0x24],
        "0x24": Literal["LANG_SLOVENIAN"],
        "LANG_SPANISH": Literal[0x0A],
        "0x0A": Literal["LANG_SPANISH"],
        "LANG_SWAHILI": Literal[0x41],
        "0x41": Literal["LANG_SWAHILI"],
        "LANG_SWEDISH": Literal[0x1D],
        "0x1D": Literal["LANG_SWEDISH"],
        "LANG_SYRIAC": Literal[0x5A],
        "0x5A": Literal["LANG_SYRIAC"],
        "LANG_TAMIL": Literal[0x49],
        "0x49": Literal["LANG_TAMIL"],
        "LANG_TATAR": Literal[0x44],
        "0x44": Literal["LANG_TATAR"],
        "LANG_TELUGU": Literal[0x4A],
        "0x4A": Literal["LANG_TELUGU"],
        "LANG_THAI": Literal[0x1E],
        "0x1E": Literal["LANG_THAI"],
        "LANG_TURKISH": Literal[0x1F],
        "0x1F": Literal["LANG_TURKISH"],
        "LANG_UKRAINIAN": Literal[0x22],
        "0x22": Literal["LANG_UKRAINIAN"],
        "LANG_URDU": Literal[0x20],
        "0x20": Literal["LANG_URDU"],
        "LANG_UZBEK": Literal[0x43],
        "0x43": Literal["LANG_UZBEK"],
        "LANG_VIETNAMESE": Literal[0x2A],
        "0x2A": Literal["LANG_VIETNAMESE"],
        "LANG_GAELIC": Literal[0x3C],
        "0x3C": Literal["LANG_GAELIC"],
        "LANG_MALTESE": Literal[0x3A],
        "0x3A": Literal["LANG_MALTESE"],
        "LANG_MAORI": Literal[0x28],
        "0x28": Literal["LANG_MAORI"],
        "LANG_RHAETO_ROMANCE": Literal[0x17],
        "0x17": Literal["LANG_RHAETO_ROMANCE"],
        "LANG_SAAMI": Literal[0x3B],
        "0x3B": Literal["LANG_SAAMI"],
        "LANG_SORBIAN": Literal[0x2E],
        "0x2E": Literal["LANG_SORBIAN"],
        "LANG_SUTU": Literal[0x30],
        "0x30": Literal["LANG_SUTU"],
        "LANG_TSONGA": Literal[0x31],
        "0x31": Literal["LANG_TSONGA"],
        "LANG_TSWANA": Literal[0x32],
        "0x32": Literal["LANG_TSWANA"],
        "LANG_VENDA": Literal[0x33],
        "0x33": Literal["LANG_VENDA"],
        "LANG_XHOSA": Literal[0x34],
        "0x34": Literal["LANG_XHOSA"],
        "LANG_ZULU": Literal[0x35],
        "0x35": Literal["LANG_ZULU"],
        "LANG_ESPERANTO": Literal[0x8F],
        "0x8F": Literal["LANG_ESPERANTO"],
        "LANG_WALON": Literal[0x90],
        "0x90": Literal["LANG_WALON"],
        "LANG_CORNISH": Literal[0x91],
        "0x91": Literal["LANG_CORNISH"],
        "LANG_WELSH": Literal[0x92],
        "0x92": Literal["LANG_WELSH"],
        "LANG_BRETON": Literal[0x93],
        "0x93": Literal["LANG_BRETON"],
    },
)
_LANG_DICT_NAMES = Literal[
    "LANG_NEUTRAL",
    "LANG_INVARIANT",
    "LANG_AFRIKAANS",
    "LANG_ALBANIAN",
    "LANG_ARABIC",
    "LANG_ARMENIAN",
    "LANG_ASSAMESE",
    "LANG_AZERI",
    "LANG_BASQUE",
    "LANG_BELARUSIAN",
    "LANG_BENGALI",
    "LANG_BULGARIAN",
    "LANG_CATALAN",
    "LANG_CHINESE",
    "LANG_CROATIAN",
    "LANG_CZECH",
    "LANG_DANISH",
    "LANG_DIVEHI",
    "LANG_DUTCH",
    "LANG_ENGLISH",
    "LANG_ESTONIAN",
    "LANG_FAEROESE",
    "LANG_FARSI",
    "LANG_FINNISH",
    "LANG_FRENCH",
    "LANG_GALICIAN",
    "LANG_GEORGIAN",
    "LANG_GERMAN",
    "LANG_GREEK",
    "LANG_GUJARATI",
    "LANG_HEBREW",
    "LANG_HINDI",
    "LANG_HUNGARIAN",
    "LANG_ICELANDIC",
    "LANG_INDONESIAN",
    "LANG_ITALIAN",
    "LANG_JAPANESE",
    "LANG_KANNADA",
    "LANG_KASHMIRI",
    "LANG_KAZAK",
    "LANG_KONKANI",
    "LANG_KOREAN",
    "LANG_KYRGYZ",
    "LANG_LATVIAN",
    "LANG_LITHUANIAN",
    "LANG_MACEDONIAN",
    "LANG_MALAY",
    "LANG_MALAYALAM",
    "LANG_MANIPURI",
    "LANG_MARATHI",
    "LANG_MONGOLIAN",
    "LANG_NEPALI",
    "LANG_NORWEGIAN",
    "LANG_ORIYA",
    "LANG_POLISH",
    "LANG_PORTUGUESE",
    "LANG_PUNJABI",
    "LANG_ROMANIAN",
    "LANG_RUSSIAN",
    "LANG_SANSKRIT",
    "LANG_SERBIAN",
    "LANG_SINDHI",
    "LANG_SLOVAK",
    "LANG_SLOVENIAN",
    "LANG_SPANISH",
    "LANG_SWAHILI",
    "LANG_SWEDISH",
    "LANG_SYRIAC",
    "LANG_TAMIL",
    "LANG_TATAR",
    "LANG_TELUGU",
    "LANG_THAI",
    "LANG_TURKISH",
    "LANG_UKRAINIAN",
    "LANG_URDU",
    "LANG_UZBEK",
    "LANG_VIETNAMESE",
    "LANG_GAELIC",
    "LANG_MALTESE",
    "LANG_MAORI",
    "LANG_RHAETO_ROMANCE",
    "LANG_SAAMI",
    "LANG_SORBIAN",
    "LANG_SUTU",
    "LANG_TSONGA",
    "LANG_TSWANA",
    "LANG_VENDA",
    "LANG_XHOSA",
    "LANG_ZULU",
    "LANG_ESPERANTO",
    "LANG_WALON",
    "LANG_CORNISH",
    "LANG_WELSH",
    "LANG_BRETON",
]
_LANG_DICT_VALUES = Literal[
    0x00,
    0x01,
    0x02,
    0x03,
    0x04,
    0x05,
    0x06,
    0x07,
    0x08,
    0x09,
    0x0A,
    0x0B,
    0x0C,
    0x0D,
    0x0E,
    0x0F,
    0x10,
    0x11,
    0x12,
    0x13,
    0x14,
    0x15,
    0x16,
    0x17,
    0x18,
    0x19,
    0x1A,
    0x1B,
    0x1C,
    0x1D,
    0x1E,
    0x1F,
    0x20,
    0x21,
    0x22,
    0x23,
    0x24,
    0x25,
    0x26,
    0x27,
    0x28,
    0x29,
    0x2A,
    0x2B,
    0x2C,
    0x2D,
    0x2E,
    0x2F,
    0x30,
    0x31,
    0x32,
    0x33,
    0x34,
    0x35,
    0x36,
    0x37,
    0x38,
    0x39,
    0x3A,
    0x3B,
    0x3C,
    0x3E,
    0x3F,
    0x40,
    0x41,
    0x43,
    0x44,
    0x45,
    0x46,
    0x47,
    0x48,
    0x49,
    0x4A,
    0x4B,
    0x4C,
    0x4D,
    0x4E,
    0x4F,
    0x50,
    0x56,
    0x57,
    0x58,
    0x59,
    0x5A,
    0x60,
    0x61,
    0x65,
    0x7F,
    0x8F,
    0x90,
    0x91,
    0x92,
    0x93,
]

sublang: _NAME_LOOKUP_LIST = ...
SUBLANG: _SUBLANG_DICT = ...
_SUBLANG_DICT = TypedDict(
    "_SUBLANG_DICT",
    {
        "SUBLANG_NEUTRAL": Literal[0x00],
        "SUBLANG_DEFAULT": Literal[0x01],
        "SUBLANG_SYS_DEFAULT": Literal[0x02],
        "SUBLANG_ARABIC_SAUDI_ARABIA": Literal[0x01],
        "SUBLANG_ARABIC_IRAQ": Literal[0x02],
        "SUBLANG_ARABIC_EGYPT": Literal[0x03],
        "SUBLANG_ARABIC_LIBYA": Literal[0x04],
        "SUBLANG_ARABIC_ALGERIA": Literal[0x05],
        "SUBLANG_ARABIC_MOROCCO": Literal[0x06],
        "SUBLANG_ARABIC_TUNISIA": Literal[0x07],
        "SUBLANG_ARABIC_OMAN": Literal[0x08],
        "SUBLANG_ARABIC_YEMEN": Literal[0x09],
        "SUBLANG_ARABIC_SYRIA": Literal[0x0A],
        "SUBLANG_ARABIC_JORDAN": Literal[0x0B],
        "SUBLANG_ARABIC_LEBANON": Literal[0x0C],
        "SUBLANG_ARABIC_KUWAIT": Literal[0x0D],
        "SUBLANG_ARABIC_UAE": Literal[0x0E],
        "SUBLANG_ARABIC_BAHRAIN": Literal[0x0F],
        "SUBLANG_ARABIC_QATAR": Literal[0x10],
        "SUBLANG_AZERI_LATIN": Literal[0x01],
        "SUBLANG_AZERI_CYRILLIC": Literal[0x02],
        "SUBLANG_CHINESE_TRADITIONAL": Literal[0x01],
        "SUBLANG_CHINESE_SIMPLIFIED": Literal[0x02],
        "SUBLANG_CHINESE_HONGKONG": Literal[0x03],
        "SUBLANG_CHINESE_SINGAPORE": Literal[0x04],
        "SUBLANG_CHINESE_MACAU": Literal[0x05],
        "SUBLANG_DUTCH": Literal[0x01],
        "SUBLANG_DUTCH_BELGIAN": Literal[0x02],
        "SUBLANG_ENGLISH_US": Literal[0x01],
        "SUBLANG_ENGLISH_UK": Literal[0x02],
        "SUBLANG_ENGLISH_AUS": Literal[0x03],
        "SUBLANG_ENGLISH_CAN": Literal[0x04],
        "SUBLANG_ENGLISH_NZ": Literal[0x05],
        "SUBLANG_ENGLISH_EIRE": Literal[0x06],
        "SUBLANG_ENGLISH_SOUTH_AFRICA": Literal[0x07],
        "SUBLANG_ENGLISH_JAMAICA": Literal[0x08],
        "SUBLANG_ENGLISH_CARIBBEAN": Literal[0x09],
        "SUBLANG_ENGLISH_BELIZE": Literal[0x0A],
        "SUBLANG_ENGLISH_TRINIDAD": Literal[0x0B],
        "SUBLANG_ENGLISH_ZIMBABWE": Literal[0x0C],
        "SUBLANG_ENGLISH_PHILIPPINES": Literal[0x0D],
        "SUBLANG_FRENCH": Literal[0x01],
        "SUBLANG_FRENCH_BELGIAN": Literal[0x02],
        "SUBLANG_FRENCH_CANADIAN": Literal[0x03],
        "SUBLANG_FRENCH_SWISS": Literal[0x04],
        "SUBLANG_FRENCH_LUXEMBOURG": Literal[0x05],
        "SUBLANG_FRENCH_MONACO": Literal[0x06],
        "SUBLANG_GERMAN": Literal[0x01],
        "SUBLANG_GERMAN_SWISS": Literal[0x02],
        "SUBLANG_GERMAN_AUSTRIAN": Literal[0x03],
        "SUBLANG_GERMAN_LUXEMBOURG": Literal[0x04],
        "SUBLANG_GERMAN_LIECHTENSTEIN": Literal[0x05],
        "SUBLANG_ITALIAN": Literal[0x01],
        "SUBLANG_ITALIAN_SWISS": Literal[0x02],
        "SUBLANG_KASHMIRI_SASIA": Literal[0x02],
        "SUBLANG_KASHMIRI_INDIA": Literal[0x02],
        "SUBLANG_KOREAN": Literal[0x01],
        "SUBLANG_LITHUANIAN": Literal[0x01],
        "SUBLANG_MALAY_MALAYSIA": Literal[0x01],
        "SUBLANG_MALAY_BRUNEI_DARUSSALAM": Literal[0x02],
        "SUBLANG_NEPALI_INDIA": Literal[0x02],
        "SUBLANG_NORWEGIAN_BOKMAL": Literal[0x01],
        "SUBLANG_NORWEGIAN_NYNORSK": Literal[0x02],
        "SUBLANG_PORTUGUESE": Literal[0x02],
        "SUBLANG_PORTUGUESE_BRAZILIAN": Literal[0x01],
        "SUBLANG_SERBIAN_LATIN": Literal[0x02],
        "SUBLANG_SERBIAN_CYRILLIC": Literal[0x03],
        "SUBLANG_SPANISH": Literal[0x01],
        "SUBLANG_SPANISH_MEXICAN": Literal[0x02],
        "SUBLANG_SPANISH_MODERN": Literal[0x03],
        "SUBLANG_SPANISH_GUATEMALA": Literal[0x04],
        "SUBLANG_SPANISH_COSTA_RICA": Literal[0x05],
        "SUBLANG_SPANISH_PANAMA": Literal[0x06],
        "SUBLANG_SPANISH_DOMINICAN_REPUBLIC": Literal[0x07],
        "SUBLANG_SPANISH_VENEZUELA": Literal[0x08],
        "SUBLANG_SPANISH_COLOMBIA": Literal[0x09],
        "SUBLANG_SPANISH_PERU": Literal[0x0A],
        "SUBLANG_SPANISH_ARGENTINA": Literal[0x0B],
        "SUBLANG_SPANISH_ECUADOR": Literal[0x0C],
        "SUBLANG_SPANISH_CHILE": Literal[0x0D],
        "SUBLANG_SPANISH_URUGUAY": Literal[0x0E],
        "SUBLANG_SPANISH_PARAGUAY": Literal[0x0F],
        "SUBLANG_SPANISH_BOLIVIA": Literal[0x10],
        "SUBLANG_SPANISH_EL_SALVADOR": Literal[0x11],
        "SUBLANG_SPANISH_HONDURAS": Literal[0x12],
        "SUBLANG_SPANISH_NICARAGUA": Literal[0x13],
        "SUBLANG_SPANISH_PUERTO_RICO": Literal[0x14],
        "SUBLANG_SWEDISH": Literal[0x01],
        "SUBLANG_SWEDISH_FINLAND": Literal[0x02],
        "SUBLANG_URDU_PAKISTAN": Literal[0x01],
        "SUBLANG_URDU_INDIA": Literal[0x02],
        "SUBLANG_UZBEK_LATIN": Literal[0x01],
        "SUBLANG_UZBEK_CYRILLIC": Literal[0x02],
        "SUBLANG_DUTCH_SURINAM": Literal[0x03],
        "SUBLANG_ROMANIAN": Literal[0x01],
        "SUBLANG_ROMANIAN_MOLDAVIA": Literal[0x02],
        "SUBLANG_RUSSIAN": Literal[0x01],
        "SUBLANG_RUSSIAN_MOLDAVIA": Literal[0x02],
        "SUBLANG_CROATIAN": Literal[0x01],
        "SUBLANG_LITHUANIAN_CLASSIC": Literal[0x02],
        "SUBLANG_GAELIC": Literal[0x01],
        "SUBLANG_GAELIC_SCOTTISH": Literal[0x02],
        "SUBLANG_GAELIC_MANX": Literal[0x03],
        "0x00": tuple[Literal["SUBLANG_NEUTRAL"]],
        "0x01": tuple[
            Literal["SUBLANG_DEFAULT"],
            Literal["SUBLANG_ARABIC_SAUDI_ARABIA"],
            Literal["SUBLANG_AZERI_LATIN"],
            Literal["SUBLANG_CHINESE_TRADITIONAL"],
            Literal["SUBLANG_DUTCH"],
            Literal["SUBLANG_ENGLISH_US"],
            Literal["SUBLANG_FRENCH"],
            Literal["SUBLANG_GERMAN"],
            Literal["SUBLANG_ITALIAN"],
            Literal["SUBLANG_KOREAN"],
            Literal["SUBLANG_LITHUANIAN"],
            Literal["SUBLANG_MALAY_MALAYSIA"],
            Literal["SUBLANG_NORWEGIAN_BOKMAL"],
            Literal["SUBLANG_PORTUGUESE_BRAZILIAN"],
            Literal["SUBLANG_SPANISH"],
            Literal["SUBLANG_SWEDISH"],
            Literal["SUBLANG_URDU_PAKISTAN"],
            Literal["SUBLANG_UZBEK_LATIN"],
            Literal["SUBLANG_ROMANIAN"],
            Literal["SUBLANG_RUSSIAN"],
            Literal["SUBLANG_CROATIAN"],
            Literal["SUBLANG_GAELIC"],
        ],
        "0x02": tuple[
            Literal["SUBLANG_SYS_DEFAULT"],
            Literal["SUBLANG_ARABIC_IRAQ"],
            Literal["SUBLANG_AZERI_CYRILLIC"],
            Literal["SUBLANG_CHINESE_SIMPLIFIED"],
            Literal["SUBLANG_DUTCH_BELGIAN"],
            Literal["SUBLANG_ENGLISH_UK"],
            Literal["SUBLANG_FRENCH_BELGIAN"],
            Literal["SUBLANG_GERMAN_SWISS"],
            Literal["SUBLANG_ITALIAN_SWISS"],
            Literal["SUBLANG_KASHMIRI_SASIA"],
            Literal["SUBLANG_KASHMIRI_INDIA"],
            Literal["SUBLANG_MALAY_BRUNEI_DARUSSALAM"],
            Literal["SUBLANG_NEPALI_INDIA"],
            Literal["SUBLANG_NORWEGIAN_NYNORSK"],
            Literal["SUBLANG_PORTUGUESE"],
            Literal["SUBLANG_SERBIAN_LATIN"],
            Literal["SUBLANG_SPANISH_MEXICAN"],
            Literal["SUBLANG_SWEDISH_FINLAND"],
            Literal["SUBLANG_URDU_INDIA"],
            Literal["SUBLANG_UZBEK_CYRILLIC"],
            Literal["SUBLANG_ROMANIAN_MOLDAVIA"],
            Literal["SUBLANG_RUSSIAN_MOLDAVIA"],
            Literal["SUBLANG_LITHUANIAN_CLASSIC"],
            Literal["SUBLANG_GAELIC_SCOTTISH"],
        ],
        "0x03": tuple[
            Literal["SUBLANG_ARABIC_EGYPT"],
            Literal["SUBLANG_CHINESE_HONGKONG"],
            Literal["SUBLANG_ENGLISH_AUS"],
            Literal["SUBLANG_FRENCH_CANADIAN"],
            Literal["SUBLANG_GERMAN_AUSTRIAN"],
            Literal["SUBLANG_SERBIAN_CYRILLIC"],
            Literal["SUBLANG_SPANISH_MODERN"],
            Literal["SUBLANG_DUTCH_SURINAM"],
            Literal["SUBLANG_GAELIC_MANX"],
        ],
        "0x04": tuple[
            Literal["SUBLANG_ARABIC_LIBYA"],
            Literal["SUBLANG_CHINESE_SINGAPORE"],
            Literal["SUBLANG_ENGLISH_CAN"],
            Literal["SUBLANG_FRENCH_SWISS"],
            Literal["SUBLANG_GERMAN_LUXEMBOURG"],
            Literal["SUBLANG_SPANISH_GUATEMALA"],
        ],
        "0x05": tuple[
            Literal["SUBLANG_ARABIC_ALGERIA"],
            Literal["SUBLANG_CHINESE_MACAU"],
            Literal["SUBLANG_ENGLISH_NZ"],
            Literal["SUBLANG_FRENCH_LUXEMBOURG"],
            Literal["SUBLANG_GERMAN_LIECHTENSTEIN"],
            Literal["SUBLANG_SPANISH_COSTA_RICA"],
        ],
        "0x06": tuple[
            Literal["SUBLANG_ARABIC_MOROCCO"],
            Literal["SUBLANG_ENGLISH_EIRE"],
            Literal["SUBLANG_FRENCH_MONACO"],
            Literal["SUBLANG_SPANISH_PANAMA"],
        ],
        "0x07": tuple[
            Literal["SUBLANG_ARABIC_TUNISIA"],
            Literal["SUBLANG_ENGLISH_SOUTH_AFRICA"],
            Literal["SUBLANG_SPANISH_DOMINICAN_REPUBLIC"],
        ],
        "0x08": tuple[
            Literal["SUBLANG_ARABIC_OMAN"],
            Literal["SUBLANG_ENGLISH_JAMAICA"],
            Literal["SUBLANG_SPANISH_VENEZUELA"],
        ],
        "0x09": tuple[
            Literal["SUBLANG_ARABIC_YEMEN"],
            Literal["SUBLANG_ENGLISH_CARIBBEAN"],
            Literal["SUBLANG_SPANISH_COLOMBIA"],
        ],
        "0x0A": tuple[
            Literal["SUBLANG_ARABIC_SYRIA"],
            Literal["SUBLANG_ENGLISH_BELIZE"],
            Literal["SUBLANG_SPANISH_PERU"],
        ],
        "0x0B": tuple[
            Literal["SUBLANG_ARABIC_JORDAN"],
            Literal["SUBLANG_ENGLISH_TRINIDAD"],
            Literal["SUBLANG_SPANISH_ARGENTINA"],
        ],
        "0x0C": tuple[
            Literal["SUBLANG_ARABIC_LEBANON"],
            Literal["SUBLANG_ENGLISH_ZIMBABWE"],
            Literal["SUBLANG_SPANISH_ECUADOR"],
        ],
        "0x0D": tuple[
            Literal["SUBLANG_ARABIC_KUWAIT"],
            Literal["SUBLANG_ENGLISH_PHILIPPINES"],
            Literal["SUBLANG_SPANISH_CHILE"],
        ],
        "0x0E": tuple[
            Literal["SUBLANG_ARABIC_UAE"], Literal["SUBLANG_SPANISH_URUGUAY"]
        ],
        "0x0F": tuple[
            Literal["SUBLANG_ARABIC_BAHRAIN"], Literal["SUBLANG_SPANISH_PARAGUAY"]
        ],
        "0x10": tuple[
            Literal["SUBLANG_ARABIC_QATAR"], Literal["SUBLANG_SPANISH_BOLIVIA"]
        ],
        "0x11": tuple[Literal["SUBLANG_SPANISH_EL_SALVADOR"]],
        "0x12": tuple[Literal["SUBLANG_SPANISH_HONDURAS"]],
        "0x13": tuple[Literal["SUBLANG_SPANISH_NICARAGUA"]],
        "0x14": tuple[Literal["SUBLANG_SPANISH_PUERTO_RICO"]],
    },
)
_SUBLANG_DICT_NAMES: Literal[
    "SUBLANG_NEUTRAL",
    "SUBLANG_DEFAULT",
    "SUBLANG_SYS_DEFAULT",
    "SUBLANG_ARABIC_SAUDI_ARABIA",
    "SUBLANG_ARABIC_IRAQ",
    "SUBLANG_ARABIC_EGYPT",
    "SUBLANG_ARABIC_LIBYA",
    "SUBLANG_ARABIC_ALGERIA",
    "SUBLANG_ARABIC_MOROCCO",
    "SUBLANG_ARABIC_TUNISIA",
    "SUBLANG_ARABIC_OMAN",
    "SUBLANG_ARABIC_YEMEN",
    "SUBLANG_ARABIC_SYRIA",
    "SUBLANG_ARABIC_JORDAN",
    "SUBLANG_ARABIC_LEBANON",
    "SUBLANG_ARABIC_KUWAIT",
    "SUBLANG_ARABIC_UAE",
    "SUBLANG_ARABIC_BAHRAIN",
    "SUBLANG_ARABIC_QATAR",
    "SUBLANG_AZERI_LATIN",
    "SUBLANG_AZERI_CYRILLIC",
    "SUBLANG_CHINESE_TRADITIONAL",
    "SUBLANG_CHINESE_SIMPLIFIED",
    "SUBLANG_CHINESE_HONGKONG",
    "SUBLANG_CHINESE_SINGAPORE",
    "SUBLANG_CHINESE_MACAU",
    "SUBLANG_DUTCH",
    "SUBLANG_DUTCH_BELGIAN",
    "SUBLANG_ENGLISH_US",
    "SUBLANG_ENGLISH_UK",
    "SUBLANG_ENGLISH_AUS",
    "SUBLANG_ENGLISH_CAN",
    "SUBLANG_ENGLISH_NZ",
    "SUBLANG_ENGLISH_EIRE",
    "SUBLANG_ENGLISH_SOUTH_AFRICA",
    "SUBLANG_ENGLISH_JAMAICA",
    "SUBLANG_ENGLISH_CARIBBEAN",
    "SUBLANG_ENGLISH_BELIZE",
    "SUBLANG_ENGLISH_TRINIDAD",
    "SUBLANG_ENGLISH_ZIMBABWE",
    "SUBLANG_ENGLISH_PHILIPPINES",
    "SUBLANG_FRENCH",
    "SUBLANG_FRENCH_BELGIAN",
    "SUBLANG_FRENCH_CANADIAN",
    "SUBLANG_FRENCH_SWISS",
    "SUBLANG_FRENCH_LUXEMBOURG",
    "SUBLANG_FRENCH_MONACO",
    "SUBLANG_GERMAN",
    "SUBLANG_GERMAN_SWISS",
    "SUBLANG_GERMAN_AUSTRIAN",
    "SUBLANG_GERMAN_LUXEMBOURG",
    "SUBLANG_GERMAN_LIECHTENSTEIN",
    "SUBLANG_ITALIAN",
    "SUBLANG_ITALIAN_SWISS",
    "SUBLANG_KASHMIRI_SASIA",
    "SUBLANG_KASHMIRI_INDIA",
    "SUBLANG_KOREAN",
    "SUBLANG_LITHUANIAN",
    "SUBLANG_MALAY_MALAYSIA",
    "SUBLANG_MALAY_BRUNEI_DARUSSALAM",
    "SUBLANG_NEPALI_INDIA",
    "SUBLANG_NORWEGIAN_BOKMAL",
    "SUBLANG_NORWEGIAN_NYNORSK",
    "SUBLANG_PORTUGUESE",
    "SUBLANG_PORTUGUESE_BRAZILIAN",
    "SUBLANG_SERBIAN_LATIN",
    "SUBLANG_SERBIAN_CYRILLIC",
    "SUBLANG_SPANISH",
    "SUBLANG_SPANISH_MEXICAN",
    "SUBLANG_SPANISH_MODERN",
    "SUBLANG_SPANISH_GUATEMALA",
    "SUBLANG_SPANISH_COSTA_RICA",
    "SUBLANG_SPANISH_PANAMA",
    "SUBLANG_SPANISH_DOMINICAN_REPUBLIC",
    "SUBLANG_SPANISH_VENEZUELA",
    "SUBLANG_SPANISH_COLOMBIA",
    "SUBLANG_SPANISH_PERU",
    "SUBLANG_SPANISH_ARGENTINA",
    "SUBLANG_SPANISH_ECUADOR",
    "SUBLANG_SPANISH_CHILE",
    "SUBLANG_SPANISH_URUGUAY",
    "SUBLANG_SPANISH_PARAGUAY",
    "SUBLANG_SPANISH_BOLIVIA",
    "SUBLANG_SPANISH_EL_SALVADOR",
    "SUBLANG_SPANISH_HONDURAS",
    "SUBLANG_SPANISH_NICARAGUA",
    "SUBLANG_SPANISH_PUERTO_RICO",
    "SUBLANG_SWEDISH",
    "SUBLANG_SWEDISH_FINLAND",
    "SUBLANG_URDU_PAKISTAN",
    "SUBLANG_URDU_INDIA",
    "SUBLANG_UZBEK_LATIN",
    "SUBLANG_UZBEK_CYRILLIC",
    "SUBLANG_DUTCH_SURINAM",
    "SUBLANG_ROMANIAN",
    "SUBLANG_ROMANIAN_MOLDAVIA",
    "SUBLANG_RUSSIAN",
    "SUBLANG_RUSSIAN_MOLDAVIA",
    "SUBLANG_CROATIAN",
    "SUBLANG_LITHUANIAN_CLASSIC",
    "SUBLANG_GAELIC",
    "SUBLANG_GAELIC_SCOTTISH",
    "SUBLANG_GAELIC_MANX",
]
_SUBLANG_DICT_VALUES = Literal[
    0x00,
    0x01,
    0x02,
    0x03,
    0x04,
    0x05,
    0x06,
    0x07,
    0x08,
    0x09,
    0x0A,
    0x0B,
    0x0C,
    0x0D,
    0x0E,
    0x0F,
    0x10,
    0x11,
    0x12,
    0x13,
    0x14,
]

sublang_name: Any
sublang_value: Any

def get_sublang_name_for_lang(
    lang_value: _LANG_DICT_VALUES, sublang_value: _SUBLANG_DICT_VALUES
) -> str: ...
def parse_strings(data: str, counter: int, l: list[bytes]) -> None: ...
def retrieve_flags(
    flag_dict: dict[str | bytes, str | bytes], flag_filter: str | bytes
) -> list[tuple[str | bytes, str | bytes]]: ...
def set_flags(obj: Any, flag_field: bytes, flags: list[tuple[str, bytes]]) -> None: ...
def power_of_two(val: bytes) -> bool: ...
def b(x: _DATA_TYPE) -> bytes: ...

class AddressSet(set[_T]):
    def __init__(self) -> None: ...
    def add(self, value: _T) -> None: ...
    def diff(self) -> _T: ...

class UnicodeStringWrapperPostProcessor:
    def __init__(self, pe: PE, rva_ptr: int) -> None: ...
    def get_rva(self) -> int: ...
    def __str__(self) -> str: ...
    def decode(self, *args: str) -> str: ...
    def invalidate(self) -> None: ...
    def render_pascal_16(self) -> None: ...
    def get_pascal_16_length(self) -> Any | Literal[False]: ...
    def ask_unicode_16(self, next_rva_ptr: int) -> bool: ...
    def render_unicode_16(self) -> None: ...

class PEFormatError(Exception):
    def __init__(self, value: Any) -> None: ...
    def __str__(self) -> str: ...

class Dump:
    def __init__(self) -> None: ...
    def add_lines(self, txt: list[str], indent: int = ...) -> None: ...
    def add_line(self, txt: str, indent: int = ...) -> None: ...
    def add(self, txt: str, indent: int = ...) -> None: ...
    def add_header(self, txt: str) -> None: ...
    def add_newline(self) -> None: ...
    def get_text(self) -> str: ...

STRUCT_SIZEOF_TYPES: dict[str, int] = ...

_STRUCTURE_FORMAT = tuple[str, Sequence[str]]
_NAMED_STRUCTURE_FORMAT = tuple[_T, Sequence[str]]

@lru_cache(maxsize=2048)
def sizeof_type(t: str) -> int: ...
@lru_cache(maxsize=2048, copy=True)
def set_format(
    format: _STRUCTURE_FORMAT,
) -> tuple[str, list[None], dict[str, int], list[str], int]: ...

class _Structure_Dict_Value(TypedDict):
    FileOffset: int
    Offset: int
    Value: str

class Structure:
    __file_offset__: int

    def __init__(
        self,
        format: _STRUCTURE_FORMAT,
        name: str | None = ...,
        file_offset: int | None = ...,
    ) -> None: ...
    def __get_format__(self) -> str: ...
    def get_field_absolute_offset(self, field_name: str) -> int: ...
    def get_field_relative_offset(self, field_name: str) -> int: ...
    def get_file_offset(self) -> int: ...
    def set_file_offset(self, offset: int) -> None: ...
    def all_zeroes(self) -> bool: ...
    def sizeof(self) -> int: ...
    def __unpack__(self, data: _DATA_TYPE) -> None: ...
    def __pack__(self) -> bytes: ...
    def __str__(self) -> str: ...
    def __repr__(self) -> str: ...
    def dump(self, indentation: int = ...) -> list[str]: ...
    def dump_dict(self) -> dict[str, str | _Structure_Dict_Value]: ...

class SectionStructure(Structure):
    pe: PE
    PhysicalAddress: _UInt32
    VirtualAddress: _UInt32
    Misc_VirtualSize: _UInt32
    SizeOfRawData: _UInt32
    PointerToRawData: _UInt32
    PointerToRelocations: _UInt32
    PointerToLinenumbers: _UInt32
    NumberOfRelocations: _UInt16
    NumberOfLinenumbers: _UInt16
    Characteristics: _UInt32
    Name: _char[8]

    PointerToRawData_adj: int | None
    VirtualAddress_adj: int | None
    section_min_addr: int | None
    section_max_addr: int | None

    next_section_virtual_address: int | None

    def __init__(self, *argl: Any, **argd: Any) -> None: ...
    def get_PointerToRawData_adj(self) -> int: ...
    def get_VirtualAddress_adj(self) -> int: ...
    def get_data(
        self,
        start: int | None = ...,
        length: int | None = ...,
        ignore_padding: bool = ...,
    ) -> bytes: ...
    def __setattr__(self, name: str, val: Any) -> None: ...
    def get_rva_from_offset(self, offset: int) -> int: ...
    def get_offset_from_rva(self, rva: int) -> int: ...
    def contains_offset(self, offset: int) -> bool: ...
    def contains_rva(self, rva: int) -> bool: ...
    def contains(self, rva: int) -> bool: ...
    def get_entropy(self) -> float | Literal[0]: ...
    def get_hash_sha1(self) -> str | None: ...
    def get_hash_sha256(self) -> str | None: ...
    def get_hash_sha512(self) -> str | None: ...
    def get_hash_md5(self) -> str | None: ...
    def entropy_H(self, data: _DATA_TYPE) -> float | Literal[0]: ...

@lru_cache(maxsize=2048, copy=False)
def set_bitfields_format(
    format: _STRUCTURE_FORMAT,
) -> tuple[
    str,
    int,
    dict[str, int],
    list[str],
    list[str],
    dict[int, tuple[str, list[tuple[str, int]]]],
]: ...

class StructureWithBitfields(Structure):
    BTF_NAME_IDX: Literal[0] = ...
    BTF_BITCNT_IDX: Literal[1] = ...
    CF_TYPE_IDX: Literal[0] = ...
    CF_SUBFLD_IDX: Literal[1] = ...
    def __init__(
        self,
        format: _STRUCTURE_FORMAT,
        name: str | None = ...,
        file_offset: int | None = ...,
    ) -> None: ...
    def __unpack__(self, data: _DATA_TYPE) -> None: ...
    def __pack__(self) -> bytes: ...
    def dump(self, indentation: int = ...) -> list[str]: ...
    def dump_dict(self) -> dict[str, str | _Structure_Dict_Value]: ...

class _DOS_Header(Structure):
    name: Literal["IMAGE_DOS_HEADER"]
    e_magic: _char[2]  # H
    e_cblp: _UInt16
    e_cp: _UInt16
    e_crlc: _UInt16
    e_parhdr: _UInt16
    e_minalloc: _UInt16
    e_maxalloc: _UInt16
    e_ss: _UInt16
    e_sp: _UInt16
    e_csum: _UInt16
    e_ip: _UInt16
    e_cs: _UInt16
    e_lfarlc: _UInt16
    e_ovno: _UInt16
    e_res: _char[8]  # 8s
    e_oemid: _UInt16
    e_oeminfo: _UInt16
    e_res2: _char[20]  # 20s
    e_lfanew: _Int32

class _File_Header(Structure):
    name: Literal["IMAGE_FILE_HEADER"]
    Machine: _MACHINE_TYPE_DICT_VALUES
    NumberOfSections: _UInt16
    TimeDateStamp: _UInt32
    PointerToSymbolTable: _UInt32
    NumberOfSymbols: _UInt32
    SizeOfOptionalHeader: _UInt16
    Characteristics: _UInt16

class _Data_Directory(Structure):
    name: Literal["IMAGE_DATA_DIRECTORY"]
    VirtualAddress: _UInt32
    Size: _UInt32

_MAGIC_TYPE = _UInt16

class _Optional_Header_Base(Structure, Generic[_Ptr]):
    Magic: _MAGIC_TYPE
    MajorLinkerVersion: _byte
    MinorLinkerVersion: _byte
    SizeOfCode: _UInt32
    SizeOfInitializedData: _UInt32
    SizeOfUninitializedData: _UInt32
    AddressOfEntryPoint: _UInt32
    BaseOfCode: _UInt32
    ImageBase: _Ptr
    SectionAlignment: _UInt32
    FileAlignment: _UInt32
    MajorOperatingSystemVersion: _UInt16
    MinorOperatingSystemVersion: _UInt16
    MajorImageVersion: _UInt16
    MinorImageVersion: _UInt16
    MajorSubsystemVersion: _UInt16
    MinorSubsystemVersion: _UInt16
    Win32VersionValue: _UInt32
    SizeOfImage: _UInt32
    SizeOfHeaders: _UInt32
    CheckSum: _UInt32
    Subsystem: _SUBSYSTEM_TYPE_VAL
    DllCharacteristics: _DLL_CHARACTERISTICS_VALUES
    SizeOfStackReserve: _Ptr
    SizeOfStackCommit: _Ptr
    SizeOfHeapReserve: _Ptr
    SizeOfHeapCommit: _Ptr
    LoaderFlags: _UInt32
    NumberOfRvaAndSizes: _UInt32
    # DataDirectory: list[int]
    DATA_DIRECTORY: list[_Data_Directory]

class _Optional_Header32(_Optional_Header_Base[_UInt32]):
    name: Literal["IMAGE_OPTIONAL_HEADER32"]
    BaseOfData: _UInt32

class _Optional_Header64(_Optional_Header_Base[_UInt64]):
    name: Literal["IMAGE_OPTIONAL_HEADER64"]

_Optional_Header = _Optional_Header32 | _Optional_Header64

class _NT_Headers(Structure):
    name: Literal["IMAGE_NT_HEADERS"]
    Signature: _UInt32
    # FileHeader: _File_Header
    FILE_HEADER: _File_Header
    # OptionalHeader: _Optional_Header
    OPTIONAL_HEADER: _Optional_Header32 | _Optional_Header64

# IMAGE_SECTION_HEADER is implemented as SectionStructure

class _Delay_Import_Descriptor(Structure):
    name: Literal["IMAGE_DELAY_IMPORT_DESCRIPTOR"]
    grAttrs: _UInt32
    szName: _UInt32
    phmod: _UInt32
    pIAT: _UInt32
    pINT: _UInt32
    pBoundIAT: _UInt32
    pUnloadIAT: _UInt32
    dwTimeStamp: _UInt32

class _Import_Descriptor(Structure):
    name: Literal["IMAGE_IMPORT_DESCRIPTOR"]
    OriginalFirstThunk: _UInt32
    Characteristics: _UInt32
    TimeDateStamp: _UInt32
    ForwarderChain: _UInt32
    Name: _UInt32
    FirstThunk: _UInt32

class _Export_Directory(Structure):
    name: Literal["IMAGE_EXPORT_DIRECTORY"]
    Characteristics: _UInt32
    TimeDateStamp: _UInt32
    MajorVersion: _UInt16
    MinorVersion: _UInt16
    Name: _UInt32
    Base: _UInt32
    NumberOfFunctions: _UInt32
    NumberOfNames: _UInt32
    AddressOfFunctions: _UInt32
    AddressOfNames: _UInt32
    AddressOfNameOrdinals: _UInt32

class _Resource_Directory(Structure):
    name: Literal["IMAGE_RESOURCE_DIRECTORY"]
    Characteristics: _UInt32
    TimeDateStamp: _UInt32
    MajorVersion: _UInt16
    MinorVersion: _UInt16
    NumberOfNamedEntries: _UInt16
    NumberOfIdEntries: _UInt16

class _Resource_Directory_Entry(Structure):
    name: Literal["IMAGE_RESOURCE_DIRECTORY_ENTRY"]
    Name: _RESOURCE_TYPE_DICT_VALUES
    Id: _RESOURCE_TYPE_DICT_VALUES
    NameOffset: _UInt32

    OffsetToData: _UInt32
    Size: _UInt32
    CodePage: _UInt32
    Reserved: _UInt32

    DataIsDirectory: _UInt32
    OffsetToDirectory: _UInt32

    __pad: _UInt32

class _Resource_Data_Entry(Structure):
    name: Literal["IMAGE_RESOURCE_DATA_ENTRY"]
    OffsetToData: _UInt32
    Size: _UInt32
    CodePage: _UInt32
    Reserved: _UInt32

class _VersionStructure(Structure):
    Length: _UInt16
    ValueLength: _UInt16
    Type: _UInt16
    Key: bytes

class _VersionInfo(_VersionStructure):
    name: Literal["VS_VERSIONINFO"]

class _FixedFileInfo(Structure):
    name: Literal["VS_FIXEDFILEINFO"]
    Signature: _UInt32
    StrucVersion: _UInt32
    FileVersionMS: _UInt32
    FileVersionLS: _UInt32
    ProductVersionMS: _UInt32
    ProductVersionLS: _UInt32
    FileFlagsMask: _UInt32
    FileFlags: _UInt32
    FileOS: _UInt32
    FileType: _UInt32
    FileSubtype: _UInt32
    FileDateMS: _UInt32
    FileDateLS: _UInt32

class _StringFileInfo(_VersionStructure):
    name: Literal["StringFileInfo"]
    StringTable: list["_StringTable"]
    Var: list["_Var"]

class _StringTable(_VersionStructure):
    name: Literal["StringTable"]

    entries: dict[bytes, bytes]
    entries_offsets: dict[bytes, tuple[_UInt32, _UInt32]]
    entries_lengths: dict[bytes, tuple[int, int]]
    LangID: bytes
    Length: int

class _String(_VersionStructure):
    name: Literal["String"]

class _VarFileInfo(_VersionStructure):
    name: Literal["VarFileInfo"]
    Var: list["_Var"]  # "Children"

class _Var(_VersionStructure):
    name: Literal["Var"]
    entry: dict[bytes, str]  # "Value"

class _Thunk_Data_Base(Structure, Generic[_Ptr]):
    name: Literal["IMAGE_THUNK_DATA"]
    # Union
    ForwarderString: _Ptr
    Function: _Ptr
    Ordinal: _Ptr
    AddressOfData: _Ptr
    # /Union

class _Thunk_Data32(_Thunk_Data_Base[_UInt32]):
    pass

class _Thunk_Data64(_Thunk_Data_Base[_UInt64]):
    pass

_Thunk_Data = _Thunk_Data32 | _Thunk_Data64

class _Debug_Directory(Structure):
    name: Literal["IMAGE_DEBUG_DIRECTORY"]
    Characteristics: _UInt32
    TimeDateStamp: _UInt32
    MajorVersion: _UInt16
    MinorVersion: _UInt16
    Type: _DEBUG_TYPE_DICT_VALUES
    SizeOfData: _UInt32
    AddressOfRawData: _UInt32
    PointerToRawData: _UInt32

class _Base_Relocation(Structure):
    name: Literal["IMAGE_BASE_RELOCATION"]
    VirtualAddress: _UInt32
    SizeOfBlock: _UInt32

class _Base_Relocation_Entry(Structure):
    name: Literal["IMAGE_BASE_RELOCATION_ENTRY"]
    Data: _UInt16

class _Dynamic_Relocation_Bitfield(StructureWithBitfields):
    PageRelativeOffset: int  # I:12

class _Import_Control_Transfer_Dynamic_Relocation(_Dynamic_Relocation_Bitfield):
    name: Literal["IMAGE_IMPORT_CONTROL_TRANSFER_DYNAMIC_RELOCATION"]
    PageRelativeOffset: int  # I:12
    IndirectCall: int  # I:1
    IATIndex: int  # I:19

class _Indir_Control_Transfer_Dynamic_Relocation(_Dynamic_Relocation_Bitfield):
    name: Literal["IMAGE_INDIR_CONTROL_TRANSFER_DYNAMIC_RELOCATION"]
    PageRelativeOffset: int  # H:12
    IndirectCall: int  # H:1
    RexWPrefix: int  # H:1
    CfgCheck: int  # H:1
    Reserved: int  # H:1

class _Switchtable_Branch_Dynamic_Relocation(_Dynamic_Relocation_Bitfield):
    name: Literal["IMAGE_SWITCHTABLE_BRANCH_DYNAMIC_RELOCATION"]
    PageRelativeOffset: int  # H:12
    RegisterNumber: int  # H:4

class _Function_Override_Header(Structure):
    name: Literal["IMAGE_FUNCTION_OVERRIDE_HEADER"]
    FuncOverrideSize: _UInt32

class _Function_Override_Dynamic_Relocation(Structure):
    name: Literal["IMAGE_FUNCTION_OVERRIDE_DYNAMIC_RELOCATION"]
    OriginalRva: _UInt32
    BDDOffset: _UInt32
    RvaSize: _UInt32
    BaseRelocSize: _UInt32

class _BDD_Info(Structure):
    name: Literal["IMAGE_BDD_INFO"]
    Version: _UInt32
    BDDSize: _UInt32

class _BDD_Dynamic_Relocation(Structure):
    name: Literal["IMAGE_BDD_DYNAMIC_RELOCATION"]
    Left: _UInt16
    Right: _UInt16
    Value: _UInt32

class _TLS_Directory_Base(Structure, Generic[_Ptr]):
    name: Literal["IMAGE_TLS_DIRECTORY"]
    SizeOfZeroFill: _UInt32
    Characteristics: _UInt32
    StartAddressOfRawData: _Ptr
    EndAddressOfRawData: _Ptr
    AddressOfIndex: _Ptr
    AddressOfCallBacks: _Ptr

class _TLS_Directory32(_TLS_Directory_Base[_UInt32]):
    pass

class _TLS_Directory64(_TLS_Directory_Base[_UInt64]):
    pass

_TLS_Directory = _TLS_Directory32 | _TLS_Directory64

class _Load_Config_Directory_Base(Structure, Generic[_Ptr]):
    name: Literal["IMAGE_LOAD_CONFIG_DIRECTORY"]
    Size: _UInt32
    TimeDateStamp: _UInt32
    MajorVersion: _UInt16
    MinorVersion: _UInt16
    GlobalFlagsClear: _UInt32
    GlobalFlagsSet: _UInt32
    CriticalSectionDefaultTimeout: _UInt32
    DeCommitFreeBlockThreshold: _Ptr
    DeCommitTotalFreeThreshold: _Ptr
    LockPrefixTable: _Ptr
    MaximumAllocationSize: _Ptr
    VirtualMemoryThreshold: _Ptr
    ProcessHeapFlags: _UInt32
    ProcessAffinityMask: _Ptr
    CSDVersion: _UInt16
    DependentLoadFlags: _UInt16
    EditList: _Ptr
    SecurityCookie: _Ptr
    SEHandlerTable: _Ptr
    SEHandlerCount: _Ptr
    GuardCFCheckFunctionPointer: _Ptr
    GuardCFDispatchFunctionPointer: _Ptr
    GuardCFFunctionTable: _Ptr
    GuardCFFunctionCount: _Ptr
    GuardFlags: _UInt32
    CodeIntegrityFlags: _UInt16
    CodeIntegrityCatalog: _UInt16
    CodeIntegrityCatalogOffset: _UInt32
    CodeIntegrityReserved: _UInt32
    GuardAddressTakenIatEntryTable: _Ptr
    GuardAddressTakenIatEntryCount: _Ptr
    GuardLongJumpTargetTable: _Ptr
    GuardLongJumpTargetCount: _Ptr
    DynamicValueRelocTable: _Ptr
    CHPEMetadataPointer: _Ptr
    GuardRFFailureRoutine: _Ptr
    GuardRFFailureRoutineFunctionPointer: _Ptr
    DynamicValueRelocTableOffset: _UInt32
    DynamicValueRelocTableSection: _UInt16
    Reserved2: _UInt16
    GuardRFVerifyStackPointerFunctionPointer: _Ptr
    HotPatchTableOffset: _UInt32
    Reserved3: _UInt32
    EnclaveConfigurationPointer: _Ptr
    VolatileMetadataPointer: _Ptr
    GuardEHContinuationTable: _Ptr
    GuardEHContinuationCount: _Ptr
    GuardXFGCheckFunctionPointer: _Ptr
    GuardXFGDispatchFunctionPointer: _Ptr
    GuardXFGTableDispatchFunctionPointer: _Ptr
    CastGuardOsDeterminedFailureMode: _Ptr
    GuardMemcpyFunctionPointer: _Ptr

class _Load_Config_Directory32(_Load_Config_Directory_Base[_UInt32]):
    pass

class _Load_Config_Directory64(_Load_Config_Directory_Base[_UInt64]):
    pass

_Load_Config_Directory = _Load_Config_Directory32 | _Load_Config_Directory64

class _Dynamic_Relocation_Table(Structure):
    name: Literal["IMAGE_DYNAMIC_RELOCATION_TABLE"]
    Version: _UInt32
    Size: _UInt32

class _Dynamic_Relocation_Base(Structure, Generic[_Ptr]):
    Symbol: _Ptr
    BaseRelocSize: _UInt32

class _Dynamic_Relocation32(_Dynamic_Relocation_Base[_UInt32]):
    name: Literal["IMAGE_DYNAMIC_RELOCATION"]

class _Dynamic_Relocation64(_Dynamic_Relocation_Base[_UInt64]):
    name: Literal["IMAGE_DYNAMIC_RELOCATION64"]

_Dynamic_Relocation = _Dynamic_Relocation32 | _Dynamic_Relocation64

class _Dynamic_Relocation_V2_Base(Structure, Generic[_Ptr]):
    HeaderSize: _UInt32
    FixupInfoSize: _UInt32
    Symbol: _Ptr
    SymbolGroup: _UInt32
    Flags: _UInt32

class _Dynamic_Relocation32_V2(_Dynamic_Relocation_V2_Base[_UInt32]):
    name: Literal["IMAGE_DYNAMIC_RELOCATION_V2"]

class _Dynamic_Relocation64_V2(_Dynamic_Relocation_V2_Base[_UInt64]):
    name: Literal["IMAGE_DYNAMIC_RELOCATION64_V2"]

_Dynamic_Relocation_V2 = _Dynamic_Relocation32_V2 | _Dynamic_Relocation64_V2

class _Bound_Import_Descriptor(Structure):
    name: Literal["IMAGE_BOUND_IMPORT_DESCRIPTOR"]
    TimeDateStamp: _UInt32
    OffsetModuleName: _UInt16
    NumberOfModuleForwarderRefs: _UInt16

class _Bound_Forwarder_Ref(Structure):
    name: Literal["IMAGE_BOUND_FORWARDER_REF"]
    TimeDateStamp: _UInt32
    OffsetModuleName: _UInt16
    Reserved: _UInt16

class _Runtime_Function(Structure):
    name: Literal["RUNTIME_FUNCTION"]
    BeginAddress: _UInt32
    EndAddress: _UInt32
    UnwindData: _UInt32
    UnwindInfoAddress: _UInt32

# Debug Types
class _Debug_Type(Structure):
    pass

class _Debug_Misc(_Debug_Type):
    name: Literal["IMAGE_DEBUG_MISC"]
    DataType: _UInt32
    Length: _UInt32
    Unicode: _char
    Reserved1: _char
    Reserved2: _UInt16

class _CV_Info_PDB20(_Debug_Type):
    name: Literal["CV_INFO_PDB20"]
    CvHeaderSignature: _UInt32
    CvHeaderOffset: _UInt32
    Signature: _UInt32
    Age: _UInt32

class _CV_Info_PDB70(_Debug_Type):
    name: Literal["CV_INFO_PDB70"]
    CvSignature: _char[4]
    Signature_Data1: _UInt32  # Signature is of GUID type
    Signature_Data2: _UInt16
    Signature_Data3: _UInt16
    Signature_Data4: _char
    Signature_Data5: _char
    Signature_Data6: _char[6]
    Signature_Data6_value: bytes
    Age: _UInt32
    PdbFileName: _char[int]  # (Debug_Directory.SizeOfData - sizeof(CV_INFO_PDB70))
    Signature_String: str

# Misc
class _RichHeader:
    checksum: bytes
    values: bytes
    key: bytes
    raw_data: bytes
    clear_data: bytes

class DataContainer:
    name: bytes | None
    def __init__(self, **args: Any) -> None: ...

class _DataContainer_Struct(DataContainer, Generic[_T]):
    struct: _T
    def __init(self, struct: _T, **args) -> None: ...

class ImportDescData(
    _DataContainer_Struct[_Import_Descriptor | _Delay_Import_Descriptor]
):
    dll: bytes
    imports: list["ImportData"]

class ImportData(DataContainer):
    pe: PE
    struct_table: _Thunk_Data
    struct_iat: _Thunk_Data | None
    import_by_ordinal: bool
    ordinal: bytes | None
    ordinal_offset: int
    hint: _UInt16
    name_offset: int
    bound: _UInt32 | _UInt64
    address: _UInt32 | _UInt64
    hint_name_table_rva: _UInt32 | _UInt64
    thunk_offset: int
    thunk_rva: int
    def __setattr__(self, name: str, val: Any) -> None: ...

class ExportDirData(_DataContainer_Struct[_Export_Directory]): ...

class ExportData(DataContainer):
    pe: PE
    ordinal: int
    ordinal_offset: int
    address: int
    address_offset: int
    name: bytes
    name_offset: int
    forwarder: bytes
    forwarder_offset: int
    def __setattr__(self, name: str, val: Any) -> None: ...

class ResourceDirData(_DataContainer_Struct[_Resource_Directory]):
    entries: list[ResourceDirEntryData]
    strings: dict[int, str]

class ResourceDirEntryData(_DataContainer_Struct[_Resource_Directory_Entry]):
    id: _RESOURCE_TYPE_DICT_VALUES
    directory: ResourceDirData
    data: ResourceDataEntryData

class ResourceDataEntryData(_DataContainer_Struct[_Resource_Data_Entry]):
    lang: _LANG_DICT_VALUES
    sublang: _SUBLANG_DICT_VALUES

class DebugData(_DataContainer_Struct[_Debug_Directory]):
    entry: _Debug_Type

class DynamicRelocationData(_DataContainer_Struct[_Dynamic_Relocation]):
    relocations: list[BaseRelocationData]

class FunctionOverrideData(_DataContainer_Struct[_Dynamic_Relocation]):
    bdd_relocs: list[BddDynamicRelocationData]
    func_relocs: list[FunctionOverrideDynamicRelocationData]

class FunctionOverrideDynamicRelocationData(
    _DataContainer_Struct[_Function_Override_Dynamic_Relocation]
):
    relocations: list[BaseRelocationData]

class BddDynamicRelocationData(_DataContainer_Struct[_BDD_Dynamic_Relocation]): ...

class BaseRelocationData(_DataContainer_Struct[_Base_Relocation]):
    entries: list[RelocationData]

class RelocationData(
    _DataContainer_Struct[_Base_Relocation_Entry | _Dynamic_Relocation_Bitfield]
):
    type: _RELOCATION_TYPE_DICT_VALUES
    rva: int
    base_rva: int
    def __setattr__(self, name: str, val: Any) -> None: ...

class TlsData(_DataContainer_Struct[_TLS_Directory]): ...

class BoundImportDescData(_DataContainer_Struct[_Bound_Import_Descriptor]):
    entries: list[BoundImportRefData]

class LoadConfigData(_DataContainer_Struct[_Load_Config_Directory]):
    dynamic_relocations: list[DynamicRelocationData]

class BoundImportRefData(_DataContainer_Struct[_Bound_Forwarder_Ref]): ...

class ExceptionsDirEntryData(_DataContainer_Struct[_Runtime_Function]):
    unwindinfo: UnwindInfo

class UnwindInfo(StructureWithBitfields):
    Version: _char[3]
    Flags: _char[5]
    SizeOfProlog: _char
    CountOfCodes: int
    FrameRegister: _char[4]
    FrameOffset: _char[4]

    UNW_FLAG_EHANDLER: Literal[0, 0x01]
    UNW_FLAG_UHANDLER: Literal[0, 0x02]
    UNW_FLAG_CHAININFO: Literal[0, 0x04]
    def __init__(self, file_offset: int = ...) -> None: ...
    def unpack_in_stages(self, data: _DATA_TYPE) -> str | None: ...
    def dump(self, indentation: int = ...) -> list[str]: ...
    def dump_dict(self) -> dict[str, str | _Structure_Dict_Value]: ...
    def __setattr__(self, name: str, val: Any) -> None: ...
    def sizeof(self) -> int: ...
    def __pack__(self) -> bytes: ...
    def get_chained_function_entry(self) -> ExceptionsDirEntryData: ...
    def set_chained_function_entry(self, entry: ExceptionsDirEntryData) -> None: ...

class _Unwind_Code_Base(UnwindInfo):
    CodeOffset: _char
    UnwindOp: _char[4]
    OpInfo: _char[4]

class _Unwind_Code(_Unwind_Code_Base):
    name: Literal["UNWIND_CODE"]

_Unwind_Code_Type = TypeVar("_Unwind_Code_Type", bound=_Unwind_Code_Base)

class _Unwind_Code_Push_NonVol(_Unwind_Code_Base):
    name: Literal["UNWIND_CODE_PUSH_NONVOL"]
    Reg: _REGISTERS_DICT_VALUES

class _Unwind_Code_Alloc_Large(_Unwind_Code_Base):
    name: Literal["UNWIND_CODE_ALLOC_LARGE"]
    AllocSizeInQwords: _UInt16
    AllocSize: _UInt32

class _Unwind_Code_Alloc_Small(_Unwind_Code_Base):
    name: Literal["UNWIND_CODE_ALLOC_SMALL"]
    AllocSizeInQwordsMinus8: int

_Unwind_Code_Set_Fp = _Unwind_Code

class _Unwind_Code_Save_Reg(_Unwind_Code_Base):
    name: Literal["UNWIND_CODE_SAVE_NONVOL"]
    Reg: _REGISTERS_DICT_VALUES
    OffsetInQwords: _UInt16

class _Unwind_Code_Save_Reg_Far(_Unwind_Code_Base):
    name: Literal["UNWIND_CODE_SAVE_NONVOL_FAR"]
    Reg: _REGISTERS_DICT_VALUES
    Offset: _UInt32

class _Unwind_Code_Save_XMM(_Unwind_Code_Base):
    name: Literal["UNWIND_CODE_SAVE_XMM128"]
    Reg: _char[4]
    OffsetIn2Qwords: _UInt16

class _Unwind_Code_Save_XMM_Far(_Unwind_Code_Base):
    name: Literal["UNWIND_CODE_SAVE_XMM128_FAR"]
    Reg: int
    Offset: "_UInt32"

_Unwind_Code_Push_Frame = _Unwind_Code

class _Unwind_Code_Epilog_Marker(_Unwind_Code_Base):
    name: Literal["UNWIND_CODE_EPILOG"]
    Size: _char
    UnwindOp: _char[4]
    Flags: _char[4]
    OffsetLow: _char
    Unused: _char[4]
    OffsetHigh: _char[4]

class PrologEpilogOp(ABC, Generic[_Unwind_Code_Type]):
    struct: _Unwind_Code_Type
    def initialize(
        self,
        unw_code: StructureWithBitfields,
        data: _DATA_TYPE,
        unw_info: UnwindInfo,
        file_offset: int | None,
    ) -> None: ...
    def length_in_code_structures(
        self, unw_code: StructureWithBitfields, unw_info: UnwindInfo
    ) -> int: ...
    def is_valid(self) -> bool: ...

class PrologEpilogOpPushReg(PrologEpilogOp[_Unwind_Code_Push_NonVol]):
    def __str__(self) -> str: ...

class PrologEpilogOpAllocLarge(PrologEpilogOp[_Unwind_Code_Alloc_Large]):
    def length_in_code_structures(
        self, unw_code: StructureWithBitfields, unw_info: UnwindInfo
    ) -> int: ...
    def get_alloc_size(self) -> int: ...
    def __str__(self) -> str: ...

class PrologEpilogOpAllocSmall(PrologEpilogOp[_Unwind_Code_Alloc_Small]):
    def get_alloc_size(self) -> int: ...
    def __str__(self) -> str: ...

class PrologEpilogOpSetFP(PrologEpilogOp[_Unwind_Code_Set_Fp]):
    def initialize(
        self,
        unw_code: StructureWithBitfields,
        data: _DATA_TYPE,
        unw_info: UnwindInfo,
        file_offset: int | None,
    ) -> None: ...
    def __str__(self) -> str: ...

class PrologEpilogOpSaveReg(PrologEpilogOp[_Unwind_Code_Save_Reg]):
    def length_in_code_structures(
        self, unwcode: StructureWithBitfields, unw_info: UnwindInfo
    ) -> int: ...
    def get_offset(self) -> int: ...
    def __str__(self) -> str: ...

class PrologEpilogOpSaveRegFar(PrologEpilogOp[_Unwind_Code_Save_Reg_Far]):
    def length_in_code_structures(
        self, unw_code: StructureWithBitfields, unw_info: UnwindInfo
    ) -> int: ...
    def get_offset(self) -> int: ...
    def __str__(self) -> str: ...

class PrologEpilogOpSaveXMM(PrologEpilogOp[_Unwind_Code_Save_XMM]):
    def length_in_code_structures(
        self, unw_code: StructureWithBitfields, unw_info: UnwindInfo
    ) -> int: ...
    def get_offset(self) -> int: ...
    def __str__(self) -> str: ...

class PrologEpilogOpSaveXMMFar(PrologEpilogOp[_Unwind_Code_Save_XMM_Far]):
    def length_in_code_structures(
        self, unw_code: StructureWithBitfields, unw_info: UnwindInfo
    ) -> int: ...
    def get_offset(self) -> int: ...
    def __str__(self) -> str: ...

class PrologEpilogOpPushFrame(PrologEpilogOp[_Unwind_Code_Push_Frame]):
    def __str__(self) -> str: ...

class PrologEpilogOpEpilogMarker(PrologEpilogOp[_Unwind_Code_Epilog_Marker]):
    def initialize(
        self,
        unw_code: StructureWithBitfields,
        data: _DATA_TYPE,
        unw_info: UnwindInfo,
        file_offset: int | None,
    ) -> None: ...
    def length_in_code_structures(
        self, unw_code: StructureWithBitfields, unw_info: UnwindInfo
    ) -> int: ...
    def get_offset(self) -> int: ...
    def is_valid(self) -> bool: ...
    def __str__(self) -> str: ...

class PrologEpilogOpsFactory:
    _class_dict: dict[int, type[PrologEpilogOp[Any]]] = ...
    @staticmethod
    def create(unwcode: StructureWithBitfields) -> PrologEpilogOp[Any]: ...

allowed_filename: bytes = ...

def is_valid_dos_filename(s: str | bytes | bytearray) -> bool: ...

allowed_function_name: bytes = ...

@lru_cache(maxsize=2048)
def is_valid_function_name(
    s: str | bytes | bytearray, relax_allowed_characters: bool = ...
) -> bool: ...

class PE(AbstractContextManager["PE"]):
    __IMAGE_DOS_HEADER_format__: _NAMED_STRUCTURE_FORMAT[
        Literal["IMAGE_DOS_HEADER"]
    ] = ...
    __IMAGE_FILE_HEADER_format__: _NAMED_STRUCTURE_FORMAT[
        Literal["IMAGE_FILE_HEADER"]
    ] = ...
    __IMAGE_DATA_DIRECTORY_format__: _NAMED_STRUCTURE_FORMAT[
        Literal["IMAGE_DATA_DIRECTORY"]
    ] = ...
    __IMAGE_OPTIONAL_HEADER_format__: _NAMED_STRUCTURE_FORMAT[
        Literal["IMAGE_OPTIONAL_HEADER"]
    ] = ...
    __IMAGE_OPTIONAL_HEADER64_format__: _NAMED_STRUCTURE_FORMAT[
        Literal["IMAGE_OPTIONAL_HEADER64"]
    ] = ...
    __IMAGE_NT_HEADERS_format__: _NAMED_STRUCTURE_FORMAT[
        Literal["IMAGE_NT_HEADERS"]
    ] = ...
    __IMAGE_SECTION_HEADER_format__: _NAMED_STRUCTURE_FORMAT[
        Literal["IMAGE_SECTION_HEADER"]
    ] = ...
    __IMAGE_DELAY_IMPORT_DESCRIPTOR_format__: _NAMED_STRUCTURE_FORMAT[
        Literal["IMAGE_DELAY_IMPORT_DESCRIPTOR"]
    ] = ...
    __IMAGE_IMPORT_DESCRIPTOR_format__: _NAMED_STRUCTURE_FORMAT[
        Literal["IMAGE_IMPORT_DESCRIPTOR"]
    ] = ...
    __IMAGE_EXPORT_DIRECTORY_format__: _NAMED_STRUCTURE_FORMAT[
        Literal["IMAGE_EXPORT_DIRECTORY"]
    ] = ...
    __IMAGE_RESOURCE_DIRECTORY_format__: _NAMED_STRUCTURE_FORMAT[
        Literal["IMAGE_RESOURCE_DIRECTORY"]
    ] = ...
    __IMAGE_RESOURCE_DIRECTORY_ENTRY_format__: _NAMED_STRUCTURE_FORMAT[
        Literal["IMAGE_RESOURCE_DIRECTORY_ENTRY"]
    ] = ...
    __IMAGE_RESOURCE_DATA_ENTRY_format__: _NAMED_STRUCTURE_FORMAT[
        Literal["IMAGE_RESOURCE_DATA_ENTRY"]
    ] = ...
    __VS_VERSIONINFO_format__: _NAMED_STRUCTURE_FORMAT[Literal["VS_VERSIONINFO"]] = ...
    __VS_FIXEDFILEINFO_format__: _NAMED_STRUCTURE_FORMAT[
        Literal["VS_FIXEDFILEINFO"]
    ] = ...
    __StringFileInfo_format__: _NAMED_STRUCTURE_FORMAT[Literal["StringFileInfo"]] = ...
    __StringTable_format__: _NAMED_STRUCTURE_FORMAT[Literal["StringTable"]] = ...
    __String_format__: _NAMED_STRUCTURE_FORMAT[Literal["String"]] = ...
    __Var_format__: _NAMED_STRUCTURE_FORMAT[Literal["Var"]] = ...
    __IMAGE_THUNK_DATA_format__: _NAMED_STRUCTURE_FORMAT[
        Literal["IMAGE_THUNK_DATA"]
    ] = ...
    __IMAGE_THUNK_DATA64_format__: _NAMED_STRUCTURE_FORMAT[
        Literal["IMAGE_THUNK_DATA64"]
    ] = ...
    __IMAGE_DEBUG_DIRECTORY_format__: _NAMED_STRUCTURE_FORMAT[
        Literal["IMAGE_DEBUG_DIRECTORY"]
    ] = ...
    __IMAGE_BASE_RELOCATION_format__: _NAMED_STRUCTURE_FORMAT[
        Literal["IMAGE_BASE_RELOCATION"]
    ] = ...
    __IMAGE_BASE_RELOCATION_ENTRY_format__: _NAMED_STRUCTURE_FORMAT[
        Literal["IMAGE_BASE_RELOCATION_ENTRY"]
    ] = ...
    __IMAGE_IMPORT_CONTROL_TRANSFER_DYNAMIC_RELOCATION_format__: _NAMED_STRUCTURE_FORMAT[
        Literal["IMAGE_IMPORT_CONTROL_TRANSFER_DYNAMIC_RELOCATION"]
    ] = ...
    __IMAGE_INDIR_CONTROL_TRANSFER_DYNAMIC_RELOCATION_format__: _NAMED_STRUCTURE_FORMAT[
        Literal["IMAGE_INDIR_CONTROL_TRANSFER_DYNAMIC_RELOCATION"]
    ] = ...
    __IMAGE_SWITCHTABLE_BRANCH_DYNAMIC_RELOCATION_format__: _NAMED_STRUCTURE_FORMAT[
        Literal["IMAGE_SWITCHTABLE_BRANCH_DYNAMIC_RELOCATION"]
    ] = ...
    __IMAGE_FUNCTION_OVERRIDE_HEADER_format__: _NAMED_STRUCTURE_FORMAT[
        Literal["IMAGE_FUNCTION_OVERRIDE_HEADER"]
    ] = ...
    __IMAGE_FUNCTION_OVERRIDE_DYNAMIC_RELOCATION_format__: _NAMED_STRUCTURE_FORMAT[
        Literal["IMAGE_FUNCTION_OVERRIDE_DYNAMIC_RELOCATION"]
    ] = ...
    __IMAGE_BDD_INFO_format__: _NAMED_STRUCTURE_FORMAT[Literal["IMAGE_BDD_INFO"]] = ...
    __IMAGE_BDD_DYNAMIC_RELOCATION_format__: _NAMED_STRUCTURE_FORMAT[
        Literal["IMAGE_BDD_DYNAMIC_RELOCATION"]
    ] = ...
    __IMAGE_TLS_DIRECTORY_format__: _NAMED_STRUCTURE_FORMAT[
        Literal["IMAGE_TLS_DIRECTORY"]
    ] = ...
    __IMAGE_TLS_DIRECTORY64_format__: _NAMED_STRUCTURE_FORMAT[
        Literal["IMAGE_TLS_DIRECTORY64"]
    ] = ...
    __IMAGE_LOAD_CONFIG_DIRECTORY_format__: _NAMED_STRUCTURE_FORMAT[
        Literal["IMAGE_LOAD_CONFIG_DIRECTORY"]
    ] = ...
    __IMAGE_LOAD_CONFIG_DIRECTORY64_format__: _NAMED_STRUCTURE_FORMAT[
        Literal["IMAGE_LOAD_CONFIG_DIRECTORY64"]
    ] = ...
    __IMAGE_DYNAMIC_RELOCATION_TABLE_format__: _NAMED_STRUCTURE_FORMAT[
        Literal["IMAGE_DYNAMIC_RELOCATION_TABLE"]
    ] = ...
    __IMAGE_DYNAMIC_RELOCATION_format__: _NAMED_STRUCTURE_FORMAT[
        Literal["IMAGE_DYNAMIC_RELOCATION"]
    ] = ...
    __IMAGE_DYNAMIC_RELOCATION64_format__: _NAMED_STRUCTURE_FORMAT[
        Literal["IMAGE_DYNAMIC_RELOCATION64"]
    ] = ...
    __IMAGE_DYNAMIC_RELOCATION_V2_format__: _NAMED_STRUCTURE_FORMAT[
        Literal["IMAGE_DYNAMIC_RELOCATION_V2"]
    ] = ...
    __IMAGE_DYNAMIC_RELOCATION64_V2_format__: _NAMED_STRUCTURE_FORMAT[
        Literal["IMAGE_DYNAMIC_RELOCATION64_V2"]
    ] = ...
    __IMAGE_BOUND_IMPORT_DESCRIPTOR_format__: _NAMED_STRUCTURE_FORMAT[
        Literal["IMAGE_BOUND_IMPORT_DESCRIPTOR"]
    ] = ...
    __IMAGE_BOUND_FORWARDER_REF_format__: _NAMED_STRUCTURE_FORMAT[
        Literal["IMAGE_BOUND_FORWARDER_REF"]
    ] = ...
    __RUNTIME_FUNCTION_format__: _NAMED_STRUCTURE_FORMAT[
        Literal["RUNTIME_FUNCTION"]
    ] = ...

    DOS_HEADER: _DOS_Header
    OPTIONAL_HEADER: _Optional_Header
    NT_HEADERS: _NT_Headers
    FILE_HEADER: _File_Header

    sections: list[SectionStructure]

    DIRECTORY_ENTRY_IMPORT: list[ImportDescData]
    DIRECTORY_ENTRY_EXPORT: ExportDirData
    DIRECTORY_ENTRY_RESOURCE: ResourceDirData
    DIRECTORY_ENTRY_DEBUG: list[DebugData]
    DIRECTORY_ENTRY_BASERELOC: list[BaseRelocationData]
    DIRECTORY_ENTRY_TLS: TlsData
    DIRECTORY_ENTRY_BOUND_IMPORT: list[BoundImportDescData]

    DIRECTORY_ENTRY_LOAD_CONFIG: LoadConfigData
    DIRECTORY_ENTRY_EXCEPTION: list[ExceptionsDirEntryData]
    DIRECTORY_ENTRY_DELAY_IMPORT: list[ImportDescData]

    VS_VERSIONINFO: list[_VersionInfo]
    VS_FIXEDFILEINFO: list[_FixedFileInfo]
    FileInfo: list[list[_StringFileInfo]]

    __data__: bytes | mmap.mmap
    __structures__: list[Structure]

    @overload
    def __init__(
        self,
        name: str = ...,
        data: None = ...,
        fast_load: bool | None = ...,
        max_symbol_exports: int = ...,
        max_repeated_symbol: int = ...,
    ) -> None: ...
    @overload
    def __init__(
        self,
        name: None = ...,
        data: _DATA_TYPE = ...,
        fast_load: bool | None = ...,
        max_symbol_exports: int = ...,
        max_repeated_symbol: int = ...,
    ) -> None: ...
    def __enter__(self) -> Self: ...
    def __exit__(
        self,
        type: type[BaseException] | None,
        value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None: ...
    def close(self) -> None: ...
    @overload
    def __unpack_data__(
        self,
        format: _NAMED_STRUCTURE_FORMAT[Literal["IMAGE_DOS_HEADER"]],
        data: _DATA_TYPE,
        file_offset: int,
    ) -> _DOS_Header | None: ...
    @overload
    def __unpack_data__(
        self,
        format: _NAMED_STRUCTURE_FORMAT[Literal["IMAGE_FILE_HEADER"]],
        data: _DATA_TYPE,
        file_offset: int,
    ) -> _File_Header | None: ...
    @overload
    def __unpack_data__(
        self,
        format: _NAMED_STRUCTURE_FORMAT[Literal["IMAGE_DATA_DIRECTORY"]],
        data: _DATA_TYPE,
        file_offset: int,
    ) -> _Data_Directory | None: ...
    @overload
    def __unpack_data__(
        self,
        format: _NAMED_STRUCTURE_FORMAT[Literal["IMAGE_OPTIONAL_HEADER"]],
        data: _DATA_TYPE,
        file_offset: int,
    ) -> _Optional_Header32 | None: ...
    @overload
    def __unpack_data__(
        self,
        format: _NAMED_STRUCTURE_FORMAT[Literal["IMAGE_OPTIONAL_HEADER64"]],
        data: _DATA_TYPE,
        file_offset: int,
    ) -> _Optional_Header64 | None: ...
    @overload
    def __unpack_data__(
        self,
        format: _NAMED_STRUCTURE_FORMAT[Literal["IMAGE_NT_HEADERS"]],
        data: _DATA_TYPE,
        file_offset: int,
    ) -> _NT_Headers | None: ...
    @overload
    def __unpack_data__(
        self,
        format: _NAMED_STRUCTURE_FORMAT[Literal["IMAGE_DELAY_IMPORT_DESCRIPTOR"]],
        data: _DATA_TYPE,
        file_offset: int,
    ) -> _Delay_Import_Descriptor | None: ...
    @overload
    def __unpack_data__(
        self,
        format: _NAMED_STRUCTURE_FORMAT[Literal["IMAGE_IMPORT_DESCRIPTOR"]],
        data: _DATA_TYPE,
        file_offset: int,
    ) -> _Import_Descriptor | None: ...
    @overload
    def __unpack_data__(
        self,
        format: _NAMED_STRUCTURE_FORMAT[Literal["IMAGE_EXPORT_DIRECTORY"]],
        data: _DATA_TYPE,
        file_offset: int,
    ) -> _Export_Directory | None: ...
    @overload
    def __unpack_data__(
        self,
        format: _NAMED_STRUCTURE_FORMAT[Literal["IMAGE_RESOURCE_DIRECTORY"]],
        data: _DATA_TYPE,
        file_offset: int,
    ) -> _Resource_Directory | None: ...
    @overload
    def __unpack_data__(
        self,
        format: _NAMED_STRUCTURE_FORMAT[Literal["IMAGE_RESOURCE_DIRECTORY_ENTRY"]],
        data: _DATA_TYPE,
        file_offset: int,
    ) -> _Resource_Directory_Entry | None: ...
    @overload
    def __unpack_data__(
        self,
        format: _NAMED_STRUCTURE_FORMAT[Literal["IMAGE_RESOURCE_DATA_ENTRY"]],
        data: _DATA_TYPE,
        file_offset: int,
    ) -> _Resource_Data_Entry | None: ...
    @overload
    def __unpack_data__(
        self,
        format: _NAMED_STRUCTURE_FORMAT[Literal["VS_VERSIONINFO"]],
        data: _DATA_TYPE,
        file_offset: int,
    ) -> _VersionInfo | None: ...
    @overload
    def __unpack_data__(
        self,
        format: _NAMED_STRUCTURE_FORMAT[Literal["VS_FIXEDFILEINFO"]],
        data: _DATA_TYPE,
        file_offset: int,
    ) -> _FixedFileInfo | None: ...
    @overload
    def __unpack_data__(
        self,
        format: _NAMED_STRUCTURE_FORMAT[Literal["StringFileInfo"]],
        data: _DATA_TYPE,
        file_offset: int,
    ) -> _StringFileInfo | None: ...
    @overload
    def __unpack_data__(
        self,
        format: _NAMED_STRUCTURE_FORMAT[Literal["StringTable"]],
        data: _DATA_TYPE,
        file_offset: int,
    ) -> _StringTable | None: ...
    @overload
    def __unpack_data__(
        self,
        format: _NAMED_STRUCTURE_FORMAT[Literal["String"]],
        data: _DATA_TYPE,
        file_offset: int,
    ) -> _String | None: ...
    @overload
    def __unpack_data__(
        self,
        format: _NAMED_STRUCTURE_FORMAT[Literal["VarFileInfo"]],
        data: _DATA_TYPE,
        file_offset: int,
    ) -> _VarFileInfo | None: ...
    @overload
    def __unpack_data__(
        self,
        format: _NAMED_STRUCTURE_FORMAT[Literal["RUNTIME_FUNCTION"]],
        data: _DATA_TYPE,
        file_offset: int,
    ) -> _Runtime_Function | None: ...
    @overload
    def __unpack_data__(
        self,
        format: _NAMED_STRUCTURE_FORMAT[Literal["IMAGE_BOUND_FORWARDER_REF"]],
        data: _DATA_TYPE,
        file_offset: int,
    ) -> _Bound_Forwarder_Ref | None: ...
    @overload
    def __unpack_data__(
        self,
        format: _NAMED_STRUCTURE_FORMAT[Literal["Var"]],
        data: _DATA_TYPE,
        file_offset: int,
    ) -> _Var | None: ...
    @overload
    def __unpack_data__(
        self,
        format: _NAMED_STRUCTURE_FORMAT[Literal["IMAGE_THUNK_DATA"]],
        data: _DATA_TYPE,
        file_offset: int,
    ) -> _Thunk_Data32 | _Thunk_Data64 | None: ...
    @overload
    def __unpack_data__(
        self,
        format: _NAMED_STRUCTURE_FORMAT[Literal["IMAGE_DEBUG_DIRECTORY"]],
        data: _DATA_TYPE,
        file_offset: int,
    ) -> _Debug_Directory | None: ...
    @overload
    def __unpack_data__(
        self,
        format: _NAMED_STRUCTURE_FORMAT[Literal["IMAGE_BASE_RELOCATION"]],
        data: _DATA_TYPE,
        file_offset: int,
    ) -> _Base_Relocation | None: ...
    @overload
    def __unpack_data__(
        self,
        format: _NAMED_STRUCTURE_FORMAT[Literal["IMAGE_BASE_RELOCATION_ENTRY"]],
        data: _DATA_TYPE,
        file_offset: int,
    ) -> _Base_Relocation_Entry | None: ...
    @overload
    def __unpack_data__(
        self,
        format: tuple[
            Literal["IMAGE_IMPORT_CONTROL_TRANSFER_DYNAMIC_RELOCATION"], tuple[str, ...]
        ],
        data: _DATA_TYPE,
        file_offset: int,
    ) -> _Import_Control_Transfer_Dynamic_Relocation | None: ...
    @overload
    def __unpack_data__(
        self,
        format: tuple[
            Literal["IMAGE_INDIR_CONTROL_TRANSFER_DYNAMIC_RELOCATION"], tuple[str, ...]
        ],
        data: _DATA_TYPE,
        file_offset: int,
    ) -> _Indir_Control_Transfer_Dynamic_Relocation | None: ...
    @overload
    def __unpack_data__(
        self,
        format: tuple[
            Literal["IMAGE_SWITCHTABLE_BRANCH_DYNAMIC_RELOCATION"], tuple[str, ...]
        ],
        data: _DATA_TYPE,
        file_offset: int,
    ) -> _Switchtable_Branch_Dynamic_Relocation | None: ...
    @overload
    def __unpack_data__(
        self,
        format: _NAMED_STRUCTURE_FORMAT[Literal["IMAGE_FUNCTION_OVERRIDE_HEADER"]],
        data: _DATA_TYPE,
        file_offset: int,
    ) -> _Function_Override_Header | None: ...
    @overload
    def __unpack_data__(
        self,
        format: tuple[
            Literal["IMAGE_FUNCTION_OVERRIDE_DYNAMIC_RELOCATION"], tuple[str, ...]
        ],
        data: _DATA_TYPE,
        file_offset: int,
    ) -> _Function_Override_Dynamic_Relocation | None: ...
    @overload
    def __unpack_data__(
        self,
        format: _NAMED_STRUCTURE_FORMAT[Literal["IMAGE_BDD_INFO"]],
        data: _DATA_TYPE,
        file_offset: int,
    ) -> _BDD_Info | None: ...
    @overload
    def __unpack_data__(
        self,
        format: _NAMED_STRUCTURE_FORMAT[Literal["IMAGE_BDD_DYNAMIC_RELOCATION"]],
        data: _DATA_TYPE,
        file_offset: int,
    ) -> _BDD_Dynamic_Relocation | None: ...
    @overload
    def __unpack_data__(
        self,
        format: _NAMED_STRUCTURE_FORMAT[Literal["IMAGE_LOAD_CONFIG_DIRECTORY"]],
        data: _DATA_TYPE,
        file_offset: int,
    ) -> _Load_Config_Directory32 | _Load_Config_Directory64 | None: ...
    @overload
    def __unpack_data__(
        self,
        format: _NAMED_STRUCTURE_FORMAT[Literal["IMAGE_DYNAMIC_RELOCATION_TABLE"]],
        data: _DATA_TYPE,
        file_offset: int,
    ) -> _Dynamic_Relocation_Table | None: ...
    @overload
    def __unpack_data__(
        self,
        format: _NAMED_STRUCTURE_FORMAT[Literal["IMAGE_DYNAMIC_RELOCATION"]],
        data: _DATA_TYPE,
        file_offset: int,
    ) -> _Dynamic_Relocation32 | None: ...
    @overload
    def __unpack_data__(
        self,
        format: _NAMED_STRUCTURE_FORMAT[Literal["IMAGE_DYNAMIC_RELOCATION64"]],
        data: _DATA_TYPE,
        file_offset: int,
    ) -> _Dynamic_Relocation64 | None: ...
    @overload
    def __unpack_data__(
        self,
        format: _NAMED_STRUCTURE_FORMAT[Literal["IMAGE_DYNAMIC_RELOCATION_V2"]],
        data: _DATA_TYPE,
        file_offset: int,
    ) -> _Dynamic_Relocation32_V2 | None: ...
    @overload
    def __unpack_data__(
        self,
        format: _NAMED_STRUCTURE_FORMAT[Literal["IMAGE_DYNAMIC_RELOCATION64_V2"]],
        data: _DATA_TYPE,
        file_offset: int,
    ) -> _Dynamic_Relocation64_V2 | None: ...
    @overload
    def __unpack_data__(
        self,
        format: _NAMED_STRUCTURE_FORMAT[Literal["IMAGE_TLS_DIRECTORY"]],
        data: _DATA_TYPE,
        file_offset: int,
    ) -> _TLS_Directory | None: ...
    @overload
    def __unpack_data__(
        self,
        format: _NAMED_STRUCTURE_FORMAT[Literal["IMAGE_BOUND_IMPORT_DESCRIPTOR"]],
        data: _DATA_TYPE,
        file_offset: int,
    ) -> _Bound_Import_Descriptor | None: ...
    @overload
    def __unpack_data__(
        self,
        format: _NAMED_STRUCTURE_FORMAT[Literal["IMAGE_DEBUG_MISC"]],
        data: _DATA_TYPE,
        file_offset: int,
    ) -> _Debug_Misc | None: ...
    @overload
    def __unpack_data__(
        self,
        format: _NAMED_STRUCTURE_FORMAT[Literal["CV_INFO_PDB20"]],
        data: _DATA_TYPE,
        file_offset: int,
    ) -> _CV_Info_PDB20 | None: ...
    @overload
    def __unpack_data__(
        self,
        format: _NAMED_STRUCTURE_FORMAT[Literal["CV_INFO_PDB70"]],
        data: _DATA_TYPE,
        file_offset: int,
    ) -> _CV_Info_PDB70 | None: ...
    @overload
    def __unpack_data__(
        self, format: _STRUCTURE_FORMAT, data: _DATA_TYPE, file_offset: int
    ) -> Structure | None: ...
    @overload
    def __unpack_data_with_bitfields__(
        self,
        format: _NAMED_STRUCTURE_FORMAT[
            Literal["IMAGE_IMPORT_CONTROL_TRANSFER_DYNAMIC_RELOCATION"]
        ],
        data: _DATA_TYPE,
        file_offset: int,
    ) -> _Import_Control_Transfer_Dynamic_Relocation | None: ...
    @overload
    def __unpack_data_with_bitfields__(
        self,
        format: _NAMED_STRUCTURE_FORMAT[
            Literal["IMAGE_INDIR_CONTROL_TRANSFER_DYNAMIC_RELOCATION"]
        ],
        data: _DATA_TYPE,
        file_offset: int,
    ) -> _Indir_Control_Transfer_Dynamic_Relocation | None: ...
    @overload
    def __unpack_data_with_bitfields__(
        self,
        format: _NAMED_STRUCTURE_FORMAT[
            Literal["IMAGE_SWITCHTABLE_BRANCH_DYNAMIC_RELOCATION"]
        ],
        data: _DATA_TYPE,
        file_offset: int,
    ) -> _Switchtable_Branch_Dynamic_Relocation | None: ...
    @overload
    def __unpack_data_with_bitfields__(
        self, format: _STRUCTURE_FORMAT, data: _DATA_TYPE, file_offset: int
    ) -> StructureWithBitfields | None: ...
    @overload
    def __parse__(self, fname: str, data: None, fast_load: bool) -> None: ...
    @overload
    def __parse__(self, fname: None, data: _DATA_TYPE, fast_load: bool) -> None: ...
    def parse_rich_header(self) -> dict[str, bytes] | None: ...
    def get_warnings(self) -> list[str]: ...
    def show_warnings(self) -> None: ...
    def full_load(self) -> None: ...
    @overload
    def write(self) -> bytearray: ...
    @overload
    def write(self, filename: str) -> None: ...
    @overload
    def write(self, filename: None = ...) -> bytearray: ...
    def parse_sections(self, offset: int) -> None: ...
    def parse_data_directories(
        self,
        directories: list[int] | None = ...,
        forwarded_exports_only: bool = ...,
        import_dllnames_only: bool = ...,
    ) -> None: ...
    def parse_exceptions_directory(
        self, rva: int, size: int
    ) -> list[ExceptionsDirEntryData] | None: ...
    def parse_directory_bound_imports(
        self, rva: int, size: int
    ) -> list[ImportData] | None: ...
    def parse_directory_tls(self, rva: int, size: int) -> TlsData | None: ...
    def parse_directory_load_config(
        self, rva: int, size: int
    ) -> LoadConfigData | None: ...
    def parse_dynamic_relocations(
        self,
        dynamic_value_reloc_table_offset: int,
        dynamic_value_reloc_table_section: int,
    ) -> list[DynamicRelocationData] | None: ...
    def parse_function_override_data(self, rva: int) -> list[FunctionOverrideData]: ...
    def parse_relocations_directory(
        self, rva: int, size: int
    ) -> list[BaseRelocationData]: ...
    def parse_image_base_relocation_list(
        self, rva: int, size: int, fmt: _STRUCTURE_FORMAT | None = ...
    ) -> list[BaseRelocationData]: ...
    def parse_relocations(
        self, data_rva: int, rva: int, size: int
    ) -> list[RelocationData]: ...
    def parse_relocations_with_format(
        self, data_rva: int, rva: int, size: int, format: _STRUCTURE_FORMAT | None
    ) -> list[RelocationData]: ...
    def parse_debug_directory(self, rva: int, size: int) -> list[DebugData] | None: ...
    def parse_resources_directory(
        self,
        rva: int,
        size: int = ...,
        base_rva: int | None = ...,
        level: int = ...,
        dirs: list[int] | None = ...,
    ) -> ResourceDirData | None: ...
    def parse_resource_data_entry(self, rva: int) -> _Resource_Data_Entry | None: ...
    def parse_resource_entry(self, rva: int) -> _Resource_Directory_Entry | None: ...
    def parse_version_information(
        self, version_struct: _Resource_Data_Entry
    ) -> None: ...
    def parse_export_directory(
        self, rva: int, size: int, forwarded_only: bool = ...
    ) -> ExportDirData | None: ...
    def dword_align(self, offset: int, base: int) -> int: ...
    def normalize_import_va(self, va: int) -> int: ...
    def parse_delay_import_directory(
        self, rva: int, size: int
    ) -> list[ImportDescData]: ...
    def get_rich_header_hash(
        self,
        algorithm: Literal["md5", "sha1", "sha256", "sha512"] = ...,
    ) -> _Hash: ...
    def get_imphash(self) -> str: ...
    def get_exphash(self) -> str: ...
    def parse_import_directory(
        self, rva: int, size: int, dllnames_only: bool = ...
    ) -> list[ImportDescData]: ...
    def parse_imports(
        self,
        original_first_thunk: int,
        first_thunk: int,
        forwarder_chain: Any | None,
        max_length: int | None = ...,
        contains_addresses: bool = ...,
    ) -> list[ImportData]: ...
    def get_import_table(
        self, rva: int, max_length: int | None = ..., contains_addresses: bool = ...
    ) -> list[_Thunk_Data] | None: ...
    def get_memory_mapped_image(
        self, max_virtual_address: int = ..., ImageBase: int | None = ...
    ) -> bytes: ...
    def get_resources_strings(self) -> list[str]: ...
    def get_data(self, rva: int = ..., length: int | None = ...) -> bytes: ...
    def get_rva_from_offset(self, offset: int) -> int: ...
    def get_offset_from_rva(self, rva: int) -> int: ...
    @overload
    def get_string_at_rva(self, rva: None, max_length: int | None) -> None: ...
    @overload
    def get_string_at_rva(self, rva: int, max_length: int | None = ...) -> bytes: ...
    def get_bytes_from_data(self, offset: int, data: _DATA_TYPE) -> bytes: ...
    def get_string_from_data(self, offset: int, data: _DATA_TYPE) -> bytes: ...
    def get_string_u_at_rva(
        self, rva: int, max_length: int | None = ..., encoding: str | None = ...
    ) -> bytes: ...
    def get_section_by_offset(self, offset: int) -> SectionStructure | None: ...
    def get_section_by_rva(self, rva: int) -> SectionStructure | None: ...
    def __str__(self) -> str: ...
    def has_relocs(self) -> bool: ...
    def has_dynamic_relocs(self) -> bool: ...
    def print_info(self, encoding: str | None = ...) -> None: ...
    def dump_info(self, dump: Dump | None = ..., encoding: str | None = ...) -> str: ...
    def dump_dict(self) -> dict[str, Any]: ...
    def get_physical_by_rva(self, rva: int) -> int: ...
    def get_data_from_dword(self, dword: _DWORD) -> bytes: ...
    def get_dword_from_data(self, data: _DATA_TYPE, offset: int) -> _DWORD | None: ...
    def get_dword_at_rva(self, rva: int) -> _DWORD | None: ...
    def get_dword_from_offset(self, offset: int) -> _DWORD | None: ...
    def set_dword_at_rva(self, rva: int, dword: _DWORD) -> bool: ...
    def set_dword_at_offset(self, offset: int, dword: _DWORD) -> bool: ...
    def get_data_from_word(self, word: _WORD) -> bytes: ...
    def get_word_from_data(self, data: _DATA_TYPE, offset: int) -> _WORD | None: ...
    def get_word_at_rva(self, rva: int) -> _WORD | None: ...
    def get_word_from_offset(self, offset: int) -> _WORD | None: ...
    def set_word_at_rva(self, rva: int, word: _WORD) -> bool: ...
    def set_word_at_offset(self, offset: int, word: _WORD) -> bool: ...
    def get_data_from_qword(self, word: _QWORD) -> bytes: ...
    def get_qword_from_data(self, data: _DATA_TYPE, offset: int) -> _QWORD | None: ...
    def get_qword_at_rva(self, rva: int) -> _QWORD | None: ...
    def get_qword_from_offset(self, offset: int) -> _QWORD | None: ...
    def set_qword_at_rva(self, rva: int, qword: _QWORD) -> bool: ...
    def set_qword_at_offset(self, offset: int, qword: _QWORD) -> bool: ...
    def set_bytes_at_rva(self, rva: int, data: _DATA_TYPE) -> bool: ...
    def set_bytes_at_offset(self, offset: int, data: _DATA_TYPE) -> bool: ...
    def set_data_bytes(self, offset: int, data: _DATA_TYPE) -> None: ...
    def merge_modified_section_data(self) -> None: ...
    def relocate_image(self, new_ImageBase: int) -> None: ...
    def verify_checksum(self) -> bool: ...
    def generate_checksum(self) -> int: ...
    def is_exe(self) -> bool: ...
    def is_dll(self) -> bool: ...
    def is_driver(self) -> bool: ...
    def get_overlay_data_start_offset(self) -> int | None: ...
    def get_overlay(self) -> bytes | None: ...
    def trim(self) -> bytes: ...
    def adjust_FileAlignment(self, val: int, file_alignment: int) -> int: ...
    def adjust_SectionAlignment(
        self, val: int, section_alignment: int, file_alignment: int
    ) -> int: ...

def main() -> None: ...

if __name__ == "__main__": ...
