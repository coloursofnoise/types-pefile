# fmt: off
"""
THIS FILE WAS AUTOMATICALLY GENERATED BASED ON pefile 2023.2.7

Copyright (C) 2023  coloursofnoise

This software is licensed under the GNU General Public License, version 3 or
later (GPLv3+). A full copy of the license is available in the COPYING file
located at the root of the project, or at <https://www.gnu.org/licenses/>.
"""

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


class DIRECTORY_ENTRY_DICT(_NAME_LOOKUP[int, str]):
    @overload
    def __getitem__(self, key: Literal[0]) -> Literal["IMAGE_DIRECTORY_ENTRY_EXPORT"]:...

    @overload
    def __getitem__(self, key: Literal[1]) -> Literal["IMAGE_DIRECTORY_ENTRY_IMPORT"]:...

    @overload
    def __getitem__(self, key: Literal[2]) -> Literal["IMAGE_DIRECTORY_ENTRY_RESOURCE"]:...

    @overload
    def __getitem__(self, key: Literal[3]) -> Literal["IMAGE_DIRECTORY_ENTRY_EXCEPTION"]:...

    @overload
    def __getitem__(self, key: Literal[4]) -> Literal["IMAGE_DIRECTORY_ENTRY_SECURITY"]:...

    @overload
    def __getitem__(self, key: Literal[5]) -> Literal["IMAGE_DIRECTORY_ENTRY_BASERELOC"]:...

    @overload
    def __getitem__(self, key: Literal[6]) -> Literal["IMAGE_DIRECTORY_ENTRY_DEBUG"]:...

    @overload
    def __getitem__(self, key: Literal[7]) -> Literal["IMAGE_DIRECTORY_ENTRY_COPYRIGHT"]:...

    @overload
    def __getitem__(self, key: Literal[8]) -> Literal["IMAGE_DIRECTORY_ENTRY_GLOBALPTR"]:...

    @overload
    def __getitem__(self, key: Literal[9]) -> Literal["IMAGE_DIRECTORY_ENTRY_TLS"]:...

    @overload
    def __getitem__(self, key: Literal[10]) -> Literal["IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG"]:...

    @overload
    def __getitem__(self, key: Literal[11]) -> Literal["IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT"]:...

    @overload
    def __getitem__(self, key: Literal[12]) -> Literal["IMAGE_DIRECTORY_ENTRY_IAT"]:...

    @overload
    def __getitem__(self, key: Literal[13]) -> Literal["IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT"]:...

    @overload
    def __getitem__(self, key: Literal[14]) -> Literal["IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR"]:...

    @overload
    def __getitem__(self, key: Literal[15]) -> Literal["IMAGE_DIRECTORY_ENTRY_RESERVED"]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_DIRECTORY_ENTRY_EXPORT"]) -> Literal[0]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_DIRECTORY_ENTRY_IMPORT"]) -> Literal[1]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_DIRECTORY_ENTRY_RESOURCE"]) -> Literal[2]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_DIRECTORY_ENTRY_EXCEPTION"]) -> Literal[3]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_DIRECTORY_ENTRY_SECURITY"]) -> Literal[4]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_DIRECTORY_ENTRY_BASERELOC"]) -> Literal[5]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_DIRECTORY_ENTRY_DEBUG"]) -> Literal[6]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_DIRECTORY_ENTRY_COPYRIGHT"]) -> Literal[7]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_DIRECTORY_ENTRY_GLOBALPTR"]) -> Literal[8]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_DIRECTORY_ENTRY_TLS"]) -> Literal[9]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG"]) -> Literal[10]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT"]) -> Literal[11]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_DIRECTORY_ENTRY_IAT"]) -> Literal[12]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT"]) -> Literal[13]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR"]) -> Literal[14]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_DIRECTORY_ENTRY_RESERVED"]) -> Literal[15]:...
DIRECTORY_ENTRY_DICT_NAMES = Literal[
    "IMAGE_DIRECTORY_ENTRY_BASERELOC",
    "IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT",
    "IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR",
    "IMAGE_DIRECTORY_ENTRY_COPYRIGHT",
    "IMAGE_DIRECTORY_ENTRY_DEBUG",
    "IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT",
    "IMAGE_DIRECTORY_ENTRY_EXCEPTION",
    "IMAGE_DIRECTORY_ENTRY_EXPORT",
    "IMAGE_DIRECTORY_ENTRY_GLOBALPTR",
    "IMAGE_DIRECTORY_ENTRY_IAT",
    "IMAGE_DIRECTORY_ENTRY_IMPORT",
    "IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG",
    "IMAGE_DIRECTORY_ENTRY_RESERVED",
    "IMAGE_DIRECTORY_ENTRY_RESOURCE",
    "IMAGE_DIRECTORY_ENTRY_SECURITY",
    "IMAGE_DIRECTORY_ENTRY_TLS",
]
DIRECTORY_ENTRY_DICT_VALUES = Literal[
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
class IMAGE_CHARACTERISTICS_DICT(_NAME_LOOKUP[int, str]):
    @overload
    def __getitem__(self, key: Literal[0x0001]) -> Literal["IMAGE_FILE_RELOCS_STRIPPED"]:...

    @overload
    def __getitem__(self, key: Literal[0x0002]) -> Literal["IMAGE_FILE_EXECUTABLE_IMAGE"]:...

    @overload
    def __getitem__(self, key: Literal[0x0004]) -> Literal["IMAGE_FILE_LINE_NUMS_STRIPPED"]:...

    @overload
    def __getitem__(self, key: Literal[0x0008]) -> Literal["IMAGE_FILE_LOCAL_SYMS_STRIPPED"]:...

    @overload
    def __getitem__(self, key: Literal[0x0010]) -> Literal["IMAGE_FILE_AGGRESIVE_WS_TRIM"]:...

    @overload
    def __getitem__(self, key: Literal[0x0020]) -> Literal["IMAGE_FILE_LARGE_ADDRESS_AWARE"]:...

    @overload
    def __getitem__(self, key: Literal[0x0040]) -> Literal["IMAGE_FILE_16BIT_MACHINE"]:...

    @overload
    def __getitem__(self, key: Literal[0x0080]) -> Literal["IMAGE_FILE_BYTES_REVERSED_LO"]:...

    @overload
    def __getitem__(self, key: Literal[0x0100]) -> Literal["IMAGE_FILE_32BIT_MACHINE"]:...

    @overload
    def __getitem__(self, key: Literal[0x0200]) -> Literal["IMAGE_FILE_DEBUG_STRIPPED"]:...

    @overload
    def __getitem__(self, key: Literal[0x0400]) -> Literal["IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP"]:...

    @overload
    def __getitem__(self, key: Literal[0x0800]) -> Literal["IMAGE_FILE_NET_RUN_FROM_SWAP"]:...

    @overload
    def __getitem__(self, key: Literal[0x1000]) -> Literal["IMAGE_FILE_SYSTEM"]:...

    @overload
    def __getitem__(self, key: Literal[0x2000]) -> Literal["IMAGE_FILE_DLL"]:...

    @overload
    def __getitem__(self, key: Literal[0x4000]) -> Literal["IMAGE_FILE_UP_SYSTEM_ONLY"]:...

    @overload
    def __getitem__(self, key: Literal[0x8000]) -> Literal["IMAGE_FILE_BYTES_REVERSED_HI"]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_FILE_RELOCS_STRIPPED"]) -> Literal[0x0001]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_FILE_EXECUTABLE_IMAGE"]) -> Literal[0x0002]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_FILE_LINE_NUMS_STRIPPED"]) -> Literal[0x0004]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_FILE_LOCAL_SYMS_STRIPPED"]) -> Literal[0x0008]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_FILE_AGGRESIVE_WS_TRIM"]) -> Literal[0x0010]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_FILE_LARGE_ADDRESS_AWARE"]) -> Literal[0x0020]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_FILE_16BIT_MACHINE"]) -> Literal[0x0040]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_FILE_BYTES_REVERSED_LO"]) -> Literal[0x0080]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_FILE_32BIT_MACHINE"]) -> Literal[0x0100]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_FILE_DEBUG_STRIPPED"]) -> Literal[0x0200]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP"]) -> Literal[0x0400]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_FILE_NET_RUN_FROM_SWAP"]) -> Literal[0x0800]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_FILE_SYSTEM"]) -> Literal[0x1000]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_FILE_DLL"]) -> Literal[0x2000]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_FILE_UP_SYSTEM_ONLY"]) -> Literal[0x4000]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_FILE_BYTES_REVERSED_HI"]) -> Literal[0x8000]:...
IMAGE_CHARACTERISTICS_DICT_NAMES = Literal[
    "IMAGE_FILE_16BIT_MACHINE",
    "IMAGE_FILE_32BIT_MACHINE",
    "IMAGE_FILE_AGGRESIVE_WS_TRIM",
    "IMAGE_FILE_BYTES_REVERSED_HI",
    "IMAGE_FILE_BYTES_REVERSED_LO",
    "IMAGE_FILE_DEBUG_STRIPPED",
    "IMAGE_FILE_DLL",
    "IMAGE_FILE_EXECUTABLE_IMAGE",
    "IMAGE_FILE_LARGE_ADDRESS_AWARE",
    "IMAGE_FILE_LINE_NUMS_STRIPPED",
    "IMAGE_FILE_LOCAL_SYMS_STRIPPED",
    "IMAGE_FILE_NET_RUN_FROM_SWAP",
    "IMAGE_FILE_RELOCS_STRIPPED",
    "IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP",
    "IMAGE_FILE_SYSTEM",
    "IMAGE_FILE_UP_SYSTEM_ONLY",
]
IMAGE_CHARACTERISTICS_DICT_VALUES = Literal[
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
class SECTION_CHARACTERISTICS_DICT(_NAME_LOOKUP[int, str]):
    @overload
    def __getitem__(self, key: Literal[0x00000000]) -> Literal["IMAGE_SCN_TYPE_REG"]:...

    @overload
    def __getitem__(self, key: Literal[0x00000001]) -> Literal["IMAGE_SCN_TYPE_DSECT"]:...

    @overload
    def __getitem__(self, key: Literal[0x00000002]) -> Literal["IMAGE_SCN_TYPE_NOLOAD"]:...

    @overload
    def __getitem__(self, key: Literal[0x00000004]) -> Literal["IMAGE_SCN_TYPE_GROUP"]:...

    @overload
    def __getitem__(self, key: Literal[0x00000008]) -> Literal["IMAGE_SCN_TYPE_NO_PAD"]:...

    @overload
    def __getitem__(self, key: Literal[0x00000010]) -> Literal["IMAGE_SCN_TYPE_COPY"]:...

    @overload
    def __getitem__(self, key: Literal[0x00000020]) -> Literal["IMAGE_SCN_CNT_CODE"]:...

    @overload
    def __getitem__(self, key: Literal[0x00000040]) -> Literal["IMAGE_SCN_CNT_INITIALIZED_DATA"]:...

    @overload
    def __getitem__(self, key: Literal[0x00000080]) -> Literal["IMAGE_SCN_CNT_UNINITIALIZED_DATA"]:...

    @overload
    def __getitem__(self, key: Literal[0x00000100]) -> Literal["IMAGE_SCN_LNK_OTHER"]:...

    @overload
    def __getitem__(self, key: Literal[0x00000200]) -> Literal["IMAGE_SCN_LNK_INFO"]:...

    @overload
    def __getitem__(self, key: Literal[0x00000400]) -> Literal["IMAGE_SCN_LNK_OVER"]:...

    @overload
    def __getitem__(self, key: Literal[0x00000800]) -> Literal["IMAGE_SCN_LNK_REMOVE"]:...

    @overload
    def __getitem__(self, key: Literal[0x00001000]) -> Literal["IMAGE_SCN_LNK_COMDAT"]:...

    @overload
    def __getitem__(self, key: Literal[0x00004000]) -> Literal["IMAGE_SCN_NO_DEFER_SPEC_EXC"]:...

    @overload
    def __getitem__(self, key: Literal[0x00008000]) -> Literal["IMAGE_SCN_MEM_FARDATA"]:...

    @overload
    def __getitem__(self, key: Literal[0x00010000]) -> Literal["IMAGE_SCN_MEM_SYSHEAP"]:...

    @overload
    def __getitem__(self, key: Literal[0x00020000]) -> Literal["IMAGE_SCN_MEM_16BIT"]:...

    @overload
    def __getitem__(self, key: Literal[0x00040000]) -> Literal["IMAGE_SCN_MEM_LOCKED"]:...

    @overload
    def __getitem__(self, key: Literal[0x00080000]) -> Literal["IMAGE_SCN_MEM_PRELOAD"]:...

    @overload
    def __getitem__(self, key: Literal[0x00100000]) -> Literal["IMAGE_SCN_ALIGN_1BYTES"]:...

    @overload
    def __getitem__(self, key: Literal[0x00200000]) -> Literal["IMAGE_SCN_ALIGN_2BYTES"]:...

    @overload
    def __getitem__(self, key: Literal[0x00300000]) -> Literal["IMAGE_SCN_ALIGN_4BYTES"]:...

    @overload
    def __getitem__(self, key: Literal[0x00400000]) -> Literal["IMAGE_SCN_ALIGN_8BYTES"]:...

    @overload
    def __getitem__(self, key: Literal[0x00500000]) -> Literal["IMAGE_SCN_ALIGN_16BYTES"]:...

    @overload
    def __getitem__(self, key: Literal[0x00600000]) -> Literal["IMAGE_SCN_ALIGN_32BYTES"]:...

    @overload
    def __getitem__(self, key: Literal[0x00700000]) -> Literal["IMAGE_SCN_ALIGN_64BYTES"]:...

    @overload
    def __getitem__(self, key: Literal[0x00800000]) -> Literal["IMAGE_SCN_ALIGN_128BYTES"]:...

    @overload
    def __getitem__(self, key: Literal[0x00900000]) -> Literal["IMAGE_SCN_ALIGN_256BYTES"]:...

    @overload
    def __getitem__(self, key: Literal[0x00A00000]) -> Literal["IMAGE_SCN_ALIGN_512BYTES"]:...

    @overload
    def __getitem__(self, key: Literal[0x00B00000]) -> Literal["IMAGE_SCN_ALIGN_1024BYTES"]:...

    @overload
    def __getitem__(self, key: Literal[0x00C00000]) -> Literal["IMAGE_SCN_ALIGN_2048BYTES"]:...

    @overload
    def __getitem__(self, key: Literal[0x00D00000]) -> Literal["IMAGE_SCN_ALIGN_4096BYTES"]:...

    @overload
    def __getitem__(self, key: Literal[0x00E00000]) -> Literal["IMAGE_SCN_ALIGN_8192BYTES"]:...

    @overload
    def __getitem__(self, key: Literal[0x00F00000]) -> Literal["IMAGE_SCN_ALIGN_MASK"]:...

    @overload
    def __getitem__(self, key: Literal[0x01000000]) -> Literal["IMAGE_SCN_LNK_NRELOC_OVFL"]:...

    @overload
    def __getitem__(self, key: Literal[0x02000000]) -> Literal["IMAGE_SCN_MEM_DISCARDABLE"]:...

    @overload
    def __getitem__(self, key: Literal[0x04000000]) -> Literal["IMAGE_SCN_MEM_NOT_CACHED"]:...

    @overload
    def __getitem__(self, key: Literal[0x08000000]) -> Literal["IMAGE_SCN_MEM_NOT_PAGED"]:...

    @overload
    def __getitem__(self, key: Literal[0x10000000]) -> Literal["IMAGE_SCN_MEM_SHARED"]:...

    @overload
    def __getitem__(self, key: Literal[0x20000000]) -> Literal["IMAGE_SCN_MEM_EXECUTE"]:...

    @overload
    def __getitem__(self, key: Literal[0x40000000]) -> Literal["IMAGE_SCN_MEM_READ"]:...

    @overload
    def __getitem__(self, key: Literal[0x80000000]) -> Literal["IMAGE_SCN_MEM_WRITE"]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_SCN_TYPE_REG"]) -> Literal[0x00000000]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_SCN_TYPE_DSECT"]) -> Literal[0x00000001]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_SCN_TYPE_NOLOAD"]) -> Literal[0x00000002]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_SCN_TYPE_GROUP"]) -> Literal[0x00000004]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_SCN_TYPE_NO_PAD"]) -> Literal[0x00000008]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_SCN_TYPE_COPY"]) -> Literal[0x00000010]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_SCN_CNT_CODE"]) -> Literal[0x00000020]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_SCN_CNT_INITIALIZED_DATA"]) -> Literal[0x00000040]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_SCN_CNT_UNINITIALIZED_DATA"]) -> Literal[0x00000080]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_SCN_LNK_OTHER"]) -> Literal[0x00000100]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_SCN_LNK_INFO"]) -> Literal[0x00000200]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_SCN_LNK_OVER"]) -> Literal[0x00000400]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_SCN_LNK_REMOVE"]) -> Literal[0x00000800]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_SCN_LNK_COMDAT"]) -> Literal[0x00001000]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_SCN_MEM_PROTECTED"]) -> Literal[0x00004000]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_SCN_NO_DEFER_SPEC_EXC"]) -> Literal[0x00004000]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_SCN_GPREL"]) -> Literal[0x00008000]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_SCN_MEM_FARDATA"]) -> Literal[0x00008000]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_SCN_MEM_SYSHEAP"]) -> Literal[0x00010000]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_SCN_MEM_PURGEABLE"]) -> Literal[0x00020000]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_SCN_MEM_16BIT"]) -> Literal[0x00020000]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_SCN_MEM_LOCKED"]) -> Literal[0x00040000]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_SCN_MEM_PRELOAD"]) -> Literal[0x00080000]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_SCN_ALIGN_1BYTES"]) -> Literal[0x00100000]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_SCN_ALIGN_2BYTES"]) -> Literal[0x00200000]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_SCN_ALIGN_4BYTES"]) -> Literal[0x00300000]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_SCN_ALIGN_8BYTES"]) -> Literal[0x00400000]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_SCN_ALIGN_16BYTES"]) -> Literal[0x00500000]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_SCN_ALIGN_32BYTES"]) -> Literal[0x00600000]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_SCN_ALIGN_64BYTES"]) -> Literal[0x00700000]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_SCN_ALIGN_128BYTES"]) -> Literal[0x00800000]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_SCN_ALIGN_256BYTES"]) -> Literal[0x00900000]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_SCN_ALIGN_512BYTES"]) -> Literal[0x00A00000]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_SCN_ALIGN_1024BYTES"]) -> Literal[0x00B00000]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_SCN_ALIGN_2048BYTES"]) -> Literal[0x00C00000]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_SCN_ALIGN_4096BYTES"]) -> Literal[0x00D00000]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_SCN_ALIGN_8192BYTES"]) -> Literal[0x00E00000]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_SCN_ALIGN_MASK"]) -> Literal[0x00F00000]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_SCN_LNK_NRELOC_OVFL"]) -> Literal[0x01000000]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_SCN_MEM_DISCARDABLE"]) -> Literal[0x02000000]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_SCN_MEM_NOT_CACHED"]) -> Literal[0x04000000]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_SCN_MEM_NOT_PAGED"]) -> Literal[0x08000000]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_SCN_MEM_SHARED"]) -> Literal[0x10000000]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_SCN_MEM_EXECUTE"]) -> Literal[0x20000000]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_SCN_MEM_READ"]) -> Literal[0x40000000]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_SCN_MEM_WRITE"]) -> Literal[0x80000000]:...
SECTION_CHARACTERISTICS_DICT_NAMES = Literal[
    "IMAGE_SCN_ALIGN_1024BYTES",
    "IMAGE_SCN_ALIGN_128BYTES",
    "IMAGE_SCN_ALIGN_16BYTES",
    "IMAGE_SCN_ALIGN_1BYTES",
    "IMAGE_SCN_ALIGN_2048BYTES",
    "IMAGE_SCN_ALIGN_256BYTES",
    "IMAGE_SCN_ALIGN_2BYTES",
    "IMAGE_SCN_ALIGN_32BYTES",
    "IMAGE_SCN_ALIGN_4096BYTES",
    "IMAGE_SCN_ALIGN_4BYTES",
    "IMAGE_SCN_ALIGN_512BYTES",
    "IMAGE_SCN_ALIGN_64BYTES",
    "IMAGE_SCN_ALIGN_8192BYTES",
    "IMAGE_SCN_ALIGN_8BYTES",
    "IMAGE_SCN_ALIGN_MASK",
    "IMAGE_SCN_CNT_CODE",
    "IMAGE_SCN_CNT_INITIALIZED_DATA",
    "IMAGE_SCN_CNT_UNINITIALIZED_DATA",
    "IMAGE_SCN_GPREL",
    "IMAGE_SCN_LNK_COMDAT",
    "IMAGE_SCN_LNK_INFO",
    "IMAGE_SCN_LNK_NRELOC_OVFL",
    "IMAGE_SCN_LNK_OTHER",
    "IMAGE_SCN_LNK_OVER",
    "IMAGE_SCN_LNK_REMOVE",
    "IMAGE_SCN_MEM_16BIT",
    "IMAGE_SCN_MEM_DISCARDABLE",
    "IMAGE_SCN_MEM_EXECUTE",
    "IMAGE_SCN_MEM_FARDATA",
    "IMAGE_SCN_MEM_LOCKED",
    "IMAGE_SCN_MEM_NOT_CACHED",
    "IMAGE_SCN_MEM_NOT_PAGED",
    "IMAGE_SCN_MEM_PRELOAD",
    "IMAGE_SCN_MEM_PROTECTED",
    "IMAGE_SCN_MEM_PURGEABLE",
    "IMAGE_SCN_MEM_READ",
    "IMAGE_SCN_MEM_SHARED",
    "IMAGE_SCN_MEM_SYSHEAP",
    "IMAGE_SCN_MEM_WRITE",
    "IMAGE_SCN_NO_DEFER_SPEC_EXC",
    "IMAGE_SCN_TYPE_COPY",
    "IMAGE_SCN_TYPE_DSECT",
    "IMAGE_SCN_TYPE_GROUP",
    "IMAGE_SCN_TYPE_NOLOAD",
    "IMAGE_SCN_TYPE_NO_PAD",
    "IMAGE_SCN_TYPE_REG",
]
SECTION_CHARACTERISTICS_DICT_VALUES = Literal[
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
class DEBUG_TYPE_DICT(_NAME_LOOKUP[int, str]):
    @overload
    def __getitem__(self, key: Literal[0]) -> Literal["IMAGE_DEBUG_TYPE_UNKNOWN"]:...

    @overload
    def __getitem__(self, key: Literal[1]) -> Literal["IMAGE_DEBUG_TYPE_COFF"]:...

    @overload
    def __getitem__(self, key: Literal[2]) -> Literal["IMAGE_DEBUG_TYPE_CODEVIEW"]:...

    @overload
    def __getitem__(self, key: Literal[3]) -> Literal["IMAGE_DEBUG_TYPE_FPO"]:...

    @overload
    def __getitem__(self, key: Literal[4]) -> Literal["IMAGE_DEBUG_TYPE_MISC"]:...

    @overload
    def __getitem__(self, key: Literal[5]) -> Literal["IMAGE_DEBUG_TYPE_EXCEPTION"]:...

    @overload
    def __getitem__(self, key: Literal[6]) -> Literal["IMAGE_DEBUG_TYPE_FIXUP"]:...

    @overload
    def __getitem__(self, key: Literal[7]) -> Literal["IMAGE_DEBUG_TYPE_OMAP_TO_SRC"]:...

    @overload
    def __getitem__(self, key: Literal[8]) -> Literal["IMAGE_DEBUG_TYPE_OMAP_FROM_SRC"]:...

    @overload
    def __getitem__(self, key: Literal[9]) -> Literal["IMAGE_DEBUG_TYPE_BORLAND"]:...

    @overload
    def __getitem__(self, key: Literal[10]) -> Literal["IMAGE_DEBUG_TYPE_RESERVED10"]:...

    @overload
    def __getitem__(self, key: Literal[11]) -> Literal["IMAGE_DEBUG_TYPE_CLSID"]:...

    @overload
    def __getitem__(self, key: Literal[12]) -> Literal["IMAGE_DEBUG_TYPE_VC_FEATURE"]:...

    @overload
    def __getitem__(self, key: Literal[13]) -> Literal["IMAGE_DEBUG_TYPE_POGO"]:...

    @overload
    def __getitem__(self, key: Literal[14]) -> Literal["IMAGE_DEBUG_TYPE_ILTCG"]:...

    @overload
    def __getitem__(self, key: Literal[15]) -> Literal["IMAGE_DEBUG_TYPE_MPX"]:...

    @overload
    def __getitem__(self, key: Literal[16]) -> Literal["IMAGE_DEBUG_TYPE_REPRO"]:...

    @overload
    def __getitem__(self, key: Literal[20]) -> Literal["IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS"]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_DEBUG_TYPE_UNKNOWN"]) -> Literal[0]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_DEBUG_TYPE_COFF"]) -> Literal[1]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_DEBUG_TYPE_CODEVIEW"]) -> Literal[2]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_DEBUG_TYPE_FPO"]) -> Literal[3]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_DEBUG_TYPE_MISC"]) -> Literal[4]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_DEBUG_TYPE_EXCEPTION"]) -> Literal[5]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_DEBUG_TYPE_FIXUP"]) -> Literal[6]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_DEBUG_TYPE_OMAP_TO_SRC"]) -> Literal[7]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_DEBUG_TYPE_OMAP_FROM_SRC"]) -> Literal[8]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_DEBUG_TYPE_BORLAND"]) -> Literal[9]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_DEBUG_TYPE_RESERVED10"]) -> Literal[10]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_DEBUG_TYPE_CLSID"]) -> Literal[11]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_DEBUG_TYPE_VC_FEATURE"]) -> Literal[12]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_DEBUG_TYPE_POGO"]) -> Literal[13]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_DEBUG_TYPE_ILTCG"]) -> Literal[14]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_DEBUG_TYPE_MPX"]) -> Literal[15]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_DEBUG_TYPE_REPRO"]) -> Literal[16]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS"]) -> Literal[20]:...
DEBUG_TYPE_DICT_NAMES = Literal[
    "IMAGE_DEBUG_TYPE_BORLAND",
    "IMAGE_DEBUG_TYPE_CLSID",
    "IMAGE_DEBUG_TYPE_CODEVIEW",
    "IMAGE_DEBUG_TYPE_COFF",
    "IMAGE_DEBUG_TYPE_EXCEPTION",
    "IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS",
    "IMAGE_DEBUG_TYPE_FIXUP",
    "IMAGE_DEBUG_TYPE_FPO",
    "IMAGE_DEBUG_TYPE_ILTCG",
    "IMAGE_DEBUG_TYPE_MISC",
    "IMAGE_DEBUG_TYPE_MPX",
    "IMAGE_DEBUG_TYPE_OMAP_FROM_SRC",
    "IMAGE_DEBUG_TYPE_OMAP_TO_SRC",
    "IMAGE_DEBUG_TYPE_POGO",
    "IMAGE_DEBUG_TYPE_REPRO",
    "IMAGE_DEBUG_TYPE_RESERVED10",
    "IMAGE_DEBUG_TYPE_UNKNOWN",
    "IMAGE_DEBUG_TYPE_VC_FEATURE",
]
DEBUG_TYPE_DICT_VALUES = Literal[
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
class SUBSYSTEM_TYPE_DICT(_NAME_LOOKUP[int, str]):
    @overload
    def __getitem__(self, key: Literal[0]) -> Literal["IMAGE_SUBSYSTEM_UNKNOWN"]:...

    @overload
    def __getitem__(self, key: Literal[1]) -> Literal["IMAGE_SUBSYSTEM_NATIVE"]:...

    @overload
    def __getitem__(self, key: Literal[2]) -> Literal["IMAGE_SUBSYSTEM_WINDOWS_GUI"]:...

    @overload
    def __getitem__(self, key: Literal[3]) -> Literal["IMAGE_SUBSYSTEM_WINDOWS_CUI"]:...

    @overload
    def __getitem__(self, key: Literal[5]) -> Literal["IMAGE_SUBSYSTEM_OS2_CUI"]:...

    @overload
    def __getitem__(self, key: Literal[7]) -> Literal["IMAGE_SUBSYSTEM_POSIX_CUI"]:...

    @overload
    def __getitem__(self, key: Literal[8]) -> Literal["IMAGE_SUBSYSTEM_NATIVE_WINDOWS"]:...

    @overload
    def __getitem__(self, key: Literal[9]) -> Literal["IMAGE_SUBSYSTEM_WINDOWS_CE_GUI"]:...

    @overload
    def __getitem__(self, key: Literal[10]) -> Literal["IMAGE_SUBSYSTEM_EFI_APPLICATION"]:...

    @overload
    def __getitem__(self, key: Literal[11]) -> Literal["IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER"]:...

    @overload
    def __getitem__(self, key: Literal[12]) -> Literal["IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER"]:...

    @overload
    def __getitem__(self, key: Literal[13]) -> Literal["IMAGE_SUBSYSTEM_EFI_ROM"]:...

    @overload
    def __getitem__(self, key: Literal[14]) -> Literal["IMAGE_SUBSYSTEM_XBOX"]:...

    @overload
    def __getitem__(self, key: Literal[16]) -> Literal["IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION"]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_SUBSYSTEM_UNKNOWN"]) -> Literal[0]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_SUBSYSTEM_NATIVE"]) -> Literal[1]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_SUBSYSTEM_WINDOWS_GUI"]) -> Literal[2]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_SUBSYSTEM_WINDOWS_CUI"]) -> Literal[3]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_SUBSYSTEM_OS2_CUI"]) -> Literal[5]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_SUBSYSTEM_POSIX_CUI"]) -> Literal[7]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_SUBSYSTEM_NATIVE_WINDOWS"]) -> Literal[8]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_SUBSYSTEM_WINDOWS_CE_GUI"]) -> Literal[9]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_SUBSYSTEM_EFI_APPLICATION"]) -> Literal[10]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER"]) -> Literal[11]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER"]) -> Literal[12]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_SUBSYSTEM_EFI_ROM"]) -> Literal[13]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_SUBSYSTEM_XBOX"]) -> Literal[14]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION"]) -> Literal[16]:...
SUBSYSTEM_TYPE_DICT_NAMES = Literal[
    "IMAGE_SUBSYSTEM_EFI_APPLICATION",
    "IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER",
    "IMAGE_SUBSYSTEM_EFI_ROM",
    "IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER",
    "IMAGE_SUBSYSTEM_NATIVE",
    "IMAGE_SUBSYSTEM_NATIVE_WINDOWS",
    "IMAGE_SUBSYSTEM_OS2_CUI",
    "IMAGE_SUBSYSTEM_POSIX_CUI",
    "IMAGE_SUBSYSTEM_UNKNOWN",
    "IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION",
    "IMAGE_SUBSYSTEM_WINDOWS_CE_GUI",
    "IMAGE_SUBSYSTEM_WINDOWS_CUI",
    "IMAGE_SUBSYSTEM_WINDOWS_GUI",
    "IMAGE_SUBSYSTEM_XBOX",
]
SUBSYSTEM_TYPE_DICT_VALUES = Literal[
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
class MACHINE_TYPE_DICT(_NAME_LOOKUP[int, str]):
    @overload
    def __getitem__(self, key: Literal[0x0]) -> Literal["IMAGE_FILE_MACHINE_UNKNOWN"]:...

    @overload
    def __getitem__(self, key: Literal[0x014C]) -> Literal["IMAGE_FILE_MACHINE_I386"]:...

    @overload
    def __getitem__(self, key: Literal[0x0162]) -> Literal["IMAGE_FILE_MACHINE_R3000"]:...

    @overload
    def __getitem__(self, key: Literal[0x0166]) -> Literal["IMAGE_FILE_MACHINE_R4000"]:...

    @overload
    def __getitem__(self, key: Literal[0x0168]) -> Literal["IMAGE_FILE_MACHINE_R10000"]:...

    @overload
    def __getitem__(self, key: Literal[0x0169]) -> Literal["IMAGE_FILE_MACHINE_WCEMIPSV2"]:...

    @overload
    def __getitem__(self, key: Literal[0x0184]) -> Literal["IMAGE_FILE_MACHINE_ALPHA"]:...

    @overload
    def __getitem__(self, key: Literal[0x01A2]) -> Literal["IMAGE_FILE_MACHINE_SH3"]:...

    @overload
    def __getitem__(self, key: Literal[0x01A3]) -> Literal["IMAGE_FILE_MACHINE_SH3DSP"]:...

    @overload
    def __getitem__(self, key: Literal[0x01A4]) -> Literal["IMAGE_FILE_MACHINE_SH3E"]:...

    @overload
    def __getitem__(self, key: Literal[0x01A6]) -> Literal["IMAGE_FILE_MACHINE_SH4"]:...

    @overload
    def __getitem__(self, key: Literal[0x01A8]) -> Literal["IMAGE_FILE_MACHINE_SH5"]:...

    @overload
    def __getitem__(self, key: Literal[0x01C0]) -> Literal["IMAGE_FILE_MACHINE_ARM"]:...

    @overload
    def __getitem__(self, key: Literal[0x01C2]) -> Literal["IMAGE_FILE_MACHINE_THUMB"]:...

    @overload
    def __getitem__(self, key: Literal[0x01C4]) -> Literal["IMAGE_FILE_MACHINE_ARMNT"]:...

    @overload
    def __getitem__(self, key: Literal[0x01D3]) -> Literal["IMAGE_FILE_MACHINE_AM33"]:...

    @overload
    def __getitem__(self, key: Literal[0x01F0]) -> Literal["IMAGE_FILE_MACHINE_POWERPC"]:...

    @overload
    def __getitem__(self, key: Literal[0x01F1]) -> Literal["IMAGE_FILE_MACHINE_POWERPCFP"]:...

    @overload
    def __getitem__(self, key: Literal[0x0200]) -> Literal["IMAGE_FILE_MACHINE_IA64"]:...

    @overload
    def __getitem__(self, key: Literal[0x0266]) -> Literal["IMAGE_FILE_MACHINE_MIPS16"]:...

    @overload
    def __getitem__(self, key: Literal[0x0284]) -> Literal["IMAGE_FILE_MACHINE_AXP64"]:...

    @overload
    def __getitem__(self, key: Literal[0x0366]) -> Literal["IMAGE_FILE_MACHINE_MIPSFPU"]:...

    @overload
    def __getitem__(self, key: Literal[0x0466]) -> Literal["IMAGE_FILE_MACHINE_MIPSFPU16"]:...

    @overload
    def __getitem__(self, key: Literal[0x0520]) -> Literal["IMAGE_FILE_MACHINE_TRICORE"]:...

    @overload
    def __getitem__(self, key: Literal[0x0CEF]) -> Literal["IMAGE_FILE_MACHINE_CEF"]:...

    @overload
    def __getitem__(self, key: Literal[0x0EBC]) -> Literal["IMAGE_FILE_MACHINE_EBC"]:...

    @overload
    def __getitem__(self, key: Literal[0x5032]) -> Literal["IMAGE_FILE_MACHINE_RISCV32"]:...

    @overload
    def __getitem__(self, key: Literal[0x5064]) -> Literal["IMAGE_FILE_MACHINE_RISCV64"]:...

    @overload
    def __getitem__(self, key: Literal[0x5128]) -> Literal["IMAGE_FILE_MACHINE_RISCV128"]:...

    @overload
    def __getitem__(self, key: Literal[0x6232]) -> Literal["IMAGE_FILE_MACHINE_LOONGARCH32"]:...

    @overload
    def __getitem__(self, key: Literal[0x6264]) -> Literal["IMAGE_FILE_MACHINE_LOONGARCH64"]:...

    @overload
    def __getitem__(self, key: Literal[0x8664]) -> Literal["IMAGE_FILE_MACHINE_AMD64"]:...

    @overload
    def __getitem__(self, key: Literal[0x9041]) -> Literal["IMAGE_FILE_MACHINE_M32R"]:...

    @overload
    def __getitem__(self, key: Literal[0xAA64]) -> Literal["IMAGE_FILE_MACHINE_ARM64"]:...

    @overload
    def __getitem__(self, key: Literal[0xC0EE]) -> Literal["IMAGE_FILE_MACHINE_CEE"]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_FILE_MACHINE_UNKNOWN"]) -> Literal[0x0]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_FILE_MACHINE_I386"]) -> Literal[0x014C]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_FILE_MACHINE_R3000"]) -> Literal[0x0162]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_FILE_MACHINE_R4000"]) -> Literal[0x0166]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_FILE_MACHINE_R10000"]) -> Literal[0x0168]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_FILE_MACHINE_WCEMIPSV2"]) -> Literal[0x0169]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_FILE_MACHINE_ALPHA"]) -> Literal[0x0184]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_FILE_MACHINE_SH3"]) -> Literal[0x01A2]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_FILE_MACHINE_SH3DSP"]) -> Literal[0x01A3]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_FILE_MACHINE_SH3E"]) -> Literal[0x01A4]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_FILE_MACHINE_SH4"]) -> Literal[0x01A6]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_FILE_MACHINE_SH5"]) -> Literal[0x01A8]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_FILE_MACHINE_ARM"]) -> Literal[0x01C0]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_FILE_MACHINE_THUMB"]) -> Literal[0x01C2]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_FILE_MACHINE_ARMNT"]) -> Literal[0x01C4]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_FILE_MACHINE_AM33"]) -> Literal[0x01D3]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_FILE_MACHINE_POWERPC"]) -> Literal[0x01F0]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_FILE_MACHINE_POWERPCFP"]) -> Literal[0x01F1]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_FILE_MACHINE_IA64"]) -> Literal[0x0200]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_FILE_MACHINE_MIPS16"]) -> Literal[0x0266]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_FILE_MACHINE_ALPHA64"]) -> Literal[0x0284]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_FILE_MACHINE_AXP64"]) -> Literal[0x0284]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_FILE_MACHINE_MIPSFPU"]) -> Literal[0x0366]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_FILE_MACHINE_MIPSFPU16"]) -> Literal[0x0466]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_FILE_MACHINE_TRICORE"]) -> Literal[0x0520]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_FILE_MACHINE_CEF"]) -> Literal[0x0CEF]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_FILE_MACHINE_EBC"]) -> Literal[0x0EBC]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_FILE_MACHINE_RISCV32"]) -> Literal[0x5032]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_FILE_MACHINE_RISCV64"]) -> Literal[0x5064]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_FILE_MACHINE_RISCV128"]) -> Literal[0x5128]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_FILE_MACHINE_LOONGARCH32"]) -> Literal[0x6232]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_FILE_MACHINE_LOONGARCH64"]) -> Literal[0x6264]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_FILE_MACHINE_AMD64"]) -> Literal[0x8664]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_FILE_MACHINE_M32R"]) -> Literal[0x9041]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_FILE_MACHINE_ARM64"]) -> Literal[0xAA64]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_FILE_MACHINE_CEE"]) -> Literal[0xC0EE]:...
MACHINE_TYPE_DICT_NAMES = Literal[
    "IMAGE_FILE_MACHINE_ALPHA",
    "IMAGE_FILE_MACHINE_ALPHA64",
    "IMAGE_FILE_MACHINE_AM33",
    "IMAGE_FILE_MACHINE_AMD64",
    "IMAGE_FILE_MACHINE_ARM",
    "IMAGE_FILE_MACHINE_ARM64",
    "IMAGE_FILE_MACHINE_ARMNT",
    "IMAGE_FILE_MACHINE_AXP64",
    "IMAGE_FILE_MACHINE_CEE",
    "IMAGE_FILE_MACHINE_CEF",
    "IMAGE_FILE_MACHINE_EBC",
    "IMAGE_FILE_MACHINE_I386",
    "IMAGE_FILE_MACHINE_IA64",
    "IMAGE_FILE_MACHINE_LOONGARCH32",
    "IMAGE_FILE_MACHINE_LOONGARCH64",
    "IMAGE_FILE_MACHINE_M32R",
    "IMAGE_FILE_MACHINE_MIPS16",
    "IMAGE_FILE_MACHINE_MIPSFPU",
    "IMAGE_FILE_MACHINE_MIPSFPU16",
    "IMAGE_FILE_MACHINE_POWERPC",
    "IMAGE_FILE_MACHINE_POWERPCFP",
    "IMAGE_FILE_MACHINE_R10000",
    "IMAGE_FILE_MACHINE_R3000",
    "IMAGE_FILE_MACHINE_R4000",
    "IMAGE_FILE_MACHINE_RISCV128",
    "IMAGE_FILE_MACHINE_RISCV32",
    "IMAGE_FILE_MACHINE_RISCV64",
    "IMAGE_FILE_MACHINE_SH3",
    "IMAGE_FILE_MACHINE_SH3DSP",
    "IMAGE_FILE_MACHINE_SH3E",
    "IMAGE_FILE_MACHINE_SH4",
    "IMAGE_FILE_MACHINE_SH5",
    "IMAGE_FILE_MACHINE_THUMB",
    "IMAGE_FILE_MACHINE_TRICORE",
    "IMAGE_FILE_MACHINE_UNKNOWN",
    "IMAGE_FILE_MACHINE_WCEMIPSV2",
]
MACHINE_TYPE_DICT_VALUES = Literal[
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
class RELOCATION_TYPE_DICT(_NAME_LOOKUP[int, str]):
    @overload
    def __getitem__(self, key: Literal[0]) -> Literal["IMAGE_REL_BASED_ABSOLUTE"]:...

    @overload
    def __getitem__(self, key: Literal[1]) -> Literal["IMAGE_REL_BASED_HIGH"]:...

    @overload
    def __getitem__(self, key: Literal[2]) -> Literal["IMAGE_REL_BASED_LOW"]:...

    @overload
    def __getitem__(self, key: Literal[3]) -> Literal["IMAGE_REL_BASED_HIGHLOW"]:...

    @overload
    def __getitem__(self, key: Literal[4]) -> Literal["IMAGE_REL_BASED_HIGHADJ"]:...

    @overload
    def __getitem__(self, key: Literal[5]) -> Literal["IMAGE_REL_BASED_MIPS_JMPADDR"]:...

    @overload
    def __getitem__(self, key: Literal[6]) -> Literal["IMAGE_REL_BASED_SECTION"]:...

    @overload
    def __getitem__(self, key: Literal[7]) -> Literal["IMAGE_REL_BASED_REL"]:...

    @overload
    def __getitem__(self, key: Literal[9]) -> Literal["IMAGE_REL_BASED_IA64_IMM64"]:...

    @overload
    def __getitem__(self, key: Literal[10]) -> Literal["IMAGE_REL_BASED_DIR64"]:...

    @overload
    def __getitem__(self, key: Literal[11]) -> Literal["IMAGE_REL_BASED_HIGH3ADJ"]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_REL_BASED_ABSOLUTE"]) -> Literal[0]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_REL_BASED_HIGH"]) -> Literal[1]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_REL_BASED_LOW"]) -> Literal[2]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_REL_BASED_HIGHLOW"]) -> Literal[3]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_REL_BASED_HIGHADJ"]) -> Literal[4]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_REL_BASED_MIPS_JMPADDR"]) -> Literal[5]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_REL_BASED_SECTION"]) -> Literal[6]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_REL_BASED_REL"]) -> Literal[7]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_REL_BASED_MIPS_JMPADDR16"]) -> Literal[9]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_REL_BASED_IA64_IMM64"]) -> Literal[9]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_REL_BASED_DIR64"]) -> Literal[10]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_REL_BASED_HIGH3ADJ"]) -> Literal[11]:...
RELOCATION_TYPE_DICT_NAMES = Literal[
    "IMAGE_REL_BASED_ABSOLUTE",
    "IMAGE_REL_BASED_DIR64",
    "IMAGE_REL_BASED_HIGH",
    "IMAGE_REL_BASED_HIGH3ADJ",
    "IMAGE_REL_BASED_HIGHADJ",
    "IMAGE_REL_BASED_HIGHLOW",
    "IMAGE_REL_BASED_IA64_IMM64",
    "IMAGE_REL_BASED_LOW",
    "IMAGE_REL_BASED_MIPS_JMPADDR",
    "IMAGE_REL_BASED_MIPS_JMPADDR16",
    "IMAGE_REL_BASED_REL",
    "IMAGE_REL_BASED_SECTION",
]
RELOCATION_TYPE_DICT_VALUES = Literal[
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
class DLL_CHARACTERISTICS_DICT(_NAME_LOOKUP[int, str]):
    @overload
    def __getitem__(self, key: Literal[0x0001]) -> Literal["IMAGE_LIBRARY_PROCESS_INIT"]:...

    @overload
    def __getitem__(self, key: Literal[0x0002]) -> Literal["IMAGE_LIBRARY_PROCESS_TERM"]:...

    @overload
    def __getitem__(self, key: Literal[0x0004]) -> Literal["IMAGE_LIBRARY_THREAD_INIT"]:...

    @overload
    def __getitem__(self, key: Literal[0x0008]) -> Literal["IMAGE_LIBRARY_THREAD_TERM"]:...

    @overload
    def __getitem__(self, key: Literal[0x0020]) -> Literal["IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA"]:...

    @overload
    def __getitem__(self, key: Literal[0x0040]) -> Literal["IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE"]:...

    @overload
    def __getitem__(self, key: Literal[0x0080]) -> Literal["IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY"]:...

    @overload
    def __getitem__(self, key: Literal[0x0100]) -> Literal["IMAGE_DLLCHARACTERISTICS_NX_COMPAT"]:...

    @overload
    def __getitem__(self, key: Literal[0x0200]) -> Literal["IMAGE_DLLCHARACTERISTICS_NO_ISOLATION"]:...

    @overload
    def __getitem__(self, key: Literal[0x0400]) -> Literal["IMAGE_DLLCHARACTERISTICS_NO_SEH"]:...

    @overload
    def __getitem__(self, key: Literal[0x0800]) -> Literal["IMAGE_DLLCHARACTERISTICS_NO_BIND"]:...

    @overload
    def __getitem__(self, key: Literal[0x1000]) -> Literal["IMAGE_DLLCHARACTERISTICS_APPCONTAINER"]:...

    @overload
    def __getitem__(self, key: Literal[0x2000]) -> Literal["IMAGE_DLLCHARACTERISTICS_WDM_DRIVER"]:...

    @overload
    def __getitem__(self, key: Literal[0x4000]) -> Literal["IMAGE_DLLCHARACTERISTICS_GUARD_CF"]:...

    @overload
    def __getitem__(self, key: Literal[0x8000]) -> Literal["IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE"]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_LIBRARY_PROCESS_INIT"]) -> Literal[0x0001]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_LIBRARY_PROCESS_TERM"]) -> Literal[0x0002]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_LIBRARY_THREAD_INIT"]) -> Literal[0x0004]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_LIBRARY_THREAD_TERM"]) -> Literal[0x0008]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA"]) -> Literal[0x0020]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE"]) -> Literal[0x0040]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY"]) -> Literal[0x0080]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_DLLCHARACTERISTICS_NX_COMPAT"]) -> Literal[0x0100]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_DLLCHARACTERISTICS_NO_ISOLATION"]) -> Literal[0x0200]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_DLLCHARACTERISTICS_NO_SEH"]) -> Literal[0x0400]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_DLLCHARACTERISTICS_NO_BIND"]) -> Literal[0x0800]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_DLLCHARACTERISTICS_APPCONTAINER"]) -> Literal[0x1000]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_DLLCHARACTERISTICS_WDM_DRIVER"]) -> Literal[0x2000]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_DLLCHARACTERISTICS_GUARD_CF"]) -> Literal[0x4000]:...

    @overload
    def __getitem__(self, key: Literal["IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE"]) -> Literal[0x8000]:...
DLL_CHARACTERISTICS_DICT_NAMES = Literal[
    "IMAGE_DLLCHARACTERISTICS_APPCONTAINER",
    "IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE",
    "IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY",
    "IMAGE_DLLCHARACTERISTICS_GUARD_CF",
    "IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA",
    "IMAGE_DLLCHARACTERISTICS_NO_BIND",
    "IMAGE_DLLCHARACTERISTICS_NO_ISOLATION",
    "IMAGE_DLLCHARACTERISTICS_NO_SEH",
    "IMAGE_DLLCHARACTERISTICS_NX_COMPAT",
    "IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE",
    "IMAGE_DLLCHARACTERISTICS_WDM_DRIVER",
    "IMAGE_LIBRARY_PROCESS_INIT",
    "IMAGE_LIBRARY_PROCESS_TERM",
    "IMAGE_LIBRARY_THREAD_INIT",
    "IMAGE_LIBRARY_THREAD_TERM",
]
DLL_CHARACTERISTICS_DICT_VALUES = Literal[
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
class UNWIND_INFO_FLAGS_DICT(_NAME_LOOKUP[int, str]):
    @overload
    def __getitem__(self, key: Literal[0x01]) -> Literal["UNW_FLAG_EHANDLER"]:...

    @overload
    def __getitem__(self, key: Literal[0x02]) -> Literal["UNW_FLAG_UHANDLER"]:...

    @overload
    def __getitem__(self, key: Literal[0x04]) -> Literal["UNW_FLAG_CHAININFO"]:...

    @overload
    def __getitem__(self, key: Literal["UNW_FLAG_EHANDLER"]) -> Literal[0x01]:...

    @overload
    def __getitem__(self, key: Literal["UNW_FLAG_UHANDLER"]) -> Literal[0x02]:...

    @overload
    def __getitem__(self, key: Literal["UNW_FLAG_CHAININFO"]) -> Literal[0x04]:...
UNWIND_INFO_FLAGS_DICT_NAMES = Literal[
    "UNW_FLAG_CHAININFO",
    "UNW_FLAG_EHANDLER",
    "UNW_FLAG_UHANDLER",
]
UNWIND_INFO_FLAGS_DICT_VALUES = Literal[
    0x01,
    0x02,
    0x04,
]
class REGISTERS_DICT(_NAME_LOOKUP[int, str]):
    @overload
    def __getitem__(self, key: Literal[0]) -> Literal["RAX"]:...

    @overload
    def __getitem__(self, key: Literal[1]) -> Literal["RCX"]:...

    @overload
    def __getitem__(self, key: Literal[2]) -> Literal["RDX"]:...

    @overload
    def __getitem__(self, key: Literal[3]) -> Literal["RBX"]:...

    @overload
    def __getitem__(self, key: Literal[4]) -> Literal["RSP"]:...

    @overload
    def __getitem__(self, key: Literal[5]) -> Literal["RBP"]:...

    @overload
    def __getitem__(self, key: Literal[6]) -> Literal["RSI"]:...

    @overload
    def __getitem__(self, key: Literal[7]) -> Literal["RDI"]:...

    @overload
    def __getitem__(self, key: Literal[8]) -> Literal["R8"]:...

    @overload
    def __getitem__(self, key: Literal[9]) -> Literal["R9"]:...

    @overload
    def __getitem__(self, key: Literal[10]) -> Literal["R10"]:...

    @overload
    def __getitem__(self, key: Literal[11]) -> Literal["R11"]:...

    @overload
    def __getitem__(self, key: Literal[12]) -> Literal["R12"]:...

    @overload
    def __getitem__(self, key: Literal[13]) -> Literal["R13"]:...

    @overload
    def __getitem__(self, key: Literal[14]) -> Literal["R14"]:...

    @overload
    def __getitem__(self, key: Literal[15]) -> Literal["R15"]:...

    @overload
    def __getitem__(self, key: Literal["RAX"]) -> Literal[0]:...

    @overload
    def __getitem__(self, key: Literal["RCX"]) -> Literal[1]:...

    @overload
    def __getitem__(self, key: Literal["RDX"]) -> Literal[2]:...

    @overload
    def __getitem__(self, key: Literal["RBX"]) -> Literal[3]:...

    @overload
    def __getitem__(self, key: Literal["RSP"]) -> Literal[4]:...

    @overload
    def __getitem__(self, key: Literal["RBP"]) -> Literal[5]:...

    @overload
    def __getitem__(self, key: Literal["RSI"]) -> Literal[6]:...

    @overload
    def __getitem__(self, key: Literal["RDI"]) -> Literal[7]:...

    @overload
    def __getitem__(self, key: Literal["R8"]) -> Literal[8]:...

    @overload
    def __getitem__(self, key: Literal["R9"]) -> Literal[9]:...

    @overload
    def __getitem__(self, key: Literal["R10"]) -> Literal[10]:...

    @overload
    def __getitem__(self, key: Literal["R11"]) -> Literal[11]:...

    @overload
    def __getitem__(self, key: Literal["R12"]) -> Literal[12]:...

    @overload
    def __getitem__(self, key: Literal["R13"]) -> Literal[13]:...

    @overload
    def __getitem__(self, key: Literal["R14"]) -> Literal[14]:...

    @overload
    def __getitem__(self, key: Literal["R15"]) -> Literal[15]:...
REGISTERS_DICT_NAMES = Literal[
    "R10",
    "R11",
    "R12",
    "R13",
    "R14",
    "R15",
    "R8",
    "R9",
    "RAX",
    "RBP",
    "RBX",
    "RCX",
    "RDI",
    "RDX",
    "RSI",
    "RSP",
]
REGISTERS_DICT_VALUES = Literal[
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
class RESOURCE_TYPE_DICT(_NAME_LOOKUP[int, str]):
    @overload
    def __getitem__(self, key: Literal[1]) -> Literal["RT_CURSOR"]:...

    @overload
    def __getitem__(self, key: Literal[2]) -> Literal["RT_BITMAP"]:...

    @overload
    def __getitem__(self, key: Literal[3]) -> Literal["RT_ICON"]:...

    @overload
    def __getitem__(self, key: Literal[4]) -> Literal["RT_MENU"]:...

    @overload
    def __getitem__(self, key: Literal[5]) -> Literal["RT_DIALOG"]:...

    @overload
    def __getitem__(self, key: Literal[6]) -> Literal["RT_STRING"]:...

    @overload
    def __getitem__(self, key: Literal[7]) -> Literal["RT_FONTDIR"]:...

    @overload
    def __getitem__(self, key: Literal[8]) -> Literal["RT_FONT"]:...

    @overload
    def __getitem__(self, key: Literal[9]) -> Literal["RT_ACCELERATOR"]:...

    @overload
    def __getitem__(self, key: Literal[10]) -> Literal["RT_RCDATA"]:...

    @overload
    def __getitem__(self, key: Literal[11]) -> Literal["RT_MESSAGETABLE"]:...

    @overload
    def __getitem__(self, key: Literal[12]) -> Literal["RT_GROUP_CURSOR"]:...

    @overload
    def __getitem__(self, key: Literal[14]) -> Literal["RT_GROUP_ICON"]:...

    @overload
    def __getitem__(self, key: Literal[16]) -> Literal["RT_VERSION"]:...

    @overload
    def __getitem__(self, key: Literal[17]) -> Literal["RT_DLGINCLUDE"]:...

    @overload
    def __getitem__(self, key: Literal[19]) -> Literal["RT_PLUGPLAY"]:...

    @overload
    def __getitem__(self, key: Literal[20]) -> Literal["RT_VXD"]:...

    @overload
    def __getitem__(self, key: Literal[21]) -> Literal["RT_ANICURSOR"]:...

    @overload
    def __getitem__(self, key: Literal[22]) -> Literal["RT_ANIICON"]:...

    @overload
    def __getitem__(self, key: Literal[23]) -> Literal["RT_HTML"]:...

    @overload
    def __getitem__(self, key: Literal[24]) -> Literal["RT_MANIFEST"]:...

    @overload
    def __getitem__(self, key: Literal["RT_CURSOR"]) -> Literal[1]:...

    @overload
    def __getitem__(self, key: Literal["RT_BITMAP"]) -> Literal[2]:...

    @overload
    def __getitem__(self, key: Literal["RT_ICON"]) -> Literal[3]:...

    @overload
    def __getitem__(self, key: Literal["RT_MENU"]) -> Literal[4]:...

    @overload
    def __getitem__(self, key: Literal["RT_DIALOG"]) -> Literal[5]:...

    @overload
    def __getitem__(self, key: Literal["RT_STRING"]) -> Literal[6]:...

    @overload
    def __getitem__(self, key: Literal["RT_FONTDIR"]) -> Literal[7]:...

    @overload
    def __getitem__(self, key: Literal["RT_FONT"]) -> Literal[8]:...

    @overload
    def __getitem__(self, key: Literal["RT_ACCELERATOR"]) -> Literal[9]:...

    @overload
    def __getitem__(self, key: Literal["RT_RCDATA"]) -> Literal[10]:...

    @overload
    def __getitem__(self, key: Literal["RT_MESSAGETABLE"]) -> Literal[11]:...

    @overload
    def __getitem__(self, key: Literal["RT_GROUP_CURSOR"]) -> Literal[12]:...

    @overload
    def __getitem__(self, key: Literal["RT_GROUP_ICON"]) -> Literal[14]:...

    @overload
    def __getitem__(self, key: Literal["RT_VERSION"]) -> Literal[16]:...

    @overload
    def __getitem__(self, key: Literal["RT_DLGINCLUDE"]) -> Literal[17]:...

    @overload
    def __getitem__(self, key: Literal["RT_PLUGPLAY"]) -> Literal[19]:...

    @overload
    def __getitem__(self, key: Literal["RT_VXD"]) -> Literal[20]:...

    @overload
    def __getitem__(self, key: Literal["RT_ANICURSOR"]) -> Literal[21]:...

    @overload
    def __getitem__(self, key: Literal["RT_ANIICON"]) -> Literal[22]:...

    @overload
    def __getitem__(self, key: Literal["RT_HTML"]) -> Literal[23]:...

    @overload
    def __getitem__(self, key: Literal["RT_MANIFEST"]) -> Literal[24]:...
RESOURCE_TYPE_DICT_NAMES = Literal[
    "RT_ACCELERATOR",
    "RT_ANICURSOR",
    "RT_ANIICON",
    "RT_BITMAP",
    "RT_CURSOR",
    "RT_DIALOG",
    "RT_DLGINCLUDE",
    "RT_FONT",
    "RT_FONTDIR",
    "RT_GROUP_CURSOR",
    "RT_GROUP_ICON",
    "RT_HTML",
    "RT_ICON",
    "RT_MANIFEST",
    "RT_MENU",
    "RT_MESSAGETABLE",
    "RT_PLUGPLAY",
    "RT_RCDATA",
    "RT_STRING",
    "RT_VERSION",
    "RT_VXD",
]
RESOURCE_TYPE_DICT_VALUES = Literal[
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
class LANG_DICT(_NAME_LOOKUP[int, str]):
    @overload
    def __getitem__(self, key: Literal[0x00]) -> Literal["LANG_NEUTRAL"]:...

    @overload
    def __getitem__(self, key: Literal[0x7F]) -> Literal["LANG_INVARIANT"]:...

    @overload
    def __getitem__(self, key: Literal[0x36]) -> Literal["LANG_AFRIKAANS"]:...

    @overload
    def __getitem__(self, key: Literal[0x1C]) -> Literal["LANG_ALBANIAN"]:...

    @overload
    def __getitem__(self, key: Literal[0x01]) -> Literal["LANG_ARABIC"]:...

    @overload
    def __getitem__(self, key: Literal[0x2B]) -> Literal["LANG_ARMENIAN"]:...

    @overload
    def __getitem__(self, key: Literal[0x4D]) -> Literal["LANG_ASSAMESE"]:...

    @overload
    def __getitem__(self, key: Literal[0x2C]) -> Literal["LANG_AZERI"]:...

    @overload
    def __getitem__(self, key: Literal[0x2D]) -> Literal["LANG_BASQUE"]:...

    @overload
    def __getitem__(self, key: Literal[0x23]) -> Literal["LANG_BELARUSIAN"]:...

    @overload
    def __getitem__(self, key: Literal[0x45]) -> Literal["LANG_BENGALI"]:...

    @overload
    def __getitem__(self, key: Literal[0x02]) -> Literal["LANG_BULGARIAN"]:...

    @overload
    def __getitem__(self, key: Literal[0x03]) -> Literal["LANG_CATALAN"]:...

    @overload
    def __getitem__(self, key: Literal[0x04]) -> Literal["LANG_CHINESE"]:...

    @overload
    def __getitem__(self, key: Literal[0x1A]) -> Literal["LANG_SERBIAN"]:...

    @overload
    def __getitem__(self, key: Literal[0x05]) -> Literal["LANG_CZECH"]:...

    @overload
    def __getitem__(self, key: Literal[0x06]) -> Literal["LANG_DANISH"]:...

    @overload
    def __getitem__(self, key: Literal[0x65]) -> Literal["LANG_DIVEHI"]:...

    @overload
    def __getitem__(self, key: Literal[0x13]) -> Literal["LANG_DUTCH"]:...

    @overload
    def __getitem__(self, key: Literal[0x09]) -> Literal["LANG_ENGLISH"]:...

    @overload
    def __getitem__(self, key: Literal[0x25]) -> Literal["LANG_ESTONIAN"]:...

    @overload
    def __getitem__(self, key: Literal[0x38]) -> Literal["LANG_FAEROESE"]:...

    @overload
    def __getitem__(self, key: Literal[0x29]) -> Literal["LANG_FARSI"]:...

    @overload
    def __getitem__(self, key: Literal[0x0B]) -> Literal["LANG_FINNISH"]:...

    @overload
    def __getitem__(self, key: Literal[0x0C]) -> Literal["LANG_FRENCH"]:...

    @overload
    def __getitem__(self, key: Literal[0x56]) -> Literal["LANG_GALICIAN"]:...

    @overload
    def __getitem__(self, key: Literal[0x37]) -> Literal["LANG_GEORGIAN"]:...

    @overload
    def __getitem__(self, key: Literal[0x07]) -> Literal["LANG_GERMAN"]:...

    @overload
    def __getitem__(self, key: Literal[0x08]) -> Literal["LANG_GREEK"]:...

    @overload
    def __getitem__(self, key: Literal[0x47]) -> Literal["LANG_GUJARATI"]:...

    @overload
    def __getitem__(self, key: Literal[0x0D]) -> Literal["LANG_HEBREW"]:...

    @overload
    def __getitem__(self, key: Literal[0x39]) -> Literal["LANG_HINDI"]:...

    @overload
    def __getitem__(self, key: Literal[0x0E]) -> Literal["LANG_HUNGARIAN"]:...

    @overload
    def __getitem__(self, key: Literal[0x0F]) -> Literal["LANG_ICELANDIC"]:...

    @overload
    def __getitem__(self, key: Literal[0x21]) -> Literal["LANG_INDONESIAN"]:...

    @overload
    def __getitem__(self, key: Literal[0x10]) -> Literal["LANG_ITALIAN"]:...

    @overload
    def __getitem__(self, key: Literal[0x11]) -> Literal["LANG_JAPANESE"]:...

    @overload
    def __getitem__(self, key: Literal[0x4B]) -> Literal["LANG_KANNADA"]:...

    @overload
    def __getitem__(self, key: Literal[0x60]) -> Literal["LANG_KASHMIRI"]:...

    @overload
    def __getitem__(self, key: Literal[0x3F]) -> Literal["LANG_KAZAK"]:...

    @overload
    def __getitem__(self, key: Literal[0x57]) -> Literal["LANG_KONKANI"]:...

    @overload
    def __getitem__(self, key: Literal[0x12]) -> Literal["LANG_KOREAN"]:...

    @overload
    def __getitem__(self, key: Literal[0x40]) -> Literal["LANG_KYRGYZ"]:...

    @overload
    def __getitem__(self, key: Literal[0x26]) -> Literal["LANG_LATVIAN"]:...

    @overload
    def __getitem__(self, key: Literal[0x27]) -> Literal["LANG_LITHUANIAN"]:...

    @overload
    def __getitem__(self, key: Literal[0x2F]) -> Literal["LANG_MACEDONIAN"]:...

    @overload
    def __getitem__(self, key: Literal[0x3E]) -> Literal["LANG_MALAY"]:...

    @overload
    def __getitem__(self, key: Literal[0x4C]) -> Literal["LANG_MALAYALAM"]:...

    @overload
    def __getitem__(self, key: Literal[0x58]) -> Literal["LANG_MANIPURI"]:...

    @overload
    def __getitem__(self, key: Literal[0x4E]) -> Literal["LANG_MARATHI"]:...

    @overload
    def __getitem__(self, key: Literal[0x50]) -> Literal["LANG_MONGOLIAN"]:...

    @overload
    def __getitem__(self, key: Literal[0x61]) -> Literal["LANG_NEPALI"]:...

    @overload
    def __getitem__(self, key: Literal[0x14]) -> Literal["LANG_NORWEGIAN"]:...

    @overload
    def __getitem__(self, key: Literal[0x48]) -> Literal["LANG_ORIYA"]:...

    @overload
    def __getitem__(self, key: Literal[0x15]) -> Literal["LANG_POLISH"]:...

    @overload
    def __getitem__(self, key: Literal[0x16]) -> Literal["LANG_PORTUGUESE"]:...

    @overload
    def __getitem__(self, key: Literal[0x46]) -> Literal["LANG_PUNJABI"]:...

    @overload
    def __getitem__(self, key: Literal[0x18]) -> Literal["LANG_ROMANIAN"]:...

    @overload
    def __getitem__(self, key: Literal[0x19]) -> Literal["LANG_RUSSIAN"]:...

    @overload
    def __getitem__(self, key: Literal[0x4F]) -> Literal["LANG_SANSKRIT"]:...

    @overload
    def __getitem__(self, key: Literal[0x59]) -> Literal["LANG_SINDHI"]:...

    @overload
    def __getitem__(self, key: Literal[0x1B]) -> Literal["LANG_SLOVAK"]:...

    @overload
    def __getitem__(self, key: Literal[0x24]) -> Literal["LANG_SLOVENIAN"]:...

    @overload
    def __getitem__(self, key: Literal[0x0A]) -> Literal["LANG_SPANISH"]:...

    @overload
    def __getitem__(self, key: Literal[0x41]) -> Literal["LANG_SWAHILI"]:...

    @overload
    def __getitem__(self, key: Literal[0x1D]) -> Literal["LANG_SWEDISH"]:...

    @overload
    def __getitem__(self, key: Literal[0x5A]) -> Literal["LANG_SYRIAC"]:...

    @overload
    def __getitem__(self, key: Literal[0x49]) -> Literal["LANG_TAMIL"]:...

    @overload
    def __getitem__(self, key: Literal[0x44]) -> Literal["LANG_TATAR"]:...

    @overload
    def __getitem__(self, key: Literal[0x4A]) -> Literal["LANG_TELUGU"]:...

    @overload
    def __getitem__(self, key: Literal[0x1E]) -> Literal["LANG_THAI"]:...

    @overload
    def __getitem__(self, key: Literal[0x1F]) -> Literal["LANG_TURKISH"]:...

    @overload
    def __getitem__(self, key: Literal[0x22]) -> Literal["LANG_UKRAINIAN"]:...

    @overload
    def __getitem__(self, key: Literal[0x20]) -> Literal["LANG_URDU"]:...

    @overload
    def __getitem__(self, key: Literal[0x43]) -> Literal["LANG_UZBEK"]:...

    @overload
    def __getitem__(self, key: Literal[0x2A]) -> Literal["LANG_VIETNAMESE"]:...

    @overload
    def __getitem__(self, key: Literal[0x3C]) -> Literal["LANG_GAELIC"]:...

    @overload
    def __getitem__(self, key: Literal[0x3A]) -> Literal["LANG_MALTESE"]:...

    @overload
    def __getitem__(self, key: Literal[0x28]) -> Literal["LANG_MAORI"]:...

    @overload
    def __getitem__(self, key: Literal[0x17]) -> Literal["LANG_RHAETO_ROMANCE"]:...

    @overload
    def __getitem__(self, key: Literal[0x3B]) -> Literal["LANG_SAAMI"]:...

    @overload
    def __getitem__(self, key: Literal[0x2E]) -> Literal["LANG_SORBIAN"]:...

    @overload
    def __getitem__(self, key: Literal[0x30]) -> Literal["LANG_SUTU"]:...

    @overload
    def __getitem__(self, key: Literal[0x31]) -> Literal["LANG_TSONGA"]:...

    @overload
    def __getitem__(self, key: Literal[0x32]) -> Literal["LANG_TSWANA"]:...

    @overload
    def __getitem__(self, key: Literal[0x33]) -> Literal["LANG_VENDA"]:...

    @overload
    def __getitem__(self, key: Literal[0x34]) -> Literal["LANG_XHOSA"]:...

    @overload
    def __getitem__(self, key: Literal[0x35]) -> Literal["LANG_ZULU"]:...

    @overload
    def __getitem__(self, key: Literal[0x8F]) -> Literal["LANG_ESPERANTO"]:...

    @overload
    def __getitem__(self, key: Literal[0x90]) -> Literal["LANG_WALON"]:...

    @overload
    def __getitem__(self, key: Literal[0x91]) -> Literal["LANG_CORNISH"]:...

    @overload
    def __getitem__(self, key: Literal[0x92]) -> Literal["LANG_WELSH"]:...

    @overload
    def __getitem__(self, key: Literal[0x93]) -> Literal["LANG_BRETON"]:...

    @overload
    def __getitem__(self, key: Literal["LANG_NEUTRAL"]) -> Literal[0x00]:...

    @overload
    def __getitem__(self, key: Literal["LANG_INVARIANT"]) -> Literal[0x7F]:...

    @overload
    def __getitem__(self, key: Literal["LANG_AFRIKAANS"]) -> Literal[0x36]:...

    @overload
    def __getitem__(self, key: Literal["LANG_ALBANIAN"]) -> Literal[0x1C]:...

    @overload
    def __getitem__(self, key: Literal["LANG_ARABIC"]) -> Literal[0x01]:...

    @overload
    def __getitem__(self, key: Literal["LANG_ARMENIAN"]) -> Literal[0x2B]:...

    @overload
    def __getitem__(self, key: Literal["LANG_ASSAMESE"]) -> Literal[0x4D]:...

    @overload
    def __getitem__(self, key: Literal["LANG_AZERI"]) -> Literal[0x2C]:...

    @overload
    def __getitem__(self, key: Literal["LANG_BASQUE"]) -> Literal[0x2D]:...

    @overload
    def __getitem__(self, key: Literal["LANG_BELARUSIAN"]) -> Literal[0x23]:...

    @overload
    def __getitem__(self, key: Literal["LANG_BENGALI"]) -> Literal[0x45]:...

    @overload
    def __getitem__(self, key: Literal["LANG_BULGARIAN"]) -> Literal[0x02]:...

    @overload
    def __getitem__(self, key: Literal["LANG_CATALAN"]) -> Literal[0x03]:...

    @overload
    def __getitem__(self, key: Literal["LANG_CHINESE"]) -> Literal[0x04]:...

    @overload
    def __getitem__(self, key: Literal["LANG_CROATIAN"]) -> Literal[0x1A]:...

    @overload
    def __getitem__(self, key: Literal["LANG_CZECH"]) -> Literal[0x05]:...

    @overload
    def __getitem__(self, key: Literal["LANG_DANISH"]) -> Literal[0x06]:...

    @overload
    def __getitem__(self, key: Literal["LANG_DIVEHI"]) -> Literal[0x65]:...

    @overload
    def __getitem__(self, key: Literal["LANG_DUTCH"]) -> Literal[0x13]:...

    @overload
    def __getitem__(self, key: Literal["LANG_ENGLISH"]) -> Literal[0x09]:...

    @overload
    def __getitem__(self, key: Literal["LANG_ESTONIAN"]) -> Literal[0x25]:...

    @overload
    def __getitem__(self, key: Literal["LANG_FAEROESE"]) -> Literal[0x38]:...

    @overload
    def __getitem__(self, key: Literal["LANG_FARSI"]) -> Literal[0x29]:...

    @overload
    def __getitem__(self, key: Literal["LANG_FINNISH"]) -> Literal[0x0B]:...

    @overload
    def __getitem__(self, key: Literal["LANG_FRENCH"]) -> Literal[0x0C]:...

    @overload
    def __getitem__(self, key: Literal["LANG_GALICIAN"]) -> Literal[0x56]:...

    @overload
    def __getitem__(self, key: Literal["LANG_GEORGIAN"]) -> Literal[0x37]:...

    @overload
    def __getitem__(self, key: Literal["LANG_GERMAN"]) -> Literal[0x07]:...

    @overload
    def __getitem__(self, key: Literal["LANG_GREEK"]) -> Literal[0x08]:...

    @overload
    def __getitem__(self, key: Literal["LANG_GUJARATI"]) -> Literal[0x47]:...

    @overload
    def __getitem__(self, key: Literal["LANG_HEBREW"]) -> Literal[0x0D]:...

    @overload
    def __getitem__(self, key: Literal["LANG_HINDI"]) -> Literal[0x39]:...

    @overload
    def __getitem__(self, key: Literal["LANG_HUNGARIAN"]) -> Literal[0x0E]:...

    @overload
    def __getitem__(self, key: Literal["LANG_ICELANDIC"]) -> Literal[0x0F]:...

    @overload
    def __getitem__(self, key: Literal["LANG_INDONESIAN"]) -> Literal[0x21]:...

    @overload
    def __getitem__(self, key: Literal["LANG_ITALIAN"]) -> Literal[0x10]:...

    @overload
    def __getitem__(self, key: Literal["LANG_JAPANESE"]) -> Literal[0x11]:...

    @overload
    def __getitem__(self, key: Literal["LANG_KANNADA"]) -> Literal[0x4B]:...

    @overload
    def __getitem__(self, key: Literal["LANG_KASHMIRI"]) -> Literal[0x60]:...

    @overload
    def __getitem__(self, key: Literal["LANG_KAZAK"]) -> Literal[0x3F]:...

    @overload
    def __getitem__(self, key: Literal["LANG_KONKANI"]) -> Literal[0x57]:...

    @overload
    def __getitem__(self, key: Literal["LANG_KOREAN"]) -> Literal[0x12]:...

    @overload
    def __getitem__(self, key: Literal["LANG_KYRGYZ"]) -> Literal[0x40]:...

    @overload
    def __getitem__(self, key: Literal["LANG_LATVIAN"]) -> Literal[0x26]:...

    @overload
    def __getitem__(self, key: Literal["LANG_LITHUANIAN"]) -> Literal[0x27]:...

    @overload
    def __getitem__(self, key: Literal["LANG_MACEDONIAN"]) -> Literal[0x2F]:...

    @overload
    def __getitem__(self, key: Literal["LANG_MALAY"]) -> Literal[0x3E]:...

    @overload
    def __getitem__(self, key: Literal["LANG_MALAYALAM"]) -> Literal[0x4C]:...

    @overload
    def __getitem__(self, key: Literal["LANG_MANIPURI"]) -> Literal[0x58]:...

    @overload
    def __getitem__(self, key: Literal["LANG_MARATHI"]) -> Literal[0x4E]:...

    @overload
    def __getitem__(self, key: Literal["LANG_MONGOLIAN"]) -> Literal[0x50]:...

    @overload
    def __getitem__(self, key: Literal["LANG_NEPALI"]) -> Literal[0x61]:...

    @overload
    def __getitem__(self, key: Literal["LANG_NORWEGIAN"]) -> Literal[0x14]:...

    @overload
    def __getitem__(self, key: Literal["LANG_ORIYA"]) -> Literal[0x48]:...

    @overload
    def __getitem__(self, key: Literal["LANG_POLISH"]) -> Literal[0x15]:...

    @overload
    def __getitem__(self, key: Literal["LANG_PORTUGUESE"]) -> Literal[0x16]:...

    @overload
    def __getitem__(self, key: Literal["LANG_PUNJABI"]) -> Literal[0x46]:...

    @overload
    def __getitem__(self, key: Literal["LANG_ROMANIAN"]) -> Literal[0x18]:...

    @overload
    def __getitem__(self, key: Literal["LANG_RUSSIAN"]) -> Literal[0x19]:...

    @overload
    def __getitem__(self, key: Literal["LANG_SANSKRIT"]) -> Literal[0x4F]:...

    @overload
    def __getitem__(self, key: Literal["LANG_SERBIAN"]) -> Literal[0x1A]:...

    @overload
    def __getitem__(self, key: Literal["LANG_SINDHI"]) -> Literal[0x59]:...

    @overload
    def __getitem__(self, key: Literal["LANG_SLOVAK"]) -> Literal[0x1B]:...

    @overload
    def __getitem__(self, key: Literal["LANG_SLOVENIAN"]) -> Literal[0x24]:...

    @overload
    def __getitem__(self, key: Literal["LANG_SPANISH"]) -> Literal[0x0A]:...

    @overload
    def __getitem__(self, key: Literal["LANG_SWAHILI"]) -> Literal[0x41]:...

    @overload
    def __getitem__(self, key: Literal["LANG_SWEDISH"]) -> Literal[0x1D]:...

    @overload
    def __getitem__(self, key: Literal["LANG_SYRIAC"]) -> Literal[0x5A]:...

    @overload
    def __getitem__(self, key: Literal["LANG_TAMIL"]) -> Literal[0x49]:...

    @overload
    def __getitem__(self, key: Literal["LANG_TATAR"]) -> Literal[0x44]:...

    @overload
    def __getitem__(self, key: Literal["LANG_TELUGU"]) -> Literal[0x4A]:...

    @overload
    def __getitem__(self, key: Literal["LANG_THAI"]) -> Literal[0x1E]:...

    @overload
    def __getitem__(self, key: Literal["LANG_TURKISH"]) -> Literal[0x1F]:...

    @overload
    def __getitem__(self, key: Literal["LANG_UKRAINIAN"]) -> Literal[0x22]:...

    @overload
    def __getitem__(self, key: Literal["LANG_URDU"]) -> Literal[0x20]:...

    @overload
    def __getitem__(self, key: Literal["LANG_UZBEK"]) -> Literal[0x43]:...

    @overload
    def __getitem__(self, key: Literal["LANG_VIETNAMESE"]) -> Literal[0x2A]:...

    @overload
    def __getitem__(self, key: Literal["LANG_GAELIC"]) -> Literal[0x3C]:...

    @overload
    def __getitem__(self, key: Literal["LANG_MALTESE"]) -> Literal[0x3A]:...

    @overload
    def __getitem__(self, key: Literal["LANG_MAORI"]) -> Literal[0x28]:...

    @overload
    def __getitem__(self, key: Literal["LANG_RHAETO_ROMANCE"]) -> Literal[0x17]:...

    @overload
    def __getitem__(self, key: Literal["LANG_SAAMI"]) -> Literal[0x3B]:...

    @overload
    def __getitem__(self, key: Literal["LANG_SORBIAN"]) -> Literal[0x2E]:...

    @overload
    def __getitem__(self, key: Literal["LANG_SUTU"]) -> Literal[0x30]:...

    @overload
    def __getitem__(self, key: Literal["LANG_TSONGA"]) -> Literal[0x31]:...

    @overload
    def __getitem__(self, key: Literal["LANG_TSWANA"]) -> Literal[0x32]:...

    @overload
    def __getitem__(self, key: Literal["LANG_VENDA"]) -> Literal[0x33]:...

    @overload
    def __getitem__(self, key: Literal["LANG_XHOSA"]) -> Literal[0x34]:...

    @overload
    def __getitem__(self, key: Literal["LANG_ZULU"]) -> Literal[0x35]:...

    @overload
    def __getitem__(self, key: Literal["LANG_ESPERANTO"]) -> Literal[0x8F]:...

    @overload
    def __getitem__(self, key: Literal["LANG_WALON"]) -> Literal[0x90]:...

    @overload
    def __getitem__(self, key: Literal["LANG_CORNISH"]) -> Literal[0x91]:...

    @overload
    def __getitem__(self, key: Literal["LANG_WELSH"]) -> Literal[0x92]:...

    @overload
    def __getitem__(self, key: Literal["LANG_BRETON"]) -> Literal[0x93]:...
LANG_DICT_NAMES = Literal[
    "LANG_AFRIKAANS",
    "LANG_ALBANIAN",
    "LANG_ARABIC",
    "LANG_ARMENIAN",
    "LANG_ASSAMESE",
    "LANG_AZERI",
    "LANG_BASQUE",
    "LANG_BELARUSIAN",
    "LANG_BENGALI",
    "LANG_BRETON",
    "LANG_BULGARIAN",
    "LANG_CATALAN",
    "LANG_CHINESE",
    "LANG_CORNISH",
    "LANG_CROATIAN",
    "LANG_CZECH",
    "LANG_DANISH",
    "LANG_DIVEHI",
    "LANG_DUTCH",
    "LANG_ENGLISH",
    "LANG_ESPERANTO",
    "LANG_ESTONIAN",
    "LANG_FAEROESE",
    "LANG_FARSI",
    "LANG_FINNISH",
    "LANG_FRENCH",
    "LANG_GAELIC",
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
    "LANG_INVARIANT",
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
    "LANG_MALTESE",
    "LANG_MANIPURI",
    "LANG_MAORI",
    "LANG_MARATHI",
    "LANG_MONGOLIAN",
    "LANG_NEPALI",
    "LANG_NEUTRAL",
    "LANG_NORWEGIAN",
    "LANG_ORIYA",
    "LANG_POLISH",
    "LANG_PORTUGUESE",
    "LANG_PUNJABI",
    "LANG_RHAETO_ROMANCE",
    "LANG_ROMANIAN",
    "LANG_RUSSIAN",
    "LANG_SAAMI",
    "LANG_SANSKRIT",
    "LANG_SERBIAN",
    "LANG_SINDHI",
    "LANG_SLOVAK",
    "LANG_SLOVENIAN",
    "LANG_SORBIAN",
    "LANG_SPANISH",
    "LANG_SUTU",
    "LANG_SWAHILI",
    "LANG_SWEDISH",
    "LANG_SYRIAC",
    "LANG_TAMIL",
    "LANG_TATAR",
    "LANG_TELUGU",
    "LANG_THAI",
    "LANG_TSONGA",
    "LANG_TSWANA",
    "LANG_TURKISH",
    "LANG_UKRAINIAN",
    "LANG_URDU",
    "LANG_UZBEK",
    "LANG_VENDA",
    "LANG_VIETNAMESE",
    "LANG_WALON",
    "LANG_WELSH",
    "LANG_XHOSA",
    "LANG_ZULU",
]
LANG_DICT_VALUES = Literal[
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
class SUBLANG_DICT(_NAME_LOOKUP[int, str]):
    @overload
    def __getitem__(self, key: Literal["SUBLANG_NEUTRAL"]) -> Literal[0x00]:...

    @overload
    def __getitem__(self, key: Literal["SUBLANG_DEFAULT"]) -> Literal[0x01]:...

    @overload
    def __getitem__(self, key: Literal["SUBLANG_SYS_DEFAULT"]) -> Literal[0x02]:...

    @overload
    def __getitem__(self, key: Literal["SUBLANG_ARABIC_SAUDI_ARABIA"]) -> Literal[0x01]:...

    @overload
    def __getitem__(self, key: Literal["SUBLANG_ARABIC_IRAQ"]) -> Literal[0x02]:...

    @overload
    def __getitem__(self, key: Literal["SUBLANG_ARABIC_EGYPT"]) -> Literal[0x03]:...

    @overload
    def __getitem__(self, key: Literal["SUBLANG_ARABIC_LIBYA"]) -> Literal[0x04]:...

    @overload
    def __getitem__(self, key: Literal["SUBLANG_ARABIC_ALGERIA"]) -> Literal[0x05]:...

    @overload
    def __getitem__(self, key: Literal["SUBLANG_ARABIC_MOROCCO"]) -> Literal[0x06]:...

    @overload
    def __getitem__(self, key: Literal["SUBLANG_ARABIC_TUNISIA"]) -> Literal[0x07]:...

    @overload
    def __getitem__(self, key: Literal["SUBLANG_ARABIC_OMAN"]) -> Literal[0x08]:...

    @overload
    def __getitem__(self, key: Literal["SUBLANG_ARABIC_YEMEN"]) -> Literal[0x09]:...

    @overload
    def __getitem__(self, key: Literal["SUBLANG_ARABIC_SYRIA"]) -> Literal[0x0A]:...

    @overload
    def __getitem__(self, key: Literal["SUBLANG_ARABIC_JORDAN"]) -> Literal[0x0B]:...

    @overload
    def __getitem__(self, key: Literal["SUBLANG_ARABIC_LEBANON"]) -> Literal[0x0C]:...

    @overload
    def __getitem__(self, key: Literal["SUBLANG_ARABIC_KUWAIT"]) -> Literal[0x0D]:...

    @overload
    def __getitem__(self, key: Literal["SUBLANG_ARABIC_UAE"]) -> Literal[0x0E]:...

    @overload
    def __getitem__(self, key: Literal["SUBLANG_ARABIC_BAHRAIN"]) -> Literal[0x0F]:...

    @overload
    def __getitem__(self, key: Literal["SUBLANG_ARABIC_QATAR"]) -> Literal[0x10]:...

    @overload
    def __getitem__(self, key: Literal["SUBLANG_AZERI_LATIN"]) -> Literal[0x01]:...

    @overload
    def __getitem__(self, key: Literal["SUBLANG_AZERI_CYRILLIC"]) -> Literal[0x02]:...

    @overload
    def __getitem__(self, key: Literal["SUBLANG_CHINESE_TRADITIONAL"]) -> Literal[0x01]:...

    @overload
    def __getitem__(self, key: Literal["SUBLANG_CHINESE_SIMPLIFIED"]) -> Literal[0x02]:...

    @overload
    def __getitem__(self, key: Literal["SUBLANG_CHINESE_HONGKONG"]) -> Literal[0x03]:...

    @overload
    def __getitem__(self, key: Literal["SUBLANG_CHINESE_SINGAPORE"]) -> Literal[0x04]:...

    @overload
    def __getitem__(self, key: Literal["SUBLANG_CHINESE_MACAU"]) -> Literal[0x05]:...

    @overload
    def __getitem__(self, key: Literal["SUBLANG_DUTCH"]) -> Literal[0x01]:...

    @overload
    def __getitem__(self, key: Literal["SUBLANG_DUTCH_BELGIAN"]) -> Literal[0x02]:...

    @overload
    def __getitem__(self, key: Literal["SUBLANG_ENGLISH_US"]) -> Literal[0x01]:...

    @overload
    def __getitem__(self, key: Literal["SUBLANG_ENGLISH_UK"]) -> Literal[0x02]:...

    @overload
    def __getitem__(self, key: Literal["SUBLANG_ENGLISH_AUS"]) -> Literal[0x03]:...

    @overload
    def __getitem__(self, key: Literal["SUBLANG_ENGLISH_CAN"]) -> Literal[0x04]:...

    @overload
    def __getitem__(self, key: Literal["SUBLANG_ENGLISH_NZ"]) -> Literal[0x05]:...

    @overload
    def __getitem__(self, key: Literal["SUBLANG_ENGLISH_EIRE"]) -> Literal[0x06]:...

    @overload
    def __getitem__(self, key: Literal["SUBLANG_ENGLISH_SOUTH_AFRICA"]) -> Literal[0x07]:...

    @overload
    def __getitem__(self, key: Literal["SUBLANG_ENGLISH_JAMAICA"]) -> Literal[0x08]:...

    @overload
    def __getitem__(self, key: Literal["SUBLANG_ENGLISH_CARIBBEAN"]) -> Literal[0x09]:...

    @overload
    def __getitem__(self, key: Literal["SUBLANG_ENGLISH_BELIZE"]) -> Literal[0x0A]:...

    @overload
    def __getitem__(self, key: Literal["SUBLANG_ENGLISH_TRINIDAD"]) -> Literal[0x0B]:...

    @overload
    def __getitem__(self, key: Literal["SUBLANG_ENGLISH_ZIMBABWE"]) -> Literal[0x0C]:...

    @overload
    def __getitem__(self, key: Literal["SUBLANG_ENGLISH_PHILIPPINES"]) -> Literal[0x0D]:...

    @overload
    def __getitem__(self, key: Literal["SUBLANG_FRENCH"]) -> Literal[0x01]:...

    @overload
    def __getitem__(self, key: Literal["SUBLANG_FRENCH_BELGIAN"]) -> Literal[0x02]:...

    @overload
    def __getitem__(self, key: Literal["SUBLANG_FRENCH_CANADIAN"]) -> Literal[0x03]:...

    @overload
    def __getitem__(self, key: Literal["SUBLANG_FRENCH_SWISS"]) -> Literal[0x04]:...

    @overload
    def __getitem__(self, key: Literal["SUBLANG_FRENCH_LUXEMBOURG"]) -> Literal[0x05]:...

    @overload
    def __getitem__(self, key: Literal["SUBLANG_FRENCH_MONACO"]) -> Literal[0x06]:...

    @overload
    def __getitem__(self, key: Literal["SUBLANG_GERMAN"]) -> Literal[0x01]:...

    @overload
    def __getitem__(self, key: Literal["SUBLANG_GERMAN_SWISS"]) -> Literal[0x02]:...

    @overload
    def __getitem__(self, key: Literal["SUBLANG_GERMAN_AUSTRIAN"]) -> Literal[0x03]:...

    @overload
    def __getitem__(self, key: Literal["SUBLANG_GERMAN_LUXEMBOURG"]) -> Literal[0x04]:...

    @overload
    def __getitem__(self, key: Literal["SUBLANG_GERMAN_LIECHTENSTEIN"]) -> Literal[0x05]:...

    @overload
    def __getitem__(self, key: Literal["SUBLANG_ITALIAN"]) -> Literal[0x01]:...

    @overload
    def __getitem__(self, key: Literal["SUBLANG_ITALIAN_SWISS"]) -> Literal[0x02]:...

    @overload
    def __getitem__(self, key: Literal["SUBLANG_KASHMIRI_SASIA"]) -> Literal[0x02]:...

    @overload
    def __getitem__(self, key: Literal["SUBLANG_KASHMIRI_INDIA"]) -> Literal[0x02]:...

    @overload
    def __getitem__(self, key: Literal["SUBLANG_KOREAN"]) -> Literal[0x01]:...

    @overload
    def __getitem__(self, key: Literal["SUBLANG_LITHUANIAN"]) -> Literal[0x01]:...

    @overload
    def __getitem__(self, key: Literal["SUBLANG_MALAY_MALAYSIA"]) -> Literal[0x01]:...

    @overload
    def __getitem__(self, key: Literal["SUBLANG_MALAY_BRUNEI_DARUSSALAM"]) -> Literal[0x02]:...

    @overload
    def __getitem__(self, key: Literal["SUBLANG_NEPALI_INDIA"]) -> Literal[0x02]:...

    @overload
    def __getitem__(self, key: Literal["SUBLANG_NORWEGIAN_BOKMAL"]) -> Literal[0x01]:...

    @overload
    def __getitem__(self, key: Literal["SUBLANG_NORWEGIAN_NYNORSK"]) -> Literal[0x02]:...

    @overload
    def __getitem__(self, key: Literal["SUBLANG_PORTUGUESE"]) -> Literal[0x02]:...

    @overload
    def __getitem__(self, key: Literal["SUBLANG_PORTUGUESE_BRAZILIAN"]) -> Literal[0x01]:...

    @overload
    def __getitem__(self, key: Literal["SUBLANG_SERBIAN_LATIN"]) -> Literal[0x02]:...

    @overload
    def __getitem__(self, key: Literal["SUBLANG_SERBIAN_CYRILLIC"]) -> Literal[0x03]:...

    @overload
    def __getitem__(self, key: Literal["SUBLANG_SPANISH"]) -> Literal[0x01]:...

    @overload
    def __getitem__(self, key: Literal["SUBLANG_SPANISH_MEXICAN"]) -> Literal[0x02]:...

    @overload
    def __getitem__(self, key: Literal["SUBLANG_SPANISH_MODERN"]) -> Literal[0x03]:...

    @overload
    def __getitem__(self, key: Literal["SUBLANG_SPANISH_GUATEMALA"]) -> Literal[0x04]:...

    @overload
    def __getitem__(self, key: Literal["SUBLANG_SPANISH_COSTA_RICA"]) -> Literal[0x05]:...

    @overload
    def __getitem__(self, key: Literal["SUBLANG_SPANISH_PANAMA"]) -> Literal[0x06]:...

    @overload
    def __getitem__(self, key: Literal["SUBLANG_SPANISH_DOMINICAN_REPUBLIC"]) -> Literal[0x07]:...

    @overload
    def __getitem__(self, key: Literal["SUBLANG_SPANISH_VENEZUELA"]) -> Literal[0x08]:...

    @overload
    def __getitem__(self, key: Literal["SUBLANG_SPANISH_COLOMBIA"]) -> Literal[0x09]:...

    @overload
    def __getitem__(self, key: Literal["SUBLANG_SPANISH_PERU"]) -> Literal[0x0A]:...

    @overload
    def __getitem__(self, key: Literal["SUBLANG_SPANISH_ARGENTINA"]) -> Literal[0x0B]:...

    @overload
    def __getitem__(self, key: Literal["SUBLANG_SPANISH_ECUADOR"]) -> Literal[0x0C]:...

    @overload
    def __getitem__(self, key: Literal["SUBLANG_SPANISH_CHILE"]) -> Literal[0x0D]:...

    @overload
    def __getitem__(self, key: Literal["SUBLANG_SPANISH_URUGUAY"]) -> Literal[0x0E]:...

    @overload
    def __getitem__(self, key: Literal["SUBLANG_SPANISH_PARAGUAY"]) -> Literal[0x0F]:...

    @overload
    def __getitem__(self, key: Literal["SUBLANG_SPANISH_BOLIVIA"]) -> Literal[0x10]:...

    @overload
    def __getitem__(self, key: Literal["SUBLANG_SPANISH_EL_SALVADOR"]) -> Literal[0x11]:...

    @overload
    def __getitem__(self, key: Literal["SUBLANG_SPANISH_HONDURAS"]) -> Literal[0x12]:...

    @overload
    def __getitem__(self, key: Literal["SUBLANG_SPANISH_NICARAGUA"]) -> Literal[0x13]:...

    @overload
    def __getitem__(self, key: Literal["SUBLANG_SPANISH_PUERTO_RICO"]) -> Literal[0x14]:...

    @overload
    def __getitem__(self, key: Literal["SUBLANG_SWEDISH"]) -> Literal[0x01]:...

    @overload
    def __getitem__(self, key: Literal["SUBLANG_SWEDISH_FINLAND"]) -> Literal[0x02]:...

    @overload
    def __getitem__(self, key: Literal["SUBLANG_URDU_PAKISTAN"]) -> Literal[0x01]:...

    @overload
    def __getitem__(self, key: Literal["SUBLANG_URDU_INDIA"]) -> Literal[0x02]:...

    @overload
    def __getitem__(self, key: Literal["SUBLANG_UZBEK_LATIN"]) -> Literal[0x01]:...

    @overload
    def __getitem__(self, key: Literal["SUBLANG_UZBEK_CYRILLIC"]) -> Literal[0x02]:...

    @overload
    def __getitem__(self, key: Literal["SUBLANG_DUTCH_SURINAM"]) -> Literal[0x03]:...

    @overload
    def __getitem__(self, key: Literal["SUBLANG_ROMANIAN"]) -> Literal[0x01]:...

    @overload
    def __getitem__(self, key: Literal["SUBLANG_ROMANIAN_MOLDAVIA"]) -> Literal[0x02]:...

    @overload
    def __getitem__(self, key: Literal["SUBLANG_RUSSIAN"]) -> Literal[0x01]:...

    @overload
    def __getitem__(self, key: Literal["SUBLANG_RUSSIAN_MOLDAVIA"]) -> Literal[0x02]:...

    @overload
    def __getitem__(self, key: Literal["SUBLANG_CROATIAN"]) -> Literal[0x01]:...

    @overload
    def __getitem__(self, key: Literal["SUBLANG_LITHUANIAN_CLASSIC"]) -> Literal[0x02]:...

    @overload
    def __getitem__(self, key: Literal["SUBLANG_GAELIC"]) -> Literal[0x01]:...

    @overload
    def __getitem__(self, key: Literal["SUBLANG_GAELIC_SCOTTISH"]) -> Literal[0x02]:...

    @overload
    def __getitem__(self, key: Literal["SUBLANG_GAELIC_MANX"]) -> Literal[0x03]:...

    @overload
    def __getitem__(self, key: Literal[0x00]) -> tuple[Literal["SUBLANG_NEUTRAL"]]:...

    @overload
    def __getitem__(self, key: Literal[0x01]) -> tuple[Literal["SUBLANG_DEFAULT"],Literal["SUBLANG_ARABIC_SAUDI_ARABIA"],Literal["SUBLANG_AZERI_LATIN"],Literal["SUBLANG_CHINESE_TRADITIONAL"],Literal["SUBLANG_DUTCH"],Literal["SUBLANG_ENGLISH_US"],Literal["SUBLANG_FRENCH"],Literal["SUBLANG_GERMAN"],Literal["SUBLANG_ITALIAN"],Literal["SUBLANG_KOREAN"],Literal["SUBLANG_LITHUANIAN"],Literal["SUBLANG_MALAY_MALAYSIA"],Literal["SUBLANG_NORWEGIAN_BOKMAL"],Literal["SUBLANG_PORTUGUESE_BRAZILIAN"],Literal["SUBLANG_SPANISH"],Literal["SUBLANG_SWEDISH"],Literal["SUBLANG_URDU_PAKISTAN"],Literal["SUBLANG_UZBEK_LATIN"],Literal["SUBLANG_ROMANIAN"],Literal["SUBLANG_RUSSIAN"],Literal["SUBLANG_CROATIAN"],Literal["SUBLANG_GAELIC"]]:...

    @overload
    def __getitem__(self, key: Literal[0x02]) -> tuple[Literal["SUBLANG_SYS_DEFAULT"],Literal["SUBLANG_ARABIC_IRAQ"],Literal["SUBLANG_AZERI_CYRILLIC"],Literal["SUBLANG_CHINESE_SIMPLIFIED"],Literal["SUBLANG_DUTCH_BELGIAN"],Literal["SUBLANG_ENGLISH_UK"],Literal["SUBLANG_FRENCH_BELGIAN"],Literal["SUBLANG_GERMAN_SWISS"],Literal["SUBLANG_ITALIAN_SWISS"],Literal["SUBLANG_KASHMIRI_SASIA"],Literal["SUBLANG_KASHMIRI_INDIA"],Literal["SUBLANG_MALAY_BRUNEI_DARUSSALAM"],Literal["SUBLANG_NEPALI_INDIA"],Literal["SUBLANG_NORWEGIAN_NYNORSK"],Literal["SUBLANG_PORTUGUESE"],Literal["SUBLANG_SERBIAN_LATIN"],Literal["SUBLANG_SPANISH_MEXICAN"],Literal["SUBLANG_SWEDISH_FINLAND"],Literal["SUBLANG_URDU_INDIA"],Literal["SUBLANG_UZBEK_CYRILLIC"],Literal["SUBLANG_ROMANIAN_MOLDAVIA"],Literal["SUBLANG_RUSSIAN_MOLDAVIA"],Literal["SUBLANG_LITHUANIAN_CLASSIC"],Literal["SUBLANG_GAELIC_SCOTTISH"]]:...

    @overload
    def __getitem__(self, key: Literal[0x03]) -> tuple[Literal["SUBLANG_ARABIC_EGYPT"],Literal["SUBLANG_CHINESE_HONGKONG"],Literal["SUBLANG_ENGLISH_AUS"],Literal["SUBLANG_FRENCH_CANADIAN"],Literal["SUBLANG_GERMAN_AUSTRIAN"],Literal["SUBLANG_SERBIAN_CYRILLIC"],Literal["SUBLANG_SPANISH_MODERN"],Literal["SUBLANG_DUTCH_SURINAM"],Literal["SUBLANG_GAELIC_MANX"]]:...

    @overload
    def __getitem__(self, key: Literal[0x04]) -> tuple[Literal["SUBLANG_ARABIC_LIBYA"],Literal["SUBLANG_CHINESE_SINGAPORE"],Literal["SUBLANG_ENGLISH_CAN"],Literal["SUBLANG_FRENCH_SWISS"],Literal["SUBLANG_GERMAN_LUXEMBOURG"],Literal["SUBLANG_SPANISH_GUATEMALA"]]:...

    @overload
    def __getitem__(self, key: Literal[0x05]) -> tuple[Literal["SUBLANG_ARABIC_ALGERIA"],Literal["SUBLANG_CHINESE_MACAU"],Literal["SUBLANG_ENGLISH_NZ"],Literal["SUBLANG_FRENCH_LUXEMBOURG"],Literal["SUBLANG_GERMAN_LIECHTENSTEIN"],Literal["SUBLANG_SPANISH_COSTA_RICA"]]:...

    @overload
    def __getitem__(self, key: Literal[0x06]) -> tuple[Literal["SUBLANG_ARABIC_MOROCCO"],Literal["SUBLANG_ENGLISH_EIRE"],Literal["SUBLANG_FRENCH_MONACO"],Literal["SUBLANG_SPANISH_PANAMA"]]:...

    @overload
    def __getitem__(self, key: Literal[0x07]) -> tuple[Literal["SUBLANG_ARABIC_TUNISIA"],Literal["SUBLANG_ENGLISH_SOUTH_AFRICA"],Literal["SUBLANG_SPANISH_DOMINICAN_REPUBLIC"]]:...

    @overload
    def __getitem__(self, key: Literal[0x08]) -> tuple[Literal["SUBLANG_ARABIC_OMAN"],Literal["SUBLANG_ENGLISH_JAMAICA"],Literal["SUBLANG_SPANISH_VENEZUELA"]]:...

    @overload
    def __getitem__(self, key: Literal[0x09]) -> tuple[Literal["SUBLANG_ARABIC_YEMEN"],Literal["SUBLANG_ENGLISH_CARIBBEAN"],Literal["SUBLANG_SPANISH_COLOMBIA"]]:...

    @overload
    def __getitem__(self, key: Literal[0x0A]) -> tuple[Literal["SUBLANG_ARABIC_SYRIA"],Literal["SUBLANG_ENGLISH_BELIZE"],Literal["SUBLANG_SPANISH_PERU"]]:...

    @overload
    def __getitem__(self, key: Literal[0x0B]) -> tuple[Literal["SUBLANG_ARABIC_JORDAN"],Literal["SUBLANG_ENGLISH_TRINIDAD"],Literal["SUBLANG_SPANISH_ARGENTINA"]]:...

    @overload
    def __getitem__(self, key: Literal[0x0C]) -> tuple[Literal["SUBLANG_ARABIC_LEBANON"],Literal["SUBLANG_ENGLISH_ZIMBABWE"],Literal["SUBLANG_SPANISH_ECUADOR"]]:...

    @overload
    def __getitem__(self, key: Literal[0x0D]) -> tuple[Literal["SUBLANG_ARABIC_KUWAIT"],Literal["SUBLANG_ENGLISH_PHILIPPINES"],Literal["SUBLANG_SPANISH_CHILE"]]:...

    @overload
    def __getitem__(self, key: Literal[0x0E]) -> tuple[Literal["SUBLANG_ARABIC_UAE"],Literal["SUBLANG_SPANISH_URUGUAY"]]:...

    @overload
    def __getitem__(self, key: Literal[0x0F]) -> tuple[Literal["SUBLANG_ARABIC_BAHRAIN"],Literal["SUBLANG_SPANISH_PARAGUAY"]]:...

    @overload
    def __getitem__(self, key: Literal[0x10]) -> tuple[Literal["SUBLANG_ARABIC_QATAR"],Literal["SUBLANG_SPANISH_BOLIVIA"]]:...

    @overload
    def __getitem__(self, key: Literal[0x11]) -> tuple[Literal["SUBLANG_SPANISH_EL_SALVADOR"]]:...

    @overload
    def __getitem__(self, key: Literal[0x12]) -> tuple[Literal["SUBLANG_SPANISH_HONDURAS"]]:...

    @overload
    def __getitem__(self, key: Literal[0x13]) -> tuple[Literal["SUBLANG_SPANISH_NICARAGUA"]]:...

    @overload
    def __getitem__(self, key: Literal[0x14]) -> tuple[Literal["SUBLANG_SPANISH_PUERTO_RICO"]]:...
SUBLANG_DICT_NAMES = Literal[
    "SUBLANG_ARABIC_ALGERIA",
    "SUBLANG_ARABIC_BAHRAIN",
    "SUBLANG_ARABIC_EGYPT",
    "SUBLANG_ARABIC_IRAQ",
    "SUBLANG_ARABIC_JORDAN",
    "SUBLANG_ARABIC_KUWAIT",
    "SUBLANG_ARABIC_LEBANON",
    "SUBLANG_ARABIC_LIBYA",
    "SUBLANG_ARABIC_MOROCCO",
    "SUBLANG_ARABIC_OMAN",
    "SUBLANG_ARABIC_QATAR",
    "SUBLANG_ARABIC_SAUDI_ARABIA",
    "SUBLANG_ARABIC_SYRIA",
    "SUBLANG_ARABIC_TUNISIA",
    "SUBLANG_ARABIC_UAE",
    "SUBLANG_ARABIC_YEMEN",
    "SUBLANG_AZERI_CYRILLIC",
    "SUBLANG_AZERI_LATIN",
    "SUBLANG_CHINESE_HONGKONG",
    "SUBLANG_CHINESE_MACAU",
    "SUBLANG_CHINESE_SIMPLIFIED",
    "SUBLANG_CHINESE_SINGAPORE",
    "SUBLANG_CHINESE_TRADITIONAL",
    "SUBLANG_CROATIAN",
    "SUBLANG_DEFAULT",
    "SUBLANG_DUTCH",
    "SUBLANG_DUTCH_BELGIAN",
    "SUBLANG_DUTCH_SURINAM",
    "SUBLANG_ENGLISH_AUS",
    "SUBLANG_ENGLISH_BELIZE",
    "SUBLANG_ENGLISH_CAN",
    "SUBLANG_ENGLISH_CARIBBEAN",
    "SUBLANG_ENGLISH_EIRE",
    "SUBLANG_ENGLISH_JAMAICA",
    "SUBLANG_ENGLISH_NZ",
    "SUBLANG_ENGLISH_PHILIPPINES",
    "SUBLANG_ENGLISH_SOUTH_AFRICA",
    "SUBLANG_ENGLISH_TRINIDAD",
    "SUBLANG_ENGLISH_UK",
    "SUBLANG_ENGLISH_US",
    "SUBLANG_ENGLISH_ZIMBABWE",
    "SUBLANG_FRENCH",
    "SUBLANG_FRENCH_BELGIAN",
    "SUBLANG_FRENCH_CANADIAN",
    "SUBLANG_FRENCH_LUXEMBOURG",
    "SUBLANG_FRENCH_MONACO",
    "SUBLANG_FRENCH_SWISS",
    "SUBLANG_GAELIC",
    "SUBLANG_GAELIC_MANX",
    "SUBLANG_GAELIC_SCOTTISH",
    "SUBLANG_GERMAN",
    "SUBLANG_GERMAN_AUSTRIAN",
    "SUBLANG_GERMAN_LIECHTENSTEIN",
    "SUBLANG_GERMAN_LUXEMBOURG",
    "SUBLANG_GERMAN_SWISS",
    "SUBLANG_ITALIAN",
    "SUBLANG_ITALIAN_SWISS",
    "SUBLANG_KASHMIRI_INDIA",
    "SUBLANG_KASHMIRI_SASIA",
    "SUBLANG_KOREAN",
    "SUBLANG_LITHUANIAN",
    "SUBLANG_LITHUANIAN_CLASSIC",
    "SUBLANG_MALAY_BRUNEI_DARUSSALAM",
    "SUBLANG_MALAY_MALAYSIA",
    "SUBLANG_NEPALI_INDIA",
    "SUBLANG_NEUTRAL",
    "SUBLANG_NORWEGIAN_BOKMAL",
    "SUBLANG_NORWEGIAN_NYNORSK",
    "SUBLANG_PORTUGUESE",
    "SUBLANG_PORTUGUESE_BRAZILIAN",
    "SUBLANG_ROMANIAN",
    "SUBLANG_ROMANIAN_MOLDAVIA",
    "SUBLANG_RUSSIAN",
    "SUBLANG_RUSSIAN_MOLDAVIA",
    "SUBLANG_SERBIAN_CYRILLIC",
    "SUBLANG_SERBIAN_LATIN",
    "SUBLANG_SPANISH",
    "SUBLANG_SPANISH_ARGENTINA",
    "SUBLANG_SPANISH_BOLIVIA",
    "SUBLANG_SPANISH_CHILE",
    "SUBLANG_SPANISH_COLOMBIA",
    "SUBLANG_SPANISH_COSTA_RICA",
    "SUBLANG_SPANISH_DOMINICAN_REPUBLIC",
    "SUBLANG_SPANISH_ECUADOR",
    "SUBLANG_SPANISH_EL_SALVADOR",
    "SUBLANG_SPANISH_GUATEMALA",
    "SUBLANG_SPANISH_HONDURAS",
    "SUBLANG_SPANISH_MEXICAN",
    "SUBLANG_SPANISH_MODERN",
    "SUBLANG_SPANISH_NICARAGUA",
    "SUBLANG_SPANISH_PANAMA",
    "SUBLANG_SPANISH_PARAGUAY",
    "SUBLANG_SPANISH_PERU",
    "SUBLANG_SPANISH_PUERTO_RICO",
    "SUBLANG_SPANISH_URUGUAY",
    "SUBLANG_SPANISH_VENEZUELA",
    "SUBLANG_SWEDISH",
    "SUBLANG_SWEDISH_FINLAND",
    "SUBLANG_SYS_DEFAULT",
    "SUBLANG_URDU_INDIA",
    "SUBLANG_URDU_PAKISTAN",
    "SUBLANG_UZBEK_CYRILLIC",
    "SUBLANG_UZBEK_LATIN",
]
SUBLANG_DICT_VALUES = Literal[
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
