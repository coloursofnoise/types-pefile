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


class ORD_NAMES_DICT(_NAME_LOOKUP[int, bytes]):
    @overload
    def __getitem__(self, key: Literal[1]) -> Literal[b'accept']:...

    @overload
    def __getitem__(self, key: Literal[2]) -> Literal[b'bind']:...

    @overload
    def __getitem__(self, key: Literal[3]) -> Literal[b'closesocket']:...

    @overload
    def __getitem__(self, key: Literal[4]) -> Literal[b'connect']:...

    @overload
    def __getitem__(self, key: Literal[5]) -> Literal[b'getpeername']:...

    @overload
    def __getitem__(self, key: Literal[6]) -> Literal[b'getsockname']:...

    @overload
    def __getitem__(self, key: Literal[7]) -> Literal[b'getsockopt']:...

    @overload
    def __getitem__(self, key: Literal[8]) -> Literal[b'htonl']:...

    @overload
    def __getitem__(self, key: Literal[9]) -> Literal[b'htons']:...

    @overload
    def __getitem__(self, key: Literal[10]) -> Literal[b'ioctlsocket']:...

    @overload
    def __getitem__(self, key: Literal[11]) -> Literal[b'inet_addr']:...

    @overload
    def __getitem__(self, key: Literal[12]) -> Literal[b'inet_ntoa']:...

    @overload
    def __getitem__(self, key: Literal[13]) -> Literal[b'listen']:...

    @overload
    def __getitem__(self, key: Literal[14]) -> Literal[b'ntohl']:...

    @overload
    def __getitem__(self, key: Literal[15]) -> Literal[b'ntohs']:...

    @overload
    def __getitem__(self, key: Literal[16]) -> Literal[b'recv']:...

    @overload
    def __getitem__(self, key: Literal[17]) -> Literal[b'recvfrom']:...

    @overload
    def __getitem__(self, key: Literal[18]) -> Literal[b'select']:...

    @overload
    def __getitem__(self, key: Literal[19]) -> Literal[b'send']:...

    @overload
    def __getitem__(self, key: Literal[20]) -> Literal[b'sendto']:...

    @overload
    def __getitem__(self, key: Literal[21]) -> Literal[b'setsockopt']:...

    @overload
    def __getitem__(self, key: Literal[22]) -> Literal[b'shutdown']:...

    @overload
    def __getitem__(self, key: Literal[23]) -> Literal[b'socket']:...

    @overload
    def __getitem__(self, key: Literal[24]) -> Literal[b'GetAddrInfoW']:...

    @overload
    def __getitem__(self, key: Literal[25]) -> Literal[b'GetNameInfoW']:...

    @overload
    def __getitem__(self, key: Literal[26]) -> Literal[b'WSApSetPostRoutine']:...

    @overload
    def __getitem__(self, key: Literal[27]) -> Literal[b'FreeAddrInfoW']:...

    @overload
    def __getitem__(self, key: Literal[28]) -> Literal[b'WPUCompleteOverlappedRequest']:...

    @overload
    def __getitem__(self, key: Literal[29]) -> Literal[b'WSAAccept']:...

    @overload
    def __getitem__(self, key: Literal[30]) -> Literal[b'WSAAddressToStringA']:...

    @overload
    def __getitem__(self, key: Literal[31]) -> Literal[b'WSAAddressToStringW']:...

    @overload
    def __getitem__(self, key: Literal[32]) -> Literal[b'WSACloseEvent']:...

    @overload
    def __getitem__(self, key: Literal[33]) -> Literal[b'WSAConnect']:...

    @overload
    def __getitem__(self, key: Literal[34]) -> Literal[b'WSACreateEvent']:...

    @overload
    def __getitem__(self, key: Literal[35]) -> Literal[b'WSADuplicateSocketA']:...

    @overload
    def __getitem__(self, key: Literal[36]) -> Literal[b'WSADuplicateSocketW']:...

    @overload
    def __getitem__(self, key: Literal[37]) -> Literal[b'WSAEnumNameSpaceProvidersA']:...

    @overload
    def __getitem__(self, key: Literal[38]) -> Literal[b'WSAEnumNameSpaceProvidersW']:...

    @overload
    def __getitem__(self, key: Literal[39]) -> Literal[b'WSAEnumNetworkEvents']:...

    @overload
    def __getitem__(self, key: Literal[40]) -> Literal[b'WSAEnumProtocolsA']:...

    @overload
    def __getitem__(self, key: Literal[41]) -> Literal[b'WSAEnumProtocolsW']:...

    @overload
    def __getitem__(self, key: Literal[42]) -> Literal[b'WSAEventSelect']:...

    @overload
    def __getitem__(self, key: Literal[43]) -> Literal[b'WSAGetOverlappedResult']:...

    @overload
    def __getitem__(self, key: Literal[44]) -> Literal[b'WSAGetQOSByName']:...

    @overload
    def __getitem__(self, key: Literal[45]) -> Literal[b'WSAGetServiceClassInfoA']:...

    @overload
    def __getitem__(self, key: Literal[46]) -> Literal[b'WSAGetServiceClassInfoW']:...

    @overload
    def __getitem__(self, key: Literal[47]) -> Literal[b'WSAGetServiceClassNameByClassIdA']:...

    @overload
    def __getitem__(self, key: Literal[48]) -> Literal[b'WSAGetServiceClassNameByClassIdW']:...

    @overload
    def __getitem__(self, key: Literal[49]) -> Literal[b'WSAHtonl']:...

    @overload
    def __getitem__(self, key: Literal[50]) -> Literal[b'WSAHtons']:...

    @overload
    def __getitem__(self, key: Literal[51]) -> Literal[b'gethostbyaddr']:...

    @overload
    def __getitem__(self, key: Literal[52]) -> Literal[b'gethostbyname']:...

    @overload
    def __getitem__(self, key: Literal[53]) -> Literal[b'getprotobyname']:...

    @overload
    def __getitem__(self, key: Literal[54]) -> Literal[b'getprotobynumber']:...

    @overload
    def __getitem__(self, key: Literal[55]) -> Literal[b'getservbyname']:...

    @overload
    def __getitem__(self, key: Literal[56]) -> Literal[b'getservbyport']:...

    @overload
    def __getitem__(self, key: Literal[57]) -> Literal[b'gethostname']:...

    @overload
    def __getitem__(self, key: Literal[58]) -> Literal[b'WSAInstallServiceClassA']:...

    @overload
    def __getitem__(self, key: Literal[59]) -> Literal[b'WSAInstallServiceClassW']:...

    @overload
    def __getitem__(self, key: Literal[60]) -> Literal[b'WSAIoctl']:...

    @overload
    def __getitem__(self, key: Literal[61]) -> Literal[b'WSAJoinLeaf']:...

    @overload
    def __getitem__(self, key: Literal[62]) -> Literal[b'WSALookupServiceBeginA']:...

    @overload
    def __getitem__(self, key: Literal[63]) -> Literal[b'WSALookupServiceBeginW']:...

    @overload
    def __getitem__(self, key: Literal[64]) -> Literal[b'WSALookupServiceEnd']:...

    @overload
    def __getitem__(self, key: Literal[65]) -> Literal[b'WSALookupServiceNextA']:...

    @overload
    def __getitem__(self, key: Literal[66]) -> Literal[b'WSALookupServiceNextW']:...

    @overload
    def __getitem__(self, key: Literal[67]) -> Literal[b'WSANSPIoctl']:...

    @overload
    def __getitem__(self, key: Literal[68]) -> Literal[b'WSANtohl']:...

    @overload
    def __getitem__(self, key: Literal[69]) -> Literal[b'WSANtohs']:...

    @overload
    def __getitem__(self, key: Literal[70]) -> Literal[b'WSAProviderConfigChange']:...

    @overload
    def __getitem__(self, key: Literal[71]) -> Literal[b'WSARecv']:...

    @overload
    def __getitem__(self, key: Literal[72]) -> Literal[b'WSARecvDisconnect']:...

    @overload
    def __getitem__(self, key: Literal[73]) -> Literal[b'WSARecvFrom']:...

    @overload
    def __getitem__(self, key: Literal[74]) -> Literal[b'WSARemoveServiceClass']:...

    @overload
    def __getitem__(self, key: Literal[75]) -> Literal[b'WSAResetEvent']:...

    @overload
    def __getitem__(self, key: Literal[76]) -> Literal[b'WSASend']:...

    @overload
    def __getitem__(self, key: Literal[77]) -> Literal[b'WSASendDisconnect']:...

    @overload
    def __getitem__(self, key: Literal[78]) -> Literal[b'WSASendTo']:...

    @overload
    def __getitem__(self, key: Literal[79]) -> Literal[b'WSASetEvent']:...

    @overload
    def __getitem__(self, key: Literal[80]) -> Literal[b'WSASetServiceA']:...

    @overload
    def __getitem__(self, key: Literal[81]) -> Literal[b'WSASetServiceW']:...

    @overload
    def __getitem__(self, key: Literal[82]) -> Literal[b'WSASocketA']:...

    @overload
    def __getitem__(self, key: Literal[83]) -> Literal[b'WSASocketW']:...

    @overload
    def __getitem__(self, key: Literal[84]) -> Literal[b'WSAStringToAddressA']:...

    @overload
    def __getitem__(self, key: Literal[85]) -> Literal[b'WSAStringToAddressW']:...

    @overload
    def __getitem__(self, key: Literal[86]) -> Literal[b'WSAWaitForMultipleEvents']:...

    @overload
    def __getitem__(self, key: Literal[87]) -> Literal[b'WSCDeinstallProvider']:...

    @overload
    def __getitem__(self, key: Literal[88]) -> Literal[b'WSCEnableNSProvider']:...

    @overload
    def __getitem__(self, key: Literal[89]) -> Literal[b'WSCEnumProtocols']:...

    @overload
    def __getitem__(self, key: Literal[90]) -> Literal[b'WSCGetProviderPath']:...

    @overload
    def __getitem__(self, key: Literal[91]) -> Literal[b'WSCInstallNameSpace']:...

    @overload
    def __getitem__(self, key: Literal[92]) -> Literal[b'WSCInstallProvider']:...

    @overload
    def __getitem__(self, key: Literal[93]) -> Literal[b'WSCUnInstallNameSpace']:...

    @overload
    def __getitem__(self, key: Literal[94]) -> Literal[b'WSCUpdateProvider']:...

    @overload
    def __getitem__(self, key: Literal[95]) -> Literal[b'WSCWriteNameSpaceOrder']:...

    @overload
    def __getitem__(self, key: Literal[96]) -> Literal[b'WSCWriteProviderOrder']:...

    @overload
    def __getitem__(self, key: Literal[97]) -> Literal[b'freeaddrinfo']:...

    @overload
    def __getitem__(self, key: Literal[98]) -> Literal[b'getaddrinfo']:...

    @overload
    def __getitem__(self, key: Literal[99]) -> Literal[b'getnameinfo']:...

    @overload
    def __getitem__(self, key: Literal[101]) -> Literal[b'WSAAsyncSelect']:...

    @overload
    def __getitem__(self, key: Literal[102]) -> Literal[b'WSAAsyncGetHostByAddr']:...

    @overload
    def __getitem__(self, key: Literal[103]) -> Literal[b'WSAAsyncGetHostByName']:...

    @overload
    def __getitem__(self, key: Literal[104]) -> Literal[b'WSAAsyncGetProtoByNumber']:...

    @overload
    def __getitem__(self, key: Literal[105]) -> Literal[b'WSAAsyncGetProtoByName']:...

    @overload
    def __getitem__(self, key: Literal[106]) -> Literal[b'WSAAsyncGetServByPort']:...

    @overload
    def __getitem__(self, key: Literal[107]) -> Literal[b'WSAAsyncGetServByName']:...

    @overload
    def __getitem__(self, key: Literal[108]) -> Literal[b'WSACancelAsyncRequest']:...

    @overload
    def __getitem__(self, key: Literal[109]) -> Literal[b'WSASetBlockingHook']:...

    @overload
    def __getitem__(self, key: Literal[110]) -> Literal[b'WSAUnhookBlockingHook']:...

    @overload
    def __getitem__(self, key: Literal[111]) -> Literal[b'WSAGetLastError']:...

    @overload
    def __getitem__(self, key: Literal[112]) -> Literal[b'WSASetLastError']:...

    @overload
    def __getitem__(self, key: Literal[113]) -> Literal[b'WSACancelBlockingCall']:...

    @overload
    def __getitem__(self, key: Literal[114]) -> Literal[b'WSAIsBlocking']:...

    @overload
    def __getitem__(self, key: Literal[115]) -> Literal[b'WSAStartup']:...

    @overload
    def __getitem__(self, key: Literal[116]) -> Literal[b'WSACleanup']:...

    @overload
    def __getitem__(self, key: Literal[151]) -> Literal[b'__WSAFDIsSet']:...

    @overload
    def __getitem__(self, key: Literal[500]) -> Literal[b'WEP']:...
ORD_NAMES_DICT_VALUES = Literal[
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
    17,
    18,
    19,
    20,
    21,
    22,
    23,
    24,
    25,
    26,
    27,
    28,
    29,
    30,
    31,
    32,
    33,
    34,
    35,
    36,
    37,
    38,
    39,
    40,
    41,
    42,
    43,
    44,
    45,
    46,
    47,
    48,
    49,
    50,
    51,
    52,
    53,
    54,
    55,
    56,
    57,
    58,
    59,
    60,
    61,
    62,
    63,
    64,
    65,
    66,
    67,
    68,
    69,
    70,
    71,
    72,
    73,
    74,
    75,
    76,
    77,
    78,
    79,
    80,
    81,
    82,
    83,
    84,
    85,
    86,
    87,
    88,
    89,
    90,
    91,
    92,
    93,
    94,
    95,
    96,
    97,
    98,
    99,
    101,
    102,
    103,
    104,
    105,
    106,
    107,
    108,
    109,
    110,
    111,
    112,
    113,
    114,
    115,
    116,
    151,
    500,
]
ORD_NAMES_DICT_NAMES = Literal[
    b'accept',
    b'bind',
    b'closesocket',
    b'connect',
    b'getpeername',
    b'getsockname',
    b'getsockopt',
    b'htonl',
    b'htons',
    b'ioctlsocket',
    b'inet_addr',
    b'inet_ntoa',
    b'listen',
    b'ntohl',
    b'ntohs',
    b'recv',
    b'recvfrom',
    b'select',
    b'send',
    b'sendto',
    b'setsockopt',
    b'shutdown',
    b'socket',
    b'GetAddrInfoW',
    b'GetNameInfoW',
    b'WSApSetPostRoutine',
    b'FreeAddrInfoW',
    b'WPUCompleteOverlappedRequest',
    b'WSAAccept',
    b'WSAAddressToStringA',
    b'WSAAddressToStringW',
    b'WSACloseEvent',
    b'WSAConnect',
    b'WSACreateEvent',
    b'WSADuplicateSocketA',
    b'WSADuplicateSocketW',
    b'WSAEnumNameSpaceProvidersA',
    b'WSAEnumNameSpaceProvidersW',
    b'WSAEnumNetworkEvents',
    b'WSAEnumProtocolsA',
    b'WSAEnumProtocolsW',
    b'WSAEventSelect',
    b'WSAGetOverlappedResult',
    b'WSAGetQOSByName',
    b'WSAGetServiceClassInfoA',
    b'WSAGetServiceClassInfoW',
    b'WSAGetServiceClassNameByClassIdA',
    b'WSAGetServiceClassNameByClassIdW',
    b'WSAHtonl',
    b'WSAHtons',
    b'gethostbyaddr',
    b'gethostbyname',
    b'getprotobyname',
    b'getprotobynumber',
    b'getservbyname',
    b'getservbyport',
    b'gethostname',
    b'WSAInstallServiceClassA',
    b'WSAInstallServiceClassW',
    b'WSAIoctl',
    b'WSAJoinLeaf',
    b'WSALookupServiceBeginA',
    b'WSALookupServiceBeginW',
    b'WSALookupServiceEnd',
    b'WSALookupServiceNextA',
    b'WSALookupServiceNextW',
    b'WSANSPIoctl',
    b'WSANtohl',
    b'WSANtohs',
    b'WSAProviderConfigChange',
    b'WSARecv',
    b'WSARecvDisconnect',
    b'WSARecvFrom',
    b'WSARemoveServiceClass',
    b'WSAResetEvent',
    b'WSASend',
    b'WSASendDisconnect',
    b'WSASendTo',
    b'WSASetEvent',
    b'WSASetServiceA',
    b'WSASetServiceW',
    b'WSASocketA',
    b'WSASocketW',
    b'WSAStringToAddressA',
    b'WSAStringToAddressW',
    b'WSAWaitForMultipleEvents',
    b'WSCDeinstallProvider',
    b'WSCEnableNSProvider',
    b'WSCEnumProtocols',
    b'WSCGetProviderPath',
    b'WSCInstallNameSpace',
    b'WSCInstallProvider',
    b'WSCUnInstallNameSpace',
    b'WSCUpdateProvider',
    b'WSCWriteNameSpaceOrder',
    b'WSCWriteProviderOrder',
    b'freeaddrinfo',
    b'getaddrinfo',
    b'getnameinfo',
    b'WSAAsyncSelect',
    b'WSAAsyncGetHostByAddr',
    b'WSAAsyncGetHostByName',
    b'WSAAsyncGetProtoByNumber',
    b'WSAAsyncGetProtoByName',
    b'WSAAsyncGetServByPort',
    b'WSAAsyncGetServByName',
    b'WSACancelAsyncRequest',
    b'WSASetBlockingHook',
    b'WSAUnhookBlockingHook',
    b'WSAGetLastError',
    b'WSASetLastError',
    b'WSACancelBlockingCall',
    b'WSAIsBlocking',
    b'WSAStartup',
    b'WSACleanup',
    b'__WSAFDIsSet',
    b'WEP',
]
