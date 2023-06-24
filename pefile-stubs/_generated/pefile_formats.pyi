# fmt: off
"""
THIS FILE WAS AUTOMATICALLY GENERATED BASED ON pefile 2023.2.7

Copyright (C) 2023  coloursofnoise

This software is licensed under the GNU General Public License, version 3 or
later (GPLv3+). A full copy of the license is available in the COPYING file
located at the root of the project, or at <https://www.gnu.org/licenses/>.
"""

from typing import Literal


IMAGE_DOS_HEADER_format_name = Literal["IMAGE_DOS_HEADER"]
IMAGE_DOS_HEADER_format = tuple[IMAGE_DOS_HEADER_format_name,tuple[Literal["H,e_magic"],Literal["H,e_cblp"],Literal["H,e_cp"],Literal["H,e_crlc"],Literal["H,e_cparhdr"],Literal["H,e_minalloc"],Literal["H,e_maxalloc"],Literal["H,e_ss"],Literal["H,e_sp"],Literal["H,e_csum"],Literal["H,e_ip"],Literal["H,e_cs"],Literal["H,e_lfarlc"],Literal["H,e_ovno"],Literal["8s,e_res"],Literal["H,e_oemid"],Literal["H,e_oeminfo"],Literal["20s,e_res2"],Literal["I,e_lfanew"]]]
IMAGE_FILE_HEADER_format_name = Literal["IMAGE_FILE_HEADER"]
IMAGE_FILE_HEADER_format = tuple[IMAGE_FILE_HEADER_format_name,tuple[Literal["H,Machine"],Literal["H,NumberOfSections"],Literal["I,TimeDateStamp"],Literal["I,PointerToSymbolTable"],Literal["I,NumberOfSymbols"],Literal["H,SizeOfOptionalHeader"],Literal["H,Characteristics"]]]
IMAGE_DATA_DIRECTORY_format_name = Literal["IMAGE_DATA_DIRECTORY"]
IMAGE_DATA_DIRECTORY_format = tuple[IMAGE_DATA_DIRECTORY_format_name,tuple[Literal["I,VirtualAddress"],Literal["I,Size"]]]
IMAGE_OPTIONAL_HEADER_format_name = Literal["IMAGE_OPTIONAL_HEADER"]
IMAGE_OPTIONAL_HEADER_format = tuple[IMAGE_OPTIONAL_HEADER_format_name,tuple[Literal["H,Magic"],Literal["B,MajorLinkerVersion"],Literal["B,MinorLinkerVersion"],Literal["I,SizeOfCode"],Literal["I,SizeOfInitializedData"],Literal["I,SizeOfUninitializedData"],Literal["I,AddressOfEntryPoint"],Literal["I,BaseOfCode"],Literal["I,BaseOfData"],Literal["I,ImageBase"],Literal["I,SectionAlignment"],Literal["I,FileAlignment"],Literal["H,MajorOperatingSystemVersion"],Literal["H,MinorOperatingSystemVersion"],Literal["H,MajorImageVersion"],Literal["H,MinorImageVersion"],Literal["H,MajorSubsystemVersion"],Literal["H,MinorSubsystemVersion"],Literal["I,Reserved1"],Literal["I,SizeOfImage"],Literal["I,SizeOfHeaders"],Literal["I,CheckSum"],Literal["H,Subsystem"],Literal["H,DllCharacteristics"],Literal["I,SizeOfStackReserve"],Literal["I,SizeOfStackCommit"],Literal["I,SizeOfHeapReserve"],Literal["I,SizeOfHeapCommit"],Literal["I,LoaderFlags"],Literal["I,NumberOfRvaAndSizes"]]]
IMAGE_OPTIONAL_HEADER64_format_name = Literal["IMAGE_OPTIONAL_HEADER64"]
IMAGE_OPTIONAL_HEADER64_format = tuple[IMAGE_OPTIONAL_HEADER64_format_name,tuple[Literal["H,Magic"],Literal["B,MajorLinkerVersion"],Literal["B,MinorLinkerVersion"],Literal["I,SizeOfCode"],Literal["I,SizeOfInitializedData"],Literal["I,SizeOfUninitializedData"],Literal["I,AddressOfEntryPoint"],Literal["I,BaseOfCode"],Literal["Q,ImageBase"],Literal["I,SectionAlignment"],Literal["I,FileAlignment"],Literal["H,MajorOperatingSystemVersion"],Literal["H,MinorOperatingSystemVersion"],Literal["H,MajorImageVersion"],Literal["H,MinorImageVersion"],Literal["H,MajorSubsystemVersion"],Literal["H,MinorSubsystemVersion"],Literal["I,Reserved1"],Literal["I,SizeOfImage"],Literal["I,SizeOfHeaders"],Literal["I,CheckSum"],Literal["H,Subsystem"],Literal["H,DllCharacteristics"],Literal["Q,SizeOfStackReserve"],Literal["Q,SizeOfStackCommit"],Literal["Q,SizeOfHeapReserve"],Literal["Q,SizeOfHeapCommit"],Literal["I,LoaderFlags"],Literal["I,NumberOfRvaAndSizes"]]]
IMAGE_NT_HEADERS_format_name = Literal["IMAGE_NT_HEADERS"]
IMAGE_NT_HEADERS_format = tuple[IMAGE_NT_HEADERS_format_name,tuple[Literal["I,Signature"]]]
IMAGE_SECTION_HEADER_format_name = Literal["IMAGE_SECTION_HEADER"]
IMAGE_SECTION_HEADER_format = tuple[IMAGE_SECTION_HEADER_format_name,tuple[Literal["8s,Name"],Literal["I,Misc,Misc_PhysicalAddress,Misc_VirtualSize"],Literal["I,VirtualAddress"],Literal["I,SizeOfRawData"],Literal["I,PointerToRawData"],Literal["I,PointerToRelocations"],Literal["I,PointerToLinenumbers"],Literal["H,NumberOfRelocations"],Literal["H,NumberOfLinenumbers"],Literal["I,Characteristics"]]]
IMAGE_DELAY_IMPORT_DESCRIPTOR_format_name = Literal["IMAGE_DELAY_IMPORT_DESCRIPTOR"]
IMAGE_DELAY_IMPORT_DESCRIPTOR_format = tuple[IMAGE_DELAY_IMPORT_DESCRIPTOR_format_name,tuple[Literal["I,grAttrs"],Literal["I,szName"],Literal["I,phmod"],Literal["I,pIAT"],Literal["I,pINT"],Literal["I,pBoundIAT"],Literal["I,pUnloadIAT"],Literal["I,dwTimeStamp"]]]
IMAGE_IMPORT_DESCRIPTOR_format_name = Literal["IMAGE_IMPORT_DESCRIPTOR"]
IMAGE_IMPORT_DESCRIPTOR_format = tuple[IMAGE_IMPORT_DESCRIPTOR_format_name,tuple[Literal["I,OriginalFirstThunk,Characteristics"],Literal["I,TimeDateStamp"],Literal["I,ForwarderChain"],Literal["I,Name"],Literal["I,FirstThunk"]]]
IMAGE_EXPORT_DIRECTORY_format_name = Literal["IMAGE_EXPORT_DIRECTORY"]
IMAGE_EXPORT_DIRECTORY_format = tuple[IMAGE_EXPORT_DIRECTORY_format_name,tuple[Literal["I,Characteristics"],Literal["I,TimeDateStamp"],Literal["H,MajorVersion"],Literal["H,MinorVersion"],Literal["I,Name"],Literal["I,Base"],Literal["I,NumberOfFunctions"],Literal["I,NumberOfNames"],Literal["I,AddressOfFunctions"],Literal["I,AddressOfNames"],Literal["I,AddressOfNameOrdinals"]]]
IMAGE_RESOURCE_DIRECTORY_format_name = Literal["IMAGE_RESOURCE_DIRECTORY"]
IMAGE_RESOURCE_DIRECTORY_format = tuple[IMAGE_RESOURCE_DIRECTORY_format_name,tuple[Literal["I,Characteristics"],Literal["I,TimeDateStamp"],Literal["H,MajorVersion"],Literal["H,MinorVersion"],Literal["H,NumberOfNamedEntries"],Literal["H,NumberOfIdEntries"]]]
IMAGE_RESOURCE_DIRECTORY_ENTRY_format_name = Literal["IMAGE_RESOURCE_DIRECTORY_ENTRY"]
IMAGE_RESOURCE_DIRECTORY_ENTRY_format = tuple[IMAGE_RESOURCE_DIRECTORY_ENTRY_format_name,tuple[Literal["I,Name"],Literal["I,OffsetToData"]]]
IMAGE_RESOURCE_DATA_ENTRY_format_name = Literal["IMAGE_RESOURCE_DATA_ENTRY"]
IMAGE_RESOURCE_DATA_ENTRY_format = tuple[IMAGE_RESOURCE_DATA_ENTRY_format_name,tuple[Literal["I,OffsetToData"],Literal["I,Size"],Literal["I,CodePage"],Literal["I,Reserved"]]]
VS_VERSIONINFO_format_name = Literal["VS_VERSIONINFO"]
VS_VERSIONINFO_format = tuple[VS_VERSIONINFO_format_name,tuple[Literal["H,Length"],Literal["H,ValueLength"],Literal["H,Type"]]]
VS_FIXEDFILEINFO_format_name = Literal["VS_FIXEDFILEINFO"]
VS_FIXEDFILEINFO_format = tuple[VS_FIXEDFILEINFO_format_name,tuple[Literal["I,Signature"],Literal["I,StrucVersion"],Literal["I,FileVersionMS"],Literal["I,FileVersionLS"],Literal["I,ProductVersionMS"],Literal["I,ProductVersionLS"],Literal["I,FileFlagsMask"],Literal["I,FileFlags"],Literal["I,FileOS"],Literal["I,FileType"],Literal["I,FileSubtype"],Literal["I,FileDateMS"],Literal["I,FileDateLS"]]]
StringFileInfo_format_name = Literal["StringFileInfo"]
StringFileInfo_format = tuple[StringFileInfo_format_name,tuple[Literal["H,Length"],Literal["H,ValueLength"],Literal["H,Type"]]]
StringTable_format_name = Literal["StringTable"]
StringTable_format = tuple[StringTable_format_name,tuple[Literal["H,Length"],Literal["H,ValueLength"],Literal["H,Type"]]]
String_format_name = Literal["String"]
String_format = tuple[String_format_name,tuple[Literal["H,Length"],Literal["H,ValueLength"],Literal["H,Type"]]]
Var_format_name = Literal["Var"]
Var_format = tuple[Var_format_name,tuple[Literal["H,Length"],Literal["H,ValueLength"],Literal["H,Type"]]]
IMAGE_THUNK_DATA_format_name = Literal["IMAGE_THUNK_DATA"]
IMAGE_THUNK_DATA_format = tuple[IMAGE_THUNK_DATA_format_name,tuple[Literal["I,ForwarderString,Function,Ordinal,AddressOfData"]]]
IMAGE_THUNK_DATA64_format_name = Literal["IMAGE_THUNK_DATA"]
IMAGE_THUNK_DATA64_format = tuple[IMAGE_THUNK_DATA64_format_name,tuple[Literal["Q,ForwarderString,Function,Ordinal,AddressOfData"]]]
IMAGE_DEBUG_DIRECTORY_format_name = Literal["IMAGE_DEBUG_DIRECTORY"]
IMAGE_DEBUG_DIRECTORY_format = tuple[IMAGE_DEBUG_DIRECTORY_format_name,tuple[Literal["I,Characteristics"],Literal["I,TimeDateStamp"],Literal["H,MajorVersion"],Literal["H,MinorVersion"],Literal["I,Type"],Literal["I,SizeOfData"],Literal["I,AddressOfRawData"],Literal["I,PointerToRawData"]]]
IMAGE_BASE_RELOCATION_format_name = Literal["IMAGE_BASE_RELOCATION"]
IMAGE_BASE_RELOCATION_format = tuple[IMAGE_BASE_RELOCATION_format_name,tuple[Literal["I,VirtualAddress"],Literal["I,SizeOfBlock"]]]
IMAGE_BASE_RELOCATION_ENTRY_format_name = Literal["IMAGE_BASE_RELOCATION_ENTRY"]
IMAGE_BASE_RELOCATION_ENTRY_format = tuple[IMAGE_BASE_RELOCATION_ENTRY_format_name,tuple[Literal["H,Data"]]]
IMAGE_IMPORT_CONTROL_TRANSFER_DYNAMIC_RELOCATION_format_name = Literal["IMAGE_IMPORT_CONTROL_TRANSFER_DYNAMIC_RELOCATION"]
IMAGE_IMPORT_CONTROL_TRANSFER_DYNAMIC_RELOCATION_format = tuple[IMAGE_IMPORT_CONTROL_TRANSFER_DYNAMIC_RELOCATION_format_name,tuple[Literal["I:12,PageRelativeOffset"],Literal["I:1,IndirectCall"],Literal["I:19,IATIndex"]]]
IMAGE_INDIR_CONTROL_TRANSFER_DYNAMIC_RELOCATION_format_name = Literal["IMAGE_INDIR_CONTROL_TRANSFER_DYNAMIC_RELOCATION"]
IMAGE_INDIR_CONTROL_TRANSFER_DYNAMIC_RELOCATION_format = tuple[IMAGE_INDIR_CONTROL_TRANSFER_DYNAMIC_RELOCATION_format_name,tuple[Literal["I:12,PageRelativeOffset"],Literal["I:1,IndirectCall"],Literal["I:1,RexWPrefix"],Literal["I:1,CfgCheck"],Literal["I:1,Reserved"]]]
IMAGE_SWITCHTABLE_BRANCH_DYNAMIC_RELOCATION_format_name = Literal["IMAGE_SWITCHTABLE_BRANCH_DYNAMIC_RELOCATION"]
IMAGE_SWITCHTABLE_BRANCH_DYNAMIC_RELOCATION_format = tuple[IMAGE_SWITCHTABLE_BRANCH_DYNAMIC_RELOCATION_format_name,tuple[Literal["I:12,PageRelativeOffset"],Literal["I:4,RegisterNumber"]]]
IMAGE_TLS_DIRECTORY_format_name = Literal["IMAGE_TLS_DIRECTORY"]
IMAGE_TLS_DIRECTORY_format = tuple[IMAGE_TLS_DIRECTORY_format_name,tuple[Literal["I,StartAddressOfRawData"],Literal["I,EndAddressOfRawData"],Literal["I,AddressOfIndex"],Literal["I,AddressOfCallBacks"],Literal["I,SizeOfZeroFill"],Literal["I,Characteristics"]]]
IMAGE_TLS_DIRECTORY64_format_name = Literal["IMAGE_TLS_DIRECTORY"]
IMAGE_TLS_DIRECTORY64_format = tuple[IMAGE_TLS_DIRECTORY64_format_name,tuple[Literal["Q,StartAddressOfRawData"],Literal["Q,EndAddressOfRawData"],Literal["Q,AddressOfIndex"],Literal["Q,AddressOfCallBacks"],Literal["I,SizeOfZeroFill"],Literal["I,Characteristics"]]]
IMAGE_LOAD_CONFIG_DIRECTORY_format_name = Literal["IMAGE_LOAD_CONFIG_DIRECTORY"]
IMAGE_LOAD_CONFIG_DIRECTORY_format = tuple[IMAGE_LOAD_CONFIG_DIRECTORY_format_name,tuple[Literal["I,Size"],Literal["I,TimeDateStamp"],Literal["H,MajorVersion"],Literal["H,MinorVersion"],Literal["I,GlobalFlagsClear"],Literal["I,GlobalFlagsSet"],Literal["I,CriticalSectionDefaultTimeout"],Literal["I,DeCommitFreeBlockThreshold"],Literal["I,DeCommitTotalFreeThreshold"],Literal["I,LockPrefixTable"],Literal["I,MaximumAllocationSize"],Literal["I,VirtualMemoryThreshold"],Literal["I,ProcessHeapFlags"],Literal["I,ProcessAffinityMask"],Literal["H,CSDVersion"],Literal["H,Reserved1"],Literal["I,EditList"],Literal["I,SecurityCookie"],Literal["I,SEHandlerTable"],Literal["I,SEHandlerCount"],Literal["I,GuardCFCheckFunctionPointer"],Literal["I,GuardCFDispatchFunctionPointer"],Literal["I,GuardCFFunctionTable"],Literal["I,GuardCFFunctionCount"],Literal["I,GuardFlags"],Literal["H,CodeIntegrityFlags"],Literal["H,CodeIntegrityCatalog"],Literal["I,CodeIntegrityCatalogOffset"],Literal["I,CodeIntegrityReserved"],Literal["I,GuardAddressTakenIatEntryTable"],Literal["I,GuardAddressTakenIatEntryCount"],Literal["I,GuardLongJumpTargetTable"],Literal["I,GuardLongJumpTargetCount"],Literal["I,DynamicValueRelocTable"],Literal["I,CHPEMetadataPointer"],Literal["I,GuardRFFailureRoutine"],Literal["I,GuardRFFailureRoutineFunctionPointer"],Literal["I,DynamicValueRelocTableOffset"],Literal["H,DynamicValueRelocTableSection"],Literal["H,Reserved2"],Literal["I,GuardRFVerifyStackPointerFunctionPointerI,HotPatchTableOffset"],Literal["I,Reserved3"],Literal["I,EnclaveConfigurationPointer"]]]
IMAGE_LOAD_CONFIG_DIRECTORY64_format_name = Literal["IMAGE_LOAD_CONFIG_DIRECTORY"]
IMAGE_LOAD_CONFIG_DIRECTORY64_format = tuple[IMAGE_LOAD_CONFIG_DIRECTORY64_format_name,tuple[Literal["I,Size"],Literal["I,TimeDateStamp"],Literal["H,MajorVersion"],Literal["H,MinorVersion"],Literal["I,GlobalFlagsClear"],Literal["I,GlobalFlagsSet"],Literal["I,CriticalSectionDefaultTimeout"],Literal["Q,DeCommitFreeBlockThreshold"],Literal["Q,DeCommitTotalFreeThreshold"],Literal["Q,LockPrefixTable"],Literal["Q,MaximumAllocationSize"],Literal["Q,VirtualMemoryThreshold"],Literal["Q,ProcessAffinityMask"],Literal["I,ProcessHeapFlags"],Literal["H,CSDVersion"],Literal["H,Reserved1"],Literal["Q,EditList"],Literal["Q,SecurityCookie"],Literal["Q,SEHandlerTable"],Literal["Q,SEHandlerCount"],Literal["Q,GuardCFCheckFunctionPointer"],Literal["Q,GuardCFDispatchFunctionPointer"],Literal["Q,GuardCFFunctionTable"],Literal["Q,GuardCFFunctionCount"],Literal["I,GuardFlags"],Literal["H,CodeIntegrityFlags"],Literal["H,CodeIntegrityCatalog"],Literal["I,CodeIntegrityCatalogOffset"],Literal["I,CodeIntegrityReserved"],Literal["Q,GuardAddressTakenIatEntryTable"],Literal["Q,GuardAddressTakenIatEntryCount"],Literal["Q,GuardLongJumpTargetTable"],Literal["Q,GuardLongJumpTargetCount"],Literal["Q,DynamicValueRelocTable"],Literal["Q,CHPEMetadataPointer"],Literal["Q,GuardRFFailureRoutine"],Literal["Q,GuardRFFailureRoutineFunctionPointer"],Literal["I,DynamicValueRelocTableOffset"],Literal["H,DynamicValueRelocTableSection"],Literal["H,Reserved2"],Literal["Q,GuardRFVerifyStackPointerFunctionPointer"],Literal["I,HotPatchTableOffset"],Literal["I,Reserved3"],Literal["Q,EnclaveConfigurationPointer"]]]
IMAGE_DYNAMIC_RELOCATION_TABLE_format_name = Literal["IMAGE_DYNAMIC_RELOCATION_TABLE"]
IMAGE_DYNAMIC_RELOCATION_TABLE_format = tuple[IMAGE_DYNAMIC_RELOCATION_TABLE_format_name,tuple[Literal["I,Version"],Literal["I,Size"]]]
IMAGE_DYNAMIC_RELOCATION_format_name = Literal["IMAGE_DYNAMIC_RELOCATION"]
IMAGE_DYNAMIC_RELOCATION_format = tuple[IMAGE_DYNAMIC_RELOCATION_format_name,tuple[Literal["I,Symbol"],Literal["I,BaseRelocSize"]]]
IMAGE_DYNAMIC_RELOCATION64_format_name = Literal["IMAGE_DYNAMIC_RELOCATION64"]
IMAGE_DYNAMIC_RELOCATION64_format = tuple[IMAGE_DYNAMIC_RELOCATION64_format_name,tuple[Literal["Q,Symbol"],Literal["I,BaseRelocSize"]]]
IMAGE_DYNAMIC_RELOCATION_V2_format_name = Literal["IMAGE_DYNAMIC_RELOCATION_V2"]
IMAGE_DYNAMIC_RELOCATION_V2_format = tuple[IMAGE_DYNAMIC_RELOCATION_V2_format_name,tuple[Literal["I,HeaderSize"],Literal["I,FixupInfoSize"],Literal["I,Symbol"],Literal["I,SymbolGroup"],Literal["I,Flags"]]]
IMAGE_DYNAMIC_RELOCATION64_V2_format_name = Literal["IMAGE_DYNAMIC_RELOCATION64_V2"]
IMAGE_DYNAMIC_RELOCATION64_V2_format = tuple[IMAGE_DYNAMIC_RELOCATION64_V2_format_name,tuple[Literal["I,HeaderSize"],Literal["I,FixupInfoSize"],Literal["Q,Symbol"],Literal["I,SymbolGroup"],Literal["I,Flags"]]]
IMAGE_BOUND_IMPORT_DESCRIPTOR_format_name = Literal["IMAGE_BOUND_IMPORT_DESCRIPTOR"]
IMAGE_BOUND_IMPORT_DESCRIPTOR_format = tuple[IMAGE_BOUND_IMPORT_DESCRIPTOR_format_name,tuple[Literal["I,TimeDateStamp"],Literal["H,OffsetModuleName"],Literal["H,NumberOfModuleForwarderRefs"]]]
IMAGE_BOUND_FORWARDER_REF_format_name = Literal["IMAGE_BOUND_FORWARDER_REF"]
IMAGE_BOUND_FORWARDER_REF_format = tuple[IMAGE_BOUND_FORWARDER_REF_format_name,tuple[Literal["I,TimeDateStamp"],Literal["H,OffsetModuleName"],Literal["H,Reserved"]]]
RUNTIME_FUNCTION_format_name = Literal["RUNTIME_FUNCTION"]
RUNTIME_FUNCTION_format = tuple[RUNTIME_FUNCTION_format_name,tuple[Literal["I,BeginAddress"],Literal["I,EndAddress"],Literal["I,UnwindData"]]]



class PE:
    __IMAGE_DOS_HEADER_format__: IMAGE_DOS_HEADER_format = ...
    __IMAGE_FILE_HEADER_format__: IMAGE_FILE_HEADER_format = ...
    __IMAGE_DATA_DIRECTORY_format__: IMAGE_DATA_DIRECTORY_format = ...
    __IMAGE_OPTIONAL_HEADER_format__: IMAGE_OPTIONAL_HEADER_format = ...
    __IMAGE_OPTIONAL_HEADER64_format__: IMAGE_OPTIONAL_HEADER64_format = ...
    __IMAGE_NT_HEADERS_format__: IMAGE_NT_HEADERS_format = ...
    __IMAGE_SECTION_HEADER_format__: IMAGE_SECTION_HEADER_format = ...
    __IMAGE_DELAY_IMPORT_DESCRIPTOR_format__: IMAGE_DELAY_IMPORT_DESCRIPTOR_format = ...
    __IMAGE_IMPORT_DESCRIPTOR_format__: IMAGE_IMPORT_DESCRIPTOR_format = ...
    __IMAGE_EXPORT_DIRECTORY_format__: IMAGE_EXPORT_DIRECTORY_format = ...
    __IMAGE_RESOURCE_DIRECTORY_format__: IMAGE_RESOURCE_DIRECTORY_format = ...
    __IMAGE_RESOURCE_DIRECTORY_ENTRY_format__: IMAGE_RESOURCE_DIRECTORY_ENTRY_format = ...
    __IMAGE_RESOURCE_DATA_ENTRY_format__: IMAGE_RESOURCE_DATA_ENTRY_format = ...
    __VS_VERSIONINFO_format__: VS_VERSIONINFO_format = ...
    __VS_FIXEDFILEINFO_format__: VS_FIXEDFILEINFO_format = ...
    __StringFileInfo_format__: StringFileInfo_format = ...
    __StringTable_format__: StringTable_format = ...
    __String_format__: String_format = ...
    __Var_format__: Var_format = ...
    __IMAGE_THUNK_DATA_format__: IMAGE_THUNK_DATA_format = ...
    __IMAGE_THUNK_DATA64_format__: IMAGE_THUNK_DATA64_format = ...
    __IMAGE_DEBUG_DIRECTORY_format__: IMAGE_DEBUG_DIRECTORY_format = ...
    __IMAGE_BASE_RELOCATION_format__: IMAGE_BASE_RELOCATION_format = ...
    __IMAGE_BASE_RELOCATION_ENTRY_format__: IMAGE_BASE_RELOCATION_ENTRY_format = ...
    __IMAGE_IMPORT_CONTROL_TRANSFER_DYNAMIC_RELOCATION_format__: IMAGE_IMPORT_CONTROL_TRANSFER_DYNAMIC_RELOCATION_format = ...
    __IMAGE_INDIR_CONTROL_TRANSFER_DYNAMIC_RELOCATION_format__: IMAGE_INDIR_CONTROL_TRANSFER_DYNAMIC_RELOCATION_format = ...
    __IMAGE_SWITCHTABLE_BRANCH_DYNAMIC_RELOCATION_format__: IMAGE_SWITCHTABLE_BRANCH_DYNAMIC_RELOCATION_format = ...
    __IMAGE_TLS_DIRECTORY_format__: IMAGE_TLS_DIRECTORY_format = ...
    __IMAGE_TLS_DIRECTORY64_format__: IMAGE_TLS_DIRECTORY64_format = ...
    __IMAGE_LOAD_CONFIG_DIRECTORY_format__: IMAGE_LOAD_CONFIG_DIRECTORY_format = ...
    __IMAGE_LOAD_CONFIG_DIRECTORY64_format__: IMAGE_LOAD_CONFIG_DIRECTORY64_format = ...
    __IMAGE_DYNAMIC_RELOCATION_TABLE_format__: IMAGE_DYNAMIC_RELOCATION_TABLE_format = ...
    __IMAGE_DYNAMIC_RELOCATION_format__: IMAGE_DYNAMIC_RELOCATION_format = ...
    __IMAGE_DYNAMIC_RELOCATION64_format__: IMAGE_DYNAMIC_RELOCATION64_format = ...
    __IMAGE_DYNAMIC_RELOCATION_V2_format__: IMAGE_DYNAMIC_RELOCATION_V2_format = ...
    __IMAGE_DYNAMIC_RELOCATION64_V2_format__: IMAGE_DYNAMIC_RELOCATION64_V2_format = ...
    __IMAGE_BOUND_IMPORT_DESCRIPTOR_format__: IMAGE_BOUND_IMPORT_DESCRIPTOR_format = ...
    __IMAGE_BOUND_FORWARDER_REF_format__: IMAGE_BOUND_FORWARDER_REF_format = ...
    __RUNTIME_FUNCTION_format__: RUNTIME_FUNCTION_format = ...
