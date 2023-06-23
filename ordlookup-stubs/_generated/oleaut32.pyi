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
    def __getitem__(self, key: Literal[2]) -> Literal[b'SysAllocString']:...

    @overload
    def __getitem__(self, key: Literal[3]) -> Literal[b'SysReAllocString']:...

    @overload
    def __getitem__(self, key: Literal[4]) -> Literal[b'SysAllocStringLen']:...

    @overload
    def __getitem__(self, key: Literal[5]) -> Literal[b'SysReAllocStringLen']:...

    @overload
    def __getitem__(self, key: Literal[6]) -> Literal[b'SysFreeString']:...

    @overload
    def __getitem__(self, key: Literal[7]) -> Literal[b'SysStringLen']:...

    @overload
    def __getitem__(self, key: Literal[8]) -> Literal[b'VariantInit']:...

    @overload
    def __getitem__(self, key: Literal[9]) -> Literal[b'VariantClear']:...

    @overload
    def __getitem__(self, key: Literal[10]) -> Literal[b'VariantCopy']:...

    @overload
    def __getitem__(self, key: Literal[11]) -> Literal[b'VariantCopyInd']:...

    @overload
    def __getitem__(self, key: Literal[12]) -> Literal[b'VariantChangeType']:...

    @overload
    def __getitem__(self, key: Literal[13]) -> Literal[b'VariantTimeToDosDateTime']:...

    @overload
    def __getitem__(self, key: Literal[14]) -> Literal[b'DosDateTimeToVariantTime']:...

    @overload
    def __getitem__(self, key: Literal[15]) -> Literal[b'SafeArrayCreate']:...

    @overload
    def __getitem__(self, key: Literal[16]) -> Literal[b'SafeArrayDestroy']:...

    @overload
    def __getitem__(self, key: Literal[17]) -> Literal[b'SafeArrayGetDim']:...

    @overload
    def __getitem__(self, key: Literal[18]) -> Literal[b'SafeArrayGetElemsize']:...

    @overload
    def __getitem__(self, key: Literal[19]) -> Literal[b'SafeArrayGetUBound']:...

    @overload
    def __getitem__(self, key: Literal[20]) -> Literal[b'SafeArrayGetLBound']:...

    @overload
    def __getitem__(self, key: Literal[21]) -> Literal[b'SafeArrayLock']:...

    @overload
    def __getitem__(self, key: Literal[22]) -> Literal[b'SafeArrayUnlock']:...

    @overload
    def __getitem__(self, key: Literal[23]) -> Literal[b'SafeArrayAccessData']:...

    @overload
    def __getitem__(self, key: Literal[24]) -> Literal[b'SafeArrayUnaccessData']:...

    @overload
    def __getitem__(self, key: Literal[25]) -> Literal[b'SafeArrayGetElement']:...

    @overload
    def __getitem__(self, key: Literal[26]) -> Literal[b'SafeArrayPutElement']:...

    @overload
    def __getitem__(self, key: Literal[27]) -> Literal[b'SafeArrayCopy']:...

    @overload
    def __getitem__(self, key: Literal[28]) -> Literal[b'DispGetParam']:...

    @overload
    def __getitem__(self, key: Literal[29]) -> Literal[b'DispGetIDsOfNames']:...

    @overload
    def __getitem__(self, key: Literal[30]) -> Literal[b'DispInvoke']:...

    @overload
    def __getitem__(self, key: Literal[31]) -> Literal[b'CreateDispTypeInfo']:...

    @overload
    def __getitem__(self, key: Literal[32]) -> Literal[b'CreateStdDispatch']:...

    @overload
    def __getitem__(self, key: Literal[33]) -> Literal[b'RegisterActiveObject']:...

    @overload
    def __getitem__(self, key: Literal[34]) -> Literal[b'RevokeActiveObject']:...

    @overload
    def __getitem__(self, key: Literal[35]) -> Literal[b'GetActiveObject']:...

    @overload
    def __getitem__(self, key: Literal[36]) -> Literal[b'SafeArrayAllocDescriptor']:...

    @overload
    def __getitem__(self, key: Literal[37]) -> Literal[b'SafeArrayAllocData']:...

    @overload
    def __getitem__(self, key: Literal[38]) -> Literal[b'SafeArrayDestroyDescriptor']:...

    @overload
    def __getitem__(self, key: Literal[39]) -> Literal[b'SafeArrayDestroyData']:...

    @overload
    def __getitem__(self, key: Literal[40]) -> Literal[b'SafeArrayRedim']:...

    @overload
    def __getitem__(self, key: Literal[41]) -> Literal[b'SafeArrayAllocDescriptorEx']:...

    @overload
    def __getitem__(self, key: Literal[42]) -> Literal[b'SafeArrayCreateEx']:...

    @overload
    def __getitem__(self, key: Literal[43]) -> Literal[b'SafeArrayCreateVectorEx']:...

    @overload
    def __getitem__(self, key: Literal[44]) -> Literal[b'SafeArraySetRecordInfo']:...

    @overload
    def __getitem__(self, key: Literal[45]) -> Literal[b'SafeArrayGetRecordInfo']:...

    @overload
    def __getitem__(self, key: Literal[46]) -> Literal[b'VarParseNumFromStr']:...

    @overload
    def __getitem__(self, key: Literal[47]) -> Literal[b'VarNumFromParseNum']:...

    @overload
    def __getitem__(self, key: Literal[48]) -> Literal[b'VarI2FromUI1']:...

    @overload
    def __getitem__(self, key: Literal[49]) -> Literal[b'VarI2FromI4']:...

    @overload
    def __getitem__(self, key: Literal[50]) -> Literal[b'VarI2FromR4']:...

    @overload
    def __getitem__(self, key: Literal[51]) -> Literal[b'VarI2FromR8']:...

    @overload
    def __getitem__(self, key: Literal[52]) -> Literal[b'VarI2FromCy']:...

    @overload
    def __getitem__(self, key: Literal[53]) -> Literal[b'VarI2FromDate']:...

    @overload
    def __getitem__(self, key: Literal[54]) -> Literal[b'VarI2FromStr']:...

    @overload
    def __getitem__(self, key: Literal[55]) -> Literal[b'VarI2FromDisp']:...

    @overload
    def __getitem__(self, key: Literal[56]) -> Literal[b'VarI2FromBool']:...

    @overload
    def __getitem__(self, key: Literal[57]) -> Literal[b'SafeArraySetIID']:...

    @overload
    def __getitem__(self, key: Literal[58]) -> Literal[b'VarI4FromUI1']:...

    @overload
    def __getitem__(self, key: Literal[59]) -> Literal[b'VarI4FromI2']:...

    @overload
    def __getitem__(self, key: Literal[60]) -> Literal[b'VarI4FromR4']:...

    @overload
    def __getitem__(self, key: Literal[61]) -> Literal[b'VarI4FromR8']:...

    @overload
    def __getitem__(self, key: Literal[62]) -> Literal[b'VarI4FromCy']:...

    @overload
    def __getitem__(self, key: Literal[63]) -> Literal[b'VarI4FromDate']:...

    @overload
    def __getitem__(self, key: Literal[64]) -> Literal[b'VarI4FromStr']:...

    @overload
    def __getitem__(self, key: Literal[65]) -> Literal[b'VarI4FromDisp']:...

    @overload
    def __getitem__(self, key: Literal[66]) -> Literal[b'VarI4FromBool']:...

    @overload
    def __getitem__(self, key: Literal[67]) -> Literal[b'SafeArrayGetIID']:...

    @overload
    def __getitem__(self, key: Literal[68]) -> Literal[b'VarR4FromUI1']:...

    @overload
    def __getitem__(self, key: Literal[69]) -> Literal[b'VarR4FromI2']:...

    @overload
    def __getitem__(self, key: Literal[70]) -> Literal[b'VarR4FromI4']:...

    @overload
    def __getitem__(self, key: Literal[71]) -> Literal[b'VarR4FromR8']:...

    @overload
    def __getitem__(self, key: Literal[72]) -> Literal[b'VarR4FromCy']:...

    @overload
    def __getitem__(self, key: Literal[73]) -> Literal[b'VarR4FromDate']:...

    @overload
    def __getitem__(self, key: Literal[74]) -> Literal[b'VarR4FromStr']:...

    @overload
    def __getitem__(self, key: Literal[75]) -> Literal[b'VarR4FromDisp']:...

    @overload
    def __getitem__(self, key: Literal[76]) -> Literal[b'VarR4FromBool']:...

    @overload
    def __getitem__(self, key: Literal[77]) -> Literal[b'SafeArrayGetVartype']:...

    @overload
    def __getitem__(self, key: Literal[78]) -> Literal[b'VarR8FromUI1']:...

    @overload
    def __getitem__(self, key: Literal[79]) -> Literal[b'VarR8FromI2']:...

    @overload
    def __getitem__(self, key: Literal[80]) -> Literal[b'VarR8FromI4']:...

    @overload
    def __getitem__(self, key: Literal[81]) -> Literal[b'VarR8FromR4']:...

    @overload
    def __getitem__(self, key: Literal[82]) -> Literal[b'VarR8FromCy']:...

    @overload
    def __getitem__(self, key: Literal[83]) -> Literal[b'VarR8FromDate']:...

    @overload
    def __getitem__(self, key: Literal[84]) -> Literal[b'VarR8FromStr']:...

    @overload
    def __getitem__(self, key: Literal[85]) -> Literal[b'VarR8FromDisp']:...

    @overload
    def __getitem__(self, key: Literal[86]) -> Literal[b'VarR8FromBool']:...

    @overload
    def __getitem__(self, key: Literal[87]) -> Literal[b'VarFormat']:...

    @overload
    def __getitem__(self, key: Literal[88]) -> Literal[b'VarDateFromUI1']:...

    @overload
    def __getitem__(self, key: Literal[89]) -> Literal[b'VarDateFromI2']:...

    @overload
    def __getitem__(self, key: Literal[90]) -> Literal[b'VarDateFromI4']:...

    @overload
    def __getitem__(self, key: Literal[91]) -> Literal[b'VarDateFromR4']:...

    @overload
    def __getitem__(self, key: Literal[92]) -> Literal[b'VarDateFromR8']:...

    @overload
    def __getitem__(self, key: Literal[93]) -> Literal[b'VarDateFromCy']:...

    @overload
    def __getitem__(self, key: Literal[94]) -> Literal[b'VarDateFromStr']:...

    @overload
    def __getitem__(self, key: Literal[95]) -> Literal[b'VarDateFromDisp']:...

    @overload
    def __getitem__(self, key: Literal[96]) -> Literal[b'VarDateFromBool']:...

    @overload
    def __getitem__(self, key: Literal[97]) -> Literal[b'VarFormatDateTime']:...

    @overload
    def __getitem__(self, key: Literal[98]) -> Literal[b'VarCyFromUI1']:...

    @overload
    def __getitem__(self, key: Literal[99]) -> Literal[b'VarCyFromI2']:...

    @overload
    def __getitem__(self, key: Literal[100]) -> Literal[b'VarCyFromI4']:...

    @overload
    def __getitem__(self, key: Literal[101]) -> Literal[b'VarCyFromR4']:...

    @overload
    def __getitem__(self, key: Literal[102]) -> Literal[b'VarCyFromR8']:...

    @overload
    def __getitem__(self, key: Literal[103]) -> Literal[b'VarCyFromDate']:...

    @overload
    def __getitem__(self, key: Literal[104]) -> Literal[b'VarCyFromStr']:...

    @overload
    def __getitem__(self, key: Literal[105]) -> Literal[b'VarCyFromDisp']:...

    @overload
    def __getitem__(self, key: Literal[106]) -> Literal[b'VarCyFromBool']:...

    @overload
    def __getitem__(self, key: Literal[107]) -> Literal[b'VarFormatNumber']:...

    @overload
    def __getitem__(self, key: Literal[108]) -> Literal[b'VarBstrFromUI1']:...

    @overload
    def __getitem__(self, key: Literal[109]) -> Literal[b'VarBstrFromI2']:...

    @overload
    def __getitem__(self, key: Literal[110]) -> Literal[b'VarBstrFromI4']:...

    @overload
    def __getitem__(self, key: Literal[111]) -> Literal[b'VarBstrFromR4']:...

    @overload
    def __getitem__(self, key: Literal[112]) -> Literal[b'VarBstrFromR8']:...

    @overload
    def __getitem__(self, key: Literal[113]) -> Literal[b'VarBstrFromCy']:...

    @overload
    def __getitem__(self, key: Literal[114]) -> Literal[b'VarBstrFromDate']:...

    @overload
    def __getitem__(self, key: Literal[115]) -> Literal[b'VarBstrFromDisp']:...

    @overload
    def __getitem__(self, key: Literal[116]) -> Literal[b'VarBstrFromBool']:...

    @overload
    def __getitem__(self, key: Literal[117]) -> Literal[b'VarFormatPercent']:...

    @overload
    def __getitem__(self, key: Literal[118]) -> Literal[b'VarBoolFromUI1']:...

    @overload
    def __getitem__(self, key: Literal[119]) -> Literal[b'VarBoolFromI2']:...

    @overload
    def __getitem__(self, key: Literal[120]) -> Literal[b'VarBoolFromI4']:...

    @overload
    def __getitem__(self, key: Literal[121]) -> Literal[b'VarBoolFromR4']:...

    @overload
    def __getitem__(self, key: Literal[122]) -> Literal[b'VarBoolFromR8']:...

    @overload
    def __getitem__(self, key: Literal[123]) -> Literal[b'VarBoolFromDate']:...

    @overload
    def __getitem__(self, key: Literal[124]) -> Literal[b'VarBoolFromCy']:...

    @overload
    def __getitem__(self, key: Literal[125]) -> Literal[b'VarBoolFromStr']:...

    @overload
    def __getitem__(self, key: Literal[126]) -> Literal[b'VarBoolFromDisp']:...

    @overload
    def __getitem__(self, key: Literal[127]) -> Literal[b'VarFormatCurrency']:...

    @overload
    def __getitem__(self, key: Literal[128]) -> Literal[b'VarWeekdayName']:...

    @overload
    def __getitem__(self, key: Literal[129]) -> Literal[b'VarMonthName']:...

    @overload
    def __getitem__(self, key: Literal[130]) -> Literal[b'VarUI1FromI2']:...

    @overload
    def __getitem__(self, key: Literal[131]) -> Literal[b'VarUI1FromI4']:...

    @overload
    def __getitem__(self, key: Literal[132]) -> Literal[b'VarUI1FromR4']:...

    @overload
    def __getitem__(self, key: Literal[133]) -> Literal[b'VarUI1FromR8']:...

    @overload
    def __getitem__(self, key: Literal[134]) -> Literal[b'VarUI1FromCy']:...

    @overload
    def __getitem__(self, key: Literal[135]) -> Literal[b'VarUI1FromDate']:...

    @overload
    def __getitem__(self, key: Literal[136]) -> Literal[b'VarUI1FromStr']:...

    @overload
    def __getitem__(self, key: Literal[137]) -> Literal[b'VarUI1FromDisp']:...

    @overload
    def __getitem__(self, key: Literal[138]) -> Literal[b'VarUI1FromBool']:...

    @overload
    def __getitem__(self, key: Literal[139]) -> Literal[b'VarFormatFromTokens']:...

    @overload
    def __getitem__(self, key: Literal[140]) -> Literal[b'VarTokenizeFormatString']:...

    @overload
    def __getitem__(self, key: Literal[141]) -> Literal[b'VarAdd']:...

    @overload
    def __getitem__(self, key: Literal[142]) -> Literal[b'VarAnd']:...

    @overload
    def __getitem__(self, key: Literal[143]) -> Literal[b'VarDiv']:...

    @overload
    def __getitem__(self, key: Literal[144]) -> Literal[b'DllCanUnloadNow']:...

    @overload
    def __getitem__(self, key: Literal[145]) -> Literal[b'DllGetClassObject']:...

    @overload
    def __getitem__(self, key: Literal[146]) -> Literal[b'DispCallFunc']:...

    @overload
    def __getitem__(self, key: Literal[147]) -> Literal[b'VariantChangeTypeEx']:...

    @overload
    def __getitem__(self, key: Literal[148]) -> Literal[b'SafeArrayPtrOfIndex']:...

    @overload
    def __getitem__(self, key: Literal[149]) -> Literal[b'SysStringByteLen']:...

    @overload
    def __getitem__(self, key: Literal[150]) -> Literal[b'SysAllocStringByteLen']:...

    @overload
    def __getitem__(self, key: Literal[151]) -> Literal[b'DllRegisterServer']:...

    @overload
    def __getitem__(self, key: Literal[152]) -> Literal[b'VarEqv']:...

    @overload
    def __getitem__(self, key: Literal[153]) -> Literal[b'VarIdiv']:...

    @overload
    def __getitem__(self, key: Literal[154]) -> Literal[b'VarImp']:...

    @overload
    def __getitem__(self, key: Literal[155]) -> Literal[b'VarMod']:...

    @overload
    def __getitem__(self, key: Literal[156]) -> Literal[b'VarMul']:...

    @overload
    def __getitem__(self, key: Literal[157]) -> Literal[b'VarOr']:...

    @overload
    def __getitem__(self, key: Literal[158]) -> Literal[b'VarPow']:...

    @overload
    def __getitem__(self, key: Literal[159]) -> Literal[b'VarSub']:...

    @overload
    def __getitem__(self, key: Literal[160]) -> Literal[b'CreateTypeLib']:...

    @overload
    def __getitem__(self, key: Literal[161]) -> Literal[b'LoadTypeLib']:...

    @overload
    def __getitem__(self, key: Literal[162]) -> Literal[b'LoadRegTypeLib']:...

    @overload
    def __getitem__(self, key: Literal[163]) -> Literal[b'RegisterTypeLib']:...

    @overload
    def __getitem__(self, key: Literal[164]) -> Literal[b'QueryPathOfRegTypeLib']:...

    @overload
    def __getitem__(self, key: Literal[165]) -> Literal[b'LHashValOfNameSys']:...

    @overload
    def __getitem__(self, key: Literal[166]) -> Literal[b'LHashValOfNameSysA']:...

    @overload
    def __getitem__(self, key: Literal[167]) -> Literal[b'VarXor']:...

    @overload
    def __getitem__(self, key: Literal[168]) -> Literal[b'VarAbs']:...

    @overload
    def __getitem__(self, key: Literal[169]) -> Literal[b'VarFix']:...

    @overload
    def __getitem__(self, key: Literal[170]) -> Literal[b'OaBuildVersion']:...

    @overload
    def __getitem__(self, key: Literal[171]) -> Literal[b'ClearCustData']:...

    @overload
    def __getitem__(self, key: Literal[172]) -> Literal[b'VarInt']:...

    @overload
    def __getitem__(self, key: Literal[173]) -> Literal[b'VarNeg']:...

    @overload
    def __getitem__(self, key: Literal[174]) -> Literal[b'VarNot']:...

    @overload
    def __getitem__(self, key: Literal[175]) -> Literal[b'VarRound']:...

    @overload
    def __getitem__(self, key: Literal[176]) -> Literal[b'VarCmp']:...

    @overload
    def __getitem__(self, key: Literal[177]) -> Literal[b'VarDecAdd']:...

    @overload
    def __getitem__(self, key: Literal[178]) -> Literal[b'VarDecDiv']:...

    @overload
    def __getitem__(self, key: Literal[179]) -> Literal[b'VarDecMul']:...

    @overload
    def __getitem__(self, key: Literal[180]) -> Literal[b'CreateTypeLib2']:...

    @overload
    def __getitem__(self, key: Literal[181]) -> Literal[b'VarDecSub']:...

    @overload
    def __getitem__(self, key: Literal[182]) -> Literal[b'VarDecAbs']:...

    @overload
    def __getitem__(self, key: Literal[183]) -> Literal[b'LoadTypeLibEx']:...

    @overload
    def __getitem__(self, key: Literal[184]) -> Literal[b'SystemTimeToVariantTime']:...

    @overload
    def __getitem__(self, key: Literal[185]) -> Literal[b'VariantTimeToSystemTime']:...

    @overload
    def __getitem__(self, key: Literal[186]) -> Literal[b'UnRegisterTypeLib']:...

    @overload
    def __getitem__(self, key: Literal[187]) -> Literal[b'VarDecFix']:...

    @overload
    def __getitem__(self, key: Literal[188]) -> Literal[b'VarDecInt']:...

    @overload
    def __getitem__(self, key: Literal[189]) -> Literal[b'VarDecNeg']:...

    @overload
    def __getitem__(self, key: Literal[190]) -> Literal[b'VarDecFromUI1']:...

    @overload
    def __getitem__(self, key: Literal[191]) -> Literal[b'VarDecFromI2']:...

    @overload
    def __getitem__(self, key: Literal[192]) -> Literal[b'VarDecFromI4']:...

    @overload
    def __getitem__(self, key: Literal[193]) -> Literal[b'VarDecFromR4']:...

    @overload
    def __getitem__(self, key: Literal[194]) -> Literal[b'VarDecFromR8']:...

    @overload
    def __getitem__(self, key: Literal[195]) -> Literal[b'VarDecFromDate']:...

    @overload
    def __getitem__(self, key: Literal[196]) -> Literal[b'VarDecFromCy']:...

    @overload
    def __getitem__(self, key: Literal[197]) -> Literal[b'VarDecFromStr']:...

    @overload
    def __getitem__(self, key: Literal[198]) -> Literal[b'VarDecFromDisp']:...

    @overload
    def __getitem__(self, key: Literal[199]) -> Literal[b'VarDecFromBool']:...

    @overload
    def __getitem__(self, key: Literal[200]) -> Literal[b'GetErrorInfo']:...

    @overload
    def __getitem__(self, key: Literal[201]) -> Literal[b'SetErrorInfo']:...

    @overload
    def __getitem__(self, key: Literal[202]) -> Literal[b'CreateErrorInfo']:...

    @overload
    def __getitem__(self, key: Literal[203]) -> Literal[b'VarDecRound']:...

    @overload
    def __getitem__(self, key: Literal[204]) -> Literal[b'VarDecCmp']:...

    @overload
    def __getitem__(self, key: Literal[205]) -> Literal[b'VarI2FromI1']:...

    @overload
    def __getitem__(self, key: Literal[206]) -> Literal[b'VarI2FromUI2']:...

    @overload
    def __getitem__(self, key: Literal[207]) -> Literal[b'VarI2FromUI4']:...

    @overload
    def __getitem__(self, key: Literal[208]) -> Literal[b'VarI2FromDec']:...

    @overload
    def __getitem__(self, key: Literal[209]) -> Literal[b'VarI4FromI1']:...

    @overload
    def __getitem__(self, key: Literal[210]) -> Literal[b'VarI4FromUI2']:...

    @overload
    def __getitem__(self, key: Literal[211]) -> Literal[b'VarI4FromUI4']:...

    @overload
    def __getitem__(self, key: Literal[212]) -> Literal[b'VarI4FromDec']:...

    @overload
    def __getitem__(self, key: Literal[213]) -> Literal[b'VarR4FromI1']:...

    @overload
    def __getitem__(self, key: Literal[214]) -> Literal[b'VarR4FromUI2']:...

    @overload
    def __getitem__(self, key: Literal[215]) -> Literal[b'VarR4FromUI4']:...

    @overload
    def __getitem__(self, key: Literal[216]) -> Literal[b'VarR4FromDec']:...

    @overload
    def __getitem__(self, key: Literal[217]) -> Literal[b'VarR8FromI1']:...

    @overload
    def __getitem__(self, key: Literal[218]) -> Literal[b'VarR8FromUI2']:...

    @overload
    def __getitem__(self, key: Literal[219]) -> Literal[b'VarR8FromUI4']:...

    @overload
    def __getitem__(self, key: Literal[220]) -> Literal[b'VarR8FromDec']:...

    @overload
    def __getitem__(self, key: Literal[221]) -> Literal[b'VarDateFromI1']:...

    @overload
    def __getitem__(self, key: Literal[222]) -> Literal[b'VarDateFromUI2']:...

    @overload
    def __getitem__(self, key: Literal[223]) -> Literal[b'VarDateFromUI4']:...

    @overload
    def __getitem__(self, key: Literal[224]) -> Literal[b'VarDateFromDec']:...

    @overload
    def __getitem__(self, key: Literal[225]) -> Literal[b'VarCyFromI1']:...

    @overload
    def __getitem__(self, key: Literal[226]) -> Literal[b'VarCyFromUI2']:...

    @overload
    def __getitem__(self, key: Literal[227]) -> Literal[b'VarCyFromUI4']:...

    @overload
    def __getitem__(self, key: Literal[228]) -> Literal[b'VarCyFromDec']:...

    @overload
    def __getitem__(self, key: Literal[229]) -> Literal[b'VarBstrFromI1']:...

    @overload
    def __getitem__(self, key: Literal[230]) -> Literal[b'VarBstrFromUI2']:...

    @overload
    def __getitem__(self, key: Literal[231]) -> Literal[b'VarBstrFromUI4']:...

    @overload
    def __getitem__(self, key: Literal[232]) -> Literal[b'VarBstrFromDec']:...

    @overload
    def __getitem__(self, key: Literal[233]) -> Literal[b'VarBoolFromI1']:...

    @overload
    def __getitem__(self, key: Literal[234]) -> Literal[b'VarBoolFromUI2']:...

    @overload
    def __getitem__(self, key: Literal[235]) -> Literal[b'VarBoolFromUI4']:...

    @overload
    def __getitem__(self, key: Literal[236]) -> Literal[b'VarBoolFromDec']:...

    @overload
    def __getitem__(self, key: Literal[237]) -> Literal[b'VarUI1FromI1']:...

    @overload
    def __getitem__(self, key: Literal[238]) -> Literal[b'VarUI1FromUI2']:...

    @overload
    def __getitem__(self, key: Literal[239]) -> Literal[b'VarUI1FromUI4']:...

    @overload
    def __getitem__(self, key: Literal[240]) -> Literal[b'VarUI1FromDec']:...

    @overload
    def __getitem__(self, key: Literal[241]) -> Literal[b'VarDecFromI1']:...

    @overload
    def __getitem__(self, key: Literal[242]) -> Literal[b'VarDecFromUI2']:...

    @overload
    def __getitem__(self, key: Literal[243]) -> Literal[b'VarDecFromUI4']:...

    @overload
    def __getitem__(self, key: Literal[244]) -> Literal[b'VarI1FromUI1']:...

    @overload
    def __getitem__(self, key: Literal[245]) -> Literal[b'VarI1FromI2']:...

    @overload
    def __getitem__(self, key: Literal[246]) -> Literal[b'VarI1FromI4']:...

    @overload
    def __getitem__(self, key: Literal[247]) -> Literal[b'VarI1FromR4']:...

    @overload
    def __getitem__(self, key: Literal[248]) -> Literal[b'VarI1FromR8']:...

    @overload
    def __getitem__(self, key: Literal[249]) -> Literal[b'VarI1FromDate']:...

    @overload
    def __getitem__(self, key: Literal[250]) -> Literal[b'VarI1FromCy']:...

    @overload
    def __getitem__(self, key: Literal[251]) -> Literal[b'VarI1FromStr']:...

    @overload
    def __getitem__(self, key: Literal[252]) -> Literal[b'VarI1FromDisp']:...

    @overload
    def __getitem__(self, key: Literal[253]) -> Literal[b'VarI1FromBool']:...

    @overload
    def __getitem__(self, key: Literal[254]) -> Literal[b'VarI1FromUI2']:...

    @overload
    def __getitem__(self, key: Literal[255]) -> Literal[b'VarI1FromUI4']:...

    @overload
    def __getitem__(self, key: Literal[256]) -> Literal[b'VarI1FromDec']:...

    @overload
    def __getitem__(self, key: Literal[257]) -> Literal[b'VarUI2FromUI1']:...

    @overload
    def __getitem__(self, key: Literal[258]) -> Literal[b'VarUI2FromI2']:...

    @overload
    def __getitem__(self, key: Literal[259]) -> Literal[b'VarUI2FromI4']:...

    @overload
    def __getitem__(self, key: Literal[260]) -> Literal[b'VarUI2FromR4']:...

    @overload
    def __getitem__(self, key: Literal[261]) -> Literal[b'VarUI2FromR8']:...

    @overload
    def __getitem__(self, key: Literal[262]) -> Literal[b'VarUI2FromDate']:...

    @overload
    def __getitem__(self, key: Literal[263]) -> Literal[b'VarUI2FromCy']:...

    @overload
    def __getitem__(self, key: Literal[264]) -> Literal[b'VarUI2FromStr']:...

    @overload
    def __getitem__(self, key: Literal[265]) -> Literal[b'VarUI2FromDisp']:...

    @overload
    def __getitem__(self, key: Literal[266]) -> Literal[b'VarUI2FromBool']:...

    @overload
    def __getitem__(self, key: Literal[267]) -> Literal[b'VarUI2FromI1']:...

    @overload
    def __getitem__(self, key: Literal[268]) -> Literal[b'VarUI2FromUI4']:...

    @overload
    def __getitem__(self, key: Literal[269]) -> Literal[b'VarUI2FromDec']:...

    @overload
    def __getitem__(self, key: Literal[270]) -> Literal[b'VarUI4FromUI1']:...

    @overload
    def __getitem__(self, key: Literal[271]) -> Literal[b'VarUI4FromI2']:...

    @overload
    def __getitem__(self, key: Literal[272]) -> Literal[b'VarUI4FromI4']:...

    @overload
    def __getitem__(self, key: Literal[273]) -> Literal[b'VarUI4FromR4']:...

    @overload
    def __getitem__(self, key: Literal[274]) -> Literal[b'VarUI4FromR8']:...

    @overload
    def __getitem__(self, key: Literal[275]) -> Literal[b'VarUI4FromDate']:...

    @overload
    def __getitem__(self, key: Literal[276]) -> Literal[b'VarUI4FromCy']:...

    @overload
    def __getitem__(self, key: Literal[277]) -> Literal[b'VarUI4FromStr']:...

    @overload
    def __getitem__(self, key: Literal[278]) -> Literal[b'VarUI4FromDisp']:...

    @overload
    def __getitem__(self, key: Literal[279]) -> Literal[b'VarUI4FromBool']:...

    @overload
    def __getitem__(self, key: Literal[280]) -> Literal[b'VarUI4FromI1']:...

    @overload
    def __getitem__(self, key: Literal[281]) -> Literal[b'VarUI4FromUI2']:...

    @overload
    def __getitem__(self, key: Literal[282]) -> Literal[b'VarUI4FromDec']:...

    @overload
    def __getitem__(self, key: Literal[283]) -> Literal[b'BSTR_UserSize']:...

    @overload
    def __getitem__(self, key: Literal[284]) -> Literal[b'BSTR_UserMarshal']:...

    @overload
    def __getitem__(self, key: Literal[285]) -> Literal[b'BSTR_UserUnmarshal']:...

    @overload
    def __getitem__(self, key: Literal[286]) -> Literal[b'BSTR_UserFree']:...

    @overload
    def __getitem__(self, key: Literal[287]) -> Literal[b'VARIANT_UserSize']:...

    @overload
    def __getitem__(self, key: Literal[288]) -> Literal[b'VARIANT_UserMarshal']:...

    @overload
    def __getitem__(self, key: Literal[289]) -> Literal[b'VARIANT_UserUnmarshal']:...

    @overload
    def __getitem__(self, key: Literal[290]) -> Literal[b'VARIANT_UserFree']:...

    @overload
    def __getitem__(self, key: Literal[291]) -> Literal[b'LPSAFEARRAY_UserSize']:...

    @overload
    def __getitem__(self, key: Literal[292]) -> Literal[b'LPSAFEARRAY_UserMarshal']:...

    @overload
    def __getitem__(self, key: Literal[293]) -> Literal[b'LPSAFEARRAY_UserUnmarshal']:...

    @overload
    def __getitem__(self, key: Literal[294]) -> Literal[b'LPSAFEARRAY_UserFree']:...

    @overload
    def __getitem__(self, key: Literal[295]) -> Literal[b'LPSAFEARRAY_Size']:...

    @overload
    def __getitem__(self, key: Literal[296]) -> Literal[b'LPSAFEARRAY_Marshal']:...

    @overload
    def __getitem__(self, key: Literal[297]) -> Literal[b'LPSAFEARRAY_Unmarshal']:...

    @overload
    def __getitem__(self, key: Literal[298]) -> Literal[b'VarDecCmpR8']:...

    @overload
    def __getitem__(self, key: Literal[299]) -> Literal[b'VarCyAdd']:...

    @overload
    def __getitem__(self, key: Literal[300]) -> Literal[b'DllUnregisterServer']:...

    @overload
    def __getitem__(self, key: Literal[301]) -> Literal[b'OACreateTypeLib2']:...

    @overload
    def __getitem__(self, key: Literal[303]) -> Literal[b'VarCyMul']:...

    @overload
    def __getitem__(self, key: Literal[304]) -> Literal[b'VarCyMulI4']:...

    @overload
    def __getitem__(self, key: Literal[305]) -> Literal[b'VarCySub']:...

    @overload
    def __getitem__(self, key: Literal[306]) -> Literal[b'VarCyAbs']:...

    @overload
    def __getitem__(self, key: Literal[307]) -> Literal[b'VarCyFix']:...

    @overload
    def __getitem__(self, key: Literal[308]) -> Literal[b'VarCyInt']:...

    @overload
    def __getitem__(self, key: Literal[309]) -> Literal[b'VarCyNeg']:...

    @overload
    def __getitem__(self, key: Literal[310]) -> Literal[b'VarCyRound']:...

    @overload
    def __getitem__(self, key: Literal[311]) -> Literal[b'VarCyCmp']:...

    @overload
    def __getitem__(self, key: Literal[312]) -> Literal[b'VarCyCmpR8']:...

    @overload
    def __getitem__(self, key: Literal[313]) -> Literal[b'VarBstrCat']:...

    @overload
    def __getitem__(self, key: Literal[314]) -> Literal[b'VarBstrCmp']:...

    @overload
    def __getitem__(self, key: Literal[315]) -> Literal[b'VarR8Pow']:...

    @overload
    def __getitem__(self, key: Literal[316]) -> Literal[b'VarR4CmpR8']:...

    @overload
    def __getitem__(self, key: Literal[317]) -> Literal[b'VarR8Round']:...

    @overload
    def __getitem__(self, key: Literal[318]) -> Literal[b'VarCat']:...

    @overload
    def __getitem__(self, key: Literal[319]) -> Literal[b'VarDateFromUdateEx']:...

    @overload
    def __getitem__(self, key: Literal[322]) -> Literal[b'GetRecordInfoFromGuids']:...

    @overload
    def __getitem__(self, key: Literal[323]) -> Literal[b'GetRecordInfoFromTypeInfo']:...

    @overload
    def __getitem__(self, key: Literal[325]) -> Literal[b'SetVarConversionLocaleSetting']:...

    @overload
    def __getitem__(self, key: Literal[326]) -> Literal[b'GetVarConversionLocaleSetting']:...

    @overload
    def __getitem__(self, key: Literal[327]) -> Literal[b'SetOaNoCache']:...

    @overload
    def __getitem__(self, key: Literal[329]) -> Literal[b'VarCyMulI8']:...

    @overload
    def __getitem__(self, key: Literal[330]) -> Literal[b'VarDateFromUdate']:...

    @overload
    def __getitem__(self, key: Literal[331]) -> Literal[b'VarUdateFromDate']:...

    @overload
    def __getitem__(self, key: Literal[332]) -> Literal[b'GetAltMonthNames']:...

    @overload
    def __getitem__(self, key: Literal[333]) -> Literal[b'VarI8FromUI1']:...

    @overload
    def __getitem__(self, key: Literal[334]) -> Literal[b'VarI8FromI2']:...

    @overload
    def __getitem__(self, key: Literal[335]) -> Literal[b'VarI8FromR4']:...

    @overload
    def __getitem__(self, key: Literal[336]) -> Literal[b'VarI8FromR8']:...

    @overload
    def __getitem__(self, key: Literal[337]) -> Literal[b'VarI8FromCy']:...

    @overload
    def __getitem__(self, key: Literal[338]) -> Literal[b'VarI8FromDate']:...

    @overload
    def __getitem__(self, key: Literal[339]) -> Literal[b'VarI8FromStr']:...

    @overload
    def __getitem__(self, key: Literal[340]) -> Literal[b'VarI8FromDisp']:...

    @overload
    def __getitem__(self, key: Literal[341]) -> Literal[b'VarI8FromBool']:...

    @overload
    def __getitem__(self, key: Literal[342]) -> Literal[b'VarI8FromI1']:...

    @overload
    def __getitem__(self, key: Literal[343]) -> Literal[b'VarI8FromUI2']:...

    @overload
    def __getitem__(self, key: Literal[344]) -> Literal[b'VarI8FromUI4']:...

    @overload
    def __getitem__(self, key: Literal[345]) -> Literal[b'VarI8FromDec']:...

    @overload
    def __getitem__(self, key: Literal[346]) -> Literal[b'VarI2FromI8']:...

    @overload
    def __getitem__(self, key: Literal[347]) -> Literal[b'VarI2FromUI8']:...

    @overload
    def __getitem__(self, key: Literal[348]) -> Literal[b'VarI4FromI8']:...

    @overload
    def __getitem__(self, key: Literal[349]) -> Literal[b'VarI4FromUI8']:...

    @overload
    def __getitem__(self, key: Literal[360]) -> Literal[b'VarR4FromI8']:...

    @overload
    def __getitem__(self, key: Literal[361]) -> Literal[b'VarR4FromUI8']:...

    @overload
    def __getitem__(self, key: Literal[362]) -> Literal[b'VarR8FromI8']:...

    @overload
    def __getitem__(self, key: Literal[363]) -> Literal[b'VarR8FromUI8']:...

    @overload
    def __getitem__(self, key: Literal[364]) -> Literal[b'VarDateFromI8']:...

    @overload
    def __getitem__(self, key: Literal[365]) -> Literal[b'VarDateFromUI8']:...

    @overload
    def __getitem__(self, key: Literal[366]) -> Literal[b'VarCyFromI8']:...

    @overload
    def __getitem__(self, key: Literal[367]) -> Literal[b'VarCyFromUI8']:...

    @overload
    def __getitem__(self, key: Literal[368]) -> Literal[b'VarBstrFromI8']:...

    @overload
    def __getitem__(self, key: Literal[369]) -> Literal[b'VarBstrFromUI8']:...

    @overload
    def __getitem__(self, key: Literal[370]) -> Literal[b'VarBoolFromI8']:...

    @overload
    def __getitem__(self, key: Literal[371]) -> Literal[b'VarBoolFromUI8']:...

    @overload
    def __getitem__(self, key: Literal[372]) -> Literal[b'VarUI1FromI8']:...

    @overload
    def __getitem__(self, key: Literal[373]) -> Literal[b'VarUI1FromUI8']:...

    @overload
    def __getitem__(self, key: Literal[374]) -> Literal[b'VarDecFromI8']:...

    @overload
    def __getitem__(self, key: Literal[375]) -> Literal[b'VarDecFromUI8']:...

    @overload
    def __getitem__(self, key: Literal[376]) -> Literal[b'VarI1FromI8']:...

    @overload
    def __getitem__(self, key: Literal[377]) -> Literal[b'VarI1FromUI8']:...

    @overload
    def __getitem__(self, key: Literal[378]) -> Literal[b'VarUI2FromI8']:...

    @overload
    def __getitem__(self, key: Literal[379]) -> Literal[b'VarUI2FromUI8']:...

    @overload
    def __getitem__(self, key: Literal[401]) -> Literal[b'OleLoadPictureEx']:...

    @overload
    def __getitem__(self, key: Literal[402]) -> Literal[b'OleLoadPictureFileEx']:...

    @overload
    def __getitem__(self, key: Literal[411]) -> Literal[b'SafeArrayCreateVector']:...

    @overload
    def __getitem__(self, key: Literal[412]) -> Literal[b'SafeArrayCopyData']:...

    @overload
    def __getitem__(self, key: Literal[413]) -> Literal[b'VectorFromBstr']:...

    @overload
    def __getitem__(self, key: Literal[414]) -> Literal[b'BstrFromVector']:...

    @overload
    def __getitem__(self, key: Literal[415]) -> Literal[b'OleIconToCursor']:...

    @overload
    def __getitem__(self, key: Literal[416]) -> Literal[b'OleCreatePropertyFrameIndirect']:...

    @overload
    def __getitem__(self, key: Literal[417]) -> Literal[b'OleCreatePropertyFrame']:...

    @overload
    def __getitem__(self, key: Literal[418]) -> Literal[b'OleLoadPicture']:...

    @overload
    def __getitem__(self, key: Literal[419]) -> Literal[b'OleCreatePictureIndirect']:...

    @overload
    def __getitem__(self, key: Literal[420]) -> Literal[b'OleCreateFontIndirect']:...

    @overload
    def __getitem__(self, key: Literal[421]) -> Literal[b'OleTranslateColor']:...

    @overload
    def __getitem__(self, key: Literal[422]) -> Literal[b'OleLoadPictureFile']:...

    @overload
    def __getitem__(self, key: Literal[423]) -> Literal[b'OleSavePictureFile']:...

    @overload
    def __getitem__(self, key: Literal[424]) -> Literal[b'OleLoadPicturePath']:...

    @overload
    def __getitem__(self, key: Literal[425]) -> Literal[b'VarUI4FromI8']:...

    @overload
    def __getitem__(self, key: Literal[426]) -> Literal[b'VarUI4FromUI8']:...

    @overload
    def __getitem__(self, key: Literal[427]) -> Literal[b'VarI8FromUI8']:...

    @overload
    def __getitem__(self, key: Literal[428]) -> Literal[b'VarUI8FromI8']:...

    @overload
    def __getitem__(self, key: Literal[429]) -> Literal[b'VarUI8FromUI1']:...

    @overload
    def __getitem__(self, key: Literal[430]) -> Literal[b'VarUI8FromI2']:...

    @overload
    def __getitem__(self, key: Literal[431]) -> Literal[b'VarUI8FromR4']:...

    @overload
    def __getitem__(self, key: Literal[432]) -> Literal[b'VarUI8FromR8']:...

    @overload
    def __getitem__(self, key: Literal[433]) -> Literal[b'VarUI8FromCy']:...

    @overload
    def __getitem__(self, key: Literal[434]) -> Literal[b'VarUI8FromDate']:...

    @overload
    def __getitem__(self, key: Literal[435]) -> Literal[b'VarUI8FromStr']:...

    @overload
    def __getitem__(self, key: Literal[436]) -> Literal[b'VarUI8FromDisp']:...

    @overload
    def __getitem__(self, key: Literal[437]) -> Literal[b'VarUI8FromBool']:...

    @overload
    def __getitem__(self, key: Literal[438]) -> Literal[b'VarUI8FromI1']:...

    @overload
    def __getitem__(self, key: Literal[439]) -> Literal[b'VarUI8FromUI2']:...

    @overload
    def __getitem__(self, key: Literal[440]) -> Literal[b'VarUI8FromUI4']:...

    @overload
    def __getitem__(self, key: Literal[441]) -> Literal[b'VarUI8FromDec']:...

    @overload
    def __getitem__(self, key: Literal[442]) -> Literal[b'RegisterTypeLibForUser']:...

    @overload
    def __getitem__(self, key: Literal[443]) -> Literal[b'UnRegisterTypeLibForUser']:...
ORD_NAMES_DICT_VALUES = Literal[
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
    100,
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
    117,
    118,
    119,
    120,
    121,
    122,
    123,
    124,
    125,
    126,
    127,
    128,
    129,
    130,
    131,
    132,
    133,
    134,
    135,
    136,
    137,
    138,
    139,
    140,
    141,
    142,
    143,
    144,
    145,
    146,
    147,
    148,
    149,
    150,
    151,
    152,
    153,
    154,
    155,
    156,
    157,
    158,
    159,
    160,
    161,
    162,
    163,
    164,
    165,
    166,
    167,
    168,
    169,
    170,
    171,
    172,
    173,
    174,
    175,
    176,
    177,
    178,
    179,
    180,
    181,
    182,
    183,
    184,
    185,
    186,
    187,
    188,
    189,
    190,
    191,
    192,
    193,
    194,
    195,
    196,
    197,
    198,
    199,
    200,
    201,
    202,
    203,
    204,
    205,
    206,
    207,
    208,
    209,
    210,
    211,
    212,
    213,
    214,
    215,
    216,
    217,
    218,
    219,
    220,
    221,
    222,
    223,
    224,
    225,
    226,
    227,
    228,
    229,
    230,
    231,
    232,
    233,
    234,
    235,
    236,
    237,
    238,
    239,
    240,
    241,
    242,
    243,
    244,
    245,
    246,
    247,
    248,
    249,
    250,
    251,
    252,
    253,
    254,
    255,
    256,
    257,
    258,
    259,
    260,
    261,
    262,
    263,
    264,
    265,
    266,
    267,
    268,
    269,
    270,
    271,
    272,
    273,
    274,
    275,
    276,
    277,
    278,
    279,
    280,
    281,
    282,
    283,
    284,
    285,
    286,
    287,
    288,
    289,
    290,
    291,
    292,
    293,
    294,
    295,
    296,
    297,
    298,
    299,
    300,
    301,
    303,
    304,
    305,
    306,
    307,
    308,
    309,
    310,
    311,
    312,
    313,
    314,
    315,
    316,
    317,
    318,
    319,
    322,
    323,
    325,
    326,
    327,
    329,
    330,
    331,
    332,
    333,
    334,
    335,
    336,
    337,
    338,
    339,
    340,
    341,
    342,
    343,
    344,
    345,
    346,
    347,
    348,
    349,
    360,
    361,
    362,
    363,
    364,
    365,
    366,
    367,
    368,
    369,
    370,
    371,
    372,
    373,
    374,
    375,
    376,
    377,
    378,
    379,
    401,
    402,
    411,
    412,
    413,
    414,
    415,
    416,
    417,
    418,
    419,
    420,
    421,
    422,
    423,
    424,
    425,
    426,
    427,
    428,
    429,
    430,
    431,
    432,
    433,
    434,
    435,
    436,
    437,
    438,
    439,
    440,
    441,
    442,
    443,
]
ORD_NAMES_DICT_NAMES = Literal[
    b'SysAllocString',
    b'SysReAllocString',
    b'SysAllocStringLen',
    b'SysReAllocStringLen',
    b'SysFreeString',
    b'SysStringLen',
    b'VariantInit',
    b'VariantClear',
    b'VariantCopy',
    b'VariantCopyInd',
    b'VariantChangeType',
    b'VariantTimeToDosDateTime',
    b'DosDateTimeToVariantTime',
    b'SafeArrayCreate',
    b'SafeArrayDestroy',
    b'SafeArrayGetDim',
    b'SafeArrayGetElemsize',
    b'SafeArrayGetUBound',
    b'SafeArrayGetLBound',
    b'SafeArrayLock',
    b'SafeArrayUnlock',
    b'SafeArrayAccessData',
    b'SafeArrayUnaccessData',
    b'SafeArrayGetElement',
    b'SafeArrayPutElement',
    b'SafeArrayCopy',
    b'DispGetParam',
    b'DispGetIDsOfNames',
    b'DispInvoke',
    b'CreateDispTypeInfo',
    b'CreateStdDispatch',
    b'RegisterActiveObject',
    b'RevokeActiveObject',
    b'GetActiveObject',
    b'SafeArrayAllocDescriptor',
    b'SafeArrayAllocData',
    b'SafeArrayDestroyDescriptor',
    b'SafeArrayDestroyData',
    b'SafeArrayRedim',
    b'SafeArrayAllocDescriptorEx',
    b'SafeArrayCreateEx',
    b'SafeArrayCreateVectorEx',
    b'SafeArraySetRecordInfo',
    b'SafeArrayGetRecordInfo',
    b'VarParseNumFromStr',
    b'VarNumFromParseNum',
    b'VarI2FromUI1',
    b'VarI2FromI4',
    b'VarI2FromR4',
    b'VarI2FromR8',
    b'VarI2FromCy',
    b'VarI2FromDate',
    b'VarI2FromStr',
    b'VarI2FromDisp',
    b'VarI2FromBool',
    b'SafeArraySetIID',
    b'VarI4FromUI1',
    b'VarI4FromI2',
    b'VarI4FromR4',
    b'VarI4FromR8',
    b'VarI4FromCy',
    b'VarI4FromDate',
    b'VarI4FromStr',
    b'VarI4FromDisp',
    b'VarI4FromBool',
    b'SafeArrayGetIID',
    b'VarR4FromUI1',
    b'VarR4FromI2',
    b'VarR4FromI4',
    b'VarR4FromR8',
    b'VarR4FromCy',
    b'VarR4FromDate',
    b'VarR4FromStr',
    b'VarR4FromDisp',
    b'VarR4FromBool',
    b'SafeArrayGetVartype',
    b'VarR8FromUI1',
    b'VarR8FromI2',
    b'VarR8FromI4',
    b'VarR8FromR4',
    b'VarR8FromCy',
    b'VarR8FromDate',
    b'VarR8FromStr',
    b'VarR8FromDisp',
    b'VarR8FromBool',
    b'VarFormat',
    b'VarDateFromUI1',
    b'VarDateFromI2',
    b'VarDateFromI4',
    b'VarDateFromR4',
    b'VarDateFromR8',
    b'VarDateFromCy',
    b'VarDateFromStr',
    b'VarDateFromDisp',
    b'VarDateFromBool',
    b'VarFormatDateTime',
    b'VarCyFromUI1',
    b'VarCyFromI2',
    b'VarCyFromI4',
    b'VarCyFromR4',
    b'VarCyFromR8',
    b'VarCyFromDate',
    b'VarCyFromStr',
    b'VarCyFromDisp',
    b'VarCyFromBool',
    b'VarFormatNumber',
    b'VarBstrFromUI1',
    b'VarBstrFromI2',
    b'VarBstrFromI4',
    b'VarBstrFromR4',
    b'VarBstrFromR8',
    b'VarBstrFromCy',
    b'VarBstrFromDate',
    b'VarBstrFromDisp',
    b'VarBstrFromBool',
    b'VarFormatPercent',
    b'VarBoolFromUI1',
    b'VarBoolFromI2',
    b'VarBoolFromI4',
    b'VarBoolFromR4',
    b'VarBoolFromR8',
    b'VarBoolFromDate',
    b'VarBoolFromCy',
    b'VarBoolFromStr',
    b'VarBoolFromDisp',
    b'VarFormatCurrency',
    b'VarWeekdayName',
    b'VarMonthName',
    b'VarUI1FromI2',
    b'VarUI1FromI4',
    b'VarUI1FromR4',
    b'VarUI1FromR8',
    b'VarUI1FromCy',
    b'VarUI1FromDate',
    b'VarUI1FromStr',
    b'VarUI1FromDisp',
    b'VarUI1FromBool',
    b'VarFormatFromTokens',
    b'VarTokenizeFormatString',
    b'VarAdd',
    b'VarAnd',
    b'VarDiv',
    b'DllCanUnloadNow',
    b'DllGetClassObject',
    b'DispCallFunc',
    b'VariantChangeTypeEx',
    b'SafeArrayPtrOfIndex',
    b'SysStringByteLen',
    b'SysAllocStringByteLen',
    b'DllRegisterServer',
    b'VarEqv',
    b'VarIdiv',
    b'VarImp',
    b'VarMod',
    b'VarMul',
    b'VarOr',
    b'VarPow',
    b'VarSub',
    b'CreateTypeLib',
    b'LoadTypeLib',
    b'LoadRegTypeLib',
    b'RegisterTypeLib',
    b'QueryPathOfRegTypeLib',
    b'LHashValOfNameSys',
    b'LHashValOfNameSysA',
    b'VarXor',
    b'VarAbs',
    b'VarFix',
    b'OaBuildVersion',
    b'ClearCustData',
    b'VarInt',
    b'VarNeg',
    b'VarNot',
    b'VarRound',
    b'VarCmp',
    b'VarDecAdd',
    b'VarDecDiv',
    b'VarDecMul',
    b'CreateTypeLib2',
    b'VarDecSub',
    b'VarDecAbs',
    b'LoadTypeLibEx',
    b'SystemTimeToVariantTime',
    b'VariantTimeToSystemTime',
    b'UnRegisterTypeLib',
    b'VarDecFix',
    b'VarDecInt',
    b'VarDecNeg',
    b'VarDecFromUI1',
    b'VarDecFromI2',
    b'VarDecFromI4',
    b'VarDecFromR4',
    b'VarDecFromR8',
    b'VarDecFromDate',
    b'VarDecFromCy',
    b'VarDecFromStr',
    b'VarDecFromDisp',
    b'VarDecFromBool',
    b'GetErrorInfo',
    b'SetErrorInfo',
    b'CreateErrorInfo',
    b'VarDecRound',
    b'VarDecCmp',
    b'VarI2FromI1',
    b'VarI2FromUI2',
    b'VarI2FromUI4',
    b'VarI2FromDec',
    b'VarI4FromI1',
    b'VarI4FromUI2',
    b'VarI4FromUI4',
    b'VarI4FromDec',
    b'VarR4FromI1',
    b'VarR4FromUI2',
    b'VarR4FromUI4',
    b'VarR4FromDec',
    b'VarR8FromI1',
    b'VarR8FromUI2',
    b'VarR8FromUI4',
    b'VarR8FromDec',
    b'VarDateFromI1',
    b'VarDateFromUI2',
    b'VarDateFromUI4',
    b'VarDateFromDec',
    b'VarCyFromI1',
    b'VarCyFromUI2',
    b'VarCyFromUI4',
    b'VarCyFromDec',
    b'VarBstrFromI1',
    b'VarBstrFromUI2',
    b'VarBstrFromUI4',
    b'VarBstrFromDec',
    b'VarBoolFromI1',
    b'VarBoolFromUI2',
    b'VarBoolFromUI4',
    b'VarBoolFromDec',
    b'VarUI1FromI1',
    b'VarUI1FromUI2',
    b'VarUI1FromUI4',
    b'VarUI1FromDec',
    b'VarDecFromI1',
    b'VarDecFromUI2',
    b'VarDecFromUI4',
    b'VarI1FromUI1',
    b'VarI1FromI2',
    b'VarI1FromI4',
    b'VarI1FromR4',
    b'VarI1FromR8',
    b'VarI1FromDate',
    b'VarI1FromCy',
    b'VarI1FromStr',
    b'VarI1FromDisp',
    b'VarI1FromBool',
    b'VarI1FromUI2',
    b'VarI1FromUI4',
    b'VarI1FromDec',
    b'VarUI2FromUI1',
    b'VarUI2FromI2',
    b'VarUI2FromI4',
    b'VarUI2FromR4',
    b'VarUI2FromR8',
    b'VarUI2FromDate',
    b'VarUI2FromCy',
    b'VarUI2FromStr',
    b'VarUI2FromDisp',
    b'VarUI2FromBool',
    b'VarUI2FromI1',
    b'VarUI2FromUI4',
    b'VarUI2FromDec',
    b'VarUI4FromUI1',
    b'VarUI4FromI2',
    b'VarUI4FromI4',
    b'VarUI4FromR4',
    b'VarUI4FromR8',
    b'VarUI4FromDate',
    b'VarUI4FromCy',
    b'VarUI4FromStr',
    b'VarUI4FromDisp',
    b'VarUI4FromBool',
    b'VarUI4FromI1',
    b'VarUI4FromUI2',
    b'VarUI4FromDec',
    b'BSTR_UserSize',
    b'BSTR_UserMarshal',
    b'BSTR_UserUnmarshal',
    b'BSTR_UserFree',
    b'VARIANT_UserSize',
    b'VARIANT_UserMarshal',
    b'VARIANT_UserUnmarshal',
    b'VARIANT_UserFree',
    b'LPSAFEARRAY_UserSize',
    b'LPSAFEARRAY_UserMarshal',
    b'LPSAFEARRAY_UserUnmarshal',
    b'LPSAFEARRAY_UserFree',
    b'LPSAFEARRAY_Size',
    b'LPSAFEARRAY_Marshal',
    b'LPSAFEARRAY_Unmarshal',
    b'VarDecCmpR8',
    b'VarCyAdd',
    b'DllUnregisterServer',
    b'OACreateTypeLib2',
    b'VarCyMul',
    b'VarCyMulI4',
    b'VarCySub',
    b'VarCyAbs',
    b'VarCyFix',
    b'VarCyInt',
    b'VarCyNeg',
    b'VarCyRound',
    b'VarCyCmp',
    b'VarCyCmpR8',
    b'VarBstrCat',
    b'VarBstrCmp',
    b'VarR8Pow',
    b'VarR4CmpR8',
    b'VarR8Round',
    b'VarCat',
    b'VarDateFromUdateEx',
    b'GetRecordInfoFromGuids',
    b'GetRecordInfoFromTypeInfo',
    b'SetVarConversionLocaleSetting',
    b'GetVarConversionLocaleSetting',
    b'SetOaNoCache',
    b'VarCyMulI8',
    b'VarDateFromUdate',
    b'VarUdateFromDate',
    b'GetAltMonthNames',
    b'VarI8FromUI1',
    b'VarI8FromI2',
    b'VarI8FromR4',
    b'VarI8FromR8',
    b'VarI8FromCy',
    b'VarI8FromDate',
    b'VarI8FromStr',
    b'VarI8FromDisp',
    b'VarI8FromBool',
    b'VarI8FromI1',
    b'VarI8FromUI2',
    b'VarI8FromUI4',
    b'VarI8FromDec',
    b'VarI2FromI8',
    b'VarI2FromUI8',
    b'VarI4FromI8',
    b'VarI4FromUI8',
    b'VarR4FromI8',
    b'VarR4FromUI8',
    b'VarR8FromI8',
    b'VarR8FromUI8',
    b'VarDateFromI8',
    b'VarDateFromUI8',
    b'VarCyFromI8',
    b'VarCyFromUI8',
    b'VarBstrFromI8',
    b'VarBstrFromUI8',
    b'VarBoolFromI8',
    b'VarBoolFromUI8',
    b'VarUI1FromI8',
    b'VarUI1FromUI8',
    b'VarDecFromI8',
    b'VarDecFromUI8',
    b'VarI1FromI8',
    b'VarI1FromUI8',
    b'VarUI2FromI8',
    b'VarUI2FromUI8',
    b'OleLoadPictureEx',
    b'OleLoadPictureFileEx',
    b'SafeArrayCreateVector',
    b'SafeArrayCopyData',
    b'VectorFromBstr',
    b'BstrFromVector',
    b'OleIconToCursor',
    b'OleCreatePropertyFrameIndirect',
    b'OleCreatePropertyFrame',
    b'OleLoadPicture',
    b'OleCreatePictureIndirect',
    b'OleCreateFontIndirect',
    b'OleTranslateColor',
    b'OleLoadPictureFile',
    b'OleSavePictureFile',
    b'OleLoadPicturePath',
    b'VarUI4FromI8',
    b'VarUI4FromUI8',
    b'VarI8FromUI8',
    b'VarUI8FromI8',
    b'VarUI8FromUI1',
    b'VarUI8FromI2',
    b'VarUI8FromR4',
    b'VarUI8FromR8',
    b'VarUI8FromCy',
    b'VarUI8FromDate',
    b'VarUI8FromStr',
    b'VarUI8FromDisp',
    b'VarUI8FromBool',
    b'VarUI8FromI1',
    b'VarUI8FromUI2',
    b'VarUI8FromUI4',
    b'VarUI8FromDec',
    b'RegisterTypeLibForUser',
    b'UnRegisterTypeLibForUser',
]
