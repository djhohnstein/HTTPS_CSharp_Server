
//  Microsoft (R) .NET Framework IL Disassembler.  Version 4.8.3928.0
//  Copyright (c) Microsoft Corporation.  All rights reserved.



// Metadata version: v4.0.30319
.module extern kernel32.dll
.assembly extern mscorlib
{
  .publickeytoken = (B7 7A 5C 56 19 34 E0 89 )                         // .z\V.4..
  .ver 4:0:0:0
}
.assembly extern System
{
  .publickeytoken = (B7 7A 5C 56 19 34 E0 89 )                         // .z\V.4..
  .ver 4:0:0:0
}
.assembly extern System.Configuration.Install
{
  .publickeytoken = (B0 3F 5F 7F 11 D5 0A 3A )                         // .?_....:
  .ver 4:0:0:0
}
.assembly extern System.Configuration
{
  .publickeytoken = (B0 3F 5F 7F 11 D5 0A 3A )                         // .?_....:
  .ver 4:0:0:0
}
.assembly HTTPProxyServer
{
  .custom instance void [mscorlib]System.Runtime.CompilerServices.CompilationRelaxationsAttribute::.ctor(int32) = ( 01 00 08 00 00 00 00 00 ) 
  .custom instance void [mscorlib]System.Runtime.CompilerServices.RuntimeCompatibilityAttribute::.ctor() = ( 01 00 01 00 54 02 16 57 72 61 70 4E 6F 6E 45 78   // ....T..WrapNonEx
                                                                                                             63 65 70 74 69 6F 6E 54 68 72 6F 77 73 01 )       // ceptionThrows.

  // --- The following custom attribute is added automatically, do not uncomment -------
  //  .custom instance void [mscorlib]System.Diagnostics.DebuggableAttribute::.ctor(valuetype [mscorlib]System.Diagnostics.DebuggableAttribute/DebuggingModes) = ( 01 00 02 00 00 00 00 00 ) 

  .custom instance void [mscorlib]System.Runtime.Versioning.TargetFrameworkAttribute::.ctor(string) = ( 01 00 1C 2E 4E 45 54 46 72 61 6D 65 77 6F 72 6B   // ....NETFramework
                                                                                                        2C 56 65 72 73 69 6F 6E 3D 76 34 2E 37 2E 32 01   // ,Version=v4.7.2.
                                                                                                        00 54 0E 14 46 72 61 6D 65 77 6F 72 6B 44 69 73   // .T..FrameworkDis
                                                                                                        70 6C 61 79 4E 61 6D 65 14 2E 4E 45 54 20 46 72   // playName..NET Fr
                                                                                                        61 6D 65 77 6F 72 6B 20 34 2E 37 2E 32 )          // amework 4.7.2
  .hash algorithm 0x00008004
  .ver 0:0:0:0
}
.module HTTPProxyServer.dll
// MVID: {32412C61-0587-45B4-A03F-82CB02BDE027}
.imagebase 0x10000000
.file alignment 0x00000200
.stackreserve 0x00100000
.subsystem 0x0003       // WINDOWS_CUI
.corflags 0x00000001    //  ILONLY
// Image base: 0x07000000


// =============== CLASS MEMBERS DECLARATION ===================

.class public auto ansi beforefieldinit Exports
       extends [mscorlib]System.Object
{
  .method public hidebysig static void  Exec() cil managed
  {
    // Code size       34 (0x22)
    .maxstack  8
    IL_0000:  ldc.i4.2
    IL_0001:  newarr     [mscorlib]System.String
    IL_0006:  dup
    IL_0007:  ldc.i4.0
    IL_0008:  ldstr      "-h"
    IL_000d:  stelem.ref
    IL_000e:  dup
    IL_000f:  ldc.i4.1
    IL_0010:  ldstr      "-p"
    IL_0015:  stelem.ref
    IL_0016:  call       bool Exports::AllocConsole()
    IL_001b:  pop
    IL_001c:  call       void HTTPProxyServer.Program::Main(string[])
    IL_0021:  ret
  } // end of method Exports::Exec

  .method public hidebysig static bool  DllRegisterServer() cil managed
  {
    // Code size       7 (0x7)
	.export[0]
    .maxstack  8
    IL_0000:  call       void Exports::Exec()
    IL_0005:  ldc.i4.1
    IL_0006:  ret
  } // end of method Exports::DllRegisterServer

  .method public hidebysig static bool  DllUnregisterServer() cil managed
  {
    // Code size       7 (0x7)
	.export[1]
    .maxstack  8
    IL_0000:  call       void Exports::Exec()
    IL_0005:  ldc.i4.1
    IL_0006:  ret
  } // end of method Exports::DllUnregisterServer

  .method public hidebysig instance uint32 
          DllGetClassObject(native int refclsid,
                            native int refiid,
                            native int& ppv) cil managed
  {
    // Code size       7 (0x7)
	.export[2]
    .maxstack  8
    IL_0000:  call       void Exports::Exec()
    IL_0005:  ldc.i4.0
    IL_0006:  ret
  } // end of method Exports::DllGetClassObject

  .method public hidebysig static pinvokeimpl("kernel32.dll" lasterr winapi) 
          bool  marshal( bool)  AllocConsole() cil managed preservesig
  {
  }
  .method public hidebysig static void  EntryPoint(native int hwnd,
                                                   native int hinst,
                                                   string lpszCmdLine,
                                                   int32 nCmdShow) cil managed
  {
    // Code size       6 (0x6)
	.export[3]
    .maxstack  8
    IL_0000:  call       void Exports::Exec()
    IL_0005:  ret
  } // end of method Exports::EntryPoint

  .method public hidebysig specialname rtspecialname 
          instance void  .ctor() cil managed
  {
    // Code size       7 (0x7)
    .maxstack  8
    IL_0000:  ldarg.0
    IL_0001:  call       instance void [mscorlib]System.Object::.ctor()
    IL_0006:  ret
  } // end of method Exports::.ctor

} // end of class Exports

.class public auto ansi beforefieldinit Sample
       extends [System.Configuration.Install]System.Configuration.Install.Installer
{
  .custom instance void [System]System.ComponentModel.RunInstallerAttribute::.ctor(bool) = ( 01 00 01 00 00 ) 
  .method public hidebysig virtual instance void 
          Uninstall(class [mscorlib]System.Collections.IDictionary savedState) cil managed
  {
    // Code size       28 (0x1c)
    .maxstack  8
    IL_0000:  ldc.i4.2
    IL_0001:  newarr     [mscorlib]System.String
    IL_0006:  dup
    IL_0007:  ldc.i4.0
    IL_0008:  ldstr      "-h"
    IL_000d:  stelem.ref
    IL_000e:  dup
    IL_000f:  ldc.i4.1
    IL_0010:  ldstr      "-p"
    IL_0015:  stelem.ref
    IL_0016:  call       void HTTPProxyServer.Program::Main(string[])
    IL_001b:  ret
  } // end of method Sample::Uninstall

  .method public hidebysig specialname rtspecialname 
          instance void  .ctor() cil managed
  {
    // Code size       7 (0x7)
    .maxstack  8
    IL_0000:  ldarg.0
    IL_0001:  call       instance void [System.Configuration.Install]System.Configuration.Install.Installer::.ctor()
    IL_0006:  ret
  } // end of method Sample::.ctor

} // end of class Sample

.class public auto ansi beforefieldinit HTTPProxyServer.CacheEntry
       extends [mscorlib]System.Object
{
  .field private class HTTPProxyServer.CacheKey '<Key>k__BackingField'
  .custom instance void [mscorlib]System.Runtime.CompilerServices.CompilerGeneratedAttribute::.ctor() = ( 01 00 00 00 ) 
  .field private valuetype [mscorlib]System.Nullable`1<valuetype [mscorlib]System.DateTime> '<Expires>k__BackingField'
  .custom instance void [mscorlib]System.Runtime.CompilerServices.CompilerGeneratedAttribute::.ctor() = ( 01 00 00 00 ) 
  .field private valuetype [mscorlib]System.DateTime '<DateStored>k__BackingField'
  .custom instance void [mscorlib]System.Runtime.CompilerServices.CompilerGeneratedAttribute::.ctor() = ( 01 00 00 00 ) 
  .field private uint8[] '<ResponseBytes>k__BackingField'
  .custom instance void [mscorlib]System.Runtime.CompilerServices.CompilerGeneratedAttribute::.ctor() = ( 01 00 00 00 ) 
  .field private valuetype [System]System.Net.HttpStatusCode '<StatusCode>k__BackingField'
  .custom instance void [mscorlib]System.Runtime.CompilerServices.CompilerGeneratedAttribute::.ctor() = ( 01 00 00 00 ) 
  .field private string '<StatusDescription>k__BackingField'
  .custom instance void [mscorlib]System.Runtime.CompilerServices.CompilerGeneratedAttribute::.ctor() = ( 01 00 00 00 ) 
  .field private class [mscorlib]System.Collections.Generic.List`1<class [mscorlib]System.Tuple`2<string,string>> '<Headers>k__BackingField'
  .custom instance void [mscorlib]System.Runtime.CompilerServices.CompilerGeneratedAttribute::.ctor() = ( 01 00 00 00 ) 
  .field private bool '<FlagRemove>k__BackingField'
  .custom instance void [mscorlib]System.Runtime.CompilerServices.CompilerGeneratedAttribute::.ctor() = ( 01 00 00 00 ) 
  .method public hidebysig specialname instance class HTTPProxyServer.CacheKey 
          get_Key() cil managed
  {
    .custom instance void [mscorlib]System.Runtime.CompilerServices.CompilerGeneratedAttribute::.ctor() = ( 01 00 00 00 ) 
    // Code size       7 (0x7)
    .maxstack  8
    IL_0000:  ldarg.0
    IL_0001:  ldfld      class HTTPProxyServer.CacheKey HTTPProxyServer.CacheEntry::'<Key>k__BackingField'
    IL_0006:  ret
  } // end of method CacheEntry::get_Key

  .method public hidebysig specialname instance void 
          set_Key(class HTTPProxyServer.CacheKey 'value') cil managed
  {
    .custom instance void [mscorlib]System.Runtime.CompilerServices.CompilerGeneratedAttribute::.ctor() = ( 01 00 00 00 ) 
    // Code size       8 (0x8)
    .maxstack  8
    IL_0000:  ldarg.0
    IL_0001:  ldarg.1
    IL_0002:  stfld      class HTTPProxyServer.CacheKey HTTPProxyServer.CacheEntry::'<Key>k__BackingField'
    IL_0007:  ret
  } // end of method CacheEntry::set_Key

  .method public hidebysig specialname instance valuetype [mscorlib]System.Nullable`1<valuetype [mscorlib]System.DateTime> 
          get_Expires() cil managed
  {
    .custom instance void [mscorlib]System.Runtime.CompilerServices.CompilerGeneratedAttribute::.ctor() = ( 01 00 00 00 ) 
    // Code size       7 (0x7)
    .maxstack  8
    IL_0000:  ldarg.0
    IL_0001:  ldfld      valuetype [mscorlib]System.Nullable`1<valuetype [mscorlib]System.DateTime> HTTPProxyServer.CacheEntry::'<Expires>k__BackingField'
    IL_0006:  ret
  } // end of method CacheEntry::get_Expires

  .method public hidebysig specialname instance void 
          set_Expires(valuetype [mscorlib]System.Nullable`1<valuetype [mscorlib]System.DateTime> 'value') cil managed
  {
    .custom instance void [mscorlib]System.Runtime.CompilerServices.CompilerGeneratedAttribute::.ctor() = ( 01 00 00 00 ) 
    // Code size       8 (0x8)
    .maxstack  8
    IL_0000:  ldarg.0
    IL_0001:  ldarg.1
    IL_0002:  stfld      valuetype [mscorlib]System.Nullable`1<valuetype [mscorlib]System.DateTime> HTTPProxyServer.CacheEntry::'<Expires>k__BackingField'
    IL_0007:  ret
  } // end of method CacheEntry::set_Expires

  .method public hidebysig specialname instance valuetype [mscorlib]System.DateTime 
          get_DateStored() cil managed
  {
    .custom instance void [mscorlib]System.Runtime.CompilerServices.CompilerGeneratedAttribute::.ctor() = ( 01 00 00 00 ) 
    // Code size       7 (0x7)
    .maxstack  8
    IL_0000:  ldarg.0
    IL_0001:  ldfld      valuetype [mscorlib]System.DateTime HTTPProxyServer.CacheEntry::'<DateStored>k__BackingField'
    IL_0006:  ret
  } // end of method CacheEntry::get_DateStored

  .method public hidebysig specialname instance void 
          set_DateStored(valuetype [mscorlib]System.DateTime 'value') cil managed
  {
    .custom instance void [mscorlib]System.Runtime.CompilerServices.CompilerGeneratedAttribute::.ctor() = ( 01 00 00 00 ) 
    // Code size       8 (0x8)
    .maxstack  8
    IL_0000:  ldarg.0
    IL_0001:  ldarg.1
    IL_0002:  stfld      valuetype [mscorlib]System.DateTime HTTPProxyServer.CacheEntry::'<DateStored>k__BackingField'
    IL_0007:  ret
  } // end of method CacheEntry::set_DateStored

  .method public hidebysig specialname instance uint8[] 
          get_ResponseBytes() cil managed
  {
    .custom instance void [mscorlib]System.Runtime.CompilerServices.CompilerGeneratedAttribute::.ctor() = ( 01 00 00 00 ) 
    // Code size       7 (0x7)
    .maxstack  8
    IL_0000:  ldarg.0
    IL_0001:  ldfld      uint8[] HTTPProxyServer.CacheEntry::'<ResponseBytes>k__BackingField'
    IL_0006:  ret
  } // end of method CacheEntry::get_ResponseBytes

  .method public hidebysig specialname instance void 
          set_ResponseBytes(uint8[] 'value') cil managed
  {
    .custom instance void [mscorlib]System.Runtime.CompilerServices.CompilerGeneratedAttribute::.ctor() = ( 01 00 00 00 ) 
    // Code size       8 (0x8)
    .maxstack  8
    IL_0000:  ldarg.0
    IL_0001:  ldarg.1
    IL_0002:  stfld      uint8[] HTTPProxyServer.CacheEntry::'<ResponseBytes>k__BackingField'
    IL_0007:  ret
  } // end of method CacheEntry::set_ResponseBytes

  .method public hidebysig specialname instance valuetype [System]System.Net.HttpStatusCode 
          get_StatusCode() cil managed
  {
    .custom instance void [mscorlib]System.Runtime.CompilerServices.CompilerGeneratedAttribute::.ctor() = ( 01 00 00 00 ) 
    // Code size       7 (0x7)
    .maxstack  8
    IL_0000:  ldarg.0
    IL_0001:  ldfld      valuetype [System]System.Net.HttpStatusCode HTTPProxyServer.CacheEntry::'<StatusCode>k__BackingField'
    IL_0006:  ret
  } // end of method CacheEntry::get_StatusCode

  .method public hidebysig specialname instance void 
          set_StatusCode(valuetype [System]System.Net.HttpStatusCode 'value') cil managed
  {
    .custom instance void [mscorlib]System.Runtime.CompilerServices.CompilerGeneratedAttribute::.ctor() = ( 01 00 00 00 ) 
    // Code size       8 (0x8)
    .maxstack  8
    IL_0000:  ldarg.0
    IL_0001:  ldarg.1
    IL_0002:  stfld      valuetype [System]System.Net.HttpStatusCode HTTPProxyServer.CacheEntry::'<StatusCode>k__BackingField'
    IL_0007:  ret
  } // end of method CacheEntry::set_StatusCode

  .method public hidebysig specialname instance string 
          get_StatusDescription() cil managed
  {
    .custom instance void [mscorlib]System.Runtime.CompilerServices.CompilerGeneratedAttribute::.ctor() = ( 01 00 00 00 ) 
    // Code size       7 (0x7)
    .maxstack  8
    IL_0000:  ldarg.0
    IL_0001:  ldfld      string HTTPProxyServer.CacheEntry::'<StatusDescription>k__BackingField'
    IL_0006:  ret
  } // end of method CacheEntry::get_StatusDescription

  .method public hidebysig specialname instance void 
          set_StatusDescription(string 'value') cil managed
  {
    .custom instance void [mscorlib]System.Runtime.CompilerServices.CompilerGeneratedAttribute::.ctor() = ( 01 00 00 00 ) 
    // Code size       8 (0x8)
    .maxstack  8
    IL_0000:  ldarg.0
    IL_0001:  ldarg.1
    IL_0002:  stfld      string HTTPProxyServer.CacheEntry::'<StatusDescription>k__BackingField'
    IL_0007:  ret
  } // end of method CacheEntry::set_StatusDescription

  .method public hidebysig specialname instance class [mscorlib]System.Collections.Generic.List`1<class [mscorlib]System.Tuple`2<string,string>> 
          get_Headers() cil managed
  {
    .custom instance void [mscorlib]System.Runtime.CompilerServices.CompilerGeneratedAttribute::.ctor() = ( 01 00 00 00 ) 
    // Code size       7 (0x7)
    .maxstack  8
    IL_0000:  ldarg.0
    IL_0001:  ldfld      class [mscorlib]System.Collections.Generic.List`1<class [mscorlib]System.Tuple`2<string,string>> HTTPProxyServer.CacheEntry::'<Headers>k__BackingField'
    IL_0006:  ret
  } // end of method CacheEntry::get_Headers

  .method public hidebysig specialname instance void 
          set_Headers(class [mscorlib]System.Collections.Generic.List`1<class [mscorlib]System.Tuple`2<string,string>> 'value') cil managed
  {
    .custom instance void [mscorlib]System.Runtime.CompilerServices.CompilerGeneratedAttribute::.ctor() = ( 01 00 00 00 ) 
    // Code size       8 (0x8)
    .maxstack  8
    IL_0000:  ldarg.0
    IL_0001:  ldarg.1
    IL_0002:  stfld      class [mscorlib]System.Collections.Generic.List`1<class [mscorlib]System.Tuple`2<string,string>> HTTPProxyServer.CacheEntry::'<Headers>k__BackingField'
    IL_0007:  ret
  } // end of method CacheEntry::set_Headers

  .method public hidebysig specialname instance bool 
          get_FlagRemove() cil managed
  {
    .custom instance void [mscorlib]System.Runtime.CompilerServices.CompilerGeneratedAttribute::.ctor() = ( 01 00 00 00 ) 
    // Code size       7 (0x7)
    .maxstack  8
    IL_0000:  ldarg.0
    IL_0001:  ldfld      bool HTTPProxyServer.CacheEntry::'<FlagRemove>k__BackingField'
    IL_0006:  ret
  } // end of method CacheEntry::get_FlagRemove

  .method public hidebysig specialname instance void 
          set_FlagRemove(bool 'value') cil managed
  {
    .custom instance void [mscorlib]System.Runtime.CompilerServices.CompilerGeneratedAttribute::.ctor() = ( 01 00 00 00 ) 
    // Code size       8 (0x8)
    .maxstack  8
    IL_0000:  ldarg.0
    IL_0001:  ldarg.1
    IL_0002:  stfld      bool HTTPProxyServer.CacheEntry::'<FlagRemove>k__BackingField'
    IL_0007:  ret
  } // end of method CacheEntry::set_FlagRemove

  .method public hidebysig specialname rtspecialname 
          instance void  .ctor() cil managed
  {
    // Code size       7 (0x7)
    .maxstack  8
    IL_0000:  ldarg.0
    IL_0001:  call       instance void [mscorlib]System.Object::.ctor()
    IL_0006:  ret
  } // end of method CacheEntry::.ctor

  .property instance class HTTPProxyServer.CacheKey
          Key()
  {
    .get instance class HTTPProxyServer.CacheKey HTTPProxyServer.CacheEntry::get_Key()
    .set instance void HTTPProxyServer.CacheEntry::set_Key(class HTTPProxyServer.CacheKey)
  } // end of property CacheEntry::Key
  .property instance valuetype [mscorlib]System.Nullable`1<valuetype [mscorlib]System.DateTime>
          Expires()
  {
    .get instance valuetype [mscorlib]System.Nullable`1<valuetype [mscorlib]System.DateTime> HTTPProxyServer.CacheEntry::get_Expires()
    .set instance void HTTPProxyServer.CacheEntry::set_Expires(valuetype [mscorlib]System.Nullable`1<valuetype [mscorlib]System.DateTime>)
  } // end of property CacheEntry::Expires
  .property instance valuetype [mscorlib]System.DateTime
          DateStored()
  {
    .get instance valuetype [mscorlib]System.DateTime HTTPProxyServer.CacheEntry::get_DateStored()
    .set instance void HTTPProxyServer.CacheEntry::set_DateStored(valuetype [mscorlib]System.DateTime)
  } // end of property CacheEntry::DateStored
  .property instance uint8[] ResponseBytes()
  {
    .get instance uint8[] HTTPProxyServer.CacheEntry::get_ResponseBytes()
    .set instance void HTTPProxyServer.CacheEntry::set_ResponseBytes(uint8[])
  } // end of property CacheEntry::ResponseBytes
  .property instance valuetype [System]System.Net.HttpStatusCode
          StatusCode()
  {
    .get instance valuetype [System]System.Net.HttpStatusCode HTTPProxyServer.CacheEntry::get_StatusCode()
    .set instance void HTTPProxyServer.CacheEntry::set_StatusCode(valuetype [System]System.Net.HttpStatusCode)
  } // end of property CacheEntry::StatusCode
  .property instance string StatusDescription()
  {
    .get instance string HTTPProxyServer.CacheEntry::get_StatusDescription()
    .set instance void HTTPProxyServer.CacheEntry::set_StatusDescription(string)
  } // end of property CacheEntry::StatusDescription
  .property instance class [mscorlib]System.Collections.Generic.List`1<class [mscorlib]System.Tuple`2<string,string>>
          Headers()
  {
    .get instance class [mscorlib]System.Collections.Generic.List`1<class [mscorlib]System.Tuple`2<string,string>> HTTPProxyServer.CacheEntry::get_Headers()
    .set instance void HTTPProxyServer.CacheEntry::set_Headers(class [mscorlib]System.Collections.Generic.List`1<class [mscorlib]System.Tuple`2<string,string>>)
  } // end of property CacheEntry::Headers
  .property instance bool FlagRemove()
  {
    .get instance bool HTTPProxyServer.CacheEntry::get_FlagRemove()
    .set instance void HTTPProxyServer.CacheEntry::set_FlagRemove(bool)
  } // end of property CacheEntry::FlagRemove
} // end of class HTTPProxyServer.CacheEntry

.class public auto ansi beforefieldinit HTTPProxyServer.CacheKey
       extends [mscorlib]System.Object
{
  .field private string '<AbsoluteUri>k__BackingField'
  .custom instance void [mscorlib]System.Runtime.CompilerServices.CompilerGeneratedAttribute::.ctor() = ( 01 00 00 00 ) 
  .field private string '<UserAgent>k__BackingField'
  .custom instance void [mscorlib]System.Runtime.CompilerServices.CompilerGeneratedAttribute::.ctor() = ( 01 00 00 00 ) 
  .method public hidebysig specialname instance string 
          get_AbsoluteUri() cil managed
  {
    .custom instance void [mscorlib]System.Runtime.CompilerServices.CompilerGeneratedAttribute::.ctor() = ( 01 00 00 00 ) 
    // Code size       7 (0x7)
    .maxstack  8
    IL_0000:  ldarg.0
    IL_0001:  ldfld      string HTTPProxyServer.CacheKey::'<AbsoluteUri>k__BackingField'
    IL_0006:  ret
  } // end of method CacheKey::get_AbsoluteUri

  .method public hidebysig specialname instance void 
          set_AbsoluteUri(string 'value') cil managed
  {
    .custom instance void [mscorlib]System.Runtime.CompilerServices.CompilerGeneratedAttribute::.ctor() = ( 01 00 00 00 ) 
    // Code size       8 (0x8)
    .maxstack  8
    IL_0000:  ldarg.0
    IL_0001:  ldarg.1
    IL_0002:  stfld      string HTTPProxyServer.CacheKey::'<AbsoluteUri>k__BackingField'
    IL_0007:  ret
  } // end of method CacheKey::set_AbsoluteUri

  .method public hidebysig specialname instance string 
          get_UserAgent() cil managed
  {
    .custom instance void [mscorlib]System.Runtime.CompilerServices.CompilerGeneratedAttribute::.ctor() = ( 01 00 00 00 ) 
    // Code size       7 (0x7)
    .maxstack  8
    IL_0000:  ldarg.0
    IL_0001:  ldfld      string HTTPProxyServer.CacheKey::'<UserAgent>k__BackingField'
    IL_0006:  ret
  } // end of method CacheKey::get_UserAgent

  .method public hidebysig specialname instance void 
          set_UserAgent(string 'value') cil managed
  {
    .custom instance void [mscorlib]System.Runtime.CompilerServices.CompilerGeneratedAttribute::.ctor() = ( 01 00 00 00 ) 
    // Code size       8 (0x8)
    .maxstack  8
    IL_0000:  ldarg.0
    IL_0001:  ldarg.1
    IL_0002:  stfld      string HTTPProxyServer.CacheKey::'<UserAgent>k__BackingField'
    IL_0007:  ret
  } // end of method CacheKey::set_UserAgent

  .method public hidebysig specialname rtspecialname 
          instance void  .ctor(string requestUri,
                               string userAgent) cil managed
  {
    // Code size       21 (0x15)
    .maxstack  8
    IL_0000:  ldarg.0
    IL_0001:  call       instance void [mscorlib]System.Object::.ctor()
    IL_0006:  ldarg.0
    IL_0007:  ldarg.1
    IL_0008:  call       instance void HTTPProxyServer.CacheKey::set_AbsoluteUri(string)
    IL_000d:  ldarg.0
    IL_000e:  ldarg.2
    IL_000f:  call       instance void HTTPProxyServer.CacheKey::set_UserAgent(string)
    IL_0014:  ret
  } // end of method CacheKey::.ctor

  .method public hidebysig virtual instance bool 
          Equals(object obj) cil managed
  {
    // Code size       51 (0x33)
    .maxstack  2
    .locals init ([0] class HTTPProxyServer.CacheKey key)
    IL_0000:  ldarg.1
    IL_0001:  isinst     HTTPProxyServer.CacheKey
    IL_0006:  stloc.0
    IL_0007:  ldloc.0
    IL_0008:  brfalse.s  IL_0031

    IL_000a:  ldloc.0
    IL_000b:  callvirt   instance string HTTPProxyServer.CacheKey::get_AbsoluteUri()
    IL_0010:  ldarg.0
    IL_0011:  call       instance string HTTPProxyServer.CacheKey::get_AbsoluteUri()
    IL_0016:  call       bool [mscorlib]System.String::op_Equality(string,
                                                                   string)
    IL_001b:  brfalse.s  IL_002f

    IL_001d:  ldloc.0
    IL_001e:  callvirt   instance string HTTPProxyServer.CacheKey::get_UserAgent()
    IL_0023:  ldarg.0
    IL_0024:  call       instance string HTTPProxyServer.CacheKey::get_UserAgent()
    IL_0029:  call       bool [mscorlib]System.String::op_Equality(string,
                                                                   string)
    IL_002e:  ret

    IL_002f:  ldc.i4.0
    IL_0030:  ret

    IL_0031:  ldc.i4.0
    IL_0032:  ret
  } // end of method CacheKey::Equals

  .method public hidebysig virtual instance int32 
          GetHashCode() cil managed
  {
    // Code size       23 (0x17)
    .maxstack  8
    IL_0000:  ldarg.0
    IL_0001:  call       instance string HTTPProxyServer.CacheKey::get_AbsoluteUri()
    IL_0006:  ldarg.0
    IL_0007:  call       instance string HTTPProxyServer.CacheKey::get_UserAgent()
    IL_000c:  call       string [mscorlib]System.String::Concat(string,
                                                                string)
    IL_0011:  callvirt   instance int32 [mscorlib]System.Object::GetHashCode()
    IL_0016:  ret
  } // end of method CacheKey::GetHashCode

  .property instance string AbsoluteUri()
  {
    .get instance string HTTPProxyServer.CacheKey::get_AbsoluteUri()
    .set instance void HTTPProxyServer.CacheKey::set_AbsoluteUri(string)
  } // end of property CacheKey::AbsoluteUri
  .property instance string UserAgent()
  {
    .get instance string HTTPProxyServer.CacheKey::get_UserAgent()
    .set instance void HTTPProxyServer.CacheKey::set_UserAgent(string)
  } // end of property CacheKey::UserAgent
} // end of class HTTPProxyServer.CacheKey

.class private auto ansi beforefieldinit HTTPProxyServer.Program
       extends [mscorlib]System.Object
{
  .method private hidebysig static void  PrintUsageInfo() cil managed
  {
    // Code size       141 (0x8d)
    .maxstack  1
    IL_0000:  ldstr      "matt-dot-net proxy server usage: "
    IL_0005:  call       void [mscorlib]System.Console::WriteLine(string)
    IL_000a:  ldstr      "\t-\? = this help"
    IL_000f:  call       void [mscorlib]System.Console::WriteLine(string)
    IL_0014:  ldstr      "\t-h = dump headers to standard output"
    IL_0019:  call       void [mscorlib]System.Console::WriteLine(string)
    IL_001e:  ldstr      "\t-p = dump post data to standard output"
    IL_0023:  call       void [mscorlib]System.Console::WriteLine(string)
    IL_0028:  ldstr      "\t-r = dump response data to standard output (WARNI"
    + "NG: redirect your output to a file)"
    IL_002d:  call       void [mscorlib]System.Console::WriteLine(string)
    IL_0032:  call       void [mscorlib]System.Console::WriteLine()
    IL_0037:  ldstr      "\tNote: Data dumping kills performance"
    IL_003c:  call       void [mscorlib]System.Console::WriteLine(string)
    IL_0041:  call       void [mscorlib]System.Console::WriteLine()
    IL_0046:  ldstr      "\tDisclaimer: This proxy server is for testing and "
    + "development purposes only."
    IL_004b:  call       void [mscorlib]System.Console::WriteLine(string)
    IL_0050:  ldstr      "\t            Installing this server on a network w"
    + "ithout the knowledge of others is not"
    IL_0055:  call       void [mscorlib]System.Console::WriteLine(string)
    IL_005a:  ldstr      "\t            condoned by the author. This proxy se"
    + "rver presents a security risk for"
    IL_005f:  call       void [mscorlib]System.Console::WriteLine(string)
    IL_0064:  ldstr      "\t            users who do not understand SSL certi"
    + "ficates and browser security."
    IL_0069:  call       void [mscorlib]System.Console::WriteLine(string)
    IL_006e:  call       void [mscorlib]System.Console::WriteLine()
    IL_0073:  ldstr      "\tAuthor: Matt McKnight <matt_mcknight@live.com>"
    IL_0078:  call       void [mscorlib]System.Console::WriteLine(string)
    IL_007d:  ldstr      "\tAuthor: Adapted 2021 - Casey Smith @subTee "
    IL_0082:  call       void [mscorlib]System.Console::WriteLine(string)
    IL_0087:  call       void [mscorlib]System.Console::WriteLine()
    IL_008c:  ret
  } // end of method Program::PrintUsageInfo

  .method public hidebysig static void  Main(string[] args) cil managed
  {
    // Code size       295 (0x127)
    .maxstack  3
    .locals init ([0] class [System]System.Text.RegularExpressions.Regex argRexH,
             [1] class [System]System.Text.RegularExpressions.Regex argRexP,
             [2] class [System]System.Text.RegularExpressions.Regex argRexR,
             [3] string[] V_3,
             [4] int32 V_4,
             [5] string s)
    IL_0000:  ldarg.0
    IL_0001:  ldlen
    IL_0002:  brfalse    IL_00be

    IL_0007:  ldarg.0
    IL_0008:  ldlen
    IL_0009:  conv.i4
    IL_000a:  ldc.i4.4
    IL_000b:  bgt        IL_00b2

    IL_0010:  ldstr      "^(/|-)\\\?$"
    IL_0015:  newobj     instance void [System]System.Text.RegularExpressions.Regex::.ctor(string)
    IL_001a:  pop
    IL_001b:  ldstr      "^(/|-)h$"
    IL_0020:  newobj     instance void [System]System.Text.RegularExpressions.Regex::.ctor(string)
    IL_0025:  stloc.0
    IL_0026:  ldstr      "^(/|-)p$"
    IL_002b:  newobj     instance void [System]System.Text.RegularExpressions.Regex::.ctor(string)
    IL_0030:  stloc.1
    IL_0031:  ldstr      "^(/|-)r$"
    IL_0036:  newobj     instance void [System]System.Text.RegularExpressions.Regex::.ctor(string)
    IL_003b:  stloc.2
    IL_003c:  ldarg.0
    IL_003d:  stloc.3
    IL_003e:  ldc.i4.0
    IL_003f:  stloc.s    V_4
    IL_0041:  br.s       IL_00a9

    IL_0043:  ldloc.3
    IL_0044:  ldloc.s    V_4
    IL_0046:  ldelem.ref
    IL_0047:  stloc.s    s
    IL_0049:  ldloc.0
    IL_004a:  ldloc.s    s
    IL_004c:  callvirt   instance string [mscorlib]System.String::ToLower()
    IL_0051:  callvirt   instance bool [System]System.Text.RegularExpressions.Regex::IsMatch(string)
    IL_0056:  brfalse.s  IL_0065

    IL_0058:  call       class HTTPProxyServer.ProxyServer HTTPProxyServer.ProxyServer::get_Server()
    IL_005d:  ldc.i4.1
    IL_005e:  callvirt   instance void HTTPProxyServer.ProxyServer::set_DumpHeaders(bool)
    IL_0063:  br.s       IL_00a3

    IL_0065:  ldloc.1
    IL_0066:  ldloc.s    s
    IL_0068:  callvirt   instance string [mscorlib]System.String::ToLower()
    IL_006d:  callvirt   instance bool [System]System.Text.RegularExpressions.Regex::IsMatch(string)
    IL_0072:  brfalse.s  IL_0081

    IL_0074:  call       class HTTPProxyServer.ProxyServer HTTPProxyServer.ProxyServer::get_Server()
    IL_0079:  ldc.i4.1
    IL_007a:  callvirt   instance void HTTPProxyServer.ProxyServer::set_DumpPostData(bool)
    IL_007f:  br.s       IL_00a3

    IL_0081:  ldloc.2
    IL_0082:  ldloc.s    s
    IL_0084:  callvirt   instance string [mscorlib]System.String::ToLower()
    IL_0089:  callvirt   instance bool [System]System.Text.RegularExpressions.Regex::IsMatch(string)
    IL_008e:  brfalse.s  IL_009d

    IL_0090:  call       class HTTPProxyServer.ProxyServer HTTPProxyServer.ProxyServer::get_Server()
    IL_0095:  ldc.i4.1
    IL_0096:  callvirt   instance void HTTPProxyServer.ProxyServer::set_DumpResponseData(bool)
    IL_009b:  br.s       IL_00a3

    IL_009d:  call       void HTTPProxyServer.Program::PrintUsageInfo()
    IL_00a2:  ret

    IL_00a3:  ldloc.s    V_4
    IL_00a5:  ldc.i4.1
    IL_00a6:  add
    IL_00a7:  stloc.s    V_4
    IL_00a9:  ldloc.s    V_4
    IL_00ab:  ldloc.3
    IL_00ac:  ldlen
    IL_00ad:  conv.i4
    IL_00ae:  blt.s      IL_0043

    IL_00b0:  br.s       IL_00be

    IL_00b2:  ldarg.0
    IL_00b3:  ldlen
    IL_00b4:  conv.i4
    IL_00b5:  ldc.i4.4
    IL_00b6:  ble.s      IL_00be

    IL_00b8:  call       void HTTPProxyServer.Program::PrintUsageInfo()
    IL_00bd:  ret

    IL_00be:  call       class HTTPProxyServer.ProxyServer HTTPProxyServer.ProxyServer::get_Server()
    IL_00c3:  callvirt   instance bool HTTPProxyServer.ProxyServer::Start()
    IL_00c8:  brfalse.s  IL_0116

    IL_00ca:  ldstr      "Server started on {0}:{1}...Press enter key to end"
    IL_00cf:  call       class HTTPProxyServer.ProxyServer HTTPProxyServer.ProxyServer::get_Server()
    IL_00d4:  callvirt   instance class [System]System.Net.IPAddress HTTPProxyServer.ProxyServer::get_ListeningIPInterface()
    IL_00d9:  call       class HTTPProxyServer.ProxyServer HTTPProxyServer.ProxyServer::get_Server()
    IL_00de:  callvirt   instance int32 HTTPProxyServer.ProxyServer::get_ListeningPort()
    IL_00e3:  box        [mscorlib]System.Int32
    IL_00e8:  call       string [mscorlib]System.String::Format(string,
                                                                object,
                                                                object)
    IL_00ed:  call       void [mscorlib]System.Console::WriteLine(string)
    IL_00f2:  call       string [mscorlib]System.Console::ReadLine()
    IL_00f7:  pop
    IL_00f8:  ldstr      "Shutting down"
    IL_00fd:  call       void [mscorlib]System.Console::WriteLine(string)
    IL_0102:  call       class HTTPProxyServer.ProxyServer HTTPProxyServer.ProxyServer::get_Server()
    IL_0107:  callvirt   instance void HTTPProxyServer.ProxyServer::Stop()
    IL_010c:  ldstr      "Server stopped..."
    IL_0111:  call       void [mscorlib]System.Console::WriteLine(string)
    IL_0116:  ldstr      "Press enter to exit"
    IL_011b:  call       void [mscorlib]System.Console::WriteLine(string)
    IL_0120:  call       string [mscorlib]System.Console::ReadLine()
    IL_0125:  pop
    IL_0126:  ret
  } // end of method Program::Main

  .method public hidebysig specialname rtspecialname 
          instance void  .ctor() cil managed
  {
    // Code size       7 (0x7)
    .maxstack  8
    IL_0000:  ldarg.0
    IL_0001:  call       instance void [mscorlib]System.Object::.ctor()
    IL_0006:  ret
  } // end of method Program::.ctor

} // end of class HTTPProxyServer.Program

.class public abstract auto ansi sealed beforefieldinit HTTPProxyServer.ProxyCache
       extends [mscorlib]System.Object
{
  .field private static class [mscorlib]System.Collections.Hashtable _cache
  .field private static object _cacheLockObj
  .field private static object _statsLockObj
  .field private static int32 _hits
  .method public hidebysig static class HTTPProxyServer.CacheEntry 
          GetData(class [System]System.Net.HttpWebRequest 'request') cil managed
  {
    // Code size       162 (0xa2)
    .maxstack  2
    .locals init ([0] class HTTPProxyServer.CacheKey key,
             [1] class HTTPProxyServer.CacheEntry entry,
             [2] valuetype [mscorlib]System.Nullable`1<valuetype [mscorlib]System.DateTime> V_2,
             [3] valuetype [mscorlib]System.DateTime V_3)
    IL_0000:  ldarg.0
    IL_0001:  callvirt   instance class [System]System.Uri [System]System.Net.WebRequest::get_RequestUri()
    IL_0006:  callvirt   instance string [System]System.Uri::get_AbsoluteUri()
    IL_000b:  ldarg.0
    IL_000c:  callvirt   instance string [System]System.Net.HttpWebRequest::get_UserAgent()
    IL_0011:  newobj     instance void HTTPProxyServer.CacheKey::.ctor(string,
                                                                       string)
    IL_0016:  stloc.0
    IL_0017:  ldsfld     class [mscorlib]System.Collections.Hashtable HTTPProxyServer.ProxyCache::_cache
    IL_001c:  ldloc.0
    IL_001d:  callvirt   instance object [mscorlib]System.Collections.Hashtable::get_Item(object)
    IL_0022:  brfalse.s  IL_00a0

    IL_0024:  ldsfld     class [mscorlib]System.Collections.Hashtable HTTPProxyServer.ProxyCache::_cache
    IL_0029:  ldloc.0
    IL_002a:  callvirt   instance object [mscorlib]System.Collections.Hashtable::get_Item(object)
    IL_002f:  castclass  HTTPProxyServer.CacheEntry
    IL_0034:  stloc.1
    IL_0035:  ldloc.1
    IL_0036:  callvirt   instance bool HTTPProxyServer.CacheEntry::get_FlagRemove()
    IL_003b:  brtrue.s   IL_0075

    IL_003d:  ldloc.1
    IL_003e:  callvirt   instance valuetype [mscorlib]System.Nullable`1<valuetype [mscorlib]System.DateTime> HTTPProxyServer.CacheEntry::get_Expires()
    IL_0043:  stloc.2
    IL_0044:  ldloca.s   V_2
    IL_0046:  call       instance bool valuetype [mscorlib]System.Nullable`1<valuetype [mscorlib]System.DateTime>::get_HasValue()
    IL_004b:  brfalse.s  IL_007e

    IL_004d:  ldloc.1
    IL_004e:  callvirt   instance valuetype [mscorlib]System.Nullable`1<valuetype [mscorlib]System.DateTime> HTTPProxyServer.CacheEntry::get_Expires()
    IL_0053:  stloc.2
    IL_0054:  call       valuetype [mscorlib]System.DateTime [mscorlib]System.DateTime::get_Now()
    IL_0059:  stloc.3
    IL_005a:  ldloca.s   V_2
    IL_005c:  call       instance bool valuetype [mscorlib]System.Nullable`1<valuetype [mscorlib]System.DateTime>::get_HasValue()
    IL_0061:  brtrue.s   IL_0066

    IL_0063:  ldc.i4.0
    IL_0064:  br.s       IL_0073

    IL_0066:  ldloca.s   V_2
    IL_0068:  call       instance !0 valuetype [mscorlib]System.Nullable`1<valuetype [mscorlib]System.DateTime>::GetValueOrDefault()
    IL_006d:  ldloc.3
    IL_006e:  call       bool [mscorlib]System.DateTime::op_LessThan(valuetype [mscorlib]System.DateTime,
                                                                     valuetype [mscorlib]System.DateTime)
    IL_0073:  brfalse.s  IL_007e

    IL_0075:  ldloc.1
    IL_0076:  ldc.i4.1
    IL_0077:  callvirt   instance void HTTPProxyServer.CacheEntry::set_FlagRemove(bool)
    IL_007c:  ldnull
    IL_007d:  ret

    IL_007e:  ldsfld     object HTTPProxyServer.ProxyCache::_statsLockObj
    IL_0083:  call       void [mscorlib]System.Threading.Monitor::Enter(object)
    IL_0088:  ldsfld     int32 HTTPProxyServer.ProxyCache::_hits
    IL_008d:  ldc.i4.1
    IL_008e:  add
    IL_008f:  stsfld     int32 HTTPProxyServer.ProxyCache::_hits
    IL_0094:  ldsfld     object HTTPProxyServer.ProxyCache::_statsLockObj
    IL_0099:  call       void [mscorlib]System.Threading.Monitor::Exit(object)
    IL_009e:  ldloc.1
    IL_009f:  ret

    IL_00a0:  ldnull
    IL_00a1:  ret
  } // end of method ProxyCache::GetData

  .method public hidebysig static class HTTPProxyServer.CacheEntry 
          MakeEntry(class [System]System.Net.HttpWebRequest 'request',
                    class [System]System.Net.HttpWebResponse response,
                    class [mscorlib]System.Collections.Generic.List`1<class [mscorlib]System.Tuple`2<string,string>> headers,
                    valuetype [mscorlib]System.Nullable`1<valuetype [mscorlib]System.DateTime> expires) cil managed
  {
    // Code size       113 (0x71)
    .maxstack  3
    .locals init ([0] class HTTPProxyServer.CacheEntry newEntry)
    IL_0000:  newobj     instance void HTTPProxyServer.CacheEntry::.ctor()
    IL_0005:  stloc.0
    IL_0006:  ldloc.0
    IL_0007:  ldarg.3
    IL_0008:  callvirt   instance void HTTPProxyServer.CacheEntry::set_Expires(valuetype [mscorlib]System.Nullable`1<valuetype [mscorlib]System.DateTime>)
    IL_000d:  ldloc.0
    IL_000e:  call       valuetype [mscorlib]System.DateTime [mscorlib]System.DateTime::get_Now()
    IL_0013:  callvirt   instance void HTTPProxyServer.CacheEntry::set_DateStored(valuetype [mscorlib]System.DateTime)
    IL_0018:  ldloc.0
    IL_0019:  ldarg.2
    IL_001a:  callvirt   instance void HTTPProxyServer.CacheEntry::set_Headers(class [mscorlib]System.Collections.Generic.List`1<class [mscorlib]System.Tuple`2<string,string>>)
    IL_001f:  ldloc.0
    IL_0020:  ldarg.0
    IL_0021:  callvirt   instance class [System]System.Uri [System]System.Net.WebRequest::get_RequestUri()
    IL_0026:  callvirt   instance string [System]System.Uri::get_AbsoluteUri()
    IL_002b:  ldarg.0
    IL_002c:  callvirt   instance string [System]System.Net.HttpWebRequest::get_UserAgent()
    IL_0031:  newobj     instance void HTTPProxyServer.CacheKey::.ctor(string,
                                                                       string)
    IL_0036:  callvirt   instance void HTTPProxyServer.CacheEntry::set_Key(class HTTPProxyServer.CacheKey)
    IL_003b:  ldloc.0
    IL_003c:  ldarg.1
    IL_003d:  callvirt   instance valuetype [System]System.Net.HttpStatusCode [System]System.Net.HttpWebResponse::get_StatusCode()
    IL_0042:  callvirt   instance void HTTPProxyServer.CacheEntry::set_StatusCode(valuetype [System]System.Net.HttpStatusCode)
    IL_0047:  ldloc.0
    IL_0048:  ldarg.1
    IL_0049:  callvirt   instance string [System]System.Net.HttpWebResponse::get_StatusDescription()
    IL_004e:  callvirt   instance void HTTPProxyServer.CacheEntry::set_StatusDescription(string)
    IL_0053:  ldarg.1
    IL_0054:  callvirt   instance int64 [System]System.Net.WebResponse::get_ContentLength()
    IL_0059:  ldc.i4.0
    IL_005a:  conv.i8
    IL_005b:  ble.s      IL_006f

    IL_005d:  ldloc.0
    IL_005e:  ldarg.1
    IL_005f:  callvirt   instance int64 [System]System.Net.WebResponse::get_ContentLength()
    IL_0064:  conv.ovf.i
    IL_0065:  newarr     [mscorlib]System.Byte
    IL_006a:  callvirt   instance void HTTPProxyServer.CacheEntry::set_ResponseBytes(uint8[])
    IL_006f:  ldloc.0
    IL_0070:  ret
  } // end of method ProxyCache::MakeEntry

  .method public hidebysig static void  AddData(class HTTPProxyServer.CacheEntry entry) cil managed
  {
    // Code size       56 (0x38)
    .maxstack  8
    IL_0000:  ldsfld     object HTTPProxyServer.ProxyCache::_cacheLockObj
    IL_0005:  call       void [mscorlib]System.Threading.Monitor::Enter(object)
    IL_000a:  ldsfld     class [mscorlib]System.Collections.Hashtable HTTPProxyServer.ProxyCache::_cache
    IL_000f:  ldarg.0
    IL_0010:  callvirt   instance class HTTPProxyServer.CacheKey HTTPProxyServer.CacheEntry::get_Key()
    IL_0015:  callvirt   instance bool [mscorlib]System.Collections.Hashtable::Contains(object)
    IL_001a:  brtrue.s   IL_002d

    IL_001c:  ldsfld     class [mscorlib]System.Collections.Hashtable HTTPProxyServer.ProxyCache::_cache
    IL_0021:  ldarg.0
    IL_0022:  callvirt   instance class HTTPProxyServer.CacheKey HTTPProxyServer.CacheEntry::get_Key()
    IL_0027:  ldarg.0
    IL_0028:  callvirt   instance void [mscorlib]System.Collections.Hashtable::Add(object,
                                                                                   object)
    IL_002d:  ldsfld     object HTTPProxyServer.ProxyCache::_cacheLockObj
    IL_0032:  call       void [mscorlib]System.Threading.Monitor::Exit(object)
    IL_0037:  ret
  } // end of method ProxyCache::AddData

  .method public hidebysig static bool  CanCache(class [System]System.Net.WebHeaderCollection headers,
                                                 valuetype [mscorlib]System.Nullable`1<valuetype [mscorlib]System.DateTime>& expires) cil managed
  {
    // Code size       308 (0x134)
    .maxstack  2
    .locals init ([0] string[] V_0,
             [1] int32 V_1,
             [2] string s,
             [3] string 'value',
             [4] valuetype [mscorlib]System.DateTime dExpire,
             [5] string V_5,
             [6] int32 seconds,
             [7] valuetype [mscorlib]System.DateTime d,
             [8] valuetype [mscorlib]System.DateTime V_8)
    IL_0000:  ldarg.0
    IL_0001:  callvirt   instance string[] [System]System.Collections.Specialized.NameValueCollection::get_AllKeys()
    IL_0006:  stloc.0
    IL_0007:  ldc.i4.0
    IL_0008:  stloc.1
    IL_0009:  br         IL_0129

    IL_000e:  ldloc.0
    IL_000f:  ldloc.1
    IL_0010:  ldelem.ref
    IL_0011:  stloc.2
    IL_0012:  ldarg.0
    IL_0013:  ldloc.2
    IL_0014:  callvirt   instance string [System]System.Collections.Specialized.NameValueCollection::get_Item(string)
    IL_0019:  callvirt   instance string [mscorlib]System.String::ToLower()
    IL_001e:  stloc.3
    IL_001f:  ldloc.2
    IL_0020:  callvirt   instance string [mscorlib]System.String::ToLower()
    IL_0025:  stloc.s    V_5
    IL_0027:  ldloc.s    V_5
    IL_0029:  ldstr      "cache-control"
    IL_002e:  call       bool [mscorlib]System.String::op_Equality(string,
                                                                   string)
    IL_0033:  brtrue.s   IL_005c

    IL_0035:  ldloc.s    V_5
    IL_0037:  ldstr      "pragma"
    IL_003c:  call       bool [mscorlib]System.String::op_Equality(string,
                                                                   string)
    IL_0041:  brtrue     IL_00e8

    IL_0046:  ldloc.s    V_5
    IL_0048:  ldstr      "expires"
    IL_004d:  call       bool [mscorlib]System.String::op_Equality(string,
                                                                   string)
    IL_0052:  brtrue     IL_00f7

    IL_0057:  br         IL_0125

    IL_005c:  ldloc.3
    IL_005d:  ldstr      "max-age"
    IL_0062:  callvirt   instance bool [mscorlib]System.String::Contains(string)
    IL_0067:  brfalse.s  IL_00b0

    IL_0069:  ldloc.3
    IL_006a:  ldloca.s   seconds
    IL_006c:  call       bool [mscorlib]System.Int32::TryParse(string,
                                                               int32&)
    IL_0071:  brfalse.s  IL_00b0

    IL_0073:  ldloc.s    seconds
    IL_0075:  brtrue.s   IL_0079

    IL_0077:  ldc.i4.0
    IL_0078:  ret

    IL_0079:  call       valuetype [mscorlib]System.DateTime [mscorlib]System.DateTime::get_Now()
    IL_007e:  stloc.s    V_8
    IL_0080:  ldloca.s   V_8
    IL_0082:  ldloc.s    seconds
    IL_0084:  conv.r8
    IL_0085:  call       instance valuetype [mscorlib]System.DateTime [mscorlib]System.DateTime::AddSeconds(float64)
    IL_008a:  stloc.s    d
    IL_008c:  ldarg.1
    IL_008d:  call       instance bool valuetype [mscorlib]System.Nullable`1<valuetype [mscorlib]System.DateTime>::get_HasValue()
    IL_0092:  brfalse.s  IL_00a3

    IL_0094:  ldarg.1
    IL_0095:  call       instance !0 valuetype [mscorlib]System.Nullable`1<valuetype [mscorlib]System.DateTime>::get_Value()
    IL_009a:  ldloc.s    d
    IL_009c:  call       bool [mscorlib]System.DateTime::op_LessThan(valuetype [mscorlib]System.DateTime,
                                                                     valuetype [mscorlib]System.DateTime)
    IL_00a1:  brfalse.s  IL_00b0

    IL_00a3:  ldarg.1
    IL_00a4:  ldloc.s    d
    IL_00a6:  newobj     instance void valuetype [mscorlib]System.Nullable`1<valuetype [mscorlib]System.DateTime>::.ctor(!0)
    IL_00ab:  stobj      valuetype [mscorlib]System.Nullable`1<valuetype [mscorlib]System.DateTime>
    IL_00b0:  ldloc.3
    IL_00b1:  ldstr      "private"
    IL_00b6:  callvirt   instance bool [mscorlib]System.String::Contains(string)
    IL_00bb:  brtrue.s   IL_00ca

    IL_00bd:  ldloc.3
    IL_00be:  ldstr      "no-cache"
    IL_00c3:  callvirt   instance bool [mscorlib]System.String::Contains(string)
    IL_00c8:  brfalse.s  IL_00cc

    IL_00ca:  ldc.i4.0
    IL_00cb:  ret

    IL_00cc:  ldloc.3
    IL_00cd:  ldstr      "public"
    IL_00d2:  callvirt   instance bool [mscorlib]System.String::Contains(string)
    IL_00d7:  brtrue.s   IL_00e6

    IL_00d9:  ldloc.3
    IL_00da:  ldstr      "no-store"
    IL_00df:  callvirt   instance bool [mscorlib]System.String::Contains(string)
    IL_00e4:  brfalse.s  IL_0125

    IL_00e6:  ldc.i4.1
    IL_00e7:  ret

    IL_00e8:  ldloc.3
    IL_00e9:  ldstr      "no-cache"
    IL_00ee:  call       bool [mscorlib]System.String::op_Equality(string,
                                                                   string)
    IL_00f3:  brfalse.s  IL_0125

    IL_00f5:  ldc.i4.0
    IL_00f6:  ret

    IL_00f7:  ldloc.3
    IL_00f8:  ldloca.s   dExpire
    IL_00fa:  call       bool [mscorlib]System.DateTime::TryParse(string,
                                                                  valuetype [mscorlib]System.DateTime&)
    IL_00ff:  brfalse.s  IL_0125

    IL_0101:  ldarg.1
    IL_0102:  call       instance bool valuetype [mscorlib]System.Nullable`1<valuetype [mscorlib]System.DateTime>::get_HasValue()
    IL_0107:  brfalse.s  IL_0118

    IL_0109:  ldarg.1
    IL_010a:  call       instance !0 valuetype [mscorlib]System.Nullable`1<valuetype [mscorlib]System.DateTime>::get_Value()
    IL_010f:  ldloc.s    dExpire
    IL_0111:  call       bool [mscorlib]System.DateTime::op_LessThan(valuetype [mscorlib]System.DateTime,
                                                                     valuetype [mscorlib]System.DateTime)
    IL_0116:  brfalse.s  IL_0125

    IL_0118:  ldarg.1
    IL_0119:  ldloc.s    dExpire
    IL_011b:  newobj     instance void valuetype [mscorlib]System.Nullable`1<valuetype [mscorlib]System.DateTime>::.ctor(!0)
    IL_0120:  stobj      valuetype [mscorlib]System.Nullable`1<valuetype [mscorlib]System.DateTime>
    IL_0125:  ldloc.1
    IL_0126:  ldc.i4.1
    IL_0127:  add
    IL_0128:  stloc.1
    IL_0129:  ldloc.1
    IL_012a:  ldloc.0
    IL_012b:  ldlen
    IL_012c:  conv.i4
    IL_012d:  blt        IL_000e

    IL_0132:  ldc.i4.1
    IL_0133:  ret
  } // end of method ProxyCache::CanCache

  .method public hidebysig static void  CacheMaintenance() cil managed
  {
    // Code size       256 (0x100)
    .maxstack  3
    .locals init ([0] class [mscorlib]System.Collections.Generic.List`1<class HTTPProxyServer.CacheKey> keysToRemove,
             [1] class [mscorlib]System.Collections.IEnumerator V_1,
             [2] class HTTPProxyServer.CacheKey key,
             [3] class HTTPProxyServer.CacheEntry entry,
             [4] valuetype [mscorlib]System.Nullable`1<valuetype [mscorlib]System.DateTime> V_4,
             [5] valuetype [mscorlib]System.DateTime V_5,
             [6] class [mscorlib]System.IDisposable V_6,
             [7] valuetype [mscorlib]System.Collections.Generic.List`1/Enumerator<class HTTPProxyServer.CacheKey> V_7,
             [8] class HTTPProxyServer.CacheKey V_8)
    .try
    {
      IL_0000:  ldc.i4     0x7530
      IL_0005:  call       void [mscorlib]System.Threading.Thread::Sleep(int32)
      IL_000a:  newobj     instance void class [mscorlib]System.Collections.Generic.List`1<class HTTPProxyServer.CacheKey>::.ctor()
      IL_000f:  stloc.0
      IL_0010:  ldsfld     class [mscorlib]System.Collections.Hashtable HTTPProxyServer.ProxyCache::_cache
      IL_0015:  callvirt   instance class [mscorlib]System.Collections.ICollection [mscorlib]System.Collections.Hashtable::get_Keys()
      IL_001a:  callvirt   instance class [mscorlib]System.Collections.IEnumerator [mscorlib]System.Collections.IEnumerable::GetEnumerator()
      IL_001f:  stloc.1
      .try
      {
        IL_0020:  br.s       IL_0079

        IL_0022:  ldloc.1
        IL_0023:  callvirt   instance object [mscorlib]System.Collections.IEnumerator::get_Current()
        IL_0028:  castclass  HTTPProxyServer.CacheKey
        IL_002d:  stloc.2
        IL_002e:  ldsfld     class [mscorlib]System.Collections.Hashtable HTTPProxyServer.ProxyCache::_cache
        IL_0033:  ldloc.2
        IL_0034:  callvirt   instance object [mscorlib]System.Collections.Hashtable::get_Item(object)
        IL_0039:  castclass  HTTPProxyServer.CacheEntry
        IL_003e:  stloc.3
        IL_003f:  ldloc.3
        IL_0040:  callvirt   instance bool HTTPProxyServer.CacheEntry::get_FlagRemove()
        IL_0045:  brtrue.s   IL_0072

        IL_0047:  ldloc.3
        IL_0048:  callvirt   instance valuetype [mscorlib]System.Nullable`1<valuetype [mscorlib]System.DateTime> HTTPProxyServer.CacheEntry::get_Expires()
        IL_004d:  stloc.s    V_4
        IL_004f:  call       valuetype [mscorlib]System.DateTime [mscorlib]System.DateTime::get_Now()
        IL_0054:  stloc.s    V_5
        IL_0056:  ldloca.s   V_4
        IL_0058:  call       instance bool valuetype [mscorlib]System.Nullable`1<valuetype [mscorlib]System.DateTime>::get_HasValue()
        IL_005d:  brtrue.s   IL_0062

        IL_005f:  ldc.i4.0
        IL_0060:  br.s       IL_0070

        IL_0062:  ldloca.s   V_4
        IL_0064:  call       instance !0 valuetype [mscorlib]System.Nullable`1<valuetype [mscorlib]System.DateTime>::GetValueOrDefault()
        IL_0069:  ldloc.s    V_5
        IL_006b:  call       bool [mscorlib]System.DateTime::op_LessThan(valuetype [mscorlib]System.DateTime,
                                                                         valuetype [mscorlib]System.DateTime)
        IL_0070:  brfalse.s  IL_0079

        IL_0072:  ldloc.0
        IL_0073:  ldloc.2
        IL_0074:  callvirt   instance void class [mscorlib]System.Collections.Generic.List`1<class HTTPProxyServer.CacheKey>::Add(!0)
        IL_0079:  ldloc.1
        IL_007a:  callvirt   instance bool [mscorlib]System.Collections.IEnumerator::MoveNext()
        IL_007f:  brtrue.s   IL_0022

        IL_0081:  leave.s    IL_0097

      }  // end .try
      finally
      {
        IL_0083:  ldloc.1
        IL_0084:  isinst     [mscorlib]System.IDisposable
        IL_0089:  stloc.s    V_6
        IL_008b:  ldloc.s    V_6
        IL_008d:  brfalse.s  IL_0096

        IL_008f:  ldloc.s    V_6
        IL_0091:  callvirt   instance void [mscorlib]System.IDisposable::Dispose()
        IL_0096:  endfinally
      }  // end handler
      IL_0097:  ldloc.0
      IL_0098:  callvirt   instance valuetype [mscorlib]System.Collections.Generic.List`1/Enumerator<!0> class [mscorlib]System.Collections.Generic.List`1<class HTTPProxyServer.CacheKey>::GetEnumerator()
      IL_009d:  stloc.s    V_7
      .try
      {
        IL_009f:  br.s       IL_00b6

        IL_00a1:  ldloca.s   V_7
        IL_00a3:  call       instance !0 valuetype [mscorlib]System.Collections.Generic.List`1/Enumerator<class HTTPProxyServer.CacheKey>::get_Current()
        IL_00a8:  stloc.s    V_8
        IL_00aa:  ldsfld     class [mscorlib]System.Collections.Hashtable HTTPProxyServer.ProxyCache::_cache
        IL_00af:  ldloc.s    V_8
        IL_00b1:  callvirt   instance void [mscorlib]System.Collections.Hashtable::Remove(object)
        IL_00b6:  ldloca.s   V_7
        IL_00b8:  call       instance bool valuetype [mscorlib]System.Collections.Generic.List`1/Enumerator<class HTTPProxyServer.CacheKey>::MoveNext()
        IL_00bd:  brtrue.s   IL_00a1

        IL_00bf:  leave.s    IL_00cf

      }  // end .try
      finally
      {
        IL_00c1:  ldloca.s   V_7
        IL_00c3:  constrained. valuetype [mscorlib]System.Collections.Generic.List`1/Enumerator<class HTTPProxyServer.CacheKey>
        IL_00c9:  callvirt   instance void [mscorlib]System.IDisposable::Dispose()
        IL_00ce:  endfinally
      }  // end handler
      IL_00cf:  ldstr      "Cache maintenance complete.  Number of items store"
      + "d={0} Number of cache hits={1} "
      IL_00d4:  ldsfld     class [mscorlib]System.Collections.Hashtable HTTPProxyServer.ProxyCache::_cache
      IL_00d9:  callvirt   instance int32 [mscorlib]System.Collections.Hashtable::get_Count()
      IL_00de:  box        [mscorlib]System.Int32
      IL_00e3:  ldsfld     int32 HTTPProxyServer.ProxyCache::_hits
      IL_00e8:  box        [mscorlib]System.Int32
      IL_00ed:  call       string [mscorlib]System.String::Format(string,
                                                                  object,
                                                                  object)
      IL_00f2:  call       void [mscorlib]System.Console::WriteLine(string)
      IL_00f7:  br         IL_0000

    }  // end .try
    catch [mscorlib]System.Threading.ThreadAbortException 
    {
      IL_00fc:  pop
      IL_00fd:  leave.s    IL_00ff

    }  // end handler
    IL_00ff:  ret
  } // end of method ProxyCache::CacheMaintenance

  .method private hidebysig specialname rtspecialname static 
          void  .cctor() cil managed
  {
    // Code size       31 (0x1f)
    .maxstack  8
    IL_0000:  newobj     instance void [mscorlib]System.Collections.Hashtable::.ctor()
    IL_0005:  stsfld     class [mscorlib]System.Collections.Hashtable HTTPProxyServer.ProxyCache::_cache
    IL_000a:  newobj     instance void [mscorlib]System.Object::.ctor()
    IL_000f:  stsfld     object HTTPProxyServer.ProxyCache::_cacheLockObj
    IL_0014:  newobj     instance void [mscorlib]System.Object::.ctor()
    IL_0019:  stsfld     object HTTPProxyServer.ProxyCache::_statsLockObj
    IL_001e:  ret
  } // end of method ProxyCache::.cctor

} // end of class HTTPProxyServer.ProxyCache

.class public auto ansi sealed beforefieldinit HTTPProxyServer.ProxyServer
       extends [mscorlib]System.Object
{
  .class auto ansi serializable sealed nested private beforefieldinit '<>c'
         extends [mscorlib]System.Object
  {
    .custom instance void [mscorlib]System.Runtime.CompilerServices.CompilerGeneratedAttribute::.ctor() = ( 01 00 00 00 ) 
    .field public static initonly class HTTPProxyServer.ProxyServer/'<>c' '<>9'
    .field public static class [System]System.Net.Security.RemoteCertificateValidationCallback '<>9__19_0'
    .method private hidebysig specialname rtspecialname static 
            void  .cctor() cil managed
    {
      // Code size       11 (0xb)
      .maxstack  8
      IL_0000:  newobj     instance void HTTPProxyServer.ProxyServer/'<>c'::.ctor()
      IL_0005:  stsfld     class HTTPProxyServer.ProxyServer/'<>c' HTTPProxyServer.ProxyServer/'<>c'::'<>9'
      IL_000a:  ret
    } // end of method '<>c'::.cctor

    .method public hidebysig specialname rtspecialname 
            instance void  .ctor() cil managed
    {
      // Code size       7 (0x7)
      .maxstack  8
      IL_0000:  ldarg.0
      IL_0001:  call       instance void [mscorlib]System.Object::.ctor()
      IL_0006:  ret
    } // end of method '<>c'::.ctor

    .method assembly hidebysig instance bool 
            '<.ctor>b__19_0'(object '<p0>',
                             class [mscorlib]System.Security.Cryptography.X509Certificates.X509Certificate '<p1>',
                             class [System]System.Security.Cryptography.X509Certificates.X509Chain '<p2>',
                             valuetype [System]System.Net.Security.SslPolicyErrors '<p3>') cil managed
    {
      // Code size       2 (0x2)
      .maxstack  8
      IL_0000:  ldc.i4.1
      IL_0001:  ret
    } // end of method '<>c'::'<.ctor>b__19_0'

  } // end of class '<>c'

  .field private static initonly class HTTPProxyServer.ProxyServer _server
  .field private static initonly int32 BUFFER_SIZE
  .field private static initonly char[] semiSplit
  .field private static initonly char[] equalSplit
  .field private static initonly string[] colonSpaceSplit
  .field private static initonly char[] spaceSplit
  .field private static initonly char[] commaSplit
  .field private static initonly char[] colonSplit
  .field private static initonly class [System]System.Text.RegularExpressions.Regex cookieSplitRegEx
  .field private static class [System]System.Security.Cryptography.X509Certificates.X509Certificate2 _certificate
  .field private static class [System]System.Security.Cryptography.X509Certificates.X509Certificate2 _certCA
  .field private static object _outputLockObj
  .field private class [System]System.Net.Sockets.TcpListener _listener
  .field private class [mscorlib]System.Threading.Thread _listenerThread
  .field private class [mscorlib]System.Threading.Thread _cacheMaintenanceThread
  .field private bool '<DumpHeaders>k__BackingField'
  .custom instance void [mscorlib]System.Runtime.CompilerServices.CompilerGeneratedAttribute::.ctor() = ( 01 00 00 00 ) 
  .field private bool '<DumpPostData>k__BackingField'
  .custom instance void [mscorlib]System.Runtime.CompilerServices.CompilerGeneratedAttribute::.ctor() = ( 01 00 00 00 ) 
  .field private bool '<DumpResponseData>k__BackingField'
  .custom instance void [mscorlib]System.Runtime.CompilerServices.CompilerGeneratedAttribute::.ctor() = ( 01 00 00 00 ) 
  .method public hidebysig specialname instance class [System]System.Net.IPAddress 
          get_ListeningIPInterface() cil managed
  {
    // Code size       48 (0x30)
    .maxstack  2
    .locals init ([0] class [System]System.Net.IPAddress addr)
    IL_0000:  ldsfld     class [System]System.Net.IPAddress [System]System.Net.IPAddress::Loopback
    IL_0005:  stloc.0
    IL_0006:  call       class [System]System.Collections.Specialized.NameValueCollection [System.Configuration]System.Configuration.ConfigurationManager::get_AppSettings()
    IL_000b:  ldstr      "ListeningIPInterface"
    IL_0010:  callvirt   instance string [System]System.Collections.Specialized.NameValueCollection::get_Item(string)
    IL_0015:  brfalse.s  IL_002e

    IL_0017:  call       class [System]System.Collections.Specialized.NameValueCollection [System.Configuration]System.Configuration.ConfigurationManager::get_AppSettings()
    IL_001c:  ldstr      "ListeningIPInterface"
    IL_0021:  callvirt   instance string [System]System.Collections.Specialized.NameValueCollection::get_Item(string)
    IL_0026:  ldloca.s   addr
    IL_0028:  call       bool [System]System.Net.IPAddress::TryParse(string,
                                                                     class [System]System.Net.IPAddress&)
    IL_002d:  pop
    IL_002e:  ldloc.0
    IL_002f:  ret
  } // end of method ProxyServer::get_ListeningIPInterface

  .method public hidebysig specialname instance int32 
          get_ListeningPort() cil managed
  {
    // Code size       48 (0x30)
    .maxstack  2
    .locals init ([0] int32 port)
    IL_0000:  ldc.i4     0x1f91
    IL_0005:  stloc.0
    IL_0006:  call       class [System]System.Collections.Specialized.NameValueCollection [System.Configuration]System.Configuration.ConfigurationManager::get_AppSettings()
    IL_000b:  ldstr      "ListeningPort"
    IL_0010:  callvirt   instance string [System]System.Collections.Specialized.NameValueCollection::get_Item(string)
    IL_0015:  brfalse.s  IL_002e

    IL_0017:  call       class [System]System.Collections.Specialized.NameValueCollection [System.Configuration]System.Configuration.ConfigurationManager::get_AppSettings()
    IL_001c:  ldstr      "ListeningPort"
    IL_0021:  callvirt   instance string [System]System.Collections.Specialized.NameValueCollection::get_Item(string)
    IL_0026:  ldloca.s   port
    IL_0028:  call       bool [mscorlib]System.Int32::TryParse(string,
                                                               int32&)
    IL_002d:  pop
    IL_002e:  ldloc.0
    IL_002f:  ret
  } // end of method ProxyServer::get_ListeningPort

  .method private hidebysig specialname rtspecialname 
          instance void  .ctor() cil managed
  {
    // Code size       66 (0x42)
    .maxstack  3
    IL_0000:  ldarg.0
    IL_0001:  call       instance void [mscorlib]System.Object::.ctor()
    IL_0006:  ldarg.0
    IL_0007:  ldarg.0
    IL_0008:  call       instance class [System]System.Net.IPAddress HTTPProxyServer.ProxyServer::get_ListeningIPInterface()
    IL_000d:  ldarg.0
    IL_000e:  call       instance int32 HTTPProxyServer.ProxyServer::get_ListeningPort()
    IL_0013:  newobj     instance void [System]System.Net.Sockets.TcpListener::.ctor(class [System]System.Net.IPAddress,
                                                                                     int32)
    IL_0018:  stfld      class [System]System.Net.Sockets.TcpListener HTTPProxyServer.ProxyServer::_listener
    IL_001d:  ldsfld     class [System]System.Net.Security.RemoteCertificateValidationCallback HTTPProxyServer.ProxyServer/'<>c'::'<>9__19_0'
    IL_0022:  dup
    IL_0023:  brtrue.s   IL_003c

    IL_0025:  pop
    IL_0026:  ldsfld     class HTTPProxyServer.ProxyServer/'<>c' HTTPProxyServer.ProxyServer/'<>c'::'<>9'
    IL_002b:  ldftn      instance bool HTTPProxyServer.ProxyServer/'<>c'::'<.ctor>b__19_0'(object,
                                                                                           class [mscorlib]System.Security.Cryptography.X509Certificates.X509Certificate,
                                                                                           class [System]System.Security.Cryptography.X509Certificates.X509Chain,
                                                                                           valuetype [System]System.Net.Security.SslPolicyErrors)
    IL_0031:  newobj     instance void [System]System.Net.Security.RemoteCertificateValidationCallback::.ctor(object,
                                                                                                              native int)
    IL_0036:  dup
    IL_0037:  stsfld     class [System]System.Net.Security.RemoteCertificateValidationCallback HTTPProxyServer.ProxyServer/'<>c'::'<>9__19_0'
    IL_003c:  call       void [System]System.Net.ServicePointManager::set_ServerCertificateValidationCallback(class [System]System.Net.Security.RemoteCertificateValidationCallback)
    IL_0041:  ret
  } // end of method ProxyServer::.ctor

  .method public hidebysig specialname instance bool 
          get_DumpHeaders() cil managed
  {
    .custom instance void [mscorlib]System.Runtime.CompilerServices.CompilerGeneratedAttribute::.ctor() = ( 01 00 00 00 ) 
    // Code size       7 (0x7)
    .maxstack  8
    IL_0000:  ldarg.0
    IL_0001:  ldfld      bool HTTPProxyServer.ProxyServer::'<DumpHeaders>k__BackingField'
    IL_0006:  ret
  } // end of method ProxyServer::get_DumpHeaders

  .method public hidebysig specialname instance void 
          set_DumpHeaders(bool 'value') cil managed
  {
    .custom instance void [mscorlib]System.Runtime.CompilerServices.CompilerGeneratedAttribute::.ctor() = ( 01 00 00 00 ) 
    // Code size       8 (0x8)
    .maxstack  8
    IL_0000:  ldarg.0
    IL_0001:  ldarg.1
    IL_0002:  stfld      bool HTTPProxyServer.ProxyServer::'<DumpHeaders>k__BackingField'
    IL_0007:  ret
  } // end of method ProxyServer::set_DumpHeaders

  .method public hidebysig specialname instance bool 
          get_DumpPostData() cil managed
  {
    .custom instance void [mscorlib]System.Runtime.CompilerServices.CompilerGeneratedAttribute::.ctor() = ( 01 00 00 00 ) 
    // Code size       7 (0x7)
    .maxstack  8
    IL_0000:  ldarg.0
    IL_0001:  ldfld      bool HTTPProxyServer.ProxyServer::'<DumpPostData>k__BackingField'
    IL_0006:  ret
  } // end of method ProxyServer::get_DumpPostData

  .method public hidebysig specialname instance void 
          set_DumpPostData(bool 'value') cil managed
  {
    .custom instance void [mscorlib]System.Runtime.CompilerServices.CompilerGeneratedAttribute::.ctor() = ( 01 00 00 00 ) 
    // Code size       8 (0x8)
    .maxstack  8
    IL_0000:  ldarg.0
    IL_0001:  ldarg.1
    IL_0002:  stfld      bool HTTPProxyServer.ProxyServer::'<DumpPostData>k__BackingField'
    IL_0007:  ret
  } // end of method ProxyServer::set_DumpPostData

  .method public hidebysig specialname instance bool 
          get_DumpResponseData() cil managed
  {
    .custom instance void [mscorlib]System.Runtime.CompilerServices.CompilerGeneratedAttribute::.ctor() = ( 01 00 00 00 ) 
    // Code size       7 (0x7)
    .maxstack  8
    IL_0000:  ldarg.0
    IL_0001:  ldfld      bool HTTPProxyServer.ProxyServer::'<DumpResponseData>k__BackingField'
    IL_0006:  ret
  } // end of method ProxyServer::get_DumpResponseData

  .method public hidebysig specialname instance void 
          set_DumpResponseData(bool 'value') cil managed
  {
    .custom instance void [mscorlib]System.Runtime.CompilerServices.CompilerGeneratedAttribute::.ctor() = ( 01 00 00 00 ) 
    // Code size       8 (0x8)
    .maxstack  8
    IL_0000:  ldarg.0
    IL_0001:  ldarg.1
    IL_0002:  stfld      bool HTTPProxyServer.ProxyServer::'<DumpResponseData>k__BackingField'
    IL_0007:  ret
  } // end of method ProxyServer::set_DumpResponseData

  .method public hidebysig specialname static 
          class HTTPProxyServer.ProxyServer 
          get_Server() cil managed
  {
    // Code size       6 (0x6)
    .maxstack  8
    IL_0000:  ldsfld     class HTTPProxyServer.ProxyServer HTTPProxyServer.ProxyServer::_server
    IL_0005:  ret
  } // end of method ProxyServer::get_Server

  .method public hidebysig instance bool 
          Start() cil managed
  {
    // Code size       105 (0x69)
    .maxstack  3
    .locals init ([0] bool V_0)
    .try
    {
      IL_0000:  ldarg.0
      IL_0001:  ldfld      class [System]System.Net.Sockets.TcpListener HTTPProxyServer.ProxyServer::_listener
      IL_0006:  callvirt   instance void [System]System.Net.Sockets.TcpListener::Start()
      IL_000b:  leave.s    IL_001b

    }  // end .try
    catch [mscorlib]System.Exception 
    {
      IL_000d:  callvirt   instance string [mscorlib]System.Exception::get_Message()
      IL_0012:  call       void [mscorlib]System.Console::WriteLine(string)
      IL_0017:  ldc.i4.0
      IL_0018:  stloc.0
      IL_0019:  leave.s    IL_0067

    }  // end handler
    IL_001b:  ldarg.0
    IL_001c:  ldnull
    IL_001d:  ldftn      void HTTPProxyServer.ProxyServer::Listen(object)
    IL_0023:  newobj     instance void [mscorlib]System.Threading.ParameterizedThreadStart::.ctor(object,
                                                                                                  native int)
    IL_0028:  newobj     instance void [mscorlib]System.Threading.Thread::.ctor(class [mscorlib]System.Threading.ParameterizedThreadStart)
    IL_002d:  stfld      class [mscorlib]System.Threading.Thread HTTPProxyServer.ProxyServer::_listenerThread
    IL_0032:  ldarg.0
    IL_0033:  ldnull
    IL_0034:  ldftn      void HTTPProxyServer.ProxyCache::CacheMaintenance()
    IL_003a:  newobj     instance void [mscorlib]System.Threading.ThreadStart::.ctor(object,
                                                                                     native int)
    IL_003f:  newobj     instance void [mscorlib]System.Threading.Thread::.ctor(class [mscorlib]System.Threading.ThreadStart)
    IL_0044:  stfld      class [mscorlib]System.Threading.Thread HTTPProxyServer.ProxyServer::_cacheMaintenanceThread
    IL_0049:  ldarg.0
    IL_004a:  ldfld      class [mscorlib]System.Threading.Thread HTTPProxyServer.ProxyServer::_listenerThread
    IL_004f:  ldarg.0
    IL_0050:  ldfld      class [System]System.Net.Sockets.TcpListener HTTPProxyServer.ProxyServer::_listener
    IL_0055:  callvirt   instance void [mscorlib]System.Threading.Thread::Start(object)
    IL_005a:  ldarg.0
    IL_005b:  ldfld      class [mscorlib]System.Threading.Thread HTTPProxyServer.ProxyServer::_cacheMaintenanceThread
    IL_0060:  callvirt   instance void [mscorlib]System.Threading.Thread::Start()
    IL_0065:  ldc.i4.1
    IL_0066:  ret

    IL_0067:  ldloc.0
    IL_0068:  ret
  } // end of method ProxyServer::Start

  .method public hidebysig instance void 
          Stop() cil managed
  {
    // Code size       56 (0x38)
    .maxstack  8
    IL_0000:  ldarg.0
    IL_0001:  ldfld      class [System]System.Net.Sockets.TcpListener HTTPProxyServer.ProxyServer::_listener
    IL_0006:  callvirt   instance void [System]System.Net.Sockets.TcpListener::Stop()
    IL_000b:  ldarg.0
    IL_000c:  ldfld      class [mscorlib]System.Threading.Thread HTTPProxyServer.ProxyServer::_listenerThread
    IL_0011:  callvirt   instance void [mscorlib]System.Threading.Thread::Abort()
    IL_0016:  ldarg.0
    IL_0017:  ldfld      class [mscorlib]System.Threading.Thread HTTPProxyServer.ProxyServer::_cacheMaintenanceThread
    IL_001c:  callvirt   instance void [mscorlib]System.Threading.Thread::Abort()
    IL_0021:  ldarg.0
    IL_0022:  ldfld      class [mscorlib]System.Threading.Thread HTTPProxyServer.ProxyServer::_listenerThread
    IL_0027:  callvirt   instance void [mscorlib]System.Threading.Thread::Join()
    IL_002c:  ldarg.0
    IL_002d:  ldfld      class [mscorlib]System.Threading.Thread HTTPProxyServer.ProxyServer::_listenerThread
    IL_0032:  callvirt   instance void [mscorlib]System.Threading.Thread::Join()
    IL_0037:  ret
  } // end of method ProxyServer::Stop

  .method private hidebysig static void  Listen(object obj) cil managed
  {
    // Code size       43 (0x2b)
    .maxstack  2
    .locals init ([0] class [System]System.Net.Sockets.TcpListener listener,
             [1] class [System]System.Net.Sockets.TcpClient client)
    IL_0000:  ldarg.0
    IL_0001:  castclass  [System]System.Net.Sockets.TcpListener
    IL_0006:  stloc.0
    .try
    {
      IL_0007:  ldloc.0
      IL_0008:  callvirt   instance class [System]System.Net.Sockets.TcpClient [System]System.Net.Sockets.TcpListener::AcceptTcpClient()
      IL_000d:  stloc.1
      IL_000e:  ldnull
      IL_000f:  ldftn      void HTTPProxyServer.ProxyServer::ProcessClient(object)
      IL_0015:  newobj     instance void [mscorlib]System.Threading.WaitCallback::.ctor(object,
                                                                                        native int)
      IL_001a:  ldloc.1
      IL_001b:  call       bool [mscorlib]System.Threading.ThreadPool::QueueUserWorkItem(class [mscorlib]System.Threading.WaitCallback,
                                                                                         object)
      IL_0020:  brfalse.s  IL_000e

      IL_0022:  br.s       IL_0007

    }  // end .try
    catch [mscorlib]System.Threading.ThreadAbortException 
    {
      IL_0024:  pop
      IL_0025:  leave.s    IL_002a

    }  // end handler
    catch [System]System.Net.Sockets.SocketException 
    {
      IL_0027:  pop
      IL_0028:  leave.s    IL_002a

    }  // end handler
    IL_002a:  ret
  } // end of method ProxyServer::Listen

  .method private hidebysig static void  ProcessClient(object obj) cil managed
  {
    // Code size       35 (0x23)
    .maxstack  1
    .locals init ([0] class [System]System.Net.Sockets.TcpClient client)
    IL_0000:  ldarg.0
    IL_0001:  castclass  [System]System.Net.Sockets.TcpClient
    IL_0006:  stloc.0
    .try
    {
      .try
      {
        IL_0007:  ldloc.0
        IL_0008:  call       void HTTPProxyServer.ProxyServer::DoHttpProcessing(class [System]System.Net.Sockets.TcpClient)
        IL_000d:  leave.s    IL_0022

      }  // end .try
      catch [mscorlib]System.Exception 
      {
        IL_000f:  callvirt   instance string [mscorlib]System.Exception::get_Message()
        IL_0014:  call       void [mscorlib]System.Console::WriteLine(string)
        IL_0019:  leave.s    IL_0022

      }  // end handler
    }  // end .try
    finally
    {
      IL_001b:  ldloc.0
      IL_001c:  callvirt   instance void [System]System.Net.Sockets.TcpClient::Close()
      IL_0021:  endfinally
    }  // end handler
    IL_0022:  ret
  } // end of method ProxyServer::ProcessClient

  .method private hidebysig static void  DoHttpProcessing(class [System]System.Net.Sockets.TcpClient client) cil managed
  {
    // Code size       1426 (0x592)
    .maxstack  5
    .locals init ([0] class [mscorlib]System.IO.Stream clientStream,
             [1] class [mscorlib]System.IO.Stream outStream,
             [2] class [System]System.Net.Security.SslStream sslStream,
             [3] class [mscorlib]System.IO.StreamReader clientStreamReader,
             [4] class HTTPProxyServer.CacheEntry cacheEntry,
             [5] class [mscorlib]System.IO.MemoryStream cacheStream,
             [6] string httpCmd,
             [7] string[] splitBuffer,
             [8] string subjectName,
             [9] string 'method',
             [10] string remoteUri,
             [11] class [mscorlib]System.Version version,
             [12] class [System]System.Net.HttpWebRequest webReq,
             [13] class [System]System.Net.HttpWebResponse response,
             [14] int32 contentLen,
             [15] class [mscorlib]System.IO.StreamWriter connectStreamWriter,
             [16] valuetype [mscorlib]System.DateTime V_16,
             [17] char[] postBuffer,
             [18] int32 bytesRead,
             [19] int32 totalBytesRead,
             [20] class [mscorlib]System.IO.StreamWriter sw,
             [21] class [mscorlib]System.Collections.Generic.List`1<class [mscorlib]System.Tuple`2<string,string>> responseHeaders,
             [22] class [mscorlib]System.IO.StreamWriter myResponseWriter,
             [23] class [mscorlib]System.IO.Stream responseStream,
             [24] valuetype [mscorlib]System.Nullable`1<valuetype [mscorlib]System.DateTime> expires,
             [25] class HTTPProxyServer.CacheEntry entry,
             [26] bool canCache,
             [27] uint8[] buffer,
             [28] int32 V_28,
             [29] class [mscorlib]System.IO.StreamWriter V_29)
    IL_0000:  ldarg.0
    IL_0001:  callvirt   instance class [System]System.Net.Sockets.NetworkStream [System]System.Net.Sockets.TcpClient::GetStream()
    IL_0006:  stloc.0
    IL_0007:  ldloc.0
    IL_0008:  stloc.1
    IL_0009:  ldnull
    IL_000a:  stloc.2
    IL_000b:  ldloc.0
    IL_000c:  newobj     instance void [mscorlib]System.IO.StreamReader::.ctor(class [mscorlib]System.IO.Stream)
    IL_0011:  stloc.3
    IL_0012:  ldnull
    IL_0013:  stloc.s    cacheEntry
    IL_0015:  ldnull
    IL_0016:  stloc.s    cacheStream
    IL_0018:  call       class HTTPProxyServer.ProxyServer HTTPProxyServer.ProxyServer::get_Server()
    IL_001d:  callvirt   instance bool HTTPProxyServer.ProxyServer::get_DumpHeaders()
    IL_0022:  brtrue.s   IL_003c

    IL_0024:  call       class HTTPProxyServer.ProxyServer HTTPProxyServer.ProxyServer::get_Server()
    IL_0029:  callvirt   instance bool HTTPProxyServer.ProxyServer::get_DumpPostData()
    IL_002e:  brtrue.s   IL_003c

    IL_0030:  call       class HTTPProxyServer.ProxyServer HTTPProxyServer.ProxyServer::get_Server()
    IL_0035:  callvirt   instance bool HTTPProxyServer.ProxyServer::get_DumpResponseData()
    IL_003a:  brfalse.s  IL_0055

    IL_003c:  ldsfld     object HTTPProxyServer.ProxyServer::_outputLockObj
    IL_0041:  ldc.r8     -1.
    IL_004a:  call       valuetype [mscorlib]System.TimeSpan [mscorlib]System.TimeSpan::FromMilliseconds(float64)
    IL_004f:  call       bool [mscorlib]System.Threading.Monitor::TryEnter(object,
                                                                           valuetype [mscorlib]System.TimeSpan)
    IL_0054:  pop
    IL_0055:  nop
    .try
    {
      .try
      {
        IL_0056:  ldloc.3
        IL_0057:  callvirt   instance string [mscorlib]System.IO.TextReader::ReadLine()
        IL_005c:  stloc.s    httpCmd
        IL_005e:  ldloc.s    httpCmd
        IL_0060:  call       bool [mscorlib]System.String::IsNullOrEmpty(string)
        IL_0065:  brfalse.s  IL_0078

        IL_0067:  ldloc.3
        IL_0068:  callvirt   instance void [mscorlib]System.IO.TextReader::Close()
        IL_006d:  ldloc.0
        IL_006e:  callvirt   instance void [mscorlib]System.IO.Stream::Close()
        IL_0073:  leave      IL_0591

        IL_0078:  ldloc.s    httpCmd
        IL_007a:  ldsfld     char[] HTTPProxyServer.ProxyServer::spaceSplit
        IL_007f:  ldc.i4.3
        IL_0080:  callvirt   instance string[] [mscorlib]System.String::Split(char[],
                                                                              int32)
        IL_0085:  stloc.s    splitBuffer
        IL_0087:  ldloc.s    splitBuffer
        IL_0089:  ldc.i4.1
        IL_008a:  ldelem.ref
        IL_008b:  ldsfld     char[] HTTPProxyServer.ProxyServer::colonSplit
        IL_0090:  ldc.i4.2
        IL_0091:  callvirt   instance string[] [mscorlib]System.String::Split(char[],
                                                                              int32)
        IL_0096:  ldc.i4.0
        IL_0097:  ldelem.ref
        IL_0098:  stloc.s    subjectName
        IL_009a:  ldloc.s    subjectName
        IL_009c:  call       void [mscorlib]System.Console::WriteLine(string)
        IL_00a1:  ldloc.s    splitBuffer
        IL_00a3:  ldc.i4.0
        IL_00a4:  ldelem.ref
        IL_00a5:  stloc.s    'method'
        IL_00a7:  ldloc.s    splitBuffer
        IL_00a9:  ldc.i4.1
        IL_00aa:  ldelem.ref
        IL_00ab:  stloc.s    remoteUri
        IL_00ad:  ldc.i4.1
        IL_00ae:  ldc.i4.0
        IL_00af:  newobj     instance void [mscorlib]System.Version::.ctor(int32,
                                                                           int32)
        IL_00b4:  stloc.s    version
        IL_00b6:  ldnull
        IL_00b7:  stloc.s    response
        IL_00b9:  ldloc.s    splitBuffer
        IL_00bb:  ldc.i4.0
        IL_00bc:  ldelem.ref
        IL_00bd:  callvirt   instance string [mscorlib]System.String::ToUpper()
        IL_00c2:  ldstr      "CONNECT"
        IL_00c7:  call       bool [mscorlib]System.String::op_Equality(string,
                                                                       string)
        IL_00cc:  brfalse    IL_01cb

        IL_00d1:  ldstr      "https://"
        IL_00d6:  ldloc.s    splitBuffer
        IL_00d8:  ldc.i4.1
        IL_00d9:  ldelem.ref
        IL_00da:  call       string [mscorlib]System.String::Concat(string,
                                                                    string)
        IL_00df:  stloc.s    remoteUri
        IL_00e1:  ldloc.3
        IL_00e2:  callvirt   instance string [mscorlib]System.IO.TextReader::ReadLine()
        IL_00e7:  call       bool [mscorlib]System.String::IsNullOrEmpty(string)
        IL_00ec:  brfalse.s  IL_00e1

        IL_00ee:  ldloc.0
        IL_00ef:  newobj     instance void [mscorlib]System.IO.StreamWriter::.ctor(class [mscorlib]System.IO.Stream)
        IL_00f4:  stloc.s    connectStreamWriter
        IL_00f6:  ldloc.s    connectStreamWriter
        IL_00f8:  ldstr      "HTTP/1.0 200 Connection established"
        IL_00fd:  callvirt   instance void [mscorlib]System.IO.TextWriter::WriteLine(string)
        IL_0102:  ldloc.s    connectStreamWriter
        IL_0104:  ldstr      "Timestamp: {0}"
        IL_0109:  call       valuetype [mscorlib]System.DateTime [mscorlib]System.DateTime::get_Now()
        IL_010e:  stloc.s    V_16
        IL_0110:  ldloca.s   V_16
        IL_0112:  call       instance string [mscorlib]System.DateTime::ToString()
        IL_0117:  call       string [mscorlib]System.String::Format(string,
                                                                    object)
        IL_011c:  callvirt   instance void [mscorlib]System.IO.TextWriter::WriteLine(string)
        IL_0121:  ldloc.s    connectStreamWriter
        IL_0123:  callvirt   instance void [mscorlib]System.IO.TextWriter::WriteLine()
        IL_0128:  ldloc.s    connectStreamWriter
        IL_012a:  callvirt   instance void [mscorlib]System.IO.TextWriter::Flush()
        IL_012f:  ldloc.0
        IL_0130:  ldc.i4.0
        IL_0131:  newobj     instance void [System]System.Net.Security.SslStream::.ctor(class [mscorlib]System.IO.Stream,
                                                                                        bool)
        IL_0136:  stloc.2
        .try
        {
          IL_0137:  ldloc.s    subjectName
          IL_0139:  call       class [System]System.Security.Cryptography.X509Certificates.X509Certificate2 HTTPProxyServer.ProxyServer::CertificateSubjectNameLookup(string)
          IL_013e:  stsfld     class [System]System.Security.Cryptography.X509Certificates.X509Certificate2 HTTPProxyServer.ProxyServer::_certificate
          IL_0143:  ldloc.2
          IL_0144:  ldsfld     class [System]System.Security.Cryptography.X509Certificates.X509Certificate2 HTTPProxyServer.ProxyServer::_certificate
          IL_0149:  ldc.i4.0
          IL_014a:  ldc.i4     0xc00
          IL_014f:  ldc.i4.1
          IL_0150:  callvirt   instance void [System]System.Net.Security.SslStream::AuthenticateAsServer(class [mscorlib]System.Security.Cryptography.X509Certificates.X509Certificate,
                                                                                                         bool,
                                                                                                         valuetype [System]System.Security.Authentication.SslProtocols,
                                                                                                         bool)
          IL_0155:  leave.s    IL_0176

        }  // end .try
        catch [mscorlib]System.Exception 
        {
          IL_0157:  pop
          IL_0158:  ldloc.2
          IL_0159:  callvirt   instance void [mscorlib]System.IO.Stream::Close()
          IL_015e:  ldloc.3
          IL_015f:  callvirt   instance void [mscorlib]System.IO.TextReader::Close()
          IL_0164:  ldloc.s    connectStreamWriter
          IL_0166:  callvirt   instance void [mscorlib]System.IO.TextWriter::Close()
          IL_016b:  ldloc.0
          IL_016c:  callvirt   instance void [mscorlib]System.IO.Stream::Close()
          IL_0171:  leave      IL_0591

        }  // end handler
        IL_0176:  ldloc.2
        IL_0177:  stloc.0
        IL_0178:  ldloc.2
        IL_0179:  newobj     instance void [mscorlib]System.IO.StreamReader::.ctor(class [mscorlib]System.IO.Stream)
        IL_017e:  stloc.3
        IL_017f:  ldloc.2
        IL_0180:  stloc.1
        IL_0181:  ldloc.3
        IL_0182:  callvirt   instance string [mscorlib]System.IO.TextReader::ReadLine()
        IL_0187:  stloc.s    httpCmd
        IL_0189:  ldloc.s    httpCmd
        IL_018b:  call       bool [mscorlib]System.String::IsNullOrEmpty(string)
        IL_0190:  brfalse.s  IL_01a9

        IL_0192:  ldloc.3
        IL_0193:  callvirt   instance void [mscorlib]System.IO.TextReader::Close()
        IL_0198:  ldloc.0
        IL_0199:  callvirt   instance void [mscorlib]System.IO.Stream::Close()
        IL_019e:  ldloc.2
        IL_019f:  callvirt   instance void [mscorlib]System.IO.Stream::Close()
        IL_01a4:  leave      IL_0591

        IL_01a9:  ldloc.s    httpCmd
        IL_01ab:  ldsfld     char[] HTTPProxyServer.ProxyServer::spaceSplit
        IL_01b0:  ldc.i4.3
        IL_01b1:  callvirt   instance string[] [mscorlib]System.String::Split(char[],
                                                                              int32)
        IL_01b6:  stloc.s    splitBuffer
        IL_01b8:  ldloc.s    splitBuffer
        IL_01ba:  ldc.i4.0
        IL_01bb:  ldelem.ref
        IL_01bc:  stloc.s    'method'
        IL_01be:  ldloc.s    remoteUri
        IL_01c0:  ldloc.s    splitBuffer
        IL_01c2:  ldc.i4.1
        IL_01c3:  ldelem.ref
        IL_01c4:  call       string [mscorlib]System.String::Concat(string,
                                                                    string)
        IL_01c9:  stloc.s    remoteUri
        IL_01cb:  ldloc.s    remoteUri
        IL_01cd:  call       class [System]System.Net.WebRequest [System]System.Net.WebRequest::Create(string)
        IL_01d2:  castclass  [System]System.Net.HttpWebRequest
        IL_01d7:  stloc.s    webReq
        IL_01d9:  ldloc.s    webReq
        IL_01db:  ldloc.s    'method'
        IL_01dd:  callvirt   instance void [System]System.Net.WebRequest::set_Method(string)
        IL_01e2:  ldloc.s    webReq
        IL_01e4:  ldloc.s    version
        IL_01e6:  callvirt   instance void [System]System.Net.HttpWebRequest::set_ProtocolVersion(class [mscorlib]System.Version)
        IL_01eb:  ldloc.3
        IL_01ec:  ldloc.s    webReq
        IL_01ee:  call       int32 HTTPProxyServer.ProxyServer::ReadRequestHeaders(class [mscorlib]System.IO.StreamReader,
                                                                                   class [System]System.Net.HttpWebRequest)
        IL_01f3:  stloc.s    contentLen
        IL_01f5:  ldloc.s    webReq
        IL_01f7:  ldnull
        IL_01f8:  callvirt   instance void [System]System.Net.WebRequest::set_Proxy(class [System]System.Net.IWebProxy)
        IL_01fd:  ldloc.s    webReq
        IL_01ff:  ldc.i4.0
        IL_0200:  callvirt   instance void [System]System.Net.HttpWebRequest::set_KeepAlive(bool)
        IL_0205:  ldloc.s    webReq
        IL_0207:  ldc.i4.0
        IL_0208:  callvirt   instance void [System]System.Net.HttpWebRequest::set_AllowAutoRedirect(bool)
        IL_020d:  ldloc.s    webReq
        IL_020f:  ldc.i4.0
        IL_0210:  callvirt   instance void [System]System.Net.HttpWebRequest::set_AutomaticDecompression(valuetype [System]System.Net.DecompressionMethods)
        IL_0215:  call       class HTTPProxyServer.ProxyServer HTTPProxyServer.ProxyServer::get_Server()
        IL_021a:  callvirt   instance bool HTTPProxyServer.ProxyServer::get_DumpHeaders()
        IL_021f:  brfalse.s  IL_0256

        IL_0221:  ldstr      "{0} {1} HTTP/{2}"
        IL_0226:  ldloc.s    webReq
        IL_0228:  callvirt   instance string [System]System.Net.WebRequest::get_Method()
        IL_022d:  ldloc.s    webReq
        IL_022f:  callvirt   instance class [System]System.Uri [System]System.Net.WebRequest::get_RequestUri()
        IL_0234:  callvirt   instance string [System]System.Uri::get_AbsoluteUri()
        IL_0239:  ldloc.s    webReq
        IL_023b:  callvirt   instance class [mscorlib]System.Version [System]System.Net.HttpWebRequest::get_ProtocolVersion()
        IL_0240:  call       string [mscorlib]System.String::Format(string,
                                                                    object,
                                                                    object,
                                                                    object)
        IL_0245:  call       void [mscorlib]System.Console::WriteLine(string)
        IL_024a:  ldloc.s    webReq
        IL_024c:  callvirt   instance class [System]System.Net.WebHeaderCollection [System]System.Net.WebRequest::get_Headers()
        IL_0251:  call       void HTTPProxyServer.ProxyServer::DumpHeaderCollectionToConsole(class [System]System.Net.WebHeaderCollection)
        IL_0256:  ldloc.s    'method'
        IL_0258:  callvirt   instance string [mscorlib]System.String::ToUpper()
        IL_025d:  ldstr      "GET"
        IL_0262:  call       bool [mscorlib]System.String::op_Equality(string,
                                                                       string)
        IL_0267:  brfalse.s  IL_0277

        IL_0269:  ldloc.s    webReq
        IL_026b:  call       class HTTPProxyServer.CacheEntry HTTPProxyServer.ProxyCache::GetData(class [System]System.Net.HttpWebRequest)
        IL_0270:  stloc.s    cacheEntry
        IL_0272:  br         IL_0303

        IL_0277:  ldloc.s    'method'
        IL_0279:  callvirt   instance string [mscorlib]System.String::ToUpper()
        IL_027e:  ldstr      "POST"
        IL_0283:  call       bool [mscorlib]System.String::op_Equality(string,
                                                                       string)
        IL_0288:  brfalse.s  IL_0303

        IL_028a:  ldloc.s    contentLen
        IL_028c:  newarr     [mscorlib]System.Char
        IL_0291:  stloc.s    postBuffer
        IL_0293:  ldc.i4.0
        IL_0294:  stloc.s    totalBytesRead
        IL_0296:  ldloc.s    webReq
        IL_0298:  callvirt   instance class [mscorlib]System.IO.Stream [System]System.Net.WebRequest::GetRequestStream()
        IL_029d:  newobj     instance void [mscorlib]System.IO.StreamWriter::.ctor(class [mscorlib]System.IO.Stream)
        IL_02a2:  stloc.s    sw
        IL_02a4:  br.s       IL_02cf

        IL_02a6:  ldloc.s    totalBytesRead
        IL_02a8:  ldloc.s    bytesRead
        IL_02aa:  add
        IL_02ab:  stloc.s    totalBytesRead
        IL_02ad:  ldloc.s    sw
        IL_02af:  ldloc.s    postBuffer
        IL_02b1:  ldc.i4.0
        IL_02b2:  ldloc.s    bytesRead
        IL_02b4:  callvirt   instance void [mscorlib]System.IO.TextWriter::Write(char[],
                                                                                 int32,
                                                                                 int32)
        IL_02b9:  call       class HTTPProxyServer.ProxyServer HTTPProxyServer.ProxyServer::get_Server()
        IL_02be:  callvirt   instance bool HTTPProxyServer.ProxyServer::get_DumpPostData()
        IL_02c3:  brfalse.s  IL_02cf

        IL_02c5:  ldloc.s    postBuffer
        IL_02c7:  ldc.i4.0
        IL_02c8:  ldloc.s    bytesRead
        IL_02ca:  call       void [mscorlib]System.Console::Write(char[],
                                                                  int32,
                                                                  int32)
        IL_02cf:  ldloc.s    totalBytesRead
        IL_02d1:  ldloc.s    contentLen
        IL_02d3:  bge.s      IL_02e6

        IL_02d5:  ldloc.3
        IL_02d6:  ldloc.s    postBuffer
        IL_02d8:  ldc.i4.0
        IL_02d9:  ldloc.s    contentLen
        IL_02db:  callvirt   instance int32 [mscorlib]System.IO.TextReader::ReadBlock(char[],
                                                                                      int32,
                                                                                      int32)
        IL_02e0:  dup
        IL_02e1:  stloc.s    bytesRead
        IL_02e3:  ldc.i4.0
        IL_02e4:  bgt.s      IL_02a6

        IL_02e6:  call       class HTTPProxyServer.ProxyServer HTTPProxyServer.ProxyServer::get_Server()
        IL_02eb:  callvirt   instance bool HTTPProxyServer.ProxyServer::get_DumpPostData()
        IL_02f0:  brfalse.s  IL_02fc

        IL_02f2:  call       void [mscorlib]System.Console::WriteLine()
        IL_02f7:  call       void [mscorlib]System.Console::WriteLine()
        IL_02fc:  ldloc.s    sw
        IL_02fe:  callvirt   instance void [mscorlib]System.IO.TextWriter::Close()
        IL_0303:  ldloc.s    cacheEntry
        IL_0305:  brtrue     IL_04a2

        IL_030a:  ldloc.s    webReq
        IL_030c:  ldc.i4     0x3a98
        IL_0311:  callvirt   instance void [System]System.Net.WebRequest::set_Timeout(int32)
        .try
        {
          IL_0316:  ldloc.s    webReq
          IL_0318:  callvirt   instance class [System]System.Net.WebResponse [System]System.Net.WebRequest::GetResponse()
          IL_031d:  castclass  [System]System.Net.HttpWebResponse
          IL_0322:  stloc.s    response
          IL_0324:  leave.s    IL_0334

        }  // end .try
        catch [System]System.Net.WebException 
        {
          IL_0326:  callvirt   instance class [System]System.Net.WebResponse [System]System.Net.WebException::get_Response()
          IL_032b:  isinst     [System]System.Net.HttpWebResponse
          IL_0330:  stloc.s    response
          IL_0332:  leave.s    IL_0334

        }  // end handler
        IL_0334:  ldloc.s    response
        IL_0336:  brfalse    IL_052e

        IL_033b:  ldloc.s    response
        IL_033d:  call       class [mscorlib]System.Collections.Generic.List`1<class [mscorlib]System.Tuple`2<string,string>> HTTPProxyServer.ProxyServer::ProcessResponse(class [System]System.Net.HttpWebResponse)
        IL_0342:  stloc.s    responseHeaders
        IL_0344:  ldloc.1
        IL_0345:  newobj     instance void [mscorlib]System.IO.StreamWriter::.ctor(class [mscorlib]System.IO.Stream)
        IL_034a:  stloc.s    myResponseWriter
        IL_034c:  ldloc.s    response
        IL_034e:  callvirt   instance class [mscorlib]System.IO.Stream [System]System.Net.WebResponse::GetResponseStream()
        IL_0353:  stloc.s    responseStream
        .try
        {
          .try
          {
            IL_0355:  ldloc.s    response
            IL_0357:  callvirt   instance valuetype [System]System.Net.HttpStatusCode [System]System.Net.HttpWebResponse::get_StatusCode()
            IL_035c:  ldloc.s    response
            IL_035e:  callvirt   instance string [System]System.Net.HttpWebResponse::get_StatusDescription()
            IL_0363:  ldloc.s    myResponseWriter
            IL_0365:  call       void HTTPProxyServer.ProxyServer::WriteResponseStatus(valuetype [System]System.Net.HttpStatusCode,
                                                                                       string,
                                                                                       class [mscorlib]System.IO.StreamWriter)
            IL_036a:  ldloc.s    myResponseWriter
            IL_036c:  ldloc.s    responseHeaders
            IL_036e:  call       void HTTPProxyServer.ProxyServer::WriteResponseHeaders(class [mscorlib]System.IO.StreamWriter,
                                                                                        class [mscorlib]System.Collections.Generic.List`1<class [mscorlib]System.Tuple`2<string,string>>)
            IL_0373:  ldloca.s   expires
            IL_0375:  initobj    valuetype [mscorlib]System.Nullable`1<valuetype [mscorlib]System.DateTime>
            IL_037b:  ldnull
            IL_037c:  stloc.s    entry
            IL_037e:  ldloc.2
            IL_037f:  brtrue.s   IL_0391

            IL_0381:  ldloc.s    response
            IL_0383:  callvirt   instance class [System]System.Net.WebHeaderCollection [System]System.Net.WebResponse::get_Headers()
            IL_0388:  ldloca.s   expires
            IL_038a:  call       bool HTTPProxyServer.ProxyCache::CanCache(class [System]System.Net.WebHeaderCollection,
                                                                           valuetype [mscorlib]System.Nullable`1<valuetype [mscorlib]System.DateTime>&)
            IL_038f:  br.s       IL_0392

            IL_0391:  ldc.i4.0
            IL_0392:  stloc.s    canCache
            IL_0394:  ldloc.s    canCache
            IL_0396:  brfalse.s  IL_03c0

            IL_0398:  ldloc.s    webReq
            IL_039a:  ldloc.s    response
            IL_039c:  ldloc.s    responseHeaders
            IL_039e:  ldloc.s    expires
            IL_03a0:  call       class HTTPProxyServer.CacheEntry HTTPProxyServer.ProxyCache::MakeEntry(class [System]System.Net.HttpWebRequest,
                                                                                                        class [System]System.Net.HttpWebResponse,
                                                                                                        class [mscorlib]System.Collections.Generic.List`1<class [mscorlib]System.Tuple`2<string,string>>,
                                                                                                        valuetype [mscorlib]System.Nullable`1<valuetype [mscorlib]System.DateTime>)
            IL_03a5:  stloc.s    entry
            IL_03a7:  ldloc.s    response
            IL_03a9:  callvirt   instance int64 [System]System.Net.WebResponse::get_ContentLength()
            IL_03ae:  ldc.i4.0
            IL_03af:  conv.i8
            IL_03b0:  ble.s      IL_03c0

            IL_03b2:  ldloc.s    entry
            IL_03b4:  callvirt   instance uint8[] HTTPProxyServer.CacheEntry::get_ResponseBytes()
            IL_03b9:  newobj     instance void [mscorlib]System.IO.MemoryStream::.ctor(uint8[])
            IL_03be:  stloc.s    cacheStream
            IL_03c0:  ldloc.s    response
            IL_03c2:  callvirt   instance int64 [System]System.Net.WebResponse::get_ContentLength()
            IL_03c7:  ldc.i4.0
            IL_03c8:  conv.i8
            IL_03c9:  ble.s      IL_03dc

            IL_03cb:  ldloc.s    response
            IL_03cd:  callvirt   instance int64 [System]System.Net.WebResponse::get_ContentLength()
            IL_03d2:  conv.ovf.i
            IL_03d3:  newarr     [mscorlib]System.Byte
            IL_03d8:  stloc.s    buffer
            IL_03da:  br.s       IL_0425

            IL_03dc:  ldsfld     int32 HTTPProxyServer.ProxyServer::BUFFER_SIZE
            IL_03e1:  newarr     [mscorlib]System.Byte
            IL_03e6:  stloc.s    buffer
            IL_03e8:  br.s       IL_0425

            IL_03ea:  ldloc.s    cacheStream
            IL_03ec:  brfalse.s  IL_03fa

            IL_03ee:  ldloc.s    cacheStream
            IL_03f0:  ldloc.s    buffer
            IL_03f2:  ldc.i4.0
            IL_03f3:  ldloc.s    V_28
            IL_03f5:  callvirt   instance void [mscorlib]System.IO.Stream::Write(uint8[],
                                                                                 int32,
                                                                                 int32)
            IL_03fa:  ldloc.1
            IL_03fb:  ldloc.s    buffer
            IL_03fd:  ldc.i4.0
            IL_03fe:  ldloc.s    V_28
            IL_0400:  callvirt   instance void [mscorlib]System.IO.Stream::Write(uint8[],
                                                                                 int32,
                                                                                 int32)
            IL_0405:  call       class HTTPProxyServer.ProxyServer HTTPProxyServer.ProxyServer::get_Server()
            IL_040a:  callvirt   instance bool HTTPProxyServer.ProxyServer::get_DumpResponseData()
            IL_040f:  brfalse.s  IL_0425

            IL_0411:  call       class [mscorlib]System.Text.Encoding [mscorlib]System.Text.Encoding::get_UTF8()
            IL_0416:  ldloc.s    buffer
            IL_0418:  ldc.i4.0
            IL_0419:  ldloc.s    V_28
            IL_041b:  callvirt   instance string [mscorlib]System.Text.Encoding::GetString(uint8[],
                                                                                           int32,
                                                                                           int32)
            IL_0420:  call       void [mscorlib]System.Console::Write(string)
            IL_0425:  ldloc.s    responseStream
            IL_0427:  ldloc.s    buffer
            IL_0429:  ldc.i4.0
            IL_042a:  ldloc.s    buffer
            IL_042c:  ldlen
            IL_042d:  conv.i4
            IL_042e:  callvirt   instance int32 [mscorlib]System.IO.Stream::Read(uint8[],
                                                                                 int32,
                                                                                 int32)
            IL_0433:  dup
            IL_0434:  stloc.s    V_28
            IL_0436:  ldc.i4.0
            IL_0437:  bgt.s      IL_03ea

            IL_0439:  call       class HTTPProxyServer.ProxyServer HTTPProxyServer.ProxyServer::get_Server()
            IL_043e:  callvirt   instance bool HTTPProxyServer.ProxyServer::get_DumpResponseData()
            IL_0443:  brfalse.s  IL_044f

            IL_0445:  call       void [mscorlib]System.Console::WriteLine()
            IL_044a:  call       void [mscorlib]System.Console::WriteLine()
            IL_044f:  ldloc.s    responseStream
            IL_0451:  callvirt   instance void [mscorlib]System.IO.Stream::Close()
            IL_0456:  ldloc.s    cacheStream
            IL_0458:  brfalse.s  IL_0468

            IL_045a:  ldloc.s    cacheStream
            IL_045c:  callvirt   instance void [mscorlib]System.IO.Stream::Flush()
            IL_0461:  ldloc.s    cacheStream
            IL_0463:  callvirt   instance void [mscorlib]System.IO.Stream::Close()
            IL_0468:  ldloc.1
            IL_0469:  callvirt   instance void [mscorlib]System.IO.Stream::Flush()
            IL_046e:  ldloc.s    canCache
            IL_0470:  brfalse.s  IL_0479

            IL_0472:  ldloc.s    entry
            IL_0474:  call       void HTTPProxyServer.ProxyCache::AddData(class HTTPProxyServer.CacheEntry)
            IL_0479:  leave.s    IL_0487

          }  // end .try
          catch [mscorlib]System.Exception 
          {
            IL_047b:  callvirt   instance string [mscorlib]System.Exception::get_Message()
            IL_0480:  call       void [mscorlib]System.Console::WriteLine(string)
            IL_0485:  leave.s    IL_0487

          }  // end handler
          IL_0487:  leave      IL_052e

        }  // end .try
        finally
        {
          IL_048c:  ldloc.s    responseStream
          IL_048e:  callvirt   instance void [mscorlib]System.IO.Stream::Close()
          IL_0493:  ldloc.s    response
          IL_0495:  callvirt   instance void [System]System.Net.WebResponse::Close()
          IL_049a:  ldloc.s    myResponseWriter
          IL_049c:  callvirt   instance void [mscorlib]System.IO.TextWriter::Close()
          IL_04a1:  endfinally
        }  // end handler
        IL_04a2:  ldloc.1
        IL_04a3:  newobj     instance void [mscorlib]System.IO.StreamWriter::.ctor(class [mscorlib]System.IO.Stream)
        IL_04a8:  stloc.s    V_29
        .try
        {
          .try
          {
            IL_04aa:  ldloc.s    cacheEntry
            IL_04ac:  callvirt   instance valuetype [System]System.Net.HttpStatusCode HTTPProxyServer.CacheEntry::get_StatusCode()
            IL_04b1:  ldloc.s    cacheEntry
            IL_04b3:  callvirt   instance string HTTPProxyServer.CacheEntry::get_StatusDescription()
            IL_04b8:  ldloc.s    V_29
            IL_04ba:  call       void HTTPProxyServer.ProxyServer::WriteResponseStatus(valuetype [System]System.Net.HttpStatusCode,
                                                                                       string,
                                                                                       class [mscorlib]System.IO.StreamWriter)
            IL_04bf:  ldloc.s    V_29
            IL_04c1:  ldloc.s    cacheEntry
            IL_04c3:  callvirt   instance class [mscorlib]System.Collections.Generic.List`1<class [mscorlib]System.Tuple`2<string,string>> HTTPProxyServer.CacheEntry::get_Headers()
            IL_04c8:  call       void HTTPProxyServer.ProxyServer::WriteResponseHeaders(class [mscorlib]System.IO.StreamWriter,
                                                                                        class [mscorlib]System.Collections.Generic.List`1<class [mscorlib]System.Tuple`2<string,string>>)
            IL_04cd:  ldloc.s    cacheEntry
            IL_04cf:  callvirt   instance uint8[] HTTPProxyServer.CacheEntry::get_ResponseBytes()
            IL_04d4:  brfalse.s  IL_050f

            IL_04d6:  ldloc.1
            IL_04d7:  ldloc.s    cacheEntry
            IL_04d9:  callvirt   instance uint8[] HTTPProxyServer.CacheEntry::get_ResponseBytes()
            IL_04de:  ldc.i4.0
            IL_04df:  ldloc.s    cacheEntry
            IL_04e1:  callvirt   instance uint8[] HTTPProxyServer.CacheEntry::get_ResponseBytes()
            IL_04e6:  ldlen
            IL_04e7:  conv.i4
            IL_04e8:  callvirt   instance void [mscorlib]System.IO.Stream::Write(uint8[],
                                                                                 int32,
                                                                                 int32)
            IL_04ed:  call       class HTTPProxyServer.ProxyServer HTTPProxyServer.ProxyServer::get_Server()
            IL_04f2:  callvirt   instance bool HTTPProxyServer.ProxyServer::get_DumpResponseData()
            IL_04f7:  brfalse.s  IL_050f

            IL_04f9:  call       class [mscorlib]System.Text.Encoding [mscorlib]System.Text.Encoding::get_UTF8()
            IL_04fe:  ldloc.s    cacheEntry
            IL_0500:  callvirt   instance uint8[] HTTPProxyServer.CacheEntry::get_ResponseBytes()
            IL_0505:  callvirt   instance string [mscorlib]System.Text.Encoding::GetString(uint8[])
            IL_050a:  call       void [mscorlib]System.Console::Write(string)
            IL_050f:  ldloc.s    V_29
            IL_0511:  callvirt   instance void [mscorlib]System.IO.TextWriter::Close()
            IL_0516:  leave.s    IL_0524

          }  // end .try
          catch [mscorlib]System.Exception 
          {
            IL_0518:  callvirt   instance string [mscorlib]System.Exception::get_Message()
            IL_051d:  call       void [mscorlib]System.Console::WriteLine(string)
            IL_0522:  leave.s    IL_0524

          }  // end handler
          IL_0524:  leave.s    IL_052e

        }  // end .try
        finally
        {
          IL_0526:  ldloc.s    V_29
          IL_0528:  callvirt   instance void [mscorlib]System.IO.TextWriter::Close()
          IL_052d:  endfinally
        }  // end handler
        IL_052e:  leave.s    IL_0591

      }  // end .try
      catch [mscorlib]System.Exception 
      {
        IL_0530:  callvirt   instance string [mscorlib]System.Exception::get_Message()
        IL_0535:  call       void [mscorlib]System.Console::WriteLine(string)
        IL_053a:  leave.s    IL_0591

      }  // end handler
    }  // end .try
    finally
    {
      IL_053c:  call       class HTTPProxyServer.ProxyServer HTTPProxyServer.ProxyServer::get_Server()
      IL_0541:  callvirt   instance bool HTTPProxyServer.ProxyServer::get_DumpHeaders()
      IL_0546:  brtrue.s   IL_0560

      IL_0548:  call       class HTTPProxyServer.ProxyServer HTTPProxyServer.ProxyServer::get_Server()
      IL_054d:  callvirt   instance bool HTTPProxyServer.ProxyServer::get_DumpPostData()
      IL_0552:  brtrue.s   IL_0560

      IL_0554:  call       class HTTPProxyServer.ProxyServer HTTPProxyServer.ProxyServer::get_Server()
      IL_0559:  callvirt   instance bool HTTPProxyServer.ProxyServer::get_DumpResponseData()
      IL_055e:  brfalse.s  IL_056a

      IL_0560:  ldsfld     object HTTPProxyServer.ProxyServer::_outputLockObj
      IL_0565:  call       void [mscorlib]System.Threading.Monitor::Exit(object)
      IL_056a:  ldloc.3
      IL_056b:  callvirt   instance void [mscorlib]System.IO.TextReader::Close()
      IL_0570:  ldloc.0
      IL_0571:  callvirt   instance void [mscorlib]System.IO.Stream::Close()
      IL_0576:  ldloc.2
      IL_0577:  brfalse.s  IL_057f

      IL_0579:  ldloc.2
      IL_057a:  callvirt   instance void [mscorlib]System.IO.Stream::Close()
      IL_057f:  ldloc.1
      IL_0580:  callvirt   instance void [mscorlib]System.IO.Stream::Close()
      IL_0585:  ldloc.s    cacheStream
      IL_0587:  brfalse.s  IL_0590

      IL_0589:  ldloc.s    cacheStream
      IL_058b:  callvirt   instance void [mscorlib]System.IO.Stream::Close()
      IL_0590:  endfinally
    }  // end handler
    IL_0591:  ret
  } // end of method ProxyServer::DoHttpProcessing

  .method private hidebysig static class [mscorlib]System.Collections.Generic.List`1<class [mscorlib]System.Tuple`2<string,string>> 
          ProcessResponse(class [System]System.Net.HttpWebResponse response) cil managed
  {
    // Code size       215 (0xd7)
    .maxstack  4
    .locals init ([0] string 'value',
             [1] string header,
             [2] class [mscorlib]System.Collections.Generic.List`1<class [mscorlib]System.Tuple`2<string,string>> returnHeaders,
             [3] class [mscorlib]System.Collections.IEnumerator V_3,
             [4] string s,
             [5] class [mscorlib]System.IDisposable V_5,
             [6] string[] V_6,
             [7] int32 V_7,
             [8] string cookie)
    IL_0000:  ldnull
    IL_0001:  stloc.0
    IL_0002:  ldnull
    IL_0003:  stloc.1
    IL_0004:  newobj     instance void class [mscorlib]System.Collections.Generic.List`1<class [mscorlib]System.Tuple`2<string,string>>::.ctor()
    IL_0009:  stloc.2
    IL_000a:  ldarg.0
    IL_000b:  callvirt   instance class [System]System.Net.WebHeaderCollection [System]System.Net.WebResponse::get_Headers()
    IL_0010:  callvirt   instance class [System]System.Collections.Specialized.NameObjectCollectionBase/KeysCollection [System]System.Collections.Specialized.NameObjectCollectionBase::get_Keys()
    IL_0015:  callvirt   instance class [mscorlib]System.Collections.IEnumerator [System]System.Collections.Specialized.NameObjectCollectionBase/KeysCollection::GetEnumerator()
    IL_001a:  stloc.3
    .try
    {
      IL_001b:  br.s       IL_006a

      IL_001d:  ldloc.3
      IL_001e:  callvirt   instance object [mscorlib]System.Collections.IEnumerator::get_Current()
      IL_0023:  castclass  [mscorlib]System.String
      IL_0028:  stloc.s    s
      IL_002a:  ldloc.s    s
      IL_002c:  callvirt   instance string [mscorlib]System.String::ToLower()
      IL_0031:  ldstr      "set-cookie"
      IL_0036:  call       bool [mscorlib]System.String::op_Equality(string,
                                                                     string)
      IL_003b:  brfalse.s  IL_0050

      IL_003d:  ldloc.s    s
      IL_003f:  stloc.1
      IL_0040:  ldarg.0
      IL_0041:  callvirt   instance class [System]System.Net.WebHeaderCollection [System]System.Net.WebResponse::get_Headers()
      IL_0046:  ldloc.s    s
      IL_0048:  callvirt   instance string [System]System.Collections.Specialized.NameValueCollection::get_Item(string)
      IL_004d:  stloc.0
      IL_004e:  br.s       IL_006a

      IL_0050:  ldloc.2
      IL_0051:  ldloc.s    s
      IL_0053:  ldarg.0
      IL_0054:  callvirt   instance class [System]System.Net.WebHeaderCollection [System]System.Net.WebResponse::get_Headers()
      IL_0059:  ldloc.s    s
      IL_005b:  callvirt   instance string [System]System.Collections.Specialized.NameValueCollection::get_Item(string)
      IL_0060:  newobj     instance void class [mscorlib]System.Tuple`2<string,string>::.ctor(!0,
                                                                                              !1)
      IL_0065:  callvirt   instance void class [mscorlib]System.Collections.Generic.List`1<class [mscorlib]System.Tuple`2<string,string>>::Add(!0)
      IL_006a:  ldloc.3
      IL_006b:  callvirt   instance bool [mscorlib]System.Collections.IEnumerator::MoveNext()
      IL_0070:  brtrue.s   IL_001d

      IL_0072:  leave.s    IL_0088

    }  // end .try
    finally
    {
      IL_0074:  ldloc.3
      IL_0075:  isinst     [mscorlib]System.IDisposable
      IL_007a:  stloc.s    V_5
      IL_007c:  ldloc.s    V_5
      IL_007e:  brfalse.s  IL_0087

      IL_0080:  ldloc.s    V_5
      IL_0082:  callvirt   instance void [mscorlib]System.IDisposable::Dispose()
      IL_0087:  endfinally
    }  // end handler
    IL_0088:  ldloc.0
    IL_0089:  call       bool [mscorlib]System.String::IsNullOrWhiteSpace(string)
    IL_008e:  brtrue.s   IL_00d5

    IL_0090:  ldarg.0
    IL_0091:  callvirt   instance class [System]System.Net.WebHeaderCollection [System]System.Net.WebResponse::get_Headers()
    IL_0096:  ldloc.1
    IL_0097:  callvirt   instance void [System]System.Collections.Specialized.NameValueCollection::Remove(string)
    IL_009c:  ldsfld     class [System]System.Text.RegularExpressions.Regex HTTPProxyServer.ProxyServer::cookieSplitRegEx
    IL_00a1:  ldloc.0
    IL_00a2:  callvirt   instance string[] [System]System.Text.RegularExpressions.Regex::Split(string)
    IL_00a7:  stloc.s    V_6
    IL_00a9:  ldc.i4.0
    IL_00aa:  stloc.s    V_7
    IL_00ac:  br.s       IL_00cd

    IL_00ae:  ldloc.s    V_6
    IL_00b0:  ldloc.s    V_7
    IL_00b2:  ldelem.ref
    IL_00b3:  stloc.s    cookie
    IL_00b5:  ldloc.2
    IL_00b6:  ldstr      "Set-Cookie"
    IL_00bb:  ldloc.s    cookie
    IL_00bd:  newobj     instance void class [mscorlib]System.Tuple`2<string,string>::.ctor(!0,
                                                                                            !1)
    IL_00c2:  callvirt   instance void class [mscorlib]System.Collections.Generic.List`1<class [mscorlib]System.Tuple`2<string,string>>::Add(!0)
    IL_00c7:  ldloc.s    V_7
    IL_00c9:  ldc.i4.1
    IL_00ca:  add
    IL_00cb:  stloc.s    V_7
    IL_00cd:  ldloc.s    V_7
    IL_00cf:  ldloc.s    V_6
    IL_00d1:  ldlen
    IL_00d2:  conv.i4
    IL_00d3:  blt.s      IL_00ae

    IL_00d5:  ldloc.2
    IL_00d6:  ret
  } // end of method ProxyServer::ProcessResponse

  .method private hidebysig static void  WriteResponseStatus(valuetype [System]System.Net.HttpStatusCode code,
                                                             string description,
                                                             class [mscorlib]System.IO.StreamWriter myResponseWriter) cil managed
  {
    // Code size       44 (0x2c)
    .maxstack  3
    .locals init ([0] string s)
    IL_0000:  ldstr      "HTTP/1.0 {0} {1}"
    IL_0005:  ldarg.0
    IL_0006:  box        [mscorlib]System.Int32
    IL_000b:  ldarg.1
    IL_000c:  call       string [mscorlib]System.String::Format(string,
                                                                object,
                                                                object)
    IL_0011:  stloc.0
    IL_0012:  ldarg.2
    IL_0013:  ldloc.0
    IL_0014:  callvirt   instance void [mscorlib]System.IO.TextWriter::WriteLine(string)
    IL_0019:  call       class HTTPProxyServer.ProxyServer HTTPProxyServer.ProxyServer::get_Server()
    IL_001e:  callvirt   instance bool HTTPProxyServer.ProxyServer::get_DumpHeaders()
    IL_0023:  brfalse.s  IL_002b

    IL_0025:  ldloc.0
    IL_0026:  call       void [mscorlib]System.Console::WriteLine(string)
    IL_002b:  ret
  } // end of method ProxyServer::WriteResponseStatus

  .method private hidebysig static void  WriteResponseHeaders(class [mscorlib]System.IO.StreamWriter myResponseWriter,
                                                              class [mscorlib]System.Collections.Generic.List`1<class [mscorlib]System.Tuple`2<string,string>> headers) cil managed
  {
    // Code size       104 (0x68)
    .maxstack  4
    .locals init ([0] valuetype [mscorlib]System.Collections.Generic.List`1/Enumerator<class [mscorlib]System.Tuple`2<string,string>> V_0,
             [1] class [mscorlib]System.Tuple`2<string,string> header)
    IL_0000:  ldarg.1
    IL_0001:  brfalse.s  IL_0049

    IL_0003:  ldarg.1
    IL_0004:  callvirt   instance valuetype [mscorlib]System.Collections.Generic.List`1/Enumerator<!0> class [mscorlib]System.Collections.Generic.List`1<class [mscorlib]System.Tuple`2<string,string>>::GetEnumerator()
    IL_0009:  stloc.0
    .try
    {
      IL_000a:  br.s       IL_0030

      IL_000c:  ldloca.s   V_0
      IL_000e:  call       instance !0 valuetype [mscorlib]System.Collections.Generic.List`1/Enumerator<class [mscorlib]System.Tuple`2<string,string>>::get_Current()
      IL_0013:  stloc.1
      IL_0014:  ldarg.0
      IL_0015:  ldstr      "{0}: {1}"
      IL_001a:  ldloc.1
      IL_001b:  callvirt   instance !0 class [mscorlib]System.Tuple`2<string,string>::get_Item1()
      IL_0020:  ldloc.1
      IL_0021:  callvirt   instance !1 class [mscorlib]System.Tuple`2<string,string>::get_Item2()
      IL_0026:  call       string [mscorlib]System.String::Format(string,
                                                                  object,
                                                                  object)
      IL_002b:  callvirt   instance void [mscorlib]System.IO.TextWriter::WriteLine(string)
      IL_0030:  ldloca.s   V_0
      IL_0032:  call       instance bool valuetype [mscorlib]System.Collections.Generic.List`1/Enumerator<class [mscorlib]System.Tuple`2<string,string>>::MoveNext()
      IL_0037:  brtrue.s   IL_000c

      IL_0039:  leave.s    IL_0049

    }  // end .try
    finally
    {
      IL_003b:  ldloca.s   V_0
      IL_003d:  constrained. valuetype [mscorlib]System.Collections.Generic.List`1/Enumerator<class [mscorlib]System.Tuple`2<string,string>>
      IL_0043:  callvirt   instance void [mscorlib]System.IDisposable::Dispose()
      IL_0048:  endfinally
    }  // end handler
    IL_0049:  ldarg.0
    IL_004a:  callvirt   instance void [mscorlib]System.IO.TextWriter::WriteLine()
    IL_004f:  ldarg.0
    IL_0050:  callvirt   instance void [mscorlib]System.IO.TextWriter::Flush()
    IL_0055:  call       class HTTPProxyServer.ProxyServer HTTPProxyServer.ProxyServer::get_Server()
    IL_005a:  callvirt   instance bool HTTPProxyServer.ProxyServer::get_DumpHeaders()
    IL_005f:  brfalse.s  IL_0067

    IL_0061:  ldarg.1
    IL_0062:  call       void HTTPProxyServer.ProxyServer::DumpHeaderCollectionToConsole(class [mscorlib]System.Collections.Generic.List`1<class [mscorlib]System.Tuple`2<string,string>>)
    IL_0067:  ret
  } // end of method ProxyServer::WriteResponseHeaders

  .method private hidebysig static void  DumpHeaderCollectionToConsole(class [System]System.Net.WebHeaderCollection headers) cil managed
  {
    // Code size       54 (0x36)
    .maxstack  4
    .locals init ([0] string[] V_0,
             [1] int32 V_1,
             [2] string s)
    IL_0000:  ldarg.0
    IL_0001:  callvirt   instance string[] [System]System.Collections.Specialized.NameValueCollection::get_AllKeys()
    IL_0006:  stloc.0
    IL_0007:  ldc.i4.0
    IL_0008:  stloc.1
    IL_0009:  br.s       IL_002a

    IL_000b:  ldloc.0
    IL_000c:  ldloc.1
    IL_000d:  ldelem.ref
    IL_000e:  stloc.2
    IL_000f:  ldstr      "{0}: {1}"
    IL_0014:  ldloc.2
    IL_0015:  ldarg.0
    IL_0016:  ldloc.2
    IL_0017:  callvirt   instance string [System]System.Collections.Specialized.NameValueCollection::get_Item(string)
    IL_001c:  call       string [mscorlib]System.String::Format(string,
                                                                object,
                                                                object)
    IL_0021:  call       void [mscorlib]System.Console::WriteLine(string)
    IL_0026:  ldloc.1
    IL_0027:  ldc.i4.1
    IL_0028:  add
    IL_0029:  stloc.1
    IL_002a:  ldloc.1
    IL_002b:  ldloc.0
    IL_002c:  ldlen
    IL_002d:  conv.i4
    IL_002e:  blt.s      IL_000b

    IL_0030:  call       void [mscorlib]System.Console::WriteLine()
    IL_0035:  ret
  } // end of method ProxyServer::DumpHeaderCollectionToConsole

  .method private hidebysig static void  DumpHeaderCollectionToConsole(class [mscorlib]System.Collections.Generic.List`1<class [mscorlib]System.Tuple`2<string,string>> headers) cil managed
  {
    // Code size       75 (0x4b)
    .maxstack  3
    .locals init ([0] valuetype [mscorlib]System.Collections.Generic.List`1/Enumerator<class [mscorlib]System.Tuple`2<string,string>> V_0,
             [1] class [mscorlib]System.Tuple`2<string,string> header)
    IL_0000:  ldarg.0
    IL_0001:  callvirt   instance valuetype [mscorlib]System.Collections.Generic.List`1/Enumerator<!0> class [mscorlib]System.Collections.Generic.List`1<class [mscorlib]System.Tuple`2<string,string>>::GetEnumerator()
    IL_0006:  stloc.0
    .try
    {
      IL_0007:  br.s       IL_002c

      IL_0009:  ldloca.s   V_0
      IL_000b:  call       instance !0 valuetype [mscorlib]System.Collections.Generic.List`1/Enumerator<class [mscorlib]System.Tuple`2<string,string>>::get_Current()
      IL_0010:  stloc.1
      IL_0011:  ldstr      "{0}: {1}"
      IL_0016:  ldloc.1
      IL_0017:  callvirt   instance !0 class [mscorlib]System.Tuple`2<string,string>::get_Item1()
      IL_001c:  ldloc.1
      IL_001d:  callvirt   instance !1 class [mscorlib]System.Tuple`2<string,string>::get_Item2()
      IL_0022:  call       string [mscorlib]System.String::Format(string,
                                                                  object,
                                                                  object)
      IL_0027:  call       void [mscorlib]System.Console::WriteLine(string)
      IL_002c:  ldloca.s   V_0
      IL_002e:  call       instance bool valuetype [mscorlib]System.Collections.Generic.List`1/Enumerator<class [mscorlib]System.Tuple`2<string,string>>::MoveNext()
      IL_0033:  brtrue.s   IL_0009

      IL_0035:  leave.s    IL_0045

    }  // end .try
    finally
    {
      IL_0037:  ldloca.s   V_0
      IL_0039:  constrained. valuetype [mscorlib]System.Collections.Generic.List`1/Enumerator<class [mscorlib]System.Tuple`2<string,string>>
      IL_003f:  callvirt   instance void [mscorlib]System.IDisposable::Dispose()
      IL_0044:  endfinally
    }  // end handler
    IL_0045:  call       void [mscorlib]System.Console::WriteLine()
    IL_004a:  ret
  } // end of method ProxyServer::DumpHeaderCollectionToConsole

  .method private hidebysig static int32 
          ReadRequestHeaders(class [mscorlib]System.IO.StreamReader sr,
                             class [System]System.Net.HttpWebRequest webReq) cil managed
  {
    // Code size       659 (0x293)
    .maxstack  4
    .locals init ([0] string httpCmd,
             [1] int32 contentLen,
             [2] string[] header,
             [3] valuetype [mscorlib]System.DateTime d,
             [4] string V_4,
             [5] uint32 V_5,
             [6] class [mscorlib]System.Exception ex)
    IL_0000:  ldc.i4.0
    IL_0001:  stloc.1
    IL_0002:  ldarg.0
    IL_0003:  callvirt   instance string [mscorlib]System.IO.TextReader::ReadLine()
    IL_0008:  stloc.0
    IL_0009:  ldloc.0
    IL_000a:  call       bool [mscorlib]System.String::IsNullOrEmpty(string)
    IL_000f:  brfalse.s  IL_0013

    IL_0011:  ldloc.1
    IL_0012:  ret

    IL_0013:  ldloc.0
    IL_0014:  ldsfld     string[] HTTPProxyServer.ProxyServer::colonSpaceSplit
    IL_0019:  ldc.i4.2
    IL_001a:  ldc.i4.0
    IL_001b:  callvirt   instance string[] [mscorlib]System.String::Split(string[],
                                                                          int32,
                                                                          valuetype [mscorlib]System.StringSplitOptions)
    IL_0020:  stloc.2
    IL_0021:  ldloc.2
    IL_0022:  ldc.i4.0
    IL_0023:  ldelem.ref
    IL_0024:  callvirt   instance string [mscorlib]System.String::ToLower()
    IL_0029:  stloc.s    V_4
    IL_002b:  ldloc.s    V_4
    IL_002d:  call       uint32 '<PrivateImplementationDetails>'::ComputeStringHash(string)
    IL_0032:  stloc.s    V_5
    IL_0034:  ldloc.s    V_5
    IL_0036:  ldc.i4     0x4df9451d
    IL_003b:  bgt.un.s   IL_008c

    IL_003d:  ldloc.s    V_5
    IL_003f:  ldc.i4     0x24259bee
    IL_0044:  bgt.un.s   IL_0063

    IL_0046:  ldloc.s    V_5
    IL_0048:  ldc.i4     0x8247e29
    IL_004d:  beq        IL_010d

    IL_0052:  ldloc.s    V_5
    IL_0054:  ldc.i4     0x24259bee
    IL_0059:  beq        IL_00f7

    IL_005e:  br         IL_0255

    IL_0063:  ldloc.s    V_5
    IL_0065:  ldc.i4     0x32c09da6
    IL_006a:  beq        IL_014f

    IL_006f:  ldloc.s    V_5
    IL_0071:  ldc.i4     0x38b99ed9
    IL_0076:  beq        IL_0165

    IL_007b:  ldloc.s    V_5
    IL_007d:  ldc.i4     0x4df9451d
    IL_0082:  beq        IL_0191

    IL_0087:  br         IL_0255

    IL_008c:  ldloc.s    V_5
    IL_008e:  ldc.i4     0xaffea56f
    IL_0093:  bgt.un.s   IL_00bb

    IL_0095:  ldloc.s    V_5
    IL_0097:  ldc.i4     0x77a740bf
    IL_009c:  beq        IL_0139

    IL_00a1:  ldloc.s    V_5
    IL_00a3:  ldc.i4     0x83e879a9
    IL_00a8:  beq        IL_01b7

    IL_00ad:  ldloc.s    V_5
    IL_00af:  ldc.i4     0xaffea56f
    IL_00b4:  beq.s      IL_00e1

    IL_00b6:  br         IL_0255

    IL_00bb:  ldloc.s    V_5
    IL_00bd:  ldc.i4     0xe18edb80
    IL_00c2:  beq        IL_017b

    IL_00c7:  ldloc.s    V_5
    IL_00c9:  ldc.i4     0xec9af966
    IL_00ce:  beq.s      IL_0123

    IL_00d0:  ldloc.s    V_5
    IL_00d2:  ldc.i4     0xfcf70995
    IL_00d7:  beq        IL_01a4

    IL_00dc:  br         IL_0255

    IL_00e1:  ldloc.s    V_4
    IL_00e3:  ldstr      "host"
    IL_00e8:  call       bool [mscorlib]System.String::op_Equality(string,
                                                                   string)
    IL_00ed:  brtrue     IL_01ca

    IL_00f2:  br         IL_0255

    IL_00f7:  ldloc.s    V_4
    IL_00f9:  ldstr      "user-agent"
    IL_00fe:  call       bool [mscorlib]System.String::op_Equality(string,
                                                                   string)
    IL_0103:  brtrue     IL_01d8

    IL_0108:  br         IL_0255

    IL_010d:  ldloc.s    V_4
    IL_010f:  ldstr      "accept"
    IL_0114:  call       bool [mscorlib]System.String::op_Equality(string,
                                                                   string)
    IL_0119:  brtrue     IL_01e6

    IL_011e:  br         IL_0255

    IL_0123:  ldloc.s    V_4
    IL_0125:  ldstr      "referer"
    IL_012a:  call       bool [mscorlib]System.String::op_Equality(string,
                                                                   string)
    IL_012f:  brtrue     IL_01f4

    IL_0134:  br         IL_0255

    IL_0139:  ldloc.s    V_4
    IL_013b:  ldstr      "cookie"
    IL_0140:  call       bool [mscorlib]System.String::op_Equality(string,
                                                                   string)
    IL_0145:  brtrue     IL_0202

    IL_014a:  br         IL_0255

    IL_014f:  ldloc.s    V_4
    IL_0151:  ldstr      "proxy-connection"
    IL_0156:  call       bool [mscorlib]System.String::op_Equality(string,
                                                                   string)
    IL_015b:  brtrue     IL_0286

    IL_0160:  br         IL_0255

    IL_0165:  ldloc.s    V_4
    IL_0167:  ldstr      "connection"
    IL_016c:  call       bool [mscorlib]System.String::op_Equality(string,
                                                                   string)
    IL_0171:  brtrue     IL_0286

    IL_0176:  br         IL_0255

    IL_017b:  ldloc.s    V_4
    IL_017d:  ldstr      "keep-alive"
    IL_0182:  call       bool [mscorlib]System.String::op_Equality(string,
                                                                   string)
    IL_0187:  brtrue     IL_0286

    IL_018c:  br         IL_0255

    IL_0191:  ldloc.s    V_4
    IL_0193:  ldstr      "content-length"
    IL_0198:  call       bool [mscorlib]System.String::op_Equality(string,
                                                                   string)
    IL_019d:  brtrue.s   IL_0217

    IL_019f:  br         IL_0255

    IL_01a4:  ldloc.s    V_4
    IL_01a6:  ldstr      "content-type"
    IL_01ab:  call       bool [mscorlib]System.String::op_Equality(string,
                                                                   string)
    IL_01b0:  brtrue.s   IL_0224

    IL_01b2:  br         IL_0255

    IL_01b7:  ldloc.s    V_4
    IL_01b9:  ldstr      "if-modified-since"
    IL_01be:  call       bool [mscorlib]System.String::op_Equality(string,
                                                                   string)
    IL_01c3:  brtrue.s   IL_022f

    IL_01c5:  br         IL_0255

    IL_01ca:  ldarg.1
    IL_01cb:  ldloc.2
    IL_01cc:  ldc.i4.1
    IL_01cd:  ldelem.ref
    IL_01ce:  callvirt   instance void [System]System.Net.HttpWebRequest::set_Host(string)
    IL_01d3:  br         IL_0286

    IL_01d8:  ldarg.1
    IL_01d9:  ldloc.2
    IL_01da:  ldc.i4.1
    IL_01db:  ldelem.ref
    IL_01dc:  callvirt   instance void [System]System.Net.HttpWebRequest::set_UserAgent(string)
    IL_01e1:  br         IL_0286

    IL_01e6:  ldarg.1
    IL_01e7:  ldloc.2
    IL_01e8:  ldc.i4.1
    IL_01e9:  ldelem.ref
    IL_01ea:  callvirt   instance void [System]System.Net.HttpWebRequest::set_Accept(string)
    IL_01ef:  br         IL_0286

    IL_01f4:  ldarg.1
    IL_01f5:  ldloc.2
    IL_01f6:  ldc.i4.1
    IL_01f7:  ldelem.ref
    IL_01f8:  callvirt   instance void [System]System.Net.HttpWebRequest::set_Referer(string)
    IL_01fd:  br         IL_0286

    IL_0202:  ldarg.1
    IL_0203:  callvirt   instance class [System]System.Net.WebHeaderCollection [System]System.Net.WebRequest::get_Headers()
    IL_0208:  ldstr      "Cookie"
    IL_020d:  ldloc.2
    IL_020e:  ldc.i4.1
    IL_020f:  ldelem.ref
    IL_0210:  callvirt   instance void [System]System.Collections.Specialized.NameValueCollection::set_Item(string,
                                                                                                            string)
    IL_0215:  br.s       IL_0286

    IL_0217:  ldloc.2
    IL_0218:  ldc.i4.1
    IL_0219:  ldelem.ref
    IL_021a:  ldloca.s   contentLen
    IL_021c:  call       bool [mscorlib]System.Int32::TryParse(string,
                                                               int32&)
    IL_0221:  pop
    IL_0222:  br.s       IL_0286

    IL_0224:  ldarg.1
    IL_0225:  ldloc.2
    IL_0226:  ldc.i4.1
    IL_0227:  ldelem.ref
    IL_0228:  callvirt   instance void [System]System.Net.WebRequest::set_ContentType(string)
    IL_022d:  br.s       IL_0286

    IL_022f:  ldloc.2
    IL_0230:  ldc.i4.1
    IL_0231:  ldelem.ref
    IL_0232:  callvirt   instance string [mscorlib]System.String::Trim()
    IL_0237:  ldsfld     char[] HTTPProxyServer.ProxyServer::semiSplit
    IL_023c:  callvirt   instance string[] [mscorlib]System.String::Split(char[])
    IL_0241:  ldc.i4.0
    IL_0242:  ldelem.ref
    IL_0243:  ldloca.s   d
    IL_0245:  call       bool [mscorlib]System.DateTime::TryParse(string,
                                                                  valuetype [mscorlib]System.DateTime&)
    IL_024a:  brfalse.s  IL_0286

    IL_024c:  ldarg.1
    IL_024d:  ldloc.3
    IL_024e:  callvirt   instance void [System]System.Net.HttpWebRequest::set_IfModifiedSince(valuetype [mscorlib]System.DateTime)
    IL_0253:  br.s       IL_0286

    IL_0255:  nop
    .try
    {
      IL_0256:  ldarg.1
      IL_0257:  callvirt   instance class [System]System.Net.WebHeaderCollection [System]System.Net.WebRequest::get_Headers()
      IL_025c:  ldloc.2
      IL_025d:  ldc.i4.0
      IL_025e:  ldelem.ref
      IL_025f:  ldloc.2
      IL_0260:  ldc.i4.1
      IL_0261:  ldelem.ref
      IL_0262:  callvirt   instance void [System]System.Collections.Specialized.NameValueCollection::Add(string,
                                                                                                         string)
      IL_0267:  leave.s    IL_0286

    }  // end .try
    catch [mscorlib]System.Exception 
    {
      IL_0269:  stloc.s    ex
      IL_026b:  ldstr      "Could not add header {0}.  Exception message:{1}"
      IL_0270:  ldloc.2
      IL_0271:  ldc.i4.0
      IL_0272:  ldelem.ref
      IL_0273:  ldloc.s    ex
      IL_0275:  callvirt   instance string [mscorlib]System.Exception::get_Message()
      IL_027a:  call       string [mscorlib]System.String::Format(string,
                                                                  object,
                                                                  object)
      IL_027f:  call       void [mscorlib]System.Console::WriteLine(string)
      IL_0284:  leave.s    IL_0286

    }  // end handler
    IL_0286:  ldloc.0
    IL_0287:  call       bool [mscorlib]System.String::IsNullOrWhiteSpace(string)
    IL_028c:  brfalse    IL_0002

    IL_0291:  ldloc.1
    IL_0292:  ret
  } // end of method ProxyServer::ReadRequestHeaders

  .method public hidebysig static class [System]System.Security.Cryptography.X509Certificates.X509Certificate2 
          CreateCertificate(string certSubject,
                            bool isCA) cil managed
  {
    // Code size       979 (0x3d3)
    .maxstack  6
    .locals init ([0] string CAsubject,
             [1] class CERTENROLLLib.CX500DistinguishedName dn,
             [2] string strRfc822Name,
             [3] class CERTENROLLLib.CAlternativeName objRfc822Name,
             [4] class CERTENROLLLib.CAlternativeNames objAlternativeNames,
             [5] class CERTENROLLLib.CX509ExtensionAlternativeNames objExtensionAlternativeNames,
             [6] string issuer,
             [7] class CERTENROLLLib.CX500DistinguishedName issuerdn,
             [8] class CERTENROLLLib.CX509PrivateKey key,
             [9] class CERTENROLLLib.CObjectId serverauthoid,
             [10] class CERTENROLLLib.CObjectIds ekuoids,
             [11] class CERTENROLLLib.CX509ExtensionEnhancedKeyUsage ekuext,
             [12] class CERTENROLLLib.CX509CertificateRequestCertificate cert,
             [13] class CERTENROLLLib.CObjectId hashAlgorithmObject,
             [14] string certdata,
             [15] valuetype [mscorlib]System.DateTime V_15,
             [16] class CERTENROLLLib.CX509ExtensionBasicConstraints basicConst,
             [17] class [System]System.Security.Cryptography.X509Certificates.X509Certificate2Collection signer,
             [18] class CERTENROLLLib.CSignerCertificate signerCertificate,
             [19] class [System]System.Security.Cryptography.X509Certificates.X509Certificate2Collection certList,
             [20] class [System]System.Security.Cryptography.X509Certificates.X509Store xstore)
    IL_0000:  ldarg.0
    IL_0001:  stloc.0
    IL_0002:  ldstr      "884E2003-217D-11DA-B2A4-000E7BBB2B09"
    IL_0007:  newobj     instance void [mscorlib]System.Guid::.ctor(string)
    IL_000c:  call       class [mscorlib]System.Type [mscorlib]System.Runtime.InteropServices.Marshal::GetTypeFromCLSID(valuetype [mscorlib]System.Guid)
    IL_0011:  call       object [mscorlib]System.Activator::CreateInstance(class [mscorlib]System.Type)
    IL_0016:  castclass  CERTENROLLLib.CX500DistinguishedName
    IL_001b:  stloc.1
    IL_001c:  ldloc.1
    IL_001d:  ldstr      "CN="
    IL_0022:  ldloc.0
    IL_0023:  call       string [mscorlib]System.String::Concat(string,
                                                                string)
    IL_0028:  ldc.i4.0
    IL_0029:  callvirt   instance void CERTENROLLLib.IX500DistinguishedName::Encode(string,
                                                                                    valuetype CERTENROLLLib.X500NameFlags)
    IL_002e:  ldarg.0
    IL_002f:  stloc.2
    IL_0030:  ldstr      "884E2013-217D-11DA-B2A4-000E7BBB2B09"
    IL_0035:  newobj     instance void [mscorlib]System.Guid::.ctor(string)
    IL_003a:  call       class [mscorlib]System.Type [mscorlib]System.Runtime.InteropServices.Marshal::GetTypeFromCLSID(valuetype [mscorlib]System.Guid)
    IL_003f:  call       object [mscorlib]System.Activator::CreateInstance(class [mscorlib]System.Type)
    IL_0044:  castclass  CERTENROLLLib.CAlternativeName
    IL_0049:  stloc.3
    IL_004a:  ldstr      "884E2014-217D-11DA-B2A4-000E7BBB2B09"
    IL_004f:  newobj     instance void [mscorlib]System.Guid::.ctor(string)
    IL_0054:  call       class [mscorlib]System.Type [mscorlib]System.Runtime.InteropServices.Marshal::GetTypeFromCLSID(valuetype [mscorlib]System.Guid)
    IL_0059:  call       object [mscorlib]System.Activator::CreateInstance(class [mscorlib]System.Type)
    IL_005e:  castclass  CERTENROLLLib.CAlternativeNames
    IL_0063:  stloc.s    objAlternativeNames
    IL_0065:  ldstr      "884E2015-217D-11DA-B2A4-000E7BBB2B09"
    IL_006a:  newobj     instance void [mscorlib]System.Guid::.ctor(string)
    IL_006f:  call       class [mscorlib]System.Type [mscorlib]System.Runtime.InteropServices.Marshal::GetTypeFromCLSID(valuetype [mscorlib]System.Guid)
    IL_0074:  call       object [mscorlib]System.Activator::CreateInstance(class [mscorlib]System.Type)
    IL_0079:  castclass  CERTENROLLLib.CX509ExtensionAlternativeNames
    IL_007e:  stloc.s    objExtensionAlternativeNames
    IL_0080:  ldloc.3
    IL_0081:  ldc.i4.3
    IL_0082:  ldloc.2
    IL_0083:  callvirt   instance void CERTENROLLLib.IAlternativeName::InitializeFromString(valuetype CERTENROLLLib.AlternativeNameType,
                                                                                            string)
    IL_0088:  ldloc.s    objAlternativeNames
    IL_008a:  ldloc.3
    IL_008b:  callvirt   instance void CERTENROLLLib.IAlternativeNames::Add(class CERTENROLLLib.CAlternativeName)
    IL_0090:  ldloc.s    objExtensionAlternativeNames
    IL_0092:  ldloc.s    objAlternativeNames
    IL_0094:  callvirt   instance void CERTENROLLLib.IX509ExtensionAlternativeNames::InitializeEncode(class CERTENROLLLib.CAlternativeNames)
    IL_0099:  ldstr      "__Interceptor_Trusted_Root"
    IL_009e:  stloc.s    issuer
    IL_00a0:  ldstr      "884E2003-217D-11DA-B2A4-000E7BBB2B09"
    IL_00a5:  newobj     instance void [mscorlib]System.Guid::.ctor(string)
    IL_00aa:  call       class [mscorlib]System.Type [mscorlib]System.Runtime.InteropServices.Marshal::GetTypeFromCLSID(valuetype [mscorlib]System.Guid)
    IL_00af:  call       object [mscorlib]System.Activator::CreateInstance(class [mscorlib]System.Type)
    IL_00b4:  castclass  CERTENROLLLib.CX500DistinguishedName
    IL_00b9:  stloc.s    issuerdn
    IL_00bb:  ldloc.s    issuerdn
    IL_00bd:  ldstr      "CN="
    IL_00c2:  ldloc.s    issuer
    IL_00c4:  call       string [mscorlib]System.String::Concat(string,
                                                                string)
    IL_00c9:  ldc.i4.0
    IL_00ca:  callvirt   instance void CERTENROLLLib.IX500DistinguishedName::Encode(string,
                                                                                    valuetype CERTENROLLLib.X500NameFlags)
    IL_00cf:  ldstr      "884E200C-217D-11DA-B2A4-000E7BBB2B09"
    IL_00d4:  newobj     instance void [mscorlib]System.Guid::.ctor(string)
    IL_00d9:  call       class [mscorlib]System.Type [mscorlib]System.Runtime.InteropServices.Marshal::GetTypeFromCLSID(valuetype [mscorlib]System.Guid)
    IL_00de:  call       object [mscorlib]System.Activator::CreateInstance(class [mscorlib]System.Type)
    IL_00e3:  castclass  CERTENROLLLib.CX509PrivateKey
    IL_00e8:  stloc.s    key
    IL_00ea:  ldloc.s    key
    IL_00ec:  ldstr      "Microsoft Enhanced RSA and AES Cryptographic Provi"
    + "der"
    IL_00f1:  callvirt   instance void CERTENROLLLib.IX509PrivateKey2::set_ProviderName(string)
    IL_00f6:  ldarg.1
    IL_00f7:  brfalse.s  IL_0103

    IL_00f9:  ldloc.s    key
    IL_00fb:  ldc.i4.2
    IL_00fc:  callvirt   instance void CERTENROLLLib.IX509PrivateKey2::set_KeySpec(valuetype CERTENROLLLib.X509KeySpec)
    IL_0101:  br.s       IL_010b

    IL_0103:  ldloc.s    key
    IL_0105:  ldc.i4.1
    IL_0106:  callvirt   instance void CERTENROLLLib.IX509PrivateKey2::set_KeySpec(valuetype CERTENROLLLib.X509KeySpec)
    IL_010b:  ldloc.s    key
    IL_010d:  ldc.i4     0x800
    IL_0112:  callvirt   instance void CERTENROLLLib.IX509PrivateKey2::set_Length(int32)
    IL_0117:  ldloc.s    key
    IL_0119:  ldc.i4.1
    IL_011a:  callvirt   instance void CERTENROLLLib.IX509PrivateKey2::set_MachineContext(bool)
    IL_011f:  ldloc.s    key
    IL_0121:  callvirt   instance void CERTENROLLLib.IX509PrivateKey2::Create()
    IL_0126:  ldstr      "884E2000-217D-11DA-B2A4-000E7BBB2B09"
    IL_012b:  newobj     instance void [mscorlib]System.Guid::.ctor(string)
    IL_0130:  call       class [mscorlib]System.Type [mscorlib]System.Runtime.InteropServices.Marshal::GetTypeFromCLSID(valuetype [mscorlib]System.Guid)
    IL_0135:  call       object [mscorlib]System.Activator::CreateInstance(class [mscorlib]System.Type)
    IL_013a:  castclass  CERTENROLLLib.CObjectId
    IL_013f:  stloc.s    serverauthoid
    IL_0141:  ldloc.s    serverauthoid
    IL_0143:  ldstr      "1.3.6.1.5.5.7.3.1"
    IL_0148:  callvirt   instance void CERTENROLLLib.IObjectId::InitializeFromValue(string)
    IL_014d:  ldstr      "884E2001-217D-11DA-B2A4-000E7BBB2B09"
    IL_0152:  newobj     instance void [mscorlib]System.Guid::.ctor(string)
    IL_0157:  call       class [mscorlib]System.Type [mscorlib]System.Runtime.InteropServices.Marshal::GetTypeFromCLSID(valuetype [mscorlib]System.Guid)
    IL_015c:  call       object [mscorlib]System.Activator::CreateInstance(class [mscorlib]System.Type)
    IL_0161:  castclass  CERTENROLLLib.CObjectIds
    IL_0166:  stloc.s    ekuoids
    IL_0168:  ldloc.s    ekuoids
    IL_016a:  ldloc.s    serverauthoid
    IL_016c:  callvirt   instance void CERTENROLLLib.IObjectIds::Add(class CERTENROLLLib.CObjectId)
    IL_0171:  ldstr      "884E2010-217D-11DA-B2A4-000E7BBB2B09"
    IL_0176:  newobj     instance void [mscorlib]System.Guid::.ctor(string)
    IL_017b:  call       class [mscorlib]System.Type [mscorlib]System.Runtime.InteropServices.Marshal::GetTypeFromCLSID(valuetype [mscorlib]System.Guid)
    IL_0180:  call       object [mscorlib]System.Activator::CreateInstance(class [mscorlib]System.Type)
    IL_0185:  castclass  CERTENROLLLib.CX509ExtensionEnhancedKeyUsage
    IL_018a:  stloc.s    ekuext
    IL_018c:  ldloc.s    ekuext
    IL_018e:  ldloc.s    ekuoids
    IL_0190:  callvirt   instance void CERTENROLLLib.IX509ExtensionEnhancedKeyUsage::InitializeEncode(class CERTENROLLLib.CObjectIds)
    IL_0195:  ldstr      "884E2043-217D-11DA-B2A4-000E7BBB2B09"
    IL_019a:  newobj     instance void [mscorlib]System.Guid::.ctor(string)
    IL_019f:  call       class [mscorlib]System.Type [mscorlib]System.Runtime.InteropServices.Marshal::GetTypeFromCLSID(valuetype [mscorlib]System.Guid)
    IL_01a4:  call       object [mscorlib]System.Activator::CreateInstance(class [mscorlib]System.Type)
    IL_01a9:  castclass  CERTENROLLLib.CX509CertificateRequestCertificate
    IL_01ae:  stloc.s    cert
    IL_01b0:  ldloc.s    cert
    IL_01b2:  ldc.i4.2
    IL_01b3:  ldloc.s    key
    IL_01b5:  ldstr      ""
    IL_01ba:  callvirt   instance void CERTENROLLLib.IX509CertificateRequestCertificate2::InitializeFromPrivateKey(valuetype CERTENROLLLib.X509CertificateEnrollmentContext,
                                                                                                                   class CERTENROLLLib.IX509PrivateKey,
                                                                                                                   string)
    IL_01bf:  ldloc.s    cert
    IL_01c1:  ldloc.1
    IL_01c2:  callvirt   instance void CERTENROLLLib.IX509CertificateRequestCertificate2::set_Subject(class CERTENROLLLib.CX500DistinguishedName)
    IL_01c7:  ldloc.s    cert
    IL_01c9:  ldloc.s    issuerdn
    IL_01cb:  callvirt   instance void CERTENROLLLib.IX509CertificateRequestCertificate2::set_Issuer(class CERTENROLLLib.CX500DistinguishedName)
    IL_01d0:  ldloc.s    cert
    IL_01d2:  call       valuetype [mscorlib]System.DateTime [mscorlib]System.DateTime::get_Now()
    IL_01d7:  stloc.s    V_15
    IL_01d9:  ldloca.s   V_15
    IL_01db:  ldc.r8     -1.
    IL_01e4:  call       instance valuetype [mscorlib]System.DateTime [mscorlib]System.DateTime::AddDays(float64)
    IL_01e9:  callvirt   instance void CERTENROLLLib.IX509CertificateRequestCertificate2::set_NotBefore(valuetype [mscorlib]System.DateTime)
    IL_01ee:  ldloc.s    cert
    IL_01f0:  ldloc.s    cert
    IL_01f2:  callvirt   instance valuetype [mscorlib]System.DateTime CERTENROLLLib.IX509CertificateRequestCertificate2::get_NotBefore()
    IL_01f7:  stloc.s    V_15
    IL_01f9:  ldloca.s   V_15
    IL_01fb:  ldc.r8     90.
    IL_0204:  call       instance valuetype [mscorlib]System.DateTime [mscorlib]System.DateTime::AddDays(float64)
    IL_0209:  callvirt   instance void CERTENROLLLib.IX509CertificateRequestCertificate2::set_NotAfter(valuetype [mscorlib]System.DateTime)
    IL_020e:  ldstr      "884E2000-217D-11DA-B2A4-000E7BBB2B09"
    IL_0213:  newobj     instance void [mscorlib]System.Guid::.ctor(string)
    IL_0218:  call       class [mscorlib]System.Type [mscorlib]System.Runtime.InteropServices.Marshal::GetTypeFromCLSID(valuetype [mscorlib]System.Guid)
    IL_021d:  call       object [mscorlib]System.Activator::CreateInstance(class [mscorlib]System.Type)
    IL_0222:  castclass  CERTENROLLLib.CObjectId
    IL_0227:  stloc.s    hashAlgorithmObject
    IL_0229:  ldloc.s    hashAlgorithmObject
    IL_022b:  ldc.i4.1
    IL_022c:  ldc.i4.0
    IL_022d:  ldc.i4.0
    IL_022e:  ldstr      "SHA256"
    IL_0233:  callvirt   instance void CERTENROLLLib.IObjectId::InitializeFromAlgorithmName(valuetype CERTENROLLLib.ObjectIdGroupId,
                                                                                            valuetype CERTENROLLLib.ObjectIdPublicKeyFlags,
                                                                                            valuetype CERTENROLLLib.AlgorithmFlags,
                                                                                            string)
    IL_0238:  ldloc.s    cert
    IL_023a:  ldloc.s    hashAlgorithmObject
    IL_023c:  callvirt   instance void CERTENROLLLib.IX509CertificateRequestCertificate2::set_HashAlgorithm(class CERTENROLLLib.CObjectId)
    IL_0241:  ldloc.s    cert
    IL_0243:  callvirt   instance class CERTENROLLLib.CX509Extensions CERTENROLLLib.IX509CertificateRequestCertificate2::get_X509Extensions()
    IL_0248:  ldloc.s    ekuext
    IL_024a:  castclass  CERTENROLLLib.CX509Extension
    IL_024f:  callvirt   instance void CERTENROLLLib.IX509Extensions::Add(class CERTENROLLLib.CX509Extension)
    IL_0254:  ldloc.s    cert
    IL_0256:  callvirt   instance class CERTENROLLLib.CX509Extensions CERTENROLLLib.IX509CertificateRequestCertificate2::get_X509Extensions()
    IL_025b:  ldloc.s    objExtensionAlternativeNames
    IL_025d:  castclass  CERTENROLLLib.CX509Extension
    IL_0262:  callvirt   instance void CERTENROLLLib.IX509Extensions::Add(class CERTENROLLLib.CX509Extension)
    IL_0267:  ldarg.1
    IL_0268:  brfalse.s  IL_02a3

    IL_026a:  ldstr      "884E2016-217D-11DA-B2A4-000E7BBB2B09"
    IL_026f:  newobj     instance void [mscorlib]System.Guid::.ctor(string)
    IL_0274:  call       class [mscorlib]System.Type [mscorlib]System.Runtime.InteropServices.Marshal::GetTypeFromCLSID(valuetype [mscorlib]System.Guid)
    IL_0279:  call       object [mscorlib]System.Activator::CreateInstance(class [mscorlib]System.Type)
    IL_027e:  castclass  CERTENROLLLib.CX509ExtensionBasicConstraints
    IL_0283:  stloc.s    basicConst
    IL_0285:  ldloc.s    basicConst
    IL_0287:  ldc.i4.1
    IL_0288:  ldc.i4.1
    IL_0289:  callvirt   instance void CERTENROLLLib.IX509ExtensionBasicConstraints::InitializeEncode(bool,
                                                                                                      int32)
    IL_028e:  ldloc.s    cert
    IL_0290:  callvirt   instance class CERTENROLLLib.CX509Extensions CERTENROLLLib.IX509CertificateRequestCertificate2::get_X509Extensions()
    IL_0295:  ldloc.s    basicConst
    IL_0297:  castclass  CERTENROLLLib.CX509Extension
    IL_029c:  callvirt   instance void CERTENROLLLib.IX509Extensions::Add(class CERTENROLLLib.CX509Extension)
    IL_02a1:  br.s       IL_02ff

    IL_02a3:  ldc.i4.5
    IL_02a4:  ldc.i4.2
    IL_02a5:  newobj     instance void [System]System.Security.Cryptography.X509Certificates.X509Store::.ctor(valuetype [System]System.Security.Cryptography.X509Certificates.StoreName,
                                                                                                              valuetype [System]System.Security.Cryptography.X509Certificates.StoreLocation)
    IL_02aa:  dup
    IL_02ab:  ldc.i4.0
    IL_02ac:  callvirt   instance void [System]System.Security.Cryptography.X509Certificates.X509Store::Open(valuetype [System]System.Security.Cryptography.X509Certificates.OpenFlags)
    IL_02b1:  callvirt   instance class [System]System.Security.Cryptography.X509Certificates.X509Certificate2Collection [System]System.Security.Cryptography.X509Certificates.X509Store::get_Certificates()
    IL_02b6:  ldc.i4.1
    IL_02b7:  ldstr      "__Interceptor_Trusted_Root"
    IL_02bc:  ldc.i4.0
    IL_02bd:  callvirt   instance class [System]System.Security.Cryptography.X509Certificates.X509Certificate2Collection [System]System.Security.Cryptography.X509Certificates.X509Certificate2Collection::Find(valuetype [System]System.Security.Cryptography.X509Certificates.X509FindType,
                                                                                                                                                                                                                object,
                                                                                                                                                                                                                bool)
    IL_02c2:  stloc.s    signer
    IL_02c4:  ldstr      "884E203D-217D-11DA-B2A4-000E7BBB2B09"
    IL_02c9:  newobj     instance void [mscorlib]System.Guid::.ctor(string)
    IL_02ce:  call       class [mscorlib]System.Type [mscorlib]System.Runtime.InteropServices.Marshal::GetTypeFromCLSID(valuetype [mscorlib]System.Guid)
    IL_02d3:  call       object [mscorlib]System.Activator::CreateInstance(class [mscorlib]System.Type)
    IL_02d8:  castclass  CERTENROLLLib.CSignerCertificate
    IL_02dd:  stloc.s    signerCertificate
    IL_02df:  ldloc.s    signerCertificate
    IL_02e1:  ldc.i4.1
    IL_02e2:  ldc.i4.0
    IL_02e3:  ldc.i4.4
    IL_02e4:  ldloc.s    signer
    IL_02e6:  ldc.i4.0
    IL_02e7:  callvirt   instance class [System]System.Security.Cryptography.X509Certificates.X509Certificate2 [System]System.Security.Cryptography.X509Certificates.X509Certificate2Collection::get_Item(int32)
    IL_02ec:  callvirt   instance string [System]System.Security.Cryptography.X509Certificates.X509Certificate2::get_Thumbprint()
    IL_02f1:  callvirt   instance void CERTENROLLLib.ISignerCertificate::Initialize(bool,
                                                                                    valuetype CERTENROLLLib.X509PrivateKeyVerify,
                                                                                    valuetype CERTENROLLLib.EncodingType,
                                                                                    string)
    IL_02f6:  ldloc.s    cert
    IL_02f8:  ldloc.s    signerCertificate
    IL_02fa:  callvirt   instance void CERTENROLLLib.IX509CertificateRequestCertificate2::set_SignerCertificate(class CERTENROLLLib.CSignerCertificate)
    IL_02ff:  ldloc.s    cert
    IL_0301:  callvirt   instance void CERTENROLLLib.IX509CertificateRequestCertificate2::Encode()
    IL_0306:  ldstr      "884E2046-217D-11DA-B2A4-000E7BBB2B09"
    IL_030b:  newobj     instance void [mscorlib]System.Guid::.ctor(string)
    IL_0310:  call       class [mscorlib]System.Type [mscorlib]System.Runtime.InteropServices.Marshal::GetTypeFromCLSID(valuetype [mscorlib]System.Guid)
    IL_0315:  call       object [mscorlib]System.Activator::CreateInstance(class [mscorlib]System.Type)
    IL_031a:  castclass  CERTENROLLLib.CX509Enrollment
    IL_031f:  dup
    IL_0320:  ldloc.s    cert
    IL_0322:  callvirt   instance void CERTENROLLLib.IX509Enrollment2::InitializeFromRequest(class CERTENROLLLib.IX509CertificateRequest)
    IL_0327:  dup
    IL_0328:  ldc.i4.0
    IL_0329:  callvirt   instance string CERTENROLLLib.IX509Enrollment2::CreateRequest(valuetype CERTENROLLLib.EncodingType)
    IL_032e:  stloc.s    certdata
    IL_0330:  ldc.i4.2
    IL_0331:  ldloc.s    certdata
    IL_0333:  ldc.i4.0
    IL_0334:  ldstr      ""
    IL_0339:  callvirt   instance void CERTENROLLLib.IX509Enrollment2::InstallResponse(valuetype CERTENROLLLib.InstallResponseRestrictionFlags,
                                                                                       string,
                                                                                       valuetype CERTENROLLLib.EncodingType,
                                                                                       string)
    IL_033e:  ldarg.1
    IL_033f:  brfalse.s  IL_03a5

    IL_0341:  ldc.i4.5
    IL_0342:  ldc.i4.2
    IL_0343:  newobj     instance void [System]System.Security.Cryptography.X509Certificates.X509Store::.ctor(valuetype [System]System.Security.Cryptography.X509Certificates.StoreName,
                                                                                                              valuetype [System]System.Security.Cryptography.X509Certificates.StoreLocation)
    IL_0348:  dup
    IL_0349:  ldc.i4.0
    IL_034a:  callvirt   instance void [System]System.Security.Cryptography.X509Certificates.X509Store::Open(valuetype [System]System.Security.Cryptography.X509Certificates.OpenFlags)
    IL_034f:  dup
    IL_0350:  callvirt   instance class [System]System.Security.Cryptography.X509Certificates.X509Certificate2Collection [System]System.Security.Cryptography.X509Certificates.X509Store::get_Certificates()
    IL_0355:  ldc.i4.1
    IL_0356:  ldstr      "__Interceptor_Trusted_Root"
    IL_035b:  ldc.i4.0
    IL_035c:  callvirt   instance class [System]System.Security.Cryptography.X509Certificates.X509Certificate2Collection [System]System.Security.Cryptography.X509Certificates.X509Certificate2Collection::Find(valuetype [System]System.Security.Cryptography.X509Certificates.X509FindType,
                                                                                                                                                                                                                object,
                                                                                                                                                                                                                bool)
    IL_0361:  stloc.s    certList
    IL_0363:  callvirt   instance void [System]System.Security.Cryptography.X509Certificates.X509Store::Close()
    IL_0368:  ldc.i4.6
    IL_0369:  ldc.i4.2
    IL_036a:  newobj     instance void [System]System.Security.Cryptography.X509Certificates.X509Store::.ctor(valuetype [System]System.Security.Cryptography.X509Certificates.StoreName,
                                                                                                              valuetype [System]System.Security.Cryptography.X509Certificates.StoreLocation)
    IL_036f:  dup
    IL_0370:  ldc.i4.1
    IL_0371:  callvirt   instance void [System]System.Security.Cryptography.X509Certificates.X509Store::Open(valuetype [System]System.Security.Cryptography.X509Certificates.OpenFlags)
    IL_0376:  dup
    IL_0377:  callvirt   instance class [System]System.Security.Cryptography.X509Certificates.X509Certificate2Collection [System]System.Security.Cryptography.X509Certificates.X509Store::get_Certificates()
    IL_037c:  ldc.i4.1
    IL_037d:  ldstr      "__Interceptor_Trusted_Root"
    IL_0382:  ldc.i4.0
    IL_0383:  callvirt   instance class [System]System.Security.Cryptography.X509Certificates.X509Certificate2Collection [System]System.Security.Cryptography.X509Certificates.X509Certificate2Collection::Find(valuetype [System]System.Security.Cryptography.X509Certificates.X509FindType,
                                                                                                                                                                                                                object,
                                                                                                                                                                                                                bool)
    IL_0388:  pop
    IL_0389:  dup
    IL_038a:  ldloc.s    certList
    IL_038c:  ldc.i4.0
    IL_038d:  callvirt   instance class [System]System.Security.Cryptography.X509Certificates.X509Certificate2 [System]System.Security.Cryptography.X509Certificates.X509Certificate2Collection::get_Item(int32)
    IL_0392:  callvirt   instance void [System]System.Security.Cryptography.X509Certificates.X509Store::Add(class [System]System.Security.Cryptography.X509Certificates.X509Certificate2)
    IL_0397:  callvirt   instance void [System]System.Security.Cryptography.X509Certificates.X509Store::Close()
    IL_039c:  ldloc.s    certList
    IL_039e:  ldc.i4.0
    IL_039f:  callvirt   instance class [System]System.Security.Cryptography.X509Certificates.X509Certificate2 [System]System.Security.Cryptography.X509Certificates.X509Certificate2Collection::get_Item(int32)
    IL_03a4:  ret

    IL_03a5:  ldc.i4.5
    IL_03a6:  ldc.i4.2
    IL_03a7:  newobj     instance void [System]System.Security.Cryptography.X509Certificates.X509Store::.ctor(valuetype [System]System.Security.Cryptography.X509Certificates.StoreName,
                                                                                                              valuetype [System]System.Security.Cryptography.X509Certificates.StoreLocation)
    IL_03ac:  stloc.s    xstore
    IL_03ae:  ldloc.s    xstore
    IL_03b0:  ldc.i4.0
    IL_03b1:  callvirt   instance void [System]System.Security.Cryptography.X509Certificates.X509Store::Open(valuetype [System]System.Security.Cryptography.X509Certificates.OpenFlags)
    IL_03b6:  ldloc.s    xstore
    IL_03b8:  callvirt   instance class [System]System.Security.Cryptography.X509Certificates.X509Certificate2Collection [System]System.Security.Cryptography.X509Certificates.X509Store::get_Certificates()
    IL_03bd:  ldc.i4.1
    IL_03be:  ldarg.0
    IL_03bf:  ldc.i4.0
    IL_03c0:  callvirt   instance class [System]System.Security.Cryptography.X509Certificates.X509Certificate2Collection [System]System.Security.Cryptography.X509Certificates.X509Certificate2Collection::Find(valuetype [System]System.Security.Cryptography.X509Certificates.X509FindType,
                                                                                                                                                                                                                object,
                                                                                                                                                                                                                bool)
    IL_03c5:  ldloc.s    xstore
    IL_03c7:  callvirt   instance void [System]System.Security.Cryptography.X509Certificates.X509Store::Close()
    IL_03cc:  ldc.i4.0
    IL_03cd:  callvirt   instance class [System]System.Security.Cryptography.X509Certificates.X509Certificate2 [System]System.Security.Cryptography.X509Certificates.X509Certificate2Collection::get_Item(int32)
    IL_03d2:  ret
  } // end of method ProxyServer::CreateCertificate

  .method public hidebysig static int32  CertificateCleanup(string name) cil managed
  {
    // Code size       177 (0xb1)
    .maxstack  4
    .locals init ([0] class [System]System.Security.Cryptography.X509Certificates.X509Store mystore,
             [1] class [System]System.Security.Cryptography.X509Certificates.X509Store mystoreroot,
             [2] class [System]System.Security.Cryptography.X509Certificates.X509Certificate2Enumerator V_2,
             [3] class [System]System.Security.Cryptography.X509Certificates.X509Certificate2 certlst,
             [4] class [System]System.Security.Cryptography.X509Certificates.X509Certificate2 V_4)
    IL_0000:  ldc.i4.5
    IL_0001:  ldc.i4.2
    IL_0002:  newobj     instance void [System]System.Security.Cryptography.X509Certificates.X509Store::.ctor(valuetype [System]System.Security.Cryptography.X509Certificates.StoreName,
                                                                                                              valuetype [System]System.Security.Cryptography.X509Certificates.StoreLocation)
    IL_0007:  stloc.0
    IL_0008:  ldloc.0
    IL_0009:  ldc.i4.2
    IL_000a:  callvirt   instance void [System]System.Security.Cryptography.X509Certificates.X509Store::Open(valuetype [System]System.Security.Cryptography.X509Certificates.OpenFlags)
    IL_000f:  ldloc.0
    IL_0010:  callvirt   instance class [System]System.Security.Cryptography.X509Certificates.X509Certificate2Collection [System]System.Security.Cryptography.X509Certificates.X509Store::get_Certificates()
    IL_0015:  ldc.i4.3
    IL_0016:  ldarg.0
    IL_0017:  ldc.i4.0
    IL_0018:  callvirt   instance class [System]System.Security.Cryptography.X509Certificates.X509Certificate2Collection [System]System.Security.Cryptography.X509Certificates.X509Certificate2Collection::Find(valuetype [System]System.Security.Cryptography.X509Certificates.X509FindType,
                                                                                                                                                                                                                object,
                                                                                                                                                                                                                bool)
    IL_001d:  callvirt   instance class [System]System.Security.Cryptography.X509Certificates.X509Certificate2Enumerator [System]System.Security.Cryptography.X509Certificates.X509Certificate2Collection::GetEnumerator()
    IL_0022:  stloc.2
    IL_0023:  br.s       IL_0048

    IL_0025:  ldloc.2
    IL_0026:  callvirt   instance class [System]System.Security.Cryptography.X509Certificates.X509Certificate2 [System]System.Security.Cryptography.X509Certificates.X509Certificate2Enumerator::get_Current()
    IL_002b:  stloc.3
    IL_002c:  call       class [mscorlib]System.IO.TextWriter [mscorlib]System.Console::get_Out()
    IL_0031:  ldstr      "Cleanup {0} "
    IL_0036:  ldloc.3
    IL_0037:  callvirt   instance class [System]System.Security.Cryptography.X509Certificates.X500DistinguishedName [System]System.Security.Cryptography.X509Certificates.X509Certificate2::get_SubjectName()
    IL_003c:  callvirt   instance void [mscorlib]System.IO.TextWriter::WriteLine(string,
                                                                                 object)
    IL_0041:  ldloc.0
    IL_0042:  ldloc.3
    IL_0043:  callvirt   instance void [System]System.Security.Cryptography.X509Certificates.X509Store::Remove(class [System]System.Security.Cryptography.X509Certificates.X509Certificate2)
    IL_0048:  ldloc.2
    IL_0049:  callvirt   instance bool [System]System.Security.Cryptography.X509Certificates.X509Certificate2Enumerator::MoveNext()
    IL_004e:  brtrue.s   IL_0025

    IL_0050:  ldloc.0
    IL_0051:  callvirt   instance void [System]System.Security.Cryptography.X509Certificates.X509Store::Close()
    IL_0056:  ldc.i4.6
    IL_0057:  ldc.i4.2
    IL_0058:  newobj     instance void [System]System.Security.Cryptography.X509Certificates.X509Store::.ctor(valuetype [System]System.Security.Cryptography.X509Certificates.StoreName,
                                                                                                              valuetype [System]System.Security.Cryptography.X509Certificates.StoreLocation)
    IL_005d:  stloc.1
    IL_005e:  ldloc.1
    IL_005f:  ldc.i4.2
    IL_0060:  callvirt   instance void [System]System.Security.Cryptography.X509Certificates.X509Store::Open(valuetype [System]System.Security.Cryptography.X509Certificates.OpenFlags)
    IL_0065:  ldloc.1
    IL_0066:  callvirt   instance class [System]System.Security.Cryptography.X509Certificates.X509Certificate2Collection [System]System.Security.Cryptography.X509Certificates.X509Store::get_Certificates()
    IL_006b:  ldc.i4.1
    IL_006c:  ldarg.0
    IL_006d:  ldc.i4.0
    IL_006e:  callvirt   instance class [System]System.Security.Cryptography.X509Certificates.X509Certificate2Collection [System]System.Security.Cryptography.X509Certificates.X509Certificate2Collection::Find(valuetype [System]System.Security.Cryptography.X509Certificates.X509FindType,
                                                                                                                                                                                                                object,
                                                                                                                                                                                                                bool)
    IL_0073:  callvirt   instance class [System]System.Security.Cryptography.X509Certificates.X509Certificate2Enumerator [System]System.Security.Cryptography.X509Certificates.X509Certificate2Collection::GetEnumerator()
    IL_0078:  stloc.2
    IL_0079:  br.s       IL_00a1

    IL_007b:  ldloc.2
    IL_007c:  callvirt   instance class [System]System.Security.Cryptography.X509Certificates.X509Certificate2 [System]System.Security.Cryptography.X509Certificates.X509Certificate2Enumerator::get_Current()
    IL_0081:  stloc.s    V_4
    IL_0083:  call       class [mscorlib]System.IO.TextWriter [mscorlib]System.Console::get_Out()
    IL_0088:  ldstr      "Cleanup {0} "
    IL_008d:  ldloc.s    V_4
    IL_008f:  callvirt   instance class [System]System.Security.Cryptography.X509Certificates.X500DistinguishedName [System]System.Security.Cryptography.X509Certificates.X509Certificate2::get_SubjectName()
    IL_0094:  callvirt   instance void [mscorlib]System.IO.TextWriter::WriteLine(string,
                                                                                 object)
    IL_0099:  ldloc.1
    IL_009a:  ldloc.s    V_4
    IL_009c:  callvirt   instance void [System]System.Security.Cryptography.X509Certificates.X509Store::Remove(class [System]System.Security.Cryptography.X509Certificates.X509Certificate2)
    IL_00a1:  ldloc.2
    IL_00a2:  callvirt   instance bool [System]System.Security.Cryptography.X509Certificates.X509Certificate2Enumerator::MoveNext()
    IL_00a7:  brtrue.s   IL_007b

    IL_00a9:  ldloc.1
    IL_00aa:  callvirt   instance void [System]System.Security.Cryptography.X509Certificates.X509Store::Close()
    IL_00af:  ldc.i4.0
    IL_00b0:  ret
  } // end of method ProxyServer::CertificateCleanup

  .method public hidebysig static class [System]System.Security.Cryptography.X509Certificates.X509Certificate2 
          CertificateSubjectNameLookup(string subjectName) cil managed
  {
    // Code size       53 (0x35)
    .maxstack  4
    .locals init ([0] class [System]System.Security.Cryptography.X509Certificates.X509Certificate2Collection col)
    IL_0000:  ldc.i4.5
    IL_0001:  ldc.i4.2
    IL_0002:  newobj     instance void [System]System.Security.Cryptography.X509Certificates.X509Store::.ctor(valuetype [System]System.Security.Cryptography.X509Certificates.StoreName,
                                                                                                              valuetype [System]System.Security.Cryptography.X509Certificates.StoreLocation)
    IL_0007:  dup
    IL_0008:  ldc.i4.s   9
    IL_000a:  callvirt   instance void [System]System.Security.Cryptography.X509Certificates.X509Store::Open(valuetype [System]System.Security.Cryptography.X509Certificates.OpenFlags)
    IL_000f:  callvirt   instance class [System]System.Security.Cryptography.X509Certificates.X509Certificate2Collection [System]System.Security.Cryptography.X509Certificates.X509Store::get_Certificates()
    IL_0014:  ldc.i4.1
    IL_0015:  ldarg.0
    IL_0016:  ldc.i4.0
    IL_0017:  callvirt   instance class [System]System.Security.Cryptography.X509Certificates.X509Certificate2Collection [System]System.Security.Cryptography.X509Certificates.X509Certificate2Collection::Find(valuetype [System]System.Security.Cryptography.X509Certificates.X509FindType,
                                                                                                                                                                                                                object,
                                                                                                                                                                                                                bool)
    IL_001c:  stloc.0
    IL_001d:  ldloc.0
    IL_001e:  callvirt   instance int32 [mscorlib]System.Collections.CollectionBase::get_Count()
    IL_0023:  brtrue.s   IL_002d

    IL_0025:  ldarg.0
    IL_0026:  ldc.i4.0
    IL_0027:  call       class [System]System.Security.Cryptography.X509Certificates.X509Certificate2 HTTPProxyServer.ProxyServer::CreateCertificate(string,
                                                                                                                                                     bool)
    IL_002c:  ret

    IL_002d:  ldloc.0
    IL_002e:  ldc.i4.0
    IL_002f:  callvirt   instance class [System]System.Security.Cryptography.X509Certificates.X509Certificate2 [System]System.Security.Cryptography.X509Certificates.X509Certificate2Collection::get_Item(int32)
    IL_0034:  ret
  } // end of method ProxyServer::CertificateSubjectNameLookup

  .method private hidebysig specialname rtspecialname static 
          void  .cctor() cil managed
  {
    // Code size       160 (0xa0)
    .maxstack  4
    IL_0000:  newobj     instance void HTTPProxyServer.ProxyServer::.ctor()
    IL_0005:  stsfld     class HTTPProxyServer.ProxyServer HTTPProxyServer.ProxyServer::_server
    IL_000a:  ldc.i4     0x2000
    IL_000f:  stsfld     int32 HTTPProxyServer.ProxyServer::BUFFER_SIZE
    IL_0014:  ldc.i4.1
    IL_0015:  newarr     [mscorlib]System.Char
    IL_001a:  dup
    IL_001b:  ldc.i4.0
    IL_001c:  ldc.i4.s   59
    IL_001e:  stelem.i2
    IL_001f:  stsfld     char[] HTTPProxyServer.ProxyServer::semiSplit
    IL_0024:  ldc.i4.1
    IL_0025:  newarr     [mscorlib]System.Char
    IL_002a:  dup
    IL_002b:  ldc.i4.0
    IL_002c:  ldc.i4.s   61
    IL_002e:  stelem.i2
    IL_002f:  stsfld     char[] HTTPProxyServer.ProxyServer::equalSplit
    IL_0034:  ldc.i4.1
    IL_0035:  newarr     [mscorlib]System.String
    IL_003a:  dup
    IL_003b:  ldc.i4.0
    IL_003c:  ldstr      ": "
    IL_0041:  stelem.ref
    IL_0042:  stsfld     string[] HTTPProxyServer.ProxyServer::colonSpaceSplit
    IL_0047:  ldc.i4.1
    IL_0048:  newarr     [mscorlib]System.Char
    IL_004d:  dup
    IL_004e:  ldc.i4.0
    IL_004f:  ldc.i4.s   32
    IL_0051:  stelem.i2
    IL_0052:  stsfld     char[] HTTPProxyServer.ProxyServer::spaceSplit
    IL_0057:  ldc.i4.1
    IL_0058:  newarr     [mscorlib]System.Char
    IL_005d:  dup
    IL_005e:  ldc.i4.0
    IL_005f:  ldc.i4.s   44
    IL_0061:  stelem.i2
    IL_0062:  stsfld     char[] HTTPProxyServer.ProxyServer::commaSplit
    IL_0067:  ldc.i4.1
    IL_0068:  newarr     [mscorlib]System.Char
    IL_006d:  dup
    IL_006e:  ldc.i4.0
    IL_006f:  ldc.i4.s   58
    IL_0071:  stelem.i2
    IL_0072:  stsfld     char[] HTTPProxyServer.ProxyServer::colonSplit
    IL_0077:  ldstr      ",(\?! )"
    IL_007c:  newobj     instance void [System]System.Text.RegularExpressions.Regex::.ctor(string)
    IL_0081:  stsfld     class [System]System.Text.RegularExpressions.Regex HTTPProxyServer.ProxyServer::cookieSplitRegEx
    IL_0086:  ldstr      "__Interceptor_Trusted_Root"
    IL_008b:  call       class [System]System.Security.Cryptography.X509Certificates.X509Certificate2 HTTPProxyServer.ProxyServer::CertificateSubjectNameLookup(string)
    IL_0090:  stsfld     class [System]System.Security.Cryptography.X509Certificates.X509Certificate2 HTTPProxyServer.ProxyServer::_certCA
    IL_0095:  newobj     instance void [mscorlib]System.Object::.ctor()
    IL_009a:  stsfld     object HTTPProxyServer.ProxyServer::_outputLockObj
    IL_009f:  ret
  } // end of method ProxyServer::.cctor

  .property instance class [System]System.Net.IPAddress
          ListeningIPInterface()
  {
    .get instance class [System]System.Net.IPAddress HTTPProxyServer.ProxyServer::get_ListeningIPInterface()
  } // end of property ProxyServer::ListeningIPInterface
  .property instance int32 ListeningPort()
  {
    .get instance int32 HTTPProxyServer.ProxyServer::get_ListeningPort()
  } // end of property ProxyServer::ListeningPort
  .property instance bool DumpHeaders()
  {
    .get instance bool HTTPProxyServer.ProxyServer::get_DumpHeaders()
    .set instance void HTTPProxyServer.ProxyServer::set_DumpHeaders(bool)
  } // end of property ProxyServer::DumpHeaders
  .property instance bool DumpPostData()
  {
    .get instance bool HTTPProxyServer.ProxyServer::get_DumpPostData()
    .set instance void HTTPProxyServer.ProxyServer::set_DumpPostData(bool)
  } // end of property ProxyServer::DumpPostData
  .property instance bool DumpResponseData()
  {
    .get instance bool HTTPProxyServer.ProxyServer::get_DumpResponseData()
    .set instance void HTTPProxyServer.ProxyServer::set_DumpResponseData(bool)
  } // end of property ProxyServer::DumpResponseData
  .property class HTTPProxyServer.ProxyServer
          Server()
  {
    .get class HTTPProxyServer.ProxyServer HTTPProxyServer.ProxyServer::get_Server()
  } // end of property ProxyServer::Server
} // end of class HTTPProxyServer.ProxyServer

.class private auto ansi sealed '<PrivateImplementationDetails>'
       extends [mscorlib]System.Object
{
  .custom instance void [mscorlib]System.Runtime.CompilerServices.CompilerGeneratedAttribute::.ctor() = ( 01 00 00 00 ) 
  .method assembly hidebysig static uint32 
          ComputeStringHash(string s) cil managed
  {
    // Code size       44 (0x2c)
    .maxstack  2
    .locals init (uint32 V_0,
             int32 V_1)
    IL_0000:  ldarg.0
    IL_0001:  brfalse.s  IL_002a

    IL_0003:  ldc.i4     0x811c9dc5
    IL_0008:  stloc.0
    IL_0009:  ldc.i4.0
    IL_000a:  stloc.1
    IL_000b:  br.s       IL_0021

    IL_000d:  ldarg.0
    IL_000e:  ldloc.1
    IL_000f:  callvirt   instance char [mscorlib]System.String::get_Chars(int32)
    IL_0014:  ldloc.0
    IL_0015:  xor
    IL_0016:  ldc.i4     0x1000193
    IL_001b:  mul
    IL_001c:  stloc.0
    IL_001d:  ldloc.1
    IL_001e:  ldc.i4.1
    IL_001f:  add
    IL_0020:  stloc.1
    IL_0021:  ldloc.1
    IL_0022:  ldarg.0
    IL_0023:  callvirt   instance int32 [mscorlib]System.String::get_Length()
    IL_0028:  blt.s      IL_000d

    IL_002a:  ldloc.0
    IL_002b:  ret
  } // end of method '<PrivateImplementationDetails>'::ComputeStringHash

} // end of class '<PrivateImplementationDetails>'

.class public auto ansi sealed CERTENROLLLib.AlgorithmFlags
       extends [mscorlib]System.Enum
{
  .custom instance void [mscorlib]System.Runtime.CompilerServices.CompilerGeneratedAttribute::.ctor() = ( 01 00 00 00 ) 
  .custom instance void [mscorlib]System.Runtime.InteropServices.TypeIdentifierAttribute::.ctor(string,
                                                                                                string) = ( 01 00 24 37 32 38 61 62 33 34 38 2D 32 31 37 64   // ..$728ab348-217d
                                                                                                            2D 31 31 64 61 2D 62 32 61 34 2D 30 30 30 65 37   // -11da-b2a4-000e7
                                                                                                            62 62 62 32 62 30 39 1C 43 45 52 54 45 4E 52 4F   // bbb2b09.CERTENRO
                                                                                                            4C 4C 4C 69 62 2E 41 6C 67 6F 72 69 74 68 6D 46   // LLLib.AlgorithmF
                                                                                                            6C 61 67 73 00 00 )                               // lags..
  .field public specialname rtspecialname int32 value__
  .field public static literal valuetype CERTENROLLLib.AlgorithmFlags AlgorithmFlagsNone = int32(0x00000000)
  .field public static literal valuetype CERTENROLLLib.AlgorithmFlags AlgorithmFlagsWrap = int32(0x00000001)
} // end of class CERTENROLLLib.AlgorithmFlags

.class public auto ansi sealed CERTENROLLLib.AlternativeNameType
       extends [mscorlib]System.Enum
{
  .custom instance void [mscorlib]System.Runtime.CompilerServices.CompilerGeneratedAttribute::.ctor() = ( 01 00 00 00 ) 
  .custom instance void [mscorlib]System.Runtime.InteropServices.TypeIdentifierAttribute::.ctor(string,
                                                                                                string) = ( 01 00 24 37 32 38 61 62 33 34 38 2D 32 31 37 64   // ..$728ab348-217d
                                                                                                            2D 31 31 64 61 2D 62 32 61 34 2D 30 30 30 65 37   // -11da-b2a4-000e7
                                                                                                            62 62 62 32 62 30 39 21 43 45 52 54 45 4E 52 4F   // bbb2b09!CERTENRO
                                                                                                            4C 4C 4C 69 62 2E 41 6C 74 65 72 6E 61 74 69 76   // LLLib.Alternativ
                                                                                                            65 4E 61 6D 65 54 79 70 65 00 00 )                // eNameType..
  .field public specialname rtspecialname int32 value__
  .field public static literal valuetype CERTENROLLLib.AlternativeNameType XCN_CERT_ALT_NAME_UNKNOWN = int32(0x00000000)
  .field public static literal valuetype CERTENROLLLib.AlternativeNameType XCN_CERT_ALT_NAME_OTHER_NAME = int32(0x00000001)
  .field public static literal valuetype CERTENROLLLib.AlternativeNameType XCN_CERT_ALT_NAME_RFC822_NAME = int32(0x00000002)
  .field public static literal valuetype CERTENROLLLib.AlternativeNameType XCN_CERT_ALT_NAME_DNS_NAME = int32(0x00000003)
  .field public static literal valuetype CERTENROLLLib.AlternativeNameType XCN_CERT_ALT_NAME_X400_ADDRESS = int32(0x00000004)
  .field public static literal valuetype CERTENROLLLib.AlternativeNameType XCN_CERT_ALT_NAME_DIRECTORY_NAME = int32(0x00000005)
  .field public static literal valuetype CERTENROLLLib.AlternativeNameType XCN_CERT_ALT_NAME_EDI_PARTY_NAME = int32(0x00000006)
  .field public static literal valuetype CERTENROLLLib.AlternativeNameType XCN_CERT_ALT_NAME_URL = int32(0x00000007)
  .field public static literal valuetype CERTENROLLLib.AlternativeNameType XCN_CERT_ALT_NAME_IP_ADDRESS = int32(0x00000008)
  .field public static literal valuetype CERTENROLLLib.AlternativeNameType XCN_CERT_ALT_NAME_REGISTERED_ID = int32(0x00000009)
  .field public static literal valuetype CERTENROLLLib.AlternativeNameType XCN_CERT_ALT_NAME_GUID = int32(0x0000000A)
  .field public static literal valuetype CERTENROLLLib.AlternativeNameType XCN_CERT_ALT_NAME_USER_PRINCIPLE_NAME = int32(0x0000000B)
} // end of class CERTENROLLLib.AlternativeNameType

.class interface public abstract auto ansi import CERTENROLLLib.CAlternativeName
       implements CERTENROLLLib.IAlternativeName
{
  .custom instance void [mscorlib]System.Runtime.CompilerServices.CompilerGeneratedAttribute::.ctor() = ( 01 00 00 00 ) 
  .custom instance void [mscorlib]System.Runtime.InteropServices.CoClassAttribute::.ctor(class [mscorlib]System.Type) = ( 01 00 5A 53 79 73 74 65 6D 2E 4F 62 6A 65 63 74   // ..ZSystem.Object
                                                                                                                          2C 20 6D 73 63 6F 72 6C 69 62 2C 20 56 65 72 73   // , mscorlib, Vers
                                                                                                                          69 6F 6E 3D 34 2E 30 2E 30 2E 30 2C 20 43 75 6C   // ion=4.0.0.0, Cul
                                                                                                                          74 75 72 65 3D 6E 65 75 74 72 61 6C 2C 20 50 75   // ture=neutral, Pu
                                                                                                                          62 6C 69 63 4B 65 79 54 6F 6B 65 6E 3D 62 37 37   // blicKeyToken=b77
                                                                                                                          61 35 63 35 36 31 39 33 34 65 30 38 39 00 00 )    // a5c561934e089..
  .custom instance void [mscorlib]System.Runtime.InteropServices.GuidAttribute::.ctor(string) = ( 01 00 24 37 32 38 41 42 33 31 33 2D 32 31 37 44   // ..$728AB313-217D
                                                                                                  2D 31 31 44 41 2D 42 32 41 34 2D 30 30 30 45 37   // -11DA-B2A4-000E7
                                                                                                  42 42 42 32 42 30 39 00 00 )                      // BBB2B09..
  .custom instance void [mscorlib]System.Runtime.InteropServices.TypeIdentifierAttribute::.ctor() = ( 01 00 00 00 ) 
} // end of class CERTENROLLLib.CAlternativeName

.class interface public abstract auto ansi import CERTENROLLLib.CAlternativeNames
       implements CERTENROLLLib.IAlternativeNames
{
  .custom instance void [mscorlib]System.Runtime.CompilerServices.CompilerGeneratedAttribute::.ctor() = ( 01 00 00 00 ) 
  .custom instance void [mscorlib]System.Runtime.InteropServices.GuidAttribute::.ctor(string) = ( 01 00 24 37 32 38 41 42 33 31 34 2D 32 31 37 44   // ..$728AB314-217D
                                                                                                  2D 31 31 44 41 2D 42 32 41 34 2D 30 30 30 45 37   // -11DA-B2A4-000E7
                                                                                                  42 42 42 32 42 30 39 00 00 )                      // BBB2B09..
  .custom instance void [mscorlib]System.Runtime.InteropServices.CoClassAttribute::.ctor(class [mscorlib]System.Type) = ( 01 00 5A 53 79 73 74 65 6D 2E 4F 62 6A 65 63 74   // ..ZSystem.Object
                                                                                                                          2C 20 6D 73 63 6F 72 6C 69 62 2C 20 56 65 72 73   // , mscorlib, Vers
                                                                                                                          69 6F 6E 3D 34 2E 30 2E 30 2E 30 2C 20 43 75 6C   // ion=4.0.0.0, Cul
                                                                                                                          74 75 72 65 3D 6E 65 75 74 72 61 6C 2C 20 50 75   // ture=neutral, Pu
                                                                                                                          62 6C 69 63 4B 65 79 54 6F 6B 65 6E 3D 62 37 37   // blicKeyToken=b77
                                                                                                                          61 35 63 35 36 31 39 33 34 65 30 38 39 00 00 )    // a5c561934e089..
  .custom instance void [mscorlib]System.Runtime.InteropServices.TypeIdentifierAttribute::.ctor() = ( 01 00 00 00 ) 
} // end of class CERTENROLLLib.CAlternativeNames

.class interface public abstract auto ansi import CERTENROLLLib.CObjectId
       implements CERTENROLLLib.IObjectId
{
  .custom instance void [mscorlib]System.Runtime.CompilerServices.CompilerGeneratedAttribute::.ctor() = ( 01 00 00 00 ) 
  .custom instance void [mscorlib]System.Runtime.InteropServices.CoClassAttribute::.ctor(class [mscorlib]System.Type) = ( 01 00 5A 53 79 73 74 65 6D 2E 4F 62 6A 65 63 74   // ..ZSystem.Object
                                                                                                                          2C 20 6D 73 63 6F 72 6C 69 62 2C 20 56 65 72 73   // , mscorlib, Vers
                                                                                                                          69 6F 6E 3D 34 2E 30 2E 30 2E 30 2C 20 43 75 6C   // ion=4.0.0.0, Cul
                                                                                                                          74 75 72 65 3D 6E 65 75 74 72 61 6C 2C 20 50 75   // ture=neutral, Pu
                                                                                                                          62 6C 69 63 4B 65 79 54 6F 6B 65 6E 3D 62 37 37   // blicKeyToken=b77
                                                                                                                          61 35 63 35 36 31 39 33 34 65 30 38 39 00 00 )    // a5c561934e089..
  .custom instance void [mscorlib]System.Runtime.InteropServices.GuidAttribute::.ctor(string) = ( 01 00 24 37 32 38 41 42 33 30 30 2D 32 31 37 44   // ..$728AB300-217D
                                                                                                  2D 31 31 44 41 2D 42 32 41 34 2D 30 30 30 45 37   // -11DA-B2A4-000E7
                                                                                                  42 42 42 32 42 30 39 00 00 )                      // BBB2B09..
  .custom instance void [mscorlib]System.Runtime.InteropServices.TypeIdentifierAttribute::.ctor() = ( 01 00 00 00 ) 
} // end of class CERTENROLLLib.CObjectId

.class interface public abstract auto ansi import CERTENROLLLib.CObjectIds
       implements CERTENROLLLib.IObjectIds
{
  .custom instance void [mscorlib]System.Runtime.CompilerServices.CompilerGeneratedAttribute::.ctor() = ( 01 00 00 00 ) 
  .custom instance void [mscorlib]System.Runtime.InteropServices.GuidAttribute::.ctor(string) = ( 01 00 24 37 32 38 41 42 33 30 31 2D 32 31 37 44   // ..$728AB301-217D
                                                                                                  2D 31 31 44 41 2D 42 32 41 34 2D 30 30 30 45 37   // -11DA-B2A4-000E7
                                                                                                  42 42 42 32 42 30 39 00 00 )                      // BBB2B09..
  .custom instance void [mscorlib]System.Runtime.InteropServices.CoClassAttribute::.ctor(class [mscorlib]System.Type) = ( 01 00 5A 53 79 73 74 65 6D 2E 4F 62 6A 65 63 74   // ..ZSystem.Object
                                                                                                                          2C 20 6D 73 63 6F 72 6C 69 62 2C 20 56 65 72 73   // , mscorlib, Vers
                                                                                                                          69 6F 6E 3D 34 2E 30 2E 30 2E 30 2C 20 43 75 6C   // ion=4.0.0.0, Cul
                                                                                                                          74 75 72 65 3D 6E 65 75 74 72 61 6C 2C 20 50 75   // ture=neutral, Pu
                                                                                                                          62 6C 69 63 4B 65 79 54 6F 6B 65 6E 3D 62 37 37   // blicKeyToken=b77
                                                                                                                          61 35 63 35 36 31 39 33 34 65 30 38 39 00 00 )    // a5c561934e089..
  .custom instance void [mscorlib]System.Runtime.InteropServices.TypeIdentifierAttribute::.ctor() = ( 01 00 00 00 ) 
} // end of class CERTENROLLLib.CObjectIds

.class interface public abstract auto ansi import CERTENROLLLib.CSignerCertificate
       implements CERTENROLLLib.ISignerCertificate
{
  .custom instance void [mscorlib]System.Runtime.CompilerServices.CompilerGeneratedAttribute::.ctor() = ( 01 00 00 00 ) 
  .custom instance void [mscorlib]System.Runtime.InteropServices.GuidAttribute::.ctor(string) = ( 01 00 24 37 32 38 41 42 33 33 44 2D 32 31 37 44   // ..$728AB33D-217D
                                                                                                  2D 31 31 44 41 2D 42 32 41 34 2D 30 30 30 45 37   // -11DA-B2A4-000E7
                                                                                                  42 42 42 32 42 30 39 00 00 )                      // BBB2B09..
  .custom instance void [mscorlib]System.Runtime.InteropServices.CoClassAttribute::.ctor(class [mscorlib]System.Type) = ( 01 00 5A 53 79 73 74 65 6D 2E 4F 62 6A 65 63 74   // ..ZSystem.Object
                                                                                                                          2C 20 6D 73 63 6F 72 6C 69 62 2C 20 56 65 72 73   // , mscorlib, Vers
                                                                                                                          69 6F 6E 3D 34 2E 30 2E 30 2E 30 2C 20 43 75 6C   // ion=4.0.0.0, Cul
                                                                                                                          74 75 72 65 3D 6E 65 75 74 72 61 6C 2C 20 50 75   // ture=neutral, Pu
                                                                                                                          62 6C 69 63 4B 65 79 54 6F 6B 65 6E 3D 62 37 37   // blicKeyToken=b77
                                                                                                                          61 35 63 35 36 31 39 33 34 65 30 38 39 00 00 )    // a5c561934e089..
  .custom instance void [mscorlib]System.Runtime.InteropServices.TypeIdentifierAttribute::.ctor() = ( 01 00 00 00 ) 
} // end of class CERTENROLLLib.CSignerCertificate

.class interface public abstract auto ansi import CERTENROLLLib.CX500DistinguishedName
       implements CERTENROLLLib.IX500DistinguishedName
{
  .custom instance void [mscorlib]System.Runtime.CompilerServices.CompilerGeneratedAttribute::.ctor() = ( 01 00 00 00 ) 
  .custom instance void [mscorlib]System.Runtime.InteropServices.CoClassAttribute::.ctor(class [mscorlib]System.Type) = ( 01 00 5A 53 79 73 74 65 6D 2E 4F 62 6A 65 63 74   // ..ZSystem.Object
                                                                                                                          2C 20 6D 73 63 6F 72 6C 69 62 2C 20 56 65 72 73   // , mscorlib, Vers
                                                                                                                          69 6F 6E 3D 34 2E 30 2E 30 2E 30 2C 20 43 75 6C   // ion=4.0.0.0, Cul
                                                                                                                          74 75 72 65 3D 6E 65 75 74 72 61 6C 2C 20 50 75   // ture=neutral, Pu
                                                                                                                          62 6C 69 63 4B 65 79 54 6F 6B 65 6E 3D 62 37 37   // blicKeyToken=b77
                                                                                                                          61 35 63 35 36 31 39 33 34 65 30 38 39 00 00 )    // a5c561934e089..
  .custom instance void [mscorlib]System.Runtime.InteropServices.GuidAttribute::.ctor(string) = ( 01 00 24 37 32 38 41 42 33 30 33 2D 32 31 37 44   // ..$728AB303-217D
                                                                                                  2D 31 31 44 41 2D 42 32 41 34 2D 30 30 30 45 37   // -11DA-B2A4-000E7
                                                                                                  42 42 42 32 42 30 39 00 00 )                      // BBB2B09..
  .custom instance void [mscorlib]System.Runtime.InteropServices.TypeIdentifierAttribute::.ctor() = ( 01 00 00 00 ) 
} // end of class CERTENROLLLib.CX500DistinguishedName

.class interface public abstract auto ansi import CERTENROLLLib.CX509CertificateRequestCertificate
       implements CERTENROLLLib.IX509CertificateRequestCertificate2
{
  .custom instance void [mscorlib]System.Runtime.CompilerServices.CompilerGeneratedAttribute::.ctor() = ( 01 00 00 00 ) 
  .custom instance void [mscorlib]System.Runtime.InteropServices.GuidAttribute::.ctor(string) = ( 01 00 24 37 32 38 41 42 33 35 41 2D 32 31 37 44   // ..$728AB35A-217D
                                                                                                  2D 31 31 44 41 2D 42 32 41 34 2D 30 30 30 45 37   // -11DA-B2A4-000E7
                                                                                                  42 42 42 32 42 30 39 00 00 )                      // BBB2B09..
  .custom instance void [mscorlib]System.Runtime.InteropServices.CoClassAttribute::.ctor(class [mscorlib]System.Type) = ( 01 00 5A 53 79 73 74 65 6D 2E 4F 62 6A 65 63 74   // ..ZSystem.Object
                                                                                                                          2C 20 6D 73 63 6F 72 6C 69 62 2C 20 56 65 72 73   // , mscorlib, Vers
                                                                                                                          69 6F 6E 3D 34 2E 30 2E 30 2E 30 2C 20 43 75 6C   // ion=4.0.0.0, Cul
                                                                                                                          74 75 72 65 3D 6E 65 75 74 72 61 6C 2C 20 50 75   // ture=neutral, Pu
                                                                                                                          62 6C 69 63 4B 65 79 54 6F 6B 65 6E 3D 62 37 37   // blicKeyToken=b77
                                                                                                                          61 35 63 35 36 31 39 33 34 65 30 38 39 00 00 )    // a5c561934e089..
  .custom instance void [mscorlib]System.Runtime.InteropServices.TypeIdentifierAttribute::.ctor() = ( 01 00 00 00 ) 
} // end of class CERTENROLLLib.CX509CertificateRequestCertificate

.class interface public abstract auto ansi import CERTENROLLLib.CX509Enrollment
       implements CERTENROLLLib.IX509Enrollment2
{
  .custom instance void [mscorlib]System.Runtime.CompilerServices.CompilerGeneratedAttribute::.ctor() = ( 01 00 00 00 ) 
  .custom instance void [mscorlib]System.Runtime.InteropServices.GuidAttribute::.ctor(string) = ( 01 00 24 37 32 38 41 42 33 35 30 2D 32 31 37 44   // ..$728AB350-217D
                                                                                                  2D 31 31 44 41 2D 42 32 41 34 2D 30 30 30 45 37   // -11DA-B2A4-000E7
                                                                                                  42 42 42 32 42 30 39 00 00 )                      // BBB2B09..
  .custom instance void [mscorlib]System.Runtime.InteropServices.CoClassAttribute::.ctor(class [mscorlib]System.Type) = ( 01 00 5A 53 79 73 74 65 6D 2E 4F 62 6A 65 63 74   // ..ZSystem.Object
                                                                                                                          2C 20 6D 73 63 6F 72 6C 69 62 2C 20 56 65 72 73   // , mscorlib, Vers
                                                                                                                          69 6F 6E 3D 34 2E 30 2E 30 2E 30 2C 20 43 75 6C   // ion=4.0.0.0, Cul
                                                                                                                          74 75 72 65 3D 6E 65 75 74 72 61 6C 2C 20 50 75   // ture=neutral, Pu
                                                                                                                          62 6C 69 63 4B 65 79 54 6F 6B 65 6E 3D 62 37 37   // blicKeyToken=b77
                                                                                                                          61 35 63 35 36 31 39 33 34 65 30 38 39 00 00 )    // a5c561934e089..
  .custom instance void [mscorlib]System.Runtime.InteropServices.TypeIdentifierAttribute::.ctor() = ( 01 00 00 00 ) 
} // end of class CERTENROLLLib.CX509Enrollment

.class interface public abstract auto ansi import CERTENROLLLib.CX509Extension
       implements CERTENROLLLib.IX509Extension
{
  .custom instance void [mscorlib]System.Runtime.CompilerServices.CompilerGeneratedAttribute::.ctor() = ( 01 00 00 00 ) 
  .custom instance void [mscorlib]System.Runtime.InteropServices.GuidAttribute::.ctor(string) = ( 01 00 24 37 32 38 41 42 33 30 44 2D 32 31 37 44   // ..$728AB30D-217D
                                                                                                  2D 31 31 44 41 2D 42 32 41 34 2D 30 30 30 45 37   // -11DA-B2A4-000E7
                                                                                                  42 42 42 32 42 30 39 00 00 )                      // BBB2B09..
  .custom instance void [mscorlib]System.Runtime.InteropServices.CoClassAttribute::.ctor(class [mscorlib]System.Type) = ( 01 00 5A 53 79 73 74 65 6D 2E 4F 62 6A 65 63 74   // ..ZSystem.Object
                                                                                                                          2C 20 6D 73 63 6F 72 6C 69 62 2C 20 56 65 72 73   // , mscorlib, Vers
                                                                                                                          69 6F 6E 3D 34 2E 30 2E 30 2E 30 2C 20 43 75 6C   // ion=4.0.0.0, Cul
                                                                                                                          74 75 72 65 3D 6E 65 75 74 72 61 6C 2C 20 50 75   // ture=neutral, Pu
                                                                                                                          62 6C 69 63 4B 65 79 54 6F 6B 65 6E 3D 62 37 37   // blicKeyToken=b77
                                                                                                                          61 35 63 35 36 31 39 33 34 65 30 38 39 00 00 )    // a5c561934e089..
  .custom instance void [mscorlib]System.Runtime.InteropServices.TypeIdentifierAttribute::.ctor() = ( 01 00 00 00 ) 
} // end of class CERTENROLLLib.CX509Extension

.class interface public abstract auto ansi import CERTENROLLLib.CX509ExtensionAlternativeNames
       implements CERTENROLLLib.IX509ExtensionAlternativeNames
{
  .custom instance void [mscorlib]System.Runtime.CompilerServices.CompilerGeneratedAttribute::.ctor() = ( 01 00 00 00 ) 
  .custom instance void [mscorlib]System.Runtime.InteropServices.CoClassAttribute::.ctor(class [mscorlib]System.Type) = ( 01 00 5A 53 79 73 74 65 6D 2E 4F 62 6A 65 63 74   // ..ZSystem.Object
                                                                                                                          2C 20 6D 73 63 6F 72 6C 69 62 2C 20 56 65 72 73   // , mscorlib, Vers
                                                                                                                          69 6F 6E 3D 34 2E 30 2E 30 2E 30 2C 20 43 75 6C   // ion=4.0.0.0, Cul
                                                                                                                          74 75 72 65 3D 6E 65 75 74 72 61 6C 2C 20 50 75   // ture=neutral, Pu
                                                                                                                          62 6C 69 63 4B 65 79 54 6F 6B 65 6E 3D 62 37 37   // blicKeyToken=b77
                                                                                                                          61 35 63 35 36 31 39 33 34 65 30 38 39 00 00 )    // a5c561934e089..
  .custom instance void [mscorlib]System.Runtime.InteropServices.GuidAttribute::.ctor(string) = ( 01 00 24 37 32 38 41 42 33 31 35 2D 32 31 37 44   // ..$728AB315-217D
                                                                                                  2D 31 31 44 41 2D 42 32 41 34 2D 30 30 30 45 37   // -11DA-B2A4-000E7
                                                                                                  42 42 42 32 42 30 39 00 00 )                      // BBB2B09..
  .custom instance void [mscorlib]System.Runtime.InteropServices.TypeIdentifierAttribute::.ctor() = ( 01 00 00 00 ) 
} // end of class CERTENROLLLib.CX509ExtensionAlternativeNames

.class interface public abstract auto ansi import CERTENROLLLib.CX509ExtensionBasicConstraints
       implements CERTENROLLLib.IX509ExtensionBasicConstraints
{
  .custom instance void [mscorlib]System.Runtime.CompilerServices.CompilerGeneratedAttribute::.ctor() = ( 01 00 00 00 ) 
  .custom instance void [mscorlib]System.Runtime.InteropServices.GuidAttribute::.ctor(string) = ( 01 00 24 37 32 38 41 42 33 31 36 2D 32 31 37 44   // ..$728AB316-217D
                                                                                                  2D 31 31 44 41 2D 42 32 41 34 2D 30 30 30 45 37   // -11DA-B2A4-000E7
                                                                                                  42 42 42 32 42 30 39 00 00 )                      // BBB2B09..
  .custom instance void [mscorlib]System.Runtime.InteropServices.CoClassAttribute::.ctor(class [mscorlib]System.Type) = ( 01 00 5A 53 79 73 74 65 6D 2E 4F 62 6A 65 63 74   // ..ZSystem.Object
                                                                                                                          2C 20 6D 73 63 6F 72 6C 69 62 2C 20 56 65 72 73   // , mscorlib, Vers
                                                                                                                          69 6F 6E 3D 34 2E 30 2E 30 2E 30 2C 20 43 75 6C   // ion=4.0.0.0, Cul
                                                                                                                          74 75 72 65 3D 6E 65 75 74 72 61 6C 2C 20 50 75   // ture=neutral, Pu
                                                                                                                          62 6C 69 63 4B 65 79 54 6F 6B 65 6E 3D 62 37 37   // blicKeyToken=b77
                                                                                                                          61 35 63 35 36 31 39 33 34 65 30 38 39 00 00 )    // a5c561934e089..
  .custom instance void [mscorlib]System.Runtime.InteropServices.TypeIdentifierAttribute::.ctor() = ( 01 00 00 00 ) 
} // end of class CERTENROLLLib.CX509ExtensionBasicConstraints

.class interface public abstract auto ansi import CERTENROLLLib.CX509ExtensionEnhancedKeyUsage
       implements CERTENROLLLib.IX509ExtensionEnhancedKeyUsage
{
  .custom instance void [mscorlib]System.Runtime.CompilerServices.CompilerGeneratedAttribute::.ctor() = ( 01 00 00 00 ) 
  .custom instance void [mscorlib]System.Runtime.InteropServices.CoClassAttribute::.ctor(class [mscorlib]System.Type) = ( 01 00 5A 53 79 73 74 65 6D 2E 4F 62 6A 65 63 74   // ..ZSystem.Object
                                                                                                                          2C 20 6D 73 63 6F 72 6C 69 62 2C 20 56 65 72 73   // , mscorlib, Vers
                                                                                                                          69 6F 6E 3D 34 2E 30 2E 30 2E 30 2C 20 43 75 6C   // ion=4.0.0.0, Cul
                                                                                                                          74 75 72 65 3D 6E 65 75 74 72 61 6C 2C 20 50 75   // ture=neutral, Pu
                                                                                                                          62 6C 69 63 4B 65 79 54 6F 6B 65 6E 3D 62 37 37   // blicKeyToken=b77
                                                                                                                          61 35 63 35 36 31 39 33 34 65 30 38 39 00 00 )    // a5c561934e089..
  .custom instance void [mscorlib]System.Runtime.InteropServices.GuidAttribute::.ctor(string) = ( 01 00 24 37 32 38 41 42 33 31 30 2D 32 31 37 44   // ..$728AB310-217D
                                                                                                  2D 31 31 44 41 2D 42 32 41 34 2D 30 30 30 45 37   // -11DA-B2A4-000E7
                                                                                                  42 42 42 32 42 30 39 00 00 )                      // BBB2B09..
  .custom instance void [mscorlib]System.Runtime.InteropServices.TypeIdentifierAttribute::.ctor() = ( 01 00 00 00 ) 
} // end of class CERTENROLLLib.CX509ExtensionEnhancedKeyUsage

.class interface public abstract auto ansi import CERTENROLLLib.CX509Extensions
       implements CERTENROLLLib.IX509Extensions
{
  .custom instance void [mscorlib]System.Runtime.CompilerServices.CompilerGeneratedAttribute::.ctor() = ( 01 00 00 00 ) 
  .custom instance void [mscorlib]System.Runtime.InteropServices.GuidAttribute::.ctor(string) = ( 01 00 24 37 32 38 41 42 33 30 45 2D 32 31 37 44   // ..$728AB30E-217D
                                                                                                  2D 31 31 44 41 2D 42 32 41 34 2D 30 30 30 45 37   // -11DA-B2A4-000E7
                                                                                                  42 42 42 32 42 30 39 00 00 )                      // BBB2B09..
  .custom instance void [mscorlib]System.Runtime.InteropServices.CoClassAttribute::.ctor(class [mscorlib]System.Type) = ( 01 00 5A 53 79 73 74 65 6D 2E 4F 62 6A 65 63 74   // ..ZSystem.Object
                                                                                                                          2C 20 6D 73 63 6F 72 6C 69 62 2C 20 56 65 72 73   // , mscorlib, Vers
                                                                                                                          69 6F 6E 3D 34 2E 30 2E 30 2E 30 2C 20 43 75 6C   // ion=4.0.0.0, Cul
                                                                                                                          74 75 72 65 3D 6E 65 75 74 72 61 6C 2C 20 50 75   // ture=neutral, Pu
                                                                                                                          62 6C 69 63 4B 65 79 54 6F 6B 65 6E 3D 62 37 37   // blicKeyToken=b77
                                                                                                                          61 35 63 35 36 31 39 33 34 65 30 38 39 00 00 )    // a5c561934e089..
  .custom instance void [mscorlib]System.Runtime.InteropServices.TypeIdentifierAttribute::.ctor() = ( 01 00 00 00 ) 
} // end of class CERTENROLLLib.CX509Extensions

.class interface public abstract auto ansi import CERTENROLLLib.CX509PrivateKey
       implements CERTENROLLLib.IX509PrivateKey2
{
  .custom instance void [mscorlib]System.Runtime.CompilerServices.CompilerGeneratedAttribute::.ctor() = ( 01 00 00 00 ) 
  .custom instance void [mscorlib]System.Runtime.InteropServices.GuidAttribute::.ctor(string) = ( 01 00 24 37 32 38 41 42 33 36 32 2D 32 31 37 44   // ..$728AB362-217D
                                                                                                  2D 31 31 44 41 2D 42 32 41 34 2D 30 30 30 45 37   // -11DA-B2A4-000E7
                                                                                                  42 42 42 32 42 30 39 00 00 )                      // BBB2B09..
  .custom instance void [mscorlib]System.Runtime.InteropServices.CoClassAttribute::.ctor(class [mscorlib]System.Type) = ( 01 00 5A 53 79 73 74 65 6D 2E 4F 62 6A 65 63 74   // ..ZSystem.Object
                                                                                                                          2C 20 6D 73 63 6F 72 6C 69 62 2C 20 56 65 72 73   // , mscorlib, Vers
                                                                                                                          69 6F 6E 3D 34 2E 30 2E 30 2E 30 2C 20 43 75 6C   // ion=4.0.0.0, Cul
                                                                                                                          74 75 72 65 3D 6E 65 75 74 72 61 6C 2C 20 50 75   // ture=neutral, Pu
                                                                                                                          62 6C 69 63 4B 65 79 54 6F 6B 65 6E 3D 62 37 37   // blicKeyToken=b77
                                                                                                                          61 35 63 35 36 31 39 33 34 65 30 38 39 00 00 )    // a5c561934e089..
  .custom instance void [mscorlib]System.Runtime.InteropServices.TypeIdentifierAttribute::.ctor() = ( 01 00 00 00 ) 
} // end of class CERTENROLLLib.CX509PrivateKey

.class public auto ansi sealed CERTENROLLLib.EncodingType
       extends [mscorlib]System.Enum
{
  .custom instance void [mscorlib]System.Runtime.CompilerServices.CompilerGeneratedAttribute::.ctor() = ( 01 00 00 00 ) 
  .custom instance void [mscorlib]System.Runtime.InteropServices.TypeIdentifierAttribute::.ctor(string,
                                                                                                string) = ( 01 00 24 37 32 38 61 62 33 34 38 2D 32 31 37 64   // ..$728ab348-217d
                                                                                                            2D 31 31 64 61 2D 62 32 61 34 2D 30 30 30 65 37   // -11da-b2a4-000e7
                                                                                                            62 62 62 32 62 30 39 1A 43 45 52 54 45 4E 52 4F   // bbb2b09.CERTENRO
                                                                                                            4C 4C 4C 69 62 2E 45 6E 63 6F 64 69 6E 67 54 79   // LLLib.EncodingTy
                                                                                                            70 65 00 00 )                                     // pe..
  .field public specialname rtspecialname int32 value__
  .field public static literal valuetype CERTENROLLLib.EncodingType XCN_CRYPT_STRING_BASE64HEADER = int32(0x00000000)
  .field public static literal valuetype CERTENROLLLib.EncodingType XCN_CRYPT_STRING_BASE64 = int32(0x00000001)
  .field public static literal valuetype CERTENROLLLib.EncodingType XCN_CRYPT_STRING_BINARY = int32(0x00000002)
  .field public static literal valuetype CERTENROLLLib.EncodingType XCN_CRYPT_STRING_BASE64REQUESTHEADER = int32(0x00000003)
  .field public static literal valuetype CERTENROLLLib.EncodingType XCN_CRYPT_STRING_HEX = int32(0x00000004)
  .field public static literal valuetype CERTENROLLLib.EncodingType XCN_CRYPT_STRING_HEXASCII = int32(0x00000005)
  .field public static literal valuetype CERTENROLLLib.EncodingType XCN_CRYPT_STRING_BASE64_ANY = int32(0x00000006)
  .field public static literal valuetype CERTENROLLLib.EncodingType XCN_CRYPT_STRING_ANY = int32(0x00000007)
  .field public static literal valuetype CERTENROLLLib.EncodingType XCN_CRYPT_STRING_HEX_ANY = int32(0x00000008)
  .field public static literal valuetype CERTENROLLLib.EncodingType XCN_CRYPT_STRING_BASE64X509CRLHEADER = int32(0x00000009)
  .field public static literal valuetype CERTENROLLLib.EncodingType XCN_CRYPT_STRING_HEXADDR = int32(0x0000000A)
  .field public static literal valuetype CERTENROLLLib.EncodingType XCN_CRYPT_STRING_HEXASCIIADDR = int32(0x0000000B)
  .field public static literal valuetype CERTENROLLLib.EncodingType XCN_CRYPT_STRING_HEXRAW = int32(0x0000000C)
  .field public static literal valuetype CERTENROLLLib.EncodingType XCN_CRYPT_STRING_BASE64URI = int32(0x0000000D)
  .field public static literal valuetype CERTENROLLLib.EncodingType XCN_CRYPT_STRING_ENCODEMASK = int32(0x000000FF)
  .field public static literal valuetype CERTENROLLLib.EncodingType XCN_CRYPT_STRING_CHAIN = int32(0x00000100)
  .field public static literal valuetype CERTENROLLLib.EncodingType XCN_CRYPT_STRING_TEXT = int32(0x00000200)
  .field public static literal valuetype CERTENROLLLib.EncodingType XCN_CRYPT_STRING_PERCENTESCAPE = int32(0x08000000)
  .field public static literal valuetype CERTENROLLLib.EncodingType XCN_CRYPT_STRING_HASHDATA = int32(0x10000000)
  .field public static literal valuetype CERTENROLLLib.EncodingType XCN_CRYPT_STRING_STRICT = int32(0x20000000)
  .field public static literal valuetype CERTENROLLLib.EncodingType XCN_CRYPT_STRING_NOCRLF = int32(0x40000000)
  .field public static literal valuetype CERTENROLLLib.EncodingType XCN_CRYPT_STRING_NOCR = int32(0x80000000)
} // end of class CERTENROLLLib.EncodingType

.class interface public abstract auto ansi import CERTENROLLLib.IAlternativeName
{
  .custom instance void [mscorlib]System.Runtime.CompilerServices.CompilerGeneratedAttribute::.ctor() = ( 01 00 00 00 ) 
  .custom instance void [mscorlib]System.Runtime.InteropServices.GuidAttribute::.ctor(string) = ( 01 00 24 37 32 38 41 42 33 31 33 2D 32 31 37 44   // ..$728AB313-217D
                                                                                                  2D 31 31 44 41 2D 42 32 41 34 2D 30 30 30 45 37   // -11DA-B2A4-000E7
                                                                                                  42 42 42 32 42 30 39 00 00 )                      // BBB2B09..
  .custom instance void [mscorlib]System.Runtime.InteropServices.TypeIdentifierAttribute::.ctor() = ( 01 00 00 00 ) 
  .method public hidebysig newslot abstract virtual 
          instance void  InitializeFromString([in] valuetype CERTENROLLLib.AlternativeNameType Type,
                                              [in] string  marshal( bstr) strValue) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 00 00 02 60 00 00 )                         // .....`..
  } // end of method IAlternativeName::InitializeFromString

} // end of class CERTENROLLLib.IAlternativeName

.class interface public abstract auto ansi import CERTENROLLLib.IAlternativeNames
       implements [mscorlib]System.Collections.IEnumerable
{
  .custom instance void [mscorlib]System.Runtime.CompilerServices.CompilerGeneratedAttribute::.ctor() = ( 01 00 00 00 ) 
  .custom instance void [mscorlib]System.Runtime.InteropServices.GuidAttribute::.ctor(string) = ( 01 00 24 37 32 38 41 42 33 31 34 2D 32 31 37 44   // ..$728AB314-217D
                                                                                                  2D 31 31 44 41 2D 42 32 41 34 2D 30 30 30 45 37   // -11DA-B2A4-000E7
                                                                                                  42 42 42 32 42 30 39 00 00 )                      // BBB2B09..
  .custom instance void [mscorlib]System.Reflection.DefaultMemberAttribute::.ctor(string) = ( 01 00 0B 49 74 65 6D 42 79 49 6E 64 65 78 00 00 ) // ...ItemByIndex..
  .custom instance void [mscorlib]System.Runtime.InteropServices.TypeIdentifierAttribute::.ctor() = ( 01 00 00 00 ) 
  .method public specialname rtspecialname 
          instance void  _VtblGap1_3() runtime managed
  {
  } // end of method IAlternativeNames::_VtblGap1_3

  .method public hidebysig newslot abstract virtual 
          instance void  Add([in] class CERTENROLLLib.CAlternativeName  marshal( interface ) pVal) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 02 00 00 00 00 00 ) 
  } // end of method IAlternativeNames::Add

} // end of class CERTENROLLLib.IAlternativeNames

.class interface public abstract auto ansi import CERTENROLLLib.IObjectId
{
  .custom instance void [mscorlib]System.Runtime.CompilerServices.CompilerGeneratedAttribute::.ctor() = ( 01 00 00 00 ) 
  .custom instance void [mscorlib]System.Runtime.InteropServices.GuidAttribute::.ctor(string) = ( 01 00 24 37 32 38 41 42 33 30 30 2D 32 31 37 44   // ..$728AB300-217D
                                                                                                  2D 31 31 44 41 2D 42 32 41 34 2D 30 30 30 45 37   // -11DA-B2A4-000E7
                                                                                                  42 42 42 32 42 30 39 00 00 )                      // BBB2B09..
  .custom instance void [mscorlib]System.Runtime.InteropServices.TypeIdentifierAttribute::.ctor() = ( 01 00 00 00 ) 
  .method public specialname rtspecialname 
          instance void  _VtblGap1_1() runtime managed
  {
  } // end of method IObjectId::_VtblGap1_1

  .method public hidebysig newslot abstract virtual 
          instance void  InitializeFromValue([in] string  marshal( bstr) strValue) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 01 00 02 60 00 00 )                         // .....`..
  } // end of method IObjectId::InitializeFromValue

  .method public hidebysig newslot abstract virtual 
          instance void  InitializeFromAlgorithmName([in] valuetype CERTENROLLLib.ObjectIdGroupId GroupId,
                                                     [in] valuetype CERTENROLLLib.ObjectIdPublicKeyFlags KeyFlags,
                                                     [in] valuetype CERTENROLLLib.AlgorithmFlags AlgFlags,
                                                     [in] string  marshal( bstr) strAlgorithmName) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 02 00 02 60 00 00 )                         // .....`..
  } // end of method IObjectId::InitializeFromAlgorithmName

} // end of class CERTENROLLLib.IObjectId

.class interface public abstract auto ansi import CERTENROLLLib.IObjectIds
       implements [mscorlib]System.Collections.IEnumerable
{
  .custom instance void [mscorlib]System.Runtime.CompilerServices.CompilerGeneratedAttribute::.ctor() = ( 01 00 00 00 ) 
  .custom instance void [mscorlib]System.Runtime.InteropServices.GuidAttribute::.ctor(string) = ( 01 00 24 37 32 38 41 42 33 30 31 2D 32 31 37 44   // ..$728AB301-217D
                                                                                                  2D 31 31 44 41 2D 42 32 41 34 2D 30 30 30 45 37   // -11DA-B2A4-000E7
                                                                                                  42 42 42 32 42 30 39 00 00 )                      // BBB2B09..
  .custom instance void [mscorlib]System.Reflection.DefaultMemberAttribute::.ctor(string) = ( 01 00 0B 49 74 65 6D 42 79 49 6E 64 65 78 00 00 ) // ...ItemByIndex..
  .custom instance void [mscorlib]System.Runtime.InteropServices.TypeIdentifierAttribute::.ctor() = ( 01 00 00 00 ) 
  .method public specialname rtspecialname 
          instance void  _VtblGap1_3() runtime managed
  {
  } // end of method IObjectIds::_VtblGap1_3

  .method public hidebysig newslot abstract virtual 
          instance void  Add([in] class CERTENROLLLib.CObjectId  marshal( interface ) pVal) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 02 00 00 00 00 00 ) 
  } // end of method IObjectIds::Add

} // end of class CERTENROLLLib.IObjectIds

.class interface public abstract auto ansi import CERTENROLLLib.ISignerCertificate
{
  .custom instance void [mscorlib]System.Runtime.CompilerServices.CompilerGeneratedAttribute::.ctor() = ( 01 00 00 00 ) 
  .custom instance void [mscorlib]System.Runtime.InteropServices.GuidAttribute::.ctor(string) = ( 01 00 24 37 32 38 41 42 33 33 44 2D 32 31 37 44   // ..$728AB33D-217D
                                                                                                  2D 31 31 44 41 2D 42 32 41 34 2D 30 30 30 45 37   // -11DA-B2A4-000E7
                                                                                                  42 42 42 32 42 30 39 00 00 )                      // BBB2B09..
  .custom instance void [mscorlib]System.Runtime.InteropServices.TypeIdentifierAttribute::.ctor() = ( 01 00 00 00 ) 
  .method public hidebysig newslot abstract virtual 
          instance void  Initialize([in] bool MachineContext,
                                    [in] valuetype CERTENROLLLib.X509PrivateKeyVerify VerifyType,
                                    [in] valuetype CERTENROLLLib.EncodingType Encoding,
                                    [in] string  marshal( bstr) strCertificate) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 00 00 02 60 00 00 )                         // .....`..
  } // end of method ISignerCertificate::Initialize

} // end of class CERTENROLLLib.ISignerCertificate

.class interface public abstract auto ansi import CERTENROLLLib.IX500DistinguishedName
{
  .custom instance void [mscorlib]System.Runtime.CompilerServices.CompilerGeneratedAttribute::.ctor() = ( 01 00 00 00 ) 
  .custom instance void [mscorlib]System.Runtime.InteropServices.GuidAttribute::.ctor(string) = ( 01 00 24 37 32 38 41 42 33 30 33 2D 32 31 37 44   // ..$728AB303-217D
                                                                                                  2D 31 31 44 41 2D 42 32 41 34 2D 30 30 30 45 37   // -11DA-B2A4-000E7
                                                                                                  42 42 42 32 42 30 39 00 00 )                      // BBB2B09..
  .custom instance void [mscorlib]System.Runtime.InteropServices.TypeIdentifierAttribute::.ctor() = ( 01 00 00 00 ) 
  .method public specialname rtspecialname 
          instance void  _VtblGap1_1() runtime managed
  {
  } // end of method IX500DistinguishedName::_VtblGap1_1

  .method public hidebysig newslot abstract virtual 
          instance void  Encode([in] string  marshal( bstr) strName,
                                [in][opt] valuetype CERTENROLLLib.X500NameFlags NameFlags) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 01 00 02 60 00 00 )                         // .....`..
    .param [2] = int32(0x00000000)
  } // end of method IX500DistinguishedName::Encode

} // end of class CERTENROLLLib.IX500DistinguishedName

.class interface public abstract auto ansi import CERTENROLLLib.IX509CertificateRequest
{
  .custom instance void [mscorlib]System.Runtime.CompilerServices.CompilerGeneratedAttribute::.ctor() = ( 01 00 00 00 ) 
  .custom instance void [mscorlib]System.Runtime.InteropServices.GuidAttribute::.ctor(string) = ( 01 00 24 37 32 38 41 42 33 34 31 2D 32 31 37 44   // ..$728AB341-217D
                                                                                                  2D 31 31 44 41 2D 42 32 41 34 2D 30 30 30 45 37   // -11DA-B2A4-000E7
                                                                                                  42 42 42 32 42 30 39 00 00 )                      // BBB2B09..
  .custom instance void [mscorlib]System.Runtime.InteropServices.TypeIdentifierAttribute::.ctor() = ( 01 00 00 00 ) 
} // end of class CERTENROLLLib.IX509CertificateRequest

.class interface public abstract auto ansi import CERTENROLLLib.IX509CertificateRequestCertificate
       implements CERTENROLLLib.IX509CertificateRequestPkcs10
{
  .custom instance void [mscorlib]System.Runtime.CompilerServices.CompilerGeneratedAttribute::.ctor() = ( 01 00 00 00 ) 
  .custom instance void [mscorlib]System.Runtime.InteropServices.GuidAttribute::.ctor(string) = ( 01 00 24 37 32 38 41 42 33 34 33 2D 32 31 37 44   // ..$728AB343-217D
                                                                                                  2D 31 31 44 41 2D 42 32 41 34 2D 30 30 30 45 37   // -11DA-B2A4-000E7
                                                                                                  42 42 42 32 42 30 39 00 00 )                      // BBB2B09..
  .custom instance void [mscorlib]System.Runtime.InteropServices.TypeIdentifierAttribute::.ctor() = ( 01 00 00 00 ) 
} // end of class CERTENROLLLib.IX509CertificateRequestCertificate

.class interface public abstract auto ansi import CERTENROLLLib.IX509CertificateRequestCertificate2
       implements CERTENROLLLib.IX509CertificateRequestCertificate
{
  .custom instance void [mscorlib]System.Runtime.CompilerServices.CompilerGeneratedAttribute::.ctor() = ( 01 00 00 00 ) 
  .custom instance void [mscorlib]System.Runtime.InteropServices.GuidAttribute::.ctor(string) = ( 01 00 24 37 32 38 41 42 33 35 41 2D 32 31 37 44   // ..$728AB35A-217D
                                                                                                  2D 31 31 44 41 2D 42 32 41 34 2D 30 30 30 45 37   // -11DA-B2A4-000E7
                                                                                                  42 42 42 32 42 30 39 00 00 )                      // BBB2B09..
  .custom instance void [mscorlib]System.Runtime.InteropServices.TypeIdentifierAttribute::.ctor() = ( 01 00 00 00 ) 
  .method public specialname rtspecialname 
          instance void  _VtblGap1_1() runtime managed
  {
  } // end of method IX509CertificateRequestCertificate2::_VtblGap1_1

  .method public hidebysig newslot abstract virtual 
          instance void  Encode() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 01 00 02 60 00 00 )                         // .....`..
  } // end of method IX509CertificateRequestCertificate2::Encode

  .method public specialname rtspecialname 
          instance void  _VtblGap2_18() runtime managed
  {
  } // end of method IX509CertificateRequestCertificate2::_VtblGap2_18

  .method public hidebysig newslot specialname abstract virtual 
          instance class CERTENROLLLib.CObjectId 
          marshal( interface ) 
          get_HashAlgorithm() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 14 00 02 60 00 00 )                         // .....`..
  } // end of method IX509CertificateRequestCertificate2::get_HashAlgorithm

  .method public hidebysig newslot specialname abstract virtual 
          instance void  set_HashAlgorithm([in] class CERTENROLLLib.CObjectId  marshal( interface ) ppValue) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 14 00 02 60 00 00 )                         // .....`..
  } // end of method IX509CertificateRequestCertificate2::set_HashAlgorithm

  .method public specialname rtspecialname 
          instance void  _VtblGap3_4() runtime managed
  {
  } // end of method IX509CertificateRequestCertificate2::_VtblGap3_4

  .method public hidebysig newslot abstract virtual 
          instance void  InitializeFromPrivateKey([in] valuetype CERTENROLLLib.X509CertificateEnrollmentContext Context,
                                                  [in] class CERTENROLLLib.IX509PrivateKey  marshal( interface ) pPrivateKey,
                                                  [in] string  marshal( bstr) strTemplateName) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 01 00 03 60 00 00 )                         // .....`..
  } // end of method IX509CertificateRequestCertificate2::InitializeFromPrivateKey

  .method public specialname rtspecialname 
          instance void  _VtblGap4_11() runtime managed
  {
  } // end of method IX509CertificateRequestCertificate2::_VtblGap4_11

  .method public hidebysig newslot specialname abstract virtual 
          instance class CERTENROLLLib.CX500DistinguishedName 
          marshal( interface ) 
          get_Subject() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 0D 00 03 60 00 00 )                         // .....`..
  } // end of method IX509CertificateRequestCertificate2::get_Subject

  .method public hidebysig newslot specialname abstract virtual 
          instance void  set_Subject([in] class CERTENROLLLib.CX500DistinguishedName  marshal( interface ) ppValue) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 0D 00 03 60 00 00 )                         // .....`..
  } // end of method IX509CertificateRequestCertificate2::set_Subject

  .method public specialname rtspecialname 
          instance void  _VtblGap5_7() runtime managed
  {
  } // end of method IX509CertificateRequestCertificate2::_VtblGap5_7

  .method public hidebysig newslot specialname abstract virtual 
          instance class CERTENROLLLib.CX509Extensions 
          marshal( interface ) 
          get_X509Extensions() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 16 00 03 60 00 00 )                         // .....`..
  } // end of method IX509CertificateRequestCertificate2::get_X509Extensions

  .method public specialname rtspecialname 
          instance void  _VtblGap6_6() runtime managed
  {
  } // end of method IX509CertificateRequestCertificate2::_VtblGap6_6

  .method public hidebysig newslot specialname abstract virtual 
          instance class CERTENROLLLib.CX500DistinguishedName 
          marshal( interface ) 
          get_Issuer() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 01 00 04 60 00 00 )                         // .....`..
  } // end of method IX509CertificateRequestCertificate2::get_Issuer

  .method public hidebysig newslot specialname abstract virtual 
          instance void  set_Issuer([in] class CERTENROLLLib.CX500DistinguishedName  marshal( interface ) ppValue) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 01 00 04 60 00 00 )                         // .....`..
  } // end of method IX509CertificateRequestCertificate2::set_Issuer

  .method public hidebysig newslot specialname abstract virtual 
          instance valuetype [mscorlib]System.DateTime 
          get_NotBefore() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 03 00 04 60 00 00 )                         // .....`..
  } // end of method IX509CertificateRequestCertificate2::get_NotBefore

  .method public hidebysig newslot specialname abstract virtual 
          instance void  set_NotBefore([in] valuetype [mscorlib]System.DateTime pValue) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 03 00 04 60 00 00 )                         // .....`..
  } // end of method IX509CertificateRequestCertificate2::set_NotBefore

  .method public hidebysig newslot specialname abstract virtual 
          instance valuetype [mscorlib]System.DateTime 
          get_NotAfter() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 05 00 04 60 00 00 )                         // .....`..
  } // end of method IX509CertificateRequestCertificate2::get_NotAfter

  .method public hidebysig newslot specialname abstract virtual 
          instance void  set_NotAfter([in] valuetype [mscorlib]System.DateTime pValue) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 05 00 04 60 00 00 )                         // .....`..
  } // end of method IX509CertificateRequestCertificate2::set_NotAfter

  .method public specialname rtspecialname 
          instance void  _VtblGap7_2() runtime managed
  {
  } // end of method IX509CertificateRequestCertificate2::_VtblGap7_2

  .method public hidebysig newslot specialname abstract virtual 
          instance class CERTENROLLLib.CSignerCertificate 
          marshal( interface ) 
          get_SignerCertificate() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 09 00 04 60 00 00 )                         // .....`..
  } // end of method IX509CertificateRequestCertificate2::get_SignerCertificate

  .method public hidebysig newslot specialname abstract virtual 
          instance void  set_SignerCertificate([in] class CERTENROLLLib.CSignerCertificate  marshal( interface ) ppValue) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 09 00 04 60 00 00 )                         // .....`..
  } // end of method IX509CertificateRequestCertificate2::set_SignerCertificate

  .property class CERTENROLLLib.CObjectId
          HashAlgorithm()
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 14 00 02 60 00 00 )                         // .....`..
    .get instance class CERTENROLLLib.CObjectId CERTENROLLLib.IX509CertificateRequestCertificate2::get_HashAlgorithm()
    .set instance void CERTENROLLLib.IX509CertificateRequestCertificate2::set_HashAlgorithm(class CERTENROLLLib.CObjectId)
  } // end of property IX509CertificateRequestCertificate2::HashAlgorithm
  .property class CERTENROLLLib.CX500DistinguishedName
          Subject()
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 0D 00 03 60 00 00 )                         // .....`..
    .get instance class CERTENROLLLib.CX500DistinguishedName CERTENROLLLib.IX509CertificateRequestCertificate2::get_Subject()
    .set instance void CERTENROLLLib.IX509CertificateRequestCertificate2::set_Subject(class CERTENROLLLib.CX500DistinguishedName)
  } // end of property IX509CertificateRequestCertificate2::Subject
  .property class CERTENROLLLib.CX509Extensions
          X509Extensions()
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 16 00 03 60 00 00 )                         // .....`..
    .get instance class CERTENROLLLib.CX509Extensions CERTENROLLLib.IX509CertificateRequestCertificate2::get_X509Extensions()
  } // end of property IX509CertificateRequestCertificate2::X509Extensions
  .property class CERTENROLLLib.CX500DistinguishedName
          Issuer()
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 01 00 04 60 00 00 )                         // .....`..
    .get instance class CERTENROLLLib.CX500DistinguishedName CERTENROLLLib.IX509CertificateRequestCertificate2::get_Issuer()
    .set instance void CERTENROLLLib.IX509CertificateRequestCertificate2::set_Issuer(class CERTENROLLLib.CX500DistinguishedName)
  } // end of property IX509CertificateRequestCertificate2::Issuer
  .property valuetype [mscorlib]System.DateTime
          NotBefore()
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 03 00 04 60 00 00 )                         // .....`..
    .get instance valuetype [mscorlib]System.DateTime CERTENROLLLib.IX509CertificateRequestCertificate2::get_NotBefore()
    .set instance void CERTENROLLLib.IX509CertificateRequestCertificate2::set_NotBefore(valuetype [mscorlib]System.DateTime)
  } // end of property IX509CertificateRequestCertificate2::NotBefore
  .property valuetype [mscorlib]System.DateTime
          NotAfter()
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 05 00 04 60 00 00 )                         // .....`..
    .get instance valuetype [mscorlib]System.DateTime CERTENROLLLib.IX509CertificateRequestCertificate2::get_NotAfter()
    .set instance void CERTENROLLLib.IX509CertificateRequestCertificate2::set_NotAfter(valuetype [mscorlib]System.DateTime)
  } // end of property IX509CertificateRequestCertificate2::NotAfter
  .property class CERTENROLLLib.CSignerCertificate
          SignerCertificate()
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 09 00 04 60 00 00 )                         // .....`..
    .get instance class CERTENROLLLib.CSignerCertificate CERTENROLLLib.IX509CertificateRequestCertificate2::get_SignerCertificate()
    .set instance void CERTENROLLLib.IX509CertificateRequestCertificate2::set_SignerCertificate(class CERTENROLLLib.CSignerCertificate)
  } // end of property IX509CertificateRequestCertificate2::SignerCertificate
} // end of class CERTENROLLLib.IX509CertificateRequestCertificate2

.class interface public abstract auto ansi import CERTENROLLLib.IX509CertificateRequestPkcs10
       implements CERTENROLLLib.IX509CertificateRequest
{
  .custom instance void [mscorlib]System.Runtime.CompilerServices.CompilerGeneratedAttribute::.ctor() = ( 01 00 00 00 ) 
  .custom instance void [mscorlib]System.Runtime.InteropServices.GuidAttribute::.ctor(string) = ( 01 00 24 37 32 38 41 42 33 34 32 2D 32 31 37 44   // ..$728AB342-217D
                                                                                                  2D 31 31 44 41 2D 42 32 41 34 2D 30 30 30 45 37   // -11DA-B2A4-000E7
                                                                                                  42 42 42 32 42 30 39 00 00 )                      // BBB2B09..
  .custom instance void [mscorlib]System.Runtime.InteropServices.TypeIdentifierAttribute::.ctor() = ( 01 00 00 00 ) 
} // end of class CERTENROLLLib.IX509CertificateRequestPkcs10

.class interface public abstract auto ansi import CERTENROLLLib.IX509Enrollment
{
  .custom instance void [mscorlib]System.Runtime.CompilerServices.CompilerGeneratedAttribute::.ctor() = ( 01 00 00 00 ) 
  .custom instance void [mscorlib]System.Runtime.InteropServices.GuidAttribute::.ctor(string) = ( 01 00 24 37 32 38 41 42 33 34 36 2D 32 31 37 44   // ..$728AB346-217D
                                                                                                  2D 31 31 44 41 2D 42 32 41 34 2D 30 30 30 45 37   // -11DA-B2A4-000E7
                                                                                                  42 42 42 32 42 30 39 00 00 )                      // BBB2B09..
  .custom instance void [mscorlib]System.Runtime.InteropServices.TypeIdentifierAttribute::.ctor() = ( 01 00 00 00 ) 
} // end of class CERTENROLLLib.IX509Enrollment

.class interface public abstract auto ansi import CERTENROLLLib.IX509Enrollment2
       implements CERTENROLLLib.IX509Enrollment
{
  .custom instance void [mscorlib]System.Runtime.CompilerServices.CompilerGeneratedAttribute::.ctor() = ( 01 00 00 00 ) 
  .custom instance void [mscorlib]System.Runtime.InteropServices.GuidAttribute::.ctor(string) = ( 01 00 24 37 32 38 41 42 33 35 30 2D 32 31 37 44   // ..$728AB350-217D
                                                                                                  2D 31 31 44 41 2D 42 32 41 34 2D 30 30 30 45 37   // -11DA-B2A4-000E7
                                                                                                  42 42 42 32 42 30 39 00 00 )                      // BBB2B09..
  .custom instance void [mscorlib]System.Runtime.InteropServices.TypeIdentifierAttribute::.ctor() = ( 01 00 00 00 ) 
  .method public specialname rtspecialname 
          instance void  _VtblGap1_2() runtime managed
  {
  } // end of method IX509Enrollment2::_VtblGap1_2

  .method public hidebysig newslot abstract virtual 
          instance void  InitializeFromRequest([in] class CERTENROLLLib.IX509CertificateRequest  marshal( interface ) pRequest) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 02 00 02 60 00 00 )                         // .....`..
  } // end of method IX509Enrollment2::InitializeFromRequest

  .method public hidebysig newslot abstract virtual 
          instance string 
          marshal( bstr) 
          CreateRequest([in][opt] valuetype CERTENROLLLib.EncodingType Encoding) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 03 00 02 60 00 00 )                         // .....`..
    .param [1] = int32(0x00000001)
  } // end of method IX509Enrollment2::CreateRequest

  .method public specialname rtspecialname 
          instance void  _VtblGap2_1() runtime managed
  {
  } // end of method IX509Enrollment2::_VtblGap2_1

  .method public hidebysig newslot abstract virtual 
          instance void  InstallResponse([in] valuetype CERTENROLLLib.InstallResponseRestrictionFlags Restrictions,
                                         [in] string  marshal( bstr) strResponse,
                                         [in] valuetype CERTENROLLLib.EncodingType Encoding,
                                         [in] string  marshal( bstr) strPassword) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 05 00 02 60 00 00 )                         // .....`..
  } // end of method IX509Enrollment2::InstallResponse

} // end of class CERTENROLLLib.IX509Enrollment2

.class interface public abstract auto ansi import CERTENROLLLib.IX509Extension
{
  .custom instance void [mscorlib]System.Runtime.CompilerServices.CompilerGeneratedAttribute::.ctor() = ( 01 00 00 00 ) 
  .custom instance void [mscorlib]System.Runtime.InteropServices.GuidAttribute::.ctor(string) = ( 01 00 24 37 32 38 41 42 33 30 44 2D 32 31 37 44   // ..$728AB30D-217D
                                                                                                  2D 31 31 44 41 2D 42 32 41 34 2D 30 30 30 45 37   // -11DA-B2A4-000E7
                                                                                                  42 42 42 32 42 30 39 00 00 )                      // BBB2B09..
  .custom instance void [mscorlib]System.Runtime.InteropServices.TypeIdentifierAttribute::.ctor() = ( 01 00 00 00 ) 
} // end of class CERTENROLLLib.IX509Extension

.class interface public abstract auto ansi import CERTENROLLLib.IX509ExtensionAlternativeNames
       implements CERTENROLLLib.IX509Extension
{
  .custom instance void [mscorlib]System.Runtime.CompilerServices.CompilerGeneratedAttribute::.ctor() = ( 01 00 00 00 ) 
  .custom instance void [mscorlib]System.Runtime.InteropServices.GuidAttribute::.ctor(string) = ( 01 00 24 37 32 38 41 42 33 31 35 2D 32 31 37 44   // ..$728AB315-217D
                                                                                                  2D 31 31 44 41 2D 42 32 41 34 2D 30 30 30 45 37   // -11DA-B2A4-000E7
                                                                                                  42 42 42 32 42 30 39 00 00 )                      // BBB2B09..
  .custom instance void [mscorlib]System.Runtime.InteropServices.TypeIdentifierAttribute::.ctor() = ( 01 00 00 00 ) 
  .method public specialname rtspecialname 
          instance void  _VtblGap1_5() runtime managed
  {
  } // end of method IX509ExtensionAlternativeNames::_VtblGap1_5

  .method public hidebysig newslot abstract virtual 
          instance void  InitializeEncode([in] class CERTENROLLLib.CAlternativeNames  marshal( interface ) pValue) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 00 00 03 60 00 00 )                         // .....`..
  } // end of method IX509ExtensionAlternativeNames::InitializeEncode

} // end of class CERTENROLLLib.IX509ExtensionAlternativeNames

.class interface public abstract auto ansi import CERTENROLLLib.IX509ExtensionBasicConstraints
       implements CERTENROLLLib.IX509Extension
{
  .custom instance void [mscorlib]System.Runtime.CompilerServices.CompilerGeneratedAttribute::.ctor() = ( 01 00 00 00 ) 
  .custom instance void [mscorlib]System.Runtime.InteropServices.GuidAttribute::.ctor(string) = ( 01 00 24 37 32 38 41 42 33 31 36 2D 32 31 37 44   // ..$728AB316-217D
                                                                                                  2D 31 31 44 41 2D 42 32 41 34 2D 30 30 30 45 37   // -11DA-B2A4-000E7
                                                                                                  42 42 42 32 42 30 39 00 00 )                      // BBB2B09..
  .custom instance void [mscorlib]System.Runtime.InteropServices.TypeIdentifierAttribute::.ctor() = ( 01 00 00 00 ) 
  .method public specialname rtspecialname 
          instance void  _VtblGap1_5() runtime managed
  {
  } // end of method IX509ExtensionBasicConstraints::_VtblGap1_5

  .method public hidebysig newslot abstract virtual 
          instance void  InitializeEncode([in] bool IsCA,
                                          [in] int32 PathLenConstraint) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 00 00 03 60 00 00 )                         // .....`..
  } // end of method IX509ExtensionBasicConstraints::InitializeEncode

} // end of class CERTENROLLLib.IX509ExtensionBasicConstraints

.class interface public abstract auto ansi import CERTENROLLLib.IX509ExtensionEnhancedKeyUsage
       implements CERTENROLLLib.IX509Extension
{
  .custom instance void [mscorlib]System.Runtime.CompilerServices.CompilerGeneratedAttribute::.ctor() = ( 01 00 00 00 ) 
  .custom instance void [mscorlib]System.Runtime.InteropServices.GuidAttribute::.ctor(string) = ( 01 00 24 37 32 38 41 42 33 31 30 2D 32 31 37 44   // ..$728AB310-217D
                                                                                                  2D 31 31 44 41 2D 42 32 41 34 2D 30 30 30 45 37   // -11DA-B2A4-000E7
                                                                                                  42 42 42 32 42 30 39 00 00 )                      // BBB2B09..
  .custom instance void [mscorlib]System.Runtime.InteropServices.TypeIdentifierAttribute::.ctor() = ( 01 00 00 00 ) 
  .method public specialname rtspecialname 
          instance void  _VtblGap1_5() runtime managed
  {
  } // end of method IX509ExtensionEnhancedKeyUsage::_VtblGap1_5

  .method public hidebysig newslot abstract virtual 
          instance void  InitializeEncode([in] class CERTENROLLLib.CObjectIds  marshal( interface ) pValue) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 00 00 03 60 00 00 )                         // .....`..
  } // end of method IX509ExtensionEnhancedKeyUsage::InitializeEncode

} // end of class CERTENROLLLib.IX509ExtensionEnhancedKeyUsage

.class interface public abstract auto ansi import CERTENROLLLib.IX509Extensions
       implements [mscorlib]System.Collections.IEnumerable
{
  .custom instance void [mscorlib]System.Runtime.CompilerServices.CompilerGeneratedAttribute::.ctor() = ( 01 00 00 00 ) 
  .custom instance void [mscorlib]System.Reflection.DefaultMemberAttribute::.ctor(string) = ( 01 00 0B 49 74 65 6D 42 79 49 6E 64 65 78 00 00 ) // ...ItemByIndex..
  .custom instance void [mscorlib]System.Runtime.InteropServices.GuidAttribute::.ctor(string) = ( 01 00 24 37 32 38 41 42 33 30 45 2D 32 31 37 44   // ..$728AB30E-217D
                                                                                                  2D 31 31 44 41 2D 42 32 41 34 2D 30 30 30 45 37   // -11DA-B2A4-000E7
                                                                                                  42 42 42 32 42 30 39 00 00 )                      // BBB2B09..
  .custom instance void [mscorlib]System.Runtime.InteropServices.TypeIdentifierAttribute::.ctor() = ( 01 00 00 00 ) 
  .method public specialname rtspecialname 
          instance void  _VtblGap1_3() runtime managed
  {
  } // end of method IX509Extensions::_VtblGap1_3

  .method public hidebysig newslot abstract virtual 
          instance void  Add([in] class CERTENROLLLib.CX509Extension  marshal( interface ) pVal) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 02 00 00 00 00 00 ) 
  } // end of method IX509Extensions::Add

} // end of class CERTENROLLLib.IX509Extensions

.class interface public abstract auto ansi import CERTENROLLLib.IX509PrivateKey
{
  .custom instance void [mscorlib]System.Runtime.CompilerServices.CompilerGeneratedAttribute::.ctor() = ( 01 00 00 00 ) 
  .custom instance void [mscorlib]System.Runtime.InteropServices.GuidAttribute::.ctor(string) = ( 01 00 24 37 32 38 41 42 33 30 43 2D 32 31 37 44   // ..$728AB30C-217D
                                                                                                  2D 31 31 44 41 2D 42 32 41 34 2D 30 30 30 45 37   // -11DA-B2A4-000E7
                                                                                                  42 42 42 32 42 30 39 00 00 )                      // BBB2B09..
  .custom instance void [mscorlib]System.Runtime.InteropServices.TypeIdentifierAttribute::.ctor() = ( 01 00 00 00 ) 
} // end of class CERTENROLLLib.IX509PrivateKey

.class interface public abstract auto ansi import CERTENROLLLib.IX509PrivateKey2
       implements CERTENROLLLib.IX509PrivateKey
{
  .custom instance void [mscorlib]System.Runtime.CompilerServices.CompilerGeneratedAttribute::.ctor() = ( 01 00 00 00 ) 
  .custom instance void [mscorlib]System.Runtime.InteropServices.GuidAttribute::.ctor(string) = ( 01 00 24 37 32 38 41 42 33 36 32 2D 32 31 37 44   // ..$728AB362-217D
                                                                                                  2D 31 31 44 41 2D 42 32 41 34 2D 30 30 30 45 37   // -11DA-B2A4-000E7
                                                                                                  42 42 42 32 42 30 39 00 00 )                      // BBB2B09..
  .custom instance void [mscorlib]System.Runtime.InteropServices.TypeIdentifierAttribute::.ctor() = ( 01 00 00 00 ) 
  .method public specialname rtspecialname 
          instance void  _VtblGap1_1() runtime managed
  {
  } // end of method IX509PrivateKey2::_VtblGap1_1

  .method public hidebysig newslot abstract virtual 
          instance void  Create() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 01 00 02 60 00 00 )                         // .....`..
  } // end of method IX509PrivateKey2::Create

  .method public specialname rtspecialname 
          instance void  _VtblGap2_16() runtime managed
  {
  } // end of method IX509PrivateKey2::_VtblGap2_16

  .method public hidebysig newslot specialname abstract virtual 
          instance string 
          marshal( bstr) 
          get_ProviderName() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 12 00 02 60 00 00 )                         // .....`..
  } // end of method IX509PrivateKey2::get_ProviderName

  .method public hidebysig newslot specialname abstract virtual 
          instance void  set_ProviderName([in] string  marshal( bstr) pValue) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 12 00 02 60 00 00 )                         // .....`..
  } // end of method IX509PrivateKey2::set_ProviderName

  .method public specialname rtspecialname 
          instance void  _VtblGap3_6() runtime managed
  {
  } // end of method IX509PrivateKey2::_VtblGap3_6

  .method public hidebysig newslot specialname abstract virtual 
          instance valuetype CERTENROLLLib.X509KeySpec 
          get_KeySpec() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 1A 00 02 60 00 00 )                         // .....`..
  } // end of method IX509PrivateKey2::get_KeySpec

  .method public hidebysig newslot specialname abstract virtual 
          instance void  set_KeySpec([in] valuetype CERTENROLLLib.X509KeySpec pValue) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 1A 00 02 60 00 00 )                         // .....`..
  } // end of method IX509PrivateKey2::set_KeySpec

  .method public hidebysig newslot specialname abstract virtual 
          instance int32  get_Length() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 1C 00 02 60 00 00 )                         // .....`..
  } // end of method IX509PrivateKey2::get_Length

  .method public hidebysig newslot specialname abstract virtual 
          instance void  set_Length([in] int32 pValue) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 1C 00 02 60 00 00 )                         // .....`..
  } // end of method IX509PrivateKey2::set_Length

  .method public specialname rtspecialname 
          instance void  _VtblGap4_6() runtime managed
  {
  } // end of method IX509PrivateKey2::_VtblGap4_6

  .method public hidebysig newslot specialname abstract virtual 
          instance bool  get_MachineContext() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 24 00 02 60 00 00 )                         // ..$..`..
  } // end of method IX509PrivateKey2::get_MachineContext

  .method public hidebysig newslot specialname abstract virtual 
          instance void  set_MachineContext([in] bool pValue) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 24 00 02 60 00 00 )                         // ..$..`..
  } // end of method IX509PrivateKey2::set_MachineContext

  .property string ProviderName()
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 12 00 02 60 00 00 )                         // .....`..
    .get instance string CERTENROLLLib.IX509PrivateKey2::get_ProviderName()
    .set instance void CERTENROLLLib.IX509PrivateKey2::set_ProviderName(string)
  } // end of property IX509PrivateKey2::ProviderName
  .property valuetype CERTENROLLLib.X509KeySpec
          KeySpec()
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 1A 00 02 60 00 00 )                         // .....`..
    .get instance valuetype CERTENROLLLib.X509KeySpec CERTENROLLLib.IX509PrivateKey2::get_KeySpec()
    .set instance void CERTENROLLLib.IX509PrivateKey2::set_KeySpec(valuetype CERTENROLLLib.X509KeySpec)
  } // end of property IX509PrivateKey2::KeySpec
  .property int32 Length()
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 1C 00 02 60 00 00 )                         // .....`..
    .get instance int32 CERTENROLLLib.IX509PrivateKey2::get_Length()
    .set instance void CERTENROLLLib.IX509PrivateKey2::set_Length(int32)
  } // end of property IX509PrivateKey2::Length
  .property bool MachineContext()
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 24 00 02 60 00 00 )                         // ..$..`..
    .get instance bool CERTENROLLLib.IX509PrivateKey2::get_MachineContext()
    .set instance void CERTENROLLLib.IX509PrivateKey2::set_MachineContext(bool)
  } // end of property IX509PrivateKey2::MachineContext
} // end of class CERTENROLLLib.IX509PrivateKey2

.class public auto ansi sealed CERTENROLLLib.InstallResponseRestrictionFlags
       extends [mscorlib]System.Enum
{
  .custom instance void [mscorlib]System.Runtime.CompilerServices.CompilerGeneratedAttribute::.ctor() = ( 01 00 00 00 ) 
  .custom instance void [mscorlib]System.Runtime.InteropServices.TypeIdentifierAttribute::.ctor(string,
                                                                                                string) = ( 01 00 24 37 32 38 61 62 33 34 38 2D 32 31 37 64   // ..$728ab348-217d
                                                                                                            2D 31 31 64 61 2D 62 32 61 34 2D 30 30 30 65 37   // -11da-b2a4-000e7
                                                                                                            62 62 62 32 62 30 39 2D 43 45 52 54 45 4E 52 4F   // bbb2b09-CERTENRO
                                                                                                            4C 4C 4C 69 62 2E 49 6E 73 74 61 6C 6C 52 65 73   // LLLib.InstallRes
                                                                                                            70 6F 6E 73 65 52 65 73 74 72 69 63 74 69 6F 6E   // ponseRestriction
                                                                                                            46 6C 61 67 73 00 00 )                            // Flags..
  .field public specialname rtspecialname int32 value__
  .field public static literal valuetype CERTENROLLLib.InstallResponseRestrictionFlags AllowNone = int32(0x00000000)
  .field public static literal valuetype CERTENROLLLib.InstallResponseRestrictionFlags AllowNoOutstandingRequest = int32(0x00000001)
  .field public static literal valuetype CERTENROLLLib.InstallResponseRestrictionFlags AllowUntrustedCertificate = int32(0x00000002)
  .field public static literal valuetype CERTENROLLLib.InstallResponseRestrictionFlags AllowUntrustedRoot = int32(0x00000004)
} // end of class CERTENROLLLib.InstallResponseRestrictionFlags

.class public auto ansi sealed CERTENROLLLib.ObjectIdGroupId
       extends [mscorlib]System.Enum
{
  .custom instance void [mscorlib]System.Runtime.CompilerServices.CompilerGeneratedAttribute::.ctor() = ( 01 00 00 00 ) 
  .custom instance void [mscorlib]System.Runtime.InteropServices.TypeIdentifierAttribute::.ctor(string,
                                                                                                string) = ( 01 00 24 37 32 38 61 62 33 34 38 2D 32 31 37 64   // ..$728ab348-217d
                                                                                                            2D 31 31 64 61 2D 62 32 61 34 2D 30 30 30 65 37   // -11da-b2a4-000e7
                                                                                                            62 62 62 32 62 30 39 1D 43 45 52 54 45 4E 52 4F   // bbb2b09.CERTENRO
                                                                                                            4C 4C 4C 69 62 2E 4F 62 6A 65 63 74 49 64 47 72   // LLLib.ObjectIdGr
                                                                                                            6F 75 70 49 64 00 00 )                            // oupId..
  .field public specialname rtspecialname int32 value__
  .field public static literal valuetype CERTENROLLLib.ObjectIdGroupId XCN_CRYPT_ANY_GROUP_ID = int32(0x00000000)
  .field public static literal valuetype CERTENROLLLib.ObjectIdGroupId XCN_CRYPT_HASH_ALG_OID_GROUP_ID = int32(0x00000001)
  .field public static literal valuetype CERTENROLLLib.ObjectIdGroupId XCN_CRYPT_ENCRYPT_ALG_OID_GROUP_ID = int32(0x00000002)
  .field public static literal valuetype CERTENROLLLib.ObjectIdGroupId XCN_CRYPT_PUBKEY_ALG_OID_GROUP_ID = int32(0x00000003)
  .field public static literal valuetype CERTENROLLLib.ObjectIdGroupId XCN_CRYPT_SIGN_ALG_OID_GROUP_ID = int32(0x00000004)
  .field public static literal valuetype CERTENROLLLib.ObjectIdGroupId XCN_CRYPT_RDN_ATTR_OID_GROUP_ID = int32(0x00000005)
  .field public static literal valuetype CERTENROLLLib.ObjectIdGroupId XCN_CRYPT_EXT_OR_ATTR_OID_GROUP_ID = int32(0x00000006)
  .field public static literal valuetype CERTENROLLLib.ObjectIdGroupId XCN_CRYPT_ENHKEY_USAGE_OID_GROUP_ID = int32(0x00000007)
  .field public static literal valuetype CERTENROLLLib.ObjectIdGroupId XCN_CRYPT_POLICY_OID_GROUP_ID = int32(0x00000008)
  .field public static literal valuetype CERTENROLLLib.ObjectIdGroupId XCN_CRYPT_TEMPLATE_OID_GROUP_ID = int32(0x00000009)
  .field public static literal valuetype CERTENROLLLib.ObjectIdGroupId XCN_CRYPT_KDF_OID_GROUP_ID = int32(0x0000000A)
  .field public static literal valuetype CERTENROLLLib.ObjectIdGroupId XCN_CRYPT_LAST_OID_GROUP_ID = int32(0x0000000A)
  .field public static literal valuetype CERTENROLLLib.ObjectIdGroupId XCN_CRYPT_FIRST_ALG_OID_GROUP_ID = int32(0x00000001)
  .field public static literal valuetype CERTENROLLLib.ObjectIdGroupId XCN_CRYPT_LAST_ALG_OID_GROUP_ID = int32(0x00000004)
  .field public static literal valuetype CERTENROLLLib.ObjectIdGroupId XCN_CRYPT_GROUP_ID_MASK = int32(0x0000FFFF)
  .field public static literal valuetype CERTENROLLLib.ObjectIdGroupId XCN_CRYPT_OID_PREFER_CNG_ALGID_FLAG = int32(0x40000000)
  .field public static literal valuetype CERTENROLLLib.ObjectIdGroupId XCN_CRYPT_OID_DISABLE_SEARCH_DS_FLAG = int32(0x80000000)
  .field public static literal valuetype CERTENROLLLib.ObjectIdGroupId XCN_CRYPT_OID_INFO_OID_GROUP_BIT_LEN_MASK = int32(0x0FFF0000)
  .field public static literal valuetype CERTENROLLLib.ObjectIdGroupId XCN_CRYPT_OID_INFO_OID_GROUP_BIT_LEN_SHIFT = int32(0x00000010)
  .field public static literal valuetype CERTENROLLLib.ObjectIdGroupId XCN_CRYPT_KEY_LENGTH_MASK = int32(0x0FFF0000)
} // end of class CERTENROLLLib.ObjectIdGroupId

.class public auto ansi sealed CERTENROLLLib.ObjectIdPublicKeyFlags
       extends [mscorlib]System.Enum
{
  .custom instance void [mscorlib]System.Runtime.CompilerServices.CompilerGeneratedAttribute::.ctor() = ( 01 00 00 00 ) 
  .custom instance void [mscorlib]System.Runtime.InteropServices.TypeIdentifierAttribute::.ctor(string,
                                                                                                string) = ( 01 00 24 37 32 38 61 62 33 34 38 2D 32 31 37 64   // ..$728ab348-217d
                                                                                                            2D 31 31 64 61 2D 62 32 61 34 2D 30 30 30 65 37   // -11da-b2a4-000e7
                                                                                                            62 62 62 32 62 30 39 24 43 45 52 54 45 4E 52 4F   // bbb2b09$CERTENRO
                                                                                                            4C 4C 4C 69 62 2E 4F 62 6A 65 63 74 49 64 50 75   // LLLib.ObjectIdPu
                                                                                                            62 6C 69 63 4B 65 79 46 6C 61 67 73 00 00 )       // blicKeyFlags..
  .field public specialname rtspecialname int32 value__
  .field public static literal valuetype CERTENROLLLib.ObjectIdPublicKeyFlags XCN_CRYPT_OID_INFO_PUBKEY_ANY = int32(0x00000000)
  .field public static literal valuetype CERTENROLLLib.ObjectIdPublicKeyFlags XCN_CRYPT_OID_INFO_PUBKEY_SIGN_KEY_FLAG = int32(0x80000000)
  .field public static literal valuetype CERTENROLLLib.ObjectIdPublicKeyFlags XCN_CRYPT_OID_INFO_PUBKEY_ENCRYPT_KEY_FLAG = int32(0x40000000)
} // end of class CERTENROLLLib.ObjectIdPublicKeyFlags

.class public auto ansi sealed CERTENROLLLib.X500NameFlags
       extends [mscorlib]System.Enum
{
  .custom instance void [mscorlib]System.Runtime.CompilerServices.CompilerGeneratedAttribute::.ctor() = ( 01 00 00 00 ) 
  .custom instance void [mscorlib]System.Runtime.InteropServices.TypeIdentifierAttribute::.ctor(string,
                                                                                                string) = ( 01 00 24 37 32 38 61 62 33 34 38 2D 32 31 37 64   // ..$728ab348-217d
                                                                                                            2D 31 31 64 61 2D 62 32 61 34 2D 30 30 30 65 37   // -11da-b2a4-000e7
                                                                                                            62 62 62 32 62 30 39 1B 43 45 52 54 45 4E 52 4F   // bbb2b09.CERTENRO
                                                                                                            4C 4C 4C 69 62 2E 58 35 30 30 4E 61 6D 65 46 6C   // LLLib.X500NameFl
                                                                                                            61 67 73 00 00 )                                  // ags..
  .field public specialname rtspecialname int32 value__
  .field public static literal valuetype CERTENROLLLib.X500NameFlags XCN_CERT_NAME_STR_NONE = int32(0x00000000)
  .field public static literal valuetype CERTENROLLLib.X500NameFlags XCN_CERT_SIMPLE_NAME_STR = int32(0x00000001)
  .field public static literal valuetype CERTENROLLLib.X500NameFlags XCN_CERT_OID_NAME_STR = int32(0x00000002)
  .field public static literal valuetype CERTENROLLLib.X500NameFlags XCN_CERT_X500_NAME_STR = int32(0x00000003)
  .field public static literal valuetype CERTENROLLLib.X500NameFlags XCN_CERT_XML_NAME_STR = int32(0x00000004)
  .field public static literal valuetype CERTENROLLLib.X500NameFlags XCN_CERT_NAME_STR_SEMICOLON_FLAG = int32(0x40000000)
  .field public static literal valuetype CERTENROLLLib.X500NameFlags XCN_CERT_NAME_STR_NO_PLUS_FLAG = int32(0x20000000)
  .field public static literal valuetype CERTENROLLLib.X500NameFlags XCN_CERT_NAME_STR_NO_QUOTING_FLAG = int32(0x10000000)
  .field public static literal valuetype CERTENROLLLib.X500NameFlags XCN_CERT_NAME_STR_CRLF_FLAG = int32(0x08000000)
  .field public static literal valuetype CERTENROLLLib.X500NameFlags XCN_CERT_NAME_STR_COMMA_FLAG = int32(0x04000000)
  .field public static literal valuetype CERTENROLLLib.X500NameFlags XCN_CERT_NAME_STR_REVERSE_FLAG = int32(0x02000000)
  .field public static literal valuetype CERTENROLLLib.X500NameFlags XCN_CERT_NAME_STR_FORWARD_FLAG = int32(0x01000000)
  .field public static literal valuetype CERTENROLLLib.X500NameFlags XCN_CERT_NAME_STR_AMBIGUOUS_SEPARATOR_FLAGS = int32(0x4C000000)
  .field public static literal valuetype CERTENROLLLib.X500NameFlags XCN_CERT_NAME_STR_DISABLE_IE4_UTF8_FLAG = int32(0x00010000)
  .field public static literal valuetype CERTENROLLLib.X500NameFlags XCN_CERT_NAME_STR_ENABLE_T61_UNICODE_FLAG = int32(0x00020000)
  .field public static literal valuetype CERTENROLLLib.X500NameFlags XCN_CERT_NAME_STR_ENABLE_UTF8_UNICODE_FLAG = int32(0x00040000)
  .field public static literal valuetype CERTENROLLLib.X500NameFlags XCN_CERT_NAME_STR_FORCE_UTF8_DIR_STR_FLAG = int32(0x00080000)
  .field public static literal valuetype CERTENROLLLib.X500NameFlags XCN_CERT_NAME_STR_DISABLE_UTF8_DIR_STR_FLAG = int32(0x00100000)
  .field public static literal valuetype CERTENROLLLib.X500NameFlags XCN_CERT_NAME_STR_ENABLE_PUNYCODE_FLAG = int32(0x00200000)
  .field public static literal valuetype CERTENROLLLib.X500NameFlags XCN_CERT_NAME_STR_DS_ESCAPED = int32(0x00800000)
} // end of class CERTENROLLLib.X500NameFlags

.class public auto ansi sealed CERTENROLLLib.X509CertificateEnrollmentContext
       extends [mscorlib]System.Enum
{
  .custom instance void [mscorlib]System.Runtime.CompilerServices.CompilerGeneratedAttribute::.ctor() = ( 01 00 00 00 ) 
  .custom instance void [mscorlib]System.Runtime.InteropServices.TypeIdentifierAttribute::.ctor(string,
                                                                                                string) = ( 01 00 24 37 32 38 61 62 33 34 38 2D 32 31 37 64   // ..$728ab348-217d
                                                                                                            2D 31 31 64 61 2D 62 32 61 34 2D 30 30 30 65 37   // -11da-b2a4-000e7
                                                                                                            62 62 62 32 62 30 39 2E 43 45 52 54 45 4E 52 4F   // bbb2b09.CERTENRO
                                                                                                            4C 4C 4C 69 62 2E 58 35 30 39 43 65 72 74 69 66   // LLLib.X509Certif
                                                                                                            69 63 61 74 65 45 6E 72 6F 6C 6C 6D 65 6E 74 43   // icateEnrollmentC
                                                                                                            6F 6E 74 65 78 74 00 00 )                         // ontext..
  .field public specialname rtspecialname int32 value__
  .field public static literal valuetype CERTENROLLLib.X509CertificateEnrollmentContext ContextNone = int32(0x00000000)
  .field public static literal valuetype CERTENROLLLib.X509CertificateEnrollmentContext ContextUser = int32(0x00000001)
  .field public static literal valuetype CERTENROLLLib.X509CertificateEnrollmentContext ContextMachine = int32(0x00000002)
  .field public static literal valuetype CERTENROLLLib.X509CertificateEnrollmentContext ContextAdministratorForceMachine = int32(0x00000003)
} // end of class CERTENROLLLib.X509CertificateEnrollmentContext

.class public auto ansi sealed CERTENROLLLib.X509KeySpec
       extends [mscorlib]System.Enum
{
  .custom instance void [mscorlib]System.Runtime.CompilerServices.CompilerGeneratedAttribute::.ctor() = ( 01 00 00 00 ) 
  .custom instance void [mscorlib]System.Runtime.InteropServices.TypeIdentifierAttribute::.ctor(string,
                                                                                                string) = ( 01 00 24 37 32 38 61 62 33 34 38 2D 32 31 37 64   // ..$728ab348-217d
                                                                                                            2D 31 31 64 61 2D 62 32 61 34 2D 30 30 30 65 37   // -11da-b2a4-000e7
                                                                                                            62 62 62 32 62 30 39 19 43 45 52 54 45 4E 52 4F   // bbb2b09.CERTENRO
                                                                                                            4C 4C 4C 69 62 2E 58 35 30 39 4B 65 79 53 70 65   // LLLib.X509KeySpe
                                                                                                            63 00 00 )                                        // c..
  .field public specialname rtspecialname int32 value__
  .field public static literal valuetype CERTENROLLLib.X509KeySpec XCN_AT_NONE = int32(0x00000000)
  .field public static literal valuetype CERTENROLLLib.X509KeySpec XCN_AT_KEYEXCHANGE = int32(0x00000001)
  .field public static literal valuetype CERTENROLLLib.X509KeySpec XCN_AT_SIGNATURE = int32(0x00000002)
} // end of class CERTENROLLLib.X509KeySpec

.class public auto ansi sealed CERTENROLLLib.X509PrivateKeyVerify
       extends [mscorlib]System.Enum
{
  .custom instance void [mscorlib]System.Runtime.CompilerServices.CompilerGeneratedAttribute::.ctor() = ( 01 00 00 00 ) 
  .custom instance void [mscorlib]System.Runtime.InteropServices.TypeIdentifierAttribute::.ctor(string,
                                                                                                string) = ( 01 00 24 37 32 38 61 62 33 34 38 2D 32 31 37 64   // ..$728ab348-217d
                                                                                                            2D 31 31 64 61 2D 62 32 61 34 2D 30 30 30 65 37   // -11da-b2a4-000e7
                                                                                                            62 62 62 32 62 30 39 22 43 45 52 54 45 4E 52 4F   // bbb2b09"CERTENRO
                                                                                                            4C 4C 4C 69 62 2E 58 35 30 39 50 72 69 76 61 74   // LLLib.X509Privat
                                                                                                            65 4B 65 79 56 65 72 69 66 79 00 00 )             // eKeyVerify..
  .field public specialname rtspecialname int32 value__
  .field public static literal valuetype CERTENROLLLib.X509PrivateKeyVerify VerifyNone = int32(0x00000000)
  .field public static literal valuetype CERTENROLLLib.X509PrivateKeyVerify VerifySilent = int32(0x00000001)
  .field public static literal valuetype CERTENROLLLib.X509PrivateKeyVerify VerifySmartCardNone = int32(0x00000002)
  .field public static literal valuetype CERTENROLLLib.X509PrivateKeyVerify VerifySmartCardSilent = int32(0x00000003)
  .field public static literal valuetype CERTENROLLLib.X509PrivateKeyVerify VerifyAllowUI = int32(0x00000004)
} // end of class CERTENROLLLib.X509PrivateKeyVerify


// =============================================================

// *********** DISASSEMBLY COMPLETE ***********************
// WARNING: Created Win32 resource file HttpProxyServer.res
