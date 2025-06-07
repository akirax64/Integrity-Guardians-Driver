/*++

Module Name:

    public.h

Abstract:

    This module contains the common declarations shared by driver
    and user applications.

Environment:

    user and kernel

--*/

//
// Define an Interface Guid so that apps can find the device and talk to it.
//

DEFINE_GUID (GUID_DEVINTERFACE_IGWinx64Driver,
    0x34c31c73,0x73ea,0x4048,0x9b,0x3e,0x6f,0x7c,0x68,0x9c,0x30,0x8c);
// {34c31c73-73ea-4048-9b3e-6f7c689c308c}
