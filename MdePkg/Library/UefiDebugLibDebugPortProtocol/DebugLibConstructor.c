/** @file
  UEFI Dxe DebugLib constructor that prevent some debug service after ExitBootServices event,
  because some pointer is nulled at that phase.

  Copyright (c) 2018, Microsoft Corporation
  Copyright (c) 2015 - 2019, Intel Corporation. All rights reserved.<BR>

  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/DebugLib.h>
#include <Library/BaseMemoryLib.h>

//
// BOOLEAN value to indicate if it is at the post ExitBootServices pahse
//
BOOLEAN     mPostEBS = FALSE;

static EFI_EVENT   mExitBootServicesEvent;

//
// Pointer to SystemTable
// This library instance may have a cycle consume with UefiBootServicesTableLib
// because of the constructors.
//
EFI_BOOT_SERVICES     *mDebugBS;

/**
  This routine sets the mPostEBS for exit boot servies true
  to prevent DebugPort protocol dereferences when the pointer is nulled.

  @param  Event        Event whose notification function is being invoked.
  @param  Context      Pointer to the notification function's context.

**/
STATIC // MU_CHANGE - changed to static to avoid conflicts
VOID
EFIAPI
ExitBootServicesCallback (
  EFI_EVENT   Event,
  VOID*       Context
  )
{
  mPostEBS = TRUE;
  return;
}

/** MU_CHANGE START
* Destructor for Debug Port Protocol Lib. Unregisters EBS callback to prevent
* function calls on unloaded library
*
* @param  ImageHandle   The firmware allocated handle for the EFI image.
* @param  SystemTable   A pointer to the EFI System Table.
*
* @retval EFI_SUCCESS   The constructor always returns EFI_SUCCESS.
*
**/
EFI_STATUS
EFIAPI
RuntimeDebugLibDestructor(
    IN      EFI_HANDLE                ImageHandle,
    IN      EFI_SYSTEM_TABLE          *SystemTable
) {
  EFI_STATUS Status;

  if(mExitBootServicesEvent != NULL) {
    Status = mDebugBS->CloseEvent(mExitBootServicesEvent);
    ASSERT_EFI_ERROR (Status);
  }

  return EFI_SUCCESS;
} //MU_CHANGE END

/**
  The constructor gets the pointers to boot services table.
  And create a event to indicate it is after ExitBootServices.

  @param  ImageHandle     The firmware allocated handle for the EFI image.
  @param  SystemTable     A pointer to the EFI System Table.

  @retval EFI_SUCCESS     The constructor always returns EFI_SUCCESS.

**/
EFI_STATUS
EFIAPI
DxeDebugLibConstructor(
  IN EFI_HANDLE                 ImageHandle,
  IN EFI_SYSTEM_TABLE           *SystemTable
  )
{
  mDebugBS = SystemTable->BootServices;

  mDebugBS->CreateEventEx (
              EVT_NOTIFY_SIGNAL,
              TPL_NOTIFY,
              ExitBootServicesCallback,
              NULL,
              &gEfiEventExitBootServicesGuid,
              &mExitBootServicesEvent
              );

  return EFI_SUCCESS;
}
