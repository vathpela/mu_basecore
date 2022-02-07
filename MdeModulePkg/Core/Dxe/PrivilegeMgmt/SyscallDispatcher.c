/** @file
Agent Module to load other modules to deploy SMM Entry Vector for X86 CPU.
Copyright (c) 2020, AMD Incorporated. All rights reserved.<BR>
Copyright (c) Microsoft Corporation.

SPDX-License-Identifier: BSD-2-Clause-Patent

**/
#include <PiDxe.h>
#include <SmmSecurePolicy.h>

#include <Protocol/MmCpuIo.h>
#include <Protocol/MmCpu.h>

#include <Library/BaseLib.h>
#include <Library/CpuLib.h>
#include <Library/DebugLib.h>
#include <Library/IoLib.h>
#include <Library/SysCallLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/SmmPolicyGateLib.h>

#include "DxeMain.h"
#include "PrivilegeMgmt.h"

EFI_BOOT_SERVICES                   *gUserBS = NULL;
SMM_SUPV_SECURE_POLICY_DATA_V1_0    *FirmwarePolicy = NULL;

// VOID
// EFIAPI
// SyncEntryContextToCpl3 (
//   VOID
// )
// {
//   EFI_MM_STARTUP_THIS_AP UserStartupThisAp;

//   // Note: Need to make sure all the synchronized content is accessible from CPL3
//   // Otherwise all contents needs to go through syscall
//   if (gMmUserMmst != NULL) {
//     UserStartupThisAp = gMmUserMmst->MmStartupThisAp;
//     CopyMem (&(gMmUserMmst->MmStartupThisAp), &gMmCoreMmst.MmStartupThisAp, sizeof (EFI_MM_ENTRY_CONTEXT));
//     gMmUserMmst->CpuSaveStateSize = NULL;
//     gMmUserMmst->CpuSaveState = NULL;
//     // This is needed otherwise CPL3 code will call into supervisor code directly.
//     gMmUserMmst->MmStartupThisAp = UserStartupThisAp;
//   }
// }

/**
  Helper function that will evaluate the page where the input address is located belongs to a
  user page that is mapped inside MM.

  @param  Address           Target address to be inspected.
  @param  Size              Address range to be inspected.
  @param  IsUserRange       Pointer to hold inspection result, TRUE if the region is in User pages, FALSE if
                            the page is in supervisor pages. Should not be used if return value is not EFI_SUCCESS.

  @return     The result of inspection operation.

**/
STATIC
EFI_STATUS
InspectTargetRangeOwnership (
  IN  EFI_PHYSICAL_ADDRESS    Address,
  IN  UINTN                   Size,
  OUT BOOLEAN                 *IsUserRange
)
{
  EFI_STATUS              Status;

  if (Address < EFI_PAGE_SIZE || Size == 0 || IsUserRange == NULL) {
    Status = EFI_INVALID_PARAMETER;
  }

  // MU_CHANGE: DXE_SUPV: To be implemented here
  *IsUserRange = TRUE;
  Status = EFI_SUCCESS;

  return Status;
}

/**
  Conduct Syscall dispatch.
**/
UINT64
EFIAPI
SyscallDispatcher (
  UINTN         CallIndex,
  UINTN         Arg1,
  UINTN         Arg2,
  UINTN         Arg3,
  UINTN         CallerAddr,
  UINTN         Ring3StackPointer
  )
{
  UINT64      Ret = 0;
  EFI_HANDLE  MmHandle;
  BOOLEAN     IsUserRange = FALSE;
  EFI_STATUS  Status = EFI_SUCCESS;

  while (!AcquireSpinLockOrFail (mCpuToken)) {
    CpuPause ();
  }

  DEBUG ((DEBUG_VERBOSE, "%a Enter... CallIndex: %lx, Arg1: %lx, Arg2: %lx, Arg3: %lx, CallerAddr: %p, Ring3Stack %p\n",
    __FUNCTION__,
    CallIndex,
    Arg1,
    Arg2,
    Arg3,
    CallerAddr,
    Ring3StackPointer
  ));

  ReleaseSpinLock (mCpuToken);

  // The real policy come from DRTM event is copied over to FirmwarePolicy
  switch (CallIndex) {
  case DXE_SC_RDMSR:
    Status = IsMsrReadWriteAllowed (
               FirmwarePolicy,
               (UINT32)Arg1,
               SECURE_POLICY_RESOURCE_ATTR_READ_DIS
               );
    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_ERROR, "%a Read MSR 0x%p blocked by policy - %r\n", __FUNCTION__, Arg1, Status));
      goto Exit;
    }
    Ret = AsmReadMsr64 ((UINT32)Arg1);
    DEBUG ((DEBUG_VERBOSE, "%a Read MSR %x got %x\n", __FUNCTION__, Arg1, Ret));
    break;
  case DXE_SC_WRMSR:
    Status = IsMsrReadWriteAllowed (
               FirmwarePolicy,
               (UINT32)Arg1,
               SECURE_POLICY_RESOURCE_ATTR_WRITE_DIS
               );
    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_ERROR, "%a Write MSR 0x%p blocked by policy - %r\n", __FUNCTION__, Arg1, Status));
      goto Exit;
    }
    AsmWriteMsr64 ((UINT32)Arg1, (UINT64)Arg2);
    DEBUG ((DEBUG_VERBOSE, "%a Write MSR %x with %x\n", __FUNCTION__, Arg1, Arg2));
    break;
  case DXE_SC_CLI:
    Status = IsInstructionExecutionAllowed (FirmwarePolicy,
                                            SECURE_POLICY_INSTRUCTION_CLI);
    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_ERROR, "%a Instruction execution CLI blocked by policy - %r\n", __FUNCTION__, Status));
      goto Exit;
    }
    DisableInterrupts ();
    DEBUG ((DEBUG_VERBOSE, "%a Disable interrupts\n", __FUNCTION__));
    break;
  case DXE_SC_IO_READ:
    DEBUG ((DEBUG_VERBOSE, "%a Read IO type %d at %x got ", __FUNCTION__, Arg2, Arg1));
    if (Arg2 != MM_IO_UINT8 && Arg2 != MM_IO_UINT16 && Arg2 != MM_IO_UINT32) {
      DEBUG ((DEBUG_ERROR, "%a Read IO incompatible size - %d\n", __FUNCTION__, Arg2));
      Status = EFI_INVALID_PARAMETER;
      goto Exit;
    }
    Status = IsIoReadWriteAllowed(FirmwarePolicy,
                                  (UINT32) Arg1,
                                  (EFI_MM_IO_WIDTH) Arg2,
                                  SECURE_POLICY_RESOURCE_ATTR_READ_DIS);
    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_ERROR, "%a Read IO port 0x%x with width type %d blocked by policy - %r\n", __FUNCTION__, Arg1, Arg2, Status));
      goto Exit;
    }
    if (Arg2 == MM_IO_UINT8) {
      Ret = (UINT64) IoRead8 ((UINTN)Arg1);
    } else if (Arg2 == MM_IO_UINT16) {
      Ret = (UINT64) IoRead16 ((UINTN)Arg1);
    } else if (Arg2 == MM_IO_UINT32) {
      Ret = (UINT64) IoRead32 ((UINTN)Arg1);
    } else {
      // Should not happen
      Status = EFI_INVALID_PARAMETER;
      goto Exit;
    }
    DEBUG ((DEBUG_VERBOSE, "%x\n", Ret));
    break;
  case DXE_SC_IO_WRITE:
    if (Arg2 != MM_IO_UINT8 && Arg2 != MM_IO_UINT16 && Arg2 != MM_IO_UINT32) {
      DEBUG ((DEBUG_ERROR, "%a Read IO incompatible size - %d\n", __FUNCTION__, Arg2));
      Status = EFI_INVALID_PARAMETER;
      goto Exit;
    }
    Status = IsIoReadWriteAllowed (
              FirmwarePolicy,
              (UINT32) Arg1,
              (EFI_MM_IO_WIDTH) Arg2,
              SECURE_POLICY_RESOURCE_ATTR_WRITE_DIS
              );
    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_ERROR, "%a Write IO port 0x%x with width type %d blocked by policy - %r\n", __FUNCTION__, Arg1, Arg2, Status));
      goto Exit;
    }
    if (Arg2 == MM_IO_UINT8) {
      IoWrite8 ((UINTN)Arg1, (UINT8)Arg3);
    } else if (Arg2 == MM_IO_UINT16) {
      IoWrite16 ((UINTN)Arg1, (UINT16)Arg3);
    } else if (Arg2 == MM_IO_UINT32) {
      IoWrite32 ((UINTN)Arg1, (UINT32)Arg3);
    } else {
      // Should not happen
      Status = EFI_INVALID_PARAMETER;
      goto Exit;
    }
    DEBUG ((DEBUG_VERBOSE, "%a Write IO type %d at %x with %x\n", __FUNCTION__, Arg2, Arg1, Arg3));
    break;
  case DXE_SC_WBINVD:
    Status = IsInstructionExecutionAllowed (FirmwarePolicy,
                                            SECURE_POLICY_INSTRUCTION_WBINVD);
    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_ERROR, "%a Instruction execution WBINVD blocked by policy - %r\n", __FUNCTION__, Status));
      goto Exit;
    }
    DEBUG ((DEBUG_VERBOSE, "%a Write back and invalidate cache\n", __FUNCTION__));
    AsmWbinvd ();
    break;
  case DXE_SC_HLT:
    Status = IsInstructionExecutionAllowed (FirmwarePolicy,
                                            SECURE_POLICY_INSTRUCTION_HLT);
    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_ERROR, "%a Instruction execution HLT blocked by policy - %r\n", __FUNCTION__, Status));
      goto Exit;
    }
    DEBUG ((DEBUG_VERBOSE, "%a Cpu Halt\n", __FUNCTION__));
    CpuSleep ();
    break;
  case DXE_REG_HDL_JMP:
    if ((RegisteredRing3JumpPointer != 0) ||
        (RegApRing3JumpPointer != 0)) {
      Status = EFI_ALREADY_STARTED;
    }
    else if ((EFI_ERROR (InspectTargetRangeOwnership (Arg1, sizeof (Arg1), &IsUserRange)) || !IsUserRange) ||
             (EFI_ERROR (InspectTargetRangeOwnership (Arg2, sizeof (Arg2), &IsUserRange)) || !IsUserRange)) {
      Status = EFI_SECURITY_VIOLATION;
    }
    else {
      RegisteredRing3JumpPointer = Arg1;
      RegApRing3JumpPointer = Arg2;
    }
    break;
  case DXE_ALOC_PAGE:
    if (Arg2 == EfiLoaderCode ||
        Arg2 == EfiBootServicesCode ||
        Arg2 == EfiRuntimeServicesCode ||
        Arg2 == EfiPalCode) {
      Status = EFI_UNSUPPORTED;
    } else {
      Status = CoreAllocatePages ((EFI_ALLOCATE_TYPE) Arg1,
                                  (EFI_MEMORY_TYPE) Arg2,
                                  (UINTN) Arg3,
                                  (EFI_PHYSICAL_ADDRESS*) &Ret);
    }
    break;
  case DXE_FREE_PAGE:
    if (!EFI_ERROR (InspectTargetRangeOwnership (Arg1, EFI_PAGES_TO_SIZE (Arg2), &IsUserRange)) && IsUserRange) {
      Status = CoreFreePages ((EFI_PHYSICAL_ADDRESS) Arg1, Arg2);
    }
    else {
      Status = EFI_SECURITY_VIOLATION;
    }
    break;
  case DXE_SET_CPL3_TBL:
    if (EFI_ERROR (InspectTargetRangeOwnership (Arg1, sizeof (EFI_BOOT_SERVICES), &IsUserRange)) || !IsUserRange) {
      Status = EFI_SECURITY_VIOLATION;
    }
    else if (gUserBS != NULL) {
      Status = EFI_ALREADY_STARTED;
    }
    else {
      gUserBS = (EFI_BOOT_SERVICES*) Arg1;
      // SyncEntryContextToCpl3 ();
    }
    break;
  case DXE_INST_PROT:
    if (EFI_ERROR (InspectTargetRangeOwnership (Arg1, sizeof (EFI_GUID), &IsUserRange)) || !IsUserRange) {
      Status = EFI_SECURITY_VIOLATION;
    }
    else if (Arg1 == 0) {
      Status = EFI_INVALID_PARAMETER;
    }
    else {
      MmHandle = NULL;
      Status = CoreInstallProtocolInterface (
                &MmHandle,
                (EFI_GUID*) Arg1,
                EFI_NATIVE_INTERFACE,
                NULL);
    }
    break;
  case DXE_QRY_HOB:
    // Ret = (UINT64) QueryHobStartFromConfTable ();
    break;
  case DXE_ERR_RPT_JMP:
    if (EFI_ERROR (InspectTargetRangeOwnership (Arg1, sizeof (Arg1), &IsUserRange)) || !IsUserRange) {
      Status = EFI_SECURITY_VIOLATION;
    }
    else if (RegErrorReportJumpPointer != 0) {
      Status = EFI_ALREADY_STARTED;
    }
    else {
      RegErrorReportJumpPointer = Arg1;
    }
    break;
  default:
    Status = EFI_INVALID_PARAMETER;
    break;
  }

Exit:
  if (EFI_ERROR (Status)) {
    // Prepare the content and try to engage exception handler here
    // TODO: Do buffer preparation
    ASSERT_EFI_ERROR (Status);
    CpuDeadLoop ();
  }

  DEBUG ((DEBUG_VERBOSE, "%a Exit...\n", __FUNCTION__));
  return Ret;
}
