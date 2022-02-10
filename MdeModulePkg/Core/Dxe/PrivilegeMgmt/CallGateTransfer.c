/** @file
  PI SMM MemoryAttributes support

Copyright (c) 2008 - 2018, Intel Corporation. All rights reserved.<BR>
Copyright (c) 2020, AMD Incorporated. All rights reserved.<BR>
Copyright (c) Microsoft Corporation.

SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiDxe.h>
#include <Library/BaseLib.h>
#include <Library/MmServicesTableLib.h>
#include <Library/DebugLib.h>
#include <Library/PcdLib.h>
#include <Library/ResetSystemLib.h>
#include <Library/LocalApicLib.h>

#include "DxeMain.h"
#include "PrivilegeMgmt.h"

//
// Global Descriptor Table (GDT)
//
IA32_SEGMENT_DESCRIPTOR gGdtEntries[] = {
/* selector { Global Segment Descriptor                              } */
/* 0x00 */  {{0,      0,    0,  0,    0,  0,  0,  0,    0,  0, 0,  0,  0}}, //null descriptor
/* 0x08 */  {{0xffff, 0,    0,  0x2,  1,  0,  1,  0xf,  0,  0, 1,  1,  0}}, //linear data segment descriptor
/* 0x10 */  {{0xffff, 0,    0,  0xf,  1,  0,  1,  0xf,  0,  0, 1,  1,  0}}, //linear code segment descriptor
/* 0x18 */  {{0xffff, 0,    0,  0x3,  1,  0,  1,  0xf,  0,  0, 1,  1,  0}}, //system data segment descriptor
/* 0x20 */  {{0xffff, 0,    0,  0xa,  1,  0,  1,  0xf,  0,  0, 1,  1,  0}}, //system code segment descriptor
/* 0x28 */  {{0,      0,    0,  0,    0,  0,  0,  0,    0,  0, 0,  0,  0}}, //spare segment descriptor
/* 0x30 */  {{0xffff, 0,    0,  0x2,  1,  0,  1,  0xf,  0,  0, 1,  1,  0}}, //system data segment descriptor
/* 0x38 */  {{0xffff, 0,    0,  0xa,  1,  0,  1,  0xf,  0,  1, 0,  1,  0}}, //system code segment descriptor
/* 0x40 */  {{0xffff, 0,    0,  0x2,  1,  0,  1,  0xf,  0,  0, 1,  1,  0}}, //copy of system data segment descriptor, used in syscall environment
/* 0x48 */  {{0xffff, 0,    0,  0x3,  1,  3,  1,  0xf,  0,  0, 1,  1,  0}}, //ring 3 system data segment descriptor
/* 0x50 */  {{0xffff, 0,    0,  0xb,  1,  3,  1,  0xf,  0,  1, 0,  1,  0}}, //ring 3 system code segment descriptor
/* 0x58 */  {{0,      0x38, 0,  0xc,  0,  3,  1,  0,    0,  0, 0,  0,  0}}, //call gate segment descriptor
/* 0x60 */  {{0,      0,    0,  0,    0,  0,  0,  0,    0,  0, 0,  0,  0}}, //call gate segment descriptor - 2
/* 0x68 */
{{
  .LimitLow = sizeof (IA32_TASK_STATE_SEGMENT),
  .BaseLow = 0,
  .BaseMid = 0,
  .Type = 0x9,
  .S = 0,
  .DPL = 0,
  .P = 1,
  .LimitHigh = 0,
  .AVL = 0,
  .L = 0,
  .DB = 0,
  .G = 1,
  .BaseHigh = 0
}}, //tss segment descriptor
/* 0x70 */  {{0,      0,    0,  0,    0,  0,  0,  0,    0,  0, 0,  0,  0}}, //tss segment descriptor - 2
};

//
// IA32 Gdt register
//
IA32_DESCRIPTOR gGdt;

// Function pointer to jump to for handler demotion
UINTN RegisteredRing3JumpPointer = 0;
UINTN RegApRing3JumpPointer = 0;
UINTN RegErrorReportJumpPointer = 0;

// Helper function to patch the call gate
STATIC
EFI_STATUS
EFIAPI
PatchCallGatePtr (
  IN  IA32_IDT_GATE_DESCRIPTOR *CallGatePtr,
  IN  VOID                      *ReturnPointer
  )
{
  if (CallGatePtr == NULL) {
    ASSERT (FALSE);
    return EFI_INVALID_PARAMETER;
  }

  // Only touch the intended offset here
  if (CallGatePtr->Bits.OffsetLow != ((UINTN) ReturnPointer & MAX_UINT16)) {
    CallGatePtr->Bits.OffsetLow = (UINTN) ReturnPointer & MAX_UINT16;
  }
  if (CallGatePtr->Bits.OffsetHigh != (((UINTN) ReturnPointer >> 16) & MAX_UINT16)) {
    CallGatePtr->Bits.OffsetHigh = ((UINTN) ReturnPointer >> 16) & MAX_UINT16;
  }
  if (CallGatePtr->Bits.OffsetUpper != (((UINTN) ReturnPointer >> 32) & MAX_UINT32)) {
    CallGatePtr->Bits.OffsetUpper = ((UINTN) ReturnPointer >> 32) & MAX_UINT32;
  }

  return EFI_SUCCESS;
}

// Helper function to patch the Tss descriptor
STATIC
EFI_STATUS
EFIAPI
PatchTssDescriptor (
  IN  IA32_TSS_DESCRIPTOR     *TssDescPtr,
  IN  IA32_TASK_STATE_SEGMENT *TaskSegmentPtr,
  IN  VOID                    *Cpl0StackPtr
  )
{
  if ((TssDescPtr == NULL) || (TaskSegmentPtr == NULL)) {
    ASSERT (FALSE);
    return EFI_INVALID_PARAMETER;
  }

  // Update task segment descriptor
  if (TssDescPtr->Bits.BaseLow != ((UINTN) TaskSegmentPtr & MAX_UINT16)) {
    TssDescPtr->Bits.BaseLow = (UINTN) TaskSegmentPtr & MAX_UINT16;
  }
  if (TssDescPtr->Bits.BaseMidl != (((UINTN) TaskSegmentPtr >> 16) & MAX_UINT8)) {
    TssDescPtr->Bits.BaseMidl = ((UINTN) TaskSegmentPtr >> 16) & MAX_UINT8;
  }
  if (TssDescPtr->Bits.BaseMidh != (((UINTN) TaskSegmentPtr >> 24) & MAX_UINT8)) {
    TssDescPtr->Bits.BaseMidh = ((UINTN) TaskSegmentPtr >> 24) & MAX_UINT8;
  }
  if (TssDescPtr->Bits.BaseHigh != (((UINTN) TaskSegmentPtr >> 32) & MAX_UINT32)) {
    TssDescPtr->Bits.BaseHigh = ((UINTN) TaskSegmentPtr >> 32) & MAX_UINT32;
  }

  // Update stack pointer for ring 3 usage in TSS
  if (TaskSegmentPtr->RSP0 != ((UINT64) Cpl0StackPtr)) {
    TaskSegmentPtr->RSP0 = (UINT64) Cpl0StackPtr;
  }

  return EFI_SUCCESS;
}

// Function to set up call gate for just one thread/core
VOID
EFIAPI
SetupCallGate (
  IN  VOID        *ReturnPointer,
  IN  BOOLEAN     ForcedUpdate
  )
{
  IA32_DESCRIPTOR Gdtr;

  // We should be all set after ready to lock:
  // Return point is fixed for ring 3 handlers/AP routines in assembly code
  if (!ForcedUpdate) {
    return;
  }

  AsmReadGdtr (&Gdtr);

  // MU_CHANGE: DXE_SUPV: Add GDT page protection, if any, here
  // SmmClearGdtReadOnlyForThisProcessor ();

  PatchCallGatePtr (
    (IA32_IDT_GATE_DESCRIPTOR *) (UINTN) (Gdtr.Base + CALL_GATE_OFFSET),
    ReturnPointer);

  // SmmSetGdtReadOnlyForThisProcessor ();

  AsmWriteGdtr (&Gdtr);
  // Note: a same level far return to apply new GDT
}

// Function to set up TSS
VOID
EFIAPI
SetupTssDescriptor (
  IN  VOID        *Cpl0StackPtr,
  IN  BOOLEAN     ForcedUpdate
  )
{
  IA32_DESCRIPTOR Gdtr;
  UINTN           CpuIndex;
  EFI_STATUS      Status;

  // We should be all set after ready to lock:
  // Ring 3 stack is populated in TSS for each core
  if (!ForcedUpdate) {
    return;
  }

  CpuIndex = GetApicId ();

  AsmReadGdtr (&Gdtr);

  // MU_CHANGE: DXE_SUPV: Add GDT page protection, if any, here
  // SmmClearGdtReadOnlyForThisProcessor ();

  PatchTssDescriptor (
    (IA32_TSS_DESCRIPTOR *) (UINTN) (Gdtr.Base + TSS_SEL_OFFSET),
    (IA32_TASK_STATE_SEGMENT *) (UINTN) (Gdtr.Base + TSS_DESC_OFFSET),
    Cpl0StackPtr);

  // Store CPL0 stack pointer into supv data structure, this will be used upon syscall entry
  Status = UpdateCpl0StackPtrForGs (CpuIndex, (EFI_PHYSICAL_ADDRESS)Cpl0StackPtr);
  if (EFI_ERROR (Status)) {
    goto Exit;
  }

  // SmmSetGdtReadOnlyForThisProcessor ();

  AsmWriteGdtr (&Gdtr);

  // Note: a same level far return to apply new GDT
  Status = EFI_SUCCESS;
Exit:
  if (EFI_ERROR (Status)) {
    ASSERT_EFI_ERROR (Status);
    // MU_CHANGE: DXE_SUPV: Need to check pcd to determine error behavior
    CpuDeadLoop ();
  }
}

// Setup ring transition for AP procedure
VOID
EFIAPI
CallgateInit (
  IN UINTN        NumberOfCpus
  )
{
  // UINTN                 CpuIndex;
  // EFI_PHYSICAL_ADDRESS  GdtrBaseAddr;

  PrivilegeMgmtFixupAddress ();

  gGdt.Base = (UINTN)AllocatePages (EFI_SIZE_TO_PAGES (sizeof (gGdtEntries) + sizeof (IA32_TASK_STATE_SEGMENT)));
  if ((VOID*)gGdt.Base == NULL) {
    DEBUG ((DEBUG_INFO, "%a: No memory for GDT... Can't continue\n", __FUNCTION__));
    ASSERT (FALSE);
    return;
  }

  ZeroMem ((VOID*)gGdt.Base, EFI_SIZE_TO_PAGES (sizeof (gGdtEntries) + sizeof (IA32_TASK_STATE_SEGMENT)));
  CopyMem ((VOID*)(UINTN)(gGdt.Base), gGdtEntries, sizeof (gGdtEntries));
  gGdt.Limit = sizeof (gGdtEntries) - 1;
  AsmWriteGdtr (&gGdt);

  AsmWriteTr (TSS_SEL_OFFSET);

  // for (CpuIndex = 0; CpuIndex < NumberOfCpus; CpuIndex ++) {
  //   // MU_CHANGE: DXE_SUPV: This should be used as real Cpu index
  //   if (CpuIndex == GetApicId ()) {
  //     // BSP call gate will change, patch at runtime
  //     continue;
  //   }

  //   // Patch AP handlers call gate and stack here as they are static after init
  //   GdtrBaseAddr = mGdtBuffer + mGdtStepSize * CpuIndex;
  //   PatchCallGatePtr ((IA32_IDT_GATE_DESCRIPTOR *) (UINTN) (GdtrBaseAddr + CALL_GATE_OFFSET), (VOID *) ApHandlerReturnPointer);
  //   PatchTssDescriptor (
  //     (IA32_TSS_DESCRIPTOR *) (UINTN) (GdtrBaseAddr + TSS_SEL_OFFSET),
  //     (IA32_TASK_STATE_SEGMENT *) (UINTN) (GdtrBaseAddr + TSS_DESC_OFFSET),
  //     (VOID*) GetThisCpl3Stack (CpuIndex));
  // }
}
