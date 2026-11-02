// Copyright 2026 Blink Labs Software
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "textflag.h"

// func habCall(fn, r0, r1, r2, r3 uint32) uint32
//
// The frame is non-zero so the assembler saves LR, which the BLX overwrites.
// R4-R7 are callee-saved under the AAPCS, so they survive the call.
TEXT ·habCall(SB),NOSPLIT,$8-24
	MOVW	fn+0(FP), R4
	MOVW	r0+4(FP), R0
	MOVW	r1+8(FP), R1
	MOVW	r2+12(FP), R2
	MOVW	r3+16(FP), R3

	// keep the stack 8-byte aligned at the call
	MOVW	R13, R5
	BIC	$7, R13

	WORD	$0xe10f6000 // mrs r6, CPSR
	WORD	$0xe38670c0 // orr r7, r6, #0xc0 (mask IRQ, FIQ)
	WORD	$0xe121f007 // msr CPSR_c, r7

	// complete the translation table change before the first ROM fetch
	WORD	$0xf57ff04f // dsb sy
	WORD	$0xf57ff06f // isb sy

	WORD	$0xe12fff34 // blx r4 (ARM or Thumb by bit 0)

	WORD	$0xe121f006 // msr CPSR_c, r6

	MOVW	R5, R13
	MOVW	R0, ret+20(FP)

	RET

// func habRead32(addr uint32) uint32
TEXT ·habRead32(SB),NOSPLIT,$0-8
	MOVW	addr+0(FP), R0
	MOVW	(R0), R0
	MOVW	R0, ret+4(FP)

	RET

// func habWrite32(addr, val uint32)
TEXT ·habWrite32(SB),NOSPLIT,$0-8
	MOVW	addr+0(FP), R0
	MOVW	val+4(FP), R1
	MOVW	R1, (R0)

	RET

// func habTTBR0() uint32
TEXT ·habTTBR0(SB),NOSPLIT,$0-4
	MRC	15, 0, R0, C2, C0, 0
	MOVW	R0, ret+0(FP)

	RET
