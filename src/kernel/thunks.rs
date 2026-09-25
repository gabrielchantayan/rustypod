//! Registry of the osos -> S5L8702 mask ROM thunk table.
//!
//! Original: 158 entries @ 0x08037db0..0x080382a0 in osos (each 8 bytes:
//! `ldr pc, [pc, #-4]` / word 0xe51ff004, followed by the absolute ROM
//! target word). Every stub loads the program counter with a hard-coded
//! address in the S5L8702 mask ROM (0x22000000 range), which holds the
//! RTXC Quadros kernel and a copy of the ARM ADS 1.0.1 runtime. This is
//! the ADS "literal veneer" idiom: callers `bl` the stub, the stub jumps
//! into the ROM. osos.dec was verified to contain exactly these 158
//! entries — every instruction word is 0xe51ff004, every target lies in
//! 0x22000020..=0x2200881c, and the bytes after 0x080382a0 are zero
//! padding (the table is sometimes cited as ending at 0x0803829c, the
//! last target *word*).
//!
//! The ROM is not part of osos.dec, so targets cannot be disassembled
//! directly. Identification rests on two binary-verifiable facts:
//!
//! - **Runtime block aliases.** The low block of osos (0x08000000 up
//!   through the RTXC glue) is a byte-for-byte link-order mirror of the
//!   ROM image at 0x22000000: same ADS runtime objects first, same
//!   relative `bl` displacements, and absolute literals pointing at ROM
//!   data (e.g. the literal 0x2200acf4 in the osos copy @ 0x08003ec0).
//!   So ROM 0x22000XXX mirrors osos 0x08000XXX, and the ADS runtime
//!   names recovered from osos (names.yaml) carry over: 0x22000020
//!   __rt_memcpy, 0x220000d4 memmove, 0x22000188 memcpy, 0x220001f4 the
//!   shared memmove backward-copy body (overlap check + reverse word
//!   loop; `bls` to memcpy when the ranges don't overlap), 0x2200027c
//!   memzero_aligned, 0x220002d4 memzero, 0x220002d8 the shared fill
//!   body one instruction into memzero (entry with fill byte in r2,
//!   length in r1 — i.e. the memset-style entry).
//! - **Call-site evidence.** The documented osos RAM wrappers tail-
//!   branch to specific thunks: the semaphore-wait wrapper @ 0x08056510
//!   falls through to thunk 0x08037e08 (-> 0x22003fd0) once the sem
//!   pointer is non-NULL, so 0x22003fd0 is the sem-wait ROM op. Its osos
//!   mirror @ 0x08003fd0 shows the expected count-check/waiter-increment
//!   logic. 0x22003dc8 ("kernel op dispatch") is called with an op code
//!   in r0 and an on-stack argument frame in r1 from 9 sites, most in
//!   the semaphore wrapper cluster. The 0x22003ea0/0x2200408c pair is
//!   invoked back-to-back at 0x080564c0/0x080564c8, 0x080564f4/0x080564fc
//!   and 0x0809c7b4/0x0809c7c8 around critical sections — the task
//!   lock/unlock pair (see caveats below).
//! - **Relocator mirror.** The boot relocator at 0x080046e0 copies
//!   0xaed8 bytes from 0x08000000 to 0x22000000 (literals verified in
//!   osos.dec), so every target below 0x2200aed8 has a byte-identical
//!   osos body that CAN be disassembled: 0x22005018 == FUN_08005018,
//!   which identifies thunk 0x08037f88 as ui_manager_acquire, and
//!   0x2200427c == FUN_0800427c, which identifies thunk 0x08037f80 as
//!   task_delete_gateway_veneer (RTXC gateway service 0x18, task delete;
//!   the 28-byte mirror body is ported in heap/task_delete_gateway.rs).
//!   0x220060e0 == FUN_080060e0, which identifies thunk 0x08037f58 as
//!   lazy_singleton_106dc_acquire. 0x2200200c == FUN_0800200c, which
//!   identifies thunk 0x08037f60 as clock_config_dispatch_veneer: the
//!   988-byte mirror body is a 17-way selector switch (0x00-0x10) that
//!   read-modify-writes clock-bit fields of six registers in the
//!   0x3C500000 MMIO block (mode 1..3 field encodings, (divisor>>1)-1
//!   divisor nibbles), records per-selector mode/value bytes at
//!   0x089CA524, and returns 0. 0x220041cc == osos 0x080041cc names
//!   thunk 0x08037e78 signal_object: the mirror posts the gateway
//!   request {2, status, object} and returns the status word (ported in
//!   kernel/gateway_signal.rs). Selector 2 and the record shape are
//!   binary facts; the "signal" reading rests on the call sites —
//!   csem_post @ 0x080567a8 reaches it exactly when one sleeper is
//!   parked, and kobj::waiter_wake @ 0x080567f8 is a bare alias.
//!
//! Caveats / deviations:
//!
//! - `current_task_id` (0x22003eb0) is mirrored at 0x08003eb0: it loads the
//!   current task record through 0x2200acf4, then returns the aligned u32 at
//!   record +0x20. The seven unconditional callers use that value as a task
//!   category/key; the target has no argument or NULL guard.
//! - The task lock pair naming is project convention: the osos mirror of
//!   0x22003ea0 is a table-indexed handle->pointer load (table @
//!   0x08a24108) and 0x2200408c dispatches kernel op 3; 0x2200408c also
//!   has 7 call sites without an adjacent 0x22003ea0 call. The pairing
//!   at the semaphore wrappers is what the names record.
//! - Two ROM targets are aliased by two thunks each: 0x22000020
//!   (__rt_memcpy: thunks 0x08037db0 / 0x08037dd0) and 0x220000d4
//!   (memmove: thunks 0x08037dd8 / 0x08037e00). Thunk addresses
//!   themselves are unique and sorted.
//!
//! This module is primarily pure data. It also carries the one early-boot
//! literal tail-dispatch veneer at 0x08003818; its target is outside the
//! mask-ROM thunk table, so it is modeled as verbatim ARM below.

/// Instruction word every thunk stub is built from: `ldr pc, [pc, #-4]`
/// (loads PC with the target word stored immediately after the stub).
pub const THUNK_INSN: u32 = 0xe51ff004;

/// Load address of the first thunk stub in osos.
pub const THUNK_TABLE_BASE: u32 = 0x08037db0;

/// First address past the last thunk's target word (0x0803829c + 4).
pub const THUNK_TABLE_END: u32 = 0x080382a0;

/// Byte size of one thunk: 4-byte stub + 4-byte target word.
pub const THUNK_STRIDE: u32 = 8;

/// Base of the S5L8702 mask ROM the thunks jump into (RTXC Quadros
/// kernel + ARM ADS runtime copy).
pub const ROM_BASE: u32 = 0x2200_0000;

/// ARM instruction word and literal used by `kernel_indirect_dispatch`.
///
/// The raw 8-byte body at 0x08003818 is `ldr pc, [pc, #-4]` followed by
/// this literal. Loading PC makes it a tail dispatch, not the indirect call
/// and return inferred by Ghidra.
pub const KERNEL_INDIRECT_DISPATCH_INSN: u32 = 0xe51f_f004;
pub const KERNEL_INDIRECT_DISPATCH_TARGET: u32 = 0x0815_ca7c;

// The literal target is a stack-sensitive continuation, not a normal C
// callee: it immediately executes `pop {r4, lr}; b 0x0812b9a4`. Keep the
// veneer verbatim so it forwards every register and the caller's frame
// unchanged. `global_asm!` avoids the unstable naked-functions feature.
#[cfg(target_arch = "arm")]
extern "C" {
    /// kernel_indirect_dispatch — original: `FUN_08003818` @ 0x08003818
    /// (8 bytes).
    ///
    /// Loads the literal target 0x0815ca7c directly into PC. The only
    /// recovered caller passes its pointer argument in r0; the target
    /// unwinds that caller's `{r4, lr}` frame and tail-branches onward, so
    /// this veneer never returns to its immediate caller.
    ///
    /// Deviation: none on ARM; this is the original instruction and literal.
    pub fn kernel_indirect_dispatch(argument: *mut u8) -> !;
}

/// Host-only stand-in for the stack-sensitive ARM tail dispatch.
///
/// The retailOS target is unmapped on hosts and consumes its caller's saved
/// frame, so a normal host call cannot represent the transfer. It terminates
/// instead of returning, matching the veneer’s no-return-to-immediate-caller
/// contract.
#[cfg(not(target_arch = "arm"))]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn kernel_indirect_dispatch(argument: *mut u8) -> ! {
    let _ = argument;
    unreachable!("kernel_indirect_dispatch tail target unavailable on host")
}

#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .text
    .p2align 2
    .globl kernel_indirect_dispatch
    .type kernel_indirect_dispatch, %function
kernel_indirect_dispatch:
    ldr     pc, [pc, #-4]
    .word   0x0815ca7c
    .size kernel_indirect_dispatch, . - kernel_indirect_dispatch
"#
);

/// Load address and literal contents of the record-fields comparator tail
/// veneer `FUN_080038e8` @ `0x080038e8` (8 bytes: 4-byte instruction plus
/// its target word; Ghidra reports only the 4-byte instruction).
///
/// Raw `osos.dec` is `ldr pc, [pc, #-4]` / literal `0x0829fe4c`; the next
/// veneer starts at `0x080038f0`, so the true occupied range is 8 bytes.
/// Decoding every immediate ARM BL word in `osos.dec` finds exactly five
/// direct callers: four unconditional `bl` (`0x08006b0c`, `0x08006b24`,
/// `0x08008064`, `0x08008090`) and one predicated `blne` (`0x08007464`);
/// a binary scan finds no aligned data word holding `0x080038e8`, so the
/// veneer is not dispatched through a table.
///
/// The literal deliberately enters the trailing half of the 240-byte
/// record-equality comparator `FUN_0829fdac` at `0x0829fe4c`, not a normal
/// function entry. From there the comparator tail calls the 3-byte
/// `{u8, i8, i8}` field-equality helper `FUN_0829f8fc` on the +0x8c
/// subfields, the helper `FUN_0829f9f8` on the +0x91 subfields, then
/// chains predicated word compares of the +0xac/+0xb0 pairs and the +0xb1
/// byte pair, returning 1 when every trailing field matches and 0
/// otherwise (`0x0829fe94`/`0x0829fe98`). The tail reads the two records
/// from callee-saved r4/r5 and pops `{r4, r5, r6, pc}`, an ARM register
/// and stack ABI a Rust wrapper cannot reproduce; the only normal
/// register value common to all recovered callers is the first record
/// pointer in r0. The remaining ABI is intentionally not inferred.
pub const RECORD_FIELDS_COMPARE_TAIL_VENEER: u32 = 0x0800_38e8;
pub const RECORD_FIELDS_COMPARE_TAIL_VENEER_INSN: u32 = 0xe51f_f004;
pub const RECORD_FIELDS_COMPARE_TAIL_VENEER_TARGET: u32 = 0x0829_fe4c;

// The literal target reads callee-saved r4/r5 and consumes the immediate
// caller's saved frame. Keep the transfer verbatim so every register and
// the caller's frame forward unchanged. There is no deliberate ARM
// deviation.
#[cfg(target_arch = "arm")]
extern "C" {
    /// record_fields_compare_tail_veneer — original: `FUN_080038e8` @
    /// `0x080038e8` (8 bytes).
    ///
    /// Loads the literal target `0x0829fe4c` directly into PC, tail-
    /// dispatching into the record-equality comparator tail with the
    /// caller's r0 first-record pointer and unmodified remaining machine
    /// context.
    pub fn record_fields_compare_tail_veneer(record: *mut u8) -> !;
}

/// Host-only stand-in for the register- and frame-sensitive ARM tail
/// dispatch.
///
/// The retailOS comparator tail is unmapped on hosts and reads ARM
/// callee-saved registers plus its caller's saved frame, so a normal host
/// call cannot represent the transfer. It terminates instead of
/// returning, matching the veneer's no-normal-ABI contract.
#[cfg(not(target_arch = "arm"))]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn record_fields_compare_tail_veneer(record: *mut u8) -> ! {
    let _ = record;
    unreachable!("record_fields_compare_tail_veneer comparator tail unavailable on host")
}

#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .text
    .p2align 2
    .globl record_fields_compare_tail_veneer
    .type record_fields_compare_tail_veneer, %function
record_fields_compare_tail_veneer:
    ldr     pc, [pc, #-4]
    .word   0x0829fe4c
    .size record_fields_compare_tail_veneer, . - record_fields_compare_tail_veneer
"#
);
/// Load address and literal contents of the return-frame veneer
/// `thunk_FUN_0829fe9c` @ `0x08003638` (8 bytes: 4-byte instruction plus its
/// target word; Ghidra reports only the instruction).
///
/// Raw `osos.dec` is `ldr pc, [pc, #-4]` / literal `0x0829fe9c`; the next
/// literal veneer starts at `0x08003640`, so the true occupied range is 8
/// bytes. Decoding every immediate ARM BL word in `osos.dec` finds exactly
/// three direct callers, all unconditional plain `bl` (`0x08003a88`,
/// `0x08003abc`, and `0x0800730c`); there are no predicated forms.
///
/// The literal enters the final `ldmia sp!, {r4, r5, r6, pc}` instruction of
/// the preceding routine, which restores the immediate caller's frame and
/// leaves r0-r3 unchanged. It is consequently a non-local return, not
/// Ghidra's inferred indirect call. The ARM implementation is deliberately
/// verbatim; the host stand-in terminates because ordinary host calls cannot
/// consume their caller's frame.
pub const RETURN_FRAME_VENEER: u32 = 0x0800_3638;
pub const RETURN_FRAME_VENEER_INSN: u32 = 0xe51f_f004;
pub const RETURN_FRAME_VENEER_TARGET: u32 = 0x0829_fe9c;

#[cfg(target_arch = "arm")]
extern "C" {
    /// return_frame_veneer — original: `thunk_FUN_0829fe9c` @ `0x08003638`
    /// (8 bytes).
    ///
    /// Tail-dispatches to the frame-restoring instruction at `0x0829fe9c`,
    /// preserving r0-r3 and consuming the immediate caller's saved
    /// `{r4, r5, r6, pc}` frame.
    pub fn return_frame_veneer(value: u32) -> !;
}

#[cfg(not(target_arch = "arm"))]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn return_frame_veneer(value: u32) -> ! {
    let _ = value;
    unreachable!("return_frame_veneer frame-restoring transfer unavailable on host")
}

#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .text
    .p2align 2
    .globl return_frame_veneer
    .type return_frame_veneer, %function
return_frame_veneer:
    ldr     pc, [pc, #-4]
    .word   0x0829fe9c
    .size return_frame_veneer, . - return_frame_veneer
"#
);


/// Load address and literal contents of the opaque state-terminal continuation
/// veneer `thunk_FUN_082aad24` @ `0x08003728` (8 bytes: 4-byte instruction
/// plus its target word; Ghidra reports only the instruction).
///
/// Raw `osos.dec` is `ldr pc, [pc, #-4]` / literal `0x081cd998`. Every
/// immediate ARM B/BL decode finds exactly six direct callers, all
/// unconditional `bl` (0x08005194, 0x080051a8, 0x080051bc, 0x08005344,
/// 0x080059ac, and 0x080059c4); there are no aligned data-word references.
///
/// The literal deliberately enters an inner continuation rather than a normal
/// function entry. Its first word is `bl 0x082aad24`, then it consumes r4-r6
/// and the immediate caller's saved frame before tail-branching onward. The
/// only normal register value established by all recovered callers is the
/// state word in r0; its remaining ABI is intentionally not inferred.
pub const STATE_TERMINAL_CONTINUATION_VENEER: u32 = 0x0800_3728;
pub const STATE_TERMINAL_CONTINUATION_INSN: u32 = 0xe51f_f004;
pub const STATE_TERMINAL_CONTINUATION_TARGET: u32 = 0x081c_d998;

// The literal target consumes the immediate caller's full saved frame. Keep
// this transfer verbatim: a Rust wrapper cannot preserve its register/stack
// ABI. There is no deliberate ARM deviation.
#[cfg(target_arch = "arm")]
extern "C" {
    /// state_terminal_continuation_veneer — original:
    /// `thunk_FUN_082aad24` @ 0x08003728 (8 bytes).
    ///
    /// Tail-dispatches to the opaque continuation with the caller's r0 state
    /// word and unmodified remaining machine context; it does not return to
    /// its immediate caller.
    pub fn state_terminal_continuation_veneer(state: u32) -> !;
}

/// Host-only stand-in for the stack-sensitive state-terminal transfer.
///
/// The retail continuation is unmapped on hosts and consumes ARM callee-saved
/// registers plus its caller's frame. It therefore cannot be called through a
/// normal host ABI; terminating is the faithful non-return contract.
#[cfg(not(target_arch = "arm"))]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn state_terminal_continuation_veneer(state: u32) -> ! {
    let _ = state;
    unreachable!("state_terminal_continuation_veneer target unavailable on host")
}

#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .text
    .p2align 2
    .globl state_terminal_continuation_veneer
    .type state_terminal_continuation_veneer, %function
state_terminal_continuation_veneer:
    ldr     pc, [pc, #-4]
    .word   0x081cd998
    .size state_terminal_continuation_veneer, . - state_terminal_continuation_veneer
"#
);
/// Instruction word and literal in the fixed event-callback target veneer
/// at 0x08003708.
pub const EVENT_CALLBACK_DISPATCH_INSN: u32 = 0xe51f_f004;
pub const EVENT_CALLBACK_DISPATCH_TARGET: u32 = 0x0815_c8a0;

/// ABI of the virtual callback dispatch reached by
/// [`dispatch_event_callback`].  The callback context is the eight-byte
/// subobject at the supplied system-context base.
pub type EventCallbackDispatchFn = unsafe extern "C" fn(callback_context: *mut u8);

/// Host/target dispatch boundary for the unported virtual callback target.
#[derive(Clone, Copy)]
pub struct EventCallbackDispatchOps {
    pub dispatch: EventCallbackDispatchFn,
}


#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_event_callback_dispatch(_callback_context: *mut u8) {}

#[cfg(not(target_arch = "arm"))]
const DEFAULT_EVENT_CALLBACK_DISPATCH_OPS: EventCallbackDispatchOps = EventCallbackDispatchOps {
    dispatch: missing_event_callback_dispatch,
};

/// The host dispatch boundary for the unported virtual callback target.
#[cfg(not(target_arch = "arm"))]
pub static mut EVENT_CALLBACK_DISPATCH_OPS: EventCallbackDispatchOps =
    DEFAULT_EVENT_CALLBACK_DISPATCH_OPS;

#[cfg(not(target_arch = "arm"))]
#[inline(always)]
fn event_callback_dispatch() -> EventCallbackDispatchFn {
    unsafe {
        core::ptr::read_volatile(core::ptr::addr_of!(EVENT_CALLBACK_DISPATCH_OPS.dispatch))
    }
}

#[cfg(target_arch = "arm")]
extern "C" {
    /// dispatch_event_callback — original: `FUN_08005094` @ 0x08005094
    /// (12 bytes).
    ///
    /// Adds eight bytes to the system event context, selecting its callback
    /// subobject, then tail-dispatches it through the 0x08003708 literal
    /// veneer to 0x0815c8a0. That target invokes the subobject's virtual
    /// callback; r0 is the sole argument and the wrapper has no result. The
    /// ARM port is the original `add; b` sequence.
    ///
    /// # Safety
    ///
    /// `system_context` must point to the base of the retailOS context
    /// object; its callback subobject begins at offset eight, and the target
    /// owns that object's validity requirements.
    pub fn dispatch_event_callback(system_context: *mut u8);
}

/// Host implementation of the same callback-context selection, with the
/// unported tail target supplied by [`EVENT_CALLBACK_DISPATCH_OPS`].
#[cfg(not(target_arch = "arm"))]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn dispatch_event_callback(system_context: *mut u8) {
    event_callback_dispatch()(system_context.add(8));
}

// The retailOS wrapper and its literal veneer are kept as one assembly
// fragment: `add; b` preserves the original tail-dispatch ABI exactly.
#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .text
    .p2align 2
    .globl dispatch_event_callback
    .type dispatch_event_callback, %function
dispatch_event_callback:
    add     r0, r0, #8
    b       retail_event_callback_dispatch
    .size dispatch_event_callback, . - dispatch_event_callback

    .p2align 2
    .type retail_event_callback_dispatch, %function
retail_event_callback_dispatch:
    ldr     pc, [pc, #-4]
    .word   0x0815c8a0
    .size retail_event_callback_dispatch, . - retail_event_callback_dispatch
"#
);

/// Instruction word and literal in the no-argument callback veneer at
/// 0x08003790.
pub const NO_ARGUMENT_CALLBACK_DISPATCH_INSN: u32 = 0xe51f_f004;
pub const NO_ARGUMENT_CALLBACK_DISPATCH_TARGET: u32 = 0x081b_0d08;

/// ABI of the callback reached by [`dispatch_no_argument_callback`].
///
/// The literal is an internal tail entry following `FUN_081b0cf4`, and it
/// accepts no defined C arguments: it recovers its work from the surrounding
/// ARM continuation before returning to this veneer’s caller.
pub type NoArgumentCallbackDispatchFn = unsafe extern "C" fn();

/// Host/target dispatch boundary for the unported no-argument callback.
#[derive(Clone, Copy)]
pub struct NoArgumentCallbackDispatchOps {
    pub dispatch: NoArgumentCallbackDispatchFn,
}

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_no_argument_callback_dispatch() {}

#[cfg(not(target_arch = "arm"))]
const DEFAULT_NO_ARGUMENT_CALLBACK_DISPATCH_OPS: NoArgumentCallbackDispatchOps =
    NoArgumentCallbackDispatchOps {
        dispatch: missing_no_argument_callback_dispatch,
    };

/// The host dispatch boundary for the unported callback target.
#[cfg(not(target_arch = "arm"))]
pub static mut NO_ARGUMENT_CALLBACK_DISPATCH_OPS: NoArgumentCallbackDispatchOps =
    DEFAULT_NO_ARGUMENT_CALLBACK_DISPATCH_OPS;

#[cfg(not(target_arch = "arm"))]
#[inline(always)]
fn no_argument_callback_dispatch() -> NoArgumentCallbackDispatchFn {
    unsafe {
        core::ptr::read_volatile(
            core::ptr::addr_of!(NO_ARGUMENT_CALLBACK_DISPATCH_OPS.dispatch),
        )
    }
}

#[cfg(target_arch = "arm")]
extern "C" {
    /// dispatch_no_argument_callback — original: `FUN_08003790` @
    /// 0x08003790 (16 bytes: two adjacent literal veneers; this port owns
    /// the first 8-byte veneer).
    ///
    /// Loads PC from the literal at 0x08003794, tail-dispatching to
    /// 0x081b0d08. There are no defined input or output arguments: its one
    /// recovered `bl` caller at 0x08005524 treats the callback solely as a
    /// call-and-return notification.
    ///
    /// Deviation: none on ARM; this is the original instruction and literal.
    pub fn dispatch_no_argument_callback();
}

/// Host implementation of the no-argument callback dispatch.
#[cfg(not(target_arch = "arm"))]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn dispatch_no_argument_callback() {
    no_argument_callback_dispatch()();
}

// `ldr pc` preserves LR, so the literal target returns directly to this
// veneer’s caller. Keep the fixed target in assembly rather than materializing
// it as a Rust function pointer on target.
#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .text
    .p2align 2
    .globl dispatch_no_argument_callback
    .type dispatch_no_argument_callback, %function
dispatch_no_argument_callback:
    ldr     pc, [pc, #-4]
    .word   0x081b0d08
    .size dispatch_no_argument_callback, . - dispatch_no_argument_callback
"#
);
/// Load address and literal contents of the retail continuation veneer at
/// 0x080037a0.
pub const RETAIL_CONTINUATION_DISPATCH_VENEER: u32 = 0x0800_37a0;
pub const RETAIL_CONTINUATION_DISPATCH_INSN: u32 = 0xe51f_f004;
pub const RETAIL_CONTINUATION_DISPATCH_TARGET: u32 = 0x080e_a68c;

/// ABI of the opaque retail continuation reached by
/// [`retail_continuation_dispatch_veneer`].
pub type RetailContinuationDispatchFn = unsafe extern "C" fn();

/// Host/target dispatch boundary for the unported retail continuation.
#[derive(Clone, Copy)]
pub struct RetailContinuationDispatchOps {
    pub dispatch: RetailContinuationDispatchFn,
}

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_retail_continuation_dispatch() {}

#[cfg(not(target_arch = "arm"))]
const DEFAULT_RETAIL_CONTINUATION_DISPATCH_OPS: RetailContinuationDispatchOps =
    RetailContinuationDispatchOps {
        dispatch: missing_retail_continuation_dispatch,
    };

/// Host replacement for the retail continuation, which depends on its
/// predecessor's stack frame and register state.
#[cfg(not(target_arch = "arm"))]
pub static mut RETAIL_CONTINUATION_DISPATCH_OPS: RetailContinuationDispatchOps =
    DEFAULT_RETAIL_CONTINUATION_DISPATCH_OPS;

#[cfg(not(target_arch = "arm"))]
#[inline(always)]
fn retail_continuation_dispatch_target() -> RetailContinuationDispatchFn {
    unsafe {
        core::ptr::read_volatile(core::ptr::addr_of!(
            RETAIL_CONTINUATION_DISPATCH_OPS.dispatch
        ))
    }
}

#[cfg(target_arch = "arm")]
extern "C" {
    /// retail_continuation_dispatch_veneer — original: `FUN_080037a0` @
    /// 0x080037a0 (8 bytes; Ghidra reports only the four-byte instruction).
    ///
    /// Raw ARM is `ldr pc, [pc, #-4]` followed by literal 0x080ea68c, so this
    /// veneer tail-dispatches without changing any register or LR. Complete
    /// ARM B/BL decoding finds six direct call sites, all unconditional `bl`
    /// (0x080055b8, 0x08005694, 0x080056b4, 0x08005844, 0x0800584c, and
    /// 0x08005cd8); there are no predicated calls or direct `b` tail callers.
    ///
    /// The literal is not a function entry: it begins at `cmp r1, #2` inside
    /// an existing stack frame at 0x080ea68c. It has no recoverable standalone
    /// C ABI or callee identity.
    ///
    /// Deliberate deviation: none on ARM. Host builds use an injected
    /// no-argument seam because they cannot construct the retail continuation
    /// state; it preserves the observable call-and-return edge.
    pub fn retail_continuation_dispatch_veneer();
}

/// Host implementation of the opaque retail-continuation veneer.
#[cfg(not(target_arch = "arm"))]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn retail_continuation_dispatch_veneer() {
    retail_continuation_dispatch_target()();
}

// `ldr pc` preserves LR and every general-purpose register. The literal enters
// the middle of a retail routine, so it must remain a literal tail transfer.
#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .text
    .p2align 2
    .globl retail_continuation_dispatch_veneer
    .type retail_continuation_dispatch_veneer, %function
retail_continuation_dispatch_veneer:
    ldr     pc, [pc, #-4]
    .word   0x080ea68c
    .size retail_continuation_dispatch_veneer, . - retail_continuation_dispatch_veneer
"#
);


/// Instruction word and literal in the task-delete gateway thunk at
/// 0x08037f80.
///
/// Identified through the relocator mirror: the boot relocator at
/// 0x080046e0 copies 0xaed8 bytes from 0x08000000 to 0x22000000 (both
/// literals verified in osos.dec), so IRAM 0x2200427c is byte-identical
/// to osos `FUN_0800427c` — the RTXC task-delete gateway wrapper, already
/// ported as [`crate::heap::task_delete_gateway::task_delete_gateway`].
pub const TASK_DELETE_GATEWAY_VENEER: u32 = 0x0803_7f80;
pub const TASK_DELETE_GATEWAY_VENEER_INSN: u32 = 0xe51f_f004;
pub const TASK_DELETE_GATEWAY_VENEER_TARGET: u32 = 0x2200_427c;

/// ABI of the mirrored task-delete gateway body reached by
/// [`task_delete_gateway_veneer`]: task id in r0, raw r1/r3 inputs, and the
/// dispatcher's two-word result returned as an ARM EABI u64 (r0 low, r1
/// high). r2 is preserved by the target but is not a service input.
pub type TaskDeleteGatewayFn =
    unsafe extern "C" fn(task_id: u32, input_r1: u32, input_r2: u32, input_r3: u32) -> u64;

/// Host/target dispatch boundary for the IRAM task-delete gateway body.
#[derive(Clone, Copy)]
pub struct TaskDeleteGatewayVeneerOps {
    pub delete: TaskDeleteGatewayFn,
}

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_task_delete_gateway(
    _task_id: u32,
    _input_r1: u32,
    _input_r2: u32,
    _input_r3: u32,
) -> u64 {
    0
}

#[cfg(not(target_arch = "arm"))]
const DEFAULT_TASK_DELETE_GATEWAY_VENEER_OPS: TaskDeleteGatewayVeneerOps =
    TaskDeleteGatewayVeneerOps {
        delete: missing_task_delete_gateway,
    };

/// Replaceable host boundary for the mirrored task-delete gateway body.
#[cfg(not(target_arch = "arm"))]
pub static mut TASK_DELETE_GATEWAY_VENEER_OPS: TaskDeleteGatewayVeneerOps =
    DEFAULT_TASK_DELETE_GATEWAY_VENEER_OPS;

#[cfg(not(target_arch = "arm"))]
#[inline(always)]
fn task_delete_gateway_veneer_target() -> TaskDeleteGatewayFn {
    unsafe {
        core::ptr::read_volatile(core::ptr::addr_of!(TASK_DELETE_GATEWAY_VENEER_OPS.delete))
    }
}

#[cfg(target_arch = "arm")]
extern "C" {
    /// task_delete_gateway_veneer — original: `thunk_EXT_FUN_2200427c` @
    /// 0x08037f80 (8 bytes; Ghidra's 4-byte extent drops the trailing
    /// literal word, the next thunk stub starts at 0x08037f88).
    ///
    /// One stub of the osos -> IRAM thunk table (see [`ROM_THUNKS`]):
    /// `ldr pc, [pc, #-4]` loading the literal 0x2200427c. `ldr pc` is a
    /// tail dispatch preserving every register including LR, so the target
    /// returns directly to this stub's caller. Decoding every ARM B/BL
    /// word in osos.dec finds exactly five calls — unconditional `bl` at
    /// 0x080b4c5c (`task_destroy`), 0x080cdf10, and 0x08393504, plus
    /// predicated `bleq` @ 0x08392fdc and `blne` @ 0x08393eb0 — and two
    /// unconditional `b` tail branches at 0x08392fcc and 0x08393aa8; no
    /// aligned raw data-word references exist. `task_destroy` supplies the
    /// kernel task id in r0; the predicated sites sit in the RTXC
    /// semihosting debug cluster around `swi 0x123456`.
    ///
    /// Target behaviour (IRAM mirror of `FUN_0800427c` @ 0x0800427c,
    /// 28 bytes, ported as
    /// [`crate::heap::task_delete_gateway::task_delete_gateway`]): builds
    /// the four-word gateway request `{0x18, input_r1, task_id, input_r3}`
    /// (selector 0x18 = task delete; input_r2 is saved/restored but not
    /// submitted), delegates it to the foreign ROM dispatcher 0x08003660,
    /// and returns the first two post-dispatch words as an ARM EABI u64.
    ///
    /// Deviation: none on ARM; this is the original instruction and
    /// literal. Host builds expose the foreign IRAM boundary as a
    /// replaceable callback.
    pub fn task_delete_gateway_veneer(
        task_id: u32,
        input_r1: u32,
        input_r2: u32,
        input_r3: u32,
    ) -> u64;
}

/// Host implementation of the literal veneer. It preserves all four
/// argument registers and the mirrored body's two-word result exactly.
#[cfg(not(target_arch = "arm"))]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn task_delete_gateway_veneer(
    task_id: u32,
    input_r1: u32,
    input_r2: u32,
    input_r3: u32,
) -> u64 {
    unsafe { task_delete_gateway_veneer_target()(task_id, input_r1, input_r2, input_r3) }
}

// `ldr pc` preserves LR, so the IRAM target returns directly to this
// stub's caller. Keep the fixed target in assembly rather than
// materializing it as a Rust function pointer on target.
#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .text
    .p2align 2
    .globl task_delete_gateway_veneer
    .type task_delete_gateway_veneer, %function
task_delete_gateway_veneer:
    ldr     pc, [pc, #-4]
    .word   0x2200427c
    .size task_delete_gateway_veneer, . - task_delete_gateway_veneer
"#
);

/// Instruction word and literal in the shared-UI-manager accessor thunk
/// at 0x08037f88.
///
/// Identified through the relocator mirror: the boot relocator at
/// 0x080046e0 copies 0xaed8 bytes from 0x08000000 to 0x22000000 (both
/// literals verified in osos.dec), so IRAM 0x22005018 is byte-identical
/// to osos `FUN_08005018`.
pub const UI_MANAGER_ACQUIRE_INSN: u32 = 0xe51f_f004;
pub const UI_MANAGER_ACQUIRE_TARGET: u32 = 0x2200_5018;

/// ABI of the shared UI manager accessor reached by
/// [`ui_manager_acquire`]: no arguments, returns the manager pointer.
pub type UiManagerAcquireFn = unsafe extern "C" fn() -> *mut u8;

/// Host/target dispatch boundary for the unported IRAM accessor target.
#[derive(Clone, Copy)]
pub struct UiManagerAcquireOps {
    pub acquire: UiManagerAcquireFn,
}

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_ui_manager_acquire() -> *mut u8 {
    core::ptr::null_mut()
}

#[cfg(not(target_arch = "arm"))]
const DEFAULT_UI_MANAGER_ACQUIRE_OPS: UiManagerAcquireOps = UiManagerAcquireOps {
    acquire: missing_ui_manager_acquire,
};

/// The host dispatch boundary for the unported IRAM accessor target.
#[cfg(not(target_arch = "arm"))]
pub static mut UI_MANAGER_ACQUIRE_OPS: UiManagerAcquireOps =
    DEFAULT_UI_MANAGER_ACQUIRE_OPS;

#[cfg(not(target_arch = "arm"))]
#[inline(always)]
fn ui_manager_acquire_target() -> UiManagerAcquireFn {
    unsafe {
        core::ptr::read_volatile(core::ptr::addr_of!(UI_MANAGER_ACQUIRE_OPS.acquire))
    }
}

#[cfg(target_arch = "arm")]
extern "C" {
    /// ui_manager_acquire — original: `thunk_EXT_FUN_22005018` @ 0x08037f88
    /// (8 bytes; Ghidra's 4-byte extent drops the trailing literal word,
    /// the next thunk stub starts at 0x08037f90).
    ///
    /// One stub of the osos -> IRAM thunk table (see [`ROM_THUNKS`]):
    /// `ldr pc, [pc, #-4]` loading the literal 0x22005018. `ldr pc` is a
    /// tail dispatch preserving every register including LR, so the target
    /// returns directly to this stub's caller. All 44 call sites decoded
    /// from osos.dec are plain unconditional `bl` (no predicated forms);
    /// none NULL-checks the result.
    ///
    /// Target behaviour (IRAM mirror of `FUN_08005018` @ 0x08005018,
    /// 100 bytes + 16-byte literal pool): lazy accessor for the shared UI
    /// manager object at 0x220104e8. Under once-guard bit 0 of the word at
    /// state+8 (state block 0x22008c94) it runs construct-and-register:
    /// glue veneer 0x080036e0 -> 0x082a0444(state+8); on success
    /// 0x08005cb8(0x220104e8), glue veneer 0x080036e8 -> 0x082a02f0(result,
    /// 0x22005cf4, __dso_handle 0x089ca09c), glue veneer 0x080036f0 ->
    /// 0x082a0460(state+8). Under a second once-flag (byte at state+1) it
    /// runs FUN_08005448(0x220104e8), which zeroes the manager fields and
    /// constructs sub-objects at +0x10/+0x28, then stores 1 to the flag.
    /// Returns the manager pointer 0x220104e8 unchanged. Callers feed the
    /// result as the first argument of sibling manager-op thunks
    /// (0x22005114, 0x2200509c, 0x2200521c, 0x22004ee4, 0x2200530c).
    ///
    /// Deviation: none on ARM; this is the original instruction and literal.
    pub fn ui_manager_acquire() -> *mut u8;
}

/// Host implementation of the shared-UI-manager accessor, with the
/// unported IRAM target supplied by [`UI_MANAGER_ACQUIRE_OPS`].
#[cfg(not(target_arch = "arm"))]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ui_manager_acquire() -> *mut u8 {
    ui_manager_acquire_target()()
}

// `ldr pc` preserves LR, so the IRAM target returns directly to this
// stub's caller. Keep the fixed target in assembly rather than
// materializing it as a Rust function pointer on target.
#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .text
    .p2align 2
    .globl ui_manager_acquire
    .type ui_manager_acquire, %function
ui_manager_acquire:
    ldr     pc, [pc, #-4]
    .word   0x22005018
    .size ui_manager_acquire, . - ui_manager_acquire
"#
);
/// ui_manager_begin_pending_operation — original:
/// `thunk_EXT_FUN_22005114` @ `0x08038200` (Ghidra reports 4 bytes; raw
/// osos.dec proves the full **8** bytes are `ldr pc,[pc,#-4]` /
/// `0xe51ff004` and the target literal `0x22005114` at `0x08038204`; the
/// next veneer starts at `0x08038208`).
///
/// The relocator at `0x080046e0` copies `0xaed8` bytes from `0x08000000` to
/// `0x22000000`, so the literal reaches the IRAM mirror of
/// `FUN_08005114` @ `0x08005114`, not mask ROM. That 92-byte body marks a
/// pending manager operation when its second argument is nonzero, ensures
/// the manager's `+0x10` subobject is initialized, and, when both
/// `manager[0]` and its third argument are nonzero, tail-dispatches the
/// manager's `+0x28` operation path. The veneer itself preserves every
/// argument and LR, forwarding the target's result or tail control flow
/// unchanged.
///
/// Decoding every ARM B/BL word in osos.dec found exactly six direct,
/// unconditional `bl` callers at 0x08201c78, 0x08201fb8, 0x08202018,
/// 0x08235da4, 0x082360b0, and 0x08237270; there are no predicated calls,
/// direct tail branches, or aligned raw data-word references. Deviation:
/// target builds use the exact literal tail veneer; host builds expose its
/// otherwise foreign IRAM boundary as a replaceable callback.
pub const UI_MANAGER_BEGIN_PENDING_OPERATION_VENEER: u32 = 0x0803_8200;
pub const UI_MANAGER_BEGIN_PENDING_OPERATION_INSN: u32 = 0xe51f_f004;
pub const UI_MANAGER_BEGIN_PENDING_OPERATION_TARGET: u32 = 0x2200_5114;

/// ABI of the pending-operation start thunk's mirrored body.
pub type UiManagerBeginPendingOperationFn =
    unsafe extern "C" fn(manager: *mut u8, mark_pending: u32, dispatch_active: u32) -> u32;

/// Host/target dispatch boundary for the IRAM pending-operation start body.
#[derive(Clone, Copy)]
pub struct UiManagerBeginPendingOperationOps {
    pub begin: UiManagerBeginPendingOperationFn,
}

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_ui_manager_begin_pending_operation(
    _manager: *mut u8,
    _mark_pending: u32,
    _dispatch_active: u32,
) -> u32 {
    0
}

#[cfg(not(target_arch = "arm"))]
const DEFAULT_UI_MANAGER_BEGIN_PENDING_OPERATION_OPS: UiManagerBeginPendingOperationOps =
    UiManagerBeginPendingOperationOps {
        begin: missing_ui_manager_begin_pending_operation,
    };

/// Replaceable host boundary for the mirrored pending-operation start body.
#[cfg(not(target_arch = "arm"))]
pub static mut UI_MANAGER_BEGIN_PENDING_OPERATION_OPS: UiManagerBeginPendingOperationOps =
    DEFAULT_UI_MANAGER_BEGIN_PENDING_OPERATION_OPS;

#[cfg(not(target_arch = "arm"))]
#[inline(always)]
fn ui_manager_begin_pending_operation_target() -> UiManagerBeginPendingOperationFn {
    unsafe {
        core::ptr::read_volatile(core::ptr::addr_of!(
            UI_MANAGER_BEGIN_PENDING_OPERATION_OPS.begin
        ))
    }
}

#[cfg(target_arch = "arm")]
extern "C" {
    pub fn ui_manager_begin_pending_operation(
        manager: *mut u8,
        mark_pending: u32,
        dispatch_active: u32,
    ) -> u32;
}

/// Host implementation of the literal veneer. It preserves the three
/// arguments and target result exactly.
#[cfg(not(target_arch = "arm"))]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ui_manager_begin_pending_operation(
    manager: *mut u8,
    mark_pending: u32,
    dispatch_active: u32,
) -> u32 {
    unsafe { ui_manager_begin_pending_operation_target()(manager, mark_pending, dispatch_active) }
}

// `ldr pc` preserves LR and therefore forwards both ordinary returns and the
// mirrored body's active-operation tail dispatch to the original caller.
#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .text
    .p2align 2
    .globl ui_manager_begin_pending_operation
    .type ui_manager_begin_pending_operation, %function
ui_manager_begin_pending_operation:
    ldr     pc, [pc, #-4]
    .word   0x22005114
    .size ui_manager_begin_pending_operation, . - ui_manager_begin_pending_operation
"#
);
/// ui_manager_dispatch_callback_context — original:
/// `thunk_EXT_FUN_220076cc` @ `0x08038208` (Ghidra reports 4 bytes; raw
/// osos.dec proves the full **8** bytes are `ldr pc,[pc,#-4]` /
/// `0xe51ff004` and the target literal `0x220076cc` at `0x0803820c`; the
/// next veneer starts at `0x08038210`).
///
/// The relocator at `0x080046e0` mirrors the target as `FUN_080076cc` @
/// `0x080076cc`. Its two instructions load `manager + 0x20` into r0 then
/// tail-branch to the unresolved external veneer at `0x08003930`
/// (`0x0818c1a8`); r1 passes through unchanged. All four observed callers
/// acquire the UI manager through `0x22007470` and pass it with flag 1.
///
/// Decoding every ARM B/BL word in osos.dec found exactly four direct,
/// unconditional `bl` callers at 0x08201d0c, 0x08235e00, 0x08236140, and
/// 0x08237304; there are no predicated calls, direct tail branches, or
/// aligned raw data-word references. Deviation: target builds use the exact
/// literal tail veneer; host builds expose the unresolved IRAM boundary as a
/// replaceable callback and do not model its `manager + 0x20` load.
pub const UI_MANAGER_DISPATCH_CALLBACK_CONTEXT_VENEER: u32 = 0x0803_8208;
pub const UI_MANAGER_DISPATCH_CALLBACK_CONTEXT_INSN: u32 = 0xe51f_f004;
pub const UI_MANAGER_DISPATCH_CALLBACK_CONTEXT_TARGET: u32 = 0x2200_76cc;

/// ABI at the UI manager's callback-context dispatch veneer.
pub type UiManagerDispatchCallbackContextFn =
    unsafe extern "C" fn(manager: *mut u8, flag: u32);

/// Host/target dispatch boundary for the unresolved IRAM callback target.
#[derive(Clone, Copy)]
pub struct UiManagerDispatchCallbackContextOps {
    pub dispatch: UiManagerDispatchCallbackContextFn,
}

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_ui_manager_dispatch_callback_context(
    _manager: *mut u8,
    _flag: u32,
) {
}

#[cfg(not(target_arch = "arm"))]
const DEFAULT_UI_MANAGER_DISPATCH_CALLBACK_CONTEXT_OPS: UiManagerDispatchCallbackContextOps =
    UiManagerDispatchCallbackContextOps {
        dispatch: missing_ui_manager_dispatch_callback_context,
    };

/// Replaceable host boundary for the mirrored callback-context dispatch body.
#[cfg(not(target_arch = "arm"))]
pub static mut UI_MANAGER_DISPATCH_CALLBACK_CONTEXT_OPS: UiManagerDispatchCallbackContextOps =
    DEFAULT_UI_MANAGER_DISPATCH_CALLBACK_CONTEXT_OPS;

#[cfg(not(target_arch = "arm"))]
#[inline(always)]
fn ui_manager_dispatch_callback_context_target() -> UiManagerDispatchCallbackContextFn {
    unsafe {
        core::ptr::read_volatile(core::ptr::addr_of!(
            UI_MANAGER_DISPATCH_CALLBACK_CONTEXT_OPS.dispatch
        ))
    }
}

#[cfg(target_arch = "arm")]
extern "C" {
    pub fn ui_manager_dispatch_callback_context(manager: *mut u8, flag: u32);
}

/// Host implementation of the literal veneer. It preserves both arguments.
#[cfg(not(target_arch = "arm"))]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ui_manager_dispatch_callback_context(manager: *mut u8, flag: u32) {
    unsafe { ui_manager_dispatch_callback_context_target()(manager, flag) }
}

// `ldr pc` preserves LR and r1; the target loads the callback context into
// r0 then tail-dispatches its unresolved external continuation.
#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .text
    .p2align 2
    .globl ui_manager_dispatch_callback_context
    .type ui_manager_dispatch_callback_context, %function
ui_manager_dispatch_callback_context:
    ldr     pc, [pc, #-4]
    .word   0x220076cc
    .size ui_manager_dispatch_callback_context, . - ui_manager_dispatch_callback_context
"#
);

/// ui_manager_current_context — original: `thunk_EXT_FUN_22005228` @
/// `0x08038218` (Ghidra reports 4 bytes; raw `osos.dec` proves the full
/// **8** bytes are `ldr pc,[pc,#-4]` / `0xe51ff004` and target literal
/// `0x22005228` at `0x0803821c`; the next veneer begins at `0x08038220`).
///
/// The boot relocator at `0x080046e0` copies `0xaed8` bytes from
/// `0x08000000` to `0x22000000`, so the literal reaches the mirrored
/// `FUN_08005228` @ `0x08005228`, not mask ROM. Its three instructions load
/// the manager's word at `+0x1c`, load that object's word at `+0x1c`, and
/// return it. The three observed callers acquire the UI manager immediately
/// before this veneer and pass the result to UI callback setup.
///
/// Decoding every ARM B/BL word in `osos.dec` found exactly three direct,
/// unconditional `bl` callers at 0x08201f84, 0x08201fdc, and 0x08202020;
/// there are no predicated calls, direct tail branches, or aligned raw
/// data-word references. Deviation: target builds retain the exact literal
/// veneer; the host implementation performs the verified target-width word
/// loads directly.
pub const UI_MANAGER_CURRENT_CONTEXT_VENEER: u32 = 0x0803_8218;
pub const UI_MANAGER_CURRENT_CONTEXT_INSN: u32 = 0xe51f_f004;
pub const UI_MANAGER_CURRENT_CONTEXT_TARGET: u32 = 0x2200_5228;

#[cfg(target_arch = "arm")]
extern "C" {
    pub fn ui_manager_current_context(manager: *mut u8) -> *mut u8;
}

/// Host implementation of the mirrored two-level `+0x1c` context lookup.
///
/// Both pointers are target-width words, rather than host pointer fields, so
/// the observed ARM offsets remain correct on 64-bit hosts.
#[cfg(not(target_arch = "arm"))]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ui_manager_current_context(manager: *mut u8) -> *mut u8 {
    let state = core::ptr::read_volatile(manager.add(0x1c).cast::<u32>()) as usize as *mut u8;
    core::ptr::read_volatile(state.add(0x1c).cast::<u32>()) as usize as *mut u8
}

// `ldr pc` preserves LR and forwards the mirrored body's result unchanged.
#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .text
    .p2align 2
    .globl ui_manager_current_context
    .type ui_manager_current_context, %function
ui_manager_current_context:
    ldr     pc, [pc, #-4]
    .word   0x22005228
    .size ui_manager_current_context, . - ui_manager_current_context
"#
);



/// stream_buffer_flush_enter — original:
/// `thunk_FUN_08201460` @ `0x08003848` (Ghidra reports 4 bytes; raw
/// osos.dec proves the full **8** bytes are `ldr pc,[pc,#-4]` /
/// `0xe51ff004` and the target literal `0x08201460` at `0x0800384c`; the
/// next veneer starts at `0x08003850`, so the true extent is 8 bytes).
///
/// The literal target `0x08201460` is DRAM code (not an IRAM mirror): a
/// mid-function continuation entry of the stream-buffer flush routine
/// Ghidra splits as `FUN_08201460` (312 bytes). Its first three words are
/// `mov r0,r4; blx r1; b 0x082014cc` — it reads the stream-buffer object
/// from **callee-saved r4**, calls the flush callback held in r1 with the
/// object as its only argument, then runs the flush tail (reloading
/// buffer fields from `[r4,#...]` and driving the vtables at `[r4,#0x18]`
/// / `[r4,#0x1c]`). Callers copy their r0 object into r4 before the `bl`
/// (e.g. `FUN_0800602c`: `mov r6,r1; mov r4,r0; bl 0x08003848`), so the
/// veneer behaves as `flush_callback(stream_buffer)` plus the flush tail,
/// forwarding the callback's r0 result and every register unchanged.
///
/// Decoding every ARM B/BL word in osos.dec found exactly five direct,
/// unconditional `bl` callers at 0x0800603c, 0x08006094, 0x080064cc,
/// 0x08006534, and 0x080073c0; there are no predicated calls, direct tail
/// branches, or aligned raw data-word references. Deviation: target
/// builds use the exact literal tail veneer; host builds expose the
/// otherwise foreign DRAM boundary as a replaceable callback taking the
/// object and callback the caller placed in r0/r1 (r4 is not expressible
/// in the Rust ABI).
pub const STREAM_BUFFER_FLUSH_ENTER_VENEER: u32 = 0x0800_3848;
pub const STREAM_BUFFER_FLUSH_ENTER_INSN: u32 = 0xe51f_f004;
pub const STREAM_BUFFER_FLUSH_ENTER_TARGET: u32 = 0x0820_1460;

/// Flush callback the continuation invokes as `callback(stream_buffer)`.
pub type StreamBufferFlushCallbackFn = unsafe extern "C" fn(stream_buffer: *mut u8) -> u32;

/// ABI of the flush-enter continuation as seen by its callers: the
/// stream-buffer object and the flush callback to invoke on it.
pub type StreamBufferFlushEnterFn = unsafe extern "C" fn(
    stream_buffer: *mut u8,
    flush_callback: StreamBufferFlushCallbackFn,
) -> u32;

/// Host/target dispatch boundary for the flush-enter continuation body.
#[derive(Clone, Copy)]
pub struct StreamBufferFlushEnterOps {
    pub enter: StreamBufferFlushEnterFn,
}

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_stream_buffer_flush_enter(
    _stream_buffer: *mut u8,
    _flush_callback: StreamBufferFlushCallbackFn,
) -> u32 {
    0
}

#[cfg(not(target_arch = "arm"))]
const DEFAULT_STREAM_BUFFER_FLUSH_ENTER_OPS: StreamBufferFlushEnterOps =
    StreamBufferFlushEnterOps {
        enter: missing_stream_buffer_flush_enter,
    };

/// Replaceable host boundary for the flush-enter continuation body.
#[cfg(not(target_arch = "arm"))]
pub static mut STREAM_BUFFER_FLUSH_ENTER_OPS: StreamBufferFlushEnterOps =
    DEFAULT_STREAM_BUFFER_FLUSH_ENTER_OPS;

#[cfg(not(target_arch = "arm"))]
#[inline(always)]
fn stream_buffer_flush_enter_target() -> StreamBufferFlushEnterFn {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(STREAM_BUFFER_FLUSH_ENTER_OPS.enter)) }
}

#[cfg(target_arch = "arm")]
extern "C" {
    pub fn stream_buffer_flush_enter(
        stream_buffer: *mut u8,
        flush_callback: StreamBufferFlushCallbackFn,
    ) -> u32;
}

/// Host implementation of the literal veneer. It preserves both arguments
/// and the target result exactly.
#[cfg(not(target_arch = "arm"))]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn stream_buffer_flush_enter(
    stream_buffer: *mut u8,
    flush_callback: StreamBufferFlushCallbackFn,
) -> u32 {
    unsafe { stream_buffer_flush_enter_target()(stream_buffer, flush_callback) }
}

// `ldr pc` preserves LR and every argument register; the continuation's
// `mov r0,r4` relies on the caller having copied r0 into r4, which the
// verbatim veneer forwards untouched.
#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .text
    .p2align 2
    .globl stream_buffer_flush_enter
    .type stream_buffer_flush_enter, %function
stream_buffer_flush_enter:
    ldr     pc, [pc, #-4]
    .word   0x08201460
    .size stream_buffer_flush_enter, . - stream_buffer_flush_enter
"#
);

/// iram_stream_buffer_reinitialize_veneer — original:
/// `thunk_EXT_FUN_220073b0` @ `0x08038190` (Ghidra reports 4 bytes; raw
/// osos.dec proves the full **8** bytes are `ldr pc,[pc,#-4]` /
/// `0xe51ff004` and the target literal `0x220073b0` at `0x08038194`; the
/// next veneer starts at `0x08038198`).
///
/// The relocator at `0x080046e0` copies `0xaed8` bytes from `0x08000000` to
/// `0x22000000`, so the literal reaches the IRAM mirror of
/// `FUN_080073b0` @ `0x080073b0`, not mask ROM. That 60-byte body is the
/// stream-buffer flush-and-reinitialize wrapper: it saves all three
/// arguments in callee-saved registers, invokes the two stream flush
/// continuations through the literal veneers at `0x08003848` (->
/// `0x08201460`) and `0x080038f8` (-> `0x082014c8`, second argument 0),
/// clears the stream-buffer page-initialization flag byte at `0x2200aed5`,
/// then tail-calls the page initializer `FUN_080072cc` with the original
/// three arguments restored. Clearing `0x2200aed5` re-arms the guard
/// `FUN_080072cc` tests, so the tail call re-runs page setup: the existing
/// 0x20000-byte allocation is zeroed, the page pointers are rebuilt, and
/// [`crate::kernel::stream_buffer_page_contexts::stream_buffer_set_page_contexts`]
/// stores context `page_context` when `zero_page_context` is zero, else 0.
/// The initializer's r0 result (0) is forwarded to the caller.
///
/// Decoding every ARM B/BL word in osos.dec found exactly five direct,
/// unconditional `bl` callers at 0x081b0eb8, 0x08201c90, 0x08202070,
/// 0x082360c8, and 0x08237288; there are no predicated calls, direct tail
/// branches, or aligned raw data-word references. All five sites obtain the
/// buffer from the `iram_stream_buffer_initializer_veneer` accessor
/// (0x08037fd8) and pass (buffer, 1, 0). Deviation: target builds use the
/// exact literal tail veneer; host builds expose the otherwise foreign IRAM
/// boundary as a replaceable callback.
pub const IRAM_STREAM_BUFFER_REINITIALIZE_VENEER: u32 = 0x0803_8190;
pub const IRAM_STREAM_BUFFER_REINITIALIZE_INSN: u32 = 0xe51f_f004;
pub const IRAM_STREAM_BUFFER_REINITIALIZE_TARGET: u32 = 0x2200_73b0;

/// ABI of the flush-and-reinitialize thunk's mirrored body.
pub type IramStreamBufferReinitializeFn =
    unsafe extern "C" fn(stream_buffer: *mut u8, zero_page_context: u32, page_context: u32) -> u32;

/// Host/target dispatch boundary for the IRAM flush-and-reinitialize body.
#[derive(Clone, Copy)]
pub struct IramStreamBufferReinitializeOps {
    pub reinitialize: IramStreamBufferReinitializeFn,
}

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_iram_stream_buffer_reinitialize(
    _stream_buffer: *mut u8,
    _zero_page_context: u32,
    _page_context: u32,
) -> u32 {
    0
}

#[cfg(not(target_arch = "arm"))]
const DEFAULT_IRAM_STREAM_BUFFER_REINITIALIZE_OPS: IramStreamBufferReinitializeOps =
    IramStreamBufferReinitializeOps {
        reinitialize: missing_iram_stream_buffer_reinitialize,
    };

/// Replaceable host boundary for the mirrored flush-and-reinitialize body.
#[cfg(not(target_arch = "arm"))]
pub static mut IRAM_STREAM_BUFFER_REINITIALIZE_OPS: IramStreamBufferReinitializeOps =
    DEFAULT_IRAM_STREAM_BUFFER_REINITIALIZE_OPS;

#[cfg(not(target_arch = "arm"))]
#[inline(always)]
fn iram_stream_buffer_reinitialize_target() -> IramStreamBufferReinitializeFn {
    unsafe {
        core::ptr::read_volatile(core::ptr::addr_of!(
            IRAM_STREAM_BUFFER_REINITIALIZE_OPS.reinitialize
        ))
    }
}

#[cfg(target_arch = "arm")]
extern "C" {
    pub fn iram_stream_buffer_reinitialize_veneer(
        stream_buffer: *mut u8,
        zero_page_context: u32,
        page_context: u32,
    ) -> u32;
}

/// Host implementation of the literal veneer. It preserves the three
/// arguments and the mirrored body's result exactly.
#[cfg(not(target_arch = "arm"))]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn iram_stream_buffer_reinitialize_veneer(
    stream_buffer: *mut u8,
    zero_page_context: u32,
    page_context: u32,
) -> u32 {
    unsafe {
        iram_stream_buffer_reinitialize_target()(stream_buffer, zero_page_context, page_context)
    }
}

// `ldr pc` preserves LR and therefore forwards both the mirrored body's
// result and its tail call into the page initializer to the original caller.
#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .text
    .p2align 2
    .globl iram_stream_buffer_reinitialize_veneer
    .type iram_stream_buffer_reinitialize_veneer, %function
iram_stream_buffer_reinitialize_veneer:
    ldr     pc, [pc, #-4]
    .word   0x220073b0
    .size iram_stream_buffer_reinitialize_veneer, . - iram_stream_buffer_reinitialize_veneer
"#
);

/// Instruction word and literal in the I2S chunked-transfer thunk at
/// 0x08037f40.
///
/// The boot relocator at 0x080046e0 copies 0xaed8 bytes from
/// 0x08000000 to 0x22000000 (literals verified in osos.dec), so IRAM
/// target 0x220084dc is the byte-identical mirror of osos
/// `FUN_080084dc`.
pub const I2S_CHUNKED_TRANSFER_INSN: u32 = 0xe51f_f004;
pub const I2S_CHUNKED_TRANSFER_TARGET: u32 = 0x2200_84dc;

/// ABI of the chunked I2S transfer reached by
/// [`i2s_chunked_transfer_veneer`]: destination in r0, source in r1,
/// byte length in r2; always returns 0.
pub type I2sChunkedTransferFn = unsafe extern "C" fn(dst: u32, src: u32, len: u32) -> u32;

/// Host/target dispatch boundary for the unported IRAM target.
#[derive(Clone, Copy)]
pub struct I2sChunkedTransferOps {
    pub transfer: I2sChunkedTransferFn,
}

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_i2s_chunked_transfer(_dst: u32, _src: u32, _len: u32) -> u32 {
    0
}

#[cfg(not(target_arch = "arm"))]
const DEFAULT_I2S_CHUNKED_TRANSFER_OPS: I2sChunkedTransferOps = I2sChunkedTransferOps {
    transfer: missing_i2s_chunked_transfer,
};

/// The host dispatch boundary for the unported IRAM target.
#[cfg(not(target_arch = "arm"))]
pub static mut I2S_CHUNKED_TRANSFER_OPS: I2sChunkedTransferOps =
    DEFAULT_I2S_CHUNKED_TRANSFER_OPS;

#[cfg(not(target_arch = "arm"))]
#[inline(always)]
fn i2s_chunked_transfer_target() -> I2sChunkedTransferFn {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(I2S_CHUNKED_TRANSFER_OPS.transfer)) }
}

#[cfg(target_arch = "arm")]
extern "C" {
    /// i2s_chunked_transfer_veneer — original: `thunk_EXT_FUN_220084dc`
    /// @ 0x08037f40 (8 bytes; Ghidra's 4-byte extent drops the trailing
    /// literal word, the next thunk stub starts at 0x08037f48).
    ///
    /// One stub of the osos -> IRAM thunk table (see [`ROM_THUNKS`]):
    /// `ldr pc, [pc, #-4]` loading the literal 0x220084dc. `ldr pc` is a
    /// tail dispatch preserving every register including LR, so the target
    /// returns directly to this stub's caller. Decoding every ARM B/BL
    /// word in osos.dec finds exactly five calls: four plain
    /// unconditional `bl` at 0x080fa454, 0x0814dc1c, 0x081b07a8, and
    /// 0x081b07d0, plus one predicated `bleq` at 0x08093734; no tail `b`
    /// and no aligned data-word references (no virtual dispatch).
    ///
    /// Target behaviour (IRAM mirror of `FUN_080084dc` @ 0x080084dc,
    /// 0xf0 bytes of code ending at the next function 0x080085fc, with
    /// literal words 0xfff @ 0x080085d0 and 0x1ffe @ 0x080085d4): a
    /// chunked DMA/I2S memory transfer (dst in r0, src in r1, byte
    /// length in r2). It ORs the three arguments to pick a unit size:
    /// all 4-aligned -> unit 2 with byte length >>= 2 and chunk cap
    /// 0xfff << 2 = 0x3ffc; else 2-aligned -> unit 1, length >>= 1,
    /// cap 0x1ffe; else unit 0, cap 0xfff. A burst field is 7 when the
    /// unit-shifted length is a multiple of 8, 3 when a multiple of 4,
    /// else 0. Setup call FUN_080083c4(0x1c, unit, burst, 0x1c, unit,
    /// burst, &slot, &controller) (four register + four stack
    /// arguments; the I2S transfer setup path) fills a slot byte and a
    /// signed controller byte on the frame. The loop submits
    /// min(remaining, cap)-byte chunks via the ported
    /// [`crate::drivers::transfer_default_mode::queue_transfer_with_default_mode`]
    /// (FUN_08008648: src, dst, chunk, slot, controller on the stack),
    /// waits per chunk via FUN_08008690(slot, controller), advances
    /// both pointers, then tears down via FUN_080085fc(slot,
    /// controller) (the sole recovered caller of
    /// i2s_transfer_slot_cleanup) and returns 0.
    ///
    /// Deviation: none on ARM; this is the original instruction and
    /// literal. Host builds expose the foreign IRAM boundary as a
    /// replaceable callback.
    pub fn i2s_chunked_transfer_veneer(dst: u32, src: u32, len: u32) -> u32;
}

/// Host implementation of the literal veneer, with the unported IRAM
/// target supplied by [`I2S_CHUNKED_TRANSFER_OPS`].
#[cfg(not(target_arch = "arm"))]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn i2s_chunked_transfer_veneer(dst: u32, src: u32, len: u32) -> u32 {
    unsafe { i2s_chunked_transfer_target()(dst, src, len) }
}

// `ldr pc` preserves LR, so the IRAM target returns directly to this
// stub's caller. Keep the fixed target in assembly rather than
// materializing it as a Rust function pointer on target.
#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .text
    .p2align 2
    .globl i2s_chunked_transfer_veneer
    .type i2s_chunked_transfer_veneer, %function
i2s_chunked_transfer_veneer:
    ldr     pc, [pc, #-4]
    .word   0x220084dc
    .size i2s_chunked_transfer_veneer, . - i2s_chunked_transfer_veneer
"#
);

/// Instruction word and literal in the lazy-singleton accessor thunk
/// at 0x08037f58.
///
/// Identified through the relocator mirror: the boot relocator at
/// 0x080046e0 copies 0xaed8 bytes from 0x08000000 to 0x22000000 (both
/// literals verified in osos.dec), so IRAM 0x220060e0 is byte-identical
/// to osos `FUN_080060e0`.
pub const LAZY_SINGLETON_106DC_ACQUIRE_INSN: u32 = 0xe51f_f004;
pub const LAZY_SINGLETON_106DC_ACQUIRE_TARGET: u32 = 0x2200_60e0;

/// ABI of the lazy singleton accessor reached by
/// [`lazy_singleton_106dc_acquire`]: no arguments, returns the object
/// pointer.
pub type LazySingleton106dcAcquireFn = unsafe extern "C" fn() -> *mut u8;

/// Host/target dispatch boundary for the unported IRAM accessor target.
#[derive(Clone, Copy)]
pub struct LazySingleton106dcAcquireOps {
    pub acquire: LazySingleton106dcAcquireFn,
}

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_lazy_singleton_106dc_acquire() -> *mut u8 {
    core::ptr::null_mut()
}

#[cfg(not(target_arch = "arm"))]
const DEFAULT_LAZY_SINGLETON_106DC_ACQUIRE_OPS: LazySingleton106dcAcquireOps =
    LazySingleton106dcAcquireOps {
        acquire: missing_lazy_singleton_106dc_acquire,
    };

/// The host dispatch boundary for the unported IRAM accessor target.
#[cfg(not(target_arch = "arm"))]
pub static mut LAZY_SINGLETON_106DC_ACQUIRE_OPS: LazySingleton106dcAcquireOps =
    DEFAULT_LAZY_SINGLETON_106DC_ACQUIRE_OPS;

#[cfg(not(target_arch = "arm"))]
#[inline(always)]
fn lazy_singleton_106dc_acquire_target() -> LazySingleton106dcAcquireFn {
    unsafe {
        core::ptr::read_volatile(core::ptr::addr_of!(
            LAZY_SINGLETON_106DC_ACQUIRE_OPS.acquire
        ))
    }
}

#[cfg(target_arch = "arm")]
extern "C" {
    /// lazy_singleton_106dc_acquire — original: `thunk_EXT_FUN_220060e0`
    /// @ 0x08037f58 (8 bytes; Ghidra's 4-byte extent drops the trailing
    /// literal word, the next thunk stub starts at 0x08037f60).
    ///
    /// One stub of the osos -> IRAM thunk table (see [`ROM_THUNKS`]):
    /// `ldr pc, [pc, #-4]` loading the literal 0x220060e0. `ldr pc` is a
    /// tail dispatch preserving every register including LR, so the target
    /// returns directly to this stub's caller. All 32 call sites decoded
    /// from osos.dec are plain unconditional `bl` (no predicated forms,
    /// no tail `b`); none NULL-checks the result — the accessor always
    /// hands back the fixed singleton address.
    ///
    /// Target behaviour (IRAM mirror of `FUN_080060e0` @ 0x080060e0,
    /// 88 bytes of code + 16-byte literal pool; the next function opens
    /// at 0x08006148): lazy accessor for the C++ singleton object at
    /// 0x220106dc. Under once-guard bit 0 of the word at state+4 (state
    /// block 0x22008cdc) it runs construct-and-register: glue veneer
    /// 0x080036e0 -> 0x082a0444(state+4); on success ctor
    /// 0x08006988(0x220106dc) (plants vtable 0x22008a10, zeroes fields,
    /// allocates a 0x1000-byte buffer), glue veneer 0x080036e8 ->
    /// 0x082a02f0(result, dtor 0x22006ab4, __dso_handle 0x089ca09c),
    /// glue veneer 0x080036f0 -> 0x082a0460(state+4). A second once-flag
    /// (byte at state+0) is then set to 1 with NO companion init call —
    /// unlike ui_manager_acquire's target, which runs FUN_08005448 under
    /// its flag. Returns the object pointer 0x220106dc unchanged.
    /// The class identity is unrecovered: every vtable slot
    /// (0x22006ab4/0x22006928/0x220068e0/0x220065dc/0x220065a8/
    /// 0x220060cc/0x220068b8/0x22006180) is unnamed. Callers (the
    /// 0x080a5xxx cluster plus 0x080c8bxx, in the FreeType glyph
    /// rendering region) read flag bytes at +0x47/+0x94 and an 8-valued
    /// mode byte at +0x58 that selects per-mode pixel-geometry tables.
    ///
    /// Deviation: none on ARM; this is the original instruction and literal.
    pub fn lazy_singleton_106dc_acquire() -> *mut u8;
}

/// Host implementation of the lazy singleton accessor, with the
/// unported IRAM target supplied by [`LAZY_SINGLETON_106DC_ACQUIRE_OPS`].
#[cfg(not(target_arch = "arm"))]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn lazy_singleton_106dc_acquire() -> *mut u8 {
    lazy_singleton_106dc_acquire_target()()
}

// `ldr pc` preserves LR, so the IRAM target returns directly to this
// stub's caller. Keep the fixed target in assembly rather than
// materializing it as a Rust function pointer on target.
#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .text
    .p2align 2
    .globl lazy_singleton_106dc_acquire
    .type lazy_singleton_106dc_acquire, %function
lazy_singleton_106dc_acquire:
    ldr     pc, [pc, #-4]
    .word   0x220060e0
    .size lazy_singleton_106dc_acquire, . - lazy_singleton_106dc_acquire
"#
);

/// Instruction word and literal in the clock-config-dispatch thunk at
/// 0x08037f60.
///
/// The boot relocator at 0x080046e0 copies 0xaed8 bytes from
/// 0x08000000 to 0x22000000 (literals verified in osos.dec), so IRAM
/// target 0x2200200c is the byte-identical mirror of osos
/// `FUN_0800200c`.
pub const CLOCK_CONFIG_DISPATCH_INSN: u32 = 0xe51f_f004;
pub const CLOCK_CONFIG_DISPATCH_TARGET: u32 = 0x2200_200c;

/// ABI of the selector-dispatched clock-register writer reached by
/// [`clock_config_dispatch_veneer`]: selector in r0, mode in r1,
/// divisor/value in r2, always returns 0.
pub type ClockConfigDispatchFn = unsafe extern "C" fn(selector: u32, mode: u32, value: u32) -> u32;

/// Host/target dispatch boundary for the unported IRAM target.
#[derive(Clone, Copy)]
pub struct ClockConfigDispatchOps {
    pub dispatch: ClockConfigDispatchFn,
}

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_clock_config_dispatch(_selector: u32, _mode: u32, _value: u32) -> u32 {
    0
}

#[cfg(not(target_arch = "arm"))]
const DEFAULT_CLOCK_CONFIG_DISPATCH_OPS: ClockConfigDispatchOps = ClockConfigDispatchOps {
    dispatch: missing_clock_config_dispatch,
};

/// The host dispatch boundary for the unported IRAM target.
#[cfg(not(target_arch = "arm"))]
pub static mut CLOCK_CONFIG_DISPATCH_OPS: ClockConfigDispatchOps =
    DEFAULT_CLOCK_CONFIG_DISPATCH_OPS;

#[cfg(not(target_arch = "arm"))]
#[inline(always)]
fn clock_config_dispatch_target() -> ClockConfigDispatchFn {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(CLOCK_CONFIG_DISPATCH_OPS.dispatch)) }
}

#[cfg(target_arch = "arm")]
extern "C" {
    /// clock_config_dispatch_veneer — original: `thunk_EXT_FUN_2200200c`
    /// @ 0x08037f60 (8 bytes; Ghidra's 4-byte extent drops the trailing
    /// literal word, the next thunk stub starts at 0x08037f68).
    ///
    /// One stub of the osos -> IRAM thunk table (see [`ROM_THUNKS`]):
    /// `ldr pc, [pc, #-4]` loading the literal 0x2200200c. `ldr pc` is a
    /// tail dispatch preserving every register including LR, so the
    /// target returns directly to this stub's caller. Decoding every ARM
    /// B/BL word in osos.dec finds exactly five calls, all plain
    /// unconditional `bl` at 0x080a7cd0, 0x080aa138, 0x080ad428,
    /// 0x080b2808, and 0x08169d18 — no predicated forms, no tail `b`,
    /// and no aligned data-word references (no virtual dispatch).
    /// Observed arguments are selector/mode/value triples like
    /// (6, 0, 1) and (0xe, 3, 4), always paired with a companion
    /// `FUN_0836ada8(selector, 1)` call.
    ///
    /// Target behaviour (IRAM mirror of `FUN_0800200c` @ 0x0800200c,
    /// 972 bytes of code + 16-byte literal pool; the next function opens
    /// at 0x080023e8): a 17-way selector switch (0x00-0x10) that
    /// read-modify-writes bit fields of six 32-bit registers in the MMIO
    /// block at 0x3C500000 (the S5L8702 clock-controller block; register
    /// index = selector group, mode 1..3 plants 0x1000/0x2000/0x3000
    /// field encodings, divisor values > 1 are encoded as
    /// `(divisor >> 1) - 1` nibbles, with direct encodings via helper
    /// 0x0802c03c for odd divisors >= 0x12). Selectors 0 and 4
    /// busy-wait on register write-back; selector 8 writes value - 1 to
    /// 0x38501000; several selectors run the delay helper
    /// 0x08001f78(100) after the write. On exit it records the mode and
    /// value bytes per selector in the state array at 0x089CA524
    /// (+0x00 mode, +0x11 value) and returns 0. Direct predicated calls
    /// to the body exist at 0x0800289c/0x080028c4/0x08002904/0x08002924
    /// (blhi/blcc) and a plain bl at 0x08002aac — those bypass this
    /// thunk.
    ///
    /// Deviation: none on ARM; this is the original instruction and
    /// literal. Host builds expose the foreign IRAM boundary as a
    /// replaceable callback.
    pub fn clock_config_dispatch_veneer(selector: u32, mode: u32, value: u32) -> u32;
}

/// Host implementation of the literal veneer, with the unported IRAM
/// target supplied by [`CLOCK_CONFIG_DISPATCH_OPS`].
#[cfg(not(target_arch = "arm"))]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn clock_config_dispatch_veneer(selector: u32, mode: u32, value: u32) -> u32 {
    unsafe { clock_config_dispatch_target()(selector, mode, value) }
}

// `ldr pc` preserves LR, so the IRAM target returns directly to this
// stub's caller. Keep the fixed target in assembly rather than
// materializing it as a Rust function pointer on target.
#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .text
    .p2align 2
    .globl clock_config_dispatch_veneer
    .type clock_config_dispatch_veneer, %function
clock_config_dispatch_veneer:
    ldr     pc, [pc, #-4]
    .word   0x2200200c
    .size clock_config_dispatch_veneer, . - clock_config_dispatch_veneer
"#
);

/// Instruction word and literal in the event-handler-source thunk at
/// 0x08038060.
///
/// The boot relocator at 0x080046e0 copies 0xaed8 bytes from
/// 0x08000000 to 0x22000000, so IRAM target 0x22007470 is the
/// byte-identical mirror of osos `FUN_08007470`.
pub const EVENT_HANDLER_SOURCE_INSN: u32 = 0xe51f_f004;
pub const EVENT_HANDLER_SOURCE_TARGET: u32 = 0x2200_7470;

/// iram_event_handler_source_veneer — original:
/// `thunk_EXT_FUN_22007470` @ `0x08038060` (8 bytes: `ldr pc,[pc,#-4]` and
/// its target literal; Ghidra's 4-byte extent excludes the literal word).
///
/// The retailOS veneer tail-dispatches to IRAM `0x22007470`, the relocator
/// mirror of the ported [`crate::kernel::event_handler_source::event_handler_source`]
/// body at `0x08007470`. It returns that fixed source pointer to every caller.
///
/// Deliberate deviation: Rust makes a volatile indirect call and returns,
/// rather than loading PC from the literal. The initialized body has no
/// arguments and defines only the returned pointer, preserving the observable
/// ABI while keeping the veneer on the ported path.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.iram_event_handler_source_veneer")]
#[inline(never)]
pub unsafe extern "C" fn iram_event_handler_source_veneer() -> *mut u8 {
    let body = core::ptr::read_volatile(
        &(crate::kernel::event_handler_source::event_handler_source as unsafe extern "C" fn() -> *mut u8),
    );
    body()
}

/// Osos staging address of the callback-target getter veneer.
///
/// The boot relocator at 0x080046e0 copies 0xaed8 bytes from 0x08000000 to
/// 0x22000000, so this veneer actually executes at 0x22003910 and 0x08003910
/// is only where its bytes sit before relocation. Both addresses name the
/// same 8 bytes.
pub const CALLBACK_TARGET_GETTER_VENEER: u32 = 0x0800_3910;
pub const CALLBACK_TARGET_GETTER_INSN: u32 = 0xe51f_f004;
pub const CALLBACK_TARGET_GETTER_TARGET: u32 = 0x0818_c740;

/// The nine distinct vtable slots the 21 recovered call sites dispatch on the
/// pointer this veneer returns.
///
/// Every site is `bl 0x08003910; ldr r1, [r0]; ldr rX, [r1, #slot]; blx rX`,
/// so the returned object's first word is always a vtable and the largest
/// recovered slot is +0x30 (entry 12).
pub const CALLBACK_TARGET_DISPATCH_SLOTS: [u32; 9] =
    [0x00, 0x04, 0x08, 0x0c, 0x10, 0x14, 0x1c, 0x20, 0x30];

/// ABI of the getter reached by [`callback_target_getter`]: no arguments,
/// returns the selected callback target.
pub type CallbackTargetGetterFn = unsafe extern "C" fn() -> *mut u8;

/// Host/target dispatch boundary for the unported retailOS getter target.
#[derive(Clone, Copy)]
pub struct CallbackTargetGetterOps {
    pub get: CallbackTargetGetterFn,
}

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_callback_target_getter() -> *mut u8 {
    core::ptr::null_mut()
}

#[cfg(not(target_arch = "arm"))]
const DEFAULT_CALLBACK_TARGET_GETTER_OPS: CallbackTargetGetterOps = CallbackTargetGetterOps {
    get: missing_callback_target_getter,
};

/// The host dispatch boundary for the unported retailOS getter target.
#[cfg(not(target_arch = "arm"))]
pub static mut CALLBACK_TARGET_GETTER_OPS: CallbackTargetGetterOps =
    DEFAULT_CALLBACK_TARGET_GETTER_OPS;

#[cfg(not(target_arch = "arm"))]
#[inline(always)]
fn callback_target_getter_target() -> CallbackTargetGetterFn {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(CALLBACK_TARGET_GETTER_OPS.get)) }
}

#[cfg(target_arch = "arm")]
extern "C" {
    /// callback_target_getter — original: `thunk_FUN_0818c740` @ 0x08003910
    /// (8 bytes; Ghidra's 4-byte extent drops the trailing literal word, and
    /// the next veneer starts at 0x08003918).
    ///
    /// The raw body is `ldr pc, [pc, #-4]` with literal 0x0818c740: a tail
    /// dispatch out of the relocated IRAM block into retailOS that preserves
    /// every register including LR, so the target returns straight to this
    /// veneer's caller. All 21 decoded call sites are plain unconditional
    /// `bl` — no predicated forms and no tail `b` — and none of them NULL-
    /// checks the result before `ldr r1, [r0]`, which is consistent with a
    /// getter that can only return one of two statically allocated objects.
    ///
    /// The literal is a post-relocation address. The relocator copies the
    /// 0xaed8-byte IRAM block to 0x22000000 and only then moves the retailOS
    /// image down to 0x08000000, so retailOS runtime address A lives at
    /// osos.dec offset A - 0x08000000 + 0xaed8; the target's bytes are at
    /// file address 0x08197618. Read at face value the literal lands on a
    /// `pop {r3, r4, r5, r6, r7, pc}` mid-function, which is what made
    /// earlier notes call it an unliftable "return edge".
    ///
    /// The target itself is a mode-selected singleton accessor. It keeps a
    /// two-byte record (retailOS 0x089cfd28): byte 0 is a one-shot
    /// initialization flag, byte 1 the selected mode. On the first call it
    /// sets byte 0, then calls each of the two guarded-static constructors
    /// (retailOS 0x081e9784 and 0x081db84c) and invokes vtable slot 0 on each
    /// returned object. It then tail-calls the accessor selected by byte 1 —
    /// nonzero picks 0x081db84c, zero picks 0x081e9784 — and returns that
    /// object. The two sibling veneers in the same table read and write that
    /// mode byte: 0x08003908 returns 3 when it is set and 0 otherwise, and
    /// 0x08003918 sets it to (argument == 3). Neither accessor is ported, so
    /// the ARM build keeps the retail literal veneer verbatim.
    ///
    /// Deviation: none on ARM; this is the original instruction and literal.
    pub fn callback_target_getter() -> *mut u8;
}

/// Host implementation of the callback-target getter, with the unported
/// retailOS target supplied by [`CALLBACK_TARGET_GETTER_OPS`].
#[cfg(not(target_arch = "arm"))]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn callback_target_getter() -> *mut u8 {
    callback_target_getter_target()()
}

// `ldr pc` preserves LR, so the retailOS target returns directly to this
// veneer's caller. Keep the fixed target in assembly rather than
// materializing it as a Rust function pointer on target.
#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .text
    .p2align 2
    .globl callback_target_getter
    .type callback_target_getter, %function
callback_target_getter:
    ldr     pc, [pc, #-4]
    .word   0x0818c740
    .size callback_target_getter, . - callback_target_getter
"#
);
/// Osos staging address of the audio stream configuration veneer.
pub const AUDIO_STREAM_CONFIGURE_VENEER: u32 = 0x0800_3928;
pub const AUDIO_STREAM_CONFIGURE_INSN: u32 = 0xe51f_f004;
pub const AUDIO_STREAM_CONFIGURE_TARGET: u32 = 0x0818_c1c8;

/// ABI of the audio stream configuration target reached by
/// [`audio_stream_configure`].
///
/// The target accepts a stream, sample rate, sample bit depth, and channel
/// count, and returns whether the configuration was accepted.
pub type AudioStreamConfigureFn = unsafe extern "C" fn(*mut u8, u32, u32, u32) -> u32;

/// Host/target dispatch boundary for the unported retailOS audio stream
/// configuration target.
#[derive(Clone, Copy)]
pub struct AudioStreamConfigureOps {
    pub configure: AudioStreamConfigureFn,
}

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_audio_stream_configure(
    _stream: *mut u8,
    _sample_rate: u32,
    _sample_bit_depth: u32,
    _channel_count: u32,
) -> u32 {
    0
}

#[cfg(not(target_arch = "arm"))]
const DEFAULT_AUDIO_STREAM_CONFIGURE_OPS: AudioStreamConfigureOps = AudioStreamConfigureOps {
    configure: missing_audio_stream_configure,
};

/// The host dispatch boundary for the unported retailOS audio stream
/// configuration target.
#[cfg(not(target_arch = "arm"))]
pub static mut AUDIO_STREAM_CONFIGURE_OPS: AudioStreamConfigureOps =
    DEFAULT_AUDIO_STREAM_CONFIGURE_OPS;

#[cfg(not(target_arch = "arm"))]
#[inline(always)]
fn audio_stream_configure_target() -> AudioStreamConfigureFn {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(AUDIO_STREAM_CONFIGURE_OPS.configure)) }
}

#[cfg(target_arch = "arm")]
extern "C" {
    /// audio_stream_configure — original: `FUN_08003928` @ 0x08003928
    /// (8 bytes; Ghidra's 4-byte extent drops the trailing literal word, and
    /// the next veneer starts at 0x08003930).
    ///
    /// Raw osos.dec is `ldr pc, [pc, #-4]` plus literal 0x0818c1c8, so this
    /// tail veneer preserves every register including LR and forwards all four
    /// arguments directly to the target. A full A32 branch scan finds three
    /// plain unconditional BL call sites (0x08007668, 0x08007774, 0x08007ef4)
    /// and zero predicated BL call sites. The post-relocation target maps to
    /// function entry 0x081970a0, which validates stream sample rate, bit
    /// depth, and channel count before notifying its three stream consumers.
    ///
    /// Deliberate deviation: none on ARM; this is the original instruction and
    /// literal.
    pub fn audio_stream_configure(
        stream: *mut u8,
        sample_rate: u32,
        sample_bit_depth: u32,
        channel_count: u32,
    ) -> u32;
}

/// Host implementation of the audio stream configuration veneer, with the
/// unported retailOS target supplied by [`AUDIO_STREAM_CONFIGURE_OPS`].
#[cfg(not(target_arch = "arm"))]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn audio_stream_configure(
    stream: *mut u8,
    sample_rate: u32,
    sample_bit_depth: u32,
    channel_count: u32,
) -> u32 {
    audio_stream_configure_target()(stream, sample_rate, sample_bit_depth, channel_count)
}

// `ldr pc` preserves LR, so the retailOS target returns directly to this
// veneer's caller. Keep the fixed target in assembly rather than materializing
// it as a Rust function pointer on target.
#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .text
    .p2align 2
    .globl audio_stream_configure
    .type audio_stream_configure, %function
audio_stream_configure:
    ldr     pc, [pc, #-4]
    .word   0x0818c1c8
    .size audio_stream_configure, . - audio_stream_configure
"#
);

/// Instruction word and literal in the r7-context table-dispatch veneer.
pub const R7_CONTEXT_TABLE_DISPATCH_VENEER_INSN: u32 = 0xe51f_f004;
pub const R7_CONTEXT_TABLE_DISPATCH_VENEER_TARGET: u32 = 0x081f_f130;

/// ABI of the target reached by [`r7_context_table_dispatch_veneer`].
///
/// This is not a normal C entry: the literal lands at `0x081ff130`, two
/// instructions after `FUN_081ff130`'s prologue saved the incoming `r0` in
/// callee-saved `r7`. Retail callers consequently supply the required context
/// in `r7`; the literal veneer itself preserves it and returns the target's
/// `r0` result.
pub type R7ContextTableDispatchFn = unsafe extern "C" fn() -> *mut u8;

/// Host/target dispatch boundary for the unported r7-context continuation.
#[derive(Clone, Copy)]
pub struct R7ContextTableDispatchOps {
    pub dispatch: R7ContextTableDispatchFn,
}

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_r7_context_table_dispatch() -> *mut u8 {
    core::ptr::null_mut()
}

#[cfg(not(target_arch = "arm"))]
const DEFAULT_R7_CONTEXT_TABLE_DISPATCH_OPS: R7ContextTableDispatchOps =
    R7ContextTableDispatchOps {
        dispatch: missing_r7_context_table_dispatch,
    };

/// Host replacement for the literal target, which cannot consume a host
/// caller's ARM `r7` register.
#[cfg(not(target_arch = "arm"))]
pub static mut R7_CONTEXT_TABLE_DISPATCH_OPS: R7ContextTableDispatchOps =
    DEFAULT_R7_CONTEXT_TABLE_DISPATCH_OPS;

#[cfg(not(target_arch = "arm"))]
#[inline(always)]
fn r7_context_table_dispatch_target() -> R7ContextTableDispatchFn {
    unsafe {
        core::ptr::read_volatile(core::ptr::addr_of!(
            R7_CONTEXT_TABLE_DISPATCH_OPS.dispatch
        ))
    }
}

#[cfg(target_arch = "arm")]
extern "C" {
    /// r7_context_table_dispatch_veneer — original:
    /// `thunk_FUN_081ff130` @ 0x08003798 (8 bytes; Ghidra's reported 4-byte
    /// extent omits the literal word, and the next distinct veneer starts at
    /// 0x080037a0).
    ///
    /// Raw ARM is `ldr pc, [pc, #-4]` followed by `0x081ff130`. It tail-jumps
    /// into the interior of the function whose real entry is 0x081ff128,
    /// after `mov r7, r0`; that continuation walks seventeen r7-relative
    /// table entries, conditionally invokes their callbacks, then returns a
    /// result pointer in r0. The veneer itself has no algorithm beyond
    /// preserving every register and LR across that tail transfer.
    ///
    /// A complete ARM B/BL decode finds exactly seven direct `bl` call sites
    /// (0x08005538, 0x08005710, 0x08005730, 0x08005950, 0x080061fc,
    /// 0x08006570, 0x080065c0), all unconditional; there are no predicated
    /// forms. This is caller-side context setup, not a NULL guard.
    ///
    /// Deliberate deviation: none on ARM. The host seam represents only the
    /// observable call-and-return edge because x86-64 has no compatible r7
    /// continuation ABI.
    pub fn r7_context_table_dispatch_veneer() -> *mut u8;
}

/// Host implementation of the r7-context table-dispatch veneer.
#[cfg(not(target_arch = "arm"))]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn r7_context_table_dispatch_veneer() -> *mut u8 {
    r7_context_table_dispatch_target()()
}

// `ldr pc` preserves r7 and LR. The literal deliberately enters a continuation
// rather than a normal function entry, so materializing a Rust function
// pointer would not reproduce the firmware ABI.
#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .text
    .p2align 2
    .globl r7_context_table_dispatch_veneer
    .type r7_context_table_dispatch_veneer, %function
r7_context_table_dispatch_veneer:
    ldr     pc, [pc, #-4]
    .word   0x081ff130
    .size r7_context_table_dispatch_veneer, . - r7_context_table_dispatch_veneer
"#
);

/// Osos load address of the shared context-value commit veneer.
pub const CONTEXT_VALUE_COMMIT_VENEER: u32 = 0x0800_37d0;

/// Instruction word and literal in the shared context-value commit veneer.
pub const CONTEXT_VALUE_COMMIT_VENEER_INSN: u32 = 0xe51f_f004;
pub const CONTEXT_VALUE_COMMIT_VENEER_TARGET: u32 = 0x080e_cfa4;

#[cfg(target_arch = "arm")]
extern "C" {
    /// context_value_commit_veneer — original: `thunk_FUN_080ecfa4` @
    /// `0x080037d0` (8 bytes: `ldr pc,[pc,#-4]` and its target literal; Ghidra's
    /// reported 4-byte extent excludes the literal word, and the next distinct
    /// veneer starts at 0x080037d8).
    ///
    /// The literal enters the shared epilogue of `FUN_080ece68`: it stores r5
    /// at r4 + 4, then pops `{r3,r4,r5,r6,r7,r8,r9,pc}`. The tail transfer
    /// therefore commits the caller's callee-saved context value and returns
    /// directly from that caller, never to the instruction after its `bl`.
    ///
    /// A complete ARM B/BL decode finds exactly six inbound calls, all plain
    /// unconditional `bl` at 0x08005804, 0x08005824, 0x08005924, 0x080059f8,
    /// 0x08006314, and 0x08006330; there are no predicated forms. No aligned
    /// data word in osos.dec holds this veneer address, so there is no vtable
    /// dispatch.
    ///
    /// Deliberate deviation: none on ARM; it retains the raw literal tail
    /// transfer. The host-only function accepts the otherwise implicit r4/r5
    /// operands explicitly and returns normally, so tests can verify the only
    /// data-side effect without pretending that an x86 frame can be
    /// ARM-unwound.
    pub fn context_value_commit_veneer() -> !;
}

/// Host model of the context-value commit tail transfer.
///
/// `context` and `value` model the r4 and r5 operands respectively. The ARM
/// target has no NULL guard; callers must provide a valid, word-aligned
/// context containing the +4 field.
#[cfg(not(target_arch = "arm"))]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn context_value_commit_veneer(context: *mut u32, value: u32) {
    context.add(1).write(value);
}

// The literal target consumes the immediate caller's full saved frame. Keep
// this fixed ARM veneer verbatim: a Rust wrapper cannot preserve that ABI.
#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .text
    .p2align 2
    .globl context_value_commit_veneer
    .type context_value_commit_veneer, %function
context_value_commit_veneer:
    ldr     pc, [pc, #-4]
    .word   0x080ecfa4
    .size context_value_commit_veneer, . - context_value_commit_veneer
"#
);

/// Osos load address of the opaque retail selection-dispatch veneer.
pub const RETAIL_SELECTION_DISPATCH_VENEER: u32 = 0x0800_37d8;

/// Instruction word and literal in the opaque retail selection-dispatch veneer.
pub const RETAIL_SELECTION_DISPATCH_INSN: u32 = 0xe51f_f004;
pub const RETAIL_SELECTION_DISPATCH_TARGET: u32 = 0x080e_d0f4;

/// ABI inferred from the four direct callers of
/// [`retail_selection_dispatch_veneer`].
pub type RetailSelectionDispatchFn =
    unsafe extern "C" fn(u32, *mut u32, u32, u32) -> u32;

/// Host/target dispatch boundary for the unported retail selection routine.
#[derive(Clone, Copy)]
pub struct RetailSelectionDispatchOps {
    pub dispatch: RetailSelectionDispatchFn,
}

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_retail_selection_dispatch(
    _context: u32,
    _records: *mut u32,
    _selection: u32,
    _index: u32,
) -> u32 {
    0
}

#[cfg(not(target_arch = "arm"))]
const DEFAULT_RETAIL_SELECTION_DISPATCH_OPS: RetailSelectionDispatchOps =
    RetailSelectionDispatchOps {
        dispatch: missing_retail_selection_dispatch,
    };

/// Host replacement for the unported retail selection routine.
#[cfg(not(target_arch = "arm"))]
pub static mut RETAIL_SELECTION_DISPATCH_OPS: RetailSelectionDispatchOps =
    DEFAULT_RETAIL_SELECTION_DISPATCH_OPS;

#[cfg(not(target_arch = "arm"))]
#[inline(always)]
fn retail_selection_dispatch_target() -> RetailSelectionDispatchFn {
    unsafe {
        core::ptr::read_volatile(core::ptr::addr_of!(
            RETAIL_SELECTION_DISPATCH_OPS.dispatch
        ))
    }
}

#[cfg(target_arch = "arm")]
extern "C" {
    /// retail_selection_dispatch_veneer — original:
    /// `thunk_FUN_080ed0f4` @ 0x080037d8 (8 bytes; Ghidra reports only the
    /// four-byte instruction).
    ///
    /// Raw ARM is `ldr pc, [pc, #-4]` followed by literal 0x080ed0f4, so this
    /// veneer tail-dispatches without changing r0-r3 or LR. The next distinct
    /// veneer starts at 0x080037e0. Complete ARM B/BL decoding finds exactly
    /// four direct call sites, all plain unconditional `bl` (0x08005814,
    /// 0x08005834, 0x08005934, and 0x08005a08); there are no predicated forms.
    ///
    /// The callers pass a context value, record array, selection, and index in
    /// r0-r3, but the target's standalone Ghidra C has no recovered parameter
    /// use and no verified semantic identity.
    ///
    /// Deliberate deviation: none on ARM. Host builds inject the target and
    /// expose r0-r3 explicitly, preserving the observable dispatch and result.
    pub fn retail_selection_dispatch_veneer(
        context: u32,
        records: *mut u32,
        selection: u32,
        index: u32,
    ) -> u32;
}

/// Host implementation of the opaque retail selection-dispatch veneer.
#[cfg(not(target_arch = "arm"))]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn retail_selection_dispatch_veneer(
    context: u32,
    records: *mut u32,
    selection: u32,
    index: u32,
) -> u32 {
    retail_selection_dispatch_target()(context, records, selection, index)
}

// `ldr pc` preserves LR and every general-purpose register, so ARM must retain
// the raw literal tail transfer rather than materializing a Rust call.
#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .text
    .p2align 2
    .globl retail_selection_dispatch_veneer
    .type retail_selection_dispatch_veneer, %function
retail_selection_dispatch_veneer:
    ldr     pc, [pc, #-4]
    .word   0x080ed0f4
    .size retail_selection_dispatch_veneer, . - retail_selection_dispatch_veneer
"#
);

/// Osos load address of the event-handler source child-enabled veneer.
pub const EVENT_HANDLER_SOURCE_CHILD_ENABLED_VENEER: u32 = 0x0800_3950;

/// Instruction word and literal in the child-enabled veneer.
pub const EVENT_HANDLER_SOURCE_CHILD_ENABLED_VENEER_INSN: u32 = 0xe51f_f004;
pub const EVENT_HANDLER_SOURCE_CHILD_ENABLED_VENEER_TARGET: u32 = 0x0811_851c;

/// Byte offset of the enabled flag halfword inside a source child object.
pub const EVENT_HANDLER_SOURCE_CHILD_FLAG_OFFSET: usize = 0x68;

#[cfg(target_arch = "arm")]
extern "C" {
    /// event_handler_source_child_enabled — original: `FUN_08003950` @
    /// `0x08003950` (8 bytes: `ldr pc,[pc,#-4]` and its target literal
    /// 0x0811851c; Ghidra's reported 4-byte extent excludes the literal word,
    /// and the next veneer starts at 0x08003958).
    ///
    /// The literal is a post-relocation retailOS address: the relocator at
    /// 0x080046e0 copies the 0xaed8-byte IRAM block (this veneer included, so
    /// on device it is equally entered as 0x22003950) to 0x22000000 and only
    /// then moves the retailOS image down to 0x08000000, so the target's
    /// bytes live at osos.dec file address 0x081233f4 (= target - 0x08000000
    /// + 0xaed8). Read at face value the literal lands on a `strb` mid
    /// `FUN_081184d0`; at file address 0x081233f4 it is a clean 16-byte leaf:
    ///
    /// ```text
    /// ldrh r0, [r0, #0x68]
    /// cmp  r0, #0
    /// movne r0, #1
    /// bx   lr
    /// ```
    ///
    /// i.e. it reads the child object's enabled halfword at +0x68 and
    /// normalizes it to 0/1; r1 is ignored. The next function prologue at
    /// file address 0x08123404 confirms the 16-byte extent. Recovered callers
    /// are the event-handler source message/teardown paths: they use the
    /// result as a predicate, tearing the child down (`FUN_080039c8`) and
    /// decrementing the source's active-child halfword count at +0x50 when it
    /// is nonzero.
    ///
    /// A complete ARM B/BL decode of osos.dec finds exactly five inbound
    /// calls, all plain unconditional `bl` at 0x080078d0, 0x08007930,
    /// 0x080079cc, 0x08007a10, and 0x08007e08; there are no predicated forms
    /// and no tail `b`. No aligned data word in osos.dec holds 0x08003950 or
    /// 0x22003950, so there is no vtable dispatch.
    ///
    /// Deliberate deviation: none on ARM; the port is the verbatim
    /// instruction and literal. The host build implements the fully decoded
    /// 16-byte target leaf directly instead of crossing a replaceable seam.
    pub fn event_handler_source_child_enabled(child: *const u8) -> u32;
}

/// Host port of the child-enabled leaf the veneer tail-dispatches to.
///
/// The ARM target has no NULL guard and ignores r1; callers must provide a
/// valid child object at least 0x6a bytes long. The halfword read is
/// volatile so host tests observe exactly one load per call.
#[cfg(not(target_arch = "arm"))]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn event_handler_source_child_enabled(child: *const u8) -> u32 {
    let flag = core::ptr::read_volatile(
        child.add(EVENT_HANDLER_SOURCE_CHILD_FLAG_OFFSET) as *const u16
    );
    u32::from(flag != 0)
}

// `ldr pc` preserves LR, so the retailOS leaf returns directly to this
// veneer's caller. Keep the fixed target in assembly rather than
// materializing it as a Rust function pointer on target.
#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .text
    .p2align 2
    .globl event_handler_source_child_enabled
    .type event_handler_source_child_enabled, %function
event_handler_source_child_enabled:
    ldr     pc, [pc, #-4]
    .word   0x0811851c
    .size event_handler_source_child_enabled, . - event_handler_source_child_enabled
"#
);

/// Osos load address of the event-handler source child-rank veneer.
pub const EVENT_HANDLER_SOURCE_CHILD_RANK_VENEER: u32 = 0x0800_3958;

/// Instruction word and literal in the child-rank veneer.
pub const EVENT_HANDLER_SOURCE_CHILD_RANK_VENEER_INSN: u32 = 0xe51f_f004;
pub const EVENT_HANDLER_SOURCE_CHILD_RANK_VENEER_TARGET: u32 = 0x0811_78c8;

/// Byte offset of the child rank halfword.
pub const EVENT_HANDLER_SOURCE_CHILD_RANK_OFFSET: usize = 0x6b8;

#[cfg(target_arch = "arm")]
extern "C" {
    /// Event-handler source child rank — original: `thunk_FUN_081178c8` @
    /// `0x08003958` (8 bytes: `ldr pc,[pc,#-4]` and its target literal
    /// 0x081178c8; Ghidra's reported 4-byte extent excludes the literal word,
    /// and the next veneer starts at 0x08003960).
    ///
    /// The literal is a post-relocation retailOS address. The relocator at
    /// 0x080046e0 copies the 0xaed8-byte IRAM block (this veneer included, so
    /// on device it is equally entered as 0x22003958) to 0x22000000 before
    /// moving retailOS to 0x08000000. The target bytes therefore live at
    /// osos.dec file address 0x081227a0 (= target - 0x08000000 + 0xaed8).
    /// They are the 8-byte leaf `ldrh r0,[r0,#0x6b8]; bx lr`, bounded by the
    /// next function prologue at file address 0x081227a8.
    ///
    /// Decoding every ARM B/BL word in osos.dec finds exactly three inbound
    /// calls, all plain unconditional `bl` at 0x08007908, 0x080079e8, and
    /// 0x08007a00; there are no predicated forms. The event-handler source
    /// teardown path compares this rank to select enabled children to retire.
    ///
    /// Deliberate deviation: none on ARM; the port is the verbatim instruction
    /// and literal. The host build implements the decoded leaf directly.
    pub fn event_handler_source_child_rank(child: *const u8) -> u32;
}

/// Host port of the child-rank leaf the veneer tail-dispatches to.
///
/// The ARM target has no NULL guard and ignores r1; callers must provide a
/// valid child object at least 0x6ba bytes long. The halfword read is volatile
/// so host tests observe exactly one load per call.
#[cfg(not(target_arch = "arm"))]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn event_handler_source_child_rank(child: *const u8) -> u32 {
    u32::from(core::ptr::read_volatile(
        child.add(EVENT_HANDLER_SOURCE_CHILD_RANK_OFFSET) as *const u16
    ))
}

// `ldr pc` preserves LR, so the retailOS leaf returns directly to this
// veneer's caller. Keep the fixed target in assembly rather than
// materializing it as a Rust function pointer on target.
#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .text
    .p2align 2
    .globl event_handler_source_child_rank
    .type event_handler_source_child_rank, %function
event_handler_source_child_rank:
    ldr     pc, [pc, #-4]
    .word   0x081178c8
    .size event_handler_source_child_rank, . - event_handler_source_child_rank
"#
);

/// One thunk-table entry: the osos-side stub and its ROM target.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RomThunk {
    /// osos load address of the `ldr pc, [pc, #-4]` stub.
    pub thunk_addr: u32,
    /// Absolute S5L8702 mask ROM address the stub loads into PC.
    pub rom_target: u32,
    /// Semantic name for identified targets (see module header);
    /// `None` for ROM functions not yet identified.
    pub name: Option<&'static str>,
}

/// The full thunk table, in osos address order (sorted, contiguous,
/// stride 8). Extracted from osos.dec @ 0x08037db0..0x080382a0.
pub static ROM_THUNKS: [RomThunk; 158] = [
    RomThunk { thunk_addr: 0x08037db0, rom_target: 0x22000020, name: Some("__rt_memcpy") },
    RomThunk { thunk_addr: 0x08037db8, rom_target: 0x2200027c, name: Some("memzero_aligned") },
    RomThunk { thunk_addr: 0x08037dc0, rom_target: 0x220002d8, name: Some("memset_body") },
    RomThunk { thunk_addr: 0x08037dc8, rom_target: 0x220002d4, name: Some("memzero") },
    RomThunk { thunk_addr: 0x08037dd0, rom_target: 0x22000020, name: Some("__rt_memcpy") },
    RomThunk { thunk_addr: 0x08037dd8, rom_target: 0x220000d4, name: Some("memmove") },
    RomThunk { thunk_addr: 0x08037de0, rom_target: 0x22000614, name: None },
    RomThunk { thunk_addr: 0x08037de8, rom_target: 0x22000318, name: None },
    RomThunk { thunk_addr: 0x08037df0, rom_target: 0x22001f38, name: None },
    RomThunk { thunk_addr: 0x08037df8, rom_target: 0x22000188, name: Some("memcpy") },
    RomThunk { thunk_addr: 0x08037e00, rom_target: 0x220000d4, name: Some("memmove") },
    RomThunk { thunk_addr: 0x08037e08, rom_target: 0x22003fd0, name: Some("sem_wait") },
    RomThunk { thunk_addr: 0x08037e10, rom_target: 0x220042b4, name: Some("sem_signal") },
    RomThunk { thunk_addr: 0x08037e18, rom_target: 0x2200418c, name: None },
    RomThunk { thunk_addr: 0x08037e20, rom_target: 0x22001edc, name: None },
    RomThunk { thunk_addr: 0x08037e28, rom_target: 0x22003b6c, name: None },
    RomThunk { thunk_addr: 0x08037e30, rom_target: 0x22003c98, name: None },
    RomThunk { thunk_addr: 0x08037e38, rom_target: 0x22003d00, name: None },
    RomThunk { thunk_addr: 0x08037e40, rom_target: 0x22003dc8, name: Some("kernel_op_dispatch") },
    RomThunk { thunk_addr: 0x08037e48, rom_target: 0x22003ea0, name: Some("task_lock") },
    RomThunk { thunk_addr: 0x08037e50, rom_target: 0x2200408c, name: Some("task_unlock") },
    RomThunk { thunk_addr: 0x08037e58, rom_target: 0x22003ec4, name: None },
    RomThunk { thunk_addr: 0x08037e60, rom_target: 0x22003eb0, name: Some("current_task_id") },
    RomThunk { thunk_addr: 0x08037e68, rom_target: 0x22003be8, name: None },
    RomThunk { thunk_addr: 0x08037e70, rom_target: 0x22003d70, name: None },
    RomThunk { thunk_addr: 0x08037e78, rom_target: 0x220041cc, name: Some("signal_object") },
    RomThunk { thunk_addr: 0x08037e80, rom_target: 0x22001cbc, name: None },
    RomThunk { thunk_addr: 0x08037e88, rom_target: 0x22003d44, name: Some("task_delay") },
    RomThunk { thunk_addr: 0x08037e90, rom_target: 0x220043f4, name: None },
    RomThunk { thunk_addr: 0x08037e98, rom_target: 0x22004260, name: None },
    RomThunk { thunk_addr: 0x08037ea0, rom_target: 0x220043c0, name: None },
    RomThunk { thunk_addr: 0x08037ea8, rom_target: 0x22004368, name: Some("wake_object") },
    RomThunk { thunk_addr: 0x08037eb0, rom_target: 0x22003c28, name: Some("gateway_service39_request") },
    RomThunk { thunk_addr: 0x08037eb8, rom_target: 0x22001ee8, name: None },
    RomThunk { thunk_addr: 0x08037ec0, rom_target: 0x22000364, name: None },
    RomThunk { thunk_addr: 0x08037ec8, rom_target: 0x22003e44, name: None },
    RomThunk { thunk_addr: 0x08037ed0, rom_target: 0x22003bcc, name: None },
    RomThunk { thunk_addr: 0x08037ed8, rom_target: 0x22001e70, name: None },
    RomThunk { thunk_addr: 0x08037ee0, rom_target: 0x22003b00, name: None },
    RomThunk { thunk_addr: 0x08037ee8, rom_target: 0x220044c8, name: None },
    RomThunk { thunk_addr: 0x08037ef0, rom_target: 0x22001f78, name: None },
    RomThunk { thunk_addr: 0x08037ef8, rom_target: 0x22003b08, name: None },
    RomThunk { thunk_addr: 0x08037f00, rom_target: 0x22001e84, name: None },
    RomThunk { thunk_addr: 0x08037f08, rom_target: 0x22004230, name: Some("gateway_service19_request") },
    RomThunk { thunk_addr: 0x08037f10, rom_target: 0x22003e1c, name: Some("timer_free_gateway") },
    RomThunk { thunk_addr: 0x08037f18, rom_target: 0x22003b8c, name: None },
    RomThunk { thunk_addr: 0x08037f20, rom_target: 0x220041fc, name: Some("gateway_service18_request") },
    RomThunk { thunk_addr: 0x08037f28, rom_target: 0x220005a0, name: None },
    RomThunk { thunk_addr: 0x08037f30, rom_target: 0x22004154, name: None },
    RomThunk { thunk_addr: 0x08037f38, rom_target: 0x2200441c, name: None },
    RomThunk { thunk_addr: 0x08037f40, rom_target: 0x220084dc, name: Some("i2s_chunked_transfer_veneer") },
    RomThunk { thunk_addr: 0x08037f48, rom_target: 0x22003f08, name: None },
    RomThunk { thunk_addr: 0x08037f50, rom_target: 0x22003e70, name: None },
    RomThunk { thunk_addr: 0x08037f58, rom_target: 0x220060e0, name: Some("lazy_singleton_106dc_acquire") },
    RomThunk { thunk_addr: 0x08037f60, rom_target: 0x2200200c, name: Some("clock_config_dispatch_veneer") },
    RomThunk { thunk_addr: 0x08037f68, rom_target: 0x2200053c, name: None },
    RomThunk { thunk_addr: 0x08037f70, rom_target: 0x220001f4, name: Some("memmove_backward") },
    RomThunk { thunk_addr: 0x08037f78, rom_target: 0x22003e00, name: None },
    RomThunk { thunk_addr: 0x08037f80, rom_target: 0x2200427c, name: Some("task_delete_gateway_veneer") },
    RomThunk { thunk_addr: 0x08037f88, rom_target: 0x22005018, name: Some("ui_manager_acquire") },
    RomThunk { thunk_addr: 0x08037f90, rom_target: 0x22004eec, name: None },
    RomThunk { thunk_addr: 0x08037f98, rom_target: 0x22005234, name: None },
    RomThunk { thunk_addr: 0x08037fa0, rom_target: 0x22003eec, name: None },
    RomThunk { thunk_addr: 0x08037fa8, rom_target: 0x22003d28, name: None },
    RomThunk { thunk_addr: 0x08037fb0, rom_target: 0x2200439c, name: None },
    RomThunk { thunk_addr: 0x08037fb8, rom_target: 0x22002ee0, name: None },
    RomThunk { thunk_addr: 0x08037fc0, rom_target: 0x22004620, name: None },
    RomThunk { thunk_addr: 0x08037fc8, rom_target: 0x22004534, name: None },
    RomThunk { thunk_addr: 0x08037fd0, rom_target: 0x2200279c, name: None },
    RomThunk { thunk_addr: 0x08037fd8, rom_target: 0x22006e88, name: Some("iram_stream_buffer_initializer_veneer") },
    RomThunk { thunk_addr: 0x08037fe0, rom_target: 0x220072c0, name: None },
    RomThunk { thunk_addr: 0x08037fe8, rom_target: 0x22004450, name: None },
    RomThunk { thunk_addr: 0x08037ff0, rom_target: 0x220085fc, name: None },
    RomThunk { thunk_addr: 0x08037ff8, rom_target: 0x220083c4, name: None },
    RomThunk { thunk_addr: 0x08038000, rom_target: 0x220086c4, name: None },
    RomThunk { thunk_addr: 0x08038008, rom_target: 0x22008118, name: None },
    RomThunk { thunk_addr: 0x08038010, rom_target: 0x2200866c, name: None },
    RomThunk { thunk_addr: 0x08038018, rom_target: 0x22008648, name: None },
    RomThunk { thunk_addr: 0x08038020, rom_target: 0x220085d8, name: None },
    RomThunk { thunk_addr: 0x08038028, rom_target: 0x2200881c, name: None },
    RomThunk { thunk_addr: 0x08038030, rom_target: 0x22008744, name: None },
    RomThunk { thunk_addr: 0x08038038, rom_target: 0x220087bc, name: None },
    RomThunk { thunk_addr: 0x08038040, rom_target: 0x220087e0, name: None },
    RomThunk { thunk_addr: 0x08038048, rom_target: 0x22001f04, name: None },
    RomThunk { thunk_addr: 0x08038050, rom_target: 0x22006b48, name: None },
    RomThunk { thunk_addr: 0x08038058, rom_target: 0x2200813c, name: None },
    RomThunk { thunk_addr: 0x08038060, rom_target: 0x22007470, name: Some("iram_event_handler_source_veneer") },
    RomThunk { thunk_addr: 0x08038068, rom_target: 0x22007a68, name: None },
    RomThunk { thunk_addr: 0x08038070, rom_target: 0x2200796c, name: None },
    RomThunk { thunk_addr: 0x08038078, rom_target: 0x2200722c, name: None },
    RomThunk { thunk_addr: 0x08038080, rom_target: 0x220040fc, name: None },
    RomThunk { thunk_addr: 0x08038088, rom_target: 0x22003b64, name: Some("signal_embedded_object") },
    RomThunk { thunk_addr: 0x08038090, rom_target: 0x22004d7c, name: None },
    RomThunk { thunk_addr: 0x08038098, rom_target: 0x22004cf0, name: None },
    RomThunk { thunk_addr: 0x080380a0, rom_target: 0x22004d20, name: None },
    RomThunk { thunk_addr: 0x080380a8, rom_target: 0x22004d4c, name: None },
    RomThunk { thunk_addr: 0x080380b0, rom_target: 0x22004dd4, name: None },
    RomThunk { thunk_addr: 0x080380b8, rom_target: 0x22006f10, name: None },
    RomThunk { thunk_addr: 0x080380c0, rom_target: 0x22007aac, name: None },
    RomThunk { thunk_addr: 0x080380c8, rom_target: 0x22007fe4, name: None },
    RomThunk { thunk_addr: 0x080380d0, rom_target: 0x22007aec, name: None },
    RomThunk { thunk_addr: 0x080380d8, rom_target: 0x220074e8, name: None },
    RomThunk { thunk_addr: 0x080380e0, rom_target: 0x22006b38, name: None },
    RomThunk { thunk_addr: 0x080380e8, rom_target: 0x220076d4, name: None },
    RomThunk { thunk_addr: 0x080380f0, rom_target: 0x220029ac, name: None },
    RomThunk { thunk_addr: 0x080380f8, rom_target: 0x22006f40, name: None },
    RomThunk { thunk_addr: 0x08038100, rom_target: 0x22007c6c, name: None },
    RomThunk { thunk_addr: 0x08038108, rom_target: 0x22007c74, name: None },
    RomThunk { thunk_addr: 0x08038110, rom_target: 0x2200508c, name: None },
    RomThunk { thunk_addr: 0x08038118, rom_target: 0x22007530, name: None },
    RomThunk { thunk_addr: 0x08038120, rom_target: 0x220055f8, name: None },
    RomThunk { thunk_addr: 0x08038128, rom_target: 0x220052ec, name: None },
    RomThunk { thunk_addr: 0x08038130, rom_target: 0x2200509c, name: Some("ui_manager_finish_pending_operation") },
    RomThunk { thunk_addr: 0x08038138, rom_target: 0x22007f88, name: None },
    RomThunk { thunk_addr: 0x08038140, rom_target: 0x220051d0, name: None },
    RomThunk { thunk_addr: 0x08038148, rom_target: 0x22007fcc, name: None },
    RomThunk { thunk_addr: 0x08038150, rom_target: 0x22007788, name: None },
    RomThunk { thunk_addr: 0x08038158, rom_target: 0x220077a8, name: None },
    RomThunk { thunk_addr: 0x08038160, rom_target: 0x22005314, name: None },
    RomThunk { thunk_addr: 0x08038168, rom_target: 0x22007bd4, name: None },
    RomThunk { thunk_addr: 0x08038170, rom_target: 0x2200543c, name: None },
    RomThunk { thunk_addr: 0x08038178, rom_target: 0x22007e38, name: None },
    RomThunk { thunk_addr: 0x08038180, rom_target: 0x22005448, name: None },
    RomThunk { thunk_addr: 0x08038188, rom_target: 0x220072cc, name: None },
    RomThunk { thunk_addr: 0x08038190, rom_target: 0x220073b0, name: Some("iram_stream_buffer_reinitialize_veneer") },
    RomThunk { thunk_addr: 0x08038198, rom_target: 0x22005690, name: None },
    RomThunk { thunk_addr: 0x080381a0, rom_target: 0x220056b0, name: None },
    RomThunk { thunk_addr: 0x080381a8, rom_target: 0x220050fc, name: None },
    RomThunk { thunk_addr: 0x080381b0, rom_target: 0x22007bf4, name: None },
    RomThunk { thunk_addr: 0x080381b8, rom_target: 0x22007bfc, name: None },
    RomThunk { thunk_addr: 0x080381c0, rom_target: 0x22007a30, name: None },
    RomThunk { thunk_addr: 0x080381c8, rom_target: 0x22007bac, name: None },
    RomThunk { thunk_addr: 0x080381d0, rom_target: 0x220078b0, name: None },
    RomThunk { thunk_addr: 0x080381d8, rom_target: 0x22007c04, name: None },
    RomThunk { thunk_addr: 0x080381e0, rom_target: 0x22005320, name: None },
    RomThunk { thunk_addr: 0x080381e8, rom_target: 0x220054a8, name: None },
    RomThunk { thunk_addr: 0x080381f0, rom_target: 0x220050f4, name: None },
    RomThunk { thunk_addr: 0x080381f8, rom_target: 0x220056d0, name: None },
    RomThunk { thunk_addr: 0x08038200, rom_target: 0x22005114, name: Some("ui_manager_begin_pending_operation") },
    RomThunk { thunk_addr: 0x08038208, rom_target: 0x220076cc, name: Some("ui_manager_dispatch_callback_context") },
    RomThunk { thunk_addr: 0x08038210, rom_target: 0x22005cb0, name: None },
    RomThunk { thunk_addr: 0x08038218, rom_target: 0x22005228, name: Some("ui_manager_current_context") },
    RomThunk { thunk_addr: 0x08038220, rom_target: 0x22004ee4, name: None },
    RomThunk { thunk_addr: 0x08038228, rom_target: 0x2200521c, name: None },
    RomThunk { thunk_addr: 0x08038230, rom_target: 0x2200530c, name: None },
    RomThunk { thunk_addr: 0x08038238, rom_target: 0x220031b8, name: None },
    RomThunk { thunk_addr: 0x08038240, rom_target: 0x22001ed0, name: None },
    RomThunk { thunk_addr: 0x08038248, rom_target: 0x2200435c, name: None },
    RomThunk { thunk_addr: 0x08038250, rom_target: 0x22004298, name: None },
    RomThunk { thunk_addr: 0x08038258, rom_target: 0x22003bb0, name: None },
    RomThunk { thunk_addr: 0x08038260, rom_target: 0x220005fc, name: None },
    RomThunk { thunk_addr: 0x08038268, rom_target: 0x22003da8, name: None },
    RomThunk { thunk_addr: 0x08038270, rom_target: 0x22001e98, name: None },
    RomThunk { thunk_addr: 0x08038278, rom_target: 0x22000428, name: None },
    RomThunk { thunk_addr: 0x08038280, rom_target: 0x220003b8, name: None },
    RomThunk { thunk_addr: 0x08038288, rom_target: 0x220040ac, name: None },
    RomThunk { thunk_addr: 0x08038290, rom_target: 0x22004138, name: None },
    RomThunk { thunk_addr: 0x08038298, rom_target: 0x22003c5c, name: None },
];

/// Looks up a thunk by its osos stub address (0x08037db0..0x08038298).
pub fn lookup_by_thunk(thunk_addr: u32) -> Option<&'static RomThunk> {
    if thunk_addr < THUNK_TABLE_BASE || thunk_addr >= THUNK_TABLE_END {
        return None;
    }
    let index = (thunk_addr - THUNK_TABLE_BASE) / THUNK_STRIDE;
    ROM_THUNKS.get(index as usize)
}

/// Looks up the first thunk aliasing a given mask ROM target address.
/// Note that two ROM targets (__rt_memcpy, memmove) are aliased by two
/// thunks each; this returns the first in table order.
pub fn lookup_by_target(rom_target: u32) -> Option<&'static RomThunk> {
    ROM_THUNKS.iter().find(|entry| entry.rom_target == rom_target)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::collections::HashMap;
    use std::string::ToString;
    use std::vec::Vec;

    /// The table holds every entry in 0x08037db0..0x080382a0.
    #[test]
    fn entry_count_and_span() {
        assert_eq!(ROM_THUNKS.len(), 158);
        assert_eq!(
            THUNK_TABLE_END - THUNK_TABLE_BASE,
            ROM_THUNKS.len() as u32 * THUNK_STRIDE
        );
        assert_eq!(ROM_THUNKS[0].thunk_addr, THUNK_TABLE_BASE);
        assert_eq!(
            ROM_THUNKS[ROM_THUNKS.len() - 1].thunk_addr,
            THUNK_TABLE_END - THUNK_STRIDE
        );
    }

    /// Stubs are contiguous, sorted, duplicate-free, on an 8-byte stride.
    #[test]
    fn table_sorted_no_duplicate_thunks() {
        for (i, entry) in ROM_THUNKS.iter().enumerate() {
            assert_eq!(
                entry.thunk_addr,
                THUNK_TABLE_BASE + i as u32 * THUNK_STRIDE,
                "entry {i} out of place"
            );
        }
        let mut sorted: Vec<u32> = ROM_THUNKS.iter().map(|e| e.thunk_addr).collect();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), ROM_THUNKS.len(), "duplicate thunk addresses");
    }

    /// Every target points into the S5L8702 mask ROM. Range extracted
    /// from osos.dec: min 0x22000020, max 0x2200881c.
    #[test]
    fn all_targets_in_mask_rom() {
        for entry in ROM_THUNKS.iter() {
            assert!(
                (ROM_BASE..ROM_BASE + 0x1_0000).contains(&entry.rom_target),
                "target {:#010x} of thunk {:#010x} outside mask ROM",
                entry.rom_target,
                entry.thunk_addr
            );
            // ROM targets are ARM code: word aligned.
            assert_eq!(entry.rom_target & 3, 0);
        }
    }

    /// Known-target name mapping (see module header for the evidence).
    #[test]
    fn known_target_names() {
        let expected: [(u32, &str); 33] = [
            (0x22000020, "__rt_memcpy"),
            (0x220000d4, "memmove"),
            (0x22000188, "memcpy"),
            (0x220001f4, "memmove_backward"),
            (0x2200027c, "memzero_aligned"),
            (0x220002d4, "memzero"),
            (0x220002d8, "memset_body"),
            (0x22003c28, "gateway_service39_request"),
            (0x22003d44, "task_delay"),
            (0x22003dc8, "kernel_op_dispatch"),
            (0x22003ea0, "task_lock"),
            (0x22003eb0, "current_task_id"),
            (0x22003fd0, "sem_wait"),
            (0x2200408c, "task_unlock"),
            (0x220042b4, "sem_signal"),
            (0x220041cc, "signal_object"),
            (0x220041fc, "gateway_service18_request"),
            (0x22004230, "gateway_service19_request"),
            (0x22003e1c, "timer_free_gateway"),
            (0x22004368, "wake_object"),
            (0x2200427c, "task_delete_gateway_veneer"),
            (0x22005018, "ui_manager_acquire"),
            (0x2200509c, "ui_manager_finish_pending_operation"),
            (0x22005114, "ui_manager_begin_pending_operation"),
            (0x220076cc, "ui_manager_dispatch_callback_context"),
            (0x22005228, "ui_manager_current_context"),
            (0x2200200c, "clock_config_dispatch_veneer"),
            (0x220060e0, "lazy_singleton_106dc_acquire"),
            (0x22006e88, "iram_stream_buffer_initializer_veneer"),
            (0x22007470, "iram_event_handler_source_veneer"),
            (0x220073b0, "iram_stream_buffer_reinitialize_veneer"),
            (0x220084dc, "i2s_chunked_transfer_veneer"),
            (0x22003b64, "signal_embedded_object"),
        ];
        for (target, name) in expected {
            let entry = lookup_by_target(target)
                .unwrap_or_else(|| panic!("no thunk for {target:#010x}"));
            assert_eq!(entry.name, Some(name), "wrong name for {target:#010x}");
        }
        // Every named entry uses one of the known names.
        let known: Vec<&str> = expected.iter().map(|&(_, n)| n).collect();
        for entry in ROM_THUNKS.iter() {
            if let Some(name) = entry.name {
                assert!(known.contains(&name), "unexpected name {name}");
            }
        }
    }

    /// Only __rt_memcpy and memmove are aliased by two thunks each;
    /// all other ROM targets appear exactly once.
    #[test]
    fn only_known_target_duplicates() {
        let mut counts: HashMap<u32, u32> = HashMap::new();
        for entry in ROM_THUNKS.iter() {
            *counts.entry(entry.rom_target).or_insert(0) += 1;
        }
        for (target, count) in counts {
            let allowed = if target == 0x22000020 || target == 0x220000d4 {
                2
            } else {
                1
            };
            assert_eq!(count, allowed, "target {target:#010x} aliased {count} times");
        }
    }

    /// Both aliased thunks of the duplicated targets are present.
    #[test]
    fn aliased_thunk_addresses() {
        let memcpy_thunks: Vec<u32> = ROM_THUNKS

            .iter()
            .filter(|e| e.rom_target == 0x22000020)
            .map(|e| e.thunk_addr)
            .collect();
        assert_eq!(memcpy_thunks, [0x08037db0, 0x08037dd0]);
        let memmove_thunks: Vec<u32> = ROM_THUNKS
            .iter()
            .filter(|e| e.rom_target == 0x220000d4)
            .map(|e| e.thunk_addr)
            .collect();
        assert_eq!(memmove_thunks, [0x08037dd8, 0x08037e00]);
    }

    #[test]
    fn lookups_round_trip() {
        // In-range lookups hit the exact slot.
        let entry = lookup_by_thunk(0x08037e08).expect("sem_wait thunk");
        assert_eq!(entry.rom_target, 0x22003fd0);
        assert_eq!(entry.name, Some("sem_wait"));
        let entry = lookup_by_thunk(0x08037e10).expect("sem_signal thunk");
        assert_eq!(entry.rom_target, 0x220042b4);
        assert_eq!(entry.name, Some("sem_signal"));
        // Last entry.
        let entry = lookup_by_thunk(THUNK_TABLE_END - THUNK_STRIDE).expect("last thunk");
        assert_eq!(entry.thunk_addr, 0x08038298);
        // Out-of-range lookups miss.
        assert!(lookup_by_thunk(THUNK_TABLE_BASE - THUNK_STRIDE).is_none());
        assert!(lookup_by_thunk(THUNK_TABLE_END).is_none());
        assert!(lookup_by_thunk(0).is_none());
        // Target lookup returns the first alias in table order.
        assert_eq!(lookup_by_target(0x22000020).unwrap().thunk_addr, 0x08037db0);
        assert!(lookup_by_target(0x2200_0004).is_none());
    }

    /// The names map strings stay stable for future ROM-call work.
    #[test]
    fn named_entry_count() {
        let named = ROM_THUNKS.iter().filter(|e| e.name.is_some()).count();
        // 33 known targets, two of them aliased by two thunks each.
        assert_eq!(named, 35);
        let _: std::string::String = ROM_THUNKS[0].name.unwrap().to_string();
    }

    /// The raw veneer is one instruction plus its PC-relative target word;
    /// `ldr pc` is a tail dispatch rather than Ghidra's inferred call/return.
    #[test]
    fn kernel_indirect_dispatch_matches_its_literal_veneer() {
        assert_eq!(KERNEL_INDIRECT_DISPATCH_INSN, 0xe51f_f004);
        assert_eq!(KERNEL_INDIRECT_DISPATCH_TARGET, 0x0815_ca7c);
        assert_eq!(KERNEL_INDIRECT_DISPATCH_TARGET & 3, 0);
    }

    /// The target is an opaque continuation, but the veneer bytes and its
    /// complete direct-call census are independently fixed by osos.dec.
    #[test]
    fn state_terminal_continuation_veneer_matches_literal_transfer() {
        assert_eq!(STATE_TERMINAL_CONTINUATION_VENEER, 0x0800_3728);
        assert_eq!(STATE_TERMINAL_CONTINUATION_INSN, 0xe51f_f004);
        assert_eq!(STATE_TERMINAL_CONTINUATION_TARGET, 0x081c_d998);
        assert_eq!(STATE_TERMINAL_CONTINUATION_TARGET & 3, 0);
    }

    /// The raw veneer at 0x080038e8 is one `ldr pc, [pc, #-4]` instruction
    /// plus its literal target word pointing at the comparator tail
    /// 0x0829fe4c inside FUN_0829fdac; both constants and the target's word
    /// alignment are independently fixed by osos.dec.
    #[test]
    fn record_fields_compare_tail_veneer_matches_literal_transfer() {
        assert_eq!(RECORD_FIELDS_COMPARE_TAIL_VENEER, 0x0800_38e8);
        assert_eq!(RECORD_FIELDS_COMPARE_TAIL_VENEER_INSN, 0xe51f_f004);
        assert_eq!(RECORD_FIELDS_COMPARE_TAIL_VENEER_TARGET, 0x0829_fe4c);
        assert_eq!(RECORD_FIELDS_COMPARE_TAIL_VENEER_TARGET & 3, 0);
    }
    /// The raw veneer at 0x08003638 reaches the frame-restoring epilogue at
    /// 0x0829fe9c. These word-level edge constraints prevent a normal
    /// call/return wrapper from replacing the stack-sensitive transfer.
    #[test]
    fn return_frame_veneer_matches_literal_transfer() {
        assert_eq!(RETURN_FRAME_VENEER, 0x0800_3638);
        assert_eq!(RETURN_FRAME_VENEER_INSN, 0xe51f_f004);
        assert_eq!(RETURN_FRAME_VENEER_TARGET, 0x0829_fe9c);
        assert_eq!(RETURN_FRAME_VENEER_TARGET & 3, 0);
    }


    static OPS_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    static mut CALLBACK_COUNT: u32 = 0;
    static mut CALLBACK_CONTEXT: *mut u8 = core::ptr::null_mut();

    unsafe extern "C" fn record_event_callback(callback_context: *mut u8) {
        CALLBACK_COUNT += 1;
        CALLBACK_CONTEXT = callback_context;
    }

    #[test]
    fn dispatch_event_callback_selects_offset_eight_and_calls_once() {
        let guard = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            core::ptr::addr_of_mut!(CALLBACK_COUNT).write(0);
            core::ptr::addr_of_mut!(CALLBACK_CONTEXT).write(core::ptr::null_mut());
            core::ptr::addr_of_mut!(EVENT_CALLBACK_DISPATCH_OPS).write(
                EventCallbackDispatchOps {
                    dispatch: record_event_callback,
                },
            );
        }

        let mut system_context = [0u8; 16];
        unsafe {
            dispatch_event_callback(system_context.as_mut_ptr());
            assert_eq!(core::ptr::addr_of!(CALLBACK_COUNT).read(), 1);
            assert_eq!(
                core::ptr::addr_of!(CALLBACK_CONTEXT).read(),
                system_context.as_mut_ptr().add(8),
            );
            core::ptr::addr_of_mut!(EVENT_CALLBACK_DISPATCH_OPS)
                .write(DEFAULT_EVENT_CALLBACK_DISPATCH_OPS);
        }
        drop(guard);
    }

    #[test]
    fn event_callback_dispatch_matches_the_literal_veneer() {
        assert_eq!(EVENT_CALLBACK_DISPATCH_INSN, 0xe51f_f004);
        assert_eq!(EVENT_CALLBACK_DISPATCH_TARGET, 0x0815_c8a0);
        assert_eq!(EVENT_CALLBACK_DISPATCH_TARGET & 3, 0);
    }

    static mut NO_ARGUMENT_CALLBACK_COUNT: u32 = 0;

    unsafe extern "C" fn record_no_argument_callback() {
        NO_ARGUMENT_CALLBACK_COUNT += 1;
    }

    #[test]
    fn dispatch_no_argument_callback_calls_once_and_returns() {
        let guard = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            core::ptr::addr_of_mut!(NO_ARGUMENT_CALLBACK_COUNT).write(0);
            core::ptr::addr_of_mut!(NO_ARGUMENT_CALLBACK_DISPATCH_OPS).write(
                NoArgumentCallbackDispatchOps {
                    dispatch: record_no_argument_callback,
                },
            );
            dispatch_no_argument_callback();
            assert_eq!(core::ptr::addr_of!(NO_ARGUMENT_CALLBACK_COUNT).read(), 1);
            core::ptr::addr_of_mut!(NO_ARGUMENT_CALLBACK_DISPATCH_OPS)
                .write(DEFAULT_NO_ARGUMENT_CALLBACK_DISPATCH_OPS);
        }
        drop(guard);
    }

    #[test]
    fn no_argument_callback_dispatch_matches_the_literal_veneer() {
        assert_eq!(NO_ARGUMENT_CALLBACK_DISPATCH_INSN, 0xe51f_f004);
        assert_eq!(NO_ARGUMENT_CALLBACK_DISPATCH_TARGET, 0x081b_0d08);
        assert_eq!(NO_ARGUMENT_CALLBACK_DISPATCH_TARGET & 3, 0);
    }
    static mut RETAIL_CONTINUATION_DISPATCH_COUNT: u32 = 0;

    unsafe extern "C" fn record_retail_continuation_dispatch() {
        RETAIL_CONTINUATION_DISPATCH_COUNT += 1;
    }

    #[test]
    fn retail_continuation_dispatch_calls_once_and_returns() {
        let guard = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            core::ptr::addr_of_mut!(RETAIL_CONTINUATION_DISPATCH_COUNT).write(0);
            core::ptr::addr_of_mut!(RETAIL_CONTINUATION_DISPATCH_OPS).write(
                RetailContinuationDispatchOps {
                    dispatch: record_retail_continuation_dispatch,
                },
            );
            retail_continuation_dispatch_veneer();
            assert_eq!(
                core::ptr::addr_of!(RETAIL_CONTINUATION_DISPATCH_COUNT).read(),
                1
            );
            core::ptr::addr_of_mut!(RETAIL_CONTINUATION_DISPATCH_OPS)
                .write(DEFAULT_RETAIL_CONTINUATION_DISPATCH_OPS);
        }
        drop(guard);
    }

    #[test]
    fn retail_continuation_dispatch_matches_literal_veneer() {
        assert_eq!(RETAIL_CONTINUATION_DISPATCH_VENEER, 0x0800_37a0);
        assert_eq!(RETAIL_CONTINUATION_DISPATCH_INSN, 0xe51f_f004);
        assert_eq!(RETAIL_CONTINUATION_DISPATCH_TARGET, 0x080e_a68c);
        assert_eq!(RETAIL_CONTINUATION_DISPATCH_TARGET & 3, 0);
    }

    static mut RETAIL_SELECTION_DISPATCH_ARGS: [usize; 4] = [0; 4];

    unsafe extern "C" fn record_retail_selection_dispatch(
        context: u32,
        records: *mut u32,
        selection: u32,
        index: u32,
    ) -> u32 {
        RETAIL_SELECTION_DISPATCH_ARGS = [context as usize, records as usize, selection as usize, index as usize];
        0xa5a5_5a5a
    }

    #[test]
    fn retail_selection_dispatch_forwards_all_register_arguments_and_result() {
        let guard = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            core::ptr::addr_of_mut!(RETAIL_SELECTION_DISPATCH_ARGS).write([0; 4]);
            core::ptr::addr_of_mut!(RETAIL_SELECTION_DISPATCH_OPS).write(
                RetailSelectionDispatchOps {
                    dispatch: record_retail_selection_dispatch,
                },
            );
            assert_eq!(
                retail_selection_dispatch_veneer(0x1020_3040, 0x1234usize as *mut u32, 2, 17),
                0xa5a5_5a5a
            );
            assert_eq!(
                core::ptr::addr_of!(RETAIL_SELECTION_DISPATCH_ARGS).read(),
                [0x1020_3040, 0x1234, 2, 17]
            );
            core::ptr::addr_of_mut!(RETAIL_SELECTION_DISPATCH_OPS)
                .write(DEFAULT_RETAIL_SELECTION_DISPATCH_OPS);
        }
        drop(guard);
    }

    #[test]
    fn retail_selection_dispatch_matches_literal_veneer() {
        assert_eq!(RETAIL_SELECTION_DISPATCH_VENEER, 0x0800_37d8);
        assert_eq!(RETAIL_SELECTION_DISPATCH_INSN, 0xe51f_f004);
        assert_eq!(RETAIL_SELECTION_DISPATCH_TARGET, 0x080e_d0f4);
        assert_eq!(RETAIL_SELECTION_DISPATCH_TARGET & 3, 0);
    }


    /// The stub at 0x08037f80 is the literal veneer `ldr pc, [pc, #-4]`
    /// with target word 0x2200427c (raw osos.dec bytes 04 f0 1f e5
    /// 7c 42 00 22); Ghidra's 4-byte extent drops the literal.
    #[test]
    fn task_delete_gateway_veneer_matches_literal_veneer() {
        assert_eq!(TASK_DELETE_GATEWAY_VENEER, 0x0803_7f80);
        assert_eq!(TASK_DELETE_GATEWAY_VENEER_INSN, 0xe51f_f004);
        assert_eq!(TASK_DELETE_GATEWAY_VENEER_TARGET, 0x2200_427c);
        assert_eq!(TASK_DELETE_GATEWAY_VENEER_TARGET & 3, 0);
        // The relocator mirror covers the target (below 0x2200aed8).
        assert!(TASK_DELETE_GATEWAY_VENEER_TARGET < ROM_BASE + 0xaed8);
    }

    /// The thunk table resolves 0x08037f80 to the identified IRAM target.
    #[test]
    fn task_delete_gateway_veneer_thunk_table_entry_resolves() {
        let entry =
            lookup_by_thunk(TASK_DELETE_GATEWAY_VENEER).expect("thunk entry for 0x08037f80");
        assert_eq!(entry.rom_target, TASK_DELETE_GATEWAY_VENEER_TARGET);
        assert_eq!(entry.name, Some("task_delete_gateway_veneer"));
        // The target is unique in the table: exactly one stub reaches it.
        assert_eq!(
            lookup_by_target(TASK_DELETE_GATEWAY_VENEER_TARGET)
                .expect("target entry for task delete")
                .thunk_addr,
            TASK_DELETE_GATEWAY_VENEER
        );
    }

    /// With no target installed the default seam returns 0 without
    /// panicking; on device the stub always reaches the IRAM body instead.
    #[test]
    fn task_delete_gateway_veneer_default_seam_returns_zero() {
        let guard = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            assert_eq!(task_delete_gateway_veneer(0, 0, 0, 0), 0);
        }
        drop(guard);
    }

    static mut TASK_DELETE_GATEWAY_VENEER_CALLS: u32 = 0;
    static mut TASK_DELETE_GATEWAY_VENEER_ARGS: (u32, u32, u32, u32) = (0, 0, 0, 0);

    unsafe extern "C" fn record_task_delete_gateway(
        task_id: u32,
        input_r1: u32,
        input_r2: u32,
        input_r3: u32,
    ) -> u64 {
        TASK_DELETE_GATEWAY_VENEER_CALLS += 1;
        TASK_DELETE_GATEWAY_VENEER_ARGS = (task_id, input_r1, input_r2, input_r3);
        0xfeed_cafe_1234_5678
    }

    /// The host port forwards all four argument registers unchanged and
    /// passes the mirrored body's two-word result through — the veneer's
    /// only observable contract.
    #[test]
    fn task_delete_gateway_veneer_forwards_all_arguments_and_result() {
        let guard = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            core::ptr::addr_of_mut!(TASK_DELETE_GATEWAY_VENEER_CALLS).write(0);
            core::ptr::addr_of_mut!(TASK_DELETE_GATEWAY_VENEER_OPS).write(
                TaskDeleteGatewayVeneerOps {
                    delete: record_task_delete_gateway,
                },
            );

            assert_eq!(task_delete_gateway_veneer(0, 0, 0, 0), 0xfeed_cafe_1234_5678);
            assert_eq!(
                core::ptr::addr_of!(TASK_DELETE_GATEWAY_VENEER_ARGS).read(),
                (0, 0, 0, 0)
            );
            assert_eq!(
                task_delete_gateway_veneer(0xdead_beef, 0xffff_ffff, 0x8000_0001, 7),
                0xfeed_cafe_1234_5678
            );
            assert_eq!(core::ptr::addr_of!(TASK_DELETE_GATEWAY_VENEER_CALLS).read(), 2);
            assert_eq!(
                core::ptr::addr_of!(TASK_DELETE_GATEWAY_VENEER_ARGS).read(),
                (0xdead_beef, 0xffff_ffff, 0x8000_0001, 7)
            );
            core::ptr::addr_of_mut!(TASK_DELETE_GATEWAY_VENEER_OPS)
                .write(DEFAULT_TASK_DELETE_GATEWAY_VENEER_OPS);
        }
        drop(guard);
    }

    /// The stub at 0x08037f88 is the literal veneer `ldr pc, [pc, #-4]`
    /// with target word 0x22005018 (raw osos.dec bytes 04 f0 1f e5
    /// 18 50 00 22); Ghidra's 4-byte extent drops the literal.
    #[test]
    fn ui_manager_acquire_matches_the_literal_veneer() {
        assert_eq!(UI_MANAGER_ACQUIRE_INSN, 0xe51f_f004);
        assert_eq!(UI_MANAGER_ACQUIRE_TARGET, 0x2200_5018);
        assert_eq!(UI_MANAGER_ACQUIRE_TARGET & 3, 0);
    }

    /// The thunk table resolves 0x08037f88 to the identified IRAM target.
    #[test]
    fn ui_manager_acquire_thunk_table_entry_resolves() {
        let entry = lookup_by_thunk(0x08037f88).expect("thunk entry for 0x08037f88");
        assert_eq!(entry.rom_target, UI_MANAGER_ACQUIRE_TARGET);
        assert_eq!(entry.name, Some("ui_manager_acquire"));
        // The target is unique in the table: exactly one stub reaches it.
        assert_eq!(lookup_by_target(UI_MANAGER_ACQUIRE_TARGET).unwrap().thunk_addr, 0x08037f88);
    }

    static mut UI_MANAGER_ACQUIRE_CALLS: u32 = 0;
    static mut UI_MANAGER_SENTINEL: u8 = 0;

    unsafe extern "C" fn record_ui_manager_acquire() -> *mut u8 {
        UI_MANAGER_ACQUIRE_CALLS += 1;
        core::ptr::addr_of_mut!(UI_MANAGER_SENTINEL)
    }

    /// The host port forwards to the injected IRAM target exactly once and
    /// passes its pointer result through unchanged — the veneer's only
    /// observable contract (no arguments in, manager pointer out).
    #[test]
    fn ui_manager_acquire_forwards_to_target_and_returns_its_pointer() {
        let guard = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            core::ptr::addr_of_mut!(UI_MANAGER_ACQUIRE_CALLS).write(0);
            core::ptr::addr_of_mut!(UI_MANAGER_ACQUIRE_OPS).write(UiManagerAcquireOps {
                acquire: record_ui_manager_acquire,
            });
            let manager = ui_manager_acquire();
            assert_eq!(core::ptr::addr_of!(UI_MANAGER_ACQUIRE_CALLS).read(), 1);
            assert_eq!(
                manager,
                core::ptr::addr_of!(UI_MANAGER_SENTINEL).cast_mut(),
            );
            core::ptr::addr_of_mut!(UI_MANAGER_ACQUIRE_OPS)
                .write(DEFAULT_UI_MANAGER_ACQUIRE_OPS);
        }
        drop(guard);
    }

    /// With no target installed the default seam yields NULL without
    /// panicking; on device the stub always reaches the IRAM body instead.
    #[test]
    fn ui_manager_acquire_default_seam_returns_null() {
        let guard = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            assert!(ui_manager_acquire().is_null());
        }
        drop(guard);
    }

    /// The stub at 0x08037f60 is the literal veneer `ldr pc, [pc, #-4]`
    /// with target word 0x2200200c (raw osos.dec words e51ff004 /
    /// 2200200c); Ghidra's 4-byte extent drops the literal.
    #[test]
    fn clock_config_dispatch_veneer_matches_the_literal_veneer() {
        assert_eq!(CLOCK_CONFIG_DISPATCH_INSN, 0xe51f_f004);
        assert_eq!(CLOCK_CONFIG_DISPATCH_TARGET, 0x2200_200c);
        assert_eq!(CLOCK_CONFIG_DISPATCH_TARGET & 3, 0);
    }

    /// The thunk table resolves 0x08037f60 to the identified IRAM target.
    #[test]
    fn clock_config_dispatch_veneer_thunk_table_entry_resolves() {
        let entry = lookup_by_thunk(0x08037f60).expect("thunk entry for 0x08037f60");
        assert_eq!(entry.rom_target, CLOCK_CONFIG_DISPATCH_TARGET);
        assert_eq!(entry.name, Some("clock_config_dispatch_veneer"));
        // The target is unique in the table: exactly one stub reaches it.
        assert_eq!(
            lookup_by_target(CLOCK_CONFIG_DISPATCH_TARGET).unwrap().thunk_addr,
            0x08037f60
        );
    }

    /// The stub at 0x08037f40 is the literal veneer `ldr pc, [pc, #-4]`
    /// with target word 0x220084dc (raw osos.dec words e51ff004 /
    /// 220084dc); Ghidra's 4-byte extent drops the literal.
    #[test]
    fn i2s_chunked_transfer_veneer_matches_the_literal_veneer() {
        assert_eq!(I2S_CHUNKED_TRANSFER_INSN, 0xe51f_f004);
        assert_eq!(I2S_CHUNKED_TRANSFER_TARGET, 0x2200_84dc);
        assert_eq!(I2S_CHUNKED_TRANSFER_TARGET & 3, 0);
    }

    /// The thunk table resolves 0x08037f40 to the identified IRAM target.
    #[test]
    fn i2s_chunked_transfer_veneer_thunk_table_entry_resolves() {
        let entry = lookup_by_thunk(0x08037f40).expect("thunk entry for 0x08037f40");
        assert_eq!(entry.rom_target, I2S_CHUNKED_TRANSFER_TARGET);
        assert_eq!(entry.name, Some("i2s_chunked_transfer_veneer"));
        // The target is unique in the table: exactly one stub reaches it.
        assert_eq!(
            lookup_by_target(I2S_CHUNKED_TRANSFER_TARGET).unwrap().thunk_addr,
            0x08037f40
        );
    }

    static mut I2S_CHUNKED_TRANSFER_CALLS: u32 = 0;
    static mut I2S_CHUNKED_TRANSFER_ARGS: (u32, u32, u32) = (0, 0, 0);

    unsafe extern "C" fn record_i2s_chunked_transfer(dst: u32, src: u32, len: u32) -> u32 {
        I2S_CHUNKED_TRANSFER_CALLS += 1;
        I2S_CHUNKED_TRANSFER_ARGS = (dst, src, len);
        0
    }

    /// The host port forwards the full dst/src/len triple to the
    /// injected IRAM target exactly once — the veneer's only observable
    /// contract (argument registers preserved, status word returned).
    #[test]
    fn i2s_chunked_transfer_veneer_forwards_arguments_unchanged() {
        let guard = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            core::ptr::addr_of_mut!(I2S_CHUNKED_TRANSFER_CALLS).write(0);
            core::ptr::addr_of_mut!(I2S_CHUNKED_TRANSFER_OPS).write(I2sChunkedTransferOps {
                transfer: record_i2s_chunked_transfer,
            });
            // A 4-aligned block and a byte-misaligned tail, the two unit
            // paths the target distinguishes.
            assert_eq!(i2s_chunked_transfer_veneer(0x1000, 0x2000, 0x800), 0);
            assert_eq!(i2s_chunked_transfer_veneer(0x1001, 0x2003, 0x7ff), 0);
            assert_eq!(core::ptr::addr_of!(I2S_CHUNKED_TRANSFER_CALLS).read(), 2);
            assert_eq!(
                core::ptr::addr_of!(I2S_CHUNKED_TRANSFER_ARGS).read(),
                (0x1001, 0x2003, 0x7ff)
            );
            // A zero-length transfer and the widest values pass through
            // untouched.
            assert_eq!(i2s_chunked_transfer_veneer(0xffff_ffff, 0, 0), 0);
            assert_eq!(
                core::ptr::addr_of!(I2S_CHUNKED_TRANSFER_ARGS).read(),
                (0xffff_ffff, 0, 0)
            );
            core::ptr::addr_of_mut!(I2S_CHUNKED_TRANSFER_OPS)
                .write(DEFAULT_I2S_CHUNKED_TRANSFER_OPS);
        }
        drop(guard);
    }

    /// The default host seam reproduces the target's status-0 return and
    /// performs no dispatch.
    #[test]
    fn i2s_chunked_transfer_veneer_default_seam_returns_zero() {
        let guard = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            assert_eq!(i2s_chunked_transfer_veneer(1, 2, 3), 0);
        }
        drop(guard);
    }

    static mut CLOCK_CONFIG_DISPATCH_CALLS: u32 = 0;
    static mut CLOCK_CONFIG_DISPATCH_ARGS: (u32, u32, u32) = (0, 0, 0);

    unsafe extern "C" fn record_clock_config_dispatch(selector: u32, mode: u32, value: u32) -> u32 {
        CLOCK_CONFIG_DISPATCH_CALLS += 1;
        CLOCK_CONFIG_DISPATCH_ARGS = (selector, mode, value);
        0
    }

    /// The host port forwards the full selector/mode/value triple to the
    /// injected IRAM target exactly once — the veneer's only observable
    /// contract (argument registers preserved, status word returned).
    #[test]
    fn clock_config_dispatch_veneer_forwards_arguments_unchanged() {
        let guard = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            core::ptr::addr_of_mut!(CLOCK_CONFIG_DISPATCH_CALLS).write(0);
            core::ptr::addr_of_mut!(CLOCK_CONFIG_DISPATCH_OPS).write(ClockConfigDispatchOps {
                dispatch: record_clock_config_dispatch,
            });
            // Both observed stock call shapes.
            assert_eq!(clock_config_dispatch_veneer(6, 0, 1), 0);
            assert_eq!(clock_config_dispatch_veneer(0xe, 3, 4), 0);
            assert_eq!(core::ptr::addr_of!(CLOCK_CONFIG_DISPATCH_CALLS).read(), 2);
            assert_eq!(
                core::ptr::addr_of!(CLOCK_CONFIG_DISPATCH_ARGS).read(),
                (0xe, 3, 4)
            );
            // Widest selector: boundary value passes through untouched.
            assert_eq!(clock_config_dispatch_veneer(0x10, 3, 0xffff_ffff), 0);
            assert_eq!(
                core::ptr::addr_of!(CLOCK_CONFIG_DISPATCH_ARGS).read(),
                (0x10, 3, 0xffff_ffff)
            );
            core::ptr::addr_of_mut!(CLOCK_CONFIG_DISPATCH_OPS)
                .write(DEFAULT_CLOCK_CONFIG_DISPATCH_OPS);
        }
        drop(guard);
    }

    /// With no target installed the default seam returns the target's
    /// status 0 without panicking; on device the stub always reaches the
    /// IRAM body instead.
    #[test]
    fn clock_config_dispatch_veneer_default_seam_returns_zero() {
        let guard = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            assert_eq!(clock_config_dispatch_veneer(0, 1, 1), 0);
        }
        drop(guard);
    }

    #[test]
    fn ui_manager_begin_pending_operation_matches_literal_veneer() {
        assert_eq!(UI_MANAGER_BEGIN_PENDING_OPERATION_VENEER, 0x0803_8200);
        assert_eq!(UI_MANAGER_BEGIN_PENDING_OPERATION_INSN, 0xe51f_f004);
        assert_eq!(UI_MANAGER_BEGIN_PENDING_OPERATION_TARGET, 0x2200_5114);
        assert_eq!(UI_MANAGER_BEGIN_PENDING_OPERATION_TARGET & 3, 0);
    }

    #[test]
    fn ui_manager_begin_pending_operation_thunk_table_entry_resolves() {
        let entry = lookup_by_thunk(UI_MANAGER_BEGIN_PENDING_OPERATION_VENEER)
            .expect("thunk entry for pending-operation start");
        assert_eq!(entry.rom_target, UI_MANAGER_BEGIN_PENDING_OPERATION_TARGET);
        assert_eq!(entry.name, Some("ui_manager_begin_pending_operation"));
        assert_eq!(
            lookup_by_target(UI_MANAGER_BEGIN_PENDING_OPERATION_TARGET)
                .expect("target entry for pending-operation start")
                .thunk_addr,
            UI_MANAGER_BEGIN_PENDING_OPERATION_VENEER
        );
    }

    static mut UI_MANAGER_BEGIN_PENDING_OPERATION_CALLS: u32 = 0;
    static mut UI_MANAGER_BEGIN_PENDING_OPERATION_ARGS: (usize, u32, u32) = (0, 0, 0);

    unsafe extern "C" fn record_ui_manager_begin_pending_operation(
        manager: *mut u8,
        mark_pending: u32,
        dispatch_active: u32,
    ) -> u32 {
        UI_MANAGER_BEGIN_PENDING_OPERATION_CALLS += 1;
        UI_MANAGER_BEGIN_PENDING_OPERATION_ARGS = (manager as usize, mark_pending, dispatch_active);
        0x4d41_4e41
    }

    #[test]
    fn ui_manager_begin_pending_operation_forwards_all_arguments_and_result() {
        let guard = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let mut manager = 0u8;
        unsafe {
            core::ptr::addr_of_mut!(UI_MANAGER_BEGIN_PENDING_OPERATION_CALLS).write(0);
            core::ptr::addr_of_mut!(UI_MANAGER_BEGIN_PENDING_OPERATION_OPS).write(
                UiManagerBeginPendingOperationOps {
                    begin: record_ui_manager_begin_pending_operation,
                },
            );

            assert_eq!(
                ui_manager_begin_pending_operation(core::ptr::null_mut(), 0, 0),
                0x4d41_4e41
            );
            assert_eq!(
                core::ptr::addr_of!(UI_MANAGER_BEGIN_PENDING_OPERATION_ARGS).read(),
                (0, 0, 0)
            );
            assert_eq!(
                ui_manager_begin_pending_operation(
                    core::ptr::addr_of_mut!(manager),
                    0xffff_ffff,
                    0x8000_0001,
                ),
                0x4d41_4e41
            );
            assert_eq!(
                core::ptr::addr_of!(UI_MANAGER_BEGIN_PENDING_OPERATION_CALLS).read(),
                2
            );
            assert_eq!(
                core::ptr::addr_of!(UI_MANAGER_BEGIN_PENDING_OPERATION_ARGS).read(),
                (core::ptr::addr_of!(manager) as usize, 0xffff_ffff, 0x8000_0001)
            );
            core::ptr::addr_of_mut!(UI_MANAGER_BEGIN_PENDING_OPERATION_OPS)
                .write(DEFAULT_UI_MANAGER_BEGIN_PENDING_OPERATION_OPS);
        }
        drop(guard);
    }

    #[test]
    fn ui_manager_dispatch_callback_context_matches_literal_veneer() {
        assert_eq!(UI_MANAGER_DISPATCH_CALLBACK_CONTEXT_VENEER, 0x0803_8208);
        assert_eq!(UI_MANAGER_DISPATCH_CALLBACK_CONTEXT_INSN, 0xe51f_f004);
        assert_eq!(UI_MANAGER_DISPATCH_CALLBACK_CONTEXT_TARGET, 0x2200_76cc);
        assert_eq!(UI_MANAGER_DISPATCH_CALLBACK_CONTEXT_TARGET & 3, 0);
    }

    #[test]
    fn ui_manager_dispatch_callback_context_thunk_table_entry_resolves() {
        let entry = lookup_by_thunk(UI_MANAGER_DISPATCH_CALLBACK_CONTEXT_VENEER)
            .expect("thunk entry for callback-context dispatch");
        assert_eq!(
            entry.rom_target,
            UI_MANAGER_DISPATCH_CALLBACK_CONTEXT_TARGET
        );
        assert_eq!(entry.name, Some("ui_manager_dispatch_callback_context"));
        assert_eq!(
            lookup_by_target(UI_MANAGER_DISPATCH_CALLBACK_CONTEXT_TARGET)
                .expect("target entry for callback-context dispatch")
                .thunk_addr,
            UI_MANAGER_DISPATCH_CALLBACK_CONTEXT_VENEER
        );
    }

    static mut UI_MANAGER_DISPATCH_CALLBACK_CONTEXT_CALLS: u32 = 0;
    static mut UI_MANAGER_DISPATCH_CALLBACK_CONTEXT_ARGS: (usize, u32) = (0, 0);

    unsafe extern "C" fn record_ui_manager_dispatch_callback_context(
        manager: *mut u8,
        flag: u32,
    ) {
        UI_MANAGER_DISPATCH_CALLBACK_CONTEXT_CALLS += 1;
        UI_MANAGER_DISPATCH_CALLBACK_CONTEXT_ARGS = (manager as usize, flag);
    }

    #[test]
    fn ui_manager_dispatch_callback_context_forwards_observed_and_edge_arguments() {
        let guard = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let mut manager = [0u8; 0x24];
        unsafe {
            core::ptr::addr_of_mut!(UI_MANAGER_DISPATCH_CALLBACK_CONTEXT_CALLS).write(0);
            core::ptr::addr_of_mut!(UI_MANAGER_DISPATCH_CALLBACK_CONTEXT_OPS).write(
                UiManagerDispatchCallbackContextOps {
                    dispatch: record_ui_manager_dispatch_callback_context,
                },
            );
            ui_manager_dispatch_callback_context(core::ptr::addr_of_mut!(manager).cast(), 1);
            assert_eq!(
                core::ptr::addr_of!(UI_MANAGER_DISPATCH_CALLBACK_CONTEXT_ARGS).read(),
                (core::ptr::addr_of!(manager) as usize, 1)
            );
            ui_manager_dispatch_callback_context(core::ptr::null_mut(), 0xffff_ffff);
            assert_eq!(
                core::ptr::addr_of!(UI_MANAGER_DISPATCH_CALLBACK_CONTEXT_CALLS).read(),
                2
            );
            assert_eq!(
                core::ptr::addr_of!(UI_MANAGER_DISPATCH_CALLBACK_CONTEXT_ARGS).read(),
                (0, 0xffff_ffff)
            );
            core::ptr::addr_of_mut!(UI_MANAGER_DISPATCH_CALLBACK_CONTEXT_OPS)
                .write(DEFAULT_UI_MANAGER_DISPATCH_CALLBACK_CONTEXT_OPS);
        }
        drop(guard);
    }

    #[test]
    fn ui_manager_current_context_reads_two_target_width_context_links() {
        let Some(slab) = crate::testing::try_map_u32_slab(
            crate::testing::hints::UI_MANAGER_CURRENT_CONTEXT,
            0x100,
        ) else {
            return;
        };
        unsafe {
            slab.write_bytes(0, 0x100);
            let state = slab.add(0x40);
            let context = slab.add(0x80);
            slab.add(0x1c).cast::<u32>().write(state as usize as u32);
            state.add(0x1c).cast::<u32>().write(context as usize as u32);
            assert_eq!(ui_manager_current_context(slab), context);
        }
    }

    static mut STREAM_BUFFER_FLUSH_ENTER_CALLS: u32 = 0;
    static mut STREAM_BUFFER_FLUSH_ENTER_ARGS: (usize, usize) = (0, 0);

    unsafe extern "C" fn recording_flush_callback(_stream_buffer: *mut u8) -> u32 {
        0x5eed_0001
    }

    unsafe extern "C" fn record_stream_buffer_flush_enter(
        stream_buffer: *mut u8,
        flush_callback: StreamBufferFlushCallbackFn,
    ) -> u32 {
        STREAM_BUFFER_FLUSH_ENTER_CALLS += 1;
        STREAM_BUFFER_FLUSH_ENTER_ARGS =
            (stream_buffer as usize, flush_callback as usize);
        // The real continuation invokes the callback with the object.
        flush_callback(stream_buffer)
    }

    #[test]
    fn stream_buffer_flush_enter_forwards_object_callback_and_result() {
        let guard = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let mut stream_buffer = 0u8;
        unsafe {
            core::ptr::addr_of_mut!(STREAM_BUFFER_FLUSH_ENTER_CALLS).write(0);
            core::ptr::addr_of_mut!(STREAM_BUFFER_FLUSH_ENTER_OPS).write(
                StreamBufferFlushEnterOps {
                    enter: record_stream_buffer_flush_enter,
                },
            );

            assert_eq!(
                stream_buffer_flush_enter(core::ptr::null_mut(), recording_flush_callback),
                0x5eed_0001
            );
            assert_eq!(
                core::ptr::addr_of!(STREAM_BUFFER_FLUSH_ENTER_ARGS).read(),
                (0, recording_flush_callback as usize)
            );
            assert_eq!(
                stream_buffer_flush_enter(
                    core::ptr::addr_of_mut!(stream_buffer),
                    recording_flush_callback,
                ),
                0x5eed_0001
            );
            assert_eq!(
                core::ptr::addr_of!(STREAM_BUFFER_FLUSH_ENTER_CALLS).read(),
                2
            );
            assert_eq!(
                core::ptr::addr_of!(STREAM_BUFFER_FLUSH_ENTER_ARGS).read(),
                (
                    core::ptr::addr_of!(stream_buffer) as usize,
                    recording_flush_callback as usize
                )
            );
            core::ptr::addr_of_mut!(STREAM_BUFFER_FLUSH_ENTER_OPS)
                .write(DEFAULT_STREAM_BUFFER_FLUSH_ENTER_OPS);
        }
        drop(guard);
    }

    #[test]
    fn stream_buffer_flush_enter_constants_match_raw_bytes() {
        assert_eq!(STREAM_BUFFER_FLUSH_ENTER_VENEER, 0x0800_3848);
        assert_eq!(STREAM_BUFFER_FLUSH_ENTER_INSN, 0xe51f_f004);
        assert_eq!(STREAM_BUFFER_FLUSH_ENTER_TARGET, 0x0820_1460);
    }

    /// The stub at 0x08038190 is the literal veneer `ldr pc, [pc, #-4]`
    /// with target word 0x220073b0 (raw osos.dec bytes 04 f0 1f e5
    /// b0 73 00 22); Ghidra's 4-byte extent drops the literal.
    #[test]
    fn iram_stream_buffer_reinitialize_veneer_matches_literal_veneer() {
        assert_eq!(IRAM_STREAM_BUFFER_REINITIALIZE_VENEER, 0x0803_8190);
        assert_eq!(IRAM_STREAM_BUFFER_REINITIALIZE_INSN, 0xe51f_f004);
        assert_eq!(IRAM_STREAM_BUFFER_REINITIALIZE_TARGET, 0x2200_73b0);
        assert_eq!(IRAM_STREAM_BUFFER_REINITIALIZE_TARGET & 3, 0);
        // The relocator mirror covers the target (below 0x2200aed8).
        assert!(IRAM_STREAM_BUFFER_REINITIALIZE_TARGET < ROM_BASE + 0xaed8);
    }

    #[test]
    fn iram_stream_buffer_reinitialize_veneer_thunk_table_entry_resolves() {
        let entry = lookup_by_thunk(IRAM_STREAM_BUFFER_REINITIALIZE_VENEER)
            .expect("thunk entry for stream-buffer reinitialize");
        assert_eq!(entry.rom_target, IRAM_STREAM_BUFFER_REINITIALIZE_TARGET);
        assert_eq!(entry.name, Some("iram_stream_buffer_reinitialize_veneer"));
        assert_eq!(
            lookup_by_target(IRAM_STREAM_BUFFER_REINITIALIZE_TARGET)
                .expect("target entry for stream-buffer reinitialize")
                .thunk_addr,
            IRAM_STREAM_BUFFER_REINITIALIZE_VENEER
        );
    }

    /// With no target installed the default seam returns 0 without
    /// panicking; on device the stub always reaches the IRAM body instead.
    #[test]
    fn iram_stream_buffer_reinitialize_veneer_default_seam_returns_zero() {
        let guard = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            assert_eq!(
                iram_stream_buffer_reinitialize_veneer(core::ptr::null_mut(), 0, 0),
                0
            );
        }
        drop(guard);
    }

    static mut IRAM_STREAM_BUFFER_REINITIALIZE_CALLS: u32 = 0;
    static mut IRAM_STREAM_BUFFER_REINITIALIZE_ARGS: (usize, u32, u32) = (0, 0, 0);

    unsafe extern "C" fn record_iram_stream_buffer_reinitialize(
        stream_buffer: *mut u8,
        zero_page_context: u32,
        page_context: u32,
    ) -> u32 {
        IRAM_STREAM_BUFFER_REINITIALIZE_CALLS += 1;
        IRAM_STREAM_BUFFER_REINITIALIZE_ARGS =
            (stream_buffer as usize, zero_page_context, page_context);
        0x5354_5242
    }

    #[test]
    fn iram_stream_buffer_reinitialize_veneer_forwards_all_arguments_and_result() {
        let guard = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let mut stream_buffer = 0u8;
        unsafe {
            core::ptr::addr_of_mut!(IRAM_STREAM_BUFFER_REINITIALIZE_CALLS).write(0);
            core::ptr::addr_of_mut!(IRAM_STREAM_BUFFER_REINITIALIZE_OPS).write(
                IramStreamBufferReinitializeOps {
                    reinitialize: record_iram_stream_buffer_reinitialize,
                },
            );

            assert_eq!(
                iram_stream_buffer_reinitialize_veneer(core::ptr::null_mut(), 0, 0),
                0x5354_5242
            );
            assert_eq!(
                core::ptr::addr_of!(IRAM_STREAM_BUFFER_REINITIALIZE_ARGS).read(),
                (0, 0, 0)
            );
            assert_eq!(
                iram_stream_buffer_reinitialize_veneer(
                    core::ptr::addr_of_mut!(stream_buffer),
                    0xffff_ffff,
                    0x8000_0001,
                ),
                0x5354_5242
            );
            assert_eq!(
                core::ptr::addr_of!(IRAM_STREAM_BUFFER_REINITIALIZE_CALLS).read(),
                2
            );
            assert_eq!(
                core::ptr::addr_of!(IRAM_STREAM_BUFFER_REINITIALIZE_ARGS).read(),
                (core::ptr::addr_of!(stream_buffer) as usize, 0xffff_ffff, 0x8000_0001)
            );
            core::ptr::addr_of_mut!(IRAM_STREAM_BUFFER_REINITIALIZE_OPS)
                .write(DEFAULT_IRAM_STREAM_BUFFER_REINITIALIZE_OPS);
        }
        drop(guard);
    }

    /// The stub at 0x08037f58 is the literal veneer `ldr pc, [pc, #-4]`
    /// with target word 0x220060e0 (raw osos.dec bytes 04 f0 1f e5
    /// e0 60 00 22); Ghidra's 4-byte extent drops the literal.
    #[test]
    fn lazy_singleton_106dc_acquire_matches_the_literal_veneer() {
        assert_eq!(LAZY_SINGLETON_106DC_ACQUIRE_INSN, 0xe51f_f004);
        assert_eq!(LAZY_SINGLETON_106DC_ACQUIRE_TARGET, 0x2200_60e0);
        assert_eq!(LAZY_SINGLETON_106DC_ACQUIRE_TARGET & 3, 0);
    }

    /// The thunk table resolves 0x08037f58 to the identified IRAM target.
    #[test]
    fn lazy_singleton_106dc_acquire_thunk_table_entry_resolves() {
        let entry = lookup_by_thunk(0x08037f58).expect("thunk entry for 0x08037f58");
        assert_eq!(entry.rom_target, LAZY_SINGLETON_106DC_ACQUIRE_TARGET);
        assert_eq!(entry.name, Some("lazy_singleton_106dc_acquire"));
        // The target is unique in the table: exactly one stub reaches it.
        assert_eq!(
            lookup_by_target(LAZY_SINGLETON_106DC_ACQUIRE_TARGET)
                .unwrap()
                .thunk_addr,
            0x08037f58
        );
    }

    static mut LAZY_SINGLETON_106DC_ACQUIRE_CALLS: u32 = 0;
    static mut LAZY_SINGLETON_106DC_SENTINEL: u8 = 0;

    unsafe extern "C" fn record_lazy_singleton_106dc_acquire() -> *mut u8 {
        LAZY_SINGLETON_106DC_ACQUIRE_CALLS += 1;
        core::ptr::addr_of_mut!(LAZY_SINGLETON_106DC_SENTINEL)
    }

    /// The host port forwards to the injected IRAM target exactly once and
    /// passes its pointer result through unchanged — the veneer's only
    /// observable contract (no arguments in, object pointer out).
    #[test]
    fn lazy_singleton_106dc_acquire_forwards_to_target_and_returns_its_pointer() {
        let guard = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            core::ptr::addr_of_mut!(LAZY_SINGLETON_106DC_ACQUIRE_CALLS).write(0);
            core::ptr::addr_of_mut!(LAZY_SINGLETON_106DC_ACQUIRE_OPS).write(
                LazySingleton106dcAcquireOps {
                    acquire: record_lazy_singleton_106dc_acquire,
                },
            );
            let object = lazy_singleton_106dc_acquire();
            assert_eq!(core::ptr::addr_of!(LAZY_SINGLETON_106DC_ACQUIRE_CALLS).read(), 1);
            assert_eq!(
                object,
                core::ptr::addr_of!(LAZY_SINGLETON_106DC_SENTINEL).cast_mut(),
            );
            core::ptr::addr_of_mut!(LAZY_SINGLETON_106DC_ACQUIRE_OPS)
                .write(DEFAULT_LAZY_SINGLETON_106DC_ACQUIRE_OPS);
        }
        drop(guard);
    }

    /// With no target installed the default seam yields NULL without
    /// panicking; on device the stub always reaches the IRAM body instead.
    #[test]
    fn lazy_singleton_106dc_acquire_default_seam_returns_null() {
        let guard = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            assert!(lazy_singleton_106dc_acquire().is_null());
        }
        drop(guard);
    }

    /// The stub at 0x08038060 is the literal veneer `ldr pc, [pc, #-4]`
    /// with target word 0x22007470 (raw osos.dec bytes 04 f0 1f e5
    /// 70 74 00 22); Ghidra's 4-byte extent drops the literal.
    #[test]
    fn event_handler_source_matches_the_literal_veneer() {
        assert_eq!(EVENT_HANDLER_SOURCE_INSN, 0xe51f_f004);
        assert_eq!(EVENT_HANDLER_SOURCE_TARGET, 0x2200_7470);
        assert_eq!(EVENT_HANDLER_SOURCE_TARGET & 3, 0);
    }

    /// The thunk table resolves 0x08038060 to the verified IRAM target.
    #[test]
    fn event_handler_source_thunk_table_entry_resolves() {
        let entry = lookup_by_thunk(0x08038060).expect("thunk entry for 0x08038060");
        assert_eq!(entry.rom_target, EVENT_HANDLER_SOURCE_TARGET);
        assert_eq!(entry.name, Some("iram_event_handler_source_veneer"));
        assert_eq!(
            lookup_by_target(EVENT_HANDLER_SOURCE_TARGET).unwrap().thunk_addr,
            0x08038060
        );
    }



    /// The veneer at 0x08003910 is `ldr pc, [pc, #-4]` with target word
    /// 0x0818c740 (raw osos.dec bytes 04 f0 1f e5 40 c7 18 08); Ghidra's
    /// 4-byte extent drops the literal, and the next veneer begins at
    /// 0x08003918.
    #[test]
    fn callback_target_getter_matches_the_literal_veneer() {
        assert_eq!(CALLBACK_TARGET_GETTER_INSN, 0xe51f_f004);
        assert_eq!(CALLBACK_TARGET_GETTER_TARGET, 0x0818_c740);
        assert_eq!(CALLBACK_TARGET_GETTER_TARGET & 3, 0);
        assert_eq!(CALLBACK_TARGET_GETTER_VENEER, 0x0800_3910);
        // The veneer lives inside the 0xaed8-byte block the relocator mirrors
        // to IRAM, so it is equally reachable as 0x22003910.
        assert!(CALLBACK_TARGET_GETTER_VENEER - 0x0800_0000 < 0xaed8);
    }

    /// Each call site dereferences the returned pointer as a vtable and
    /// dispatches one of nine recovered slots, ascending and word-aligned up
    /// to +0x30.
    #[test]
    fn callback_target_dispatch_slots_are_the_recovered_set() {
        assert_eq!(
            CALLBACK_TARGET_DISPATCH_SLOTS,
            [0x00, 0x04, 0x08, 0x0c, 0x10, 0x14, 0x1c, 0x20, 0x30]
        );
        for pair in CALLBACK_TARGET_DISPATCH_SLOTS.windows(2) {
            assert!(pair[0] < pair[1]);
        }
        assert!(CALLBACK_TARGET_DISPATCH_SLOTS.iter().all(|slot| slot % 4 == 0));
    }

    static mut CALLBACK_TARGET_GETTER_CALLS: u32 = 0;
    static mut CALLBACK_TARGET_SENTINEL: u8 = 0;

    unsafe extern "C" fn record_callback_target_getter() -> *mut u8 {
        CALLBACK_TARGET_GETTER_CALLS += 1;
        core::ptr::addr_of_mut!(CALLBACK_TARGET_SENTINEL)
    }

    /// The host port forwards to the injected retailOS target exactly once
    /// and passes its pointer result through unchanged — the veneer's only
    /// observable contract (no arguments in, callback target out).
    #[test]
    fn callback_target_getter_forwards_to_target_and_returns_its_pointer() {
        let guard = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            core::ptr::addr_of_mut!(CALLBACK_TARGET_GETTER_CALLS).write(0);
            core::ptr::addr_of_mut!(CALLBACK_TARGET_GETTER_OPS).write(CallbackTargetGetterOps {
                get: record_callback_target_getter,
            });
            let target = callback_target_getter();
            assert_eq!(core::ptr::addr_of!(CALLBACK_TARGET_GETTER_CALLS).read(), 1);
            assert_eq!(
                target,
                core::ptr::addr_of!(CALLBACK_TARGET_SENTINEL).cast_mut(),
            );
            core::ptr::addr_of_mut!(CALLBACK_TARGET_GETTER_OPS)
                .write(DEFAULT_CALLBACK_TARGET_GETTER_OPS);
        }
        drop(guard);
    }

    /// The veneer caches nothing: retailOS re-reads the mode byte on every
    /// entry, which is why three consecutive call sites at 0x080076f0,
    /// 0x08007700 and 0x08007730 each issue their own `bl`.
    #[test]
    fn callback_target_getter_reaches_the_target_on_every_call() {
        let guard = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            core::ptr::addr_of_mut!(CALLBACK_TARGET_GETTER_CALLS).write(0);
            core::ptr::addr_of_mut!(CALLBACK_TARGET_GETTER_OPS).write(CallbackTargetGetterOps {
                get: record_callback_target_getter,
            });
            let first = callback_target_getter();
            let second = callback_target_getter();
            let third = callback_target_getter();
            assert_eq!(core::ptr::addr_of!(CALLBACK_TARGET_GETTER_CALLS).read(), 3);
            assert_eq!(first, second);
            assert_eq!(second, third);
            core::ptr::addr_of_mut!(CALLBACK_TARGET_GETTER_OPS)
                .write(DEFAULT_CALLBACK_TARGET_GETTER_OPS);
        }
        drop(guard);
    }
    #[test]
    fn audio_stream_configure_matches_the_literal_veneer() {
        assert_eq!(AUDIO_STREAM_CONFIGURE_VENEER, 0x0800_3928);
        assert_eq!(AUDIO_STREAM_CONFIGURE_INSN, 0xe51f_f004);
        assert_eq!(AUDIO_STREAM_CONFIGURE_TARGET, 0x0818_c1c8);
        assert_eq!(AUDIO_STREAM_CONFIGURE_TARGET & 3, 0);
    }

    static mut AUDIO_STREAM_CONFIGURE_CALLS: u32 = 0;
    static mut AUDIO_STREAM_CONFIGURE_ARGS: (*mut u8, u32, u32, u32) =
        (core::ptr::null_mut(), 0, 0, 0);

    unsafe extern "C" fn record_audio_stream_configuration(
        stream: *mut u8,
        sample_rate: u32,
        sample_bit_depth: u32,
        channel_count: u32,
    ) -> u32 {
        AUDIO_STREAM_CONFIGURE_CALLS += 1;
        AUDIO_STREAM_CONFIGURE_ARGS = (stream, sample_rate, sample_bit_depth, channel_count);
        1
    }

    /// The host seam must preserve all four ABI arguments and the target's
    /// status result; valid and invalid stream configurations are target
    /// policy, not veneer policy.
    #[test]
    fn audio_stream_configure_forwards_unmodified_arguments_and_status() {
        let guard = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            core::ptr::addr_of_mut!(AUDIO_STREAM_CONFIGURE_CALLS).write(0);
            core::ptr::addr_of_mut!(AUDIO_STREAM_CONFIGURE_OPS).write(AudioStreamConfigureOps {
                configure: record_audio_stream_configuration,
            });
            let stream = 0x1234_5000usize as *mut u8;
            assert_eq!(audio_stream_configure(stream, 0, u32::MAX, 0), 1);
            assert_eq!(core::ptr::addr_of!(AUDIO_STREAM_CONFIGURE_CALLS).read(), 1);
            assert_eq!(
                core::ptr::addr_of!(AUDIO_STREAM_CONFIGURE_ARGS).read(),
                (stream, 0, u32::MAX, 0)
            );
            core::ptr::addr_of_mut!(AUDIO_STREAM_CONFIGURE_OPS)
                .write(DEFAULT_AUDIO_STREAM_CONFIGURE_OPS);
        }
        drop(guard);
    }

    /// With no target installed the host seam yields NULL; on device the
    /// veneer always tail-dispatches into the mapped retailOS accessor, whose
    /// two candidate results are statically allocated and never NULL — hence
    /// the unguarded `ldr r1, [r0]` at all 21 call sites.
    #[test]
    fn callback_target_getter_default_seam_returns_null() {
        let guard = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            assert!(callback_target_getter().is_null());
        }
        drop(guard);
    }

    static mut R7_CONTEXT_TABLE_DISPATCH_CALLS: u32 = 0;
    static mut R7_CONTEXT_TABLE_DISPATCH_SENTINEL: u8 = 0;

    unsafe extern "C" fn record_r7_context_table_dispatch() -> *mut u8 {
        R7_CONTEXT_TABLE_DISPATCH_CALLS += 1;
        core::ptr::addr_of_mut!(R7_CONTEXT_TABLE_DISPATCH_SENTINEL)
    }

    #[test]
    fn r7_context_table_dispatch_veneer_matches_literal_and_forwards_result() {
        assert_eq!(R7_CONTEXT_TABLE_DISPATCH_VENEER_INSN, 0xe51f_f004);
        assert_eq!(R7_CONTEXT_TABLE_DISPATCH_VENEER_TARGET, 0x081f_f130);
        assert_eq!(R7_CONTEXT_TABLE_DISPATCH_VENEER_TARGET & 3, 0);

        let guard = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            core::ptr::addr_of_mut!(R7_CONTEXT_TABLE_DISPATCH_CALLS).write(0);
            core::ptr::addr_of_mut!(R7_CONTEXT_TABLE_DISPATCH_OPS).write(
                R7ContextTableDispatchOps {
                    dispatch: record_r7_context_table_dispatch,
                },
            );
            let result = r7_context_table_dispatch_veneer();
            assert_eq!(
                core::ptr::addr_of!(R7_CONTEXT_TABLE_DISPATCH_CALLS).read(),
                1
            );
            assert_eq!(
                result,
                core::ptr::addr_of!(R7_CONTEXT_TABLE_DISPATCH_SENTINEL).cast_mut(),
            );
            core::ptr::addr_of_mut!(R7_CONTEXT_TABLE_DISPATCH_OPS)
                .write(DEFAULT_R7_CONTEXT_TABLE_DISPATCH_OPS);
        }
        drop(guard);
    }

    /// The veneer at 0x08003950 is `ldr pc, [pc, #-4]` with target word
    /// 0x0811851c (raw osos.dec bytes 04 f0 1f e5 1c 85 11 08); Ghidra's
    /// 4-byte extent drops the literal, and the next veneer begins at
    /// 0x08003958. The literal is a post-relocation retailOS address whose
    /// bytes live at osos.dec file address 0x081233f4.
    #[test]
    fn child_enabled_veneer_matches_the_literal_veneer() {
        assert_eq!(EVENT_HANDLER_SOURCE_CHILD_ENABLED_VENEER, 0x0800_3950);
        assert_eq!(EVENT_HANDLER_SOURCE_CHILD_ENABLED_VENEER_INSN, 0xe51f_f004);
        assert_eq!(EVENT_HANDLER_SOURCE_CHILD_ENABLED_VENEER_TARGET, 0x0811_851c);
        assert_eq!(EVENT_HANDLER_SOURCE_CHILD_ENABLED_VENEER_TARGET & 3, 0);
        // Post-relocation retailOS address A lives at osos.dec file offset
        // A - 0x08000000 + 0xaed8; the target leaf's bytes sit at 0x081233f4.
        assert_eq!(
            EVENT_HANDLER_SOURCE_CHILD_ENABLED_VENEER_TARGET - 0x0800_0000 + 0xaed8,
            0x0012_33f4
        );
        // The veneer lives inside the 0xaed8-byte block the relocator mirrors
        // to IRAM, so it is equally reachable as 0x22003950.
        assert!(EVENT_HANDLER_SOURCE_CHILD_ENABLED_VENEER - 0x0800_0000 < 0xaed8);
        assert_eq!(EVENT_HANDLER_SOURCE_CHILD_FLAG_OFFSET, 0x68);
    }

    /// The decoded target leaf returns `u16(child + 0x68) != 0` as 0/1 and
    /// reads nothing else: neighbors may be arbitrary without changing the
    /// result.
    #[test]
    fn child_enabled_reads_only_the_flag_halfword() {
        let mut child = [0xffff_u16; 0x40];
        child[EVENT_HANDLER_SOURCE_CHILD_FLAG_OFFSET / 2] = 0;
        unsafe {
            assert_eq!(event_handler_source_child_enabled(child.as_ptr() as *const u8), 0);
        }

        let mut child = [0x0000_u16; 0x40];
        child[EVENT_HANDLER_SOURCE_CHILD_FLAG_OFFSET / 2] = 1;
        unsafe {
            assert_eq!(event_handler_source_child_enabled(child.as_ptr() as *const u8), 1);
        }
    }

    /// Every nonzero halfword normalizes to exactly 1, including high-byte-
    /// only and sign-bit values; zero alone yields 0.
    #[test]
    fn child_enabled_normalizes_any_nonzero_halfword_to_one() {
        let mut child = [0u16; 0x40];
        for (flag, expected) in [
            (0x0000_u16, 0u32),
            (0x0001, 1),
            (0x7fff, 1),
            (0x8000, 1),
            (0xff00, 1),
            (0xffff, 1),
        ] {
            child[EVENT_HANDLER_SOURCE_CHILD_FLAG_OFFSET / 2] = flag;
            unsafe {
                assert_eq!(
                    event_handler_source_child_enabled(child.as_ptr() as *const u8),
                    expected,
                    "flag {flag:#06x}"
                );
            }
        }
    }

    /// The leaf is read-only: the child object is byte-identical after the
    /// call.
    #[test]
    fn child_enabled_leaves_the_child_untouched() {
        let mut child = [0u16; 0x40];
        for (index, word) in child.iter_mut().enumerate() {
            *word = (index as u16) * 0x0101 | 0x5a;
        }
        let before = child;
        unsafe {
            let _ = event_handler_source_child_enabled(child.as_ptr() as *const u8);
        }
        assert_eq!(child, before);
    }

    #[test]
    fn child_rank_veneer_matches_literal_and_reads_the_rank_halfword() {
        assert_eq!(EVENT_HANDLER_SOURCE_CHILD_RANK_VENEER, 0x0800_3958);
        assert_eq!(EVENT_HANDLER_SOURCE_CHILD_RANK_VENEER_INSN, 0xe51f_f004);
        assert_eq!(EVENT_HANDLER_SOURCE_CHILD_RANK_VENEER_TARGET, 0x0811_78c8);
        assert_eq!(EVENT_HANDLER_SOURCE_CHILD_RANK_VENEER_TARGET & 3, 0);
        assert_eq!(
            EVENT_HANDLER_SOURCE_CHILD_RANK_VENEER_TARGET - 0x0800_0000 + 0xaed8,
            0x0012_27a0
        );

        let mut child = [0xffff_u16; 0x400];
        for rank in [0x0000_u16, 0x0001, 0x7fff, 0x8000, 0xffff] {
            child[EVENT_HANDLER_SOURCE_CHILD_RANK_OFFSET / 2] = rank;
            unsafe {
                assert_eq!(
                    event_handler_source_child_rank(child.as_ptr().cast()),
                    u32::from(rank),
                    "rank {rank:#06x}"
                );
            }
        }
    }

    #[test]
    fn context_value_commit_veneer_matches_literal_and_commits_only_offset_four() {
        assert_eq!(CONTEXT_VALUE_COMMIT_VENEER, 0x080037d0);
        assert_eq!(CONTEXT_VALUE_COMMIT_VENEER_INSN, 0xe51f_f004);
        assert_eq!(CONTEXT_VALUE_COMMIT_VENEER_TARGET, 0x080ecfa4);
        assert_eq!(CONTEXT_VALUE_COMMIT_VENEER_TARGET & 3, 0);

        let mut context = [0x1122_3344, 0, 0x5566_7788];
        unsafe {
            context_value_commit_veneer(context.as_mut_ptr(), u32::MAX);
        }
        assert_eq!(context, [0x1122_3344, u32::MAX, 0x5566_7788]);

        unsafe {
            context_value_commit_veneer(context.as_mut_ptr(), 0);
        }
        assert_eq!(context, [0x1122_3344, 0, 0x5566_7788]);
    }
}
