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
//!
//! Caveats / deviations:
//!
//! - `size_to_class` (0x22003eb0) is UNVERIFIED, as already documented in
//!   heap/stats.rs: the ROM bytes are unavailable and the osos mirror @
//!   0x08003eb0 is a 3-instruction pointer chase through ROM data
//!   (0x2200acf4), not an arithmetic size->class mapping. The name comes
//!   from the heap telemetry call sites.
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
    RomThunk { thunk_addr: 0x08037e10, rom_target: 0x220042b4, name: None },
    RomThunk { thunk_addr: 0x08037e18, rom_target: 0x2200418c, name: None },
    RomThunk { thunk_addr: 0x08037e20, rom_target: 0x22001edc, name: None },
    RomThunk { thunk_addr: 0x08037e28, rom_target: 0x22003b6c, name: None },
    RomThunk { thunk_addr: 0x08037e30, rom_target: 0x22003c98, name: None },
    RomThunk { thunk_addr: 0x08037e38, rom_target: 0x22003d00, name: None },
    RomThunk { thunk_addr: 0x08037e40, rom_target: 0x22003dc8, name: Some("kernel_op_dispatch") },
    RomThunk { thunk_addr: 0x08037e48, rom_target: 0x22003ea0, name: Some("task_lock") },
    RomThunk { thunk_addr: 0x08037e50, rom_target: 0x2200408c, name: Some("task_unlock") },
    RomThunk { thunk_addr: 0x08037e58, rom_target: 0x22003ec4, name: None },
    RomThunk { thunk_addr: 0x08037e60, rom_target: 0x22003eb0, name: Some("size_to_class") },
    RomThunk { thunk_addr: 0x08037e68, rom_target: 0x22003be8, name: None },
    RomThunk { thunk_addr: 0x08037e70, rom_target: 0x22003d70, name: None },
    RomThunk { thunk_addr: 0x08037e78, rom_target: 0x220041cc, name: None },
    RomThunk { thunk_addr: 0x08037e80, rom_target: 0x22001cbc, name: None },
    RomThunk { thunk_addr: 0x08037e88, rom_target: 0x22003d44, name: None },
    RomThunk { thunk_addr: 0x08037e90, rom_target: 0x220043f4, name: None },
    RomThunk { thunk_addr: 0x08037e98, rom_target: 0x22004260, name: None },
    RomThunk { thunk_addr: 0x08037ea0, rom_target: 0x220043c0, name: None },
    RomThunk { thunk_addr: 0x08037ea8, rom_target: 0x22004368, name: None },
    RomThunk { thunk_addr: 0x08037eb0, rom_target: 0x22003c28, name: None },
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
    RomThunk { thunk_addr: 0x08037f08, rom_target: 0x22004230, name: None },
    RomThunk { thunk_addr: 0x08037f10, rom_target: 0x22003e1c, name: None },
    RomThunk { thunk_addr: 0x08037f18, rom_target: 0x22003b8c, name: None },
    RomThunk { thunk_addr: 0x08037f20, rom_target: 0x220041fc, name: None },
    RomThunk { thunk_addr: 0x08037f28, rom_target: 0x220005a0, name: None },
    RomThunk { thunk_addr: 0x08037f30, rom_target: 0x22004154, name: None },
    RomThunk { thunk_addr: 0x08037f38, rom_target: 0x2200441c, name: None },
    RomThunk { thunk_addr: 0x08037f40, rom_target: 0x220084dc, name: None },
    RomThunk { thunk_addr: 0x08037f48, rom_target: 0x22003f08, name: None },
    RomThunk { thunk_addr: 0x08037f50, rom_target: 0x22003e70, name: None },
    RomThunk { thunk_addr: 0x08037f58, rom_target: 0x220060e0, name: None },
    RomThunk { thunk_addr: 0x08037f60, rom_target: 0x2200200c, name: None },
    RomThunk { thunk_addr: 0x08037f68, rom_target: 0x2200053c, name: None },
    RomThunk { thunk_addr: 0x08037f70, rom_target: 0x220001f4, name: Some("memmove_backward") },
    RomThunk { thunk_addr: 0x08037f78, rom_target: 0x22003e00, name: None },
    RomThunk { thunk_addr: 0x08037f80, rom_target: 0x2200427c, name: None },
    RomThunk { thunk_addr: 0x08037f88, rom_target: 0x22005018, name: None },
    RomThunk { thunk_addr: 0x08037f90, rom_target: 0x22004eec, name: None },
    RomThunk { thunk_addr: 0x08037f98, rom_target: 0x22005234, name: None },
    RomThunk { thunk_addr: 0x08037fa0, rom_target: 0x22003eec, name: None },
    RomThunk { thunk_addr: 0x08037fa8, rom_target: 0x22003d28, name: None },
    RomThunk { thunk_addr: 0x08037fb0, rom_target: 0x2200439c, name: None },
    RomThunk { thunk_addr: 0x08037fb8, rom_target: 0x22002ee0, name: None },
    RomThunk { thunk_addr: 0x08037fc0, rom_target: 0x22004620, name: None },
    RomThunk { thunk_addr: 0x08037fc8, rom_target: 0x22004534, name: None },
    RomThunk { thunk_addr: 0x08037fd0, rom_target: 0x2200279c, name: None },
    RomThunk { thunk_addr: 0x08037fd8, rom_target: 0x22006e88, name: None },
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
    RomThunk { thunk_addr: 0x08038060, rom_target: 0x22007470, name: None },
    RomThunk { thunk_addr: 0x08038068, rom_target: 0x22007a68, name: None },
    RomThunk { thunk_addr: 0x08038070, rom_target: 0x2200796c, name: None },
    RomThunk { thunk_addr: 0x08038078, rom_target: 0x2200722c, name: None },
    RomThunk { thunk_addr: 0x08038080, rom_target: 0x220040fc, name: None },
    RomThunk { thunk_addr: 0x08038088, rom_target: 0x22003b64, name: None },
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
    RomThunk { thunk_addr: 0x08038130, rom_target: 0x2200509c, name: None },
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
    RomThunk { thunk_addr: 0x08038190, rom_target: 0x220073b0, name: None },
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
    RomThunk { thunk_addr: 0x08038200, rom_target: 0x22005114, name: None },
    RomThunk { thunk_addr: 0x08038208, rom_target: 0x220076cc, name: None },
    RomThunk { thunk_addr: 0x08038210, rom_target: 0x22005cb0, name: None },
    RomThunk { thunk_addr: 0x08038218, rom_target: 0x22005228, name: None },
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
        let expected: [(u32, &str); 12] = [
            (0x22000020, "__rt_memcpy"),
            (0x220000d4, "memmove"),
            (0x22000188, "memcpy"),
            (0x220001f4, "memmove_backward"),
            (0x2200027c, "memzero_aligned"),
            (0x220002d4, "memzero"),
            (0x220002d8, "memset_body"),
            (0x22003dc8, "kernel_op_dispatch"),
            (0x22003ea0, "task_lock"),
            (0x22003eb0, "size_to_class"),
            (0x22003fd0, "sem_wait"),
            (0x2200408c, "task_unlock"),
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
        // 12 known targets, two of them aliased by two thunks each.
        assert_eq!(named, 14);
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

}
