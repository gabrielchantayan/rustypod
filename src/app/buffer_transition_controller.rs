//! `stream_buffer_transition_controller` — original: `thunk_EXT_FUN_220029ac`
//! @ `0x080380f0` (Ghidra reports 4 bytes; raw extent is **8** bytes:
//! `ldr pc, [pc, #-4]` / `0x220029ac`). The boot relocator's `0x08000000` →
//! `0x22000000` IRAM mirror resolves that target to the osos body at
//! `0x080029ac`, whose true raw extent is **172 bytes** (`0x080029ac` through
//! `0x08002a57`): it ends with the tail branch `b 0x08002948`, and the next
//! word `0x08002a58` opens a distinct function (`push {r4, r5, r6, r7, r8,
//! r9, sl, fp, lr}` around the "iPodPowerProfile.txt" profile dump).
//! Ghidra's 348-byte `FUN_080029ac` lumps this body together with that
//! sibling and both wait functions; the extent here is verified from raw
//! bytes.
//!
//! Raw decoding of every ARM `B`/`BL` word in `work/firmware/osos.dec` found
//! **24 direct `bl` call sites** to the veneer, all unconditional, plus
//! **3 tail `b` transfers** (`0x081a5d9c`, `0x081a6794`, `0x081a684c`): 27
//! control transfers in total, no predicated `bl` forms. Callers therefore
//! never NULL-gate anything at the call site; every policy check lives
//! inside this controller.
//!
//! # Algorithm
//!
//! The request controller is the six-word block at `0x2200aebc` (IRAM):
//! `+0x00` flags, `+0x0c` inhibit word, `+0x10` requested level (written by
//! `stream_buffer_refill_level_advance`), `+0x14` base level.
//!
//! 1. Gate: if `(flags & 0x46) | inhibit_word` is nonzero, or the inhibit
//!    byte at `0x089caf4a` is nonzero, skip straight to the drain wait.
//!    Bit 0 is deliberately absent from the `0x46` mask — a pending request
//!    alone never suppresses the transition.
//! 2. Otherwise call the storage gate query `0x080518a0`; a nonzero result
//!    suppresses the transition (drain wait).
//! 3. Call the transition dispatch `0x0804afb4`, then the controller-history
//!    function (see the entry quirk below); a nonzero history result also
//!    selects the drain wait.
//! 4. With all gates clear, reload flags and base level (post-call values —
//!    the callees may have mutated the controller), then:
//!    - bit 0 (`0x01`): clamp toward the requested level:
//!      `level = max(min(base, requested), floor)` where `floor` is `0`
//!      when bit 7 (`0x80`) is set and `1` otherwise;
//!    - bit 3 (`0x08`): override the level to `0` when bit 4 (`0x10`) is
//!      set, else to `1`;
//!    - bit 5 (`0x20`) without bit 3: force the level to `0`;
//!    - otherwise the base level stands.
//! 5. Tail-enter the level wait: `0x08002948(level)` spins (semaphore 22,
//!    IRQ/FIQ masked) until the stream-buffer level word `0x2200ad14` equals
//!    the target; the suppressed path instead tail-enters `0x080044c8`,
//!    which waits for that same word to reach `0`. Both waits fall through
//!    to the stream-consumer status block `0x080042b4(22)`; the return value
//!    is theirs (or the already-met level on the early-exit path).
//!
//! ```text
//! 080029ac: e92d4010  push {r4, lr}
//! 080029b0: e59f4390  ldr  r4, [pc, #912]    ; 0x08002d48: 0x2200aebc
//! 080029b4: e5940000  ldr  r0, [r4]          ; flags
//! 080029b8: e594100c  ldr  r1, [r4, #12]     ; inhibit word
//! 080029bc: e2000046  and  r0, r0, #0x46
//! 080029c0: e1900001  orrs r0, r0, r1
//! 080029c4: 059f0380  ldreq r0, [pc, #896]   ; 0x08002d4c: 0x089caf4a
//! 080029c8: 05d00000  ldrbeq r0, [r0]        ; inhibit byte
//! 080029cc: 03500000  cmpeq r0, #0
//! 080029d0: 1a000006  bne  0x080029f0
//! 080029d4: eb0002d7  bl   0x08003538        ; veneer -> 0x080518a0
//! 080029d8: e3500000  cmp  r0, #0
//! 080029dc: 1a000003  bne  0x080029f0
//! 080029e0: eb0002d6  bl   0x08003540        ; veneer -> 0x0804afb4
//! 080029e4: eb0002d7  bl   0x08003548        ; veneer -> 0x081561f8
//! 080029e8: e3500000  cmp  r0, #0
//! 080029ec: 0a000001  beq  0x080029f8
//! 080029f0: e8bd4010  pop  {r4, lr}
//! 080029f4: ea0006b3  b    0x080044c8        ; wait level == 0
//! 080029f8: e5941000  ldr  r1, [r4]          ; flags, reloaded
//! 080029fc: e5940014  ldr  r0, [r4, #20]     ; base level
//! 08002a00: e3110001  tst  r1, #1
//! 08002a04: 0a000007  beq  0x08002a28
//! 08002a08: e5942010  ldr  r2, [r4, #16]     ; requested level
//! 08002a0c: e1520000  cmp  r2, r0
//! 08002a10: 91a00002  movls r0, r2           ; min(base, requested)
//! 08002a14: e1a02000  mov  r2, r0
//! 08002a18: e3a00001  mov  r0, #1
//! 08002a1c: e1c003a1  bic  r0, r0, r1, lsr #7 ; floor: bit7 ? 0 : 1
//! 08002a20: e1520000  cmp  r2, r0
//! 08002a24: 21a00002  movcs r0, r2           ; max(min, floor)
//! 08002a28: e3110008  tst  r1, #8
//! 08002a2c: 0a000003  beq  0x08002a40
//! 08002a30: e3110010  tst  r1, #16
//! 08002a34: e3a00001  mov  r0, #1
//! 08002a38: 0a000004  beq  0x08002a50
//! 08002a3c: ea000002  b    0x08002a4c
//! 08002a40: e3110020  tst  r1, #32
//! 08002a44: 13500000  cmpne r0, #0
//! 08002a48: 0a000000  beq  0x08002a50        ; bit5 clear keeps level
//! 08002a4c: e3a00000  mov  r0, #0
//! 08002a50: e8bd4010  pop  {r4, lr}
//! 08002a54: eaffffbb  b    0x08002948        ; wait level == r0
//! ```
//!
//! # Callee identities
//!
//! - `0x080518a0` (`retail_stream_transition_gate`): deep storage/FAT-layer
//!   query — 0x20/0x3a stack buffer arguments, `0x3f` status compares, a
//!   heap allocation, error codes `0x30`/`-0x6c`. Its true name is unknown;
//!   the seam name describes only its verified role here: a zero result
//!   permits the transition.
//! - `0x0804afb4` (`retail_stream_transition_dispatch`): scans a four-slot
//!   object table and virtual-calls slot `+0x24`, logging through
//!   `FUN_08049a84(6, 0x6b, code)` on failure. True name unknown; the seam
//!   name is role-based.
//! - `0x081561f8` (`retail_controller_history_fn`): **entry anomaly** — the
//!   veneer at `0x08003548` (whose sole caller is this controller at
//!   `0x080029e4`) targets the head of the name string `"CntrlHistoryFn"`
//!   at `0x081561f8`, not the function entry at `0x0815620c`. The five
//!   string/pointer words decode as `rsbsvc`/`cmnvc`/`ldmdbvc`/`andeq`/
//!   `ldmdaeq`: entering with V=0 and Z=0 skips all five and falls into the
//!   real entry; entering with Z=1 would execute `ldmdaeq lr!, {…, pc}` and
//!   go wild. retailOS relies on the flags the dispatch call leaves behind.
//!   The port preserves the transfer to `0x081561f8` verbatim, quirk
//!   included.
//!
//! # Deliberate deviations
//!
//! None in behavior. On ARM the five stock callees are reached through
//! `retail_*` literal veneers (`ldr pc, [pc, #-4]` + absolute target word),
//! replacing the stock PC-relative `bl`/tail-`b` once this body lives in the
//! Rust payload; the `0x081561f8` veneer keeps the anomalous string-head
//! target. Host builds replace target RAM (`0x2200aebc`, `0x089caf4a`) with
//! statics and the five callees with callback seams.


/// Flags mask (`0x46`, bits 1/2/6) that suppresses the whole transition
/// attempt. Bit 0 is intentionally not part of the mask.
pub const TRANSITION_INHIBIT_FLAGS: u32 = 0x46;
/// Flags bit 0: a request is pending at controller `+0x10`; clamp toward it.
pub const REQUEST_LEVEL_PENDING: u32 = 0x01;
/// Flags bit 3: override the computed level to 0 or 1 (see bit 4).
pub const LEVEL_OVERRIDE: u32 = 0x08;
/// Flags bit 4: with [`LEVEL_OVERRIDE`], selects 0 (set) or 1 (clear).
pub const LEVEL_OVERRIDE_TO_ZERO: u32 = 0x10;
/// Flags bit 5: without [`LEVEL_OVERRIDE`], force the level to 0.
pub const LEVEL_FORCE_ZERO: u32 = 0x20;
/// Flags bit 7: drop the floor of 1 in the pending-request clamp.
pub const LEVEL_FLOOR_DISABLE: u32 = 0x80;

/// Host/target seam type for the argument-less stock callees.
pub type TransitionSeam = unsafe extern "C" fn() -> u32;
/// Host/target seam type for the level wait, which takes the target level.
pub type LevelWaitSeam = unsafe extern "C" fn(level: u32) -> u32;

/// Host mirror of the six-word request controller at target RAM
/// `0x2200aebc`. Field order and padding mirror the ARM word offsets
/// (`+0x00` flags, `+0x0c` inhibit, `+0x10` requested, `+0x14` base).
#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct StreamBufferRequestController {
    pub flags: u32,
    pub _reserved_04_08: [u32; 2],
    pub inhibit: u32,
    pub requested_level: u32,
    pub base_level: u32,
}

/// Host-only replacement for the request-controller block at `0x2200aebc`.
#[cfg(not(target_os = "none"))]
pub static mut STREAM_BUFFER_REQUEST_CONTROLLER: StreamBufferRequestController =
    StreamBufferRequestController {
        flags: 0,
        _reserved_04_08: [0; 2],
        inhibit: 0,
        requested_level: 0,
        base_level: 0,
    };

/// Host-only replacement for the inhibit byte at `0x089caf4a`.
#[cfg(not(target_os = "none"))]
pub static mut STREAM_TRANSITION_INHIBIT_BYTE: u8 = 0;

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_transition_seam() -> u32 {
    0
}

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_level_wait_seam(_level: u32) -> u32 {
    0
}

/// Host-only callback for the storage gate query at `0x080518a0`.
#[cfg(not(target_arch = "arm"))]
pub static mut TRANSITION_GATE: TransitionSeam = missing_transition_seam;
/// Host-only callback for the transition dispatch at `0x0804afb4`.
#[cfg(not(target_arch = "arm"))]
pub static mut TRANSITION_DISPATCH: TransitionSeam = missing_transition_seam;
/// Host-only callback for the controller-history function (veneer target
/// `0x081561f8`, real entry `0x0815620c`).
#[cfg(not(target_arch = "arm"))]
pub static mut CONTROLLER_HISTORY_FN: TransitionSeam = missing_transition_seam;
/// Host-only callback for the level wait at `0x08002948`.
#[cfg(not(target_arch = "arm"))]
pub static mut LEVEL_WAIT_EQUAL: LevelWaitSeam = missing_level_wait_seam;
/// Host-only callback for the drain wait at `0x080044c8`.
#[cfg(not(target_arch = "arm"))]
pub static mut LEVEL_WAIT_ZERO: TransitionSeam = missing_transition_seam;

#[inline(always)]
fn request_controller_ptr() -> *const u32 {
    #[cfg(target_os = "none")]
    {
        0x2200_aebc as *const u32
    }

    #[cfg(not(target_os = "none"))]
    {
        core::ptr::addr_of!(STREAM_BUFFER_REQUEST_CONTROLLER) as *const u32
    }
}

#[inline(always)]
fn transition_inhibit_byte_ptr() -> *const u8 {
    #[cfg(target_os = "none")]
    {
        0x089c_af4a as *const u8
    }

    #[cfg(not(target_os = "none"))]
    {
        core::ptr::addr_of!(STREAM_TRANSITION_INHIBIT_BYTE)
    }
}

#[cfg(target_arch = "arm")]
extern "C" {
    fn retail_stream_transition_gate() -> u32;
    fn retail_stream_transition_dispatch() -> u32;
    fn retail_controller_history_fn() -> u32;
    fn retail_stream_buffer_level_wait_equal(level: u32) -> u32;
    fn retail_stream_buffer_level_wait_zero() -> u32;
}

#[cfg(not(target_arch = "arm"))]
unsafe fn retail_stream_transition_gate() -> u32 {
    core::ptr::read_volatile(core::ptr::addr_of!(TRANSITION_GATE))()
}

#[cfg(not(target_arch = "arm"))]
unsafe fn retail_stream_transition_dispatch() -> u32 {
    core::ptr::read_volatile(core::ptr::addr_of!(TRANSITION_DISPATCH))()
}

#[cfg(not(target_arch = "arm"))]
unsafe fn retail_controller_history_fn() -> u32 {
    core::ptr::read_volatile(core::ptr::addr_of!(CONTROLLER_HISTORY_FN))()
}

#[cfg(not(target_arch = "arm"))]
unsafe fn retail_stream_buffer_level_wait_equal(level: u32) -> u32 {
    core::ptr::read_volatile(core::ptr::addr_of!(LEVEL_WAIT_EQUAL))(level)
}

#[cfg(not(target_arch = "arm"))]
unsafe fn retail_stream_buffer_level_wait_zero() -> u32 {
    core::ptr::read_volatile(core::ptr::addr_of!(LEVEL_WAIT_ZERO))()
}

// The stock body reaches all five callees with PC-relative bl/b within the
// IRAM-mirrored low block. Once this body lives in the Rust payload those
// relocations cannot reach; literal veneers preserve the exact transfers,
// including the anomalous 0x081561f8 string-head target (see module docs).
#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .text
    .p2align 2
    .globl retail_stream_transition_gate
    .type retail_stream_transition_gate, %function
retail_stream_transition_gate:
    ldr     pc, [pc, #-4]
    .word   0x080518a0
    .size retail_stream_transition_gate, . - retail_stream_transition_gate

    .globl retail_stream_transition_dispatch
    .type retail_stream_transition_dispatch, %function
retail_stream_transition_dispatch:
    ldr     pc, [pc, #-4]
    .word   0x0804afb4
    .size retail_stream_transition_dispatch, . - retail_stream_transition_dispatch

    .globl retail_controller_history_fn
    .type retail_controller_history_fn, %function
retail_controller_history_fn:
    ldr     pc, [pc, #-4]
    .word   0x081561f8
    .size retail_controller_history_fn, . - retail_controller_history_fn

    .globl retail_stream_buffer_level_wait_equal
    .type retail_stream_buffer_level_wait_equal, %function
retail_stream_buffer_level_wait_equal:
    ldr     pc, [pc, #-4]
    .word   0x08002948
    .size retail_stream_buffer_level_wait_equal, . - retail_stream_buffer_level_wait_equal

    .globl retail_stream_buffer_level_wait_zero
    .type retail_stream_buffer_level_wait_zero, %function
retail_stream_buffer_level_wait_zero:
    ldr     pc, [pc, #-4]
    .word   0x080044c8
    .size retail_stream_buffer_level_wait_zero, . - retail_stream_buffer_level_wait_zero
"#
);

/// stream_buffer_transition_controller — original: `thunk_EXT_FUN_220029ac`
/// @ `0x080380f0` (8-byte veneer) → body `FUN_080029ac` @ `0x080029ac`
/// (172 bytes; Ghidra's 348 lumps in the `0x08002a58` sibling).
///
/// 24 unconditional `bl` call sites plus 3 tail `b` transfers, verified by
/// decoding every ARM `B`/`BL` word in `osos.dec`. Applies the pending
/// stream-buffer level request when the inhibit flags/word/byte, the storage
/// gate, and the controller-history check all clear; otherwise waits for the
/// buffer level to drain. Returns the chosen wait's result.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(
    target_os = "none",
    link_section = ".text.stream_buffer_transition_controller"
)]
#[inline(never)]
pub unsafe extern "C" fn stream_buffer_transition_controller() -> u32 {
    let controller = request_controller_ptr();
    let flags = core::ptr::read_volatile(controller);
    let inhibit = core::ptr::read_volatile(controller.add(3));
    if ((flags & TRANSITION_INHIBIT_FLAGS) | inhibit) == 0
        && core::ptr::read_volatile(transition_inhibit_byte_ptr()) == 0
        && retail_stream_transition_gate() == 0
    {
        retail_stream_transition_dispatch();
        if retail_controller_history_fn() == 0 {
            // The callees may have mutated the controller: reload, exactly
            // like the stock body's second ldr pair at 0x080029f8/0x080029fc.
            let flags = core::ptr::read_volatile(controller);
            let mut level = core::ptr::read_volatile(controller.add(5));
            if flags & REQUEST_LEVEL_PENDING != 0 {
                let requested = core::ptr::read_volatile(controller.add(4));
                if requested <= level {
                    level = requested;
                }
                let floor = 1 & !(flags >> 7);
                if level < floor {
                    level = floor;
                }
            }
            if flags & LEVEL_OVERRIDE != 0 {
                level = if flags & LEVEL_OVERRIDE_TO_ZERO != 0 {
                    0
                } else {
                    1
                };
            } else if flags & LEVEL_FORCE_ZERO != 0 {
                level = 0;
            }
            return retail_stream_buffer_level_wait_equal(level);
        }
    }
    retail_stream_buffer_level_wait_zero()
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    static TRANSITION_LOCK: Mutex<()> = Mutex::new(());
    static mut CALL_LOG: Vec<&'static str> = Vec::new();
    static mut GATE_RESULT: u32 = 0;
    static mut HISTORY_RESULT: u32 = 0;
    static mut WAIT_EQUAL_RESULT: u32 = 0;
    static mut WAIT_ZERO_RESULT: u32 = 0;
    static mut WAIT_EQUAL_LEVEL: u32 = 0;

    unsafe extern "C" fn recording_gate() -> u32 {
        CALL_LOG.push("gate");
        GATE_RESULT
    }

    unsafe extern "C" fn recording_dispatch() -> u32 {
        CALL_LOG.push("dispatch");
        0
    }

    unsafe extern "C" fn recording_history() -> u32 {
        CALL_LOG.push("history");
        HISTORY_RESULT
    }

    unsafe extern "C" fn recording_wait_equal(level: u32) -> u32 {
        CALL_LOG.push("wait_equal");
        WAIT_EQUAL_LEVEL = level;
        WAIT_EQUAL_RESULT
    }

    unsafe extern "C" fn recording_wait_zero() -> u32 {
        CALL_LOG.push("wait_zero");
        WAIT_ZERO_RESULT
    }

    struct Reset;

    impl Drop for Reset {
        fn drop(&mut self) {
            unsafe {
                STREAM_BUFFER_REQUEST_CONTROLLER = StreamBufferRequestController {
                    flags: 0,
                    _reserved_04_08: [0; 2],
                    inhibit: 0,
                    requested_level: 0,
                    base_level: 0,
                };
                STREAM_TRANSITION_INHIBIT_BYTE = 0;
                TRANSITION_GATE = missing_transition_seam;
                TRANSITION_DISPATCH = missing_transition_seam;
                CONTROLLER_HISTORY_FN = missing_transition_seam;
                LEVEL_WAIT_EQUAL = missing_level_wait_seam;
                LEVEL_WAIT_ZERO = missing_transition_seam;
                CALL_LOG = Vec::new();
                GATE_RESULT = 0;
                HISTORY_RESULT = 0;
                WAIT_EQUAL_RESULT = 0;
                WAIT_ZERO_RESULT = 0;
                WAIT_EQUAL_LEVEL = 0;
            }
        }
    }

    fn arrange(flags: u32, base_level: u32) -> (MutexGuard<'static, ()>, Reset) {
        let guard = TRANSITION_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        unsafe {
            STREAM_BUFFER_REQUEST_CONTROLLER.flags = flags;
            STREAM_BUFFER_REQUEST_CONTROLLER.base_level = base_level;
            TRANSITION_GATE = recording_gate;
            TRANSITION_DISPATCH = recording_dispatch;
            CONTROLLER_HISTORY_FN = recording_history;
            LEVEL_WAIT_EQUAL = recording_wait_equal;
            LEVEL_WAIT_ZERO = recording_wait_zero;
        }
        (guard, Reset)
    }

    fn log() -> Vec<&'static str> {
        unsafe { CALL_LOG.clone() }
    }

    #[test]
    fn inhibit_flag_bits_each_suppress_the_transition() {
        for bit in [0x02u32, 0x04, 0x40] {
            let (_guard, _reset) = arrange(bit, 7);
            unsafe {
                WAIT_ZERO_RESULT = 0xbeef;
            }
            let result = unsafe { stream_buffer_transition_controller() };
            assert_eq!(result, 0xbeef, "bit {:#x} result", bit);
            assert_eq!(log(), ["wait_zero"], "bit {:#x} call log", bit);
        }
    }

    #[test]
    fn inhibit_word_suppresses_the_transition() {
        let (_guard, _reset) = arrange(0, 7);
        unsafe {
            STREAM_BUFFER_REQUEST_CONTROLLER.inhibit = 1;
        }
        unsafe { stream_buffer_transition_controller() };
        assert_eq!(log(), ["wait_zero"]);
    }

    #[test]
    fn inhibit_byte_suppresses_the_transition() {
        let (_guard, _reset) = arrange(0, 7);
        unsafe {
            STREAM_TRANSITION_INHIBIT_BYTE = 1;
        }
        unsafe { stream_buffer_transition_controller() };
        assert_eq!(log(), ["wait_zero"]);
    }

    #[test]
    fn gate_failure_skips_dispatch_and_history() {
        let (_guard, _reset) = arrange(0, 7);
        unsafe {
            GATE_RESULT = 1;
        }
        unsafe { stream_buffer_transition_controller() };
        assert_eq!(log(), ["gate", "wait_zero"]);
    }

    #[test]
    fn history_failure_drains_after_dispatch() {
        let (_guard, _reset) = arrange(0, 7);
        unsafe {
            HISTORY_RESULT = 9;
            WAIT_ZERO_RESULT = 33;
        }
        let result = unsafe { stream_buffer_transition_controller() };
        assert_eq!(result, 33);
        assert_eq!(log(), ["gate", "dispatch", "history", "wait_zero"]);
    }

    #[test]
    fn base_level_passes_through_when_no_flag_bits() {
        let (_guard, _reset) = arrange(0, 9);
        unsafe { stream_buffer_transition_controller() };
        assert_eq!(log(), ["gate", "dispatch", "history", "wait_equal"]);
        assert_eq!(unsafe { WAIT_EQUAL_LEVEL }, 9);
    }

    #[test]
    fn pending_request_below_base_clamps_down() {
        let (_guard, _reset) = arrange(REQUEST_LEVEL_PENDING, 9);
        unsafe {
            STREAM_BUFFER_REQUEST_CONTROLLER.requested_level = 2;
        }
        unsafe { stream_buffer_transition_controller() };
        assert_eq!(unsafe { WAIT_EQUAL_LEVEL }, 2);
    }

    #[test]
    fn pending_request_above_base_keeps_base() {
        let (_guard, _reset) = arrange(REQUEST_LEVEL_PENDING, 9);
        unsafe {
            STREAM_BUFFER_REQUEST_CONTROLLER.requested_level = 12;
        }
        unsafe { stream_buffer_transition_controller() };
        assert_eq!(unsafe { WAIT_EQUAL_LEVEL }, 9);
    }

    #[test]
    fn pending_request_has_a_floor_of_one() {
        let (_guard, _reset) = arrange(REQUEST_LEVEL_PENDING, 9);
        unsafe {
            STREAM_BUFFER_REQUEST_CONTROLLER.requested_level = 0;
        }
        unsafe { stream_buffer_transition_controller() };
        assert_eq!(unsafe { WAIT_EQUAL_LEVEL }, 1);
    }

    #[test]
    fn floor_bit_removes_the_floor() {
        let (_guard, _reset) = arrange(REQUEST_LEVEL_PENDING | LEVEL_FLOOR_DISABLE, 9);
        unsafe {
            STREAM_BUFFER_REQUEST_CONTROLLER.requested_level = 0;
        }
        unsafe { stream_buffer_transition_controller() };
        assert_eq!(unsafe { WAIT_EQUAL_LEVEL }, 0);
    }

    #[test]
    fn override_bit_selects_one_when_low_bit_clear() {
        let (_guard, _reset) = arrange(LEVEL_OVERRIDE, 9);
        unsafe {
            STREAM_BUFFER_REQUEST_CONTROLLER.requested_level = 4;
        }
        unsafe { stream_buffer_transition_controller() };
        assert_eq!(unsafe { WAIT_EQUAL_LEVEL }, 1);
    }

    #[test]
    fn override_bit_selects_zero_when_low_bit_set() {
        let (_guard, _reset) = arrange(LEVEL_OVERRIDE | LEVEL_OVERRIDE_TO_ZERO, 9);
        unsafe { stream_buffer_transition_controller() };
        assert_eq!(unsafe { WAIT_EQUAL_LEVEL }, 0);
    }

    #[test]
    fn force_zero_bit_discards_the_computed_level() {
        let (_guard, _reset) = arrange(LEVEL_FORCE_ZERO, 9);
        unsafe { stream_buffer_transition_controller() };
        assert_eq!(unsafe { WAIT_EQUAL_LEVEL }, 0);
    }

    #[test]
    fn force_zero_bit_wins_over_pending_request() {
        let (_guard, _reset) = arrange(LEVEL_FORCE_ZERO | REQUEST_LEVEL_PENDING, 9);
        unsafe {
            STREAM_BUFFER_REQUEST_CONTROLLER.requested_level = 2;
        }
        unsafe { stream_buffer_transition_controller() };
        assert_eq!(unsafe { WAIT_EQUAL_LEVEL }, 0);
    }

    #[test]
    fn wait_equal_result_is_forwarded() {
        let (_guard, _reset) = arrange(0, 5);
        unsafe {
            WAIT_EQUAL_RESULT = 0xdead;
        }
        let result = unsafe { stream_buffer_transition_controller() };
        assert_eq!(result, 0xdead);
    }

    #[test]
    fn controller_words_are_reloaded_after_the_calls() {
        unsafe extern "C" fn mutating_dispatch() -> u32 {
            CALL_LOG.push("dispatch");
            STREAM_BUFFER_REQUEST_CONTROLLER.flags = LEVEL_OVERRIDE;
            0
        }
        unsafe extern "C" fn mutating_history() -> u32 {
            CALL_LOG.push("history");
            STREAM_BUFFER_REQUEST_CONTROLLER.base_level = 42;
            0
        }
        let (_guard, _reset) = arrange(0, 7);
        unsafe {
            TRANSITION_DISPATCH = mutating_dispatch;
            CONTROLLER_HISTORY_FN = mutating_history;
        }
        unsafe { stream_buffer_transition_controller() };
        // flags reloaded as 0x08 -> level 1, not the mutated base of 42.
        assert_eq!(unsafe { WAIT_EQUAL_LEVEL }, 1);
    }
}
