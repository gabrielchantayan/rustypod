//! Port of the ARM ADS 1.0.1 `setjmp`/`longjmp` pair and their private
//! stack-switch helper:
//!
//! - `setjmp`       — original: `FUN_08031720` @ 0x08031720 (40 bytes)
//! - `longjmp`      — original: `FUN_08031748` @ 0x08031748 (44 bytes)
//! - `stack_switch` — original: `FUN_080336cc` @ 0x080336cc (12 bytes)
//!
//! Algorithm (mirrored instruction-for-instruction from the originals):
//!
//! `setjmp(env)` stores the callee-saved state into `env` in this exact
//! memory order (it is *not* ascending register order — the original uses
//! two `stmia` groups plus two single `str`s):
//!
//! ```text
//! env[0..4]  = r8, r9, r11(fp), lr        (stmia r0!, {r8, r9, fp, lr})
//! env[4..8]  = r4, r5, r6, r7             (stmia r0!, {r4, r5, r6, r7})
//! env[8]     = r10(sl)                    (str sl, [r0], #4)
//! env[9]     = sp                         (str sp, [r0], #4)
//! env[10]    = &env[10]                   (self-pointer, see below)
//! ```
//!
//! The push {r0, lr} / mov r0, r0 / pop {r1, lr} sequence is an ADS
//! unwinder-visibility marker; its only data effect is that env[10] ends
//! up holding env + 40 (a pointer to itself). longjmp loads env[10] into
//! r0 and immediately overwrites it, so the slot is dead — kept for exact
//! buffer-size/layout parity. setjmp then returns 0.
//!
//! `longjmp(env, val)` walks the buffer backwards from env + 44: it hands
//! env[8] (sl) and env[9] (sp) to `stack_switch`, which does
//! `push {r0, r1}; ldm sp, {sl, sp}` to swap stack limit and stack pointer
//! atomically before touching anything else. val==0 is forced to 1, r4-r7
//! are reloaded, and finally r8/r9/fp/lr are restored, returning `val` to
//! the setjmp call site.
//!
//! Implementation notes:
//!
//! - Written as verbatim ARM via `core::arch::global_asm!` (stable) rather
//!   than `#[naked]` + `naked_asm!`: the latter needs
//!   `#![feature(naked_functions)]` at the crate root, which is outside
//!   this module's remit. The emitted instructions are identical.
//! - The bodies only exist for `target_arch = "arm"`; the extern
//!   declarations and `JmpBuf` are available everywhere.
//!
//! Verification: these functions are naked register/state manipulators, so
//! host `cargo test` cannot execute them — host tests cover only the
//! `JmpBuf` layout (size/alignment/field offsets) and its correspondence
//! with the original's store order. Machine-code parity is verified with
//! `tools/match.py` (ipod-decomp), where the verbatim asm matches the
//! original nearly exactly.

/// setjmp/longjmp environment: r4-r11, sp, lr plus the original's dead
/// self-pointer slot — 11 words, 44 bytes. Field order matches the
/// original's store order in memory (see module header), NOT ascending
/// register number.
#[repr(C)]
pub struct JmpBuf {
    pub r8: u32,
    pub r9: u32,
    pub r11: u32,
    /// Return address setjmp appeared to return from.
    pub lr: u32,
    pub r4: u32,
    pub r5: u32,
    pub r6: u32,
    pub r7: u32,
    /// r10 — APCS stack limit (sl).
    pub r10: u32,
    pub sp: u32,
    /// Written by setjmp with `env + 40` (a pointer to this very slot);
    /// loaded but never used by longjmp. Dead padding, kept for parity.
    pub self_ref: u32,
}

impl JmpBuf {
    /// A zeroed environment, ready to be passed to `setjmp`.
    pub const fn new() -> Self {
        JmpBuf {
            r8: 0,
            r9: 0,
            r11: 0,
            lr: 0,
            r4: 0,
            r5: 0,
            r6: 0,
            r7: 0,
            r10: 0,
            sp: 0,
            self_ref: 0,
        }
    }
}

impl Default for JmpBuf {
    fn default() -> Self {
        JmpBuf::new()
    }
}

// On ARM the bodies are the verbatim global_asm below; Rust callers see
// them through a plain extern declaration (calls are `unsafe`, matching
// the intended `pub unsafe extern "C" fn` contract). On non-ARM hosts the
// asm cannot assemble, so unreachable Rust shims keep the API surface for
// host-side compile/test.
#[cfg(target_arch = "arm")]
extern "C" {
    /// Saves the current execution state into `env`. Returns 0 on the
    /// direct call; returns `val` (never 0) when reached again via
    /// `longjmp`. `env` must point to a valid, writable `JmpBuf` that
    /// outlives any matching `longjmp`.
    pub fn setjmp(env: *mut JmpBuf) -> i32;

    /// Restores the state saved in `env`, making the corresponding
    /// `setjmp` return again with `val` (1 if `val` is 0). Never returns.
    pub fn longjmp(env: *const JmpBuf, val: i32) -> !;
}

/// Host-only shim; see the extern block above for the real contract.
#[cfg(not(target_arch = "arm"))]
pub unsafe extern "C" fn setjmp(env: *mut JmpBuf) -> i32 {
    let _ = env;
    unreachable!("setjmp is provided by global_asm on ARM targets")
}

/// Host-only shim; see the extern block above for the real contract.
#[cfg(not(target_arch = "arm"))]
pub unsafe extern "C" fn longjmp(env: *const JmpBuf, val: i32) -> ! {
    let _ = (env, val);
    unreachable!("longjmp is provided by global_asm on ARM targets")
}

// Verbatim ARM bodies, mirrored instruction-for-instruction from the
// originals (addresses/sizes in the module header). Register aliases are
// APCS: sl = r10, fp = r11. `mov r0, r0` is the original's pre-UAL nop.
#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .text
    .p2align 2
    .globl setjmp
    .type setjmp, %function
setjmp:
    stmia   r0!, {{r8, r9, fp, lr}}
    stmia   r0!, {{r4, r5, r6, r7}}
    str     sl, [r0], #4
    str     sp, [r0], #4
    push    {{r0, lr}}
    mov     r0, r0
    pop     {{r1, lr}}
    stmia   r1!, {{r0}}
    mov     r0, #0
    mov     pc, lr
    .size setjmp, . - setjmp

    .globl longjmp
    .type longjmp, %function
longjmp:
    add     r8, r0, #44
    ldr     r0, [r8, #-4]!
    mov     r4, r1
    mov     r0, r0
    ldmdb   r8!, {{r0, r1}}
    bl      stack_switch
    movs    r0, r4
    ldmdb   r8!, {{r4, r5, r6, r7}}
    moveq   r0, #1
    ldmdb   r8, {{r8, r9, fp, lr}}
    mov     pc, lr
    .size longjmp, . - longjmp

    .globl stack_switch
    .type stack_switch, %function
stack_switch:
    push    {{r0, r1}}
    ldm     sp, {{sl, sp}}
    mov     pc, lr
    .size stack_switch, . - stack_switch
"#
);

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use core::mem::{align_of, offset_of, size_of};

    /// Pure-Rust reference of what the original setjmp writes, given a
    /// fake register file. Mirrors the stmia/stmia/str/str order exactly.
    fn reference_setjmp_store(regs: &[u32; 16], env_addr: u32) -> [u32; 11] {
        let mut buf = [0u32; 11];
        // stmia r0!, {r8, r9, fp(r11), lr}
        buf[0] = regs[8];
        buf[1] = regs[9];
        buf[2] = regs[11];
        buf[3] = regs[14];
        // stmia r0!, {r4, r5, r6, r7}
        buf[4] = regs[4];
        buf[5] = regs[5];
        buf[6] = regs[6];
        buf[7] = regs[7];
        // str sl(r10), [r0], #4 ; str sp, [r0], #4
        buf[8] = regs[10];
        buf[9] = regs[13];
        // push/pop marker: env[10] = env + 40 (self-pointer, dead slot)
        buf[10] = env_addr + 40;
        buf
    }

    #[test]
    fn jmpbuf_layout() {
        assert_eq!(size_of::<JmpBuf>(), 44, "11 words: r4-r11 + sp + lr + dead slot");
        assert_eq!(align_of::<JmpBuf>(), 4);
        assert_eq!(offset_of!(JmpBuf, r8), 0);
        assert_eq!(offset_of!(JmpBuf, r9), 4);
        assert_eq!(offset_of!(JmpBuf, r11), 8);
        assert_eq!(offset_of!(JmpBuf, lr), 12);
        assert_eq!(offset_of!(JmpBuf, r4), 16);
        assert_eq!(offset_of!(JmpBuf, r5), 20);
        assert_eq!(offset_of!(JmpBuf, r6), 24);
        assert_eq!(offset_of!(JmpBuf, r7), 28);
        assert_eq!(offset_of!(JmpBuf, r10), 32);
        assert_eq!(offset_of!(JmpBuf, sp), 36);
        assert_eq!(offset_of!(JmpBuf, self_ref), 40);
    }

    /// The struct's field order in memory must equal the original's store
    /// order, so that a raw register dump lands in the named fields.
    #[test]
    fn field_order_matches_original_store_order() {
        // Distinct, recognizable "register" values.
        let mut regs = [0u32; 16];
        for (i, r) in regs.iter_mut().enumerate() {
            *r = 0xA5A5_0000 | i as u32;
        }
        let env_addr = 0x0800_1000u32;
        let expected = reference_setjmp_store(&regs, env_addr);

        // Fill a JmpBuf field-by-field as the asm would, then compare the
        // raw words against the reference dump.
        let mut env = JmpBuf::new();
        env.r8 = regs[8];
        env.r9 = regs[9];
        env.r11 = regs[11];
        env.lr = regs[14];
        env.r4 = regs[4];
        env.r5 = regs[5];
        env.r6 = regs[6];
        env.r7 = regs[7];
        env.r10 = regs[10];
        env.sp = regs[13];
        env.self_ref = env_addr + 40;

        let words: &[u32; 11] = unsafe { &*(&env as *const JmpBuf as *const [u32; 11]) };
        assert_eq!(*words, expected);
    }

    /// longjmp's "val == 0 becomes 1" rule, the only host-testable piece
    /// of its logic (the register juggling is ARM-only machine code).
    #[test]
    fn longjmp_return_value_fixup() {
        fn reference_fixup(val: i32) -> i32 {
            if val == 0 {
                1
            } else {
                val
            }
        }
        assert_eq!(reference_fixup(0), 1);
        assert_eq!(reference_fixup(1), 1);
        assert_eq!(reference_fixup(-1), -1);
        assert_eq!(reference_fixup(i32::MIN), i32::MIN);
    }

    #[test]
    fn new_is_zeroed() {
        let env = JmpBuf::new();
        let words: &[u32; 11] = unsafe { &*(&env as *const JmpBuf as *const [u32; 11]) };
        assert_eq!(*words, [0; 11]);
        let env = JmpBuf::default();
        let words: &[u32; 11] = unsafe { &*(&env as *const JmpBuf as *const [u32; 11]) };
        assert_eq!(*words, [0; 11]);
    }
}
