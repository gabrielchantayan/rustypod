//! Double-NUL termination — how the engine guarantees a string `Mem`/
//! `sqlite3_value` cell carries the two-NUL trailer the text consumers
//! (UTF-8 and UTF-16 alike) expect past its `z` payload.
//!
//! - `vdbe_mem_nul_terminate` — original: `FUN_0838bfb0` @ 0x0838bfb0
//!   (116 bytes, 0x0838bfb0..0x0838c024; **5 `bl` call sites**,
//!   binary-scanned from osos.dec — no predicated or tail branches).
//!   Upstream SQLite 3.5.9's `sqlite3VdbeMemNulTerminate`
//!   (`int sqlite3VdbeMemNulTerminate(Mem *pMem)` in vdbemem.c),
//!   verified line-for-line against the public 3.5.9 source (only the
//!   asserts are compiled out of the firmware). Its immediate caller
//!   [`vdbe_real_value`](super::vdbe_real_value) already documents it as
//!   the unported terminator in its text/blob arm.
//!
//! ### Extent
//!
//! Confirmed from raw words: 0x0838c020 is the closing `b 0x0838bfcc`
//! and the next word, 0x0838c024, is the `stmdb sp!, {r4,lr}` entry of
//! [`vdbe_mem_realify`](super::vdbe_mem_realify). No literal pool — the
//! flag tests (`0x20`, `0x2`), the grow increment (`+2`), `preserve`
//! (`1`) and both return codes are all immediates.
//!
//! ### Listing
//!
//! ```text
//! 0838bfb0  stmdb sp!, {r4,lr}
//! 0838bfb4  mov  r4,r0              @ p_mem
//! 0838bfb8  ldrh r0,[r0,#0x1c]      @ flags, sampled once
//! 0838bfbc  tst  r0,#0x20           @ MEM_Term?
//! 0838bfc0  bne  0x0838bfcc         @ already terminated: SQLITE_OK
//! 0838bfc4  tst  r0,#0x2            @ MEM_Str?
//! 0838bfc8  bne  0x0838bfd4         @ text: grow, then terminate
//! 0838bfcc  mov  r0,#0x0            @ SQLITE_OK
//! 0838bfd0  ldmia sp!, {r4,pc}
//! 0838bfd4  ldr  r0,[r4,#0x18]      @ n
//! 0838bfd8  mov  r2,#0x1            @ preserve = 1
//! 0838bfdc  add  r1,r0,#0x2         @ n + 2
//! 0838bfe0  mov  r0,r4
//! 0838bfe4  bl   0x0838bdb0         @ sqlite3VdbeMemGrow(p_mem, n+2, 1)
//! 0838bfe8  cmp  r0,#0x0
//! 0838bfec  movne r0,#0x7           @ SQLITE_NOMEM
//! 0838bff0  ldmiane sp!, {r4,pc}
//! 0838bff4  ldr  r1,[r4,#0x14]      @ z, reloaded after the grow
//! 0838bff8  ldr  r2,[r4,#0x18]      @ n, reloaded
//! 0838bffc  mov  r0,#0x0
//! 0838c000  strb r0,[r1,r2]         @ z[n] = 0
//! 0838c004  ldr  r1,[r4,#0x14]
//! 0838c008  ldr  r2,[r4,#0x18]
//! 0838c00c  add  r1,r1,r2
//! 0838c010  strb r0,[r1,#0x1]       @ z[n+1] = 0
//! 0838c014  ldrh r0,[r4,#0x1c]      @ flags, reloaded after the grow
//! 0838c018  orr  r0,r0,#0x20        @ MEM_Term
//! 0838c01c  strh r0,[r4,#0x1c]
//! 0838c020  b    0x0838bfcc
//! ```
//!
//! ### Algorithm
//!
//! The cell's `flags` halfword at +0x1c is sampled once, up front. A
//! cell that already carries `MEM_Term` (0x20) is terminated by
//! definition, and a cell without `MEM_Str` (0x2) has no text payload to
//! terminate — both short-circuit to `SQLITE_OK` with nothing touched
//! (upstream's `(pMem->flags & MEM_Term)!=0 || (pMem->flags &
//! MEM_Str)==0` guard, in the disassembly's test order). Otherwise
//! `sqlite3VdbeMemGrow` @ 0x0838bdb0 is asked to guarantee `n + 2`
//! bytes of cell-owned payload space with `preserve = 1` (room for the
//! trailer without moving the payload's meaning); a failed grow
//! short-circuits to `SQLITE_NOMEM` (7) with the cell untouched. On
//! success `z` and `n` are *reloaded* — the grow may have relocated the
//! buffer — the two NUL bytes land at `z[n]` and `z[n+1]`, and the
//! reloaded flags gain `MEM_Term` by read-modify-write, so attribute
//! bits and any concurrent flag change survive the `or`.
//!
//! Call sites (binary-scanned):
//!
//! - `bl` @ 0x082b4710 — inside FUN_082b46f8, the integer-coercion
//!   helper (NUL-terminate, `sqlite3Atoi64`-style parse @ 0x0837cb60,
//!   then [`vdbe_mem_realify`](super::vdbe_mem_realify) on the
//!   parse-failure arm).
//! - `bl` @ 0x08386788 — inside `sqlite3ValueText` @ 0x08386718
//!   (ported: [`value_text`](super::value_text)); guarantees the double
//!   NUL after the recode.
//! - `bl` @ 0x083875b0 — inside the 16 KB vdbe engine routine
//!   FUN_08386ef8.
//! - `bl` @ 0x0838b618 — inside FUN_0838b5c4, the
//!   `sqlite3VdbeIntValue`-style integer extractor.
//! - `bl` @ 0x0838c84c — inside [`vdbe_real_value`](super::vdbe_real_value)
//!   @ 0x0838c7ec, the text/blob arm before `sqlite3AtoF`.
//!
//! ### Deviations
//!
//! - `sqlite3VdbeMemGrow` @ 0x0838bdb0 is not ported. It is the
//!   [`VDBE_MEM_NUL_TERMINATE_OPS`] seam: target builds call its
//!   retailOS load address directly, while host tests install a
//!   recording mock. The ABI type and address constant are reused from
//!   [`vdbe_mem_set_str`](super::vdbe_mem_set_str), which owns them.
//! - The port goes through the typed `repr(C)` [`Mem`] with named
//!   fields rather than the original's +0x14/+0x18/+0x1c byte offsets;
//!   those target offsets are statically asserted on 32-bit targets in
//!   `sqlite/vdbe.rs`.

use super::value_set_str::SQLITE_NOMEM;
use super::vdbe::Mem;
use super::vdbe_mem_realify::SQLITE_OK;
use super::vdbe_mem_set_str::{VdbeMemGrow, MEM_STR, MEM_TERM, VDBE_MEM_GROW_ADDRESS};

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_vdbe_mem_grow(p_mem: *mut Mem, size: i32, preserve: i32) -> i32 {
    let grow: VdbeMemGrow = core::mem::transmute(VDBE_MEM_GROW_ADDRESS);
    grow(p_mem, size, preserve)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_vdbe_mem_grow(_p_mem: *mut Mem, _size: i32, _preserve: i32) -> i32 {
    panic!("vdbe_mem_nul_terminate requires sqlite3VdbeMemGrow @ 0x0838bdb0")
}

/// Indirect dispatch for the unported grow helper this terminator
/// calls. Host tests install a recording implementation; the target
/// default branches straight into retailOS.
#[derive(Clone, Copy)]
pub struct VdbeMemNulTerminateOps {
    /// `sqlite3VdbeMemGrow(pMem, size, preserve)` @ 0x0838bdb0.
    pub grow: VdbeMemGrow,
}

/// Target default: the remaining retailOS helper.
#[cfg(target_os = "none")]
pub const DEFAULT_VDBE_MEM_NUL_TERMINATE_OPS: VdbeMemNulTerminateOps =
    VdbeMemNulTerminateOps { grow: retail_vdbe_mem_grow };

/// Host default: fail loudly until a test supplies the unported helper.
#[cfg(not(target_os = "none"))]
pub const DEFAULT_VDBE_MEM_NUL_TERMINATE_OPS: VdbeMemNulTerminateOps =
    VdbeMemNulTerminateOps { grow: missing_vdbe_mem_grow };

/// Active grow helper. Host tests install recording mocks.
pub static mut VDBE_MEM_NUL_TERMINATE_OPS: VdbeMemNulTerminateOps =
    DEFAULT_VDBE_MEM_NUL_TERMINATE_OPS;

/// Reads the grow slot volatile so its host replacement cannot be
/// folded into the default.
#[inline(always)]
unsafe fn grow_op() -> VdbeMemGrow {
    core::ptr::read_volatile(core::ptr::addr_of!(VDBE_MEM_NUL_TERMINATE_OPS.grow))
}

/// vdbe_mem_nul_terminate — original: `FUN_0838bfb0` @ 0x0838bfb0
/// (116 bytes; 5 `bl` call sites).
///
/// `sqlite3VdbeMemNulTerminate`: guarantee `p_mem`'s text payload is
/// followed by a two-NUL trailer. A cell that already carries
/// `MEM_Term`, or that lacks `MEM_Str`, is returned untouched with
/// `SQLITE_OK`. Otherwise the payload buffer is grown to `n + 2` bytes
/// (`preserve = 1`), the post-grow `z` gains NULs at `z[n]` and
/// `z[n + 1]`, and the post-grow flags gain `MEM_Term`; a failed grow
/// returns `SQLITE_NOMEM` with the cell untouched.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vdbe_mem_nul_terminate(p_mem: *mut Mem) -> i32 {
    let flags = (*p_mem).flags;
    if flags & MEM_TERM != 0 {
        return SQLITE_OK;
    }
    if flags & MEM_STR == 0 {
        return SQLITE_OK;
    }
    if (grow_op())(p_mem, (*p_mem).n + 2, 1) != SQLITE_OK {
        return SQLITE_NOMEM;
    }
    let tail = (*p_mem).z.offset((*p_mem).n as isize);
    *tail = 0;
    *tail.add(1) = 0;
    (*p_mem).flags |= MEM_TERM;
    SQLITE_OK
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::sync::{Mutex, MutexGuard};

    /// Serializes tests that swap the grow slot.
    static OPS_LOCK: Mutex<()> = Mutex::new(());

    /// The payload space the recording grow hands out. Big enough that
    /// any test-chosen `n` plus its two-byte trailer fits.
    static mut PAYLOAD: [u8; 64] = [0; 64];
    /// The relocation target the recording grow can swap in, proving
    /// the terminators use the post-grow `z`.
    static mut RELOCATED: [u8; 64] = [0; 64];
    /// What the recording grow returns.
    static mut GROW_RC: i32 = SQLITE_OK;
    /// How many times the recording grow ran.
    static mut CALLS: u32 = 0;
    /// Which `Mem *` the recording grow saw.
    static mut ARG_MEM: usize = 0;
    /// Which `size` the recording grow saw.
    static mut ARG_SIZE: i32 = 0;
    /// Which `preserve` the recording grow saw.
    static mut ARG_PRESERVE: i32 = 0;
    /// Whether the recording grow relocates `z` and rewrites `n`.
    static mut RELOCATE: Option<i32> = None;
    /// Optional flags overwrite the recording grow performs before
    /// returning, proving the final `flags |= MEM_Term` reloads.
    static mut GROW_FLAGS_WRITE: Option<u16> = None;

    /// The grow mock: record the triple, optionally relocate the
    /// payload buffer and rewrite `n`/`flags` (as a buffer-moving grow
    /// would), and fail on request.
    unsafe extern "C" fn recording_grow(p_mem: *mut Mem, size: i32, preserve: i32) -> i32 {
        CALLS += 1;
        ARG_MEM = p_mem as usize;
        ARG_SIZE = size;
        ARG_PRESERVE = preserve;
        if GROW_RC == SQLITE_OK {
            if let Some(new_n) = RELOCATE {
                (*p_mem).z = core::ptr::addr_of_mut!(RELOCATED).cast::<u8>();
                (*p_mem).n = new_n;
            } else {
                (*p_mem).z = core::ptr::addr_of_mut!(PAYLOAD).cast::<u8>();
            }
            if let Some(flags) = GROW_FLAGS_WRITE {
                (*p_mem).flags = flags;
            }
        }
        GROW_RC
    }

    /// Restores the wired default grow on drop.
    struct OpsGuard;

    impl Drop for OpsGuard {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(VDBE_MEM_NUL_TERMINATE_OPS)
                    .write(DEFAULT_VDBE_MEM_NUL_TERMINATE_OPS);
            }
        }
    }

    /// Takes the module lock, installs the recording grow, and zeroes
    /// its controls/counters. The guards must stay alive for the whole
    /// test.
    fn bench() -> (MutexGuard<'static, ()>, OpsGuard) {
        let ops_guard = OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            PAYLOAD.fill(0xa5);
            RELOCATED.fill(0xa5);
            GROW_RC = SQLITE_OK;
            CALLS = 0;
            ARG_MEM = 0;
            ARG_SIZE = 0;
            ARG_PRESERVE = 0;
            RELOCATE = None;
            GROW_FLAGS_WRITE = None;
            core::ptr::write_volatile(
                core::ptr::addr_of_mut!(VDBE_MEM_NUL_TERMINATE_OPS),
                VdbeMemNulTerminateOps { grow: recording_grow },
            );
        }
        (ops_guard, OpsGuard)
    }

    /// A `Mem` with distinguishable garbage in every field, so an
    /// unintended write shows up as a mismatch.
    fn garbage_mem(flags: u16, n: i32) -> Mem {
        Mem {
            u: 0x0bad_cafe_dead_beef,
            r: f64::from_bits(0x7ff8_0000_5a5a_5a5a),
            db: 0x0bad_1000usize as *mut u8,
            z: 0x0bad_2000usize as *mut u8,
            n,
            flags,
            value_type: 0x5b,
            enc: 0xa7,
            x_del: 0x0bad_3000usize as *mut u8,
            z_malloc: 0x0bad_4000usize as *mut u8,
        }
    }

    /// Field-wise cell equality (`Mem` deliberately has no derives).
    fn assert_cell_eq(mem: &Mem, before: &Mem, context: std::string::String) {
        assert_eq!(mem.u, before.u, "{context}: u");
        assert_eq!(mem.r.to_bits(), before.r.to_bits(), "{context}: r");
        assert_eq!(mem.db, before.db, "{context}: db");
        assert_eq!(mem.z, before.z, "{context}: z");
        assert_eq!(mem.n, before.n, "{context}: n");
        assert_eq!(mem.flags, before.flags, "{context}: flags");
        assert_eq!(mem.value_type, before.value_type, "{context}: value_type");
        assert_eq!(mem.enc, before.enc, "{context}: enc");
        assert_eq!(mem.x_del, before.x_del, "{context}: x_del");
        assert_eq!(mem.z_malloc, before.z_malloc, "{context}: z_malloc");
    }

    #[test]
    fn already_terminated_cells_short_circuit_without_growing() {
        let _guards = bench();
        for flags in [
            MEM_STR | MEM_TERM,
            MEM_STR | MEM_TERM | 0x800,
            MEM_TERM, // the bit alone short-circuits, even without MEM_Str
            MEM_TERM | 0x0d1f,
            u16::MAX,
        ] {
            let before = garbage_mem(flags, 17);
            let mut mem = garbage_mem(flags, 17);
            assert_eq!(unsafe { vdbe_mem_nul_terminate(&mut mem) }, SQLITE_OK, "flags={flags:#06x}");
            assert_eq!(unsafe { CALLS }, 0, "flags={flags:#06x}: grow must not run");
            assert_cell_eq(&mem, &before, std::format!("flags={flags:#06x}: cell must be untouched"));
        }
    }

    #[test]
    fn non_string_cells_short_circuit_without_growing() {
        let _guards = bench();
        for flags in [
            0x1,  // MEM_Null
            0x4,  // MEM_Int
            0x8,  // MEM_Real
            0x10, // MEM_Blob (no MEM_Str)
            0x0,  // no type bits at all
            0xd1d, // every attribute bit, still no MEM_Str
        ] {
            let before = garbage_mem(flags, 17);
            let mut mem = garbage_mem(flags, 17);
            assert_eq!(unsafe { vdbe_mem_nul_terminate(&mut mem) }, SQLITE_OK, "flags={flags:#06x}");
            assert_eq!(unsafe { CALLS }, 0, "flags={flags:#06x}: grow must not run");
            assert_cell_eq(&mem, &before, std::format!("flags={flags:#06x}: cell must be untouched"));
        }
    }

    #[test]
    fn grow_receives_n_plus_two_with_preserve_one() {
        let _guards = bench();
        for n in [0, 1, 7, 30] {
            let mut mem = garbage_mem(MEM_STR, n);
            unsafe {
                CALLS = 0;
                assert_eq!(vdbe_mem_nul_terminate(&mut mem), SQLITE_OK, "n={n}");
                assert_eq!(CALLS, 1, "n={n}");
                assert_eq!(ARG_MEM, core::ptr::addr_of!(mem) as usize, "n={n}");
                assert_eq!(ARG_SIZE, n + 2, "n={n}");
                assert_eq!(ARG_PRESERVE, 1, "n={n}");
            }
        }
    }

    #[test]
    fn grow_failure_returns_sqlite_nomem_and_touches_nothing() {
        let _guards = bench();
        for rc in [SQLITE_NOMEM, 1, -1] {
            let before = garbage_mem(MEM_STR | 0x180, 9);
            let mut mem = garbage_mem(MEM_STR | 0x180, 9);
            unsafe {
                GROW_RC = rc;
                CALLS = 0;
                assert_eq!(vdbe_mem_nul_terminate(&mut mem), SQLITE_NOMEM, "rc={rc}");
                assert_eq!(CALLS, 1, "rc={rc}: the grow is attempted");
            }
            assert_cell_eq(&mem, &before, std::format!("rc={rc}: a failed grow leaves the cell untouched"));
            assert!(
                unsafe { PAYLOAD }.iter().all(|&b| b == 0xa5),
                "rc={rc}: a failed grow writes no terminators"
            );
        }
    }

    #[test]
    fn terminators_land_at_z_n_and_z_n_plus_one() {
        let _guards = bench();
        for n in [0, 1, 7, 30] {
            let mut mem = garbage_mem(MEM_STR, n);
            unsafe {
                PAYLOAD.fill(0xa5);
                assert_eq!(vdbe_mem_nul_terminate(&mut mem), SQLITE_OK, "n={n}");
                let z = PAYLOAD;
                assert_eq!(z[n as usize], 0, "n={n}: z[n]");
                assert_eq!(z[n as usize + 1], 0, "n={n}: z[n+1]");
                assert!(
                    z[..n as usize].iter().all(|&b| b == 0xa5)
                        && z[n as usize + 2..].iter().all(|&b| b == 0xa5),
                    "n={n}: only the two trailer bytes are written"
                );
                assert_eq!(mem.z, core::ptr::addr_of_mut!(PAYLOAD).cast::<u8>(), "n={n}");
                assert_eq!(mem.flags, MEM_STR | MEM_TERM, "n={n}");
            }
        }
    }

    #[test]
    fn terminators_use_the_post_grow_z_and_n() {
        let _guards = bench();
        let mut mem = garbage_mem(MEM_STR, 3);
        unsafe {
            RELOCATE = Some(40);
            assert_eq!(vdbe_mem_nul_terminate(&mut mem), SQLITE_OK);
            assert_eq!(RELOCATED[40], 0, "z[n] at the relocated buffer");
            assert_eq!(RELOCATED[41], 0, "z[n+1] at the relocated buffer");
            assert!(
                RELOCATED[..40].iter().all(|&b| b == 0xa5)
                    && RELOCATED[42..].iter().all(|&b| b == 0xa5),
                "only the two trailer bytes are written"
            );
            assert!(
                PAYLOAD.iter().all(|&b| b == 0xa5),
                "the pre-grow buffer is never written"
            );
        }
    }

    #[test]
    fn final_flags_are_derived_from_the_post_grow_value() {
        let _guards = bench();
        let injected = 0x0d12u16; // MEM_Blob|MEM_Str plus attribute bits, no MEM_Term
        let mut mem = garbage_mem(MEM_STR, 5);
        unsafe {
            GROW_FLAGS_WRITE = Some(injected);
            assert_eq!(vdbe_mem_nul_terminate(&mut mem), SQLITE_OK);
        }
        assert_eq!(
            mem.flags,
            injected | MEM_TERM,
            "the original reloads flags after sqlite3VdbeMemGrow returns"
        );
    }

    #[test]
    fn guard_and_flag_update_hold_for_every_flags_value() {
        let _guards = bench();
        let mut mem = garbage_mem(0, 0);
        for flags in 0..=u16::MAX {
            mem.flags = flags;
            unsafe {
                CALLS = 0;
                assert_eq!(vdbe_mem_nul_terminate(&mut mem), SQLITE_OK, "flags={flags:#06x}");
            }
            if flags & (MEM_TERM | MEM_STR) == MEM_STR {
                assert_eq!(unsafe { CALLS }, 1, "flags={flags:#06x}: grow expected");
                assert_eq!(mem.flags, flags | MEM_TERM, "flags={flags:#06x}");
            } else {
                assert_eq!(unsafe { CALLS }, 0, "flags={flags:#06x}: grow forbidden");
                assert_eq!(mem.flags, flags, "flags={flags:#06x}");
            }
        }
    }

    #[test]
    fn unrelated_fields_are_byte_for_byte_untouched() {
        let _guards = bench();
        let before = garbage_mem(MEM_STR | 0x3c0, 6);
        let mut mem = garbage_mem(MEM_STR | 0x3c0, 6);
        unsafe { vdbe_mem_nul_terminate(&mut mem) };
        assert_eq!(mem.u, before.u);
        assert_eq!(mem.r.to_bits(), before.r.to_bits());
        assert_eq!(mem.db, before.db);
        assert_eq!(mem.n, before.n);
        assert_eq!(mem.value_type, before.value_type);
        assert_eq!(mem.enc, before.enc);
        assert_eq!(mem.x_del, before.x_del);
        assert_eq!(mem.z_malloc, before.z_malloc);
        assert_eq!(mem.flags, before.flags | MEM_TERM);
    }
}
