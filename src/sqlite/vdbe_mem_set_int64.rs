//! Integer store — how the engine turns an existing
//! `Mem`/`sqlite3_value` cell into the SQL INTEGER datum.
//!
//! - `vdbe_mem_set_int64` — original: `FUN_0838c110` @ 0x0838c110
//!   (44 bytes, 0x0838c110..0x0838c13c; **2 `bl` call sites, 4
//!   tail-`b` and one `beq`**, binary-scanned from osos.dec — no
//!   predicated entries). Upstream SQLite's `sqlite3VdbeMemSetInt64`
//!   (`void sqlite3VdbeMemSetInt64(Mem *pMem, i64 val)` in vdbemem.c),
//!   the early-3.x release-store-stamp form. It sits immediately above
//!   [`vdbe_mem_set_null`] @ 0x0838c13c in the image (which calls
//!   nothing) and immediately below `sqlite3VdbeMemSetDouble` @
//!   0x0838c0c4 (which stores at +0x08 with `MEM_Real`/`SQLITE_FLOAT`)
//!   — the numeric-datum pair of the vdbeMem setter family.
//!
//! ### Extent
//!
//! Confirmed from raw words: 0x0838c138 is `ldmia sp!, {r4,r5,r6,pc}`
//! and the next word, 0x0838c13c, is the `ldrh r1, [r0, #0x1c]` entry
//! of `sqlite3VdbeMemSetNull`. No literal pool — the constants 4 and 1
//! are immediates.
//!
//! ### Listing
//!
//! ```text
//! 0838c110  stmdb sp!, {r4,r5,r6,lr}
//! 0838c114  mov  r6, r3            @ value >> 32
//! 0838c118  mov  r5, r2            @ value, low word
//! 0838c11c  mov  r4, r0            @ p_mem
//! 0838c120  bl   0x0838c04c        @ mem_release: free the old guts
//! 0838c124  mov  r0, #0x4          @ MEM_Int
//! 0838c128  stmia r4, {r5,r6}      @ u.i = value
//! 0838c12c  strh r0, [r4, #0x1c]   @ flags = MEM_Int, outright
//! 0838c130  mov  r0, #0x1          @ SQLITE_INTEGER
//! 0838c134  strb r0, [r4, #0x1e]   @ type
//! 0838c138  ldmia sp!, {r4,r5,r6,pc}
//! ```
//!
//! ### Algorithm
//!
//! One call, three stores, no branches. First
//! [`mem_release`](super::mem_release) @ 0x0838c04c runs on the cell
//! (finalizes an aggregate context, invokes the `xDel` destructor,
//! frees `zMalloc`, then NULLs `z`/`zMalloc`/`xDel`), so whatever the
//! cell held before is gone. Then the 64-bit `value` lands in the
//! integer arm of the value union at +0x00 (`stmia`, low word first —
//! this build's `Mem` keeps `u.i` at +0x00 and the `r`/`f64` arm at
//! +0x08, per `sqlite/vdbe.rs`), `flags` at +0x1c is *assigned*
//! `MEM_Int` (0x4) outright — unlike the sibling
//! [`vdbe_mem_set_null`]'s read-modify-write, no attribute bit
//! survives, matching the textbook early-3.x upstream body
//! (`pMem->u.i = val; pMem->flags = MEM_Int; pMem->type =
//! SQLITE_INTEGER;`) — and `value_type` at +0x1e becomes
//! `SQLITE_INTEGER` (1).
//!
//! Call sites (binary-scanned):
//!
//! - `bl` @ 0x08365590 — inside FUN_0836554c: fetches an 8-byte value
//!   through 0x08390eb0, doubles it with a 64-bit shift, zeros it on
//!   overflow and stores it into the embedded `Mem` at +8.
//! - `bl` @ 0x0838efbc — inside FUN_0838ef84: fallback path stores
//!   into `*(param_1 + 0x38) + param_2 * 0x28 - 0x28` (a column-indexed
//!   `Mem` array element).
//! - tail `b` @ 0x082b2974 — inside FUN_082b28b8's epilogue: embedded
//!   `Mem` at +8 (`add r0, r6, #0x8`).
//! - tail `b` @ 0x082c5030 — inside FUN_082c5008: `ldrdne r2,r3,[r0]`
//!   from a fetched cell, embedded `Mem` at +8.
//! - tail `b` @ 0x082d7a4c — inside FUN_082d79b4: sign-extends a
//!   computed 32-bit count (`mov r3, r2, asr #0x1f`), embedded `Mem`
//!   at +8.
//! - tail `b` @ 0x0839120c — the unlisted thunk @ 0x08391200
//!   (`mov r2,r1; mov r3,r1,asr #0x1f; add r0,r0,#8; b`), the
//!   32→64 sign-extending `sqlite3VdbeMemSetInt` analog, in the
//!   embedded-`Mem` setter run beside the set-null thunk @ 0x08391218.
//! - `beq` @ 0x0839292c — inside FUN_083928c8, the value copy: a byte
//!   at +0x19 discriminates the payload arm — `ldrd` from +0x00
//!   (`u.i`) with a `beq` here, or from +0x08 (`r`) with a `bne` to
//!   set-double @ 0x0838c0c4 — the two numeric arms of this family.
//!
//! ### Deviations
//!
//! - The port goes through the `repr(C)` [`Mem`] with named fields
//!   (whose +0x00/+0x1c/+0x1e offsets are statically asserted on
//!   32-bit targets in `sqlite/vdbe.rs`) rather than raw byte offsets,
//!   so the host build's wider pointer fields cannot shift the bytes
//!   this function touches.
//! - [`mem_release`] @ 0x0838c04c IS ported and is the shipped default
//!   of the [`MEM_SET_OPS`] slot; the slot is kept so host tests can
//!   intercept it — the ported `mem_release` speaks the original's raw
//!   byte offsets, which coincide with the typed [`Mem`] only on the
//!   32-bit target, so a host test running the real one against a
//!   host-layout `Mem` would read the wrong fields (the same reason
//!   `value_free` keeps its `VALUE_MEM_OPS` slot).

use super::mem_release::mem_release;
use super::vdbe::Mem;

/// The `MEM_Int` type bit stamped into `Mem.flags` (original:
/// `mov r0, #0x4` / `strh r0, [r4, #0x1c]`). Assigned outright — the
/// original does not preserve attribute bits here.
pub const MEM_INT: u16 = 0x4;

/// The `SQLITE_INTEGER` type tag stamped into `Mem.type` (original:
/// `mov r0, #0x1` / `strb r0, [r4, #0x1e]`).
pub const SQLITE_INTEGER: u8 = 1;

/// vdbe_mem_set_int64 — original: `FUN_0838c110` @ 0x0838c110 (44
/// bytes; 2 `bl` call sites, 4 tail-`b` and one `beq`).
///
/// `sqlite3VdbeMemSetInt64`: make `p_mem` the SQL INTEGER datum
/// `value`. The cell's old dynamic guts are released through
/// [`mem_release`] (the [`MEM_SET_OPS`] slot), then `u` takes `value`,
/// `flags` is assigned `MEM_INT` outright (attribute bits do not
/// survive), and `value_type` becomes `SQLITE_INTEGER`. `n`, `enc`,
/// `db` and the floating-point arm `r` are deliberately untouched —
/// the original never writes them either.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vdbe_mem_set_int64(p_mem: *mut Mem, value: i64) {
    (release_op())(p_mem as *mut u8);
    let mem = &mut *p_mem;
    mem.u = value as u64;
    mem.flags = MEM_INT;
    mem.value_type = SQLITE_INTEGER;
}

/// Indirect dispatch for the guts release @ 0x0838c04c (kept behind
/// the table so host tests can intercept it — see the module header).
#[derive(Clone, Copy)]
pub struct MemSetOps {
    /// `sqlite3VdbeMemRelease(value)` @ 0x0838c04c: release the value's
    /// dynamic resources (aggregate context / `xDel` destructor /
    /// `zMalloc`) without freeing the shell.
    pub mem_release: unsafe extern "C" fn(value: *mut u8),
}

/// Wired default: the ported guts release @ 0x0838c04c
/// ([`mem_release`]).
pub const DEFAULT_MEM_SET_OPS: MemSetOps = MemSetOps { mem_release };

/// The active guts release. Host tests install recording mocks.
pub static mut MEM_SET_OPS: MemSetOps = DEFAULT_MEM_SET_OPS;

/// Reads the mem-release slot (volatile — the slot is meant to be
/// swapped at runtime, and a plain read lets LLVM const-fold the
/// default away).
#[inline(always)]
pub(crate) unsafe fn release_op() -> unsafe extern "C" fn(*mut u8) {
    core::ptr::read_volatile(core::ptr::addr_of!(MEM_SET_OPS.mem_release))
}

#[cfg(test)]
pub(crate) mod tests {
    extern crate std;
    use super::*;
    use std::sync::{Mutex, MutexGuard};

    /// Serializes tests that swap the mem-release slot.
    static OPS_LOCK: Mutex<()> = Mutex::new(());

    /// The slot lock, shared with `vdbe_mem_set_double`'s tests —
    /// both modules swap the same `MEM_SET_OPS` slot and the host
    /// test harness runs them in one multi-threaded process.
    pub(crate) fn ops_lock() -> &'static Mutex<()> {
        &OPS_LOCK
    }

    /// A `Mem` with distinguishable garbage in every field, so an
    /// unintended write shows up as a mismatch. (The ownership
    /// pointers can be garbage too: the recording mock never touches
    /// the cell.)
    fn garbage_mem(flags: u16, value_type: u8) -> Mem {
        Mem {
            u: 0x0bad_cafe_dead_beef,
            r: f64::from_bits(0x7ff8_0000_5a5a_5a5a),
            db: 0x0bad_1000usize as *mut u8,
            z: 0x0bad_2000usize as *mut u8,
            n: -123_456_789,
            flags,
            value_type,
            enc: 0xa7,
            x_del: 0x0bad_3000usize as *mut u8,
            z_malloc: 0x0bad_4000usize as *mut u8,
        }
    }

    /// Records guts-release calls so the test can prove the
    /// `mem_release` prologue ran. The recording mock also stands in
    /// for the real `mem_release` on host: the ported release speaks
    /// the original's raw byte offsets (+0x14/+0x1c/+0x20/+0x24),
    /// which coincide with the typed [`Mem`] only on the 32-bit
    /// target — running it against a host-layout `Mem` would free
    /// through the wrong fields. Releasing is `mem_release`'s own
    /// tested contract, not this function's.
    static mut RELEASE_CALLS: u32 = 0;
    static mut RELEASE_ARG: usize = 0;

    unsafe extern "C" fn recording_mem_release(value: *mut u8) {
        unsafe {
            RELEASE_CALLS += 1;
            RELEASE_ARG = value as usize;
        }
    }

    /// Restores the wired default guts release on drop.
    struct OpsGuard;

    impl Drop for OpsGuard {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(MEM_SET_OPS).write(DEFAULT_MEM_SET_OPS);
            }
        }
    }

    /// Takes the module lock, installs the recording guts release and
    /// zeroes its counters. The guards must stay alive for the whole
    /// test.
    fn bench() -> (MutexGuard<'static, ()>, OpsGuard) {
        let ops_guard = OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            RELEASE_CALLS = 0;
            RELEASE_ARG = 0;
            core::ptr::write_volatile(
                core::ptr::addr_of_mut!(MEM_SET_OPS),
                MemSetOps {
                    mem_release: recording_mem_release,
                },
            );
        }
        (ops_guard, OpsGuard)
    }

    #[test]
    fn value_lands_in_the_integer_arm_bit_for_bit() {
        let _guards = bench();
        // Edge cases: zero, ±1, the sign-extension boundary, the
        // word-boundary split and the i64 extremes.
        let values = [
            0i64,
            1,
            -1,
            0x7fff_ffff,
            -0x8000_0000,
            0x1_0000_0000,
            -0x1_0000_0000,
            i64::MIN,
            i64::MAX,
            0xdead_beef_cafe_f00du64 as i64,
        ];
        for value in values {
            let mut mem = garbage_mem(0, 0);
            unsafe { vdbe_mem_set_int64(&mut mem, value) };
            assert_eq!(mem.u, value as u64, "value={value:#x}");
        }
    }

    #[test]
    fn flags_are_assigned_mem_int_outright_for_every_prior_value() {
        let _guards = bench();
        // Exhaustive over the whole u16 flags space: unlike
        // vdbe_mem_set_null's read-modify-write, the observable
        // contract is exactly `flags = MEM_Int` — no attribute bit
        // (MEM_Term/MEM_Dyn/MEM_Static/MEM_Agg/MEM_Zero) survives.
        let mut mem = garbage_mem(0, 0);
        for flags in 0..=u16::MAX {
            mem.flags = flags;
            unsafe { vdbe_mem_set_int64(&mut mem, 42) };
            assert_eq!(mem.flags, MEM_INT, "flags={flags:#06x}");
        }
    }

    #[test]
    fn value_type_becomes_sqlite_integer_for_every_prior_type() {
        let _guards = bench();
        let mut mem = garbage_mem(0, 0);
        for value_type in 0..=u8::MAX {
            mem.value_type = value_type;
            unsafe { vdbe_mem_set_int64(&mut mem, 42) };
            assert_eq!(mem.value_type, SQLITE_INTEGER, "type={value_type:#04x}");
        }
    }

    #[test]
    fn old_guts_are_released_through_mem_release() {
        // The guts release must run exactly once per call, on the cell
        // itself — the observable trace of the `bl 0x0838c04c`
        // prologue.
        let _guards = bench();
        let mut mem = garbage_mem(0, 0);
        unsafe { vdbe_mem_set_int64(&mut mem, 42) };
        assert_eq!(unsafe { RELEASE_CALLS }, 1);
        assert_eq!(unsafe { RELEASE_ARG }, core::ptr::addr_of!(mem) as usize);
    }

    #[test]
    fn unrelated_fields_are_byte_for_byte_untouched() {
        let _guards = bench();
        // Only the fields NEITHER this function NOR the mem_release
        // prologue writes: `z`/`x_del`/`z_malloc` are the release's
        // own contract (covered by sqlite::mem_release's tests), so
        // they are excluded here — the recording mock deliberately
        // leaves them alone.
        let before = garbage_mem(0x0fff, 0xa5);
        let mut mem = garbage_mem(0x0fff, 0xa5);
        unsafe { vdbe_mem_set_int64(&mut mem, -99) };
        assert_eq!(mem.r.to_bits(), before.r.to_bits());
        assert_eq!(mem.db, before.db);
        assert_eq!(mem.n, before.n);
        assert_eq!(mem.enc, before.enc);
    }
}
