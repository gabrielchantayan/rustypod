//! Real store — how the engine turns an existing `Mem`/`sqlite3_value`
//! cell into the SQL REAL (float) datum, with a NaN escape hatch.
//!
//! - `vdbe_mem_set_double` — original: `FUN_0838c0c4` @ 0x0838c0c4
//!   (76 bytes, 0x0838c0c4..0x0838c110; **3 `bl` call sites, 4
//!   tail-`b` and one `bne`**, binary-scanned from osos.dec — no
//!   predicated entries). Upstream SQLite's `sqlite3VdbeMemSetDouble`
//!   (`void sqlite3VdbeMemSetDouble(Mem *pMem, double val)` in
//!   vdbemem.c), the early-3.x release-store-stamp form with the
//!   NaN-to-NULL guard. It sits immediately above
//!   [`vdbe_mem_set_int64`] @ 0x0838c110 (which stores at +0x00 with
//!   `MEM_Int`/`SQLITE_INTEGER`) and below `mem_finalize`'s run — the
//!   floating-point half of the numeric-datum setter pair.
//!
//! ### Extent
//!
//! Confirmed from raw words: 0x0838c10c is `ldmia sp!, {r4,r5,r6,pc}`
//! and the next word, 0x0838c110, is the `stmdb sp!, {r4,r5,r6,lr}`
//! entry of [`vdbe_mem_set_int64`]. No literal pool — the constants 8
//! and 2 are immediates.
//!
//! ### Listing
//!
//! ```text
//! 0838c0c4  stmdb sp!, {r4,r5,r6,lr}
//! 0838c0c8  mov  r4, r0            @ p_mem
//! 0838c0cc  mov  r0, r2            @ value, low word
//! 0838c0d0  mov  r6, r3            @ value, high word (kept)
//! 0838c0d4  mov  r5, r2            @ value, low word (kept)
//! 0838c0d8  mov  r1, r3
//! 0838c0dc  bl   0x0837cb44        @ sqlite3IsNaN(value)
//! 0838c0e0  cmp  r0, #0x0
//! 0838c0e4  mov  r0, r4            @ p_mem, for either tail
//! 0838c0e8  ldmiane sp!, {r4,r5,r6,lr}
//! 0838c0ec  bne  0x0838c13c        @ NaN: tail-call MemSetNull
//! 0838c0f0  bl   0x0838c04c        @ mem_release: free the old guts
//! 0838c0f4  str  r5, [r4, #0x8]    @ r = value, low word
//! 0838c0f8  mov  r0, #0x8          @ MEM_Real
//! 0838c0fc  str  r6, [r4, #0xc]    @ r = value, high word
//! 0838c100  strh r0, [r4, #0x1c]   @ flags = MEM_Real, outright
//! 0838c104  mov  r0, #0x2          @ SQLITE_FLOAT
//! 0838c108  strb r0, [r4, #0x1e]   @ type
//! 0838c10c  ldmia sp!, {r4,r5,r6,pc}
//! ```
//!
//! ### Algorithm
//!
//! One branch on the NaN predicate. The helper @ 0x0837cb44 —
//! upstream's `sqlite3IsNaN`, `return x != x;` spelled as a
//! `__dcmpeq` @ 0x083eb748 (ported in `fp_compare`) of the value
//! against itself, result normalized to 0/1 — runs first. If the
//! value is NaN the cell is simply NULLed: a tail call to
//! [`vdbe_mem_set_null`] @ 0x0838c13c (`ldmiane`/`bne`, so
//! MemSetNull returns straight to this function's caller), which
//! read-modify-writes `flags` to `MEM_Null` and stamps `SQLITE_NULL`
//! — and nothing is released, matching upstream's
//! `if( sqlite3IsNaN(val) ){ sqlite3VdbeMemSetNull(pMem); }` arm.
//! Otherwise [`mem_release`](super::mem_release) @ 0x0838c04c runs on
//! the cell (finalizes an aggregate context, invokes the `xDel`
//! destructor, frees `zMalloc`, then NULLs `z`/`zMalloc`/`xDel`), the
//! 64-bit `value` lands in the floating-point arm of the value union
//! at +0x08 (two `str`s, low word first — this build's `Mem` keeps
//! the integer arm `u.i` at +0x00 and the `r`/`f64` arm at +0x08, per
//! `sqlite/vdbe.rs`), `flags` at +0x1c is *assigned* `MEM_Real`
//! (0x8) outright — like the sibling [`vdbe_mem_set_int64`] and
//! unlike [`vdbe_mem_set_null`]'s read-modify-write, no attribute bit
//! survives — and `value_type` at +0x1e becomes `SQLITE_FLOAT` (2).
//!
//! Call sites (binary-scanned):
//!
//! - `bl` @ 0x082d74b4 — inside FUN_082d7488.
//! - `bl` @ 0x083682e8 — inside FUN_08368254.
//! - `bl` @ 0x0838ef70 — inside FUN_0838ef38 (the counterpart of
//!   set_int64's `bl` @ 0x0838efbc fallback in the same column-`Mem`
//!   store run).
//! - tail `b` @ 0x082b2910 — inside FUN_082b28b8's epilogue.
//! - tail `b` @ 0x082b5ab0 — inside FUN_082b5a58.
//! - tail `b` @ 0x08391140 — inside FUN_08391124, in the thunk run
//!   beside the embedded-`Mem` setters @ 0x08391200/0x08391218.
//! - tail `b` @ 0x083943f4 — inside FUN_083943d0.
//! - `bne` @ 0x08392934 — inside FUN_083928c8, the value copy: a
//!   byte at +0x19 discriminates the payload arm — `ldrd` from +0x08
//!   (`r`) with a `bne` here, or from +0x00 (`u.i`) with a `beq` to
//!   set-int64 @ 0x0838c110 — the two numeric arms of this family.
//!
//! ### Deviations
//!
//! - The port goes through the `repr(C)` [`Mem`] with named fields
//!   (whose +0x08/+0x1c/+0x1e offsets are statically asserted on
//!   32-bit targets in `sqlite/vdbe.rs`) rather than raw byte
//!   offsets, so the host build's wider pointer fields cannot shift
//!   the bytes this function touches.
//! - The NaN predicate is Rust's `f64::is_nan` — the same
//!   self-inequality the original's helper @ 0x0837cb44 spells as a
//!   `__dcmpeq` of the value against itself. The helper itself is
//!   not yet ported; inlining the predicate here keeps this port to
//!   one function.
//! - The NaN route calls the ported [`vdbe_mem_set_null`] @
//!   0x0838c13c directly (it speaks the typed [`Mem`], so it is safe
//!   on host), matching the original's tail call.
//! - [`mem_release`] @ 0x0838c04c runs through the [`MEM_SET_OPS`]
//!   slot owned by [`vdbe_mem_set_int64`]'s module (its shipped
//!   default is the ported release) so host tests can intercept it —
//!   the ported release speaks the original's raw byte offsets,
//!   which coincide with the typed [`Mem`] only on the 32-bit
//!   target.

use super::vdbe::Mem;
use super::vdbe_mem_set_int64::release_op;
use super::vdbe_mem_set_null::vdbe_mem_set_null;

/// The `MEM_Real` type bit stamped into `Mem.flags` (original:
/// `mov r0, #0x8` / `strh r0, [r4, #0x1c]`). Assigned outright — the
/// original does not preserve attribute bits here.
pub const MEM_REAL: u16 = 0x8;

/// The `SQLITE_FLOAT` type tag stamped into `Mem.type` (original:
/// `mov r0, #0x2` / `strb r0, [r4, #0x1e]`).
pub const SQLITE_FLOAT: u8 = 2;

/// vdbe_mem_set_double — original: `FUN_0838c0c4` @ 0x0838c0c4 (76
/// bytes; 3 `bl` call sites, 4 tail-`b` and one `bne`).
///
/// `sqlite3VdbeMemSetDouble`: make `p_mem` the SQL REAL datum
/// `value`. A NaN `value` instead NULLs the cell through
/// [`vdbe_mem_set_null`] (the original's tail call — nothing is
/// released on that path). Otherwise the cell's old dynamic guts are
/// released through [`mem_release`](super::mem_release) (the
/// [`MEM_SET_OPS`](super::vdbe_mem_set_int64::MEM_SET_OPS) slot),
/// then `r` takes `value`, `flags` is assigned `MEM_REAL` outright
/// (attribute bits do not survive), and `value_type` becomes
/// `SQLITE_FLOAT`. `u`, `n`, `enc` and `db` are deliberately
/// untouched — the original never writes them either.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vdbe_mem_set_double(p_mem: *mut Mem, value: f64) {
    if value.is_nan() {
        vdbe_mem_set_null(p_mem);
        return;
    }
    (release_op())(p_mem as *mut u8);
    let mem = &mut *p_mem;
    mem.r = value;
    mem.flags = MEM_REAL;
    mem.value_type = SQLITE_FLOAT;
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use super::super::vdbe_mem_set_int64::{MemSetOps, DEFAULT_MEM_SET_OPS, MEM_SET_OPS};
    use super::super::vdbe_mem_set_null::MEM_TYPE_BITS;
    use super::super::value_new::{MEM_NULL, SQLITE_NULL};
    use std::sync::MutexGuard;

    /// Records guts-release calls so the test can prove the
    /// `mem_release` prologue ran exactly when it should. The
    /// recording mock also stands in for the real `mem_release` on
    /// host: the ported release speaks the original's raw byte
    /// offsets (+0x14/+0x1c/+0x20/+0x24), which coincide with the
    /// typed [`Mem`] only on the 32-bit target — running it against
    /// a host-layout `Mem` would free through the wrong fields.
    /// Releasing is `mem_release`'s own tested contract, not this
    /// function's.
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

    /// Takes the shared slot lock (vdbe_mem_set_int64's tests swap
    /// the same `MEM_SET_OPS` slot), installs the recording guts
    /// release and zeroes its counters. The guards must stay alive
    /// for the whole test.
    fn bench() -> (MutexGuard<'static, ()>, OpsGuard) {
        let ops_guard = super::super::vdbe_mem_set_int64::tests::ops_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
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

    /// A `Mem` with distinguishable garbage in every field, so an
    /// unintended write shows up as a mismatch. (The ownership
    /// pointers can be garbage too: the recording mock never touches
    /// the cell, and the NaN path's set-null writes only
    /// `flags`/`value_type`.)
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

    #[test]
    fn value_lands_in_the_real_arm_bit_for_bit() {
        let _guards = bench();
        // Edge cases: ±zero, ±1, the subnormal boundary, the largest
        // subnormal, the infinities (NOT NaN — they must be stored),
        // the finite extremes and an arbitrary bit pattern.
        let bit_patterns = [
            0x0000_0000_0000_0000u64, // +0.0
            0x8000_0000_0000_0000, // -0.0
            0x3ff0_0000_0000_0000, // 1.0
            0xbff0_0000_0000_0000, // -1.0
            0x0000_0000_0000_0001, // smallest subnormal
            0x000f_ffff_ffff_ffff, // largest subnormal
            0x0010_0000_0000_0000, // smallest normal
            0x7fef_ffff_ffff_ffff, // f64::MAX
            0xffef_ffff_ffff_ffff, // f64::MIN
            0x7ff0_0000_0000_0000, // +inf
            0xfff0_0000_0000_0000, // -inf
            0x3fd5_5555_5555_5555, // arbitrary
        ];
        for bits in bit_patterns {
            let value = f64::from_bits(bits);
            let mut mem = garbage_mem(0, 0);
            unsafe { vdbe_mem_set_double(&mut mem, value) };
            assert_eq!(mem.r.to_bits(), bits, "bits={bits:#018x}");
        }
    }

    #[test]
    fn flags_are_assigned_mem_real_outright_for_every_prior_value() {
        let _guards = bench();
        // Exhaustive over the whole u16 flags space: like the int64
        // sibling, the observable contract is exactly
        // `flags = MEM_Real` — no attribute bit survives.
        let mut mem = garbage_mem(0, 0);
        for flags in 0..=u16::MAX {
            mem.flags = flags;
            unsafe { vdbe_mem_set_double(&mut mem, 1.5) };
            assert_eq!(mem.flags, MEM_REAL, "flags={flags:#06x}");
        }
    }

    #[test]
    fn value_type_becomes_sqlite_float_for_every_prior_type() {
        let _guards = bench();
        let mut mem = garbage_mem(0, 0);
        for value_type in 0..=u8::MAX {
            mem.value_type = value_type;
            unsafe { vdbe_mem_set_double(&mut mem, 1.5) };
            assert_eq!(mem.value_type, SQLITE_FLOAT, "type={value_type:#04x}");
        }
    }

    #[test]
    fn old_guts_are_released_through_mem_release_exactly_once() {
        // The guts release must run exactly once per non-NaN call,
        // on the cell itself — the observable trace of the
        // `bl 0x0838c04c` prologue.
        let _guards = bench();
        let mut mem = garbage_mem(0, 0);
        unsafe { vdbe_mem_set_double(&mut mem, -0.25) };
        assert_eq!(unsafe { RELEASE_CALLS }, 1);
        assert_eq!(unsafe { RELEASE_ARG }, core::ptr::addr_of!(mem) as usize);
    }

    #[test]
    fn nan_routes_to_set_null_and_releases_nothing() {
        let _guards = bench();
        // NaN payloads: canonical, signaling, negative, an all-ones
        // payload, and the garbage_mem seed NaN itself. Every one
        // must take the set-null tail: flags' type bits replaced by
        // MEM_Null (attribute bits survive — set_null's
        // read-modify-write, not this function's outright assign),
        // type = SQLITE_NULL, and NO release.
        let nan_bits = [
            0x7ff8_0000_0000_0000u64, // canonical NaN
            0xfff8_0000_0000_0000, // negative NaN
            0x7ff0_0000_0000_0001, // signaling NaN
            0x7fff_ffff_ffff_ffff, // all-ones payload
            0x7ff8_0000_5a5a_5a5a, // the garbage seed NaN
        ];
        for (i, bits) in nan_bits.iter().enumerate() {
            let prior_flags = 0x0fe0u16 | (i as u16); // attribute bits set, type bits vary
            let mut mem = garbage_mem(prior_flags, 0x5a);
            unsafe { vdbe_mem_set_double(&mut mem, f64::from_bits(*bits)) };
            assert_eq!(
                mem.flags,
                (prior_flags & !MEM_TYPE_BITS) | MEM_NULL,
                "bits={bits:#018x}"
            );
            assert_eq!(mem.value_type, SQLITE_NULL, "bits={bits:#018x}");
            assert_eq!(unsafe { RELEASE_CALLS }, 0, "NaN must not release");
            // The NaN never lands in the real arm, and set_null
            // touches nothing else.
            assert_eq!(mem.r.to_bits(), 0x7ff8_0000_5a5a_5a5a, "bits={bits:#018x}");
            assert_eq!(mem.u, 0x0bad_cafe_dead_beef, "bits={bits:#018x}");
        }
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
        unsafe { vdbe_mem_set_double(&mut mem, -2.5) };
        assert_eq!(mem.u, before.u);
        assert_eq!(mem.db, before.db);
        assert_eq!(mem.n, before.n);
        assert_eq!(mem.enc, before.enc);
    }
}
