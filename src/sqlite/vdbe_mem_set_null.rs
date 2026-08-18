//! NULL-ing a value cell — how the engine turns an existing
//! `Mem`/`sqlite3_value` into the SQL NULL datum without touching its
//! payload pointers.
//!
//! - `vdbe_mem_set_null` — original: `FUN_0838c13c` @ 0x0838c13c
//!   (28 bytes, 0x0838c13c..0x0838c158; **4 `bl` call sites plus one
//!   tail-`b`**, binary-scanned from osos.dec — no predicated
//!   entries). Upstream SQLite's `sqlite3VdbeMemSetNull`
//!   (`void sqlite3VdbeMemSetNull(Mem *pMem)` in vdbemem.c) — the
//!   "delete any previous value and set the value stored in *pMem to
//!   NULL" primitive. The house seam docs already name it:
//!   `sqlite/value_set_str.rs` documents `sqlite3VdbeMemSetStr` @
//!   0x0838c158 routing a NULL `z` to "MemSetNull @ 0x0838c13c".
//!
//! ### Extent
//!
//! Confirmed from raw words: 0x0838c154 is `bx lr` and the next word,
//! 0x0838c158, is the `stmdb sp!, {r4,r5,lr}` entry of
//! `sqlite3VdbeMemSetStr`. No literal pool — the function needs none.
//!
//! ### Listing
//!
//! ```text
//! 0838c13c  ldrh r1, [r0, #0x1c]   @ flags
//! 0838c140  bic  r1, r1, #0x1f     @ drop the five type bits
//! 0838c144  orr  r1, r1, #0x1      @ MEM_Null
//! 0838c148  strh r1, [r0, #0x1c]
//! 0838c14c  mov  r1, #0x5          @ SQLITE_NULL
//! 0838c150  strb r1, [r0, #0x1e]   @ type
//! 0838c154  bx   lr
//! ```
//!
//! ### Algorithm
//!
//! Two stores, no branches, no calls. The `flags` halfword at +0x1c is
//! read-modify-written: the low five bits — this build's type bits
//! `MEM_Null` (0x1) / `MEM_Str` (0x2) / `MEM_Int` (0x4) / `MEM_Real`
//! (0x8) / `MEM_Blob` (0x10), exactly the `bic #0x1f` mask — are
//! cleared and `MEM_Null` is set, while every attribute/ownership bit
//! above survives (this build's numbering, recovered by the sibling
//! ports: `MEM_Term` 0x20 and `MEM_Dyn` 0x40 from
//! `sqlite3VdbeMemSetStr`, `MEM_Static` 0x80 likewise, `MEM_Agg` 0x400
//! from the extern release @ 0x0838c074, `MEM_Zero` 0x800 from the
//! zero-blob grow @ 0x0838bbb4's `& 0xf7df`). That is the read-
//! modify-write form of upstream's helper (later upstreams spell it
//! `MemSetTypeFlag(pMem, MEM_Null)`); the textbook early-3.x form
//! assigns `flags = MEM_Null` outright, which this binary does not do.
//! Then `type` at +0x1e becomes `SQLITE_NULL` (5).
//!
//! Nothing is released here: `z`/`zMalloc`/`xDel` stay put, so a cell
//! that still owns a buffer keeps owning it — releasing is the
//! caller's job (the `mem_release` @ 0x0838c04c family).
//!
//! Call sites (binary-scanned):
//!
//! - 0x0838c178 — inside `sqlite3VdbeMemSetStr` @ 0x0838c158: the
//!   `z == NULL` route documented in `sqlite/value_set_str.rs`.
//! - 0x0838a2d0 and 0x0838ac38 — inside FUN_08386ef8, the 16 KB vdbe
//!   routine (two sites).
//! - 0x083911b4 — inside FUN_083911a8, the out-of-memory marker: it
//!   NULLs an embedded `Mem` at +8, stamps `SQLITE_NOMEM` (7) at +0x34
//!   and sets the `mallocFailed` byte (+0x1e) of the connection at
//!   +0x18.
//! - tail `b` @ 0x0839121c — a thunk at 0x08391218
//!   (`add r0, r0, #8; b 0x0838c13c`) that NULLs the embedded `Mem`
//!   eight bytes into its argument.
//!
//! ### Deviations
//!
//! None beyond the typed struct: the port goes through the `repr(C)`
//! [`Mem`] with named fields (whose +0x1c/+0x1e offsets are statically
//! asserted on 32-bit targets in `sqlite/vdbe.rs`) rather than raw
//! byte offsets, so the host build's wider pointer fields cannot shift
//! the two bytes this function touches. Constants are reused from
//! `sqlite/value_new.rs`, which owns `MEM_NULL` and `SQLITE_NULL`.

use super::value_new::{MEM_NULL, SQLITE_NULL};
use super::vdbe::Mem;

/// This build's five `Mem.flags` type bits — `MEM_Null` (0x1) through
/// `MEM_Blob` (0x10) — the field the original clears with
/// `bic r1, r1, #0x1f`. Everything above (termination, ownership,
/// aggregate, zero-blob) is an attribute the NULL-ing preserves.
pub const MEM_TYPE_BITS: u16 = 0x001f;

/// vdbe_mem_set_null — original: `FUN_0838c13c` @ 0x0838c13c (28
/// bytes; 4 `bl` call sites plus one tail-`b`).
///
/// `sqlite3VdbeMemSetNull`: make `p_mem` the SQL NULL datum. The five
/// type bits of `flags` are replaced by `MEM_Null` — every other flag
/// bit survives — and `value_type` becomes `SQLITE_NULL`. Payload and
/// ownership fields (`z`, `n`, `enc`, `x_del`, `z_malloc`, the value
/// union) are deliberately untouched.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vdbe_mem_set_null(p_mem: *mut Mem) {
    let mem = &mut *p_mem;
    mem.flags = (mem.flags & !MEM_TYPE_BITS) | MEM_NULL;
    mem.value_type = SQLITE_NULL;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `Mem` with distinguishable garbage in every field, so an
    /// unintended write shows up as a mismatch.
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
    fn type_bits_are_replaced_by_mem_null_for_every_flags_value() {
        // Exhaustive over the whole u16 flags space: the observable
        // contract is exactly `flags = (flags & !0x1f) | MEM_Null`.
        let mut mem = garbage_mem(0, 0);
        for flags in 0..=u16::MAX {
            mem.flags = flags;
            unsafe { vdbe_mem_set_null(&mut mem) };
            assert_eq!(
                mem.flags,
                (flags & !MEM_TYPE_BITS) | MEM_NULL,
                "flags={flags:#06x}"
            );
        }
    }

    #[test]
    fn value_type_becomes_sqlite_null_for_every_prior_type() {
        let mut mem = garbage_mem(0, 0);
        for value_type in 0..=u8::MAX {
            mem.value_type = value_type;
            unsafe { vdbe_mem_set_null(&mut mem) };
            assert_eq!(mem.value_type, SQLITE_NULL, "type={value_type:#04x}");
        }
    }

    #[test]
    fn attribute_bits_above_the_type_field_survive() {
        // Spot-check the recovered attribute bits individually and in
        // combination, over a base that mixes in every type bit.
        let attribute_bits = [0x0020u16, 0x0040, 0x0080, 0x0400, 0x0800, 0xffff & !MEM_TYPE_BITS];
        for attrs in attribute_bits {
            let mut mem = garbage_mem(attrs | MEM_TYPE_BITS, 0);
            unsafe { vdbe_mem_set_null(&mut mem) };
            assert_eq!(mem.flags, attrs | MEM_NULL, "attrs={attrs:#06x}");
        }
    }

    #[test]
    fn every_other_field_is_byte_for_byte_untouched() {
        let before = garbage_mem(0x0fff, 0xa5);
        let mut mem = garbage_mem(0x0fff, 0xa5);
        unsafe { vdbe_mem_set_null(&mut mem) };
        assert_eq!(mem.u, before.u);
        assert_eq!(mem.r.to_bits(), before.r.to_bits());
        assert_eq!(mem.db, before.db);
        assert_eq!(mem.z, before.z);
        assert_eq!(mem.n, before.n);
        assert_eq!(mem.enc, before.enc);
        assert_eq!(mem.x_del, before.x_del);
        assert_eq!(mem.z_malloc, before.z_malloc);
    }
}
