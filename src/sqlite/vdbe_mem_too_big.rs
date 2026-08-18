//! Size-limit check — how the engine decides whether a `Mem`/
//! `sqlite3_value` cell's string/blob payload exceeds the connection's
//! `SQLITE_LIMIT_LENGTH` ceiling.
//!
//! - `vdbe_mem_too_big` — original: `FUN_0838c3cc` @ 0x0838c3cc
//!   (76 bytes, 0x0838c3cc..0x0838c418; **2 `bl` call sites**,
//!   binary-scanned from osos.dec — no predicated or tail branches).
//!   Upstream SQLite 3.5.x's `sqlite3VdbeMemTooBig` (`int
//!   sqlite3VdbeMemTooBig(Mem *p)` in vdbemem.c). It sits immediately
//!   after [`vdbe_mem_stringify`](super::vdbe_mem_stringify) @
//!   0x0838c32c (and its inline format literals) in the vdbe Mem
//!   helper cluster, and is the gate the vdbe engine runs before
//!   materializing an oversized TEXT/BLOB result.
//!
//! ### Extent
//!
//! Confirmed from raw words: 0x0838c414 is the `ldmia sp!, {r4,pc}`
//! return and 0x0838c418 begins the next function (`stmdb sp!,
//! {r3,r4,r5,r6,r7,r8,r9,r10,r11,lr}`). No literal pool — every
//! constant is an immediate.
//!
//! ### Listing
//!
//! ```text
//! 0838c3cc  stmdb sp!, {r4,lr}
//! 0838c3d0  ldrh r1,[r0,#0x1c]      @ flags, sampled ONCE
//! 0838c3d4  mov  r4,r0              @ pMem
//! 0838c3d8  tst  r1,#0x12           @ MEM_Str|MEM_Blob?
//! 0838c3dc  beq  0x0838c410
//! 0838c3e0  ldr  r0,[r4,#0x18]      @ n
//! 0838c3e4  tst  r1,#0x800          @ MEM_Zero?
//! 0838c3e8  beq  0x0838c3fc
//! 0838c3ec  mov  r2,r0
//! 0838c3f0  ldrd r0,r1,[r4,#0x0]    @ Mem.u, both words
//! 0838c3f4  adds r0,r0,r2           @ n += low32(u)
//! 0838c3f8  adc  r1,r1,r2, asr #0x1f @ (high half is dead — r1 is
//!                                   @  reloaded below before the cmp)
//! 0838c3fc  ldr  r1,[r4,#0x10]      @ db
//! 0838c400  ldr  r1,[r1,#0x50]      @ db->aLimit[SQLITE_LIMIT_LENGTH]
//! 0838c404  cmp  r1,r0
//! 0838c408  movlt r0,#0x1
//! 0838c40c  ldmialt sp!, {r4,pc}
//! 0838c410  mov  r0,#0x0
//! 0838c414  ldmia sp!, {r4,pc}
//! ```
//!
//! ### Algorithm
//!
//! The cell's flags are sampled once, up front, and both tests run
//! off that single halfword. Only string/blob cells (`MEM_Str` 0x02
//! or `MEM_Blob` 0x10) have a length to check — anything else returns
//! 0 without touching `db`. The payload size is `n`; a zero-tail blob
//! (`MEM_Zero` 0x800) adds the union's integer arm (`Mem.u`, the
//! pending `zeroblob` count) to it. The original computes that sum
//! as a 64-bit `adds`/`adc` pair over both `u` words, but the high
//! half is dead: `r1` is reloaded with `db` before the comparison,
//! so the verdict is the 32-bit signed `limit < n_total` — the
//! wrapping low-word add is the whole story. The limit itself is the
//! connection's `aLimit[SQLITE_LIMIT_LENGTH]` word at db+0x50 (the
//! same word [`sqlite_vm_printf`](super::vm_printf) reads). Returns
//! 1 when the payload is too big, 0 otherwise. Strictly greater:
//! `limit == n_total` is still small enough.
//!
//! Call sites (binary-scanned, both inside FUN_08386ef8, the 16 KB
//! vdbe engine routine spanning 0x08386ef8..0x0838b064):
//!
//! - `bl` @ 0x083874a4 — OP_Column-style result materialization.
//! - `bl` @ 0x0838aca8 — a second result-path check in the same
//!   routine.
//!
//! ### Deviations
//!
//! - The port goes through the typed `repr(C)` [`Mem`] with named
//!   fields rather than raw offsets; field offsets are statically
//!   asserted on 32-bit targets in `sqlite/vdbe.rs`. The `db+0x50`
//!   limit is a byte offset into the opaque connection, reached the
//!   same way [`super::vm_printf`] reaches it — host-independent.
//! - The dead 64-bit high half of the original's `adds`/`adc` is not
//!   reproduced; the port performs the observable 32-bit wrapping add
//!   of `low32(u)` directly.
//! - The original takes `Mem *` in `r0` and never writes through it;
//!   the port's parameter is `*const Mem`.

use super::value_text::MEM_ZERO;
use super::vdbe::Mem;
use super::vdbe_mem_set_str::{MEM_BLOB, MEM_STR};
use super::vm_printf::DB_LENGTH_LIMIT_OFFSET;

/// The string-or-blob type mask (original: `tst r1,#0x12` — only
/// these cells carry a byte length worth limiting).
pub const MEM_STR_OR_BLOB: u16 = MEM_STR | MEM_BLOB;

/// vdbe_mem_too_big — original: `FUN_0838c3cc` @ 0x0838c3cc (76
/// bytes; 2 `bl` call sites).
///
/// `sqlite3VdbeMemTooBig`: report 1 when the string/blob cell
/// `p_mem`'s payload — `n` bytes plus, for a `MEM_Zero` zero-tail
/// blob, the pending zero count in the low word of `Mem.u` — exceeds
/// the owning connection's `aLimit[SQLITE_LIMIT_LENGTH]` (db+0x50),
/// 0 otherwise. Non-string/blob cells are never too big and `db` is
/// never dereferenced for them.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vdbe_mem_too_big(p_mem: *const Mem) -> i32 {
    let mem = &*p_mem;
    // Original: `ldrh r1,[r0,#0x1c]` once at entry; both tests below
    // run off that single sample.
    let flags = mem.flags;
    if flags & MEM_STR_OR_BLOB != 0 {
        let mut n_total = mem.n;
        if flags & MEM_ZERO != 0 {
            // Original: `ldrd` + `adds`/`adc` whose high half is dead
            // (r1 is reloaded with db before the cmp) — the wrapping
            // low-word add is the whole story.
            n_total = (mem.u as u32 as i32).wrapping_add(n_total);
        }
        // Original: `ldr r1,[r4,#0x10]; ldr r1,[r1,#0x50]`.
        let limit = mem.db.add(DB_LENGTH_LIMIT_OFFSET).cast::<i32>().read();
        // Original: `cmp r1,r0; movlt r0,#0x1` — signed, strictly
        // greater is too big.
        if limit < n_total {
            return 1;
        }
    }
    0
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;

    /// A stand-in `sqlite3` connection covering the length-limit word
    /// at +0x50. 4-aligned so the port's limit load matches the
    /// original's aligned `ldr`.
    #[repr(align(4))]
    struct Db([u8; DB_LENGTH_LIMIT_OFFSET + 4]);

    impl Db {
        fn with_limit(limit: i32) -> Self {
            let mut db = Db([0u8; DB_LENGTH_LIMIT_OFFSET + 4]);
            db.0[DB_LENGTH_LIMIT_OFFSET..DB_LENGTH_LIMIT_OFFSET + 4]
                .copy_from_slice(&limit.to_le_bytes());
            db
        }
    }

    /// Builds a cell with the given flags/n/u hanging off `db`. The
    /// remaining fields are garbage so an unintended read stands out.
    fn mem_with(db: *mut u8, flags: u16, n: i32, u: u64) -> Mem {
        Mem {
            u,
            r: f64::from_bits(0x7ff8_0000_5a5a_5a5a),
            db,
            z: 0x0bad_2000usize as *mut u8,
            n,
            flags,
            value_type: 0xa6,
            enc: 0xa7,
            x_del: 0x0bad_3000usize as *mut u8,
            z_malloc: 0x0bad_4000usize as *mut u8,
        }
    }

    #[test]
    fn only_string_or_blob_cells_are_checked() {
        // Exhaustive over every flags value: with n strictly over the
        // limit the verdict is 1 exactly when MEM_Str|MEM_Blob shows.
        let mut db = Db::with_limit(100);
        let db_ptr = db.0.as_mut_ptr();
        for flags in 0u32..=0xffff {
            let mem = mem_with(db_ptr, flags as u16, 101, 0);
            let expect = i32::from(flags as u16 & MEM_STR_OR_BLOB != 0);
            assert_eq!(
                unsafe { vdbe_mem_too_big(&mem) },
                expect,
                "flags = {flags:#06x}"
            );
        }
    }

    #[test]
    fn at_or_under_the_limit_is_small_enough() {
        let mut db = Db::with_limit(100);
        let db_ptr = db.0.as_mut_ptr();
        for flags in [MEM_STR, MEM_BLOB, MEM_STR | MEM_BLOB] {
            for n in [0, 1, 99, 100] {
                let mem = mem_with(db_ptr, flags, n, 0);
                assert_eq!(unsafe { vdbe_mem_too_big(&mem) }, 0, "flags={flags:#x} n={n}");
            }
            // Strictly greater is too big; the boundary itself is not.
            let mem = mem_with(db_ptr, flags, 101, 0);
            assert_eq!(unsafe { vdbe_mem_too_big(&mem) }, 1, "flags={flags:#x} n=101");
        }
    }

    #[test]
    fn negative_sizes_are_never_too_big() {
        // Signed comparison: a negative n_total is below any limit,
        // and a negative limit still gates a positive n.
        let mut db = Db::with_limit(100);
        let db_ptr = db.0.as_mut_ptr();
        for n in [-1, -100, i32::MIN] {
            let mem = mem_with(db_ptr, MEM_STR, n, 0);
            assert_eq!(unsafe { vdbe_mem_too_big(&mem) }, 0, "n={n}");
        }
        let mut db = Db::with_limit(-1);
        let db_ptr = db.0.as_mut_ptr();
        let mem = mem_with(db_ptr, MEM_STR, 0, 0);
        assert_eq!(unsafe { vdbe_mem_too_big(&mem) }, 1, "limit=-1 n=0");
        let mem = mem_with(db_ptr, MEM_STR, -1, 0);
        assert_eq!(unsafe { vdbe_mem_too_big(&mem) }, 0, "limit=-1 n=-1");
    }

    #[test]
    fn zero_tail_counts_toward_the_limit() {
        // MEM_Zero adds low32(Mem.u) to n; without the flag u is
        // ignored entirely.
        let mut db = Db::with_limit(100);
        let db_ptr = db.0.as_mut_ptr();
        for flags in [MEM_BLOB, MEM_STR] {
            // 60 + 41 = 101 > 100: too big only with MEM_Zero.
            let with_zero = mem_with(db_ptr, flags | MEM_ZERO, 60, 41);
            assert_eq!(unsafe { vdbe_mem_too_big(&with_zero) }, 1, "flags={flags:#x}+zero");
            let without_zero = mem_with(db_ptr, flags, 60, 41);
            assert_eq!(unsafe { vdbe_mem_too_big(&without_zero) }, 0, "flags={flags:#x}");
            // 60 + 40 = 100 == limit: still small enough.
            let at_limit = mem_with(db_ptr, flags | MEM_ZERO, 60, 40);
            assert_eq!(unsafe { vdbe_mem_too_big(&at_limit) }, 0, "flags={flags:#x}+zero at limit");
        }
    }

    #[test]
    fn zero_tail_uses_only_the_low_word_and_wraps() {
        let mut db = Db::with_limit(100);
        let db_ptr = db.0.as_mut_ptr();
        // The high half of Mem.u is dead in the original (r1 is
        // reloaded with db before the cmp): u = 2^32 adds nothing.
        let mem = mem_with(db_ptr, MEM_BLOB | MEM_ZERO, 60, 0x1_0000_0000);
        assert_eq!(unsafe { vdbe_mem_too_big(&mem) }, 0, "high half of u ignored");
        // The 32-bit add wraps: i32::MAX + 60 wraps negative, which
        // is below the limit.
        let mem = mem_with(db_ptr, MEM_BLOB | MEM_ZERO, 60, i32::MAX as u64);
        assert_eq!(unsafe { vdbe_mem_too_big(&mem) }, 0, "wrapping low-word add");
    }

    #[test]
    fn the_cell_and_connection_are_not_written() {
        let mut db = Db::with_limit(100);
        let db_ptr = db.0.as_mut_ptr();
        let mem = mem_with(db_ptr, MEM_BLOB | MEM_ZERO, 60, 41);
        let before = Mem { ..unsafe { core::ptr::read(&mem) } };
        assert_eq!(unsafe { vdbe_mem_too_big(&mem) }, 1);
        assert_eq!(mem.u, before.u);
        assert_eq!(mem.r.to_bits(), before.r.to_bits());
        assert_eq!(mem.n, before.n);
        assert_eq!(mem.flags, before.flags);
        assert_eq!(mem.z, before.z);
        assert_eq!(mem.enc, before.enc);
        let mut expect_db = Db::with_limit(100).0.to_vec();
        expect_db.shrink_to_fit();
        assert_eq!(db.0.to_vec(), expect_db, "connection bytes untouched");
    }
}
