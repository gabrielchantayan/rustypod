//! Shallow copy — how the engine duplicates a `Mem`/`sqlite3_value`
//! cell's *value* into another cell while the destination keeps its
//! own allocation buffer (`zMalloc`).
//!
//! - `vdbe_mem_shallow_copy` — original: `FUN_0838c2d0` @ 0x0838c2d0
//!   (92 bytes, 0x0838c2d0..0x0838c32c; **2 `bl` call sites plus one
//!   `bleq`**, binary-scanned from osos.dec — no tail branches).
//!   Upstream SQLite 3.5.x's `sqlite3VdbeMemShallowCopy` (`void
//!   sqlite3VdbeMemShallowCopy(Mem *pTo, const Mem *pFrom, int
//!   srcType)` in vdbemem.c, whose `MEMCELLSIZE` copy is exactly the
//!   0x24 bytes here). It sits between
//!   [`vdbe_mem_set_str`](super::vdbe_mem_set_str) @ 0x0838c158 and
//!   `sqlite3VdbeMemStringify` @ 0x0838c32c in the vdbe Mem helper
//!   cluster, and is how OP_Column-style code hands a value from the
//!   row cache to an output register without moving the payload.
//!
//! ### Extent
//!
//! Confirmed from raw words: 0x0838c328 is `ldmia sp!, {r4,r5,r6,pc}`
//! and the next word, 0x0838c32c, is the `stmdb sp!,
//! {r2,r3,r4,r5,r6,r7,r8,lr}` entry of `sqlite3VdbeMemStringify`. No
//! literal pool — every constant is an immediate.
//!
//! ### Listing
//!
//! ```text
//! 0838c2d0  stmdb sp!, {r4,r5,r6,lr}
//! 0838c2d4  mov  r6,r2              @ src_type
//! 0838c2d8  mov  r5,r1              @ p_from
//! 0838c2dc  mov  r4,r0              @ p_to
//! 0838c2e0  bl   0x0838c074         @ mem_extern_release: drop old externals
//! 0838c2e4  mov  r2,#0x24
//! 0838c2e8  mov  r1,r5
//! 0838c2ec  mov  r0,r4
//! 0838c2f0  bl   0x08037df8         @ memcpy veneer: 0x24 bytes, all but zMalloc
//! 0838c2f4  mov  r0,#0x0
//! 0838c2f8  str  r0,[r4,#0x20]      @ xDel = NULL
//! 0838c2fc  ldrh r0,[r5,#0x1c]
//! 0838c300  tst  r0,#0x40           @ p_from->flags & MEM_Dyn?
//! 0838c304  bne  0x0838c318
//! 0838c308  ldr  r0,[r5,#0x14]!     @ z (writeback: r5 += 0x14)
//! 0838c30c  ldr  r1,[r5,#0x10]      @ zMalloc (now at +0x10)
//! 0838c310  cmp  r0,r1
//! 0838c314  ldmiane sp!, {r4,r5,r6,pc}  @ z != zMalloc: keep copied flags
//! 0838c318  ldrh r0,[r4,#0x1c]
//! 0838c31c  bic  r0,r0,#0x1c0       @ drop MEM_Dyn|MEM_Static|MEM_Ephem
//! 0838c320  orr  r0,r0,r6           @ ... and take the caller's ownership
//! 0838c324  strh r0,[r4,#0x1c]
//! 0838c328  ldmia sp!, {r4,r5,r6,pc}
//! ```
//!
//! ### Algorithm
//!
//! First the extern release @ 0x0838c074
//! ([`mem_extern_release`](super::mem_extern_release)) runs on the
//! *destination* — finalizing an aggregate context or invoking the old
//! `xDel` destructor — but `zMalloc` is deliberately NOT freed: the
//! shallow copy keeps the destination's allocation buffer for reuse
//! (freeing it is `mem_release` @ 0x0838c04c's job, which the numeric
//! setters call instead). Then 0x24 bytes are copied from source to
//! destination — the whole 0x28-byte `Mem` except the `zMalloc` word
//! at +0x24 (upstream's `MEMCELLSIZE` = `offsetof(Mem, zMalloc)`) — so
//! `u`/`r`/`db`/`z`/`n`/`flags`/`type`/`enc`/`xDel` all become the
//! source's. `xDel` is immediately NULLed: the destination never owns
//! the source's external storage.
//!
//! The ownership restamp is conditional. When the source holds its
//! payload externally (`MEM_Dyn`, 0x40) or in its own `zMalloc`
//! (`z == zMalloc` — the destination just copied a `z` pointing into
//! the *source's* buffer), the copied ownership bits cannot stand:
//! `MEM_Dyn`|`MEM_Static`|`MEM_Ephem` (0x1c0) are cleared and replaced
//! by the caller's `src_type` (0x80 = `MEM_Static`, 0x100 =
//! `MEM_Ephem` at the call sites). Otherwise — the source's `z` is
//! borrowed static/ephemeral storage with no destructor — the copied
//! flags are already correct and the function returns early
//! (`ldmiane`).
//!
//! Call sites (binary-scanned, all inside FUN_08386ef8, the 16 KB vdbe
//! routine):
//!
//! - `bl` @ 0x083874c0 — `src_type = 0x80` (`MEM_Static`): column value
//!   into the register at `[r5,#0x38] + index*0x28`.
//! - `bl` @ 0x0838752c — `src_type = 0x100` (`MEM_Ephem`): same shape
//!   over the `[r5,#0x4c]` array, followed by a `MEM_Ephem` test that
//!   makes the copy writeable through 0x0838bb30.
//! - `bleq` @ 0x0838851c — `src_type = 0x80` (`MEM_Static`), gated on a
//!   sign-extended byte at +1 equalling -8.
//!
//! ### Deviations
//!
//! - The port goes through the `repr(C)` [`Mem`] with named fields
//!   (whose offsets are statically asserted on 32-bit targets in
//!   `sqlite/vdbe.rs`) rather than the original's raw 0x24-byte
//!   `memcpy`: `*to = *from` with `z_malloc` saved and restored is the
//!   same field set, and the host build's wider pointer fields stay
//!   coherent (a raw 9-word copy of the ARM layout would tear them).
//!   The ROM veneer @ 0x08037df8 targets
//!   [`memcpy_forward_words`](crate::libc::memcpy::memcpy_forward_words);
//!   LLVM lowers the typed struct copy itself.
//! - [`mem_extern_release`] @ 0x0838c074 IS ported and is the shipped
//!   default of the [`SHALLOW_COPY_OPS`] slot; the slot is kept so
//!   host tests can intercept it — the ported extern release speaks
//!   the original's raw byte offsets, which coincide with the typed
//!   [`Mem`] only on the 32-bit target, so a host test running the
//!   real one against a host-layout `Mem` would read the wrong fields
//!   (the same reason `vdbe_mem_set_int64` keeps its `MEM_SET_OPS`
//!   slot).

use super::mem_extern_release::mem_extern_release;
use super::mem_release::FLAG_DYN;
use super::vdbe::{Mem, MEM_STATIC};

/// `MEM_Ephem`: the payload lives in an ephemeral buffer the next vdbe
/// step overwrites, so it must be copied before then (original: the
/// 0x100 arm of the `bic r0, r0, #0x1c0` ownership mask, and the
/// `src_type` of the 0x0838752c call site). This build's `MEM_*`
/// numbering is its own — see [`Mem`]'s header in `sqlite/vdbe.rs`.
pub const MEM_EPHEM: u16 = 0x0100;

/// The three ownership bits the restamp clears — `MEM_Dyn` (0x40) |
/// `MEM_Static` (0x80) | `MEM_Ephem` (0x100) — the original's
/// `bic r0, r0, #0x1c0`.
pub const MEM_OWNERSHIP_BITS: u16 = FLAG_DYN | MEM_STATIC | MEM_EPHEM;

/// Bytes the original copies — the whole `Mem` except `zMalloc`
/// (original: `mov r2, #0x24`; upstream's `MEMCELLSIZE`).
pub const SHALLOW_COPY_SIZE: usize = 0x24;

/// vdbe_mem_shallow_copy — original: `FUN_0838c2d0` @ 0x0838c2d0 (92
/// bytes; 2 `bl` call sites plus one `bleq`).
///
/// `sqlite3VdbeMemShallowCopy`: make `p_to` hold `p_from`'s value
/// without transferring payload ownership. The destination's external
/// resources are released first (the [`SHALLOW_COPY_OPS`] slot), then
/// every field but `z_malloc` is copied — the destination keeps its
/// own allocation buffer — and `x_del` is NULLed. When the source's
/// payload is externally owned (`MEM_Dyn`) or lives in the source's
/// own `z_malloc`, the copied ownership bits are replaced by
/// `src_type`; otherwise they stand. `src_type` is stored verbatim —
/// the original `orr`s it in with no mask of its own.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vdbe_mem_shallow_copy(p_to: *mut Mem, p_from: *const Mem, src_type: u16) {
    (extern_release_op())(p_to as *mut u8);
    let to = &mut *p_to;
    let from = &*p_from;
    let z_malloc = to.z_malloc;
    core::ptr::write(to, core::ptr::read(from));
    to.z_malloc = z_malloc;
    to.x_del = core::ptr::null_mut();
    if (from.flags & FLAG_DYN) != 0 || from.z == from.z_malloc {
        to.flags = (to.flags & !MEM_OWNERSHIP_BITS) | src_type;
    }
}

/// Indirect dispatch for the extern release @ 0x0838c074 (kept behind
/// the table so host tests can intercept it — see the module header).
#[derive(Clone, Copy)]
pub struct ShallowCopyOps {
    /// `vdbeMemClearExternAndSetNull(value)` @ 0x0838c074: finalize an
    /// aggregate context or invoke the `xDel` destructor of the
    /// *destination* cell, without touching its `zMalloc`. Ported
    /// ([`mem_extern_release`]) and the shipped default.
    pub extern_release: unsafe extern "C" fn(value: *mut u8),
}

/// Wired default: the ported extern release @ 0x0838c074
/// ([`mem_extern_release`]).
pub const DEFAULT_SHALLOW_COPY_OPS: ShallowCopyOps = ShallowCopyOps {
    extern_release: mem_extern_release,
};

/// The active extern release. Host tests install recording mocks.
pub static mut SHALLOW_COPY_OPS: ShallowCopyOps = DEFAULT_SHALLOW_COPY_OPS;

/// Reads the extern-release slot (volatile — the slot is meant to be
/// swapped at runtime, and a plain read lets LLVM const-fold the
/// default away).
#[inline(always)]
pub(crate) unsafe fn extern_release_op() -> unsafe extern "C" fn(*mut u8) {
    core::ptr::read_volatile(core::ptr::addr_of!(SHALLOW_COPY_OPS.extern_release))
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::sync::{Mutex, MutexGuard};

    /// Serializes tests that swap the extern-release slot.
    static OPS_LOCK: Mutex<()> = Mutex::new(());

    /// A `Mem` with distinguishable garbage in every field, so an
    /// unintended write shows up as a mismatch. `z`/`z_malloc` are the
    /// caller's: ownership cases need them equal or not.
    fn garbage_mem(flags: u16, value_type: u8, z: *mut u8, z_malloc: *mut u8) -> Mem {
        Mem {
            u: 0x0bad_cafe_dead_beef,
            r: f64::from_bits(0x7ff8_0000_5a5a_5a5a),
            db: 0x0bad_1000usize as *mut u8,
            z,
            n: -123_456_789,
            flags,
            value_type,
            enc: 0xa7,
            x_del: 0x0bad_3000usize as *mut u8,
            z_malloc,
        }
    }

    /// Records extern-release calls so the test can prove the
    /// `bl 0x0838c074` prologue ran, on the destination, before the
    /// copy. The recording mock also stands in for the real
    /// `mem_extern_release` on host: the ported release speaks the
    /// original's raw byte offsets (+0x00/+0x14/+0x1c/+0x20), which
    /// coincide with the typed [`Mem`] only on the 32-bit target —
    /// running it against a host-layout `Mem` would read the wrong
    /// fields. Releasing is `mem_extern_release`'s own tested
    /// contract, not this function's.
    static mut RELEASE_CALLS: u32 = 0;
    static mut RELEASE_ARG: usize = 0;
    static mut RELEASE_SAW_FLAGS: u16 = 0;
    static mut RELEASE_SAW_U: u64 = 0;

    unsafe extern "C" fn recording_extern_release(value: *mut u8) {
        unsafe {
            RELEASE_CALLS += 1;
            RELEASE_ARG = value as usize;
            let mem = &*(value as *const Mem);
            RELEASE_SAW_FLAGS = mem.flags;
            RELEASE_SAW_U = mem.u;
        }
    }

    /// Restores the wired default extern release on drop.
    struct OpsGuard;

    impl Drop for OpsGuard {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(SHALLOW_COPY_OPS).write(DEFAULT_SHALLOW_COPY_OPS);
            }
        }
    }

    /// Takes the module lock, installs the recording extern release
    /// and zeroes its counters. The guards must stay alive for the
    /// whole test.
    fn bench() -> (MutexGuard<'static, ()>, OpsGuard) {
        let ops_guard = OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            RELEASE_CALLS = 0;
            RELEASE_ARG = 0;
            RELEASE_SAW_FLAGS = 0;
            RELEASE_SAW_U = 0;
            core::ptr::write_volatile(
                core::ptr::addr_of_mut!(SHALLOW_COPY_OPS),
                ShallowCopyOps {
                    extern_release: recording_extern_release,
                },
            );
        }
        (ops_guard, OpsGuard)
    }

    const SRC_Z: usize = 0x0bad_2000;
    const SRC_Z_MALLOC: usize = 0x0bad_4000;
    const DST_Z: usize = 0x0bad_6000;
    const DST_Z_MALLOC: usize = 0x0bad_8000;

    /// Source payload borrowed (z != z_malloc) with no MEM_Dyn: the
    /// early-return shape.
    fn borrowed_pair(src_flags: u16) -> (Mem, Mem) {
        let from = garbage_mem(src_flags, 3, SRC_Z as *mut u8, SRC_Z_MALLOC as *mut u8);
        let to = garbage_mem(0x0fff, 5, DST_Z as *mut u8, DST_Z_MALLOC as *mut u8);
        (to, from)
    }

    #[test]
    fn every_field_but_z_malloc_and_x_del_is_copied() {
        let _guards = bench();
        let (mut to, from) = borrowed_pair(0x0012);
        unsafe { vdbe_mem_shallow_copy(&mut to, &from, MEM_STATIC) };
        assert_eq!(to.u, from.u);
        assert_eq!(to.r.to_bits(), from.r.to_bits());
        assert_eq!(to.db, from.db);
        assert_eq!(to.z, from.z);
        assert_eq!(to.n, from.n);
        assert_eq!(to.flags, from.flags);
        assert_eq!(to.value_type, from.value_type);
        assert_eq!(to.enc, from.enc);
        // The two fields the copy deliberately rewrites: z_malloc is
        // the destination's own (the 0x24-byte copy stops short of
        // +0x24), x_del is NULLed (str r0,[r4,#0x20] with r0 = 0).
        assert_eq!(to.z_malloc, DST_Z_MALLOC as *mut u8);
        assert_eq!(to.x_del, core::ptr::null_mut());
        // The source is read-only.
        assert_eq!(from.x_del, 0x0bad_3000usize as *mut u8);
        assert_eq!(from.z_malloc, SRC_Z_MALLOC as *mut u8);
    }

    #[test]
    fn extern_release_runs_once_on_the_destination_before_the_copy() {
        let _guards = bench();
        let (mut to, from) = borrowed_pair(0x0012);
        unsafe { vdbe_mem_shallow_copy(&mut to, &from, MEM_STATIC) };
        assert_eq!(unsafe { RELEASE_CALLS }, 1);
        assert_eq!(unsafe { RELEASE_ARG }, core::ptr::addr_of!(to) as usize);
        // The release saw the destination's PRE-COPY contents — it is
        // the old value's externals being dropped, not the new one's.
        assert_eq!(unsafe { RELEASE_SAW_FLAGS }, 0x0fff);
        assert_eq!(unsafe { RELEASE_SAW_U }, 0x0bad_cafe_dead_beef);
    }

    #[test]
    fn dyn_flag_forces_the_ownership_restamp_for_every_flags_value() {
        let _guards = bench();
        // Exhaustive over every source flags value that has MEM_Dyn:
        // the observable contract is exactly
        // `flags = (copied & !0x1c0) | src_type` — with z != z_malloc,
        // so only the MEM_Dyn arm of the condition can fire.
        let src_types = [MEM_STATIC, MEM_EPHEM, 0x0000, 0xffff];
        for src_type in src_types {
            for base in 0..=u16::MAX {
                let flags = base | FLAG_DYN;
                let (mut to, from) = borrowed_pair(flags);
                unsafe { vdbe_mem_shallow_copy(&mut to, &from, src_type) };
                assert_eq!(
                    to.flags,
                    (flags & !MEM_OWNERSHIP_BITS) | src_type,
                    "flags={flags:#06x} src_type={src_type:#06x}"
                );
            }
        }
    }

    #[test]
    fn self_allocated_payload_forces_the_restamp_without_dyn() {
        let _guards = bench();
        // z == z_malloc, no MEM_Dyn: the second arm of the condition
        // (`ldr r0,[r5,#0x14]!; ldr r1,[r5,#0x10]; cmp; ldmiane` NOT
        // taken) fires instead.
        let buffer = 0x0bad_5000usize as *mut u8;
        let mut from = garbage_mem(MEM_EPHEM | 0x0002, 3, buffer, buffer);
        let mut to = garbage_mem(0x0fff, 5, DST_Z as *mut u8, DST_Z_MALLOC as *mut u8);
        unsafe { vdbe_mem_shallow_copy(&mut to, &from, MEM_STATIC) };
        assert_eq!(to.flags, 0x0002 | MEM_STATIC);
        // Ownership bits beyond the three masked ones never existed in
        // the mask: 0x0400 (MEM_Agg) and 0x0020 (MEM_Term) survive.
        from.flags = FLAG_DYN | 0x0400 | 0x0020 | 0x0010;
        unsafe { vdbe_mem_shallow_copy(&mut to, &from, MEM_EPHEM) };
        assert_eq!(to.flags, 0x0400 | 0x0020 | 0x0010 | MEM_EPHEM);
    }

    #[test]
    fn borrowed_payload_keeps_the_copied_flags_for_every_flags_value() {
        let _guards = bench();
        // Exhaustive over every source flags value WITHOUT MEM_Dyn and
        // with z != z_malloc: the early return (`ldmiane`) leaves the
        // copied flags alone — src_type is irrelevant.
        for flags in 0..=u16::MAX {
            if flags & FLAG_DYN != 0 {
                continue;
            }
            let (mut to, from) = borrowed_pair(flags);
            unsafe { vdbe_mem_shallow_copy(&mut to, &from, 0xbeef) };
            assert_eq!(to.flags, flags, "flags={flags:#06x}");
        }
    }

    #[test]
    fn src_type_is_stored_verbatim_with_no_mask_of_its_own() {
        let _guards = bench();
        // The original `orr`s src_type in wholesale (orr r0,r0,r6;
        // strh): bits OUTSIDE the ownership mask in src_type land in
        // flags too. Call sites only ever pass 0x80/0x100, but the
        // observable contract is the unmasked orr.
        let (mut to, from) = borrowed_pair(FLAG_DYN | 0x0004);
        unsafe { vdbe_mem_shallow_copy(&mut to, &from, 0xaaa5) };
        assert_eq!(to.flags, 0x0004 | 0xaaa5);
    }
}
