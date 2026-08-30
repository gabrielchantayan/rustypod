//! `fixed3_assign` — original: `FUN_08281000` @ 0x08281000 (**48 bytes**,
//! 0x08281000..0x08281030; **30 `bl` call sites, 0 predicated forms, 0
//! plain `b`**, counted by decoding every B/BL word in osos.dec; **0
//! word-aligned occurrences of 0x08281000 as a data word**, so it is
//! never reached through a vtable — every caller binds it statically,
//! which is what a compiler does for a known-type assignment operator).
//!
//! The copy-assignment operator of retailOS's three-`FixedValue` record
//! (0x48 bytes: the refcounted Q16.16 scalar of
//! [`crate::app::fixed_value`], three of them back to back — a fixed-
//! point triple the Cover Flow-style view code uses for its animation
//! transforms). Whole function, decoded from the raw words:
//!
//! ```text
//! 08281000:  e92d4030   push {r4, r5, lr}
//! 08281004:  e1a05001   mov  r5, r1
//! 08281008:  e1a04000   mov  r4, r0
//! 0828100c:  ebfb44ff   bl   0x08152410        ; member_assign(this, src)
//! 08281010:  e2851018   add  r1, r5, #24
//! 08281014:  e2840018   add  r0, r4, #24
//! 08281018:  ebfb44fc   bl   0x08152410        ; member_assign(this+1, src+1)
//! 0828101c:  e2851030   add  r1, r5, #48
//! 08281020:  e2840030   add  r0, r4, #48
//! 08281024:  ebfb44f9   bl   0x08152410        ; member_assign(this+2, src+2)
//! 08281028:  e1a00004   mov  r0, r4
//! 0828102c:  e8bd8030   pop  {r4, r5, pc}      ; return dst
//! ```
//!
//! Ghidra's 48-byte extent is exact: 0x08281030 opens the next function
//! (`push {r4, r5, r6, lr}`) and there is no literal pool.
//!
//! # The member operator @ 0x08152410
//!
//! The callee is `FixedValue::operator=` (104 bytes, 0x08152410..
//! 0x08152478; exactly **3 `bl` call sites — the three above**, and 0
//! data-word occurrences): it copies +0x04 (value), +0x08 (aux), +0x0c
//! and +0x10 word by word, then rebuilds the +0x14 flags/refcount word
//! out of the source's — bit 0 by a byte `bic #1`/`and #1`/`orr`, bit 1
//! the same way, then the whole word as `(dst & 3) | (src & !3)` where
//! `dst & 3` already holds the source's two bits, so the net effect is a
//! plain word copy of +0x14. That three-step dance is ADS's codegen for
//! assigning the `{flags: 2, refcount: 30}` bitfield pair memberwise;
//! only the +0x00 vtable word is left alone, exactly what a C++
//! copy-assignment operator must do. The port's [`fixed_value_assign`]
//! models it in place, private (the wstr_case_eq house precedent); the
//! intermediate byte-partial states it skips are observable to no one —
//! the original stores each byte before the next load, single-threaded.
//!
//! Callers copy from static template records (e.g. the pools at
//! 0x081528ac/0x081528b0 in `FUN_08152728` hold 0x08a79840/0x08a79918)
//! into the owning view object's slots at a 0x18 stride; `FUN_08152728`
//! reads a template's +0x04 word as a Q16.16 scalar (adding 0x730000 =
//! 115.0) immediately after the copy, confirming the member layout.
//! The template addresses sit above the decrypted body's end
//! (0x08a1c3e8), so their contents are not binary-verifiable — only the
//! layout the callers rely on.
//!
//! # Deviations
//!
//! - The member copy is a private `#[inline(never)]` helper so the three
//!   calls remain real call boundaries, mirroring the original's three
//!   `bl`s; LLVM is free to keep or fold it, behaviour is identical.
//! - The flags-word merge is the documented net word copy, not the
//!   byte-merge dance (see above).
//! - Word accesses are `read_volatile`/`write_volatile` in ascending
//!   member/field order, the crate's standard defence against LLVM's
//!   loop-idiom pass rewriting the copy into a `memcpy` call
//!   (PORTING.md); it also pins the forward, overlap-propagating order
//!   the original's instruction pairs imply.
//! - No NULL or alignment guard on either pointer, matching the
//!   original. Self-assignment is a no-op by construction; partially
//!   overlapping records propagate stores forward, as the original does.

use crate::app::fixed_value::FixedValue;

/// Members in the record: three `FixedValue`s, 0x48 bytes total.
pub const FIXED3_MEMBERS: usize = 3;

/// `FixedValue::operator=` — original: `FUN_08152410` @ 0x08152410 (104
/// bytes; 3 `bl` call sites, all inside `fixed3_assign`).
///
/// Copies the payload words (+0x04..+0x17) of the scalar at `src` onto
/// the scalar at `dst`, preserving `dst`'s vtable. See the module
/// header for why the original's flags-byte merge is a plain word copy.
#[inline(never)]
unsafe fn fixed_value_assign(dst: *mut FixedValue, src: *const FixedValue) {
    // Ascending field order, each load before its store — the original's
    // ldr/str pairs.
    let value = core::ptr::read_volatile(core::ptr::addr_of!((*src).value_q16));
    core::ptr::write_volatile(core::ptr::addr_of_mut!((*dst).value_q16), value);
    let aux = core::ptr::read_volatile(core::ptr::addr_of!((*src).aux));
    core::ptr::write_volatile(core::ptr::addr_of_mut!((*dst).aux), aux);
    let opaque0 = core::ptr::read_volatile(core::ptr::addr_of!((*src).opaque[0]));
    core::ptr::write_volatile(core::ptr::addr_of_mut!((*dst).opaque[0]), opaque0);
    let opaque1 = core::ptr::read_volatile(core::ptr::addr_of!((*src).opaque[1]));
    core::ptr::write_volatile(core::ptr::addr_of_mut!((*dst).opaque[1]), opaque1);
    // The original merges bit 0, then bit 1, then the upper 30 bits of
    // the flags/refcount word out of the source's — which lands the
    // source's whole word (module header).
    let flags = core::ptr::read_volatile(core::ptr::addr_of!((*src).flags));
    core::ptr::write_volatile(core::ptr::addr_of_mut!((*dst).flags), flags);
}

/// fixed3_assign — original: `FUN_08281000` @ 0x08281000 (48 bytes; 30
/// `bl` call sites, binary-scanned).
///
/// Assigns the three-`FixedValue` record at `src` to the record at `dst`
/// member by member — each member's payload words (+0x04..+0x17) are
/// copied, each member's vtable (+0x00) keeps whatever `dst` already
/// had. Returns `dst`. Neither pointer need be non-NULL; there is no
/// guard, matching the original.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn fixed3_assign(
    dst: *mut FixedValue,
    src: *const FixedValue,
) -> *mut FixedValue {
    fixed_value_assign(dst, src);
    fixed_value_assign(dst.add(1), src.add(1));
    fixed_value_assign(dst.add(2), src.add(2));
    dst
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    /// A member pre-filled with sentinels, so every copied (and every
    /// deliberately preserved) word is observable.
    fn dirty(vtable: u32, seed: u32) -> FixedValue {
        FixedValue {
            vtable,
            value_q16: seed.wrapping_mul(0x0101_0101) as i32,
            aux: seed ^ 0xa5a5_a5a5,
            opaque: [seed.wrapping_add(0x0c0c_0c0c), seed.wrapping_add(0x1010_1010)],
            flags: seed | 0xffff_0000,
        }
    }

    fn words(object: &FixedValue) -> [u32; 5] {
        [
            object.value_q16 as u32,
            object.aux,
            object.opaque[0],
            object.opaque[1],
            object.flags,
        ]
    }

    #[test]
    fn it_returns_the_dst_pointer() {
        let mut dst = [dirty(0xdead_0000, 1), dirty(0xdead_0001, 2), dirty(0xdead_0002, 3)];
        let src = [dirty(0xbeef_0000, 7), dirty(0xbeef_0001, 8), dirty(0xbeef_0002, 9)];
        let returned = unsafe { fixed3_assign(dst.as_mut_ptr(), src.as_ptr()) };
        assert_eq!(returned, dst.as_mut_ptr());
    }

    #[test]
    fn it_copies_all_three_members_payload_words() {
        let mut dst = [dirty(0xdead_0000, 1), dirty(0xdead_0001, 2), dirty(0xdead_0002, 3)];
        let src = [dirty(0xbeef_0000, 7), dirty(0xbeef_0001, 8), dirty(0xbeef_0002, 9)];
        unsafe { fixed3_assign(dst.as_mut_ptr(), src.as_ptr()) };
        for member in 0..FIXED3_MEMBERS {
            assert_eq!(words(&dst[member]), words(&src[member]), "member {member}");
        }
    }

    #[test]
    fn it_preserves_each_dst_vtable() {
        let mut dst = [dirty(0xdead_0000, 1), dirty(0xdead_0001, 2), dirty(0xdead_0002, 3)];
        let src = [dirty(0xbeef_0000, 7), dirty(0xbeef_0001, 8), dirty(0xbeef_0002, 9)];
        unsafe { fixed3_assign(dst.as_mut_ptr(), src.as_ptr()) };
        assert_eq!(dst[0].vtable, 0xdead_0000);
        assert_eq!(dst[1].vtable, 0xdead_0001);
        assert_eq!(dst[2].vtable, 0xdead_0002);
    }

    #[test]
    fn the_flags_word_is_copied_wholesale_including_the_refcount_bits() {
        // The original's bit-0/bit-1/upper-30 merge nets out to a full
        // word copy: dst's old low bits must NOT survive.
        let mut dst = [dirty(0xdead_0000, 0), dirty(0xdead_0001, 0), dirty(0xdead_0002, 0)];
        for member in &mut dst {
            member.flags = 0x0000_0003; // both flag bits set in dst only
        }
        let src = [dirty(0xbeef_0000, 5), dirty(0xbeef_0001, 6), dirty(0xbeef_0002, 7)];
        unsafe { fixed3_assign(dst.as_mut_ptr(), src.as_ptr()) };
        for member in 0..FIXED3_MEMBERS {
            assert_eq!(dst[member].flags, src[member].flags);
            assert_eq!(dst[member].flags & 3, src[member].flags & 3);
        }
    }

    #[test]
    fn the_source_record_is_not_written() {
        let mut dst = [dirty(0xdead_0000, 1), dirty(0xdead_0001, 2), dirty(0xdead_0002, 3)];
        let src = [dirty(0xbeef_0000, 7), dirty(0xbeef_0001, 8), dirty(0xbeef_0002, 9)];
        let before: std::vec::Vec<_> = src.iter().map(|m| (m.vtable, words(m))).collect();
        unsafe { fixed3_assign(dst.as_mut_ptr(), src.as_ptr()) };
        let after: std::vec::Vec<_> = src.iter().map(|m| (m.vtable, words(m))).collect();
        assert_eq!(before, after);
    }

    #[test]
    fn self_assignment_is_a_no_op() {
        let mut record = [dirty(0xdead_0000, 7), dirty(0xdead_0001, 8), dirty(0xdead_0002, 9)];
        let before: std::vec::Vec<_> = record.iter().map(|m| (m.vtable, words(m))).collect();
        unsafe { fixed3_assign(record.as_mut_ptr(), record.as_ptr()) };
        let after: std::vec::Vec<_> = record.iter().map(|m| (m.vtable, words(m))).collect();
        assert_eq!(before, after);
    }
}
