//! `word_list_copy` — original: `FUN_082d27a8` @ 0x082d27a8
//! (44 bytes; 41 `bl` call sites, all unconditional — verified by decoding
//! every ARM B/BL word in osos.dec, not from Ghidra xrefs).
//!
//! Copies the *contents* of a small counted word list from `src` to `dst`:
//!
//! ```text
//! push {r4-r6, lr}
//! r0 = ldrh [src]        ; src->count
//! r1 = ldr  [src, #4]    ; src->entries
//! r2 = r0 << 2           ; count * 4 bytes
//! r0 = ldr  [dst, #4]    ; dst->entries
//! bl  0x08037df8         ; memcpy veneer (IRAM memcpy @ 0x08000188)
//! r0 = ldrh [src]        ; src->count, RE-READ after the copy
//! strh [dst], r0         ; dst->count = src->count
//! pop  {r4-r6, pc}
//! ```
//!
//! The container (laid out by its constructor `FUN_082d81e4` @ 0x082d81e4)
//! is a small vector of `u32` words with inline storage:
//!
//! ```c
//! struct WordList {
//!     u16  count;        // +0x00
//!     u16  capacity;     // +0x02 — NOT copied: dst keeps its own
//!     u32 *entries;      // +0x04 — NOT copied: dst keeps its own buffer
//!     // inline u32 storage typically follows at +0x08 (capacity 6)
//! };
//! ```
//!
//! Only the element words and the count move; the destination keeps its own
//! capacity and buffer pointer. Callers use it to snapshot and restore
//! list state (e.g. `FUN_082cb18c` @ 0x082cb18c stashes two operand lists
//! on the stack, iterates, then swaps them back). The companion
//! `FUN_082d27d4` @ 0x082d27d4 trims trailing zero entries, so the list
//! semantics are "count leading slots, trailing NULLs dropped".
//!
//! Faithful details:
//! - The count is loaded TWICE: once to size the copy, once more after the
//!   `bl` for the store (the original reuses r0 across the call). If
//!   `dst->entries` overlaps `src`'s header the copy clobbers
//!   `src->count`, and it is the *new* value that lands in `dst->count`.
//!   Reproduced, not "fixed" to a cached count.
//! - `count == 0` still enters the copy (no guard in the original); the
//!   ported memcpy body is a no-op for `len == 0`, matching the original
//!   veneer, whose bit-select tail also stores nothing.
//! - Deviation: the original calls the IRAM veneer @ 0x08037df8
//!   (`ldr pc, [pc, #-4]` -> 0x22000188, the IRAM mirror of memcpy @
//!   0x08000188); we call the ported body
//!   [`memcpy_forward_words`](crate::libc::memcpy::memcpy_forward_words)
//!   directly, as other ports do. Element buffers are `u32` arrays, so the
//!   word-aligned fast path the veneer forwards to is the correct body.

use crate::libc::memcpy::memcpy_forward_words;

/// Counted word list with out-of-line element storage; matches the
/// firmware layout `{u16 count; u16 capacity; u32 *entries}` on target
/// (offsets 0x00 / 0x02 / 0x04).
#[repr(C)]
pub struct WordList {
    /// Number of leading element slots in use.
    pub count: u16,
    /// Capacity of `entries`; private to each list, never copied.
    pub capacity: u16,
    /// Element storage, typically inline right after this header.
    pub entries: *mut u32,
}

/// word_list_copy — original: `FUN_082d27a8` @ 0x082d27a8 (44 bytes).
///
/// Copies `src`'s element words and count into `dst`'s own buffer,
/// leaving `dst`'s capacity and entries pointer untouched.
///
/// # Safety
/// `src` and `dst` must point at valid [`WordList`] headers whose
/// `entries` buffers are word-aligned and hold at least `src.count`
/// readable (src) / writable (dst) words. Ranges may overlap; the copy
/// is a forward grouped copy with the firmware memcpy's semantics, and
/// `dst->entries` overlapping the `src` header changes the stored count
/// exactly as the original's post-copy count reload does.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn word_list_copy(src: *const WordList, dst: *mut WordList) {
    let count = (*src).count as usize;
    let src_entries = (*src).entries;
    let dst_entries = (*dst).entries;
    memcpy_forward_words(dst_entries as *mut u8, src_entries as *const u8, count * 4);
    (*dst).count = (*src).count;
}

/// Inline element capacity set by the constructor; the original
/// hardcodes `mov r2, #6`.
pub const WORD_LIST_INLINE_CAPACITY: u16 = 6;

/// word_list_init — original: `FUN_082d81e4` @ 0x082d81e4 (28 bytes).
///
/// Constructor for the inline-storage form of [`WordList`], placed
/// directly ahead of its 6-word element buffer:
///
/// ```text
/// mov  r2, #0
/// strh r2, [r0]        ; this->count = 0
/// mov  r2, #6
/// add  r1, r0, #8      ; inline storage = this + 8 (past the 8-byte header)
/// strh r2, [r0, #2]    ; this->capacity = 6
/// str  r1, [r0, #4]    ; this->entries = this + 8
/// bx   lr              ; r0 never clobbered: returns `this`
/// ```
///
/// 29 `bl` call sites, ALL unconditional (0 predicated) — verified by
/// decoding every ARM B/BL word in osos.dec, not from Ghidra xrefs.
/// Extent self-verified: 7 words, and the next function's prologue
/// (`push {r4-r6, lr}`) starts exactly at 0x082d8200, so Ghidra's
/// 28 bytes is right. No data word in osos.dec holds 0x082d81e4, so the
/// constructor is not dispatched virtually. Every caller constructs the
/// list on its own stack frame (e.g. `FUN_082cb18c` @ 0x082cb18c builds
/// four of them), matching the 8-byte header + 6 inline words = 32-byte
/// stack slots seen there.
///
/// # Safety
/// `this` must point at 8 + 6*4 = 32 writable bytes: the 8-byte
/// [`WordList`] header followed by 6 words of inline element storage.
/// Returns `this` (r0 is preserved by the original).
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn word_list_init(this: *mut WordList) -> *mut WordList {
    (*this).count = 0;
    (*this).capacity = WORD_LIST_INLINE_CAPACITY;
    (*this).entries = (this as *mut u8).add(8) as *mut u32;
    this
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::{word_list_copy, word_list_init, WordList, WORD_LIST_INLINE_CAPACITY};
    use std::vec;

    fn list(buf: &mut [u32], count: u16) -> WordList {
        WordList {
            count,
            capacity: buf.len() as u16,
            entries: buf.as_mut_ptr(),
        }
    }

    #[test]
    fn copies_elements_and_count_keeps_dst_capacity_and_buffer() {
        let mut src_buf = [0x1111_1111, 0x2222_2222, 0x3333_3333, 0xdead_beef];
        let mut dst_buf = [0xaaaa_aaaa; 6];
        let src = list(&mut src_buf, 3);
        let mut dst = list(&mut dst_buf, 5);
        let dst_ptr_before = dst.entries;

        unsafe { word_list_copy(&src, &mut dst) };

        assert_eq!(dst.count, 3);
        assert_eq!(dst.capacity, 6, "capacity must not be copied");
        assert_eq!(dst.entries, dst_ptr_before, "buffer pointer must not be copied");
        assert_eq!(&dst_buf[..3], &src_buf[..3]);
        assert_eq!(&dst_buf[3..], &[0xaaaa_aaaa; 3], "tail beyond count untouched");
    }

    #[test]
    fn empty_source_only_zeroes_dst_count() {
        let mut src_buf = [0x1234_5678];
        let mut dst_buf = [0xfeed_face; 2];
        let src = list(&mut src_buf, 0);
        let mut dst = list(&mut dst_buf, 2);

        unsafe { word_list_copy(&src, &mut dst) };

        assert_eq!(dst.count, 0);
        assert_eq!(dst_buf, [0xfeed_face; 2], "no bytes copied for count 0");
    }

    #[test]
    fn self_copy_is_stable() {
        let mut buf = [1, 2, 3, 4];
        let mut src = list(&mut buf, 4);
        // src == dst: memcpy of a range onto itself, then count re-stored.
        unsafe { word_list_copy(&src, &mut src) };

        assert_eq!(src.count, 4);
        assert_eq!(buf, [1, 2, 3, 4]);
    }

    #[test]
    fn init_zeroes_count_sets_capacity_and_points_entries_past_header() {
        // Firmware layout: 8-byte header + 6 inline words = 32 bytes.
        let mut slab = [0xffff_ffffu32; 8];
        let this = slab.as_mut_ptr() as *mut WordList;

        let ret = unsafe { word_list_init(this) };

        assert_eq!(ret, this, "constructor returns this (r0 preserved)");
        let list = unsafe { &*this };
        assert_eq!(list.count, 0);
        assert_eq!(list.capacity, WORD_LIST_INLINE_CAPACITY);
        assert_eq!(
            list.entries,
            unsafe { slab.as_mut_ptr().add(2) },
            "entries must point at this + 8 bytes"
        );
        assert_eq!(
            list.entries as usize - this as usize,
            8,
            "inline storage starts right after the 8-byte header"
        );
    }

    #[test]
    fn init_overwrites_dirty_header_and_scribbles_nowhere_else() {
        // 32-byte firmware slot: 8-byte header + 6 inline words.
        let mut slab = [0xdead_beefu32; 8];
        let this = slab.as_mut_ptr() as *mut WordList;

        unsafe { word_list_init(this) };

        // Header words rewritten: {count=0, capacity=6} in the first word.
        assert_eq!(slab[0] & 0xffff, 0, "count zeroed");
        assert_eq!(slab[0] >> 16, 6, "capacity written above count");
        // The original touches ONLY the 8-byte header; the inline element
        // words are left dirty. (The `entries` struct field itself lives
        // at byte 8 on this host's repr(C) layout, so the deepest region
        // provably untouched on BOTH layouts is slab[4..].)
        assert_eq!(&slab[4..], &[0xdead_beef; 4], "no scribbling past the header");
    }

    #[test]
    fn dst_buffer_overlapping_src_header_stores_the_clobbered_count() {
        // Pathological alias the original's SECOND ldrh makes observable:
        // dst->entries covers src's header, so the forward copy overwrites
        // src->count with the low half of src_buf[0] before the count is
        // re-read and stored. A cached count would store the OLD value.
        let mut src_buf = [0x0000_0009, 0xabcd_ef01, 0x0, 0x0];
        let mut header = WordList {
            count: 2,
            capacity: 4,
            entries: src_buf.as_mut_ptr(),
        };
        // dst is a separate header whose buffer IS the src header.
        let mut dst = WordList {
            count: 0,
            capacity: 9,
            entries: (&mut header as *mut WordList) as *mut u32,
        };

        unsafe { word_list_copy(&header, &mut dst) };

        // 2 words (8 bytes) copied from src_buf over `header`: count becomes
        // the low u16 of 0x0000_0009, and that re-read value is stored.
        assert_eq!(dst.count, 9, "count must be re-read after the copy");
        assert_eq!(header.count, 9);
    }
}
