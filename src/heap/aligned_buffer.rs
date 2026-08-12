//! `aligned_buffer_reset` — the reset half of the firmware's 32-byte
//! aligned-buffer owner, a two-word value type:
//!
//! ```text
//! +0x00  data        32-aligned pointer INTO the allocation (0 when empty)
//! +0x04  allocation  the raw owned block (0 when empty)
//! ```
//!
//! Original: `FUN_081a8204` @ 0x081a8204 (40 bytes exactly,
//! 0x081a8204..0x081a822c — ten instructions, no literal pool; the next
//! body opens immediately. 53 `bl` call sites, 0 `b`, binary-scanned).
//!
//! # Algorithm
//!
//! ```text
//! if buffer.allocation != 0:
//!     operator_delete_tag3(buffer.allocation)   ; the ported 0x082aad14
//! buffer.allocation = 0        ; str r0, [r4, #4] first
//! buffer.data       = 0        ; then str r0, [r4]
//! return buffer
//! ```
//!
//! # What the object is (sibling evidence)
//!
//! The class occupies 0x081a8198..0x081a8228, four functions:
//!
//! - 0x081a8198 — the align-up helper: `pad = 0x20 - (block & 0x1f)`
//!   (0 when already aligned), stores the pad through the in/out param
//!   and returns `(block + 0x1f) & !0x1f`.
//! - 0x081a81bc — `mov r0, #0x20; bx lr`: the alignment constant. (A
//!   byte-pattern scan lumps it with the 17 `deque_seg_capacity`
//!   copies; in this translation unit it is the buffer's alignment
//!   query.)
//! - 0x081a81c4 — the constructor (29 `bl` sites): zeroes both words,
//!   `operator_new_tag3(size + 0x20)` (0x082aad74, ported), stores the
//!   raw block at +0x04, and stores the align-up result at +0x00.
//! - 0x081a8204 — THIS PORT, the reset: release the allocation, clear
//!   both words.
//!
//! 32 bytes is the ARM926EJ-S cache-line size, and the observed users
//! match: 0x0804fe68 (a FreeType-area file reader, cf. the
//! 0x08278xxx stream functions) fills the buffer with a whole file via
//! `__rt_memcpy`, and the 0x08072xxx cluster resets it on its error
//! paths — cache/DMA-aligned staging buffers.
//!
//! The conditional is the original's own `cmp r0, #0; blne` — the
//! delete is reached ONLY with a non-NULL allocation even though the
//! ported `operator_delete_tag3` NULL-guards internally (the double
//! guard is faithful). The callee is already ported
//! (`heap::veneers::operator_delete_tag3`) and called directly — no
//! seam. The zero stores keep the original's order (+0x04 before
//! +0x00). Both words are 32-bit target words; host fixtures must sit
//! below 4 GiB (the crate's `try_map_u32_slab` rule) or use small
//! integer stand-ins, which is what the tests do.

use crate::heap::veneers::operator_delete_tag3;

/// Byte offset of the 32-aligned data pointer (`str r0, [r4]`).
pub const ALIGNED_BUFFER_DATA: usize = 0x00;
/// Byte offset of the owned raw allocation (`ldr/str [r4, #4]`).
pub const ALIGNED_BUFFER_ALLOCATION: usize = 0x04;
/// The buffer alignment, from the sibling query @ 0x081a81bc
/// (`mov r0, #0x20`) and the align-up mask arithmetic @ 0x081a8198.
pub const ALIGNED_BUFFER_ALIGNMENT: usize = 0x20;

/// aligned_buffer_reset — original: `FUN_081a8204` @ 0x081a8204
/// (40 bytes; 53 `bl` call sites).
///
/// Frees the owned allocation through the ported tag-3 `operator
/// delete` when one is installed, then zeroes the allocation word and
/// the data word (in that order, as the original does) and returns the
/// object. No NULL guard on `buffer` itself, exactly like the original.
///
/// # Safety
///
/// `buffer` must point into a writable allocation covering
/// `buffer..buffer+8`, word-aligned (the original's `ldr`/`str` are
/// word accesses). A non-zero allocation word must name a live tag-3
/// heap block, as in the original.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn aligned_buffer_reset(buffer: *mut u8) -> *mut u8 {
    let allocation = (buffer.add(ALIGNED_BUFFER_ALLOCATION) as *const u32).read_volatile();
    if allocation != 0 {
        operator_delete_tag3(allocation as *mut u8);
    }
    (buffer.add(ALIGNED_BUFFER_ALLOCATION) as *mut u32).write_volatile(0);
    (buffer as *mut u32).write_volatile(0);
    buffer
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::heap::veneers::tests::{free_log, mock_heap};

    /// A fake allocation address that round-trips through the 32-bit
    /// word (the veneers.rs BLOCK_A convention).
    const ALLOCATION: u32 = 0xA110_0000;

    #[repr(align(4))]
    struct Buffer([u8; 8]);

    fn words(buffer: &Buffer) -> (u32, u32) {
        let data = u32::from_le_bytes(buffer.0[0..4].try_into().unwrap());
        let allocation = u32::from_le_bytes(buffer.0[4..8].try_into().unwrap());
        (data, allocation)
    }

    #[test]
    fn an_installed_allocation_is_freed_once_and_both_words_zeroed() {
        let _heap = mock_heap();
        let mut buffer = Buffer([0; 8]);
        buffer.0[0..4].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
        buffer.0[4..8].copy_from_slice(&ALLOCATION.to_le_bytes());

        let returned = unsafe { aligned_buffer_reset(buffer.0.as_mut_ptr()) };

        assert_eq!(returned, buffer.0.as_mut_ptr(), "returns the object");
        let (frees, freed, tag) = free_log();
        assert_eq!(frees, 1, "the delete fires exactly once");
        assert_eq!(freed, ALLOCATION as *mut u8, "with the allocation word, not the data word");
        assert_eq!(tag, 3, "through the tag-3 operator delete");
        assert_eq!(words(&buffer), (0, 0), "both words zeroed");
    }

    #[test]
    fn an_empty_buffer_frees_nothing_and_still_zeroes_both_words() {
        let _heap = mock_heap();
        let mut buffer = Buffer([0; 8]);
        buffer.0[0..4].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
        // allocation word already zero

        let returned = unsafe { aligned_buffer_reset(buffer.0.as_mut_ptr()) };

        assert_eq!(returned, buffer.0.as_mut_ptr());
        let (frees, _, _) = free_log();
        assert_eq!(frees, 0, "the cmp/blne guard: no delete without an allocation");
        assert_eq!(words(&buffer), (0, 0), "the data word is cleared regardless");
    }
}
