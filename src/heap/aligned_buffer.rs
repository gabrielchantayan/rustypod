//! `aligned_buffer_init` / `aligned_buffer_reset` — the constructor
//! and reset halves of the firmware's 32-byte aligned-buffer owner, a
//! two-word value type:
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
//!   Ported here as `aligned_buffer_init`.
//! - 0x081a8204 — the reset: release the allocation, clear both words.
//!   Ported here as `aligned_buffer_reset`.
//!
//! 32 bytes is the ARM926EJ-S cache-line size, and the observed users
//! match: 0x0804fe68 (a FreeType-area file reader, cf. the
//! 0x08278xxx stream functions) fills the buffer with a whole file via
//! `__rt_memcpy`, and the 0x08072xxx cluster resets it on its error
//! paths — cache/DMA-aligned staging buffers.
//!
//! The reset's conditional is the original's own `cmp r0, #0; blne` —
//! the delete is reached ONLY with a non-NULL allocation even though the
//! ported `operator_delete_tag3` NULL-guards internally (the double
//! guard is faithful). The callee is already ported
//! (`heap::veneers::operator_delete_tag3`) and called directly — no
//! seam. The zero stores keep the original's order (+0x04 before
//! +0x00). Both words are 32-bit target words; host fixtures must sit
//! below 4 GiB (the crate's `try_map_u32_slab` rule) or use small
//! integer stand-ins, which is what the tests do.

use crate::heap::veneers::{operator_delete_tag3, operator_new_tag3};

/// Byte offset of the 32-aligned data pointer (`str r0, [r4]`).
pub const ALIGNED_BUFFER_DATA: usize = 0x00;
/// Byte offset of the owned raw allocation (`ldr/str [r4, #4]`).
pub const ALIGNED_BUFFER_ALLOCATION: usize = 0x04;
/// The buffer alignment, from the sibling query @ 0x081a81bc
/// (`mov r0, #0x20`) and the align-up mask arithmetic @ 0x081a8198.
pub const ALIGNED_BUFFER_ALIGNMENT: usize = 0x20;

/// aligned_buffer_alignment — original: `FUN_081a81bc` @ `0x081a81bc`
/// (8 bytes; true extent `0x081a81bc..0x081a81c4`, immediately followed
/// by `aligned_buffer_init`).
///
/// Raw ARM is `mov r0, #0x20; bx lr`. Decoding every ARM B/BL word in
/// `work/firmware/osos.dec` finds five direct call sites, all plain,
/// unconditional `bl` (`0x080b54a0`, `0x080f0750`, `0x082676e0`,
/// `0x08278e5c`, and `0x08278f1c`); there are no predicated `bl` forms.
/// Returns the aligned-buffer cache-line alignment constant, 32, without
/// reading arguments or memory. Deliberate deviations: none.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub extern "C" fn aligned_buffer_alignment() -> u32 {
    ALIGNED_BUFFER_ALIGNMENT as u32
}


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

/// aligned_buffer_align_up_with_pad — original: `FUN_081a8198` @ `0x081a8198`
/// (36 bytes exactly; true extent `0x081a8198..0x081a81bc`, immediately
/// followed by `aligned_buffer_alignment`).
///
/// Raw words decode to `and r2, r0, #0x1f; rsb r2, r2, #0x20; cmp r2,
/// #0x20; str r2, [r1]; moveq r2, #0; add r0, r0, #0x1f; bic r0, r0,
/// #0x1f; streq r2, [r1]; bx lr`. Three direct callers
/// (`0x081a8190`, `0x081a81f0`, and `0x08277bb8`) use plain unconditional
/// `bl`; there are no predicated `bl` forms and the body is a leaf.
///
/// Stores the distance to the next 32-byte boundary through `pad_out`, except
/// that an already aligned address stores zero, then returns `block` rounded
/// up to that boundary. Both calculations wrap at the target's 32-bit address
/// boundary. Deliberate deviations: Rust exposes the two-register ABI as an
/// unsafe exported function; otherwise none.
///
/// # Safety
///
/// `pad_out` must be writable and four-byte aligned. `block` is treated as a
/// 32-bit target address and is not dereferenced.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn aligned_buffer_align_up_with_pad(
    block: *mut u8,
    pad_out: *mut u32,
) -> *mut u8 {
    let address = block as usize as u32;
    let mut pad = (ALIGNED_BUFFER_ALIGNMENT as u32).wrapping_sub(
        address & (ALIGNED_BUFFER_ALIGNMENT as u32 - 1),
    );
    pad_out.write_volatile(pad);
    if pad == ALIGNED_BUFFER_ALIGNMENT as u32 {
        pad = 0;
        pad_out.write_volatile(pad);
    }
    let aligned = address.wrapping_add(ALIGNED_BUFFER_ALIGNMENT as u32 - 1)
        & !(ALIGNED_BUFFER_ALIGNMENT as u32 - 1);
    aligned as usize as *mut u8
}

#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub extern "C" fn aligned_buffer_align_up(block: *mut u8) -> *mut u8 {
    let mut discarded_pad = 0;
    unsafe { aligned_buffer_align_up_with_pad(block, &mut discarded_pad) }
}

/// aligned_buffer_init — original: `FUN_081a81c4` @ 0x081a81c4 (64
/// bytes exactly, 0x081a81c4..0x081a8204 — sixteen instructions, no
/// literal pool; the reset @ 0x081a8204 opens immediately after. 29
/// `bl` call sites, every one unconditional (no predicated `blne`/
/// `bleq` forms), 0 `b`, binary-scanned by decoding every B/BL word in
/// osos.dec).
///
/// The constructor half of the aligned-buffer owner:
///
/// ```text
/// buffer.data       = 0                  ; str r0, [r4]      FIRST
/// buffer.allocation = 0                  ; str r0, [r4, #4]  second
/// raw = operator_new_tag3(size + 0x20)   ; 0x082aad74, ported
/// buffer.allocation = raw                ; stored even when NULL
/// if raw != 0:
///     buffer.data = align_up_to_cache_line(raw)   ; bl 0x081a8198
/// return buffer
/// ```
///
/// `size + 0x20` headroom guarantees the aligned view still leaves `size`
/// usable bytes. The allocation word is stored unconditionally, so a failed
/// allocation leaves both words zero and skips the align-up. The constructor
/// calls the exported `aligned_buffer_align_up` wrapper, preserving the
/// original one-register call structure and deliberately discarding its
/// stack-slot pad result. `operator_new_tag3` is called directly (ported in
/// `heap/veneers` — no seam). Both words are target u32 values.
///
/// # Safety
///
/// `buffer` must point into a writable allocation covering
/// `buffer..buffer+8`, word-aligned (the original's `str` are word
/// accesses). The installed allocation is owned by the object and must
/// later be released through `aligned_buffer_reset`, as in the
/// original.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn aligned_buffer_init(buffer: *mut u8, size: usize) -> *mut u8 {
    (buffer as *mut u32).write_volatile(0);
    (buffer.add(ALIGNED_BUFFER_ALLOCATION) as *mut u32).write_volatile(0);
    let allocation = operator_new_tag3(size.wrapping_add(ALIGNED_BUFFER_ALIGNMENT));
    (buffer.add(ALIGNED_BUFFER_ALLOCATION) as *mut u32).write_volatile(allocation as u32);
    if !allocation.is_null() {
        let data = aligned_buffer_align_up(allocation);
        (buffer as *mut u32).write_volatile(data as u32);
    }
    buffer
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::heap::veneers::tests::{alloc_log, free_log, mock_heap, set_alloc_ret};

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
    fn alignment_query_returns_the_cache_line_size_on_every_call() {
        assert_eq!(aligned_buffer_alignment(), 0x20);
        assert_eq!(aligned_buffer_alignment(), ALIGNED_BUFFER_ALIGNMENT as u32);
    }

    #[test]
    fn align_up_with_pad_rounds_every_residue_and_wraps_as_a_target_word() {
        for residue in 0..ALIGNED_BUFFER_ALIGNMENT as u32 {
            let address = ALLOCATION + residue;
            let mut pad = u32::MAX;
            let aligned = unsafe {
                aligned_buffer_align_up_with_pad(address as usize as *mut u8, &mut pad)
            } as usize as u32;
            let expected = address.wrapping_add(0x1f) & !0x1f;
            let expected_pad = if residue == 0 { 0 } else { 0x20 - residue };
            assert_eq!(aligned, expected, "residue {residue:#x}");
            assert_eq!(pad, expected_pad, "pad for residue {residue:#x}");
            assert_eq!(
                aligned_buffer_align_up(address as usize as *mut u8) as usize as u32,
                expected,
                "wrapper result for residue {residue:#x}"
            );
        }

        let mut pad = u32::MAX;
        assert_eq!(
            unsafe {
                aligned_buffer_align_up_with_pad(
                    0xffff_fff1usize as *mut u8,
                    &mut pad,
                )
            } as usize as u32,
            0,
            "the ARM u32 addition wraps at the address-space boundary"
        );
        assert_eq!(pad, 0x0f, "the pad does not depend on align-up overflow");
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

    #[test]
    fn init_allocates_size_plus_alignment_and_installs_both_views() {
        let _heap = mock_heap();
        let mut buffer = Buffer([0xAA; 8]);

        let returned = unsafe { aligned_buffer_init(buffer.0.as_mut_ptr(), 0x100) };

        assert_eq!(returned, buffer.0.as_mut_ptr(), "returns the object");
        let (allocs, size, tag) = alloc_log();
        assert_eq!(allocs, 1, "one allocation");
        assert_eq!(size, 0x100 + 0x20, "the original's add r0, r0, #0x20 headroom");
        assert_eq!(tag, 3, "through the tag-3 operator new");
        // BLOCK_A is already 32-aligned: the view IS the raw block.
        assert_eq!(words(&buffer), (ALLOCATION, ALLOCATION));
    }

    #[test]
    fn init_aligns_the_data_view_for_every_misalignment_residue() {
        let _heap = mock_heap();
        let mut buffer = Buffer([0xAA; 8]);

        for residue in 0..ALIGNED_BUFFER_ALIGNMENT as u32 {
            set_alloc_ret((ALLOCATION + residue) as *mut u8);
            unsafe { aligned_buffer_init(buffer.0.as_mut_ptr(), 0x40) };
            let (data, allocation) = words(&buffer);
            assert_eq!(allocation, ALLOCATION + residue, "raw block at +0x04, residue {residue:#x}");
            let want = ALLOCATION + if residue == 0 { 0 } else { 0x20 };
            assert_eq!(data, want, "(raw + 0x1f) & !0x1f at +0x00, residue {residue:#x}");
        }
    }

    #[test]
    fn init_with_a_failed_allocation_leaves_both_words_zero() {
        let _heap = mock_heap();
        set_alloc_ret(core::ptr::null_mut());
        let mut buffer = Buffer([0xAA; 8]);

        let returned = unsafe { aligned_buffer_init(buffer.0.as_mut_ptr(), 0x80) };

        assert_eq!(returned, buffer.0.as_mut_ptr());
        let (allocs, size, tag) = alloc_log();
        assert_eq!((allocs, size, tag), (1, 0x80 + 0x20, 3), "the alloc still fires");
        assert_eq!(
            words(&buffer),
            (0, 0),
            "NULL lands at +0x04 (the unconditional store) and +0x00 stays zero: no align-up on NULL"
        );
    }
}
