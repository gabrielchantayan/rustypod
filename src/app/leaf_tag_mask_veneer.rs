//! Leaf-tag mask veneer — `thunk_FUN_08057958` @ `0x08047cc8`.
//! True size: 4 bytes; next real function begins at `0x08047ccc`.
//! Raw word `ea003f22` tail-branches to `0x08057958` (leaf_tag_mask).
//! Whole-image aligned A32 decoding: two inbound plain BLs at
//! `0x080df40c` and `0x080e5b58`, zero predicated inbound BLs;
//! zero outgoing BLs, one unconditional tail B.
//!
//! Pass the tag unchanged to the stock mapper and return its complete
//! 64-bit mask in r0/r1. Unknown tags return zero; this veneer adds no
//! validation or state. Deviations: reuse the existing stock-call seam
//! and its raw-verified host backend; LLVM may use an indirect tail jump
//! rather than the original direct B. The mapper itself remains unported.

use crate::app::opaque_collection_mask::leaf_tag_mask;

/// Returns the stock leaf-tag mask through the retailOS veneer entry.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub extern "C" fn leaf_tag_mask_veneer(tag: u32) -> u64 {
    #[cfg(target_os = "none")]
    unsafe { leaf_tag_mask(tag) }
    #[cfg(not(target_os = "none"))]
    leaf_tag_mask(tag)
}

#[cfg(test)]
mod tests {
    use super::leaf_tag_mask_veneer;

    #[test]
    fn sparse_tags_and_both_return_words() {
        for (tag, expected) in [
            (0, 0), (1, 0x100000), (2, 1), (13, 0x800),
            (14, 0x80000), (23, 0x40000000), (24, 0x100000000),
            (25, 0x200000000), (26, 0), (29, 0x4000000000),
            (31, 0x80000000), (39, 0x80000000000),
            (40, 0x100000000000), (53, 0), (54, 0x200000000000),
            (55, 0), (67, 0), (68, 0x40000000000000),
            (69, 0x80000000000000), (70, 0), (u32::MAX, 0),
            (0x80000000, 0),
        ] {
            assert_eq!(leaf_tag_mask_veneer(tag), expected, "tag {tag}");
        }
    }
}
