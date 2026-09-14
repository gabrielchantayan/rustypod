//! HFS B-tree key-length decoder.
//!
//! The key prefix is either an 8-bit or a native little-endian 16-bit length,
//! selected by the B-tree's big-keys attribute. Fixed-length leaf keys instead
//! take their length from the control block.

use crate::fs::hfs_btree_get_node::BTreeControlBlock;

/// `BTreeControlBlock.attributes` bit: keys begin with a 16-bit length.
const BIG_KEYS_ATTRIBUTE: u32 = 0x2;
/// `BTreeControlBlock.attributes` bit: leaf keys carry their own length.
const VARIABLE_INDEX_KEYS_ATTRIBUTE: u32 = 0x4;

/// `hfs_btree_key_length` — original: `FUN_080537f8` @ `0x080537f8`
/// (36 bytes; 9 ARM words; 6 verified direct call sites, all unconditional
/// plain `bl` at `0x0803bd0c`, `0x0803bd4c`, `0x08058ffc`, `0x08059060`,
/// `0x08059600`, and `0x08064cf8`; no predicated calls).
///
/// If `is_index` is zero and B-tree attribute bit 2 (`0x4`) is clear, returns
/// the fixed `max_key_length` at `btree + 0x1e` without reading `key`.
/// Otherwise, attribute bit 1 (`0x2`) chooses an aligned little-endian `u16`
/// key prefix; a clear bit selects its zero-extended first byte. This preserves
/// every raw ARM branch and load. Deliberate deviations: none.
///
/// # Safety
///
/// `btree` must be readable through `+0x30`. If the fixed-key branch is not
/// taken, `key` must be readable for one byte or, for big keys, as an aligned
/// little-endian `u16`. The retail routine has no NULL guards.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.hfs_btree_key_length")]
#[inline(never)]
pub unsafe extern "C" fn hfs_btree_key_length(
    btree: *const BTreeControlBlock,
    key: *const u8,
    is_index: u32,
) -> u16 {
    let attributes = unsafe { (*btree).attributes };
    if is_index == 0 && attributes & VARIABLE_INDEX_KEYS_ATTRIBUTE == 0 {
        return unsafe { (*btree).max_key_length };
    }

    if attributes & BIG_KEYS_ATTRIBUTE == 0 {
        unsafe { key.read() as u16 }
    } else {
        unsafe { key.cast::<u16>().read() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe fn control_block(max_key_length: u16, attributes: u32) -> BTreeControlBlock {
        let mut btree: BTreeControlBlock = unsafe { core::mem::zeroed() };
        btree.max_key_length = max_key_length;
        btree.attributes = attributes;
        btree
    }

    #[test]
    fn fixed_leaf_key_uses_control_block_length_without_reading_key() {
        let btree = unsafe { control_block(0xbeef, 0) };
        let unreadable_key = core::ptr::dangling();

        assert_eq!(
            unsafe { hfs_btree_key_length(&btree, unreadable_key, 0) },
            0xbeef
        );
    }

    #[test]
    fn variable_or_index_small_keys_use_the_first_byte() {
        let key = [0xff_u8, 0x7a];

        let variable_btree = unsafe { control_block(0x1111, VARIABLE_INDEX_KEYS_ATTRIBUTE) };
        assert_eq!(
            unsafe { hfs_btree_key_length(&variable_btree, key.as_ptr(), 0) },
            0x00ff
        );

        let fixed_btree = unsafe { control_block(0x2222, 0) };
        assert_eq!(
            unsafe { hfs_btree_key_length(&fixed_btree, key.as_ptr(), 7) },
            0x00ff
        );
    }

    #[test]
    fn big_keys_use_an_aligned_little_endian_halfword() {
        let key = 0x80f1_u16;

        let variable_btree = unsafe {
            control_block(
                0x1111,
                BIG_KEYS_ATTRIBUTE | VARIABLE_INDEX_KEYS_ATTRIBUTE,
            )
        };
        assert_eq!(
            unsafe { hfs_btree_key_length(&variable_btree, (&key as *const u16).cast(), 0) },
            0x80f1
        );

        let fixed_btree = unsafe { control_block(0x2222, BIG_KEYS_ATTRIBUTE) };
        assert_eq!(
            unsafe { hfs_btree_key_length(&fixed_btree, (&key as *const u16).cast(), 1) },
            0x80f1
        );
    }
}
