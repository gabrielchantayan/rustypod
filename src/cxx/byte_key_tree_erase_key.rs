//! Erases every entry for one byte key from a red-black tree — retailOS
//! `FUN_083dafac` at load address `0x083dafac` (140 bytes).
//!
//! Raw `osos.dec` establishes the exact 35-word extent from `push {r4-r6,lr}`
//! at `0x083dafac` through `pop {r4-r6,pc}` at `0x083db034`; the separately
//! linked byte-key map find begins at `0x083db038`. It contains four plain
//! `bl` instructions (`0x083dafc4`, `0x083daff0`, `0x083daffc`, and
//! `0x083db028`) and zero predicated `bl` instructions. Whole-image decoding
//! finds two plain inbound `bl` sites (`0x082581b0` and `0x082581fc`), with no
//! predicated inbound calls.
//!
//! The function computes the byte-key tree's equal range, advances a cursor
//! from the first iterator to the second while counting nodes, then erases the
//! saved range and returns that count. `equal_range` @ `0x083b7ff0` and
//! `erase_range` @ `0x083b859c` remain retail helpers; their ABI contracts are
//! exposed as the narrow dispatch seam below so host tests can observe this
//! routine without inventing their implementations. Deliberate deviations:
//! stack iterator temporaries are Rust locals, and the equality helper @
//! `0x083cf740` is inlined as a word comparison.

use crate::cxx::red_black_tree_increment::red_black_tree_advance_cursor;

pub type ByteKeyTreeEqualRange = unsafe extern "C" fn(*mut u32, *mut u8, *const u8);
pub type ByteKeyTreeEraseRange = unsafe extern "C" fn(*mut u32, *mut u8, *const u32, *const u32);

#[derive(Clone, Copy)]
pub struct ByteKeyTreeEraseKeyOps {
    pub equal_range: ByteKeyTreeEqualRange,
    pub erase_range: ByteKeyTreeEraseRange,
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn retail_ops() -> ByteKeyTreeEraseKeyOps {
    ByteKeyTreeEraseKeyOps {
        equal_range: core::mem::transmute(0x083b_7ff0usize),
        erase_range: core::mem::transmute(0x083b_859cusize),
    }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_equal_range(_range: *mut u32, _tree: *mut u8, _key: *const u8) {
    panic!("byte_key_tree_erase_key requires test operations on host")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_erase_range(_result: *mut u32, _tree: *mut u8, _first: *const u32, _last: *const u32) {
    panic!("byte_key_tree_erase_key requires test operations on host")
}

#[cfg(not(target_os = "none"))]
pub static mut BYTE_KEY_TREE_ERASE_KEY_OPS: ByteKeyTreeEraseKeyOps = ByteKeyTreeEraseKeyOps {
    equal_range: unavailable_equal_range,
    erase_range: unavailable_erase_range,
};

#[inline(always)]
unsafe fn byte_key_tree_erase_key_ops() -> ByteKeyTreeEraseKeyOps {
    #[cfg(target_os = "none")]
    { retail_ops() }
    #[cfg(not(target_os = "none"))]
    { core::ptr::read_volatile(core::ptr::addr_of!(BYTE_KEY_TREE_ERASE_KEY_OPS)) }
}

/// Erases all nodes whose key equals `*key`, returning their former count.
///
/// # Safety
/// `tree` must designate a live byte-key red-black tree and `key` a readable
/// byte. The equal-range and erase-range operations must obey their retail
/// iterator contracts; every cursor between their returned bounds must be a
/// valid node for [`red_black_tree_advance_cursor`].
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.byte_key_tree_erase_key")]
#[inline(never)]
pub unsafe extern "C" fn byte_key_tree_erase_key(tree: *mut u8, key: *const u8) -> u32 {
    let ops = byte_key_tree_erase_key_ops();
    let mut range = [0u32; 2];
    (ops.equal_range)(range.as_mut_ptr(), tree, key);

    let mut cursor = range[0];
    let mut count = 0;
    while cursor != range[1] {
        count += 1;
        red_black_tree_advance_cursor(&mut cursor);
    }

    let mut result = 0;
    (ops.erase_range)(&mut result, tree, &range[0], &range[1]);
    count
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cxx::red_black_tree_increment::RedBlackTreeNode;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use core::ptr;
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut RANGE: [u32; 2] = [0; 2];
    static mut ERASED: [u32; 2] = [0; 2];
    static mut ERASE_CALLS: u32 = 0;

    unsafe extern "C" fn equal_range(result: *mut u32, _tree: *mut u8, _key: *const u8) {
        result.copy_from_nonoverlapping(RANGE.as_ptr(), 2);
    }

    unsafe extern "C" fn erase_range(_result: *mut u32, _tree: *mut u8, first: *const u32, last: *const u32) {
        ERASED = [first.read(), last.read()];
        ERASE_CALLS += 1;
    }

    struct Reset(ByteKeyTreeEraseKeyOps);
    impl Drop for Reset {
        fn drop(&mut self) { unsafe { BYTE_KEY_TREE_ERASE_KEY_OPS = self.0; } }
    }

    unsafe fn install(first: u32, last: u32) -> Reset {
        let old = BYTE_KEY_TREE_ERASE_KEY_OPS;
        BYTE_KEY_TREE_ERASE_KEY_OPS = ByteKeyTreeEraseKeyOps { equal_range, erase_range };
        RANGE = [first, last]; ERASED = [0; 2]; ERASE_CALLS = 0;
        Reset(old)
    }

    #[test]
    fn empty_equal_range_still_erases_and_returns_zero() {
        let _guard = TEST_LOCK.lock();
        unsafe {
            let _reset = install(0x1234, 0x1234);
            assert_eq!(byte_key_tree_erase_key(ptr::null_mut(), &7), 0);
            assert_eq!(ERASE_CALLS, 1);
            assert_eq!(ERASED, [0x1234, 0x1234]);
        }
    }

    #[test]
    fn counts_every_node_before_erasing_the_saved_range() {
        let _guard = TEST_LOCK.lock();
        let Some(slab) = try_map_u32_slab(hints::BYTE_KEY_TREE_ERASE_KEY, 0x1000) else {
            note_missing_u32_fixture("cxx/byte_key_tree_erase_key"); return;
        };
        unsafe {
            slab.write_bytes(0, 0x1000);
            let header = slab.cast::<RedBlackTreeNode>();
            let first = header.add(1); let second = header.add(2); let third = header.add(3);
            (*header).right = 0;
            (*first).parent = header as usize as u32; (*first).right = second as usize as u32;
            (*second).parent = first as usize as u32; (*second).right = third as usize as u32;
            (*third).parent = second as usize as u32; (*third).right = 0;
            let _reset = install(first as usize as u32, header as usize as u32);
            assert_eq!(byte_key_tree_erase_key(slab, &0x9a), 3);
            assert_eq!(ERASE_CALLS, 1);
            assert_eq!(ERASED, [first as usize as u32, header as usize as u32]);
        }
    }
}
