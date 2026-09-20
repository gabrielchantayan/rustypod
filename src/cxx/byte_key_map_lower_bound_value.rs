//! `byte_key_map_lower_bound_value` — original: `FUN_083db090` @ 0x083db090
//! (64 bytes, 0x083db090..0x083db0d0; **3 plain `bl` call sites and 0
//! predicated `bl` call sites**).
//!
//! Copies the byte at `key` into a two-byte `{ key, 0 }` stack pair, asks the
//! byte-keyed tree's lower-bound helper for its iterator, and returns the
//! mapped byte at `node + 0x11`. The node header is 0x10 bytes and the pair's
//! key is at +0x10, hence +0x11 is its one-byte mapped value.
//!
//! The lower-bound helper `FUN_083b9168` has no verified Rust identity or
//! port. Target builds call its fixed address; host tests install a typed seam.
//! This is the only deliberate deviation.

use super::byte_key_map::{ByteKeyInsertResult, ByteKeyMap};

/// ABI of `FUN_083b9168`: stores an iterator node at `result + 0` and its
/// status byte at `result + 4`.
pub type ByteKeyTreeLowerBound = unsafe extern "C" fn(
    result: *mut ByteKeyInsertResult,
    map: *mut ByteKeyMap,
    key_pair: *const u8,
);

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn byte_key_tree_lower_bound() -> ByteKeyTreeLowerBound {
    core::mem::transmute(0x083b_9168usize)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_byte_key_tree_lower_bound(
    _result: *mut ByteKeyInsertResult,
    _map: *mut ByteKeyMap,
    _key_pair: *const u8,
) {
    panic!("byte_key_map_lower_bound_value requires a lower-bound seam on host")
}

/// Host replacement for the unported byte-key tree lower-bound helper.
#[cfg(not(target_os = "none"))]
pub static mut BYTE_KEY_TREE_LOWER_BOUND: ByteKeyTreeLowerBound = missing_byte_key_tree_lower_bound;

#[inline(always)]
unsafe fn find_lower_bound(
    result: *mut ByteKeyInsertResult,
    map: *mut ByteKeyMap,
    key_pair: *const u8,
) {
    #[cfg(target_os = "none")]
    byte_key_tree_lower_bound()(result, map, key_pair);

    #[cfg(not(target_os = "none"))]
    core::ptr::read_volatile(core::ptr::addr_of!(BYTE_KEY_TREE_LOWER_BOUND))(
        result, map, key_pair,
    );
}

/// Returns the mapped byte at the lower-bound node for `*key` in `map`.
///
/// `key` must point to a readable byte. `map` must be valid for
/// `FUN_083b9168`; its iterator result must contain a valid node pointer.
/// Like retailOS, this does not reject an end/header iterator.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn byte_key_map_lower_bound_value(
    map: *mut ByteKeyMap,
    key: *const u8,
) -> *mut u8 {
    let key_pair = [key.read(), 0];
    let mut result = ByteKeyInsertResult {
        node: core::ptr::null_mut(),
        inserted: 0,
    };
    find_lower_bound(&mut result, map, key_pair.as_ptr());
    result.node.wrapping_add(0x11)
}

#[cfg(test)]
mod tests {
    use super::*;

    static TEST_LOCK: parking_lot::Mutex<()> = parking_lot::const_mutex(());
    static mut CALL: (*mut ByteKeyMap, [u8; 2]) = (core::ptr::null_mut(), [0; 2]);
    static mut NODE: *mut u8 = core::ptr::null_mut();

    unsafe extern "C" fn lower_bound(
        result: *mut ByteKeyInsertResult,
        map: *mut ByteKeyMap,
        key_pair: *const u8,
    ) {
        CALL = (map, [key_pair.read(), key_pair.add(1).read()]);
        (*result).node = NODE;
        (*result).inserted = 1;
    }

    #[test]
    fn forwards_zero_extended_key_and_returns_mapped_byte() {
        let _guard = TEST_LOCK.lock();
        unsafe {
            let mut node = [0u8; 0x20];
            let mut map_storage = [0u8; 1];
            let key = 0xff;
            NODE = node.as_mut_ptr();
            BYTE_KEY_TREE_LOWER_BOUND = lower_bound;

            let value = byte_key_map_lower_bound_value(map_storage.as_mut_ptr().cast(), &key);

            assert_eq!(CALL, (map_storage.as_mut_ptr().cast(), [0xff, 0]));
            assert_eq!(value, node.as_mut_ptr().add(0x11));
            BYTE_KEY_TREE_LOWER_BOUND = missing_byte_key_tree_lower_bound;
        }
    }
}
