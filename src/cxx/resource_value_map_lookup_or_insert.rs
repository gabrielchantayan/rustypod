//! UI resource-value map lookup-or-insert — `FUN_083db75c` @ 0x083db75c.
//!
//! Raw `osos.dec` establishes the exact 76-byte extent: 19 ARM words from
//! `push {r4,r5,lr}` at 0x083db75c through `pop {r4,r5,pc}` at 0x083db7a4;
//! the next independently entered function begins at 0x083db7a8. Decoding
//! every word finds three unconditional plain `bl` instructions and no
//! predicated `bl`: veneers at 0x083db770 and 0x083db794 resolve to
//! `cxx_string_copy_ctor` @ 0x083d8c30 and `cxx_string_release` @ 0x083d8b04,
//! and 0x083db784 resolves to the still-unported tree operation @ 0x083c6050.
//!
//! Algorithm: COW-copy `key` into a stack `{string, value}` pair, initialize
//! its value word to zero, let the tree operation find or insert the pair,
//! release the temporary string, and return `result.node + 0x14`, the mapped
//! value word. The tree operation's identity has not been established, so it
//! remains a fixed-address firmware boundary and a replaceable host seam.
//!
//! Deliberate deviations: Rust uses typed locals rather than the original
//! stack offsets; the unknown tree operation is an indirect call rather than
//! its raw veneer branch. The three semantic call boundaries are retained.

use crate::cxx::string::{cxx_string_copy_ctor, cxx_string_release};
use crate::cxx::string_map::{StringKeyInsertResult, StringKeyPair};

type ResourceValueMapInsert = unsafe extern "C" fn(
    result: *mut StringKeyInsertResult,
    map: *mut u8,
    pair: *const StringKeyPair,
);

const RESOURCE_VALUE_MAP_INSERT_ADDRESS: usize = 0x083c_6050;

#[cfg(target_os = "none")]
#[inline(never)]
unsafe fn resource_value_map_insert(
    result: *mut StringKeyInsertResult,
    map: *mut u8,
    pair: *const StringKeyPair,
) {
    let insert: ResourceValueMapInsert = unsafe {
        core::mem::transmute(RESOURCE_VALUE_MAP_INSERT_ADDRESS)
    };
    unsafe { insert(result, map, pair) }
}

#[cfg(not(target_os = "none"))]
static mut RESOURCE_VALUE_MAP_INSERT: ResourceValueMapInsert = missing_resource_value_map_insert;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_resource_value_map_insert(
    result: *mut StringKeyInsertResult,
    _map: *mut u8,
    _pair: *const StringKeyPair,
) {
    unsafe {
        (*result).node = core::ptr::null_mut();
        (*result).inserted = 0;
    }
}

#[cfg(not(target_os = "none"))]
#[inline(never)]
unsafe fn resource_value_map_insert(
    result: *mut StringKeyInsertResult,
    map: *mut u8,
    pair: *const StringKeyPair,
) {
    let insert = unsafe { core::ptr::addr_of!(RESOURCE_VALUE_MAP_INSERT).read_volatile() };
    unsafe { insert(result, map, pair) }
}

/// resource_value_map_lookup_or_insert — original: `FUN_083db75c` @
/// 0x083db75c (76 bytes; three unconditional plain `bl` instructions, no
/// predicated `bl`; the next independently entered function is 0x083db7a8).
///
/// # Safety
///
/// `key` must point to a live COW `basic_string` word. `map` and its tree
/// operation must satisfy the 0x083c6050 result contract: write a node pointer
/// at `result + 0` and an inserted flag byte at `result + 4`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn resource_value_map_lookup_or_insert(
    map: *mut u8,
    key: *const *mut u8,
) -> *mut u8 {
    let mut pair = StringKeyPair {
        key: core::ptr::null_mut(),
        value: 0,
    };
    unsafe { cxx_string_copy_ctor(core::ptr::addr_of_mut!(pair.key), key) };

    let mut result = StringKeyInsertResult {
        node: core::ptr::null_mut(),
        inserted: 0,
    };
    unsafe { resource_value_map_insert(&mut result, map, &pair) };
    let node = result.node;

    unsafe { cxx_string_release(core::ptr::addr_of_mut!(pair.key)) };
    node.wrapping_add(0x14)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::cxx::string::empty_rep_data;
    use parking_lot::Mutex;

    static OPS_LOCK: Mutex<()> = Mutex::new(());

    struct InsertGuard(ResourceValueMapInsert);

    impl InsertGuard {
        unsafe fn install(insert: ResourceValueMapInsert) -> Self {
            let previous = unsafe {
                core::ptr::addr_of!(RESOURCE_VALUE_MAP_INSERT).read_volatile()
            };
            unsafe {
                core::ptr::addr_of_mut!(RESOURCE_VALUE_MAP_INSERT).write_volatile(insert);
            }
            Self(previous)
        }
    }

    impl Drop for InsertGuard {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(RESOURCE_VALUE_MAP_INSERT).write_volatile(self.0);
            }
        }
    }

    #[test]
    fn null_result_node_returns_original_wrapping_offset() {
        let _lock = OPS_LOCK.lock();
        unsafe {
            let _guard = InsertGuard::install(missing_resource_value_map_insert);
            let key = empty_rep_data();
            let value = resource_value_map_lookup_or_insert(core::ptr::null_mut(), &key);
            assert_eq!(value as usize, 0x14);
        }
    }

    #[test]
    fn passes_zero_value_pair_and_returns_node_value_offset() {
        let _lock = OPS_LOCK.lock();
        static mut NODE: [u8; 0x20] = [0; 0x20];
        static mut SEEN_MAP: usize = 0;
        static mut SEEN_KEY: usize = 0;
        static mut SEEN_VALUE: u32 = 1;

        unsafe extern "C" fn record_insert(
            result: *mut StringKeyInsertResult,
            map: *mut u8,
            pair: *const StringKeyPair,
        ) {
            unsafe {
                core::ptr::addr_of_mut!(SEEN_MAP).write_volatile(map as usize);
                core::ptr::addr_of_mut!(SEEN_KEY).write_volatile((*pair).key as usize);
                core::ptr::addr_of_mut!(SEEN_VALUE).write_volatile((*pair).value);
                (*result).node = core::ptr::addr_of_mut!(NODE).cast();
                (*result).inserted = 1;
            }
        }

        unsafe {
            let _guard = InsertGuard::install(record_insert);
            let mut map = [0u8; 1];
            let key = empty_rep_data();
            let value = resource_value_map_lookup_or_insert(map.as_mut_ptr(), &key);

            assert_eq!(core::ptr::addr_of!(SEEN_MAP).read_volatile(), map.as_mut_ptr() as usize);
            assert_eq!(core::ptr::addr_of!(SEEN_KEY).read_volatile(), key as usize);
            assert_eq!(core::ptr::addr_of!(SEEN_VALUE).read_volatile(), 0);
            assert_eq!(value, core::ptr::addr_of_mut!(NODE).cast::<u8>().add(0x14));
        }
    }
}
