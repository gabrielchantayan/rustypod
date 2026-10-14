//! String-keyed command map value slot — `FUN_083db3d0` @ `0x083db3d0`.
//!
//! True extent: 76 bytes, ending at the next PUSH at 0x083db41c. Raw A32
//! decoding verifies three outgoing plain BLs, zero predicated BLs, and one
//! inbound plain BL (0x08290570), zero predicated inbound BLs. The caller
//! supplies a COW string in r1, omitted from Ghidra's inferred signature.
//!
//! COW-copy the key into a {string, zero value} pair, find or insert through
//! the tree operation at 0x083c28a8, release the temporary, then return the
//! node's mapped word at +0x14. Existing values are not overwritten.
//!
//! Deliberate deviations: typed repr(C) scratch accommodates wider host
//! pointers; the unported tree operation uses a literal-address BLX on ARM
//! and a replaceable host boundary. No guessed Rust callee substitution.

use crate::cxx::string::{cxx_string_copy_ctor, cxx_string_release};
use crate::cxx::string_map::{StringKeyInsertResult, StringKeyPair};

type CommandMapInsert = unsafe extern "C" fn(
    result: *mut StringKeyInsertResult,
    map: *mut u8,
    pair: *const StringKeyPair,
);

#[cfg(not(target_os = "none"))]
pub static mut COMMAND_MAP_INSERT: CommandMapInsert = missing_command_map_insert;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_command_map_insert(
    _result: *mut StringKeyInsertResult,
    _map: *mut u8,
    _pair: *const StringKeyPair,
) {
    panic!("command_map_value_slot requires tree insertion at 0x083c28a8")
}

#[inline(never)]
unsafe fn command_map_insert(
    result: *mut StringKeyInsertResult,
    map: *mut u8,
    pair: *const StringKeyPair,
) {
    #[cfg(target_os = "none")]
    let insert: CommandMapInsert = unsafe { core::mem::transmute(0x083c_28a8usize) };
    #[cfg(not(target_os = "none"))]
    let insert = unsafe { core::ptr::addr_of!(COMMAND_MAP_INSERT).read_volatile() };
    unsafe { insert(result, map, pair) };
}

/// Original: 0x083db3d0, 76 bytes, three plain BLs and no predicated BLs.
///
/// # Safety
/// `key` is a live COW string slot. `map` satisfies the retail insertion
/// contract at 0x083c28a8, which writes a live node into `result.node`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn command_map_value_slot(
    map: *mut u8,
    key: *const *mut u8,
) -> *mut u32 {
    let mut pair = StringKeyPair { key: core::ptr::null_mut(), value: 0 };
    unsafe { cxx_string_copy_ctor(core::ptr::addr_of_mut!(pair.key), key) };
    let mut result = StringKeyInsertResult { node: core::ptr::null_mut(), inserted: 0 };
    unsafe { command_map_insert(&mut result, map, &pair) };
    let node = result.node;
    unsafe { cxx_string_release(core::ptr::addr_of_mut!(pair.key)) };
    node.wrapping_add(0x14).cast()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cxx::string::{empty_rep_data, StringRep};
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());

    #[repr(C)]
    struct Map {
        node: [u32; 6],
        key: *mut u8,
    }

    unsafe extern "C" fn insert(
        result: *mut StringKeyInsertResult,
        map: *mut u8,
        pair: *const StringKeyPair,
    ) {
        let map = unsafe { &mut *map.cast::<Map>() };
        if map.key.is_null() {
            unsafe { cxx_string_copy_ctor(&mut map.key, &(*pair).key) };
            map.node[5] = unsafe { (*pair).value };
            unsafe { (*result).inserted = 1 };
        } else {
            assert_eq!(map.key, unsafe { (*pair).key });
            unsafe { (*result).inserted = 0 };
        }
        unsafe { (*result).node = map.node.as_mut_ptr().cast() };
    }

    struct Guard(CommandMapInsert);
    impl Drop for Guard {
        fn drop(&mut self) {
            unsafe { core::ptr::addr_of_mut!(COMMAND_MAP_INSERT).write(self.0) };
        }
    }

    #[test]
    fn insertion_retains_key_and_duplicate_preserves_value() {
        let _lock = LOCK.lock();
        #[repr(C)]
        struct Rep { header: StringRep, data: [u8; 4] }
        let mut rep = Rep {
            header: StringRep { refcount: 0, capacity: 3, length: 3 },
            data: *b"cmd\0",
        };
        unsafe {
            let _guard = Guard(core::ptr::addr_of!(COMMAND_MAP_INSERT).read());
            core::ptr::addr_of_mut!(COMMAND_MAP_INSERT).write(insert);
            for key in [rep.data.as_mut_ptr(), empty_rep_data()] {
                let mut map = Map { node: [0xa5a5a5a5; 6], key: core::ptr::null_mut() };
                let slot = command_map_value_slot((&mut map as *mut Map).cast(), &key);
                assert_eq!(*slot, 0);
                assert_eq!(map.node[0..5], [0xa5a5a5a5; 5]);
                if key != empty_rep_data() { assert_eq!(rep.header.refcount, 1); }
                *slot = 0xfedcba98;
                let again = command_map_value_slot((&mut map as *mut Map).cast(), &key);
                assert_eq!(again, slot);
                assert_eq!(*again, 0xfedcba98);
                assert_eq!(map.key, key);
                if key != empty_rep_data() { assert_eq!(rep.header.refcount, 1); }
                cxx_string_release(&mut map.key);
                assert_eq!(rep.header.refcount, 0);
            }
        }
    }
}
