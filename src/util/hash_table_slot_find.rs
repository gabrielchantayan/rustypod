//! Finds the bucket slot for a key in a chained hash table.
//!
//! `hash_table_slot_find` — retailOS `FUN_080e82cc` at load address
//! `0x080e82cc` (176 bytes, `0x080e82cc..0x080e837b`; the next independently
//! linked function begins at `0x080e837c`). Raw ARM decoding verifies one
//! plain `bl`, one predicated `blhi`, and two indirect `blx` calls. The three
//! inbound direct `bl` call sites are `0x082d7b28`, `0x082d7c48`, and
//! `0x082d7e0c`.
//!
//! The table hashes the key through its +8 callback, increments +0x38, and
//! writes that hash through `hash_out`. Its primary modulus is at +0x18. When
//! its remainder is below the +0x14 threshold, it instead uses the +0x10
//! modulus. It returns the bucket word or matching node's link word: nodes
//! link at +4 and carry their hash at +8. Each visited node increments +0x58;
//! a same-hash node increments +0x3c before the +4 equality callback decides
//! whether to stop.
//!
//! Deliberate deviations: Rust obtains the divide remainder through the
//! ported `__rt_udivmod` out-pointer ABI rather than the retail r1 result.
//! Host builds expose indirect callbacks as test seams; target builds load
//! their target-width function words directly from the table.

use crate::runtime::rt_div::__rt_udivmod;

type HashKey = unsafe extern "C" fn(*mut u8) -> u32;
type KeysEqual = unsafe extern "C" fn(*mut u8, *mut u8) -> u32;

#[inline(always)]
unsafe fn word(base: *const u8, offset: usize) -> u32 {
    core::ptr::read(base.add(offset).cast::<u32>())
}

#[inline(always)]
unsafe fn increment_word(base: *mut u8, offset: usize) {
    let field = base.add(offset).cast::<u32>();
    field.write(field.read().wrapping_add(1));
}

#[cfg(target_os = "none")]
unsafe fn hash_key(table: *mut u8, key: *mut u8) -> u32 {
    let callback: HashKey = core::mem::transmute(word(table, 8) as usize);
    callback(key)
}

#[cfg(target_os = "none")]
unsafe fn keys_equal(table: *mut u8, node_key: *mut u8, key: *mut u8) -> u32 {
    let callback: KeysEqual = core::mem::transmute(word(table, 4) as usize);
    callback(node_key, key)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn zero_hash(_key: *mut u8) -> u32 { 0 }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unequal_keys(_node_key: *mut u8, _key: *mut u8) -> u32 { 1 }
#[cfg(not(target_os = "none"))]
pub static mut HASH_TABLE_HASH_KEY: HashKey = zero_hash;
#[cfg(not(target_os = "none"))]
pub static mut HASH_TABLE_KEYS_EQUAL: KeysEqual = unequal_keys;
#[cfg(not(target_os = "none"))]
unsafe fn hash_key(_table: *mut u8, key: *mut u8) -> u32 { HASH_TABLE_HASH_KEY(key) }
#[cfg(not(target_os = "none"))]
unsafe fn keys_equal(_table: *mut u8, node_key: *mut u8, key: *mut u8) -> u32 { HASH_TABLE_KEYS_EQUAL(node_key, key) }

/// Returns the slot containing `key`'s matching node, or its null insertion slot.
///
/// # Safety
///
/// `table` must have the observed target-width layout and its selected bucket
/// chain and callbacks must be readable and callable. `hash_out` is writable.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn hash_table_slot_find(
    table: *mut u8,
    key: *mut u8,
    hash_out: *mut u32,
) -> *mut u32 {
    let hash = hash_key(table, key);
    increment_word(table, 0x38);
    hash_out.write(hash);

    let mut remainder = 0;
    __rt_udivmod(hash, word(table, 0x18), &mut remainder);
    if word(table, 0x14) > remainder {
        __rt_udivmod(hash, word(table, 0x10), &mut remainder);
    }

    let mut slot = (word(table, 0) as usize as *mut u8).add(remainder as usize * 4).cast::<u32>();
    let mut node = slot.read() as usize as *mut u8;
    while !node.is_null() {
        increment_word(table, 0x58);
        if word(node, 8) == hash {
            increment_word(table, 0x3c);
            if keys_equal(table, word(node, 0) as usize as *mut u8, key) == 0 {
                return slot;
            }
        }
        slot = node.add(4).cast::<u32>();
        node = slot.read() as usize as *mut u8;
    }
    slot
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use std::sync::{LazyLock, Mutex};

    const SLAB_LEN: usize = 0x1000;
    static LOCK: Mutex<()> = Mutex::new(());
    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::HASH_TABLE_SLOT_FIND, SLAB_LEN).map(|pointer| pointer as usize)
    });
    static mut EQUAL_KEY: *mut u8 = core::ptr::null_mut();

    unsafe extern "C" fn hash_key(key: *mut u8) -> u32 { key.cast::<u32>().read() }
    unsafe extern "C" fn keys_equal(node_key: *mut u8, key: *mut u8) -> u32 {
        (node_key != key || key != EQUAL_KEY) as u32
    }

    unsafe fn put_word(base: *mut u8, offset: usize, value: *mut u8) {
        base.add(offset).cast::<u32>().write(value as usize as u32);
    }

    unsafe fn fixture() -> Option<*mut u8> {
        let slab = (*SLAB)? as *mut u8;
        slab.write_bytes(0, SLAB_LEN);
        HASH_TABLE_HASH_KEY = hash_key;
        HASH_TABLE_KEYS_EQUAL = keys_equal;
        Some(slab)
    }

    #[test]
    fn selects_secondary_modulus_and_returns_matching_link_slot() {
        let _guard = LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let Some(slab) = (unsafe { fixture() }) else {
            assert!(note_missing_u32_fixture("util/hash_table_slot_find"));
            return;
        };
        unsafe {
            let table = slab;
            let buckets = slab.add(0x100);
            let first = slab.add(0x200);
            let second = slab.add(0x240);
            let key = slab.add(0x300);
            table.add(0x14).cast::<u32>().write(6);
            EQUAL_KEY = key;
            put_word(table, 0, buckets);
            table.add(0x10).cast::<u32>().write(3);
            table.add(0x14).cast::<u32>().write(2);
            table.add(0x18).cast::<u32>().write(8);
            put_word(buckets, 4, first);
            put_word(first, 0, slab.add(0x320));
            put_word(first, 4, second);
            first.add(8).cast::<u32>().write(13);
            put_word(second, 0, key);
            put_word(second, 4, core::ptr::null_mut());
            second.add(8).cast::<u32>().write(13);
            let mut output = 0;
            assert_eq!(hash_table_slot_find(table, key, &mut output), second.add(4).cast());
            assert_eq!(output, 13);
            assert_eq!(table.add(0x38).cast::<u32>().read(), 1);
            assert_eq!(table.add(0x58).cast::<u32>().read(), 2);
            assert_eq!(table.add(0x3c).cast::<u32>().read(), 2);
        }
    }

    #[test]
    fn returns_empty_bucket_slot_without_equality_call() {
        let _guard = LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let Some(slab) = (unsafe { fixture() }) else {
            assert!(note_missing_u32_fixture("util/hash_table_slot_find"));
            return;
        };
        unsafe {
            let table = slab;
            let buckets = slab.add(0x100);
            let key = slab.add(0x300);
            key.cast::<u32>().write(5);
            put_word(table, 0, buckets);
            table.add(0x14).cast::<u32>().write(0);
            table.add(0x18).cast::<u32>().write(4);
            let mut output = 0;
            assert_eq!(hash_table_slot_find(table, key, &mut output), buckets.add(4).cast());
            assert_eq!(output, 5);
            assert_eq!(table.add(0x58).cast::<u32>().read(), 0);
            assert_eq!(table.add(0x3c).cast::<u32>().read(), 0);
        }
    }
}
