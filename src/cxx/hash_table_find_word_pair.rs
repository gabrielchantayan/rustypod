//! Finds a two-word key in its hash bucket, returning an iterator pair.
//!
//! `FUN_083d21c8` @ **0x083d21c8** is **124 bytes**
//! (`0x083d21c8..0x083d2243`; the next real function starts at `0x083d2244`).
//! Raw A32 decoding finds two direct, unconditional inbound `bl` sites
//! (`0x08269768`, `0x082698e8`) and no predicated inbound calls. Its body has
//! two plain `bl` calls (`hash_word_pair` @ `0x083d63cc` and `__rt_udiv` @
//! `0x08036f14`) plus one plain `bl` to the bucket-chain search @ `0x083d6d38`,
//! and no predicated calls.
//!
//! It hashes the two-word key, selects the matching bucket, and writes an
//! iterator pair: the bucket slot address followed by its matching link, or
//! the bucket head when no link matches.
//!
//! ## Deliberate deviations
//!
//! The verified hash and divide remainder are expressed directly, while the
//! existing `hash_table_bucket_find_word_pair` port preserves the chain-search
//! call seam. Target pointers remain `u32` words so host pointer width cannot
//! alter the table layout.

use crate::cxx::hash_table_bucket_find_word_pair::hash_table_bucket_find_word_pair;
use crate::runtime::rt_div::__rt_udivmod;

const BUCKET_OFFSET: usize = 0x14 / 4;
const BUCKET_COUNT: usize = 0x18 / 4;

#[inline(always)]
fn hash_word_pair(first: u32, second: u32) -> u32 {
    let mut value = ((second as u64) << 32 | first as u64).wrapping_sub(1);
    value ^= value >> 22;
    value = value.wrapping_add(!(value << 13));
    value ^= value >> 8;
    value = value.wrapping_add(value << 3);
    value ^= value >> 15;
    value = value.wrapping_add(!(value << 27));
    (value ^ (value >> 31)) as u32
}

/// # Safety
///
/// `output` and `key` must each identify two writable or readable `u32` words.
/// `table` must identify the target-layout hash table, including its +0x14
/// bucket-array byte offset and +0x18 bucket count. The selected bucket and
/// every non-NULL link it reaches must satisfy
/// `hash_table_bucket_find_word_pair`'s safety contract.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn hash_table_find_word_pair(output: *mut u32, table: *const u32, key: *const u32) {
    let wanted_first = unsafe { key.read() };
    let wanted_second = unsafe { key.add(1).read() };
    let mut bucket_index = 0;
    unsafe { __rt_udivmod(hash_word_pair(wanted_first, wanted_second), table.add(BUCKET_COUNT).read(), &mut bucket_index) };
    let bucket = unsafe {
        (table as *const u8)
            .add(table.add(BUCKET_OFFSET).read() as usize)
            .cast::<u32>()
            .add(bucket_index as usize)
    };
    let link = unsafe { hash_table_bucket_find_word_pair(table.cast(), bucket, key) };
    unsafe {
        output.write(bucket as usize as u32);
        output.add(1).write(if link.is_null() { bucket.read() } else { link as usize as u32 });
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use std::sync::{LazyLock, Mutex};

    const FIXTURE_LEN: usize = 0x1000;
    const NODE_KEY_OFFSET: usize = 0x10;
    static LOCK: Mutex<()> = Mutex::new(());
    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::HASH_TABLE_FIND_WORD_PAIR, FIXTURE_LEN).map(|pointer| pointer as usize)
    });

    unsafe fn base() -> *mut u8 { SLAB.expect("fixture mapping was checked") as *mut u8 }

    unsafe fn target_write(field: *mut u8, value: *mut u8) {
        unsafe { field.cast::<u32>().write(value as usize as u32) };
    }

    unsafe fn prepare(key_first: u32, key_second: u32) -> (*mut u32, *mut u32, *mut u8) {
        let base = unsafe { base() };
        let table = base.cast::<u32>();
        let bucket = unsafe { base.add(0x100) };
        let key = unsafe { base.add(0x300).cast::<u32>() };
        unsafe {
            table.add(BUCKET_OFFSET).write(bucket.offset_from(base) as u32);
            table.add(BUCKET_COUNT).write(1);
            key.write(key_first);
            key.add(1).write(key_second);
        }
        (table, key, bucket)
    }

    #[test]
    fn returns_the_matching_link_after_collision_nodes() {
        let _guard = LOCK.lock().unwrap_or_else(|error| error.into_inner());
        if SLAB.is_none() {
            assert!(note_missing_u32_fixture("cxx/hash_table_find_word_pair"));
            return;
        }
        unsafe {
            let (table, key, bucket) = prepare(0xfeed_beef, 0xcafe_babe);
            let first = base().add(0x208);
            let matching = base().add(0x228);
            target_write(bucket, first);
            target_write(first, matching);
            target_write(matching, core::ptr::null_mut());
            first.sub(NODE_KEY_OFFSET).cast::<u32>().write(1);
            first.sub(NODE_KEY_OFFSET - 4).cast::<u32>().write(2);
            matching.sub(NODE_KEY_OFFSET).cast::<u32>().write(key.read());
            matching.sub(NODE_KEY_OFFSET - 4).cast::<u32>().write(key.add(1).read());
            let output = base().add(0x380).cast::<u32>();
            hash_table_find_word_pair(output, table, key);
            assert_eq!(output.read(), bucket as usize as u32);
            assert_eq!(output.add(1).read(), matching as usize as u32);
        }
    }

    #[test]
    fn returns_the_bucket_head_when_the_key_is_absent() {
        let _guard = LOCK.lock().unwrap_or_else(|error| error.into_inner());
        if SLAB.is_none() {
            assert!(note_missing_u32_fixture("cxx/hash_table_find_word_pair"));
            return;
        }
        unsafe {
            let (table, key, bucket) = prepare(7, 9);
            let link = base().add(0x208);
            target_write(bucket, link);
            target_write(link, core::ptr::null_mut());
            link.sub(NODE_KEY_OFFSET).cast::<u32>().write(1);
            link.sub(NODE_KEY_OFFSET - 4).cast::<u32>().write(2);
            let output = base().add(0x380).cast::<u32>();
            hash_table_find_word_pair(output, table, key);
            assert_eq!(output.read(), bucket as usize as u32);
            assert_eq!(output.add(1).read(), link as usize as u32);
        }
    }
}
