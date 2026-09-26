//! `hash_table_contains_word_pair` — original: `FUN_083d6cac` @
//! **0x083d6cac** (**68 bytes**, `0x083d6cac..0x083d6cf0`; the next real
//! function begins at `0x083d6cf0`).
//!
//! Raw A32 decoding finds two direct, unconditional inbound `bl` sites
//! (`0x08269a5c`, `0x0826a340`) and no predicated inbound calls. The body has
//! three plain `bl` calls (`FUN_083d63cc`, `__rt_udiv` @ `0x08036f14`, and
//! `FUN_083d6dc8`) and no predicated calls.
//!
//! Hashes a two-word key with the table's 64-bit Jenkins mix, selects its
//! modulo bucket, then follows that bucket's intrusive links for an equal key.
//! It returns whether a matching link exists.
//!
//! ## Deliberate deviations
//!
//! The hash mix, unsigned divide remainder, and key comparison are expressed
//! directly instead of adding seams for the two adjacent unported helpers.
//! Target-width links and keys remain `u32` words on hosts.

use crate::runtime::rt_div::__rt_udivmod;

const BUCKET_OFFSET: usize = 0x14 / 4;
const BUCKET_COUNT: usize = 0x18 / 4;
const NODE_KEY_OFFSET: usize = 0x08;

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
/// `table` must identify the target-layout hash table: its `+0x04` hash base,
/// `+0x14` bucket-array byte offset, and `+0x18` bucket count must be readable.
/// Its selected bucket and every link reachable through it must contain
/// target-width pointers; each non-NULL link has two readable key words at
/// offsets `-8` and `-4`. `key` must point to two readable `u32` words.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn hash_table_contains_word_pair(table: *const u32, key: *const u32) -> bool {
    let wanted_first = unsafe { key.read() };
    let wanted_second = unsafe { key.add(1).read() };
    let hash = hash_word_pair(wanted_first, wanted_second);
    let mut bucket_index = 0;
    unsafe { __rt_udivmod(hash, table.add(BUCKET_COUNT).read(), &mut bucket_index) };
    let bucket = unsafe {
        (table as *const u8)
            .add(table.add(BUCKET_OFFSET).read() as usize)
            .cast::<u32>()
            .add(bucket_index as usize)
    };
    let mut link = unsafe { bucket.read() } as usize as *mut u8;

    while !link.is_null() {
        let node_key = unsafe { link.sub(NODE_KEY_OFFSET).cast::<u32>() };
        if unsafe { node_key.read() } == wanted_first && unsafe { node_key.add(1).read() } == wanted_second {
            return true;
        }
        link = unsafe { link.cast::<u32>().read() } as usize as *mut u8;
    }
    false
}

#[cfg(test)]
mod tests {
    use core::ptr;
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use std::sync::{LazyLock, Mutex};

    const FIXTURE_LEN: usize = 0x1000;
    static LOCK: Mutex<()> = Mutex::new(());
    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::HASH_TABLE_CONTAINS_WORD_PAIR, FIXTURE_LEN)
            .map(|pointer| pointer as usize)
    });

    unsafe fn base() -> *mut u8 { SLAB.expect("fixture mapping was checked") as *mut u8 }

    unsafe fn target_write(field: *mut u8, value: *mut u8) {
        field.cast::<u32>().write(value as usize as u32);
    }

    #[test]
    fn finds_a_key_in_its_hash_bucket() {
        let _guard = LOCK.lock().unwrap_or_else(|error| error.into_inner());
        if SLAB.is_none() {
            assert!(note_missing_u32_fixture("cxx/hash_table_contains_word_pair"));
            return;
        }
        unsafe {
            let table = base().cast::<u32>();
            let bucket_base = base().add(0x100);
            let link = base().add(0x208);
            let key = base().add(0x300).cast::<u32>();
            table.add(BUCKET_OFFSET).write(bucket_base.offset_from(base()) as u32);
            table.add(BUCKET_COUNT).write(3);
            key.write(0xfeed_beef); key.add(1).write(0xcafe_babe);
            let bucket = hash_word_pair(key.read(), key.add(1).read()) % 3;
            target_write(bucket_base.add(bucket as usize * 4), link);
            target_write(link, ptr::null_mut());
            link.sub(NODE_KEY_OFFSET).cast::<u32>().write(key.read());
            link.sub(4).cast::<u32>().write(key.add(1).read());
            assert!(hash_table_contains_word_pair(table, key));
        }
    }

    #[test]
    fn rejects_a_collision_chain_without_the_key() {
        let _guard = LOCK.lock().unwrap_or_else(|error| error.into_inner());
        if SLAB.is_none() {
            assert!(note_missing_u32_fixture("cxx/hash_table_contains_word_pair"));
            return;
        }
        unsafe {
            let table = base().cast::<u32>();
            let bucket_base = base().add(0x100);
            let first_link = base().add(0x208);
            let second_link = base().add(0x228);
            let key = base().add(0x300).cast::<u32>();
            table.add(BUCKET_OFFSET).write(bucket_base.offset_from(base()) as u32);
            table.add(BUCKET_COUNT).write(1);
            key.write(7); key.add(1).write(9);
            target_write(bucket_base, first_link);
            target_write(first_link, second_link);
            target_write(second_link, ptr::null_mut());
            first_link.sub(NODE_KEY_OFFSET).cast::<u32>().write(1);
            first_link.sub(4).cast::<u32>().write(2);
            second_link.sub(NODE_KEY_OFFSET).cast::<u32>().write(3);
            second_link.sub(4).cast::<u32>().write(4);
            assert!(!hash_table_contains_word_pair(table, key));
        }
    }
}
