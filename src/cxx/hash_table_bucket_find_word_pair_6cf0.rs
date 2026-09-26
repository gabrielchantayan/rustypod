//! `hash_table_bucket_find_word_pair_6cf0` — original: `FUN_083d6cf0` @
//! **0x083d6cf0** (**72 bytes**, `0x083d6cf0..0x083d6d34`; the next separately
//! linked function starts at `0x083d6d38`).
//!
//! Raw ARM decoding finds two direct, unconditional inbound `bl` sites
//! (`0x0826a050`, `0x083d2548`) and no predicated inbound calls. The body has
//! one plain `bl` to `FUN_083d7b88` @ `0x083d7b88`, and no predicated calls.
//!
//! Starting after the bucket sentinel, follows the intrusive forward links.
//! Every link points 16 bytes past its node's two-word key; returns the first
//! link whose preceding key equals `key`, or NULL.
//!
//! ## Deliberate deviations
//!
//! `FUN_083d7b88` ignores its context argument and compares the two key words
//! directly, so Rust inlines that verified leaf rather than introducing an
//! unported firmware-call seam. The ignored `table` argument remains in the
//! ABI.
//! LLVM folds this byte-identical port with
//! `hash_table_bucket_find_word_pair` (`FUN_083d6d38`); both exported symbols
//! are present in the ARM archive and share its `.text` section.


use core::ptr;

/// # Safety
///
/// `bucket` must contain a target-width pointer to a sentinel link. Each link
/// reached from that sentinel must contain another target-width link pointer;
/// non-sentinel links must have two readable `u32` key words at offsets -16
/// and -12. `key` must point to two readable `u32` words.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn hash_table_bucket_find_word_pair_6cf0(
    _table: *const u8,
    bucket: *const u32,
    key: *const u32,
) -> *mut u8 {
    let wanted_first = key.read();
    let wanted_second = key.add(1).read();
    let mut link = bucket.read() as usize as *mut u8;

    loop {
        link = link.cast::<u32>().read() as usize as *mut u8;
        if link.is_null() {
            return ptr::null_mut();
        }

        let node_key = link.sub(16).cast::<u32>();
        if node_key.read() == wanted_first && node_key.add(1).read() == wanted_second {
            return link;
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use std::sync::{LazyLock, Mutex};

    const FIXTURE_LEN: usize = 0x1000;
    static LOCK: Mutex<()> = Mutex::new(());
    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::HASH_TABLE_BUCKET_FIND_WORD_PAIR_6CF0, FIXTURE_LEN)
            .map(|pointer| pointer as usize)
    });

    unsafe fn base() -> *mut u8 {
        SLAB.expect("fixture mapping was checked") as *mut u8
    }

    unsafe fn write_target_ptr(field: *mut u8, value: *mut u8) {
        field.cast::<u32>().write(value as usize as u32);
    }

    #[test]
    fn returns_null_for_an_empty_bucket() {
        let _guard = LOCK.lock().unwrap_or_else(|error| error.into_inner());
        if SLAB.is_none() {
            assert!(note_missing_u32_fixture("cxx/hash_table_bucket_find_word_pair_6cf0"));
            return;
        }
        unsafe {
            base().write_bytes(0, FIXTURE_LEN);
            let bucket = base().add(0x100).cast::<u32>();
            let sentinel = base().add(0x180);
            let key = base().add(0x300).cast::<u32>();
            write_target_ptr(bucket.cast(), sentinel);
            write_target_ptr(sentinel, ptr::null_mut());
            key.write(0x12);
            key.add(1).write(0x34);
            assert!(hash_table_bucket_find_word_pair_6cf0(base(), bucket, key).is_null());
        }
    }

    #[test]
    fn skips_nonmatching_nodes_and_returns_the_first_matching_link() {
        let _guard = LOCK.lock().unwrap_or_else(|error| error.into_inner());
        if SLAB.is_none() {
            assert!(note_missing_u32_fixture("cxx/hash_table_bucket_find_word_pair_6cf0"));
            return;
        }
        unsafe {
            base().write_bytes(0, FIXTURE_LEN);
            let bucket = base().add(0x100);
            let sentinel = base().add(0x180);
            let first_link = base().add(0x210);
            let second_link = base().add(0x250);
            let key = base().add(0x300).cast::<u32>();
            write_target_ptr(bucket, sentinel);
            write_target_ptr(sentinel, first_link);
            write_target_ptr(first_link, second_link);
            write_target_ptr(second_link, ptr::null_mut());
            first_link.sub(16).cast::<u32>().write(4);
            first_link.sub(12).cast::<u32>().write(8);
            second_link.sub(16).cast::<u32>().write(0xfeed_beef);
            second_link.sub(12).cast::<u32>().write(0xcafe_babe);
            key.write(0xfeed_beef);
            key.add(1).write(0xcafe_babe);
            assert_eq!(hash_table_bucket_find_word_pair_6cf0(base(), bucket.cast(), key), second_link);
        }
    }
}
