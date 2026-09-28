//! Removes a SQLite page-cache page from its hash chain.

use super::release_tracked_pair::release_tracked_pair;

/// pcache_remove_from_hash — original `FUN_08395fd0` @ `0x08395fd0` (128 bytes).
///
/// Raw `osos.dec` A32 decoding establishes the exact extent
/// `0x08395fd0..0x0839604f`; the following `push {r4-r6,lr}` starts the next
/// separately linked function at `0x08396050`. The body has no unconditional
/// plain `bl` instructions and one predicated `blne`, to
/// `release_tracked_pair` @ `0x082c369c`. Its two direct callers at
/// `0x0837e1fc` and `0x0837e228` use unconditional plain `bl` instructions.
/// A linked page is spliced out of its hash bucket: its successor's previous
/// link is updated, and either its predecessor's next link or the bucket head
/// is updated. When the cache requests it, the page's tracked pair at `+0x38`
/// is released. Finally, the page's hash key and both chain links are cleared.
/// Deliberate deviation: target pointers remain `u32` words so target offsets
/// remain valid on 64-bit host fixtures.
///
/// # Safety
/// `cache` and `page` must be valid target-layout objects. If `page + 0x04` is
/// nonzero, its links and the selected bucket head must be writable; when
/// `cache + 0x14` is nonzero, `page + 0x38` must be a valid tracked pair.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn pcache_remove_from_hash(cache: *mut u8, page: *mut u8) {
    let page_words = page.cast::<u32>();
    let hash_key = page_words.add(1).read();
    if hash_key == 0 {
        return;
    }

    let next = page_words.add(2).read() as usize as *mut u8;
    let previous = page_words.add(3).read() as usize as *mut u8;
    if !next.is_null() {
        next.add(12).cast::<u32>().write(previous as usize as u32);
    }
    if previous.is_null() {
        let bucket_mask = cache.add(0xcc).cast::<u32>().read().wrapping_sub(1);
        let bucket = hash_key & bucket_mask;
        let buckets = cache.add(0xd0).cast::<u32>().read() as usize as *mut u32;
        buckets.add(bucket as usize).write(next as usize as u32);
    } else {
        previous.add(8).cast::<u32>().write(next as usize as u32);
    }
    if cache.add(0x14).read() != 0 {
        release_tracked_pair(page.add(0x38));
    }
    page_words.add(1).write(0);
    page_words.add(3).write(0);
    page_words.add(2).write(0);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use std::sync::Mutex;

    const SLAB_LEN: usize = 0x1000;
    const CACHE: usize = 0x000;
    const BUCKETS: usize = 0x100;
    const PREVIOUS: usize = 0x300;
    const PAGE: usize = 0x500;
    const NEXT: usize = 0x700;
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    unsafe fn fixture() -> Option<*mut u8> {
        let slab = try_map_u32_slab(hints::SQLITE_PCACHE_REMOVE_FROM_HASH, SLAB_LEN)?;
        core::ptr::write_bytes(slab, 0, SLAB_LEN);
        Some(slab)
    }

    #[test]
    fn removes_middle_page_and_repairs_both_neighbors() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(slab) = (unsafe { fixture() }) else {
            assert!(note_missing_u32_fixture("sqlite/pcache_remove_from_hash"));
            return;
        };
        unsafe {
            let cache = slab.add(CACHE);
            let buckets = slab.add(BUCKETS);
            let previous = slab.add(PREVIOUS);
            let page = slab.add(PAGE);
            let next = slab.add(NEXT);
            cache.add(0xcc).cast::<u32>().write(8);
            cache.add(0xd0).cast::<u32>().write(buckets as usize as u32);
            page.add(4).cast::<u32>().write(13);
            page.add(8).cast::<u32>().write(next as usize as u32);
            page.add(12).cast::<u32>().write(previous as usize as u32);
            previous.add(8).cast::<u32>().write(page as usize as u32);
            next.add(12).cast::<u32>().write(page as usize as u32);

            pcache_remove_from_hash(cache, page);

            assert_eq!(previous.add(8).cast::<u32>().read(), next as usize as u32);
            assert_eq!(next.add(12).cast::<u32>().read(), previous as usize as u32);
            assert_eq!(page.add(4).cast::<u32>().read(), 0);
            assert_eq!(page.add(8).cast::<u32>().read(), 0);
            assert_eq!(page.add(12).cast::<u32>().read(), 0);
        }
    }

    #[test]
    fn removes_bucket_head_and_ignores_unhashed_page() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(slab) = (unsafe { fixture() }) else {
            assert!(note_missing_u32_fixture("sqlite/pcache_remove_from_hash"));
            return;
        };
        unsafe {
            let cache = slab.add(CACHE);
            let buckets = slab.add(BUCKETS);
            let page = slab.add(PAGE);
            let next = slab.add(NEXT);
            cache.add(0xcc).cast::<u32>().write(8);
            cache.add(0xd0).cast::<u32>().write(buckets as usize as u32);
            page.add(4).cast::<u32>().write(13);
            page.add(8).cast::<u32>().write(next as usize as u32);
            buckets.add(5 * 4).cast::<u32>().write(page as usize as u32);

            pcache_remove_from_hash(cache, page);

            assert_eq!(buckets.add(5 * 4).cast::<u32>().read(), next as usize as u32);
            assert_eq!(next.add(12).cast::<u32>().read(), 0);
            page.add(4).cast::<u32>().write(0);
            page.add(8).cast::<u32>().write(next as usize as u32);
            pcache_remove_from_hash(cache, page);
            assert_eq!(page.add(8).cast::<u32>().read(), next as usize as u32);
        }
    }
}
