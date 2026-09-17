//! SQLite pager-cache truncation — `pcacheTruncate`.
//!
//! `pcache_truncate` — original: `FUN_082de78c` @ 0x082de78c (136 bytes;
//! 5 outbound plain `bl`, 0 predicated `bl`; 4 inbound plain `bl`, 0
//! predicated `bl`). Raw `osos.dec` words establish the exact extent
//! `0x082de78c..0x082de814`; the following `push {r4,r5,r6,lr}` begins the
//! next function.
//!
//! Walks the cache's page chain from +0x88, stopping at the first page whose
//! number is not above the cache limit at +0x24. Referenced pages keep their
//! header but have their page-sized payload cleared. Unreferenced pages are
//! unlinked from the hash and LRU chains, their payload and header are freed,
//! and the cache page count is decremented.
//!
//! Deliberate deviations: the unported `FUN_08396050` hash-unlink callee is
//! reproduced from its verified target-word accesses; its opaque leading call
//! to unported `FUN_082d8e30` is omitted because its identity is not known.

use crate::heap::tracked::tracked_free;
use crate::libc::memzero::memzero;
use super::pcache_remove_from_lru_list::pcache_remove_from_lru_list;

const CACHE_TRUNCATE_LIMIT: usize = 0x24;
const CACHE_PAGE_SIZE: usize = 0x40;
const CACHE_PAGE_COUNT: usize = 0x44;
const CACHE_PAGE_CHAIN: usize = 0x88;
const CACHE_HASH_MASK: usize = 0xcc;
const CACHE_HASH_BUCKETS: usize = 0xd0;
const PAGE_CACHE: usize = 0x00;
const PAGE_NUMBER: usize = 0x04;
const PAGE_HASH_PREVIOUS: usize = 0x08;
const PAGE_HASH_NEXT: usize = 0x0c;
const PAGE_CHAIN_NEXT: usize = 0x18;
const PAGE_REFERENCE_COUNT: usize = 0x22;
const PAGE_DATA: usize = 0x34;

#[inline(always)]
unsafe fn read_target_pointer(base: *const u8, offset: usize) -> *mut u8 {
    unsafe { base.add(offset).cast::<u32>().read() as usize as *mut u8 }
}

#[inline(always)]
unsafe fn write_target_pointer(base: *mut u8, offset: usize, value: *mut u8) {
    unsafe { base.add(offset).cast::<u32>().write(value as usize as u32) };
}

unsafe fn remove_page_from_hash(page: *mut u8) {
    let cache = unsafe { read_target_pointer(page, PAGE_CACHE) };
    let page_number = unsafe { page.add(PAGE_NUMBER).cast::<u32>().read() };
    if page_number == 0 {
        return;
    }
    let previous = unsafe { read_target_pointer(page, PAGE_HASH_PREVIOUS) };
    let next = unsafe { read_target_pointer(page, PAGE_HASH_NEXT) };
    if !next.is_null() {
        unsafe { write_target_pointer(next, PAGE_HASH_PREVIOUS, previous) };
    }
    if previous.is_null() {
        let mask = unsafe { cache.add(CACHE_HASH_MASK).cast::<u32>().read() };
        let buckets = unsafe { read_target_pointer(cache, CACHE_HASH_BUCKETS) };
        unsafe { write_target_pointer(buckets, (page_number & (mask - 1)) as usize * 4, next) };
    } else {
        unsafe { write_target_pointer(previous, PAGE_HASH_NEXT, next) };
    }
    unsafe {
        page.add(PAGE_NUMBER).cast::<u32>().write(0);
        write_target_pointer(page, PAGE_HASH_NEXT, core::ptr::null_mut());
        write_target_pointer(page, PAGE_HASH_PREVIOUS, core::ptr::null_mut());
    }
}

/// `pcacheTruncate` — original: `FUN_082de78c` @ 0x082de78c (136 bytes;
/// 5 outbound plain `bl`, 0 predicated `bl`; 4 inbound plain `bl`, 0
/// predicated `bl`).
///
/// `cache` must name the retail 32-bit PCache layout and all traversed pages.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.pcache_truncate")]
pub unsafe extern "C" fn pcache_truncate(cache: *mut u8) {
    let limit = unsafe { cache.add(CACHE_TRUNCATE_LIMIT).cast::<u32>().read() };
    let mut link = unsafe { cache.add(CACHE_PAGE_CHAIN).cast::<u32>() };
    loop {
        let page = unsafe { link.read() as usize as *mut u8 };
        if page.is_null() || unsafe { page.add(PAGE_NUMBER).cast::<u32>().read() } <= limit {
            return;
        }
        if unsafe { page.add(PAGE_REFERENCE_COUNT).cast::<i16>().read() } > 0 {
            let data = unsafe { read_target_pointer(page, PAGE_DATA) };
            let page_size = unsafe { cache.add(CACHE_PAGE_SIZE).cast::<u32>().read() };
            unsafe { memzero(data, page_size as usize) };
            link = unsafe { page.add(PAGE_CHAIN_NEXT).cast::<u32>() };
            continue;
        }
        let next = unsafe { read_target_pointer(page, PAGE_CHAIN_NEXT) };
        unsafe {
            link.write(next as usize as u32);
            remove_page_from_hash(page);
            pcache_remove_from_lru_list(page);
            tracked_free(read_target_pointer(page, PAGE_DATA));
            tracked_free(page);
            let count = cache.add(CACHE_PAGE_COUNT).cast::<u32>();
            count.write(count.read() - 1);
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use core::ptr;
    use std::sync::{LazyLock, Mutex, MutexGuard};

    const FIXTURE_LEN: usize = 0x1000;
    const CACHE: usize = 0x000;
    const FIRST: usize = 0x200;
    const SECOND: usize = 0x400;
    const DATA: usize = 0x800;
    static FIXTURE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::SQLITE_PCACHE_TRUNCATE, FIXTURE_LEN).map(|p| p as usize)
    });
    static FIXTURE_LOCK: Mutex<()> = Mutex::new(());

    fn fixture() -> Option<(*mut u8, MutexGuard<'static, ()>)> {
        let guard = FIXTURE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let base = (*FIXTURE)? as *mut u8;
        unsafe { ptr::write_bytes(base, 0, FIXTURE_LEN) };
        Some((base, guard))
    }
    unsafe fn set_word(base: *mut u8, offset: usize, value: u32) {
        unsafe { base.add(offset).cast::<u32>().write(value) };
    }
    unsafe fn set_pointer(base: *mut u8, offset: usize, value: *mut u8) {
        unsafe { set_word(base, offset, value as usize as u32) };
    }

    #[test]
    fn clears_referenced_pages_above_limit_then_stops_at_the_limit() {
        let Some((base, _guard)) = fixture() else {
            assert!(note_missing_u32_fixture(module_path!()));
            return;
        };
        unsafe {
            let cache = base.add(CACHE);
            let first = base.add(FIRST);
            let second = base.add(SECOND);
            let data = base.add(DATA);
            ptr::write_bytes(data, 0xa5, 32);
            set_word(cache, CACHE_TRUNCATE_LIMIT, 9);
            set_word(cache, CACHE_PAGE_SIZE, 32);
            set_pointer(cache, CACHE_PAGE_CHAIN, first);
            set_word(first, PAGE_NUMBER, 10);
            first.add(PAGE_REFERENCE_COUNT).cast::<i16>().write(1);
            set_pointer(first, PAGE_DATA, data);
            set_pointer(first, PAGE_CHAIN_NEXT, second);
            set_word(second, PAGE_NUMBER, 9);
            second.add(PAGE_REFERENCE_COUNT).cast::<i16>().write(1);
            set_pointer(second, PAGE_CHAIN_NEXT, ptr::null_mut());

            pcache_truncate(cache);

            assert!(core::slice::from_raw_parts(data, 32).iter().all(|&byte| byte == 0));
            assert_eq!(first.add(PAGE_NUMBER).cast::<u32>().read(), 10);
            assert_eq!(cache.add(CACHE_PAGE_CHAIN).cast::<u32>().read(), first as usize as u32);
            assert_eq!(second.add(PAGE_NUMBER).cast::<u32>().read(), 9);
        }
    }

    #[test]
    fn leaves_the_chain_untouched_when_its_head_is_within_limit() {
        let Some((base, _guard)) = fixture() else {
            assert!(note_missing_u32_fixture(module_path!()));
            return;
        };
        unsafe {
            let cache = base.add(CACHE);
            let first = base.add(FIRST);
            set_word(cache, CACHE_TRUNCATE_LIMIT, 10);
            set_pointer(cache, CACHE_PAGE_CHAIN, first);
            set_word(first, PAGE_NUMBER, 10);
            first.add(PAGE_REFERENCE_COUNT).cast::<i16>().write(0);

            pcache_truncate(cache);

            assert_eq!(cache.add(CACHE_PAGE_CHAIN).cast::<u32>().read(), first as usize as u32);
            assert_eq!(first.add(PAGE_NUMBER).cast::<u32>().read(), 10);
        }
    }
}
