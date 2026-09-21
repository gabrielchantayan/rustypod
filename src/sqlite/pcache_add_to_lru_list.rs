//! SQLite pager-cache LRU insertion — `pcacheAddToLruList`.
//!
//! `pcache_add_to_lru_list` — original: `FUN_082d90b0` @ 0x082d90b0
//! (60 bytes; 3 direct `bl` call sites, all unconditional).
//!
//! Raw `osos.dec` disassembly establishes the exact body as
//! `0x082d90b0..0x082d90e8`; the next separately linked function starts at
//! `0x082d90ec` with `push {r4,r5,lr}`. Decoding every ARM B/BL immediate in
//! the image finds inbound plain `bl` calls at `0x082de99c`, `0x0837e288`, and
//! `0x0837e2fc`; there are no predicated calls or outbound calls.
//!
//! A `PgHdr` has its LRU-list membership byte at +0x1d, owner cache at +0x00,
//! and previous/next LRU links at +0x24/+0x28. If absent, insert it at the
//! cache head (+0x90), repair the old head's previous link, and mark it active.
//! No deliberate deviations.

const PAGE_CACHE: usize = 0x00;
const PAGE_ON_LRU_LIST: usize = 0x1d;
const PAGE_LRU_PREVIOUS: usize = 0x24;
const PAGE_LRU_NEXT: usize = 0x28;
const CACHE_LRU_HEAD: usize = 0x90;

#[inline(always)]
unsafe fn read_target_pointer(base: *const u8, offset: usize) -> *mut u8 {
    unsafe { base.add(offset).cast::<u32>().read() as usize as *mut u8 }
}

#[inline(always)]
unsafe fn write_target_pointer(base: *mut u8, offset: usize, value: *mut u8) {
    unsafe { base.add(offset).cast::<u32>().write(value as usize as u32) };
}

/// `pcacheAddToLruList` — original: `FUN_082d90b0` @ 0x082d90b0 (60 bytes;
/// 3 direct `bl` call sites, all unconditional).
///
/// Inserts `page` at the front of its owner's intrusive LRU list when its byte
/// flag at `+0x1d` is zero. The page requires a valid owner at `+0x00`; an
/// existing cache head requires writable target-layout link words.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.pcache_add_to_lru_list")]
pub unsafe extern "C" fn pcache_add_to_lru_list(page: *mut u8) {
    if unsafe { page.add(PAGE_ON_LRU_LIST).read() } != 0 {
        return;
    }

    let cache = unsafe { read_target_pointer(page, PAGE_CACHE) };
    unsafe { page.add(PAGE_ON_LRU_LIST).write(1) };
    let previous_head = unsafe { read_target_pointer(cache, CACHE_LRU_HEAD) };
    unsafe { write_target_pointer(page, PAGE_LRU_PREVIOUS, previous_head) };
    if !previous_head.is_null() {
        unsafe { write_target_pointer(previous_head, PAGE_LRU_NEXT, page) };
    }
    unsafe { write_target_pointer(page, PAGE_LRU_NEXT, core::ptr::null_mut()) };
    unsafe { write_target_pointer(cache, CACHE_LRU_HEAD, page) };
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use core::ptr;
    use std::sync::{LazyLock, Mutex, MutexGuard};

    const FIXTURE_LEN: usize = 0x1000;
    const CACHE_OFFSET: usize = 0x000;
    const HEAD_OFFSET: usize = 0x200;
    const PAGE_OFFSET: usize = 0x300;

    static FIXTURE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::SQLITE_PCACHE_ADD_TO_LRU_LIST, FIXTURE_LEN)
            .map(|pointer| pointer as usize)
    });
    static FIXTURE_LOCK: Mutex<()> = Mutex::new(());

    fn fixture() -> Option<(*mut u8, MutexGuard<'static, ()>)> {
        let guard = FIXTURE_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let base = (*FIXTURE)? as *mut u8;
        unsafe { ptr::write_bytes(base, 0, FIXTURE_LEN) };
        Some((base, guard))
    }

    unsafe fn word(base: *const u8, offset: usize) -> u32 {
        unsafe { base.add(offset).cast::<u32>().read() }
    }

    unsafe fn set_pointer(base: *mut u8, offset: usize, value: *mut u8) {
        unsafe { base.add(offset).cast::<u32>().write(value as usize as u32) };
    }

    #[test]
    fn inactive_page_becomes_the_only_head() {
        let Some((base, _guard)) = fixture() else {
            assert!(note_missing_u32_fixture(module_path!()));
            return;
        };
        unsafe {
            let cache = base.add(CACHE_OFFSET);
            let page = base.add(PAGE_OFFSET);
            set_pointer(page, PAGE_CACHE, cache);

            pcache_add_to_lru_list(page);

            assert_eq!(page.add(PAGE_ON_LRU_LIST).read(), 1);
            assert_eq!(word(cache, CACHE_LRU_HEAD), page as usize as u32);
            assert_eq!(word(page, PAGE_LRU_PREVIOUS), 0);
            assert_eq!(word(page, PAGE_LRU_NEXT), 0);
        }
    }

    #[test]
    fn inactive_page_precedes_old_head_and_repairs_back_link() {
        let Some((base, _guard)) = fixture() else {
            assert!(note_missing_u32_fixture(module_path!()));
            return;
        };
        unsafe {
            let cache = base.add(CACHE_OFFSET);
            let old_head = base.add(HEAD_OFFSET);
            let page = base.add(PAGE_OFFSET);
            set_pointer(page, PAGE_CACHE, cache);
            set_pointer(cache, CACHE_LRU_HEAD, old_head);
            set_pointer(old_head, PAGE_LRU_NEXT, ptr::null_mut());

            pcache_add_to_lru_list(page);

            assert_eq!(word(cache, CACHE_LRU_HEAD), page as usize as u32);
            assert_eq!(word(page, PAGE_LRU_PREVIOUS), old_head as usize as u32);
            assert_eq!(word(page, PAGE_LRU_NEXT), 0);
            assert_eq!(word(old_head, PAGE_LRU_NEXT), page as usize as u32);
        }
    }

    #[test]
    fn active_page_leaves_the_list_and_links_untouched() {
        let Some((base, _guard)) = fixture() else {
            assert!(note_missing_u32_fixture(module_path!()));
            return;
        };
        unsafe {
            let cache = base.add(CACHE_OFFSET);
            let old_head = base.add(HEAD_OFFSET);
            let page = base.add(PAGE_OFFSET);
            set_pointer(page, PAGE_CACHE, cache);
            page.add(PAGE_ON_LRU_LIST).write(2);
            set_pointer(page, PAGE_LRU_PREVIOUS, old_head);
            set_pointer(page, PAGE_LRU_NEXT, old_head);
            set_pointer(cache, CACHE_LRU_HEAD, old_head);

            pcache_add_to_lru_list(page);

            assert_eq!(page.add(PAGE_ON_LRU_LIST).read(), 2);
            assert_eq!(word(cache, CACHE_LRU_HEAD), old_head as usize as u32);
            assert_eq!(word(page, PAGE_LRU_PREVIOUS), old_head as usize as u32);
            assert_eq!(word(page, PAGE_LRU_NEXT), old_head as usize as u32);
        }
    }
}
