//! SQLite pager-cache LRU unlink — `pcacheRemoveFromLruList`.
//!
//! `pcache_remove_from_lru_list` — original: `FUN_082d906c` @ 0x082d906c
//! (68 bytes; 6 direct `bl` call sites, all unconditional).
//!
//! Raw `osos.dec` disassembly confirms the body is exactly
//! `0x082d906c..0x082d90b0`; the separately linked LRU insertion sibling
//! begins at `0x082d90b0`. Decoding every ARM `B`/`BL` immediate in the image
//! finds inbound plain `bl` calls at `0x082dd108`, `0x082de2e4`, `0x082de3c4`,
//! `0x082de7e4`, `0x0837e178`, and `0x0837e230`; there are no predicated calls
//! or direct tail branches to this entry.
//!
//! A `PgHdr` records whether it is on the cache's LRU list at +0x1d, its
//! previous and next LRU links at +0x24 and +0x28, and its owning cache at
//! +0x00. When flagged, this removes it from the doubly linked list, updating
//! the owner's +0x90 head when it was the head, then clears the flag. The ARM
//! body deliberately retains the page link words. No deliberate deviations.

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

/// `pcacheRemoveFromLruList` — original: `FUN_082d906c` @ 0x082d906c (68
/// bytes; 6 direct `bl` call sites, all unconditional).
///
/// Removes `page` from its owner's intrusive LRU list only if the byte flag at
/// `page+0x1d` is nonzero. A flagged page requires a valid owner at `+0x00`;
/// each non-null neighbour requires writable target-layout link words.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.pcache_remove_from_lru_list")]
pub unsafe extern "C" fn pcache_remove_from_lru_list(page: *mut u8) {
    if unsafe { page.add(PAGE_ON_LRU_LIST).read() } == 0 {
        return;
    }

    unsafe { page.add(PAGE_ON_LRU_LIST).write(0) };
    let previous = unsafe { read_target_pointer(page, PAGE_LRU_PREVIOUS) };
    let next = unsafe { read_target_pointer(page, PAGE_LRU_NEXT) };
    if previous.is_null() {
        let cache = unsafe { read_target_pointer(page, PAGE_CACHE) };
        unsafe { write_target_pointer(cache, CACHE_LRU_HEAD, next) };
    } else {
        unsafe { write_target_pointer(previous, PAGE_LRU_NEXT, next) };
    }
    if !next.is_null() {
        unsafe { write_target_pointer(next, PAGE_LRU_PREVIOUS, previous) };
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
    const CACHE_OFFSET: usize = 0x000;
    const HEAD_OFFSET: usize = 0x200;
    const MIDDLE_OFFSET: usize = 0x300;
    const TAIL_OFFSET: usize = 0x400;

    static FIXTURE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::SQLITE_PCACHE_REMOVE_FROM_LRU_LIST, FIXTURE_LEN)
            .map(|pointer| pointer as usize)
    });
    static FIXTURE_LOCK: Mutex<()> = Mutex::new(());

    fn fixture() -> Option<(*mut u8, MutexGuard<'static, ()>)> {
        let guard = FIXTURE_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let base = (*FIXTURE)? as *mut u8;
        unsafe { ptr::write_bytes(base, 0, FIXTURE_LEN) };
        Some((base, guard))
    }

    unsafe fn page(base: *mut u8, offset: usize) -> *mut u8 {
        unsafe { base.add(offset) }
    }

    unsafe fn word(base: *const u8, offset: usize) -> u32 {
        unsafe { base.add(offset).cast::<u32>().read() }
    }

    unsafe fn set_word(base: *mut u8, offset: usize, value: u32) {
        unsafe { base.add(offset).cast::<u32>().write(value) };
    }

    unsafe fn set_pointer(base: *mut u8, offset: usize, value: *mut u8) {
        unsafe { set_word(base, offset, value as usize as u32) };
    }

    unsafe fn link(page: *mut u8, cache: *mut u8, previous: *mut u8, next: *mut u8, active: u8) {
        unsafe {
            set_pointer(page, PAGE_CACHE, cache);
            set_pointer(page, PAGE_LRU_PREVIOUS, previous);
            set_pointer(page, PAGE_LRU_NEXT, next);
            page.add(PAGE_ON_LRU_LIST).write(active);
        }
    }

    #[test]
    fn inactive_page_leaves_every_lru_word_untouched() {
        let Some((base, _guard)) = fixture() else {
            assert!(note_missing_u32_fixture(module_path!()));
            return;
        };
        unsafe {
            let cache = page(base, CACHE_OFFSET);
            let page = page(base, HEAD_OFFSET);
            link(page, cache, ptr::null_mut(), ptr::null_mut(), 0);
            set_pointer(cache, CACHE_LRU_HEAD, page);

            pcache_remove_from_lru_list(page);

            assert_eq!(page.add(PAGE_ON_LRU_LIST).read(), 0);
            assert_eq!(word(page, PAGE_CACHE), cache as usize as u32);
            assert_eq!(word(page, PAGE_LRU_PREVIOUS), 0);
            assert_eq!(word(page, PAGE_LRU_NEXT), 0);
            assert_eq!(word(cache, CACHE_LRU_HEAD), page as usize as u32);
        }
    }

    #[test]
    fn removes_a_head_and_repairs_its_successor_without_clearing_page_links() {
        let Some((base, _guard)) = fixture() else {
            assert!(note_missing_u32_fixture(module_path!()));
            return;
        };
        unsafe {
            let cache = page(base, CACHE_OFFSET);
            let head = page(base, HEAD_OFFSET);
            let next = page(base, MIDDLE_OFFSET);
            link(head, cache, ptr::null_mut(), next, 2);
            link(next, cache, head, ptr::null_mut(), 1);
            set_pointer(cache, CACHE_LRU_HEAD, head);

            pcache_remove_from_lru_list(head);

            assert_eq!(head.add(PAGE_ON_LRU_LIST).read(), 0, "any nonzero flag is active");
            assert_eq!(word(cache, CACHE_LRU_HEAD), next as usize as u32);
            assert_eq!(word(next, PAGE_LRU_PREVIOUS), 0);
            assert_eq!(word(head, PAGE_LRU_PREVIOUS), 0, "the original retains the old link");
            assert_eq!(word(head, PAGE_LRU_NEXT), next as usize as u32, "the original retains the old link");
        }
    }

    #[test]
    fn splices_an_interior_page_without_changing_the_cache_head() {
        let Some((base, _guard)) = fixture() else {
            assert!(note_missing_u32_fixture(module_path!()));
            return;
        };
        unsafe {
            let cache = page(base, CACHE_OFFSET);
            let head = page(base, HEAD_OFFSET);
            let middle = page(base, MIDDLE_OFFSET);
            let tail = page(base, TAIL_OFFSET);
            link(head, cache, ptr::null_mut(), middle, 1);
            link(middle, cache, head, tail, 1);
            link(tail, cache, middle, ptr::null_mut(), 1);
            set_pointer(cache, CACHE_LRU_HEAD, head);

            pcache_remove_from_lru_list(middle);

            assert_eq!(word(cache, CACHE_LRU_HEAD), head as usize as u32);
            assert_eq!(word(head, PAGE_LRU_NEXT), tail as usize as u32);
            assert_eq!(word(tail, PAGE_LRU_PREVIOUS), head as usize as u32);
            assert_eq!(middle.add(PAGE_ON_LRU_LIST).read(), 0);
            assert_eq!(word(middle, PAGE_LRU_PREVIOUS), head as usize as u32);
            assert_eq!(word(middle, PAGE_LRU_NEXT), tail as usize as u32);
        }
    }

    #[test]
    fn removes_a_tail_without_touching_the_head_word() {
        let Some((base, _guard)) = fixture() else {
            assert!(note_missing_u32_fixture(module_path!()));
            return;
        };
        unsafe {
            let cache = page(base, CACHE_OFFSET);
            let head = page(base, HEAD_OFFSET);
            let tail = page(base, TAIL_OFFSET);
            link(head, cache, ptr::null_mut(), tail, 1);
            link(tail, cache, head, ptr::null_mut(), 1);
            set_pointer(cache, CACHE_LRU_HEAD, head);

            pcache_remove_from_lru_list(tail);

            assert_eq!(word(cache, CACHE_LRU_HEAD), head as usize as u32);
            assert_eq!(word(head, PAGE_LRU_NEXT), 0);
            assert_eq!(tail.add(PAGE_ON_LRU_LIST).read(), 0);
            assert_eq!(word(tail, PAGE_LRU_PREVIOUS), head as usize as u32);
            assert_eq!(word(tail, PAGE_LRU_NEXT), 0);
        }
    }
}
