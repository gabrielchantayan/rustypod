//! Finds a loaded 'plst' item by its selector.
//!
//! - `ui_plst_find_by_selector` — original: `FUN_08050b38` @ 0x08050b38
//!   (220 bytes; 4 direct `bl` call sites, all unconditional).

use crate::ui::plst_class_check::ui_element_is_plst_class;

const CACHE_OFFSET: usize = 0x234;
const FALLBACK_ITEM_OFFSET: usize = 0x40;
const CACHE_COUNT_OFFSET: usize = 0xc;
const CACHE_ITEMS_OFFSET: usize = 0x10;
const ITEM_SELECTOR_OFFSET: usize = 0x10;

type EnsureSelectorCache = unsafe extern "C" fn(*mut u8, u32) -> i32;

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_ensure_selector_cache(element: *mut u8, selector: u32) -> i32 {
    let call: EnsureSelectorCache = core::mem::transmute(0x080d_c49cusize);
    call(element, selector)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn retail_ensure_selector_cache(_element: *mut u8, _selector: u32) -> i32 { 0 }

/// ui_plst_find_by_selector — original: `FUN_08050b38` @ 0x08050b38
/// (220 bytes).
///
/// Raw ARM spans `0x08050b38..0x08050c14`; the next function starts with
/// `cmp r0,#0` at 0x08050c14, confirming Ghidra's 220-byte extent. The body
/// has two plain `bl` instructions (0x08050b44 and 0x08050b68), neither
/// predicated. Its four direct callers are 0x08053c54, 0x08054808,
/// 0x0817b02c, and 0x0817b6d0; all are unconditional `bl`.
///
/// Algorithm: require a 'plst' element and a nonzero selector. If its cache
/// at +0x234 is absent, ask retailOS 0x080dc49c to populate selector cache 4,
/// then re-read the cache. Search its item-pointer array (+0x10, count +0xc)
/// by the selector word at item+0x10: an ordered binary narrowing loop leaves
/// at most two candidates, which are scanned linearly. If none matches, also
/// compare the element's fallback item at +0x40. Return the matched item word
/// or zero.
///
/// Deliberate deviations: 0x080dc49c has no names.yaml entry and its full
/// semantic name is not established; this port therefore keeps it as the
/// narrow `retail_ensure_selector_cache` boundary at its verified address.
/// The original ignores its return value and re-reads +0x234; so does this
/// port. Its target-width pointers are read as aligned `u32` words before
/// widening on hosts.
///
/// # Safety
/// `element` must be readable through +0x237. A non-NULL cache must be
/// readable through its count and item-pointer array; each item pointer and
/// the fallback item, when non-NULL, must be readable through +0x13.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.ui_plst_find_by_selector")]
pub unsafe extern "C" fn ui_plst_find_by_selector(element: *mut u8, selector: u32) -> u32 {
    ui_plst_find_by_selector_with(element, selector, retail_ensure_selector_cache)
}

unsafe fn ui_plst_find_by_selector_with(
    element: *mut u8, selector: u32, ensure_cache: EnsureSelectorCache,
) -> u32 {
    if ui_element_is_plst_class(element) == 0 || selector == 0 {
        return 0;
    }

    let mut cache = element.add(CACHE_OFFSET).cast::<u32>().read();
    if cache == 0 {
        ensure_cache(element, 4);
        cache = element.add(CACHE_OFFSET).cast::<u32>().read();
        if cache == 0 {
            return 0;
        }
    }

    let cache = cache as usize as *const u8;
    let mut low = 0i32;
    let mut high = cache.add(CACHE_COUNT_OFFSET).cast::<u32>().read().wrapping_sub(1) as i32;
    while high.wrapping_sub(low) > 1 {
        let middle_sum = low.wrapping_add(high);
        let middle = middle_sum.wrapping_add((middle_sum as u32 >> 31) as i32) >> 1;
        let item = cache.add(CACHE_ITEMS_OFFSET + middle as usize * 4).cast::<u32>().read();
        let item_selector = (item as usize as *const u8).add(ITEM_SELECTOR_OFFSET).cast::<u32>().read();
        if item_selector == selector {
            return item;
        }
        if selector < item_selector {
            high = middle;
        } else {
            low = middle;
        }
    }

    while low <= high {
        let item = cache.add(CACHE_ITEMS_OFFSET + low as usize * 4).cast::<u32>().read();
        if (item as usize as *const u8).add(ITEM_SELECTOR_OFFSET).cast::<u32>().read() == selector {
            return item;
        }
        low += 1;
    }

    let fallback = element.add(FALLBACK_ITEM_OFFSET).cast::<u32>().read();
    if fallback != 0 && (fallback as usize as *const u8).add(ITEM_SELECTOR_OFFSET).cast::<u32>().read() == selector {
        fallback
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use core::ptr;
    use std::sync::{LazyLock, Mutex};

    static SEAM_LOCK: Mutex<()> = Mutex::new(());
    static mut LOADER_CALLS: u32 = 0;
    static mut LOADER_ELEMENT: *mut u8 = ptr::null_mut();
    static mut LOADER_SELECTOR: u32 = 0;
    static mut LOADER_CACHE: *mut u8 = ptr::null_mut();

    unsafe extern "C" fn loader(element: *mut u8, selector: u32) -> i32 {
        LOADER_CALLS += 1;
        LOADER_ELEMENT = element;
        LOADER_SELECTOR = selector;
        if !LOADER_CACHE.is_null() {
            element.add(CACHE_OFFSET).cast::<u32>().write(LOADER_CACHE as usize as u32);
        }
        0
    }

    fn try_slab() -> Option<*mut u8> {
        static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
            try_map_u32_slab(hints::PLST_FIND_BY_SELECTOR, 0x2000).map(|p| p as usize)
        });
        SLAB.map(|p| p as *mut u8)
    }

    unsafe fn word(record: *mut u8, offset: usize, value: u32) {
        record.add(offset).cast::<u32>().write(value);
    }

    unsafe fn prepare() -> Option<(*mut u8, *mut u8, *mut u8, *mut u8)> {
        let slab = try_slab()?;
        ptr::write_bytes(slab, 0, 0x2000);
        let element = slab;
        let cache = slab.add(0x400);
        let first = slab.add(0x800);
        let second = slab.add(0x900);
        let third = slab.add(0xa00);
        let fourth = slab.add(0xb00);
        word(element, 4, 0x706c_7374);
        word(cache, CACHE_COUNT_OFFSET, 4);
        word(cache, CACHE_ITEMS_OFFSET, first as usize as u32);
        word(cache, CACHE_ITEMS_OFFSET + 4, second as usize as u32);
        word(cache, CACHE_ITEMS_OFFSET + 8, third as usize as u32);
        word(cache, CACHE_ITEMS_OFFSET + 12, fourth as usize as u32);
        word(first, ITEM_SELECTOR_OFFSET, 10);
        word(second, ITEM_SELECTOR_OFFSET, 20);
        word(third, ITEM_SELECTOR_OFFSET, 30);
        word(fourth, ITEM_SELECTOR_OFFSET, 40);
        LOADER_CALLS = 0;
        LOADER_ELEMENT = ptr::null_mut();
        LOADER_SELECTOR = 0;
        LOADER_CACHE = ptr::null_mut();
        Some((element, cache, first, second))
    }

    #[test]
    fn zero_selector_and_wrong_class_short_circuit_without_loading() {
        let _lock = SEAM_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let Some((element, cache, _, _)) = (unsafe { prepare() }) else {
            note_missing_u32_fixture("ui::plst_find_by_selector");
            return;
        };
        unsafe {
            word(element, CACHE_OFFSET, cache as usize as u32);
            assert_eq!(ui_plst_find_by_selector_with(element, 0, loader), 0);
            word(element, 4, 0);
            assert_eq!(ui_plst_find_by_selector_with(element, 10, loader), 0);
            assert_eq!(LOADER_CALLS, 0);
        }
    }

    #[test]
    fn loads_missing_cache_then_returns_sorted_item() {
        let _lock = SEAM_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let Some((element, cache, _, second)) = (unsafe { prepare() }) else {
            note_missing_u32_fixture("ui::plst_find_by_selector");
            return;
        };
        unsafe {
            LOADER_CACHE = cache;
            assert_eq!(ui_plst_find_by_selector_with(element, 20, loader), second as usize as u32);
            assert_eq!(LOADER_CALLS, 1);
            assert_eq!(LOADER_ELEMENT, element);
            assert_eq!(LOADER_SELECTOR, 4);
        }
    }

    #[test]
    fn scans_remaining_candidates_and_uses_fallback() {
        let _lock = SEAM_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let Some((element, cache, first, _)) = (unsafe { prepare() }) else {
            note_missing_u32_fixture("ui::plst_find_by_selector");
            return;
        };
        unsafe {
            word(element, CACHE_OFFSET, cache as usize as u32);
            assert_eq!(ui_plst_find_by_selector_with(element, 10, loader), first as usize as u32);
            let fallback = element.add(0x1000);
            word(fallback, ITEM_SELECTOR_OFFSET, 77);
            word(element, FALLBACK_ITEM_OFFSET, fallback as usize as u32);
            assert_eq!(ui_plst_find_by_selector_with(element, 77, loader), fallback as usize as u32);
            assert_eq!(LOADER_CALLS, 0);
        }
    }
}
