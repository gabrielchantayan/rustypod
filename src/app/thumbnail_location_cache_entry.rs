//! `thumbnail_location_cache_entry` — original: `FUN_08052484` @
//! **0x08052484** (**116 bytes exactly**, `0x08052484..0x080524f7`; the
//! `ldr r2,[pc,#20]` at `0x080524f8` begins the independent following function).
//!
//! Raw A32 decoding finds three unconditional body `bl` calls: the cache lookup
//! at `0x080503ec`, cache entry allocation at `0x0805dfec`, and `__rt_udiv` at
//! `0x08036f14`; no body call is predicated. An independent whole-image decode
//! finds three inbound plain `bl` calls (`0x08049070`, `0x080523e0`, and
//! `0x0809edd0`) and zero predicated forms.
//!
//! # Algorithm
//!
//! A null request returns zero. Requests below 1000 select one of twenty fixed
//! 88-byte cache records from the request cache's entry base using the unsigned
//! divide remainder, then return that record's `+0xe4` payload. Other requests
//! first query the cache and allocate only when the query returns null; a found
//! or allocated entry returns its `+0x10` payload.
//!
//! # Deliberate deviations
//!
//! Rust obtains the ADS divide remainder through the ported `__rt_udivmod`
//! output pointer. The two unported cache calls remain address-named typed
//! target seams; host builds replace them for tests. Their identities are not
//! inferred beyond the raw call ABI.

use crate::runtime::rt_div::__rt_udivmod;

type RetailCacheFind = unsafe extern "C" fn(*mut u8, u32) -> *mut u8;
type RetailCacheAllocate = unsafe extern "C" fn(*mut u8, u32) -> *mut u8;

const RETAIL_CACHE_FIND_ADDRESS: usize = 0x0805_03ec;
const RETAIL_CACHE_ALLOCATE_ADDRESS: usize = 0x0805_dfec;
const REQUEST_CACHE_OFFSET: usize = 4;
const REQUEST_KEY_OFFSET: usize = 8;
const CACHE_ENTRY_BASE_OFFSET: usize = 8;
const CACHE_BUCKET_SOURCE_OFFSET: usize = 12;
const SMALL_KEY_LIMIT: u32 = 1000;
const BUCKET_COUNT: u32 = 20;
const ENTRY_STRIDE: usize = 0x58;
const ENTRY_PAYLOAD_OFFSET: usize = 0xe4;
const DYNAMIC_ENTRY_PAYLOAD_OFFSET: usize = 0x10;

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_cache_find(cache: *mut u8, key: u32) -> *mut u8 {
    unsafe { core::mem::transmute::<usize, RetailCacheFind>(RETAIL_CACHE_FIND_ADDRESS)(cache, key) }
}

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_cache_allocate(cache: *mut u8, key: u32) -> *mut u8 {
    unsafe { core::mem::transmute::<usize, RetailCacheAllocate>(RETAIL_CACHE_ALLOCATE_ADDRESS)(cache, key) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_cache_find(_cache: *mut u8, _key: u32) -> *mut u8 {
    panic!("thumbnail_location_cache_entry requires retail cache call 0x080503ec")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_cache_allocate(_cache: *mut u8, _key: u32) -> *mut u8 {
    panic!("thumbnail_location_cache_entry requires retail cache call 0x0805dfec")
}

#[cfg(target_os = "none")]
pub static mut RETAIL_CACHE_FIND: RetailCacheFind = retail_cache_find;
#[cfg(not(target_os = "none"))]
pub static mut RETAIL_CACHE_FIND: RetailCacheFind = missing_cache_find;
#[cfg(target_os = "none")]
pub static mut RETAIL_CACHE_ALLOCATE: RetailCacheAllocate = retail_cache_allocate;
#[cfg(not(target_os = "none"))]
pub static mut RETAIL_CACHE_ALLOCATE: RetailCacheAllocate = missing_cache_allocate;

#[inline(always)]
fn cache_find() -> RetailCacheFind {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(RETAIL_CACHE_FIND)) }
}

#[inline(always)]
fn cache_allocate() -> RetailCacheAllocate {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(RETAIL_CACHE_ALLOCATE)) }
}

#[inline(always)]
unsafe fn word(base: *const u8, offset: usize) -> u32 {
    unsafe { base.add(offset).cast::<u32>().read_volatile() }
}

/// Returns the cache payload selected by a request object.
///
/// # Safety
///
/// `request` and its target-width cache pointer fields must satisfy the retail
/// object layout. The cache seams retain their decoded ABIs.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", unsafe(link_section = ".text.thumbnail_location_cache_entry"))]
#[inline(never)]
pub unsafe extern "C" fn thumbnail_location_cache_entry(request: *mut u8) -> *mut u8 {
    if request.is_null() {
        return core::ptr::null_mut();
    }

    let cache = unsafe { word(request, REQUEST_CACHE_OFFSET) as usize as *mut u8 };
    let key = unsafe { word(request, REQUEST_KEY_OFFSET) };
    let entry_base = unsafe { word(cache, CACHE_ENTRY_BASE_OFFSET) as usize as *mut u8 };
    if key < SMALL_KEY_LIMIT {
        let mut bucket = 0;
        unsafe { __rt_udivmod(word(cache, CACHE_BUCKET_SOURCE_OFFSET), BUCKET_COUNT, &mut bucket) };
        return unsafe { entry_base.add(bucket as usize * ENTRY_STRIDE + ENTRY_PAYLOAD_OFFSET) };
    }

    let entry = unsafe { cache_find()(cache, key) };
    let entry = if entry.is_null() {
        unsafe { cache_allocate()(cache, key) }
    } else {
        entry
    };
    if entry.is_null() {
        core::ptr::null_mut()
    } else {
        unsafe { entry.add(DYNAMIC_ENTRY_PAYLOAD_OFFSET) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, try_map_u32_slab};
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut FIND_CALLS: u32 = 0;
    static mut ALLOCATE_CALLS: u32 = 0;
    static mut FIND_ARGS: (*mut u8, u32) = (core::ptr::null_mut(), 0);
    static mut ALLOCATE_ARGS: (*mut u8, u32) = (core::ptr::null_mut(), 0);
    static mut FIND_RESULT: *mut u8 = core::ptr::null_mut();
    static mut ALLOCATE_RESULT: *mut u8 = core::ptr::null_mut();

    unsafe extern "C" fn find(cache: *mut u8, key: u32) -> *mut u8 {
        unsafe { FIND_CALLS += 1; FIND_ARGS = (cache, key); FIND_RESULT }
    }

    unsafe extern "C" fn allocate(cache: *mut u8, key: u32) -> *mut u8 {
        unsafe { ALLOCATE_CALLS += 1; ALLOCATE_ARGS = (cache, key); ALLOCATE_RESULT }
    }

    unsafe fn set_word(base: *mut u8, offset: usize, value: usize) {
        unsafe { base.add(offset).cast::<u32>().write(value as u32) };
    }

    #[test]
    fn selects_small_buckets_and_queries_or_allocates_large_keys() {
        let _guard = LOCK.lock();
        let Some(slab) = try_map_u32_slab(hints::THUMBNAIL_LOCATION_CACHE_ENTRY, 0x1000) else { return };
        let request = slab;
        let cache = unsafe { slab.add(0x40) };
        let entry_base = unsafe { slab.add(0x200) };
        let existing = unsafe { slab.add(0x900) };
        let allocated = unsafe { slab.add(0x940) };
        unsafe {
            RETAIL_CACHE_FIND = find;
            RETAIL_CACHE_ALLOCATE = allocate;
            set_word(request, REQUEST_CACHE_OFFSET, cache as usize);
            set_word(cache, CACHE_ENTRY_BASE_OFFSET, entry_base as usize);
            set_word(cache, CACHE_BUCKET_SOURCE_OFFSET, 39);
            FIND_CALLS = 0;
            ALLOCATE_CALLS = 0;
            for (key, bucket) in [(0, 19), (19, 19), (20, 19), (999, 19)] {
                set_word(request, REQUEST_KEY_OFFSET, key);
                assert_eq!(thumbnail_location_cache_entry(request), entry_base.add(bucket * ENTRY_STRIDE + ENTRY_PAYLOAD_OFFSET));
            }
            assert_eq!(FIND_CALLS, 0);
            assert_eq!(ALLOCATE_CALLS, 0);

            FIND_RESULT = existing;
            set_word(request, REQUEST_KEY_OFFSET, 1000);
            assert_eq!(thumbnail_location_cache_entry(request), existing.add(DYNAMIC_ENTRY_PAYLOAD_OFFSET));
            assert_eq!(FIND_CALLS, 1);
            assert_eq!(FIND_ARGS, (cache, 1000));
            assert_eq!(ALLOCATE_CALLS, 0);

            FIND_RESULT = core::ptr::null_mut();
            ALLOCATE_RESULT = allocated;
            set_word(request, REQUEST_KEY_OFFSET, u32::MAX as usize);
            assert_eq!(thumbnail_location_cache_entry(request), allocated.add(DYNAMIC_ENTRY_PAYLOAD_OFFSET));
            assert_eq!(FIND_CALLS, 2);
            assert_eq!(ALLOCATE_CALLS, 1);
            assert_eq!(ALLOCATE_ARGS, (cache, u32::MAX));
            ALLOCATE_RESULT = core::ptr::null_mut();
            assert!(thumbnail_location_cache_entry(request).is_null());
            assert_eq!(ALLOCATE_CALLS, 2);
        }
        assert!(unsafe { thumbnail_location_cache_entry(core::ptr::null_mut()) }.is_null());
    }
}
