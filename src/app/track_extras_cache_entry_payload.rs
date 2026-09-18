//! TTrackExtrasCache entry payload lookup.
//!
//! Port:
//! - [`track_extras_cache_entry_payload`] — original: `FUN_081ba040` @
//!   `0x081ba040` (**20 bytes; 4 unconditional plain `bl` call sites, no
//!   predicated forms**).
//!
//! ## Stock algorithm
//!
//! Calls the cache entry lookup at `0x081ba1ec` with the cache and key passed
//! through in r0/r1. It returns zero when that lookup returns NULL; otherwise
//! it returns the matched entry's first word.
//!
//! ## Deliberate deviations
//!
//! The lookup's broader identity remains unported. Target builds call its
//! verified fixed address; host builds expose a recording seam.

use core::ptr;

/// ABI of the unported lookup at `0x081ba1ec`.
pub type TrackExtrasCacheEntryLookup = unsafe extern "C" fn(*mut u8, *mut u8) -> *const u32;

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_entry_lookup(cache: *mut u8, key: *mut u8) -> *const u32 {
    let function: TrackExtrasCacheEntryLookup = core::mem::transmute(0x081b_a1ecusize);
    function(cache, key)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn firmware_entry_lookup(_cache: *mut u8, _key: *mut u8) -> *const u32 {
    ptr::null()
}

/// Unported cache-entry lookup boundary. Volatile loading retains the target
/// call while host tests install a recorder.
pub static mut TRACK_EXTRAS_CACHE_ENTRY_LOOKUP: TrackExtrasCacheEntryLookup = firmware_entry_lookup;

#[inline(always)]
unsafe fn entry_lookup() -> TrackExtrasCacheEntryLookup {
    ptr::read_volatile(ptr::addr_of!(TRACK_EXTRAS_CACHE_ENTRY_LOOKUP))
}

/// `track_extras_cache_entry_payload` — original: `FUN_081ba040` @
/// `0x081ba040` (20 bytes; 4 unconditional plain `bl` callers, no predicated
/// forms).
///
/// Returns the first word of the entry found for `key`, or zero when no entry
/// matches. Neither the cache nor key is guarded; their validity belongs to
/// the lookup callee.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.track_extras_cache_entry_payload")]
#[inline(never)]
pub unsafe extern "C" fn track_extras_cache_entry_payload(cache: *mut u8, key: *mut u8) -> u32 {
    let entry = entry_lookup()(cache, key);
    if entry.is_null() { 0 } else { entry.read() }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use parking_lot::Mutex;
    use std::sync::LazyLock;

    static LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));
    static mut LOOKUP_RESULT: *const u32 = ptr::null();
    static mut OBSERVED: (*mut u8, *mut u8) = (ptr::null_mut(), ptr::null_mut());

    unsafe extern "C" fn recording_lookup(cache: *mut u8, key: *mut u8) -> *const u32 {
        OBSERVED = (cache, key);
        LOOKUP_RESULT
    }

    #[test]
    fn returns_zero_when_entry_lookup_finds_nothing() {
        let _lock = LOCK.lock();
        let saved = unsafe { TRACK_EXTRAS_CACHE_ENTRY_LOOKUP };
        unsafe {
            TRACK_EXTRAS_CACHE_ENTRY_LOOKUP = recording_lookup;
            LOOKUP_RESULT = ptr::null();
            let cache = 0x10usize as *mut u8;
            let key = 0x20usize as *mut u8;
            assert_eq!(track_extras_cache_entry_payload(cache, key), 0);
            assert_eq!(OBSERVED, (cache, key));
            TRACK_EXTRAS_CACHE_ENTRY_LOOKUP = saved;
        }
    }

    #[test]
    fn returns_matched_entry_first_word() {
        let _lock = LOCK.lock();
        let saved = unsafe { TRACK_EXTRAS_CACHE_ENTRY_LOOKUP };
        let entry = [0xa5a5_5a5a, 0xffff_ffff];
        unsafe {
            TRACK_EXTRAS_CACHE_ENTRY_LOOKUP = recording_lookup;
            LOOKUP_RESULT = entry.as_ptr();
            assert_eq!(track_extras_cache_entry_payload(ptr::null_mut(), ptr::null_mut()), entry[0]);
            TRACK_EXTRAS_CACHE_ENTRY_LOOKUP = saved;
        }
    }
}
