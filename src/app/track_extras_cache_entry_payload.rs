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
//! The lookup now calls the Rust search directly. Native host pointers widen;
//! the payload API continues to return the target-width object address.

use super::track_extras_cache_find_entry::track_extras_cache_find_entry;

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
    let entry = track_extras_cache_find_entry(cache, key);
    if entry.is_null() { 0 } else { (*entry).object as usize as u32 }
}

