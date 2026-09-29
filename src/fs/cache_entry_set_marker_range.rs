//! Cache-entry marker range writer.
//!
//! `cache_entry_set_marker_range` is retailOS `FUN_082e4b9c` at `0x082e4b9c`
//! (24 bytes; the next independently entered function starts at `0x082e4bb4`).
//! Two direct ARM `BL` words target it, both plain `bl`; no predicated `bl`
//! targets exist.
//!
//! Starting at `entry`, the function stores marker byte `0xe5`, then moves
//! backward one 32-byte cache-entry stride until it has marked `count` entries.
//! A zero count performs no access. The function has no NULL guard.
//!
//! Deliberate deviations: none.

/// Byte spacing between adjacent cache entries in the marked range.
const CACHE_ENTRY_STRIDE: usize = 0x20;
/// Marker written to each selected cache entry.
const CACHE_ENTRY_MARKER: u8 = 0xe5;

/// Sets the retailOS marker on `count` cache entries ending at `entry`.
///
/// Original: `FUN_082e4b9c` at `0x082e4b9c`, 24 bytes; two binary-verified
/// direct call sites (both plain `bl`).
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.cache_entry_set_marker_range")]
#[inline(never)]
pub unsafe extern "C" fn cache_entry_set_marker_range(mut entry: *mut u8, mut count: u32) {
    while count != 0 {
        count -= 1;
        entry.write_volatile(CACHE_ENTRY_MARKER);
        entry = entry.sub(CACHE_ENTRY_STRIDE);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marks_entries_backwards_at_the_cache_stride() {
        let mut entries = [0x5au8; CACHE_ENTRY_STRIDE * 3];

        unsafe {
            cache_entry_set_marker_range(entries.as_mut_ptr().add(CACHE_ENTRY_STRIDE * 2), 3);
        }

        assert_eq!(entries[0], CACHE_ENTRY_MARKER);
        assert_eq!(entries[CACHE_ENTRY_STRIDE], CACHE_ENTRY_MARKER);
        assert_eq!(entries[CACHE_ENTRY_STRIDE * 2], CACHE_ENTRY_MARKER);
        assert_eq!(entries[1], 0x5a);
        assert_eq!(entries[CACHE_ENTRY_STRIDE + 1], 0x5a);
        assert_eq!(entries[CACHE_ENTRY_STRIDE * 2 + 1], 0x5a);
    }

    #[test]
    fn zero_count_does_not_access_entry() {
        let mut entry = 0x5au8;

        unsafe {
            cache_entry_set_marker_range(&mut entry, 0);
        }

        assert_eq!(entry, 0x5a);
    }
}
