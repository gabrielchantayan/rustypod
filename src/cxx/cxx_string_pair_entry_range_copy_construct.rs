//! cxx_string_pair_entry_range_copy_construct — retailOS `FUN_083e8fc0` @
//! `0x083e8fc0`.
//!
//! **64 bytes**, true extent `0x083e8fc0..0x083e8fff`, bounded by the
//! independently linked `plist_node_child_range_copy` at `0x083e9000`.
//! Whole-image A32 decoding finds two inbound plain `bl` call sites
//! (`0x083e3034`, `0x083e3084`) and zero predicated forms. It construct-copies
//! every 12-byte COW-string-pair entry in `[first, last)` through
//! `cxx_string_pair_entry_copy_ctor`, advances both cursors by 12, and returns
//! the advanced destination. No deliberate deviations.

#[cfg(not(test))]
unsafe fn copy_entry(owner: *mut u8, destination: *mut u8, source: *const u8) {
    unsafe {
        crate::cxx::string::cxx_string_pair_entry_copy_ctor(
            owner,
            destination.cast(),
            source.cast(),
        );
    }
}

#[cfg(test)]
unsafe fn copy_entry(owner: *mut u8, destination: *mut u8, source: *const u8) {
    unsafe { test_copy_entry(owner, destination, source) };
}

/// Construct-copies target-layout COW-string-pair entries from `[first, last)`
/// to `destination` and returns the advanced destination cursor.
///
/// # Safety
///
/// `first..last` must delimit readable 12-byte entries. `destination` must
/// provide writable 12-byte entries for that range, and `owner` plus every
/// entry must be valid for `cxx_string_pair_entry_copy_ctor`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cxx_string_pair_entry_range_copy_construct(
    mut first: *const u8,
    last: *const u8,
    mut destination: *mut u8,
    owner: *mut u8,
) -> *mut u8 {
    while first != last {
        unsafe { copy_entry(owner, destination, first) };
        first = unsafe { first.add(12) };
        destination = unsafe { destination.add(12) };
    }
    destination
}

#[cfg(test)]
static TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
#[cfg(test)]
static mut COPY_CALLS: [(*mut u8, *mut u8, *const u8); 4] = [(core::ptr::null_mut(), core::ptr::null_mut(), core::ptr::null()); 4];
#[cfg(test)]
static mut COPY_COUNT: usize = 0;

#[cfg(test)]
unsafe fn test_copy_entry(owner: *mut u8, destination: *mut u8, source: *const u8) {
    unsafe {
        COPY_CALLS[COPY_COUNT] = (owner, destination, source);
        COPY_COUNT += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};

    #[test]
    fn cxx_string_pair_entry_range_copy_constructs_entries_in_order() {
        let _guard = TEST_LOCK.lock();
        let Some(slab) = try_map_u32_slab(hints::CXX_STRING_PAIR_ENTRY_RANGE_COPY_CONSTRUCT, 0x1000) else {
            assert!(note_missing_u32_fixture("cxx/cxx_string_pair_entry_range_copy_construct"));
            return;
        };
        unsafe {
            slab.write_bytes(0, 0x1000);
            let first = slab.add(0x100);
            let destination = slab.add(0x200);
            let owner = slab.add(0x300);
            COPY_COUNT = 0;

            let returned = cxx_string_pair_entry_range_copy_construct(first, first.add(24), destination, owner);

            assert_eq!(returned, destination.add(24));
            assert_eq!(COPY_COUNT, 2);
            assert_eq!(COPY_CALLS[0], (owner, destination, first.cast_const()));
            assert_eq!(COPY_CALLS[1], (owner, destination.add(12), first.add(12).cast_const()));
        }
    }

    #[test]
    fn cxx_string_pair_entry_range_copy_empty_preserves_destination_without_calls() {
        let _guard = TEST_LOCK.lock();
        unsafe {
            COPY_COUNT = 0;
            let destination = 0x2000usize as *mut u8;
            assert_eq!(cxx_string_pair_entry_range_copy_construct(core::ptr::null(), core::ptr::null(), destination, core::ptr::null_mut()), destination);
            assert_eq!(COPY_COUNT, 0);
        }
    }
}
