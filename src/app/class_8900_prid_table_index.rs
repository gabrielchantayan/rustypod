//! Resource-word lookup in the class-0x8900 runtime table.
//!
//! Original `FUN_081ec290` @ 0x081ec290: 80 code bytes and 12 literal
//! bytes, true extent 92 bytes ending at the next function @ 0x081ec2ec.
//! Raw ARM decoding finds two unconditional incoming BLs (0x080feac4,
//! 0x081edc00), zero predicated incoming BLs, and one outgoing BL to
//! resource_chain_find @ 0x0827216c. Ghidra's additional caller at
//! 0x082a354c is not an additional raw BL to this address.
//!
//! Look up ("prID", 0x6066) using the receiver's store at +0x378. If
//! present, compare its first aligned word with word +8 of each of the
//! 21 twelve-byte records at runtime address 0x089cc3cc. Return the first
//! matching zero-based index, or u32::MAX for absence or no match.
//!
//! Deliberate deviations: reuse the native-pointer Class8900 layout for
//! host fixtures; factor the scan for host tests. The target retains the
//! original runtime table rather than embedding presumed initial data.

use crate::app::class_8900::Class8900;
use crate::app::resource_chain::{resource_chain_find, ResourceKind, ResourceProvider};

const TABLE: *const u32 = 0x089c_c3cc as *const u32;
const RECORD_COUNT: usize = 21;

#[inline(always)]
unsafe fn resource_table_index(resource: *const u32, table: *const u32) -> u32 {
    if resource.is_null() {
        return u32::MAX;
    }
    let value = *resource;
    for index in 0..RECORD_COUNT {
        if *table.add(index * 3 + 2) == value {
            return index as u32;
        }
    }
    u32::MAX
}

/// Original @ 0x081ec290; 92-byte true extent, two plain incoming BLs.
/// Requires a valid receiver, provider chain, and (when found) aligned
/// resource word and readable firmware runtime table. No receiver guard.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn class_8900_prid_table_index(this: *const Class8900) -> u32 {
    let resource = resource_chain_find(
        (*this).store as *mut ResourceProvider,
        ResourceKind(0x7072_4944),
        0x6066,
    );
    resource_table_index(resource as *const u32, TABLE)
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr;

    #[test]
    fn scans_every_record_and_ignores_other_words() {
        let mut table = [0u32; RECORD_COUNT * 3];
        for index in 0..RECORD_COUNT {
            table[index * 3] = 0xffff_ffff;
            table[index * 3 + 1] = 0xffff_ffff;
            table[index * 3 + 2] = 0x6067 + index as u32;
        }
        for index in 0..RECORD_COUNT {
            let value = table[index * 3 + 2];
            assert_eq!(unsafe { resource_table_index(&value, table.as_ptr()) }, index as u32);
        }
        for value in [0, u32::MAX, 0x6066, 0x6067 + RECORD_COUNT as u32] {
            assert_eq!(unsafe { resource_table_index(&value, table.as_ptr()) }, u32::MAX);
        }
    }

    #[test]
    fn duplicate_matches_choose_first() {
        let mut table = [0u32; RECORD_COUNT * 3];
        table[2] = 42;
        table[20 * 3 + 2] = 42;
        assert_eq!(unsafe { resource_table_index(&42, table.as_ptr()) }, 0);
    }

    #[test]
    fn absent_resource_never_reads_table() {
        assert_eq!(unsafe { resource_table_index(ptr::null(), ptr::null()) }, u32::MAX);
        let owner = Class8900 {
            vtable: ptr::null(), state_below_cache: [0; 11], cached_6031: 0,
            state_below_store: [0; 209], store: ptr::null_mut(),
        };
        assert_eq!(unsafe { class_8900_prid_table_index(&owner) }, u32::MAX);
    }
}
