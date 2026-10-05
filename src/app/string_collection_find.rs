//! First equal string object in a collection.
//!
//! `string_collection_find` — `FUN_081bc548` @ 0x081bc548, exactly
//! 100 bytes (0x081bc548..0x081bc5ac), ending before the next push prologue.
//! Raw A32 decoding verifies two plain inbound BLs (0x081bc534,
//! 0x081bc5b8), zero predicated inbound BLs, four plain outbound BLs,
//! and zero predicated outbound BLs.
//!
//! Construct a five-word iterator at position -2, advance until exhaustion
//! or the first string_object_equals result that is nonzero, then clean up
//! and return the matching object word (zero on exhaustion). Entries are
//! StringObjects embedded at the start of larger records; the +8 count is
//! used by callers, not by this search. All four ported callees are called
//! directly, retaining their existing iterator bookkeeping seams.
//! Deliberate deviations: zero-initialize the local words so the existing
//! host iterator defaults cannot read uninitialized bookkeeping. The scan
//! is inlined from a helper for tests; Rust chooses the stack/register layout.

use crate::app::vtable_set::{iterator_state_construct, iterator_state_next, iterator_state_cleanup};
use crate::cxx::string_object::{StringObject, string_object_equals};

#[inline(always)]
fn first_matching(mut next: impl FnMut() -> Option<u32>, mut equals: impl FnMut(u32) -> bool) -> u32 {
    while let Some(entry) = next() {
        if equals(entry) {
            return entry;
        }
    }
    0
}

/// # Safety
/// `collection` must be a valid firmware collection for the iterator callees.
/// Each yielded word and `key` must address readable StringObjects. Stored
/// collection addresses and yielded object addresses are target-width u32.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn string_collection_find(collection: *mut u8, key: *const StringObject) -> u32 {
    let mut state = [0u32; 5];
    iterator_state_construct(state.as_mut_ptr(), collection, -2);
    let mut entry = 0u32;
    let found = first_matching(
        || {
            if iterator_state_next(state.as_mut_ptr(), (&mut entry as *mut u32).cast()) != 0 {
                Some(entry)
            } else {
                None
            }
        },
        |word| string_object_equals(word as *const StringObject, key) != 0,
    );
    iterator_state_cleanup(state.as_mut_ptr());
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    fn search(entries: &[&[u8]], key: &[u8]) -> (u32, usize) {
        let mut visited = 0;
        let result = first_matching(
            || {
                if visited == entries.len() { return None; }
                visited += 1;
                Some(visited as u32)
            },
            |word| entries[word as usize - 1] == key,
        );
        (result, visited)
    }

    #[test]
    fn empty_and_missing_collections_return_zero() {
        assert_eq!(search(&[], b""), (0, 0));
        assert_eq!(search(&[b"a", b"ab", b"abc"], b"abcd"), (0, 3));
    }

    #[test]
    fn first_equal_record_wins_without_advancing_again() {
        assert_eq!(search(&[b"same", b"same", b"tail"], b"same"), (1, 1));
        assert_eq!(search(&[b"different", b"same", b"same"], b"same"), (2, 2));
        assert_eq!(search(&[b"prefix", b"prefix-long"], b"prefix-long"), (2, 2));
    }

    #[test]
    fn empty_and_utf8_keys_are_not_special_cased() {
        assert_eq!(search(&[b"nonempty", b"", b""], b""), (2, 2));
        assert_eq!(search(&[b"caf", "café".as_bytes()], "café".as_bytes()), (2, 2));
    }
}
