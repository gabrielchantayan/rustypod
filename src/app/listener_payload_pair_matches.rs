//! Listener payload pair predicate — `FUN_082012c4` @ load address
//! **0x082012c4**, **52 bytes**, next real function at **0x082012f8**.
//! Raw ARM words verify **0 plain BL and 0 predicated BL** instructions;
//! there are two incoming plain BL sites, at 0x0811f010 and 0x0811f200.
//!
//! Dereferences the key pointer, returns 0 if its payload is null, then
//! compares payload words +4 and +8 in order. Word +0 (the tag) is ignored.
//! A first-word mismatch skips the second-word reads. Deliberate deviations:
//! none; native pointers model the outer pointer on hosts, while payload
//! offsets remain four-byte u32 word indices on every target.

/// Returns 1 exactly when a non-null key's two payload words match.
///
/// # Safety
/// `key` must be readable and aligned. Its non-null pointee and `candidate`
/// must have readable, aligned word 1; word 2 must also be readable when
/// word 1 matches. A null key pointee does not require a valid candidate.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn listener_payload_pair_matches(
    key: *const *const u32,
    candidate: *const u32,
) -> u32 {
    let payload = unsafe { key.read() };
    if payload.is_null() {
        return 0;
    }
    if unsafe { payload.add(1).read() != candidate.add(1).read() } {
        return 0;
    }
    u32::from(unsafe { payload.add(2).read() == candidate.add(2).read() })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_payload_skips_candidate() {
        let key = core::ptr::null();
        assert_eq!(unsafe { listener_payload_pair_matches(&key, core::ptr::null()) }, 0);
    }

    #[test]
    fn ignores_tag_and_requires_both_words_without_reordering() {
        let payload = [0x0898_ce24, 0, u32::MAX];
        let key = payload.as_ptr();
        for (candidate, expected) in [
            ([0, 0, u32::MAX], 1),
            ([0x0898_ce24, 1, u32::MAX], 0),
            ([0x0898_ce24, 0, 0], 0),
            ([0x0898_ce24, u32::MAX, 0], 0),
        ] {
            assert_eq!(unsafe { listener_payload_pair_matches(&key, candidate.as_ptr()) }, expected);
        }
        assert_eq!(unsafe { listener_payload_pair_matches(&key, key) }, 1);
    }

    #[test]
    fn first_mismatch_needs_no_third_word() {
        let payload = [17, 1];
        let candidate = [17, 2];
        let key = payload.as_ptr();
        assert_eq!(unsafe { listener_payload_pair_matches(&key, candidate.as_ptr()) }, 0);
    }
}
