//! guarded tagged-counter decrement — `FUN_0809f744` @ 0x0809f744 (44 bytes;
//! 28 direct `bl` call sites, binary-scanned).
//!
//! Raw ARM first calls the separately linked 0x080a7714 tag guard, which
//! returns one only for a non-NULL object whose first word is `0x7374_7263`
//! (the literal's in-memory bytes are `"crts"`; its semantic identity is not
//! established). On success, it reads the signed word at +0x30. A strictly
//! positive count is decremented and returns zero; a zero or negative count,
//! an invalid tag, and NULL all return -50 without changing the count.
//!
//! The next separately entered function begins at 0x0809f770, confirming the
//! 44-byte extent. Decoding every ARM B/BL word in osos.dec found 27 plain
//! `bl` sites and one `bleq` at 0x0806c074; there are no tail branches. The
//! conditional call is flag-gated by its caller, while this function's own
//! tag guard accepts NULL.
//!
//! Deliberate deviation: 0x080a7714 is not independently ported, so its
//! four-instruction observable tag guard is inlined here rather than exposed
//! through a dispatch seam. No identity is assigned to that callee or tag.

/// First word accepted by the unported guard at 0x080a7714.
const CRTS_TAG: u32 = 0x7374_7263;

/// The verified prefix used by `tagged_counter_try_decrement`.
///
/// The named layout preserves the original +0x30 signed counter offset on
/// both the 32-bit target and 64-bit hosts without byte-offset arithmetic.
#[repr(C)]
pub struct TaggedCounter {
    tag: u32,
    reserved: [u32; 11],
    count: i32,
}

/// tagged_counter_try_decrement — original: `FUN_0809f744` @ 0x0809f744
/// (44 bytes).
///
/// Decrements a valid `"crts"`-tagged object's positive signed counter at
/// +0x30, returning 0. Returns -50 for NULL, an unrecognised tag, or a
/// non-positive counter, leaving the object unchanged in every failure case.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn tagged_counter_try_decrement(counter: *mut TaggedCounter) -> i32 {
    if counter.is_null() || (*counter).tag != CRTS_TAG {
        return -0x32;
    }

    let count = (*counter).count;
    if count > 0 {
        (*counter).count = count - 1;
        0
    } else {
        -0x32
    }
}

/// tagged_counter_try_increment — original: `FUN_0808e16c` @ 0x0808e16c
/// (40 bytes; 27 direct `bl` call sites: 26 plain `bl`, one `bleq`).
///
/// Calls the same NULL-safe, `"crts"` tag guard as
/// `tagged_counter_try_decrement`. On a valid object, increments the raw
/// signed word at +0x30 with ARM's wrapping arithmetic and returns zero.
/// Invalid tags and NULL return -50 without touching the object.
///
/// The raw function ends at 0x0808e190, before the separately entered
/// function at 0x0808e194. Deliberate deviation: the unported guard at
/// 0x080a7714 is inlined rather than assigned an invented identity or given
/// a dispatch seam.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn tagged_counter_try_increment(counter: *mut TaggedCounter) -> i32 {
    if counter.is_null() || (*counter).tag != CRTS_TAG {
        return -0x32;
    }

    (*counter).count = (*counter).count.wrapping_add(1);
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn counter(tag: u32, count: i32) -> TaggedCounter {
        TaggedCounter { tag, reserved: [0; 11], count }
    }

    #[test]
    fn decrements_each_positive_count() {
        for count in [1, 2, i32::MAX] {
            let mut value = counter(CRTS_TAG, count);
            assert_eq!(unsafe { tagged_counter_try_decrement(&mut value) }, 0);
            assert_eq!(value.count, count - 1);
        }
    }

    #[test]
    fn refuses_non_positive_counts_without_mutating_them() {
        for count in [0, -1, i32::MIN] {
            let mut value = counter(CRTS_TAG, count);
            assert_eq!(unsafe { tagged_counter_try_decrement(&mut value) }, -0x32);
            assert_eq!(value.count, count);
        }
    }

    #[test]
    fn refuses_an_unrecognised_tag_without_touching_the_counter() {
        let mut value = counter(0, 4);
        assert_eq!(unsafe { tagged_counter_try_decrement(&mut value) }, -0x32);
        assert_eq!(value.count, 4);
    }

    #[test]
    fn null_is_rejected_before_any_dereference() {
        assert_eq!(unsafe { tagged_counter_try_decrement(core::ptr::null_mut()) }, -0x32);
    }

    #[test]
    fn increments_all_signed_counter_values_with_arm_wrapping() {
        for (count, expected) in [
            (0, 1),
            (1, 2),
            (-1, 0),
            (i32::MIN, i32::MIN + 1),
            (i32::MAX, i32::MIN),
        ] {
            let mut value = counter(CRTS_TAG, count);
            assert_eq!(unsafe { tagged_counter_try_increment(&mut value) }, 0);
            assert_eq!(value.count, expected);
        }
    }

    #[test]
    fn increment_refuses_an_unrecognised_tag_without_mutating_it() {
        let mut value = counter(0, i32::MAX);
        assert_eq!(unsafe { tagged_counter_try_increment(&mut value) }, -0x32);
        assert_eq!(value.count, i32::MAX);
    }

    #[test]
    fn increment_rejects_null_before_any_dereference() {
        assert_eq!(unsafe { tagged_counter_try_increment(core::ptr::null_mut()) }, -0x32);
    }
}
