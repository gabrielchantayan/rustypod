//! Two-word opaque-key equality predicate from retailOS.
//!
//! The four recovered callers use this as a callback with an ignored first
//! argument, a two-word search key, and a two-word candidate key. Neither the
//! key type nor the callback context has a recovered higher-level identity.

/// A pair of opaque 32-bit retailOS key words.
#[repr(C)]
pub struct OpaquePair {
    pub first: u32,
    pub second: u32,
}

/// opaque_pair_equal — original: `FUN_083d7b88` @ `0x083d7b88` (36 bytes;
/// the next separately linked function starts at `0x083d7bac`).
///
/// Four inbound direct `bl` call sites are plain and none are predicated. The
/// body has no outbound `bl` instructions. It ignores its callback context,
/// loads both aligned words from `right` and `left`, and returns true exactly
/// when both corresponding words match. It performs no writes or NULL checks.
///
/// Deliberate deviations: none.
///
/// # Safety
///
/// `left` and `right` must each point to a readable, four-byte-aligned
/// [`OpaquePair`]. As in retailOS, neither pointer is NULL-checked.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn opaque_pair_equal(
    _context: *const u8,
    left: *const OpaquePair,
    right: *const OpaquePair,
) -> bool {
    unsafe {
        let right_first = core::ptr::read_volatile(core::ptr::addr_of!((*right).first));
        let right_second = core::ptr::read_volatile(core::ptr::addr_of!((*right).second));
        let left_second = core::ptr::read_volatile(core::ptr::addr_of!((*left).second));
        let left_first = core::ptr::read_volatile(core::ptr::addr_of!((*left).first));
        (left_second == right_second) & (left_first == right_first)
    }
}

#[cfg(test)]
mod tests {
    use super::{opaque_pair_equal, OpaquePair};

    #[test]
    fn compares_both_words_and_ignores_context() {
        let pair = OpaquePair { first: 0, second: u32::MAX };
        let matching = OpaquePair { first: 0, second: u32::MAX };
        let first_mismatch = OpaquePair { first: 1, second: u32::MAX };
        let second_mismatch = OpaquePair { first: 0, second: 0 };

        unsafe {
            assert!(opaque_pair_equal(core::ptr::null(), &pair, &matching));
            assert!(!opaque_pair_equal(
                core::ptr::null(),
                &pair,
                &first_mismatch
            ));
            assert!(!opaque_pair_equal(
                core::ptr::null(),
                &pair,
                &second_mismatch
            ));
        }
    }
}
