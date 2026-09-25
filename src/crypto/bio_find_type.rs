//! OpenSSL's `BIO_find_type` chain search.
//!
//! Port: `bio_find_type` — retailOS `FUN_0803d37c` @ `0x0803d37c` (**76
//! bytes**, `0x0803d37c..0x0803d3c8`; the next separately linked function,
//! `BIO_free`, starts at `0x0803d3c8`). Raw A32 words establish this extent.
//! The three inbound calls are plain `bl` forms (0x0805fc60, 0x0805fe54, and
//! 0x080606c4); there are no predicated `bl` forms.
//!
//! # Algorithm
//!
//! Walks a null-terminated BIO chain through `next_bio` at `+0x24`. For each
//! BIO with a non-null method pointer, it reads the method type word. A query
//! whose low byte is zero is a category mask and matches any overlapping method
//! type; otherwise the method type must equal the query exactly. It returns the
//! first matching BIO or null.
//!
//! # Deliberate deviations
//!
//! None. Target pointer fields remain `u32` and are widened only to dereference
//! them on hosts.

use crate::crypto::bio_ctrl::Bio;

/// bio_find_type — original: `FUN_0803d37c` @ 0x0803d37c (76 bytes; 3 plain
/// `bl` call sites and 0 predicated `bl` call sites, binary-verified).
///
/// Returns the first BIO in `bio`'s chain whose method type matches `bio_type`.
/// A query with a zero low byte is a bitmask; every other query is exact.
///
/// # Safety
///
/// `bio` must be null or a null-terminated target-width BIO chain. Every
/// non-null method word must point to a readable method-type word.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn bio_find_type(mut bio: *mut Bio, bio_type: u32) -> *mut Bio {
    while !bio.is_null() {
        let method = unsafe { (*bio).method } as usize as *const u32;
        if !method.is_null() {
            let method_type = unsafe { method.read() };
            if if bio_type & 0xff == 0 {
                method_type & bio_type != 0
            } else {
                method_type == bio_type
            } {
                return bio;
            }
        }
        bio = unsafe { (*bio).next_bio as usize as *mut Bio };
    }
    core::ptr::null_mut()
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use parking_lot::Mutex;
    use std::sync::LazyLock;

    const FIXTURE_LEN: usize = 0x1000;
    const SECOND_BIO_OFFSET: usize = 0x100;
    const THIRD_BIO_OFFSET: usize = 0x200;
    const FIRST_METHOD_OFFSET: usize = 0x300;
    const SECOND_METHOD_OFFSET: usize = 0x304;
    const THIRD_METHOD_OFFSET: usize = 0x308;

    static BIO_FIND_TYPE_TEST_LOCK: Mutex<()> = Mutex::new(());
    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::BIO_FIND_TYPE, FIXTURE_LEN).map(|pointer| pointer as usize)
    });

    fn fixture() -> Option<(*mut Bio, *mut Bio, *mut Bio, *mut u32, *mut u32, *mut u32)> {
        let base = *SLAB.as_ref()? as *mut u8;
        unsafe {
            core::ptr::write_bytes(base, 0, FIXTURE_LEN);
            Some((
                base.cast::<Bio>(),
                base.add(SECOND_BIO_OFFSET).cast::<Bio>(),
                base.add(THIRD_BIO_OFFSET).cast::<Bio>(),
                base.add(FIRST_METHOD_OFFSET).cast::<u32>(),
                base.add(SECOND_METHOD_OFFSET).cast::<u32>(),
                base.add(THIRD_METHOD_OFFSET).cast::<u32>(),
            ))
        }
    }

    #[test]
    fn null_chain_returns_null() {
        let _lock = BIO_FIND_TYPE_TEST_LOCK.lock();
        assert!(unsafe { bio_find_type(core::ptr::null_mut(), 0x208) }.is_null());
    }

    #[test]
    fn category_mask_skips_null_methods_and_returns_first_overlap() {
        let _lock = BIO_FIND_TYPE_TEST_LOCK.lock();
        let Some((first, second, third, _first_method, second_method, third_method)) = fixture() else {
            note_missing_u32_fixture("crypto::bio_find_type");
            return;
        };
        unsafe {
            (*first).next_bio = second as usize as u32;
            (*second).method = second_method as usize as u32;
            (*second).next_bio = third as usize as u32;
            (*third).method = third_method as usize as u32;
            second_method.write(0x100);
            third_method.write(0x208);

            assert_eq!(bio_find_type(first, 0x200), third);
        }
    }

    #[test]
    fn nonzero_low_byte_requires_an_exact_type() {
        let _lock = BIO_FIND_TYPE_TEST_LOCK.lock();
        let Some((first, second, third, first_method, second_method, third_method)) = fixture() else {
            note_missing_u32_fixture("crypto::bio_find_type");
            return;
        };
        unsafe {
            (*first).method = first_method as usize as u32;
            (*first).next_bio = second as usize as u32;
            (*second).method = second_method as usize as u32;
            (*second).next_bio = third as usize as u32;
            (*third).method = third_method as usize as u32;
            first_method.write(0x208);
            second_method.write(0x308);
            third_method.write(0x208);

            assert_eq!(bio_find_type(first, 0x208), first);
            assert_eq!(bio_find_type(second, 0x208), third);
            assert!(bio_find_type(first, 0x408).is_null());
        }
    }
}
