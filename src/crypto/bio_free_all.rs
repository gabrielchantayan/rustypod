//! OpenSSL's `BIO_free_all` chain destructor.
//!
//! Port: `bio_free_all` — retailOS `FUN_0803d454` @ `0x0803d454` (**48
//! bytes**, `0x0803d454..0x0803d484`; the next separately linked function
//! starts at `0x0803d484`). Raw decoding finds **3 direct inbound call
//! sites**: one unconditional `bl` (`0x08272994`) and two `blne`
//! (`0x08060228`, `0x08060234`); no raw-image data word holds this address.
//! The function itself makes **one unconditional `bl`** (`0x0803d46c`) to
//! `bio_free` and no predicated calls.
//!
//! # Algorithm
//!
//! Walk the `next_bio` chain. Before releasing each BIO, retain its reference
//! count and successor. Release it through `bio_free`; stop after that BIO
//! when the retained count was greater than one, otherwise continue with the
//! retained successor.
//!
//! # Deliberate deviations
//!
//! None. `next_bio` remains a target-width word, as in [`Bio`].

use crate::crypto::bio_ctrl::Bio;
use crate::crypto::bio_free::bio_free;

/// bio_free_all — original: `FUN_0803d454` @ 0x0803d454 (48 bytes; 3 inbound
/// direct call sites: 1 `bl`, 2 `blne`; one unconditional internal `bl`).
///
/// Releases a BIO chain until a shared BIO is reached. The shared BIO itself
/// is released once, then its retained positive reference count stops traversal.
///
/// # Safety
///
/// Each non-null BIO in the traversed target-width chain must be valid for
/// [`bio_free`], and every nonzero `next_bio` word must name another valid BIO.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn bio_free_all(mut bio: *mut Bio) {
    while !bio.is_null() {
        let references = unsafe { (*bio).references };
        let next_bio = unsafe { (*bio).next_bio as usize as *mut Bio };

        unsafe { bio_free(bio) };
        if references > 1 {
            return;
        }
        bio = next_bio;
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use core::ptr;
    use std::sync::LazyLock;

    const FIXTURE_LEN: usize = 0x1000;
    const SECOND_BIO_OFFSET: usize = 0x100;

    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::BIO_FREE_ALL, FIXTURE_LEN).map(|pointer| pointer as usize)
    });

    fn fixture() -> Option<(*mut Bio, *mut Bio)> {
        let base = *SLAB.as_ref()? as *mut u8;
        unsafe {
            ptr::write_bytes(base, 0, FIXTURE_LEN);
            Some((base.cast(), base.add(SECOND_BIO_OFFSET).cast()))
        }
    }

    #[test]
    fn null_chain_is_a_noop() {
        unsafe { bio_free_all(ptr::null_mut()) };
    }

    #[test]
    fn shared_head_is_released_once_without_visiting_successor() {
        let Some((head, successor)) = fixture() else {
            note_missing_u32_fixture("bio_free_all");
            return;
        };
        unsafe {
            (*head).references = 2;
            (*head).next_bio = successor as usize as u32;
            (*successor).references = 2;
            bio_free_all(head);
            assert_eq!((*head).references, 1);
            assert_eq!((*successor).references, 2);
        }
    }
}
