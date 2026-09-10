//! OpenSSL BIO retry-state propagation helper.
//!
//! Port: `bio_copy_next_retry` — `FUN_0803d270` @ 0x0803d270 (**36 bytes**,
//! `0x0803d270..0x0803d294`; `BIO_ctrl` starts immediately afterward). Raw
//! decoding of every ARM B/BL word in `osos.dec` found **12 call sites**, all
//! unconditional `bl`: `0x080ebf08`, `0x080ebff0`, `0x080ee654`,
//! `0x080eeb40`, `0x080ef1b4`, `0x080ef38c`, `0x080ef6d8`, `0x080f3e84`,
//! `0x080f3fd0`, `0x080f4888`, `0x080f491c`, and `0x080f4960`. There are no
//! predicated calls, tail branches, or raw image data words holding its
//! address.
//!
//! # Algorithm
//!
//! Fetches `bio->next_bio` with no null checks, ORs that BIO's low four retry
//! flag bits into `bio->flags`, then copies its retry-reason word. It leaves
//! every other word and all already-set flag bits unchanged.
//!
//! # Deliberate deviations
//!
//! None in target behavior. The shared [`Bio`] representation retains target
//! pointers as `u32`; host tests map the linked BIO pair below 4 GiB before
//! calling this raw-pointer ABI.

use crate::crypto::bio_ctrl::Bio;

/// bio_copy_next_retry — original: `FUN_0803d270` @ 0x0803d270 (36 bytes; 12
/// direct, unconditional `bl` call sites, binary-verified from `osos.dec`).
///
/// Propagates the low retry-flag nibble and retry reason from `bio->next_bio`
/// into `bio`. The existing low nibble is retained because the ARM body ORs
/// rather than replaces it.
///
/// # Safety
///
/// `bio` and its nonzero `next_bio` word must point to aligned, writable
/// [`Bio`] instances in the target's 32-bit layout.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn bio_copy_next_retry(bio: *mut Bio) {
    let next_bio = unsafe { (*bio).next_bio as usize as *mut Bio };
    unsafe {
        (*bio).flags |= (*next_bio).flags & 0x0f;
        (*bio).retry_reason = (*next_bio).retry_reason;
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use parking_lot::Mutex;
    use std::sync::LazyLock;

    const FIXTURE_LEN: usize = 0x1000;
    const NEXT_BIO_OFFSET: usize = 0x100;

    static BIO_COPY_NEXT_RETRY_TEST_LOCK: Mutex<()> = Mutex::new(());
    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::BIO_COPY_NEXT_RETRY, FIXTURE_LEN)
            .map(|pointer| pointer as usize)
    });

    fn linked_bios() -> Option<(*mut Bio, *mut Bio)> {
        let base = *SLAB.as_ref()? as *mut u8;
        unsafe {
            core::ptr::write_bytes(base, 0, FIXTURE_LEN);
            let bio = base.cast::<Bio>();
            let next_bio = base.add(NEXT_BIO_OFFSET).cast::<Bio>();
            (*bio).next_bio = next_bio as usize as u32;
            Some((bio, next_bio))
        }
    }

    #[test]
    fn merges_next_retry_nibble_without_disturbing_other_bio_words() {
        let _lock = BIO_COPY_NEXT_RETRY_TEST_LOCK.lock();
        let Some((bio, next_bio)) = linked_bios() else {
            note_missing_u32_fixture("crypto::bio_copy_next_retry");
            return;
        };
        unsafe {
            (*bio).method = 0x1111_1111;
            (*bio).flags = 0xffff_fff0;
            (*bio).retry_reason = 0xaaaa_aaaa;
            (*next_bio).flags = 0xabcd_000d;
            (*next_bio).retry_reason = 0x1234_5678;

            bio_copy_next_retry(bio);

            assert_eq!((*bio).method, 0x1111_1111);
            assert_eq!((*bio).next_bio, next_bio as usize as u32);
            assert_eq!((*bio).flags, 0xffff_fffd);
            assert_eq!((*bio).retry_reason, 0x1234_5678);
        }
    }

    #[test]
    fn retains_existing_retry_nibble_when_next_has_no_retry_flags() {
        let _lock = BIO_COPY_NEXT_RETRY_TEST_LOCK.lock();
        let Some((bio, next_bio)) = linked_bios() else {
            note_missing_u32_fixture("crypto::bio_copy_next_retry");
            return;
        };
        unsafe {
            (*bio).flags = 0x1234_5679;
            (*bio).retry_reason = 0xffff_ffff;
            (*next_bio).flags = 0xabcd_ef00;
            (*next_bio).retry_reason = 0;

            bio_copy_next_retry(bio);

            assert_eq!((*bio).flags, 0x1234_5679);
            assert_eq!((*bio).retry_reason, 0);
        }
    }
}
