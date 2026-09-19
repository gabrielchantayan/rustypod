//! OpenSSL's `BIO_push` chain linker.
//!
//! Port: `bio_push` — `FUN_0803d69c` @ 0x0803d69c (**76 bytes**,
//! `0x0803d69c..0x0803d6e8`; the next separately linked function begins at
//! 0x0803d6e8). Raw decoding of every ARM B/BL word in `osos.dec` found **4
//! direct, unconditional `bl` call sites** (0x08060048, 0x08060294,
//! 0x0806032c, and 0x08272918), with no predicated calls.
//!
//! # Algorithm
//!
//! A null head returns the tail unchanged. Otherwise it walks `next_bio` at
//! `+0x24` to the current tail, appends the supplied tail, sets that tail's
//! `prev_bio` at `+0x28` when non-null, then sends `BIO_CTRL_PUSH` (6) to the
//! original head. The control result is deliberately ignored.
//!
//! # Deliberate deviations
//!
//! None. Target-width link fields remain `u32` on hosts; host tests map their
//! fixtures below 4 GiB before exercising the raw-pointer ABI.

use core::ffi::c_void;

use crate::crypto::bio_ctrl::{bio_ctrl, Bio, BIO_CB_CTRL};

/// bio_push — original: `FUN_0803d69c` @ 0x0803d69c (76 bytes; 4 direct,
/// unconditional `bl` call sites, binary-verified from `osos.dec`).
///
/// Appends `tail` to the end of `head`'s BIO chain, makes the reverse link,
/// and notifies the head using `BIO_CTRL_PUSH`. The notification result does
/// not alter the returned original head.
///
/// # Safety
///
/// `head` must be null or point to a writable, null-terminated target-width
/// BIO chain. A non-null `tail` must point to a writable [`Bio`].
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn bio_push(head: *mut Bio, tail: *mut Bio) -> *mut Bio {
    if head.is_null() {
        return tail;
    }

    let mut last = head;
    while unsafe { (*last).next_bio != 0 } {
        last = unsafe { (*last).next_bio as usize as *mut Bio };
    }

    unsafe { (*last).next_bio = tail as usize as u32 };
    if !tail.is_null() {
        unsafe { (*tail)._prev_bio = last as usize as u32 };
    }
    unsafe { bio_ctrl(head, BIO_CB_CTRL as i32, 0, core::ptr::null_mut::<c_void>()) };
    head
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use parking_lot::Mutex;
    use std::sync::LazyLock;

    const FIXTURE_LEN: usize = 0x1000;
    const MIDDLE_OFFSET: usize = 0x100;
    const TAIL_OFFSET: usize = 0x200;

    static BIO_PUSH_TEST_LOCK: Mutex<()> = Mutex::new(());
    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::BIO_PUSH, FIXTURE_LEN).map(|pointer| pointer as usize)
    });

    fn bios() -> Option<(*mut Bio, *mut Bio, *mut Bio)> {
        let base = *SLAB.as_ref()? as *mut u8;
        unsafe {
            core::ptr::write_bytes(base, 0, FIXTURE_LEN);
            Some((
                base.cast::<Bio>(),
                base.add(MIDDLE_OFFSET).cast::<Bio>(),
                base.add(TAIL_OFFSET).cast::<Bio>(),
            ))
        }
    }

    #[test]
    fn null_head_returns_tail_unchanged() {
        let _lock = BIO_PUSH_TEST_LOCK.lock();
        let Some((_head, _middle, tail)) = bios() else {
            note_missing_u32_fixture("crypto::bio_push");
            return;
        };
        unsafe {
            (*tail)._prev_bio = 0xfeed_beef;
            assert_eq!(bio_push(core::ptr::null_mut(), tail), tail);
            assert_eq!((*tail)._prev_bio, 0xfeed_beef);
        }
    }

    #[test]
    fn appends_at_existing_tail_and_sets_reverse_link() {
        let _lock = BIO_PUSH_TEST_LOCK.lock();
        let Some((head, middle, tail)) = bios() else {
            note_missing_u32_fixture("crypto::bio_push");
            return;
        };
        unsafe {
            (*head).next_bio = middle as usize as u32;
            (*middle).next_bio = 0;
            (*tail)._prev_bio = 0xfeed_beef;

            assert_eq!(bio_push(head, tail), head);

            assert_eq!((*head).next_bio, middle as usize as u32);
            assert_eq!((*middle).next_bio, tail as usize as u32);
            assert_eq!((*tail)._prev_bio, middle as usize as u32);
        }
    }

    #[test]
    fn null_tail_terminates_chain_without_writing_reverse_link() {
        let _lock = BIO_PUSH_TEST_LOCK.lock();
        let Some((head, middle, _tail)) = bios() else {
            note_missing_u32_fixture("crypto::bio_push");
            return;
        };
        unsafe {
            (*head).next_bio = middle as usize as u32;
            (*middle).next_bio = 0;

            assert_eq!(bio_push(head, core::ptr::null_mut()), head);
            assert_eq!((*middle).next_bio, 0);
        }
    }
}
