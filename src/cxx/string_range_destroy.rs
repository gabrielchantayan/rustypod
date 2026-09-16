//! `cxx_string_range_destroy` — original: `FUN_083e5950` @ 0x083e5950
//! (40 bytes).
//!
//! Raw ARM establishes the exact extent 0x083e5950..0x083e5978: the next
//! independently linked function (pushing r4..r8) starts at 0x083e5978. The
//! ten words are: push {r4,r5,r6,lr}; save r2 (end) and r1 (begin) into
//! r5/r4; then a loop that moves the current slot into r0, `bl`s
//! `cxx_string_release` @ 0x083d8b04, advances r4 by four bytes, and repeats
//! until r4 == r5; finally pop {r4,r5,r6,pc}. r0 (param_1) is never used.
//! A full raw scan decoding every ARM B/BL word in osos.dec verifies exactly
//! one unconditional `bl` inside (to 0x083d8b04), no predicated calls, and
//! four direct, unconditional `bl` callers at 0x083e5a84, 0x083e5b94,
//! 0x083e5c54, and 0x083e5cc8; there are no tail branches.
//!
//! Algorithm: release every four-byte COW string slot in the half-open
//! `[begin, end)` range in address order via `cxx_string_release`.
//!
//! # Deliberate deviation
//!
//! None; the call boundary to `cxx_string_release` is preserved. Host tests
//! inject a recorder through `cxx_string_range_destroy_with` so they can
//! observe the ordered slot walk without synthetic COW-string storage.

use crate::cxx::string::cxx_string_release;

type StringRelease = unsafe extern "C" fn(*mut *mut u8);

/// Releases every COW string slot in `[begin, end)`. The first argument
/// matches the original's ignored r0. On ARMv5 each slot is one 32-bit word;
/// the typed pointer keeps that stride on target while host tests retain
/// native pointer width.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.cxx_string_range_destroy")]
#[inline(never)]
pub unsafe extern "C" fn cxx_string_range_destroy(
    _ignored: *mut u8,
    begin: *mut *mut u8,
    end: *mut *mut u8,
) {
    unsafe { cxx_string_range_destroy_with(begin, end, cxx_string_release) }
}

/// Separates the verified callee so host tests can observe the element walk.
#[inline(always)]
unsafe fn cxx_string_range_destroy_with(
    begin: *mut *mut u8,
    end: *mut *mut u8,
    release_string: StringRelease,
) {
    unsafe {
        let mut current = begin;
        while current != end {
            release_string(current);
            current = current.add(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};

    static RELEASE_COUNT: AtomicUsize = AtomicUsize::new(0);
    static RELEASED_SLOTS: [AtomicUsize; 4] = [
        AtomicUsize::new(0),
        AtomicUsize::new(0),
        AtomicUsize::new(0),
        AtomicUsize::new(0),
    ];

    unsafe extern "C" fn record_string_release(slot: *mut *mut u8) {
        let index = RELEASE_COUNT.fetch_add(1, Ordering::SeqCst);
        RELEASED_SLOTS[index].store(slot as usize, Ordering::SeqCst);
    }

    fn reset_observations() {
        RELEASE_COUNT.store(0, Ordering::SeqCst);
        for slot in &RELEASED_SLOTS {
            slot.store(0, Ordering::SeqCst);
        }
    }

    #[test]
    fn releases_each_slot_in_address_order() {
        let mut slots = [
            0x1111usize as *mut u8,
            0x2222usize as *mut u8,
            0x3333usize as *mut u8,
        ];
        reset_observations();

        unsafe {
            cxx_string_range_destroy_with(
                slots.as_mut_ptr(),
                slots.as_mut_ptr().add(3),
                record_string_release,
            )
        };

        assert_eq!(RELEASE_COUNT.load(Ordering::SeqCst), 3);
        for index in 0..3 {
            assert_eq!(
                RELEASED_SLOTS[index].load(Ordering::SeqCst),
                unsafe { slots.as_mut_ptr().add(index) } as usize
            );
        }
    }

    #[test]
    fn empty_range_releases_nothing() {
        let mut slots = [0x1111usize as *mut u8];
        reset_observations();

        unsafe {
            cxx_string_range_destroy_with(slots.as_mut_ptr(), slots.as_mut_ptr(), record_string_release)
        };

        assert_eq!(RELEASE_COUNT.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn single_slot_range_releases_exactly_once() {
        let mut slots = [0xaaaausize as *mut u8];
        reset_observations();

        unsafe {
            cxx_string_range_destroy_with(
                slots.as_mut_ptr(),
                slots.as_mut_ptr().add(1),
                record_string_release,
            )
        };

        assert_eq!(RELEASE_COUNT.load(Ordering::SeqCst), 1);
        assert_eq!(RELEASED_SLOTS[0].load(Ordering::SeqCst), slots.as_mut_ptr() as usize);
    }
}
