//! `observable_element_array_clear` — retailOS `FUN_0839c258` @
//! `0x0839c258`.
//!
//! Raw ARM is exactly 24 bytes, `0x0839c258..0x0839c26c`: it saves `this`,
//! calls `FUN_0839c1c8(this)`, restores `this`, and tail-branches to the
//! ported `observable_array_clear` at `0x08271c84`. The next independently
//! linked function starts at `0x0839c270`; there is no literal pool. Decoding
//! every aligned ARM B/BL-immediate word in `osos.dec` finds five inbound
//! direct `bl` sites: four unconditional at 0x08126c7c, 0x08127458,
//! 0x08127780, and 0x08127fa0, plus one `blne` at 0x08128094. The predicated
//! caller checks an external state flag; this wrapper itself has no NULL or
//! state guard.
//!
//! # Algorithm
//!
//! First invoke [`observable_element_array_dispose_items`], which conditionally
//! walks the receiver's indexed elements and dispatches each non-NULL element's
//! vtable slot `+0x04`. Then clear the observable-array base through its
//! `+0xbc` signed tail-removal slot.
//!
//! Deliberate deviation: the stock direct `bl` is a regular Rust call. The
//! final stock tail branch is likewise a Rust call into the existing port,
//! whose ARM implementation retains the tail dispatch into the concrete array
//! vtable.

use super::observable_element_array_dispose_items::observable_element_array_dispose_items;
use super::observable_array::ObservableArray;
#[cfg(not(target_arch = "arm"))]
use super::observable_array::observable_array_clear;

#[cfg(target_arch = "arm")]
unsafe extern "C" {
    fn observable_array_clear(this: *mut ObservableArray);
}


/// Disposes indexed elements, then clears the observable-array base.
///
/// Original: `FUN_0839c258` @ `0x0839c258` (24 bytes; five inbound direct
/// `bl` sites: four unconditional and one `blne`, binary-scanned).
///
/// # Safety
///
/// `this` must satisfy both the indexed-element disposal and concrete
/// observable-array contracts. Neither stock stage guards `this`, its vtable,
/// or the final `+0xbc` slot.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.observable_element_array_clear")]
pub unsafe extern "C" fn observable_element_array_clear(this: *mut ObservableArray) {
    unsafe { observable_element_array_dispose_items(this.cast()) };
    unsafe { observable_array_clear(this) };
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::cxx::observable_element_array_dispose_items::HostObservableElementArray;
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static TEST_EVENTS: Mutex<std::vec::Vec<i64>> = Mutex::new(std::vec::Vec::new());

    #[repr(C)]
    struct ClearVtable {
        unresolved_00_3c: [usize; 16],
        element_slot: unsafe extern "C" fn(*mut u8, usize) -> *mut *mut u8,
        unresolved_44_b8: [usize; 30],
        remove_tail: unsafe extern "C" fn(*mut ObservableArray, i32),
    }

    unsafe extern "C" fn element_slot(_: *mut u8, _: usize) -> *mut *mut u8 {
        core::ptr::null_mut()
    }

    unsafe extern "C" fn record_remove_tail(_this: *mut ObservableArray, count: i32) {
        TEST_EVENTS.lock().push(i64::from(count));
    }

    #[test]
    fn clears_after_disabled_disposal_with_wrapping_lengths() {
        let _guard = TEST_LOCK.lock();
        let vtable = ClearVtable {
            unresolved_00_3c: [0; 16],
            element_slot,
            unresolved_44_b8: [0; 30],
            remove_tail: record_remove_tail,
        };

        for (len, expected_count) in [(0, 0), (-1, 1)] {
            TEST_EVENTS.lock().clear();
            let mut array = HostObservableElementArray {
                vtable: (&vtable as *const ClearVtable).cast(),
                count: len,
                unresolved_08_to_27: [0; 0x20],
                enabled: 0,
            };

            unsafe { observable_element_array_clear((&mut array as *mut HostObservableElementArray).cast()) };

            assert_eq!(*TEST_EVENTS.lock(), std::vec![i64::from(expected_count)]);
        }
    }
}
