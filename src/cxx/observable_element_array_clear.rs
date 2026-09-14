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
//! First invoke the unresolved direct callee at `0x0839c1c8`, which conditionally
//! walks the receiver's indexed elements and dispatches each non-NULL element's
//! vtable slot `+0x04`. Then clear the observable-array base through its
//! `+0xbc` signed tail-removal slot. The first callee has no established class
//! identity, so this port preserves it as an explicit direct-call boundary
//! rather than inventing one.
//!
//! Deliberate deviation: the stock `bl` to the unported first stage is an
//! indirect seam so host tests can model it; target builds call its verified
//! retailOS load address. The final stock tail branch is a regular Rust call
//! into the existing port, whose ARM implementation retains the tail dispatch
//! into the concrete array vtable.

use super::observable_array::ObservableArray;

#[cfg(not(target_arch = "arm"))]
use super::observable_array::observable_array_clear;

#[cfg(target_arch = "arm")]
unsafe extern "C" {
    fn observable_array_clear(this: *mut ObservableArray);
}

/// Firmware load address of the unresolved element-disposal stage,
/// `FUN_0839c1c8`.
pub const OBSERVABLE_ELEMENT_ARRAY_DISPOSE_ITEMS_ADDRESS: usize = 0x0839_c1c8;

/// Direct-call boundary for the first stage of
/// [`observable_element_array_clear`].
///
/// Raw ARM proves that this call accepts the same receiver and returns before
/// the observable-array clear. Its internal conditional indexed walk and
/// element `+0x04` virtual dispatch are known, but its owning class is not.
pub type ObservableElementArrayDisposeItems = unsafe extern "C" fn(*mut ObservableArray);

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_observable_element_array_dispose_items(this: *mut ObservableArray) {
    let dispose_items: ObservableElementArrayDisposeItems =
        unsafe { core::mem::transmute(OBSERVABLE_ELEMENT_ARRAY_DISPOSE_ITEMS_ADDRESS) };
    unsafe { dispose_items(this) };
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_observable_element_array_dispose_items(_this: *mut ObservableArray) {
    panic!("observable_element_array_clear requires unresolved FUN_0839c1c8")
}

#[cfg(target_os = "none")]
pub const DEFAULT_OBSERVABLE_ELEMENT_ARRAY_DISPOSE_ITEMS: ObservableElementArrayDisposeItems =
    firmware_observable_element_array_dispose_items;

#[cfg(not(target_os = "none"))]
pub const DEFAULT_OBSERVABLE_ELEMENT_ARRAY_DISPOSE_ITEMS: ObservableElementArrayDisposeItems =
    missing_observable_element_array_dispose_items;

/// Active direct-call boundary for the unresolved first stage. Host tests
/// install recorders; target builds reach the still-mapped retailOS code.
pub static mut OBSERVABLE_ELEMENT_ARRAY_DISPOSE_ITEMS: ObservableElementArrayDisposeItems =
    DEFAULT_OBSERVABLE_ELEMENT_ARRAY_DISPOSE_ITEMS;

/// Disposes indexed elements, then clears the observable-array base.
///
/// Original: `FUN_0839c258` @ `0x0839c258` (24 bytes; five inbound direct
/// `bl` sites: four unconditional and one `blne`, binary-scanned).
///
/// # Safety
///
/// `this` must satisfy the unresolved first stage's receiver contract and the
/// concrete observable-array contract of [`observable_array_clear`]. Neither
/// stock stage guards `this`, its vtable, or the final `+0xbc` slot.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.observable_element_array_clear")]
pub unsafe extern "C" fn observable_element_array_clear(this: *mut ObservableArray) {
    let dispose_items = unsafe {
        core::ptr::read_volatile(core::ptr::addr_of!(OBSERVABLE_ELEMENT_ARRAY_DISPOSE_ITEMS))
    };
    unsafe { dispose_items(this) };
    unsafe { observable_array_clear(this) };
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::cxx::observable_array::{
        ObservableArrayClearHost, ObservableArrayClearVtable,
    };
    use parking_lot::Mutex;


    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static TEST_EVENTS: Mutex<std::vec::Vec<i64>> = Mutex::new(std::vec::Vec::new());

    unsafe extern "C" fn record_dispose_items(_this: *mut ObservableArray) {
        TEST_EVENTS.lock().push(i64::MIN);
    }

    unsafe extern "C" fn record_remove_tail(_this: *mut ObservableArray, count: i32) {
        TEST_EVENTS.lock().push(i64::from(count));
    }

    #[test]
    fn disposes_before_clearing_with_wrapping_lengths() {
        let _guard = TEST_LOCK.lock();
        let vtable = ObservableArrayClearVtable {
            unresolved_00_b8: [0; 47],
            remove_tail: record_remove_tail,
        };

        unsafe { OBSERVABLE_ELEMENT_ARRAY_DISPOSE_ITEMS = record_dispose_items };
        for (len, expected_count) in [(0, 0), (u32::MAX, 1)] {
            TEST_EVENTS.lock().clear();
            let mut array = ObservableArrayClearHost {
                vtable: &vtable,
                len,
            };

            unsafe { observable_element_array_clear((&mut array as *mut ObservableArrayClearHost).cast()) };

            assert_eq!(*TEST_EVENTS.lock(), std::vec![i64::MIN, expected_count]);
        }
        unsafe {
            OBSERVABLE_ELEMENT_ARRAY_DISPOSE_ITEMS = DEFAULT_OBSERVABLE_ELEMENT_ARRAY_DISPOSE_ITEMS;
        }
    }
}
