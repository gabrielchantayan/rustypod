//! `replace_owned_pointer` — original: `FUN_083e75f4` @ `0x083e75f4`
//! (36 bytes; 5 verified direct `bl` call sites, all unconditional).
//!
//! Raw ARM establishes a 36-byte extent from `push {r4,r5,r6,lr}` through
//! `pop {r4,r5,r6,pc}` at `0x083e7614`; the separately linked sibling starts
//! at `0x083e7618`. Ghidra's 28-byte extent incorrectly treats the
//! `operator_delete` call as non-returning and omits the live trailing store.
//! The function compares the caller-owned pointer word with its replacement.
//! Equal values leave the slot alone; unequal values are released through the
//! already ported tag-2 `operator_delete` and then the replacement is stored.
//! Decoding every immediate ARM B/BL word in osos.dec finds five inbound
//! calls, all plain unconditional `bl` at `0x081a9b24`, `0x081aa270`,
//! `0x081abee8`, `0x081ad6d4`, and `0x081ad740`; no predicated direct calls
//! or direct tail branches reach this entry.
//!
//! Deliberate deviations: none.

use crate::heap::veneers::operator_delete;

/// Replaces an owned tag-2 allocation in `slot` after deleting its old value.
///
/// `slot` must be valid and aligned. The replacement is never dereferenced;
/// it is compared and stored exactly as the original's pointer word. When it
/// differs from the old value, the old value is passed to `operator_delete`,
/// whose NULL guard is part of the retail behavior.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.replace_owned_pointer")]
pub unsafe extern "C" fn replace_owned_pointer(slot: *mut *mut u8, replacement: *mut u8) {
    let old = unsafe { slot.read() };
    if old != replacement {
        unsafe { operator_delete(old) };
        unsafe { slot.write(replacement) };
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::heap::veneers::tests::{free_log, mock_heap};

    const OLD: *mut u8 = 0x08a1_2700 as *mut u8;
    const NEW: *mut u8 = 0x08a1_2710 as *mut u8;

    #[test]
    fn equal_values_leave_slot_and_heap_untouched() {
        let _lock = mock_heap();
        let mut slot = OLD;

        unsafe { replace_owned_pointer(&mut slot, OLD) };

        assert_eq!(slot, OLD);
        assert_eq!(free_log().0, 0);
    }

    #[test]
    fn replaces_non_null_value_after_tag2_delete() {
        let _lock = mock_heap();
        let mut slot = OLD;

        unsafe { replace_owned_pointer(&mut slot, NEW) };

        assert_eq!(free_log(), (1, OLD, 2));
        assert_eq!(slot, NEW);
    }

    #[test]
    fn null_replacement_deletes_old_value_then_clears_slot() {
        let _lock = mock_heap();
        let mut slot = OLD;

        unsafe { replace_owned_pointer(&mut slot, core::ptr::null_mut()) };

        assert_eq!(free_log(), (1, OLD, 2));
        assert!(slot.is_null());
    }

    #[test]
    fn null_old_value_reaches_delete_guard_before_store() {
        let _lock = mock_heap();
        let mut slot = core::ptr::null_mut();

        unsafe { replace_owned_pointer(&mut slot, NEW) };

        assert_eq!(free_log().0, 0);
        assert_eq!(slot, NEW);
    }
}
