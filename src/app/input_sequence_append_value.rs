//! Append an input value — FUN_08129a0c @ 0x08129a0c.
//!
//! Raw A32 extent [0x08129a0c, 0x08129a78): 108 bytes, ending POP;
//! the next entry starts PUSH. Three outgoing plain BLs, zero predicated BLs.
//! Whole-image decoding finds inbound BLNE at 0x08129700 and BL at 0x08129768.
//! Zero value does nothing. Otherwise a dirty window copies its initial index
//! to +0xb8, resets +0xb4, and dispatches event 0x2d. Reload the selected item
//! and action index after dispatch, queue the value with three zero metadata
//! words if selected, then advance +0xb4 with the canonical saturating helper.
//! Deviations: none. Ghidra's phantom r2/r3 arguments are not consumed by the
//! real dispatcher. The unported action insertion remains a direct-address
//! target seam; hosts panic rather than fabricate insertion behavior.

use crate::app::input_action_index::input_action_index_advance;
use crate::app::input_sequence_dispatch::input_sequence_dispatch;

// Raw 0x0812881c saves r0..r3 and loads the two stack arguments with LDRD.
// It sets the item's action bit, timestamps it, then updates or inserts a
// sorted action record. Its return registers are restored, not a result.
unsafe fn insert_action(item: *mut u8, index: u32, value: u32) {
    #[cfg(target_os = "none")]
    {
        let insert: unsafe extern "C" fn(*mut u8, u32, u32, u32, u32, u32) =
            core::mem::transmute(0x0812881cusize);
        insert(item, index, value, 0, 0, 0);
    }
    #[cfg(not(target_os = "none"))]
    { let _ = (item, index, value); panic!("unported input_sequence_item_insert_action @ 0x0812881c"); }
}

/// # Safety
/// For nonzero `value`, `state` is aligned and writable through +0xd8.
/// Its selected item and collections must satisfy the retail insertion and
/// event-0x2d dispatcher requirements. Zero accepts even a null state.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn input_sequence_append_value(state: *mut u8, value: u32) {
    if value == 0 { return; }
    let words = state.cast::<u32>();
    if state.add(0xd8).read() != 0 {
        words.add(46).write(words.add(53).read());
        words.add(45).write(0);
        input_sequence_dispatch(state, 0x2d);
    }
    let item = words.add(44).read();
    if item != 0 {
        insert_action(item as usize as *mut u8, words.add(45).read() & 255, value);
    }
    input_action_index_advance(state);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_value_never_touches_state() {
        unsafe { input_sequence_append_value(core::ptr::null_mut(), 0); }
        let mut state = [u32::MAX; 55];
        let before = state;
        unsafe { input_sequence_append_value(state.as_mut_ptr().cast(), 0); }
        assert_eq!(state, before);
    }

    #[test]
    fn absent_selection_advances_and_saturates_without_changing_other_fields() {
        for index in [0, 1, 30, 31, 32, u32::MAX] {
            for value in [1, 0xffff, 0x10000, u32::MAX] {
                let mut state = [0u32; 55];
                state[45] = index;
                state[46] = 0x12345678;
                state[53] = 0xabcdef01;
                let mut expected = state;
                expected[45] = if index < 31 { index + 1 } else { index };
                unsafe { input_sequence_append_value(state.as_mut_ptr().cast(), value); }
                assert_eq!(state, expected);
            }
        }
    }

    #[test]
    fn dirty_window_resets_before_advancing_even_when_dispatch_mode_is_inactive() {
        for mode in [0u8, 1, 5, 255] {
            for dirty in [1u8, 255] {
                let mut state = [0u32; 55];
                state[45] = u32::MAX;
                state[46] = 7;
                state[53] = 0xfedcba98;
                unsafe {
                    let p = state.as_mut_ptr().cast::<u8>();
                    p.add(0xa1).write(mode);
                    p.add(0xd8).write(dirty);
                }
                let mut expected = state;
                expected[45] = 1;
                expected[46] = expected[53];
                unsafe { input_sequence_append_value(state.as_mut_ptr().cast(), 42); }
                assert_eq!(state, expected);
            }
        }
    }
}
