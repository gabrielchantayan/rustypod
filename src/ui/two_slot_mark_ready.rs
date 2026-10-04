//! Mark a slot ready and advance its two-slot cursor.
//!
//! Original: FUN_0820c584 @ 0x0820c584, true extent 88 bytes through
//! 0x0820c5db (next function starts at 0x0820c5dc). Raw A32 decoding verifies
//! two outgoing plain BLs, zero predicated BLs, and two plain inbound BLs.
//! Read cursor at base + lane*4 + 4 before optional manager dispatch; set
//! byte base + lane*56 + cursor*28 + 8 to 1; store cursor+1, reload it,
//! and reset to zero when the signed result is >= 2.
//!
//! Deviations: reuse the ported ui_manager_instance rather than its IRAM
//! veneer. The unported 0x2200530c remains a target-only retailOS call:
//! raw 0x0800530c adds 16 to the manager and branches to 0x08005eb8.
//! Host notification fails explicitly; behavioral tests inject a local
//! notification operation. Word/byte offsets preserve the 32-bit layout.

use core::ptr;

#[cfg(target_os = "none")]
unsafe fn notify_manager() {
    let manager = crate::ui::manager::ui_manager_instance();
    let dispatch: unsafe extern "C" fn(*mut u8) =
        core::mem::transmute(0x2200_530cusize);
    dispatch(manager);
}

#[cfg(not(target_os = "none"))]
unsafe fn notify_manager() {
    panic!("UI manager dispatch at 0x2200530c requires retailOS");
}

#[inline(always)]
unsafe fn mark_ready_with(base: *mut u32, lane: u32, notify: u32, dispatch: impl FnOnce()) {
    let cursor_word = base.add(lane as usize + 1);
    let cursor = ptr::read_volatile(cursor_word);
    if notify != 0 {
        dispatch();
    }
    let offset = lane.wrapping_mul(56).wrapping_add(cursor.wrapping_mul(28)).wrapping_add(8);
    ptr::write_volatile(base.cast::<u8>().add(offset as usize), 1);
    ptr::write_volatile(cursor_word, cursor.wrapping_add(1));
    if (ptr::read_volatile(cursor_word) as i32) >= 2 {
        ptr::write_volatile(cursor_word, 0);
    }
}

/// # Safety
/// `base` must be aligned and writable at the cursor and selected slot offsets.
/// The saved cursor and lane must select valid storage; manager dispatch may
/// mutate that storage but must not invalidate it.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn two_slot_mark_ready(base: *mut u32, lane: u32, notify: u32) {
    mark_ready_with(base, lane, notify, || notify_manager());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alternates_slots_without_touching_other_bytes() {
        for lane in 0..2u32 {
            for cursor in 0..2u32 {
                let mut words = [0xa5a5_a5a5u32; 32];
                words[lane as usize + 1] = cursor;
                let mut expected = words;
                expected[lane as usize + 1] = if cursor == 0 { 1 } else { 0 };
                let offset = (lane * 56 + cursor * 28 + 8) as usize;
                unsafe {
                    expected.as_mut_ptr().cast::<u8>().add(offset).write(1);
                    two_slot_mark_ready(words.as_mut_ptr(), lane, 0);
                }
                assert_eq!(words, expected);
            }
        }
    }

    #[test]
    fn notification_precedes_writes_and_uses_saved_cursor() {
        for notify in [1, 0x8000_0000, u32::MAX] {
            let mut words = [0u32; 32];
            words[1] = 1;
            let base = words.as_mut_ptr();
            let mut calls = 0;
            unsafe {
                mark_ready_with(base, 0, notify, || {
                    calls += 1;
                    assert_eq!(*base.add(1), 1);
                    assert_eq!(*base.cast::<u8>().add(36), 0);
                    // The original retains r5 across both calls.
                    *base.add(1) = 0;
                });
            }
            assert_eq!(calls, 1);
            assert_eq!(words[1], 0);
            assert_eq!(words[2], 0);
            assert_eq!(words[9], 1);
        }
    }

    #[test]
    fn cursor_above_one_resets_after_marking() {
        let mut words = [0u32; 32];
        words[1] = 2;
        unsafe { two_slot_mark_ready(words.as_mut_ptr(), 0, 0); }
        assert_eq!(words[1], 0);
        assert_eq!(words[16], 1);
    }
}
