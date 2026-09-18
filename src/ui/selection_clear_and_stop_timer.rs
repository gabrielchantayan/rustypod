//! Clears a UI controller's selected-item bit and stops its timer when empty.
//!
//! `selection_clear_and_stop_timer_when_empty` — original: `FUN_081cc690` at
//! load address **0x081cc690** (**52 bytes**, `0x081cc690..0x081cc6c4`; the
//! next separately linked function starts with `push {r4, r5, r6, lr}` at
//! `0x081cc6c4`, with no literal pool). Decoding the raw ARM words finds **4
//! plain `bl` call sites, 0 predicated `bl` call sites**. Its own body has one
//! unconditional `bl` to `bit_set_clear` @ 0x08274774 and a predicated tail
//! `bne` to `timer_stop` @ 0x0812c6b0.
//!
//! It clears `selection_index` from the embedded BitSet at controller +0x8e8.
//! If the resulting BitSet cardinality (+0x8ec) is nonzero it returns;
//! otherwise a nonzero timer pointer at +0x8e4 is passed to `timer_stop`.
//! Deliberate deviation: the predicated tail branch is represented as a normal
//! direct call; callers cannot observe the stock return-position branch.

use crate::cxx::bit_set::{bit_set_clear, BitSet};
use crate::drivers::timer::timer_stop;
#[cfg(test)]
use crate::drivers::timer::{TIMER_STATE_RUNNING, TIMER_STATE_STOPPED};

const TIMER_OFFSET: usize = 0x8e4;
const SELECTED_BITS_OFFSET: usize = 0x8e8;

/// Clears an item's selection bit and stops the controller timer when the
/// selected-item set becomes empty.
///
/// # Safety
///
/// `controller` must point to writable storage through +0x8ef. Its embedded
/// [`BitSet`] must contain `selection_index`; a nonzero timer word must be a
/// valid timer object for [`timer_stop`]. The stock body has no NULL guard.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn selection_clear_and_stop_timer_when_empty(
    controller: *mut u8,
    selection_index: u32,
) {
    bit_set_clear(controller.add(SELECTED_BITS_OFFSET).cast::<BitSet>(), selection_index);

    if controller.add(SELECTED_BITS_OFFSET + 4).cast::<u32>().read_volatile() != 0 {
        return;
    }
    let timer = controller.add(TIMER_OFFSET).cast::<u32>().read_volatile() as usize as *mut u8;
    if !timer.is_null() {
        timer_stop(timer);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use std::sync::{LazyLock, Mutex};

    const SLAB_BYTES: usize = 0x2000;
    const WORDS_OFFSET: usize = 0x1000;
    const TIMER_STATE: usize = 0x20;
    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static TEST_SLAB: LazyLock<usize> = LazyLock::new(|| {
        crate::testing::try_map_u32_slab(
            crate::testing::hints::SELECTION_CLEAR_AND_STOP_TIMER,
            SLAB_BYTES,
        )
        .map(|slab| slab as usize)
        .unwrap_or(0)
    });

    unsafe fn controller_with_selected_bit(selection_index: u32) -> Option<*mut u8> {
        let slab = *TEST_SLAB;
        if slab == 0 {
            return None;
        }
        let controller = slab as *mut u8;
        controller.write_bytes(0, SLAB_BYTES);
        let words = controller.add(WORDS_OFFSET).cast::<u32>();
        words.add((selection_index >> 5) as usize).write(1 << (selection_index & 31));
        controller.add(SELECTED_BITS_OFFSET).cast::<BitSet>().write(BitSet {
            bit_capacity: 64,
            cardinality: 1,
            words: words as usize as u32,
            heap_tag: 0,
            reserved: [0; 3],
        });
        Some(controller)
    }

    #[test]
    fn clears_selection_and_stops_an_unblocked_timer() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let Some(controller) = (unsafe { controller_with_selected_bit(33) }) else {
            assert!(crate::testing::note_missing_u32_fixture("ui/selection_clear_and_stop_timer"));
            return;
        };
        unsafe {
            controller.add(TIMER_OFFSET).cast::<u32>().write_volatile(controller as u32);
            controller.add(TIMER_STATE).cast::<u32>().write_volatile(TIMER_STATE_RUNNING);
            selection_clear_and_stop_timer_when_empty(controller, 33);
            assert_eq!(controller.add(SELECTED_BITS_OFFSET + 4).cast::<u32>().read(), 0);
            assert_eq!(controller.add(WORDS_OFFSET + 4).cast::<u32>().read(), 0);
            assert_eq!(controller.add(TIMER_STATE).cast::<u32>().read_volatile(), TIMER_STATE_STOPPED);
        }
    }

    #[test]
    fn remaining_selection_preserves_timer_state() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let Some(controller) = (unsafe { controller_with_selected_bit(1) }) else {
            assert!(crate::testing::note_missing_u32_fixture("ui/selection_clear_and_stop_timer"));
            return;
        };
        unsafe {
            controller.add(TIMER_OFFSET).cast::<u32>().write_volatile(controller as u32);
            controller.add(WORDS_OFFSET).cast::<u32>().write(1 << 2);
            controller.add(TIMER_STATE).cast::<u32>().write_volatile(TIMER_STATE_RUNNING);
            controller.add(SELECTED_BITS_OFFSET + 4).cast::<u32>().write_volatile(2);
            selection_clear_and_stop_timer_when_empty(controller, 1);
            assert_eq!(controller.add(WORDS_OFFSET).cast::<u32>().read(), 1 << 2);
            assert_eq!(controller.add(TIMER_STATE).cast::<u32>().read_volatile(), TIMER_STATE_RUNNING);
        }
    }

    #[test]
    fn null_timer_after_clear_is_a_noop() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let Some(controller) = (unsafe { controller_with_selected_bit(0) }) else {
            assert!(crate::testing::note_missing_u32_fixture("ui/selection_clear_and_stop_timer"));
            return;
        };
        unsafe {
            selection_clear_and_stop_timer_when_empty(controller, 0);
            assert_eq!(controller.add(WORDS_OFFSET).cast::<u32>().read(), 0);
        }
    }
}
