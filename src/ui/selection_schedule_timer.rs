//! Schedules the selection controller's debounce timer.
//!
//! `selection_schedule_timer` — original: `FUN_081cc4fc` at load address
//! **0x081cc4fc** (**188 bytes**, `0x081cc4fc..0x081cc5b8`; the next function
//! opens with `push {r4, r5, r6, r7, r8, lr}`). Raw ARM branch-word scanning
//! finds **4 plain `bl` call sites and 0 predicated `bl` call sites**. Its body
//! calls `operator_new`, `timer_schedule_shim`, `timer_is_running`,
//! `timer_stop`, `bit_set_contains`, `bit_set_write`, and
//! `timer_start_after`, then tail-branches to `timer_restart`.
//!
//! # Algorithm
//!
//! A disabled controller (+0x18 == 0) returns. Otherwise it lazily allocates
//! and schedules a 0x2c-byte timer at +0x8e4. An existing timer is sampled
//! before it is stopped. The selected bit at +0x8e8 is written only when it
//! was clear; the delay is 150 for a newly allocated timer, 300 for a stopped
//! existing timer, and 10 for a running existing timer. It then programs and
//! arms the timer.
//!
//! # Deliberate deviations
//!
//! The final stock tail branch is a normal Rust call. All target pointer
//! fields remain 32-bit words, including in host fixtures.


use crate::cxx::bit_set::{bit_set_contains, bit_set_write, BitSet};
use crate::drivers::timer::{
    timer_is_running, timer_restart, timer_schedule_shim, timer_start_after, timer_stop,
};
use crate::heap::veneers::operator_new;

const TIMER_OFFSET: usize = 0x8e4;
const SELECTED_BITS_OFFSET: usize = 0x8e8;
const TIMER_SIZE: usize = 0x2c;

#[inline(always)]
unsafe fn timer(controller: *mut u8) -> *mut u8 {
    unsafe { controller.add(TIMER_OFFSET).cast::<u32>().read_volatile() as usize as *mut u8 }
}

#[inline(always)]
unsafe fn set_timer(controller: *mut u8, value: *mut u8) {
    unsafe { controller.add(TIMER_OFFSET).cast::<u32>().write_volatile(value as u32) };
}

/// Marks `selection_index` selected and re-arms the controller timer.
///
/// # Safety
///
/// `controller` must be writable through +0x8f3. Its embedded [`BitSet`] must
/// represent `selection_index`; a present timer must be valid for the timer
/// helpers. The stock allocation-failure path still invokes the timer shim.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn selection_schedule_timer(controller: *mut u8, selection_index: u32) {
    if unsafe { controller.add(0x18).read_volatile() } == 0 {
        return;
    }

    let was_running;
    if unsafe { timer(controller) }.is_null() {
        let allocated = unsafe { operator_new(TIMER_SIZE) };
        unsafe { set_timer(controller, allocated) };
        unsafe { timer_schedule_shim(controller as u32, allocated, 0, 0) };
        was_running = 0;
    } else {
        was_running = unsafe { timer_is_running(timer(controller)) };
        unsafe { timer_stop(timer(controller)) };
    }

    let selected = unsafe { controller.add(SELECTED_BITS_OFFSET).cast::<BitSet>() };
    let delay = if unsafe { bit_set_contains(selected, selection_index) } == 0 {
        unsafe { bit_set_write(selected, selection_index, 1) };
        150
    } else if was_running == 0 {
        300
    } else {
        10
    };

    unsafe { timer_start_after(timer(controller), delay) };
    unsafe { timer_restart(timer(controller)) };
}

#[cfg(test)]
mod tests {
    extern crate std;

    use core::ptr::{addr_of, addr_of_mut};
    use super::*;
    use crate::drivers::timer::{TimerOps, TIMER_OPS, TIMER_STATE_RUNNING, TIMER_STATE_STOPPED};
    use crate::heap::veneers::tests::{alloc_log, mock_heap, set_alloc_ret};
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab, TIMER_OPS_TEST_LOCK};
    use std::sync::LazyLock;

    const SLAB_LEN: usize = 0x2000;
    const TIMER_A_OFFSET: usize = 0x1000;
    const WORDS_OFFSET: usize = 0x1100;

    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::SELECTION_SCHEDULE_TIMER, SLAB_LEN).map(|p| p as usize)
    });

    unsafe extern "C" fn noop_timer(_timer: *mut u8) {}
    unsafe extern "C" fn noop_construct(_timer: *mut u8, _init: u32, _config: u32, _callback: usize) {}

    struct TimerOpsRestore(TimerOps);
    impl Drop for TimerOpsRestore {
        fn drop(&mut self) {
            unsafe { addr_of_mut!(TIMER_OPS).write_volatile(self.0) };
        }
    }

    unsafe fn install_timer_ops() -> TimerOpsRestore {
        let original = unsafe { addr_of!(TIMER_OPS).read_volatile() };
        let mut ops = original;
        ops.trace_assert = noop_timer;
        ops.arm_timer = noop_timer;
        ops.construct_timer = noop_construct;
        unsafe { addr_of_mut!(TIMER_OPS).write_volatile(ops) };
        TimerOpsRestore(original)
    }

    unsafe fn reset(base: *mut u8, selected_bit: u32, timer_state: Option<u32>) {
        unsafe { base.write_bytes(0, SLAB_LEN) };
        unsafe { base.add(0x18).write_volatile(1) };
        let words = unsafe { base.add(WORDS_OFFSET).cast::<u32>() };
        unsafe { words.write_volatile(1 << selected_bit) };
        unsafe {
            base.add(SELECTED_BITS_OFFSET).cast::<BitSet>().write(BitSet {
                bit_capacity: 64,
                cardinality: 1,
                words: words as u32,
                heap_tag: 0,
                reserved: [0; 3],
            })
        };
        if let Some(state) = timer_state {
            let timer = unsafe { base.add(TIMER_A_OFFSET) };
            unsafe { timer.add(0x20).cast::<u32>().write_volatile(state) };
            unsafe { set_timer(base, timer) };
        }
    }

    #[test]
    fn disabled_controller_does_not_allocate_or_mutate_selection() {
        let _timer_lock = TIMER_OPS_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _heap_lock = mock_heap();
        let Some(base) = *SLAB else { assert!(note_missing_u32_fixture("ui::selection_schedule_timer")); return };
        unsafe { (base as *mut u8).write_bytes(0, SLAB_LEN) };
        unsafe { selection_schedule_timer(base as *mut u8, 7) };
        assert_eq!(alloc_log().0, 0);
    }

    #[test]
    fn newly_allocated_timer_marks_missing_selection_and_uses_150ms() {
        let _timer_lock = TIMER_OPS_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _heap_lock = mock_heap();
        let Some(base) = *SLAB else { assert!(note_missing_u32_fixture("ui::selection_schedule_timer")); return };
        unsafe {
            reset(base as *mut u8, 0, None);
            set_alloc_ret((base as *mut u8).add(TIMER_A_OFFSET));
            let _restore = install_timer_ops();
            selection_schedule_timer(base as *mut u8, 33);
            assert_eq!(alloc_log(), (1, TIMER_SIZE, 2));
            assert_eq!((base as *mut u8).add(SELECTED_BITS_OFFSET + 4).cast::<u32>().read(), 2);
            assert_eq!((base as *mut u8).add(WORDS_OFFSET + 4).cast::<u32>().read(), 2);
            assert_eq!((base as *mut u8).add(TIMER_A_OFFSET + 4).cast::<u32>().read(), 150);
        }
    }

    #[test]
    fn existing_timer_delay_distinguishes_stopped_and_running_selection() {
        let _timer_lock = TIMER_OPS_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _heap_lock = mock_heap();
        let Some(base) = *SLAB else { assert!(note_missing_u32_fixture("ui::selection_schedule_timer")); return };
        unsafe {
            let _restore = install_timer_ops();
            reset(base as *mut u8, 4, Some(TIMER_STATE_STOPPED));
            selection_schedule_timer(base as *mut u8, 4);
            assert_eq!((base as *mut u8).add(TIMER_A_OFFSET + 4).cast::<u32>().read(), 300);
            reset(base as *mut u8, 4, Some(TIMER_STATE_RUNNING));
            selection_schedule_timer(base as *mut u8, 4);
            assert_eq!((base as *mut u8).add(TIMER_A_OFFSET + 4).cast::<u32>().read(), 10);
        }
    }
}
