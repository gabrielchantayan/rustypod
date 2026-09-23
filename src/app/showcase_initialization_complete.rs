//! Completes one Showcase cache initialization pass.
//!
//! `showcase_initialization_complete` — original: `FUN_081b6a38` @
//! **0x081b6a38** (**176 bytes**, `0x081b6a38..0x081b6ae8`; the next
//! separately linked function starts at `0x081b6ae8`).
//!
//! Raw ARM has four plain direct `bl` instructions and one predicated `bleq`.
//! The assigned inbound-site count is three plain `bl` calls.
//!
//! # Algorithm
//!
//! Lock the embedded mutex at `+0x18`. States zero and two need no work.
//! Otherwise, require a nonzero word at `+0xf0`; initialize the four resource
//! slots when `+0xe9` is clear, complete pending queues when `+0xec == -1`
//! and `+0xea` is clear, then refresh the selected signed slot when it exists.
//! Stamp state two and unlock on every returning path.
//!
//! # Deliberate deviations
//!
//! The final refresh at `0x081b7824` has no recovered semantic identity.
//! Target builds call that verified address; host tests use a narrow seam.
//! Target-width byte offsets preserve the retail layout on 64-bit hosts.

use crate::heap::veneers::heap_panic;
use crate::kernel::sync_mutex::{mutex_lock, mutex_unlock, Mutex};

const MUTEX_OFFSET: usize = 0x18;
const STATE_OFFSET: usize = 0x20;
const SLOT_INITIALIZED_OFFSET: usize = 0xe9;
const PENDING_QUEUES_COMPLETE_OFFSET: usize = 0xea;
const SELECTED_SLOT_OFFSET: usize = 0xec;
const ACTIVE_WORD_OFFSET: usize = 0xf0;

type ShowcaseRefresh = unsafe extern "C" fn(*mut u8, i32, u32);
#[cfg(target_os = "none")]
unsafe extern "C" {
    #[link_name = "resource_slot_table_initialize"]
    fn retail_resource_slot_table_initialize(showcase: *mut u8);
}


#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn retail_showcase_refresh(showcase: *mut u8, slot: i32, queues_completed: u32) {
    let refresh: ShowcaseRefresh = core::mem::transmute(0x081b_7824usize);
    refresh(showcase, slot, queues_completed);
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn no_op_showcase_refresh(_: *mut u8, _: i32, _: u32) {}

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
pub struct ShowcaseInitializationCompleteOps {
    pub initialize_slots: unsafe extern "C" fn(*mut u8),
    pub complete_pending_queues: unsafe extern "C" fn(*mut u8),
    pub refresh: ShowcaseRefresh,
}

#[cfg(not(target_os = "none"))]
pub const DEFAULT_SHOWCASE_INITIALIZATION_COMPLETE_OPS: ShowcaseInitializationCompleteOps = ShowcaseInitializationCompleteOps {
    initialize_slots: crate::app::resource_slot_table_initialize::resource_slot_table_initialize,
    complete_pending_queues: crate::app::showcase_pending_queues_complete::showcase_pending_queues_complete,
    refresh: no_op_showcase_refresh,
};

#[cfg(not(target_os = "none"))]
pub static mut SHOWCASE_INITIALIZATION_COMPLETE_OPS: ShowcaseInitializationCompleteOps = DEFAULT_SHOWCASE_INITIALIZATION_COMPLETE_OPS;

/// Completes an initialized Showcase cache and transitions it to state two.
///
/// # Safety
///
/// `showcase` must point to writable retail state containing an embedded mutex
/// at `+0x18`, bytes through `+0xec`, and a readable word at `+0xf0`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn showcase_initialization_complete(showcase: *mut u8) {
    let mutex = showcase.add(MUTEX_OFFSET).cast::<Mutex>();
    mutex_lock(mutex);

    let state = showcase.add(STATE_OFFSET).read_volatile();
    if state != 0 && state != 2 {
        let active = showcase.add(ACTIVE_WORD_OFFSET).cast::<u32>().read_volatile();
        if active == 0 {
            if state != 1 {
                heap_panic();
            }
        } else {
            if showcase.add(SLOT_INITIALIZED_OFFSET).read_volatile() == 0 {
                #[cfg(target_os = "none")]
                retail_resource_slot_table_initialize(showcase);
                #[cfg(not(target_os = "none"))]
                (SHOWCASE_INITIALIZATION_COMPLETE_OPS.initialize_slots)(showcase);
            }

            let selected_slot = showcase.add(SELECTED_SLOT_OFFSET).read_volatile() as i8 as i32;
            let mut queues_completed = 0;
            if selected_slot == -1 && showcase.add(PENDING_QUEUES_COMPLETE_OFFSET).read_volatile() == 0 {
                #[cfg(target_os = "none")]
                crate::app::showcase_pending_queues_complete::showcase_pending_queues_complete(showcase);
                #[cfg(not(target_os = "none"))]
                (SHOWCASE_INITIALIZATION_COMPLETE_OPS.complete_pending_queues)(showcase);
                queues_completed = 1;
            }
            if showcase.add(PENDING_QUEUES_COMPLETE_OFFSET).read_volatile() != 0 {
                if selected_slot == -1 {
                    heap_panic();
                }
                #[cfg(target_os = "none")]
                retail_showcase_refresh(showcase, selected_slot, queues_completed);
                #[cfg(not(target_os = "none"))]
                (SHOWCASE_INITIALIZATION_COMPLETE_OPS.refresh)(showcase, selected_slot, queues_completed);
            }
        }
        showcase.add(STATE_OFFSET).write_volatile(2);
    }

    mutex_unlock(mutex);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    extern crate std;
    use core::ptr::{addr_of, addr_of_mut};
    use std::sync::{LazyLock, Mutex};

    const FIXTURE_LEN: usize = 0x1000;
    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static BASE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::SHOWCASE_INITIALIZATION_COMPLETE, FIXTURE_LEN).map(|pointer| pointer as usize)
    });
    static mut INITIALIZE_CALLS: u32 = 0;
    static mut COMPLETE_CALLS: u32 = 0;
    static mut REFRESH: Option<(*mut u8, i32, u32)> = None;

    unsafe extern "C" fn initialize_slots(showcase: *mut u8) {
        INITIALIZE_CALLS += 1;
        showcase.add(SLOT_INITIALIZED_OFFSET).write(1);
    }
    unsafe extern "C" fn complete_queues(showcase: *mut u8) {
        COMPLETE_CALLS += 1;
        showcase.add(PENDING_QUEUES_COMPLETE_OFFSET).write(1);
    }
    unsafe extern "C" fn record_refresh(showcase: *mut u8, slot: i32, completed: u32) {
        REFRESH = Some((showcase, slot, completed));
    }
    struct Restore(ShowcaseInitializationCompleteOps);
    impl Drop for Restore {
        fn drop(&mut self) { unsafe { addr_of_mut!(SHOWCASE_INITIALIZATION_COMPLETE_OPS).write(self.0) }; }
    }
    unsafe fn prepare(showcase: *mut u8) -> Restore {
        showcase.write_bytes(0, FIXTURE_LEN);
        INITIALIZE_CALLS = 0;
        COMPLETE_CALLS = 0;
        REFRESH = None;
        let restore = Restore(addr_of!(SHOWCASE_INITIALIZATION_COMPLETE_OPS).read());
        SHOWCASE_INITIALIZATION_COMPLETE_OPS = ShowcaseInitializationCompleteOps {
            initialize_slots,
            complete_pending_queues: complete_queues,
            refresh: record_refresh,
        };
        restore
    }

    #[test]
    fn zero_and_two_states_only_unlock() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(base) = *BASE else { assert!(note_missing_u32_fixture("app::showcase_initialization_complete")); return; };
        unsafe {
            let showcase = base as *mut u8;
            let _restore = prepare(showcase);
            for state in [0, 2] {
                showcase.add(STATE_OFFSET).write(state);
                showcase_initialization_complete(showcase);
                assert_eq!(showcase.add(STATE_OFFSET).read(), state);
            }
            assert_eq!(INITIALIZE_CALLS, 0);
            assert_eq!(COMPLETE_CALLS, 0);
            assert_eq!(REFRESH, None);
        }
    }
    #[test]
    fn initializes_slots_before_transitioning_to_state_two() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(base) = *BASE else { assert!(note_missing_u32_fixture("app::showcase_initialization_complete")); return; };
        unsafe {
            let showcase = base as *mut u8;
            let _restore = prepare(showcase);
            showcase.add(STATE_OFFSET).write(1);
            showcase.add(ACTIVE_WORD_OFFSET).cast::<u32>().write(1);
            showcase.add(SELECTED_SLOT_OFFSET).write(0);
            showcase_initialization_complete(showcase);
            assert_eq!(INITIALIZE_CALLS, 1);
            assert_eq!(COMPLETE_CALLS, 0);
            assert_eq!(REFRESH, None);
            assert_eq!(showcase.add(STATE_OFFSET).read(), 2);
        }
    }

    #[test]
    fn refreshes_existing_completed_queue_with_signed_slot() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(base) = *BASE else { assert!(note_missing_u32_fixture("app::showcase_initialization_complete")); return; };
        unsafe {
            let showcase = base as *mut u8;
            let _restore = prepare(showcase);
            showcase.add(STATE_OFFSET).write(1);
            showcase.add(ACTIVE_WORD_OFFSET).cast::<u32>().write(1);
            showcase.add(SLOT_INITIALIZED_OFFSET).write(1);
            showcase.add(PENDING_QUEUES_COMPLETE_OFFSET).write(1);
            showcase.add(SELECTED_SLOT_OFFSET).write(0xfe);
            showcase_initialization_complete(showcase);
            assert_eq!(INITIALIZE_CALLS, 0);
            assert_eq!(COMPLETE_CALLS, 0);
            assert_eq!(REFRESH, Some((showcase, -2, 0)));
            assert_eq!(showcase.add(STATE_OFFSET).read(), 2);
        }
    }
}
