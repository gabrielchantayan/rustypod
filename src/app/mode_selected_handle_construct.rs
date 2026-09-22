//! `mode_selected_handle_construct` — original: `FUN_0822afec` @ **0x0822afec**.
//!
//! **36 bytes**, `0x0822afec..0x0822b010`: the next separately entered
//! function begins at 0x0822b020. Raw ARM decoding finds **zero `bl`**
//! instructions, plain or predicated. After checking readiness at +0x14 and
//! flag bit 0 at +0x24, the body writes an empty target-width handle when not
//! ready. Otherwise it selects the handoff at +0x330 or +0x38 from flag bit 0
//! at +0x5f8 and tail-branches to one of two byte-identical out-of-line
//! sequences at 0x08208444/0x08214acc. Each sequence locks the selected mutex,
//! invokes the unported 0x081fcb5c handle builder, then tail-branches to
//! `mutex_handoff_unlock`. Deliberate deviation: Rust shares those duplicate
//! tail sequences and calls the established mutex ports directly.

use crate::cxx::handle::RefcountedBody;
use crate::kernel::mutex_handoff::{mutex_handoff_lock, mutex_handoff_unlock, MutexHandoff};

/// ABI of the still-unidentified retail handle builder at 0x081fcb5c.
pub type LockedHandleBuild = unsafe extern "C" fn(*mut *mut RefcountedBody, *mut MutexHandoff, *mut u8, *mut u8);

#[cfg(target_arch = "arm")]
#[inline(always)]
unsafe fn locked_handle_build() -> LockedHandleBuild {
    core::mem::transmute(0x081f_cb5cu32 as usize)
}

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_locked_handle_build(slot: *mut *mut RefcountedBody, _handoff: *mut MutexHandoff, _arg2: *mut u8, _arg3: *mut u8) {
    slot.write(core::ptr::null_mut());
}

#[cfg(not(target_arch = "arm"))]
static mut LOCKED_HANDLE_BUILD: LockedHandleBuild = missing_locked_handle_build;

#[cfg(not(target_arch = "arm"))]
#[inline(always)]
unsafe fn locked_handle_build() -> LockedHandleBuild {
    core::ptr::addr_of!(LOCKED_HANDLE_BUILD).read_volatile()
}

/// Constructs the handle selected by `state` while its current mutex is held.
///
/// # Safety
/// `state` must designate the retail state layout, including a valid
/// [`MutexHandoff`] at the mode-selected offset. `slot` and the two forwarded
/// arguments must satisfy the unported handle builder's contract.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn mode_selected_handle_construct(
    slot: *mut *mut RefcountedBody,
    state: *mut u8,
    arg2: *mut u8,
    arg3: *mut u8,
) {
    if state.add(0x14).cast::<u32>().read() == 0 || state.add(0x24).read() & 1 == 0 {
        slot.write(core::ptr::null_mut());
        return;
    }

    let handoff_offset = if state.add(0x5f8).read() & 1 == 0 { 0x330 } else { 0x38 };
    let handoff = state.add(handoff_offset).cast::<MutexHandoff>();
    mutex_handoff_lock(handoff);
    locked_handle_build()(slot, handoff, arg2, arg3);
    mutex_handoff_unlock(handoff);
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};

    static BUILD_CALLS: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn record_build(_slot: *mut *mut RefcountedBody, _handoff: *mut MutexHandoff, _arg2: *mut u8, _arg3: *mut u8) {
        BUILD_CALLS.fetch_add(1, Ordering::SeqCst);
    }

    #[test]
    fn not_ready_or_unselected_clears_slot_without_building() {
        let saved = unsafe { core::ptr::addr_of!(LOCKED_HANDLE_BUILD).read_volatile() };
        unsafe { core::ptr::addr_of_mut!(LOCKED_HANDLE_BUILD).write_volatile(record_build) };
        let mut state = [0u64; 0xc0];
        let state = state.as_mut_ptr().cast::<u8>();
        let mut slot = 0x44usize as *mut RefcountedBody;
        unsafe {
            state.add(0x14).cast::<u32>().write(0);
            state.add(0x24).write(1);
            mode_selected_handle_construct(&mut slot, state, core::ptr::null_mut(), core::ptr::null_mut());
            assert!(slot.is_null());
            state.add(0x14).cast::<u32>().write(1);
            state.add(0x24).write(0);
            slot = 0x44usize as *mut RefcountedBody;
            mode_selected_handle_construct(&mut slot, state, core::ptr::null_mut(), core::ptr::null_mut());
            assert!(slot.is_null());
        }
        assert_eq!(BUILD_CALLS.load(Ordering::SeqCst), 0);
        unsafe { core::ptr::addr_of_mut!(LOCKED_HANDLE_BUILD).write_volatile(saved) };
    }
}
