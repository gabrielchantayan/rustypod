//! `layout_recompute_notify` — original: `FUN_0826d60c` @ `0x0826d60c`
//! (**64 bytes**, `0x0826d60c..0x0826d648`; `0x0826d64c` starts the distinct
//! next function).
//!
//! Raw `osos.dec` has five direct incoming calls: unconditional `bl` at
//! `0x0818124c`, `0x08181c60`, `0x08182890`, and `0x081dd44c`, plus predicated
//! `blne` at `0x081809b4`. The body has one unconditional direct `bl` to the
//! unported layout recomputation helper `FUN_0826e610`, no predicated direct
//! `bl`, and one unconditional indirect `blx` through vtable slot `+0x68`.
//!
//! Algorithm: if state flag bit `0x20` at `+0x48` is set, copy the four ABI
//! arguments to a stack-local four-word layout result, recompute that result,
//! then invoke the state's vtable layout-notification slot with the state,
//! result, and zero. It returns the original state pointer.
//!
//! Deliberate deviation: `FUN_0826e610` is not ported. Target builds call its
//! verified retailOS address; host tests install a volatile recomputation seam.
//! The vtable layout is widened on 64-bit hosts while retaining the target
//! slot's `+0x68` role.

use core::ptr::addr_of;

#[cfg(test)]
extern crate std;

const RETAIL_LAYOUT_RECOMPUTE: usize = 0x0826_e610;
const LAYOUT_DIRTY: u32 = 0x20;

/// State prefix through the dirty layout flag at target offset `+0x48`.
#[repr(C)]
pub struct LayoutState {
    pub vtable: *const LayoutStateVtable,
    pub words_before_dirty_flag: [u32; 17],
    pub dirty_flags: u32,
}

/// Recovered layout-notification vtable role.
///
/// `notify_layout` is slot `+0x68` on the 32-bit target. Host pointer width
/// widens the model, so the named field represents that slot's role.
#[repr(C)]
pub struct LayoutStateVtable {
    pub slots_before_notify: [u32; 26],
    pub notify_layout: unsafe extern "C" fn(*mut LayoutState, *mut u32, u32),
}

/// ABI of the unported layout recomputation helper at `0x0826e610`.
pub type LayoutRecompute = unsafe extern "C" fn(*mut LayoutState, *mut u32);

/// Host seam for the unported layout recomputation helper.
#[derive(Clone, Copy)]
pub struct LayoutRecomputeNotifyOps {
    pub recompute: LayoutRecompute,
}

#[cfg(target_os = "none")]
unsafe fn retail_layout_recompute(state: *mut LayoutState, result: *mut u32) {
    let recompute: LayoutRecompute = unsafe { core::mem::transmute(RETAIL_LAYOUT_RECOMPUTE) };
    unsafe { recompute(state, result) };
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_layout_recompute(_state: *mut LayoutState, _result: *mut u32) {
    panic!("install layout-recompute host operations before calling this wrapper")
}

#[cfg(not(target_os = "none"))]
pub const DEFAULT_LAYOUT_RECOMPUTE_NOTIFY_OPS: LayoutRecomputeNotifyOps = LayoutRecomputeNotifyOps {
    recompute: missing_layout_recompute,
};

/// Host-side recomputation seam. Target builds always call `0x0826e610`.
#[cfg(not(target_os = "none"))]
pub static mut LAYOUT_RECOMPUTE_NOTIFY_OPS: LayoutRecomputeNotifyOps = DEFAULT_LAYOUT_RECOMPUTE_NOTIFY_OPS;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn host_layout_recompute(state: *mut LayoutState, result: *mut u32) {
    let recompute = unsafe {
        core::ptr::read_volatile(addr_of!(LAYOUT_RECOMPUTE_NOTIFY_OPS.recompute))
    };
    unsafe { recompute(state, result) };
}

/// Recomputes and sends a dirty layout state notification.
///
/// # Safety
///
/// `state` must be valid for the retail state layout. When its dirty bit is
/// set, it must have a readable vtable and a valid layout-notification slot.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn layout_recompute_notify(
    state: *mut LayoutState,
    first: u32,
    second: u32,
    third: u32,
) -> *mut LayoutState {
    let mut result = [state as u32, first, second, third];
    if unsafe { (*state).dirty_flags } & LAYOUT_DIRTY != 0 {
        #[cfg(target_os = "none")]
        unsafe { retail_layout_recompute(state, result.as_mut_ptr()) };
        #[cfg(not(target_os = "none"))]
        unsafe { host_layout_recompute(state, result.as_mut_ptr()) };

        let vtable = unsafe { core::ptr::read_volatile(addr_of!((*state).vtable)) };
        unsafe { ((*vtable).notify_layout)(state, result.as_mut_ptr(), 0) };
    }
    state
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr::{addr_of, addr_of_mut};
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut RECOMPUTE_CALLS: u32 = 0;
    static mut NOTIFY_CALLS: u32 = 0;
    static mut OBSERVED_RESULT: [u32; 4] = [0; 4];
    static mut OBSERVED_RESERVED: u32 = 1;

    unsafe extern "C" fn recompute(_state: *mut LayoutState, result: *mut u32) {
        unsafe {
            RECOMPUTE_CALLS += 1;
            *result.add(0) = 10;
            *result.add(1) = 20;
            *result.add(2) = 30;
            *result.add(3) = 40;
        }
    }

    unsafe extern "C" fn notify(_state: *mut LayoutState, result: *mut u32, reserved: u32) {
        unsafe {
            NOTIFY_CALLS += 1;
            OBSERVED_RESULT = [*result.add(0), *result.add(1), *result.add(2), *result.add(3)];
            OBSERVED_RESERVED = reserved;
        }
    }

    static VTABLE: LayoutStateVtable = LayoutStateVtable {
        slots_before_notify: [0; 26],
        notify_layout: notify,
    };

    fn state(flags: u32) -> LayoutState {
        LayoutState {
            vtable: addr_of!(VTABLE),
            words_before_dirty_flag: [0; 17],
            dirty_flags: flags,
        }
    }

    #[test]
    fn clean_state_returns_without_recompute_or_notification() {
        let _lock = LOCK.lock();
        unsafe {
            LAYOUT_RECOMPUTE_NOTIFY_OPS = DEFAULT_LAYOUT_RECOMPUTE_NOTIFY_OPS;
            RECOMPUTE_CALLS = 0;
            NOTIFY_CALLS = 0;
        }
        let mut layout_state = state(0);
        let returned = unsafe { layout_recompute_notify(addr_of_mut!(layout_state), 1, 2, 3) };
        assert_eq!(returned, addr_of_mut!(layout_state));
        assert_eq!(unsafe { RECOMPUTE_CALLS }, 0);
        assert_eq!(unsafe { NOTIFY_CALLS }, 0);
    }

    #[test]
    fn dirty_state_recomputes_then_notifies_with_zero_reserved_argument() {
        let _lock = LOCK.lock();
        unsafe {
            LAYOUT_RECOMPUTE_NOTIFY_OPS = LayoutRecomputeNotifyOps { recompute };
            RECOMPUTE_CALLS = 0;
            NOTIFY_CALLS = 0;
            OBSERVED_RESULT = [0; 4];
            OBSERVED_RESERVED = 1;
        }
        let mut layout_state = state(LAYOUT_DIRTY);
        let returned = unsafe { layout_recompute_notify(addr_of_mut!(layout_state), 1, 2, 3) };
        assert_eq!(returned, addr_of_mut!(layout_state));
        assert_eq!(unsafe { RECOMPUTE_CALLS }, 1);
        assert_eq!(unsafe { NOTIFY_CALLS }, 1);
        assert_eq!(unsafe { OBSERVED_RESULT }, [10, 20, 30, 40]);
        assert_eq!(unsafe { OBSERVED_RESERVED }, 0);
    }
}
