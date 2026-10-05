//! Mode-selected I/O task accessor — `FUN_08197618` @ **0x08197618**.
//!
//! True size: 88 bytes: 84 instruction bytes and the state-pointer literal;
//! the next real function starts at 0x08197670. Raw A32 words contain two
//! plain BLs, zero predicated BLs, two BLX-register calls and two predicated
//! tail branches. Two inbound plain BLs were independently found in the image.
//! Set the initialization byte before obtaining and invoking vtable slot zero
//! on each task, primary first. Read the mode only after both callbacks; zero
//! selects the primary task and any nonzero byte selects the alternate task.
//!
//! Deviations: reuse the ported Mecca accessor; retain the unported alternate
//! accessor via a firmware boundary. The relocator's 0xaed8-byte slide maps
//! its file address 0x081e6724 to runtime 0x081db84c. Host builds substitute
//! state and accessor seams; repr(C) pointers preserve native vtable layout.

use core::ptr;

#[repr(C)]
pub struct IoTask {
    pub vtable: *const IoTaskVtable,
}

#[repr(C)]
pub struct IoTaskVtable {
    pub initialize: unsafe extern "C" fn(*mut IoTask),
}

#[repr(C)]
struct SelectionState {
    initialized: u8,
    mode: u8,
}

type TaskGetter = unsafe extern "C" fn() -> *mut IoTask;

#[cfg(target_os = "none")]
unsafe fn primary_task() -> *mut IoTask {
    crate::app::mecca_io_task::mecca_io_task_get().cast()
}

#[cfg(target_os = "none")]
unsafe fn alternate_task() -> *mut IoTask {
    let get: TaskGetter = core::mem::transmute(0x081d_b84cusize);
    get()
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_task() -> *mut IoTask {
    panic!("selected_io_task_get requires retailOS task accessors")
}
#[cfg(not(target_os = "none"))]
static mut HOST_STATE: SelectionState = SelectionState { initialized: 0, mode: 0 };
#[cfg(not(target_os = "none"))]
pub static mut PRIMARY_TASK_GETTER: TaskGetter = missing_task;
#[cfg(not(target_os = "none"))]
pub static mut ALTERNATE_TASK_GETTER: TaskGetter = missing_task;

#[cfg(not(target_os = "none"))]
unsafe fn primary_task() -> *mut IoTask {
    ptr::read_volatile(ptr::addr_of!(PRIMARY_TASK_GETTER))()
}
#[cfg(not(target_os = "none"))]
unsafe fn alternate_task() -> *mut IoTask {
    ptr::read_volatile(ptr::addr_of!(ALTERNATE_TASK_GETTER))()
}

/// Initialize both task interfaces once, then obtain the currently selected one.
///
/// # Safety
/// Requires valid firmware state and non-null task objects with slot-zero
/// callbacks. Calls must obey retailOS serialization; host users must install
/// accessor seams and serialize access to their state.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn selected_io_task_get() -> *mut IoTask {
    #[cfg(target_os = "none")]
    let state = 0x089c_fd28usize as *mut SelectionState;
    #[cfg(not(target_os = "none"))]
    let state = ptr::addr_of_mut!(HOST_STATE);
    if ptr::read_volatile(ptr::addr_of!((*state).initialized)) == 0 {
        ptr::write_volatile(ptr::addr_of_mut!((*state).initialized), 1);
        let primary = primary_task();
        ((*(*primary).vtable).initialize)(primary);
        let alternate = alternate_task();
        ((*(*alternate).vtable).initialize)(alternate);
    }
    if ptr::read_volatile(ptr::addr_of!((*state).mode)) == 0 {
        primary_task()
    } else {
        alternate_task()
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::sync::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut EVENTS: std::vec::Vec<u8> = std::vec::Vec::new();
    static mut CHANGE_MODE: bool = false;
    static mut REENTER: bool = false;
    static PRIMARY_VTABLE: IoTaskVtable = IoTaskVtable { initialize: initialize_primary };
    static ALTERNATE_VTABLE: IoTaskVtable = IoTaskVtable { initialize: initialize_alternate };
    static mut PRIMARY: IoTask = IoTask { vtable: &PRIMARY_VTABLE };
    static mut ALTERNATE: IoTask = IoTask { vtable: &ALTERNATE_VTABLE };

    unsafe extern "C" fn get_primary() -> *mut IoTask {
        (*ptr::addr_of_mut!(EVENTS)).push(1);
        ptr::addr_of_mut!(PRIMARY)
    }
    unsafe extern "C" fn get_alternate() -> *mut IoTask {
        (*ptr::addr_of_mut!(EVENTS)).push(3);
        ptr::addr_of_mut!(ALTERNATE)
    }
    unsafe extern "C" fn initialize_primary(task: *mut IoTask) {
        assert_eq!(task, ptr::addr_of_mut!(PRIMARY));
        assert_eq!((*ptr::addr_of!(HOST_STATE)).initialized, 1);
        (*ptr::addr_of_mut!(EVENTS)).push(2);
        if REENTER {
            assert_eq!(selected_io_task_get(), ptr::addr_of_mut!(PRIMARY));
        }
    }
    unsafe extern "C" fn initialize_alternate(task: *mut IoTask) {
        assert_eq!(task, ptr::addr_of_mut!(ALTERNATE));
        (*ptr::addr_of_mut!(EVENTS)).push(4);
        if CHANGE_MODE { (*ptr::addr_of_mut!(HOST_STATE)).mode = 255; }
    }

    #[test]
    fn initializes_both_once_and_observes_callback_mode_changes() {
        let _lock = LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            PRIMARY_TASK_GETTER = get_primary;
            ALTERNATE_TASK_GETTER = get_alternate;
            HOST_STATE = SelectionState { initialized: 0, mode: 0 };
            CHANGE_MODE = true;
            REENTER = true;
            (*ptr::addr_of_mut!(EVENTS)).clear();
            assert_eq!(selected_io_task_get(), ptr::addr_of_mut!(ALTERNATE));
            assert_eq!((*ptr::addr_of!(EVENTS)).as_slice(), &[1, 2, 1, 3, 4, 3]);
            (*ptr::addr_of_mut!(EVENTS)).clear();
            assert_eq!(selected_io_task_get(), ptr::addr_of_mut!(ALTERNATE));
            HOST_STATE.mode = 0;
            assert_eq!(selected_io_task_get(), ptr::addr_of_mut!(PRIMARY));
            assert_eq!((*ptr::addr_of!(EVENTS)).as_slice(), &[3, 1]);
            PRIMARY_TASK_GETTER = missing_task;
            ALTERNATE_TASK_GETTER = missing_task;
        }
    }

    #[test]
    fn all_nonzero_flags_skip_initialization_and_all_nonzero_modes_select_alternate() {
        let _lock = LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            PRIMARY_TASK_GETTER = get_primary;
            ALTERNATE_TASK_GETTER = get_alternate;
            for flag in [1, 2, 128, 255] {
                for mode in [0, 1, 2, 128, 255] {
                    HOST_STATE = SelectionState { initialized: flag, mode };
                    (*ptr::addr_of_mut!(EVENTS)).clear();
                    let expected = if mode == 0 { ptr::addr_of_mut!(PRIMARY) } else { ptr::addr_of_mut!(ALTERNATE) };
                    assert_eq!(selected_io_task_get(), expected);
                    assert_eq!(HOST_STATE.initialized, flag);
                    assert_eq!((*ptr::addr_of!(EVENTS)).as_slice(), if mode == 0 { &[1] } else { &[3] });
                }
            }
            PRIMARY_TASK_GETTER = missing_task;
            ALTERNATE_TASK_GETTER = missing_task;
        }
    }
}
