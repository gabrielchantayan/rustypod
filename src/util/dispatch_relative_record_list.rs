//! `dispatch_relative_record_list` — original: `FUN_081579a4` @ **0x081579a4**
//! (**124 bytes**, `0x081579a4..0x08157a20`; the next independently linked
//! function starts at `0x08157a20`).
//!
//! Whole-image ARM decoding finds **3 inbound plain `bl` call sites** and no
//! predicated `bl` forms. The body has three unconditional direct `bl` calls:
//! get the framework task target once, restore it before each record dispatch,
//! and dispatch the record. Algorithm: use `owner + 0x38` when `target` is
//! null, then walk `records`' signed-16-bit count of relative records. Each
//! record's first word advances to the next record and its payload begins four
//! bytes later. Deliberate deviations: the stock calls remain address-bound on
//! target builds because only the task-target helpers are identified; host
//! builds expose an operation seam for behavioral tests.

const OWNER_DEFAULT_TARGET_OFFSET: usize = 0x38;

type CurrentTaskGet = unsafe extern "C" fn() -> *mut u8;
type CurrentTaskSet = unsafe extern "C" fn(*mut u8);
type RecordDispatch = unsafe extern "C" fn(*mut u8, *mut u8, *mut u8, *mut u8, u32);

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn retail_current_task_get() -> *mut u8 {
    unsafe { core::mem::transmute::<usize, CurrentTaskGet>(0x0811_0c44)() }
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn retail_current_task_set(task: *mut u8) {
    unsafe { core::mem::transmute::<usize, CurrentTaskSet>(0x0811_0ca8)(task) }
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn retail_record_dispatch(target: *mut u8, owner: *mut u8, record: *mut u8, callback: *mut u8) {
    unsafe { core::mem::transmute::<usize, RecordDispatch>(0x0826_e4f0)(target, owner, record, callback, 0) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_current_task_get() -> *mut u8 {
    panic!("dispatch_relative_record_list requires a current-task getter fixture")
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_current_task_set(_: *mut u8) {
    panic!("dispatch_relative_record_list requires a current-task setter fixture")
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_record_dispatch(_: *mut u8, _: *mut u8, _: *mut u8, _: *mut u8, _: u32) {
    panic!("dispatch_relative_record_list requires a record-dispatch fixture")
}

/// Host replacements for the three address-bound retail calls.
#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
pub struct DispatchRelativeRecordListOps {
    pub current_task_get: CurrentTaskGet,
    pub current_task_set: CurrentTaskSet,
    pub record_dispatch: RecordDispatch,
}

#[cfg(not(target_os = "none"))]
pub const DEFAULT_DISPATCH_RELATIVE_RECORD_LIST_OPS: DispatchRelativeRecordListOps = DispatchRelativeRecordListOps {
    current_task_get: missing_current_task_get,
    current_task_set: missing_current_task_set,
    record_dispatch: missing_record_dispatch,
};

#[cfg(not(target_os = "none"))]
pub static mut DISPATCH_RELATIVE_RECORD_LIST_OPS: DispatchRelativeRecordListOps = DEFAULT_DISPATCH_RELATIVE_RECORD_LIST_OPS;

/// Dispatches each relative record while preserving the framework task target.
///
/// # Safety
///
/// `owner` must contain an aligned target word at `+0x38`; `records` must
/// describe at least its signed-16-bit count of relative records.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn dispatch_relative_record_list(
    owner: *mut u8,
    records: *mut u8,
    mut target: *mut u8,
    callback: *mut u8,
) {
    let saved_task = {
        #[cfg(target_os = "none")]
        { unsafe { retail_current_task_get() } }
        #[cfg(not(target_os = "none"))]
        { unsafe { (DISPATCH_RELATIVE_RECORD_LIST_OPS.current_task_get)() } }
    };
    if target.is_null() {
        target = unsafe { (owner.add(OWNER_DEFAULT_TARGET_OFFSET) as *const u32).read_volatile() as usize as *mut u8 };
    }

    let count = unsafe { (records as *const i32).read_volatile() };
    let mut index = 0i16;
    let mut record = unsafe { records.add(4) };
    while (index as i32) < count {
        #[cfg(target_os = "none")]
        unsafe {
            retail_current_task_set(saved_task);
            retail_record_dispatch(target, owner, record.add(4), callback);
        }
        #[cfg(not(target_os = "none"))]
        unsafe {
            let ops = DISPATCH_RELATIVE_RECORD_LIST_OPS;
            (ops.current_task_set)(saved_task);
            (ops.record_dispatch)(target, owner, record.add(4), callback, 0);
        }
        let next_offset = unsafe { (record as *const i32).read_volatile() };
        record = unsafe { record.offset(next_offset as isize).add(4) };
        index = index.wrapping_add(1);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr;
    use std::sync::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut GET_CALLS: usize = 0;
    static mut SET_TASKS: [usize; 4] = [0; 4];
    static mut DISPATCHES: [(usize, usize, usize, usize, u32); 4] = [(0, 0, 0, 0, 0); 4];
    static mut DISPATCH_COUNT: usize = 0;

    unsafe extern "C" fn get_task() -> *mut u8 { unsafe { GET_CALLS += 1; 0x1234_5000 as *mut u8 } }
    unsafe extern "C" fn set_task(task: *mut u8) { unsafe { SET_TASKS[DISPATCH_COUNT] = task as usize; } }
    unsafe extern "C" fn dispatch(target: *mut u8, owner: *mut u8, record: *mut u8, callback: *mut u8, flags: u32) {
        unsafe { DISPATCHES[DISPATCH_COUNT] = (target as usize, owner as usize, record as usize, callback as usize, flags); DISPATCH_COUNT += 1; }
    }

    fn ops() -> DispatchRelativeRecordListOps {
        DispatchRelativeRecordListOps { current_task_get: get_task, current_task_set: set_task, record_dispatch: dispatch }
    }

    #[test]
    fn dispatches_relative_records_in_order_and_restores_task() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            DISPATCH_RELATIVE_RECORD_LIST_OPS = ops();
            GET_CALLS = 0; DISPATCH_COUNT = 0; SET_TASKS = [0; 4]; DISPATCHES = [(0, 0, 0, 0, 0); 4];
            let mut owner = [0u8; 0x3c];
            let mut records = [0u8; 36];
            (records.as_mut_ptr() as *mut i32).write(2);
            (records.as_mut_ptr().add(4) as *mut i32).write(12);
            (records.as_mut_ptr().add(20) as *mut i32).write(0);
            dispatch_relative_record_list(owner.as_mut_ptr(), records.as_mut_ptr(), 0x2000_0000 as *mut u8, 0x3000_0000 as *mut u8);
            assert_eq!(GET_CALLS, 1);
            assert_eq!(DISPATCH_COUNT, 2);
            assert_eq!(SET_TASKS[..2], [0x1234_5000; 2]);
            assert_eq!(DISPATCHES[0], (0x2000_0000, owner.as_mut_ptr() as usize, records.as_mut_ptr().add(8) as usize, 0x3000_0000, 0));
            assert_eq!(DISPATCHES[1], (0x2000_0000, owner.as_mut_ptr() as usize, records.as_mut_ptr().add(24) as usize, 0x3000_0000, 0));
            DISPATCH_RELATIVE_RECORD_LIST_OPS = DEFAULT_DISPATCH_RELATIVE_RECORD_LIST_OPS;
        }
    }

    #[test]
    fn null_target_uses_owner_default_and_nonpositive_counts_do_not_dispatch() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            DISPATCH_RELATIVE_RECORD_LIST_OPS = ops();
            GET_CALLS = 0; DISPATCH_COUNT = 0;
            let mut owner = [0u8; 0x3c];
            (owner.as_mut_ptr().add(OWNER_DEFAULT_TARGET_OFFSET) as *mut u32).write(0x4567_8000);
            let mut records = [0u8; 16];
            (records.as_mut_ptr() as *mut i32).write(1);
            (records.as_mut_ptr().add(4) as *mut i32).write(0);
            dispatch_relative_record_list(owner.as_mut_ptr(), records.as_mut_ptr(), ptr::null_mut(), ptr::null_mut());
            assert_eq!(GET_CALLS, 1);
            assert_eq!(DISPATCH_COUNT, 1);
            assert_eq!(DISPATCHES[0].0, 0x4567_8000);
            (records.as_mut_ptr() as *mut i32).write(-1);
            dispatch_relative_record_list(owner.as_mut_ptr(), records.as_mut_ptr(), 0x1 as *mut u8, ptr::null_mut());
            assert_eq!(DISPATCH_COUNT, 1);
            DISPATCH_RELATIVE_RECORD_LIST_OPS = DEFAULT_DISPATCH_RELATIVE_RECORD_LIST_OPS;
        }
    }
}
