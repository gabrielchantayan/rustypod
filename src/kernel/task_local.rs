//! Per-task local object access.
//!
//! `task_local_for_current_task` — original: `FUN_080a3e68` @ `0x080a3e68`
//! (48 bytes; `0x080a3e68..0x080a3e98`). Raw words prove four unconditional
//! `bl` calls and no predicated calls: current-task ID (`0x08037e60`), lookup
//! (`0x080b4c20`), constructor (`0x080ccbd0`), and store (`0x080b4bfc`).
//! Ghidra's 56-byte / five-call extent is wrong: the next function starts
//! with `push {r4-r6,lr}` at `0x080a3ea0`.
//!
//! The routine obtains the current task's ID, returns its existing local
//! object if the ID-indexed slot is nonzero, otherwise constructs an object
//! for that ID, stores it into the slot, and returns it. The host-only
//! operation table is a deliberate deviation: the three retailOS helpers are
//! not yet ported, while firmware builds call their verified fixed addresses.

#[cfg(not(target_os = "none"))]
use core::ptr::{addr_of, read_volatile};

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
pub struct TaskLocalOps {
    pub current_task_id: unsafe extern "C" fn() -> u32,
    pub lookup: unsafe extern "C" fn(u32) -> u32,
    pub construct: unsafe extern "C" fn(u32) -> u32,
    pub store: unsafe extern "C" fn(u32, u32),
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_current_task_id() -> u32 { panic!("current task ID unavailable") }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_lookup(_: u32) -> u32 { panic!("task-local lookup unavailable") }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_construct(_: u32) -> u32 { panic!("task-local constructor unavailable") }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_store(_: u32, _: u32) { panic!("task-local store unavailable") }

#[cfg(not(target_os = "none"))]
pub const DEFAULT_TASK_LOCAL_OPS: TaskLocalOps = TaskLocalOps {
    current_task_id: missing_current_task_id,
    lookup: missing_lookup,
    construct: missing_construct,
    store: missing_store,
};

/// Host-side seam for the unported retailOS slot helpers.
#[cfg(not(target_os = "none"))]
pub static mut TASK_LOCAL_OPS: TaskLocalOps = DEFAULT_TASK_LOCAL_OPS;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn current_task_id() -> u32 {
    let function: unsafe extern "C" fn() -> u32 = core::mem::transmute(0x0803_7e60usize);
    function()
}
#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn lookup(task_id: u32) -> u32 {
    let function: unsafe extern "C" fn(u32) -> u32 = core::mem::transmute(0x080b_4c20usize);
    function(task_id)
}
#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn construct(task_id: u32) -> u32 {
    let function: unsafe extern "C" fn(u32) -> u32 = core::mem::transmute(0x080c_cbd0usize);
    function(task_id)
}
#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn store(task_id: u32, value: u32) {
    let function: unsafe extern "C" fn(u32, u32) = core::mem::transmute(0x080b_4bfcusize);
    function(task_id, value);
}

/// task_local_for_current_task — original: `FUN_080a3e68` @ `0x080a3e68`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn task_local_for_current_task() -> u32 {
    #[cfg(target_os = "none")]
    {
        let task_id = current_task_id();
        let value = lookup(task_id);
        if value != 0 { return value; }
        let value = construct(task_id);
        store(task_id, value);
        value
    }
    #[cfg(not(target_os = "none"))]
    {
        let ops = read_volatile(addr_of!(TASK_LOCAL_OPS));
        let task_id = (ops.current_task_id)();
        let value = (ops.lookup)(task_id);
        if value != 0 { return value; }
        let value = (ops.construct)(task_id);
        (ops.store)(task_id, value);
        value
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr::addr_of_mut;
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut EVENTS: [u32; 4] = [0; 4];
    static mut EVENT_COUNT: usize = 0;
    static mut LOOKUP_RESULT: u32 = 0;
    static mut CONSTRUCT_RESULT: u32 = 0;

    unsafe fn record(event: u32) { EVENTS[EVENT_COUNT] = event; EVENT_COUNT += 1; }
    unsafe extern "C" fn current() -> u32 { record(1); 0x31 }
    unsafe extern "C" fn lookup_mock(id: u32) -> u32 { assert_eq!(id, 0x31); record(2); LOOKUP_RESULT }
    unsafe extern "C" fn construct_mock(id: u32) -> u32 { assert_eq!(id, 0x31); record(3); CONSTRUCT_RESULT }
    unsafe extern "C" fn store_mock(id: u32, value: u32) { assert_eq!((id, value), (0x31, CONSTRUCT_RESULT)); record(4); }

    unsafe fn install(lookup_result: u32, construct_result: u32) {
        EVENT_COUNT = 0;
        LOOKUP_RESULT = lookup_result;
        CONSTRUCT_RESULT = construct_result;
        addr_of_mut!(TASK_LOCAL_OPS).write(TaskLocalOps { current_task_id: current, lookup: lookup_mock, construct: construct_mock, store: store_mock });
    }
    unsafe fn restore() { addr_of_mut!(TASK_LOCAL_OPS).write(DEFAULT_TASK_LOCAL_OPS); }

    #[test]
    fn returns_existing_task_local_without_constructing() {
        let _guard = LOCK.lock();
        unsafe {
            install(0xcafe_babe, 0);
            assert_eq!(task_local_for_current_task(), 0xcafe_babe);
            assert_eq!(&EVENTS[..EVENT_COUNT], &[1, 2]);
            restore();
        }
    }

    #[test]
    fn constructs_and_stores_missing_task_local_in_call_order() {
        let _guard = LOCK.lock();
        unsafe {
            install(0, 0xfeed_face);
            assert_eq!(task_local_for_current_task(), 0xfeed_face);
            assert_eq!(&EVENTS[..EVENT_COUNT], &[1, 2, 3, 4]);
            restore();
        }
    }
}
