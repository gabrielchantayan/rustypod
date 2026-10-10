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
//! operation table is a deliberate deviation: lookup and construction remain
//! unported, while storage now uses the Rust port below.

#[cfg(not(target_os = "none"))]
use core::ptr::{addr_of, read_volatile};

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
pub struct TaskLocalOps {
    pub current_task_id: unsafe extern "C" fn() -> u32,
    pub lookup: unsafe extern "C" fn(u32) -> u32,
    pub construct: unsafe extern "C" fn(u32) -> u32,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_current_task_id() -> u32 { panic!("current task ID unavailable") }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_lookup(_: u32) -> u32 { panic!("task-local lookup unavailable") }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_construct(_: u32) -> u32 { panic!("task-local constructor unavailable") }

#[cfg(not(target_os = "none"))]
pub const DEFAULT_TASK_LOCAL_OPS: TaskLocalOps = TaskLocalOps {
    current_task_id: missing_current_task_id,
    lookup: missing_lookup,
    construct: missing_construct,
};

/// Host-side seam for task identification and the unported retailOS helpers.
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
#[cfg(not(target_os = "none"))]
static mut HOST_TASK_LOCAL_SLOTS: [u32; 80] = [0; 80];

/// task_local_store — original: `FUN_080b4bfc` @ `0x080b4bfc`.
/// True extent: 36 bytes through 0x080b4c20 (32 code bytes, 4-byte literal).
/// Two incoming plain BLs (0x080a3e94, 0x080b16c8), zero predicated BLs.
/// Outgoing calls: zero plain BLs, one BLEQ to current_task_id @ 0x08037e60.
/// Resolve ID zero to the current task, then store the value in the aligned
/// u32 table at 0x08adc180 only if the resolved unsigned ID is below 80.
/// Zero values clear slots; a resolved zero writes slot zero without recursion.
/// Deliberate deviations: host builds substitute an 80-word table and the
/// existing current-ID seam. Device builds call the verified current-ID port;
/// volatile storage preserves the shared firmware table access.
///
/// # Safety
/// Requires initialized current-task state for ID zero and externally
/// serialized access to the task-local table.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn task_local_store(mut task_id: u32, value: u32) {
    if task_id == 0 {
        #[cfg(target_os = "none")]
        { task_id = super::task_lock::current_task_id(); }
        #[cfg(not(target_os = "none"))]
        { task_id = (read_volatile(addr_of!(TASK_LOCAL_OPS)).current_task_id)(); }
    }
    if task_id < 80 {
        #[cfg(target_os = "none")]
        let slots = 0x08ad_c180 as *mut u32;
        #[cfg(not(target_os = "none"))]
        let slots = core::ptr::addr_of_mut!(HOST_TASK_LOCAL_SLOTS).cast::<u32>();
        slots.add(task_id as usize).write_volatile(value);
    }
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
        task_local_store(task_id, value);
        value
    }
    #[cfg(not(target_os = "none"))]
    {
        let ops = read_volatile(addr_of!(TASK_LOCAL_OPS));
        let task_id = (ops.current_task_id)();
        let value = (ops.lookup)(task_id);
        if value != 0 { return value; }
        let value = (ops.construct)(task_id);
        task_local_store(task_id, value);
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

    unsafe fn install(lookup_result: u32, construct_result: u32) {
        EVENT_COUNT = 0;
        LOOKUP_RESULT = lookup_result;
        CONSTRUCT_RESULT = construct_result;
        addr_of_mut!(TASK_LOCAL_OPS).write(TaskLocalOps { current_task_id: current, lookup: lookup_mock, construct: construct_mock });
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
    fn constructs_and_stores_missing_task_local() {
        let _guard = LOCK.lock();
        unsafe {
            install(0, 0xfeed_face);
            assert_eq!(task_local_for_current_task(), 0xfeed_face);
            assert_eq!(&EVENTS[..EVENT_COUNT], &[1, 2, 3]);
            assert_eq!(HOST_TASK_LOCAL_SLOTS[0x31], 0xfeed_face);
            restore();
        }
    }

    #[test]
    fn store_unsigned_bounds_and_clear_preserve_other_slots() {
        let _guard = LOCK.lock();
        unsafe {
            addr_of_mut!(HOST_TASK_LOCAL_SLOTS).write([0x1234_5678; 80]);
            for id in [1, 79, 80, 81, u32::MAX] {
                task_local_store(id, 0xffff_ffff);
            }
            task_local_store(1, 0);
            for id in 0..80 {
                let expected = match id {
                    1 => 0,
                    79 => u32::MAX,
                    _ => 0x1234_5678,
                };
                assert_eq!(HOST_TASK_LOCAL_SLOTS[id], expected);
            }
        }
    }

    unsafe extern "C" fn current_zero() -> u32 { 0 }
    unsafe extern "C" fn current_last() -> u32 { 79 }
    unsafe extern "C" fn current_out_of_range() -> u32 { 80 }

    #[test]
    fn store_resolves_zero_once_and_checks_resolved_bounds() {
        let _guard = LOCK.lock();
        unsafe {
            for (current, expected_slot) in [
                (current_zero as unsafe extern "C" fn() -> u32, Some(0)),
                (current_last, Some(79)),
                (current_out_of_range, None),
            ] {
                addr_of_mut!(HOST_TASK_LOCAL_SLOTS).write([0x1234_5678; 80]);
                addr_of_mut!(TASK_LOCAL_OPS).write(TaskLocalOps {
                    current_task_id: current,
                    ..DEFAULT_TASK_LOCAL_OPS
                });
                task_local_store(0, 0xdead_beef);
                for id in 0..80 {
                    assert_eq!(HOST_TASK_LOCAL_SLOTS[id],
                        if Some(id) == expected_slot { 0xdead_beef } else { 0x1234_5678 });
                }
            }
            restore();
        }
    }
}
