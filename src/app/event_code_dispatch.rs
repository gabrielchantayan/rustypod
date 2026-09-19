//! `event_code_dispatch_unflagged` — original: `FUN_080873f0` @ `0x080873f0`
//! (8 bytes: `mov r1,#0; mov r0,r0`).
//!
//! `event_code_dispatch` — original: `FUN_080873f8` @ `0x080873f8` (88 bytes).
//!
//! # Verified call sites
//!
//! The unflagged entry has seven direct `bl` callers: six unconditional and one
//! `bleq`; four unconditional tail branches also enter it. The shared worker has
//! three plain `bl` instructions (`0x0808740c`, `0x0808742c`, and
//! `0x08087444`) and no predicated `bl`; `0x08087450` is the next function.
//!
//! # Algorithm
//!
//! A nonzero event code is mapped by retailOS helper `0x080e4d44`. On success,
//! the worker polls byte `+2` of the object at `0x089ca864`, sleeping the current
//! RTXC task for one tick through `0x22003d44` until it is ready, then submits
//! the mapped byte and the caller's flag to retailOS helper `0x08064820`.
//!
//! # Deliberate deviation
//!
//! The three unported calls remain address-based seams on ARM. Host builds use
//! volatile callback seams for them and for readiness rather than mapping the
//! fixed retail address.

pub type EventCodeMap = unsafe extern "C" fn(event_code: u32, mapped_code: *mut u8) -> u32;
pub type EventCodeReady = unsafe extern "C" fn() -> u8;
pub type EventCodeDispatch = unsafe extern "C" fn(mapped_code: u32, flag: u32);
pub type TaskDelay = unsafe extern "C" fn(task: u32, ticks: u32);

#[cfg(not(target_arch = "arm"))]
pub(crate) unsafe extern "C" fn missing_event_code_map(_event_code: u32, _mapped_code: *mut u8) -> u32 { 0 }
#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_event_code_ready() -> u8 { 1 }
#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_event_code_dispatch(_mapped_code: u32, _flag: u32) {}
#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_task_delay(_task: u32, _ticks: u32) {}

#[cfg(not(target_arch = "arm"))]
pub static mut EVENT_CODE_MAP: EventCodeMap = missing_event_code_map;
#[cfg(not(target_arch = "arm"))]
pub static mut EVENT_CODE_READY: EventCodeReady = missing_event_code_ready;
#[cfg(not(target_arch = "arm"))]
pub static mut EVENT_CODE_DISPATCH: EventCodeDispatch = missing_event_code_dispatch;
#[cfg(not(target_arch = "arm"))]
pub static mut EVENT_CODE_TASK_DELAY: TaskDelay = missing_task_delay;

#[cfg(test)]
pub(crate) static EVENT_CODE_DISPATCH_TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

#[inline(always)]
unsafe fn map_event_code(event_code: u32, mapped_code: *mut u8) -> u32 {
    #[cfg(target_arch = "arm")]
    {
        let map: EventCodeMap = core::mem::transmute(0x080e_4d44usize);
        map(event_code, mapped_code)
    }
    #[cfg(not(target_arch = "arm"))]
    core::ptr::read_volatile(core::ptr::addr_of!(EVENT_CODE_MAP))(event_code, mapped_code)
}

#[inline(always)]
unsafe fn event_code_ready() -> u8 {
    #[cfg(target_arch = "arm")]
    {
        core::ptr::read_volatile((0x089c_a864usize + 2) as *const u8)
    }
    #[cfg(not(target_arch = "arm"))]
    {
        core::ptr::read_volatile(core::ptr::addr_of!(EVENT_CODE_READY))()
    }
}

#[inline(always)]
unsafe fn delay_one_tick() {
    #[cfg(target_arch = "arm")]
    {
        let delay: TaskDelay = core::mem::transmute(0x2200_3d44usize);
        delay(0, 1);
    }
    #[cfg(not(target_arch = "arm"))]
    core::ptr::read_volatile(core::ptr::addr_of!(EVENT_CODE_TASK_DELAY))(0, 1);
}

#[inline(always)]
unsafe fn dispatch_event_code(mapped_code: u32, flag: u32) {
    #[cfg(target_arch = "arm")]
    {
        let dispatch: EventCodeDispatch = core::mem::transmute(0x0806_4820usize);
        dispatch(mapped_code, flag);
    }
    #[cfg(not(target_arch = "arm"))]
    core::ptr::read_volatile(core::ptr::addr_of!(EVENT_CODE_DISPATCH))(mapped_code, flag);
}

/// Clears the worker flag while preserving the event-code word.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn event_code_dispatch_unflagged(event_code: u32) {
    event_code_dispatch(event_code, 0);
}

/// Maps, waits for readiness, then dispatches a nonzero event code.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn event_code_dispatch(event_code: u32, flag: u32) {
    if event_code == 0 {
        return;
    }

    let mut mapped_code = 0u8;
    if map_event_code(event_code, core::ptr::addr_of_mut!(mapped_code)) == 0 {
        return;
    }
    while event_code_ready() == 0 {
        delay_one_tick();
    }
    dispatch_event_code(mapped_code as u32, flag);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    static mut MAP_CALLS: u32 = 0;
    static mut MAP_INPUT: u32 = 0;
    static mut READY_CALLS: u32 = 0;
    static mut DELAY_CALLS: u32 = 0;
    static mut DISPATCH: (u32, u32) = (0, 0);

    unsafe extern "C" fn map_seven(event_code: u32, mapped_code: *mut u8) -> u32 {
        MAP_CALLS += 1;
        MAP_INPUT = event_code;
        core::ptr::write(mapped_code, 0xa5);
        1
    }
    unsafe extern "C" fn map_failure(_event_code: u32, _mapped_code: *mut u8) -> u32 { 0 }
    unsafe extern "C" fn ready_after_two_polls() -> u8 {
        READY_CALLS += 1;
        (READY_CALLS == 3) as u8
    }
    unsafe extern "C" fn record_delay(task: u32, ticks: u32) {
        assert_eq!((task, ticks), (0, 1));
        DELAY_CALLS += 1;
    }
    unsafe extern "C" fn record_dispatch(mapped_code: u32, flag: u32) { DISPATCH = (mapped_code, flag); }

    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            unsafe {
                EVENT_CODE_MAP = missing_event_code_map;
                EVENT_CODE_READY = missing_event_code_ready;
                EVENT_CODE_DISPATCH = missing_event_code_dispatch;
                EVENT_CODE_TASK_DELAY = missing_task_delay;
                MAP_CALLS = 0;
                MAP_INPUT = 0;
                READY_CALLS = 0;
                DELAY_CALLS = 0;
                DISPATCH = (0, 0);
            }
        }
    }

    #[test]
    fn zero_and_unmapped_events_do_not_wait_or_dispatch() {
        let _lock = EVENT_CODE_DISPATCH_TEST_LOCK.lock();
        let _reset = Reset;
        unsafe {
            EVENT_CODE_MAP = map_failure;
            event_code_dispatch(0, u32::MAX);
            event_code_dispatch(0x17, 3);
            assert_eq!(MAP_CALLS, 0);
            assert_eq!(READY_CALLS, 0);
            assert_eq!(DELAY_CALLS, 0);
            assert_eq!(DISPATCH, (0, 0));
        }
    }

    #[test]
    fn waits_for_readiness_and_preserves_the_flag() {
        let _lock = EVENT_CODE_DISPATCH_TEST_LOCK.lock();
        let _reset = Reset;
        unsafe {
            EVENT_CODE_MAP = map_seven;
            EVENT_CODE_READY = ready_after_two_polls;
            EVENT_CODE_TASK_DELAY = record_delay;
            EVENT_CODE_DISPATCH = record_dispatch;
            event_code_dispatch(7, 2);
            assert_eq!(MAP_CALLS, 1);
            assert_eq!(MAP_INPUT, 7);
            assert_eq!(READY_CALLS, 3);
            assert_eq!(DELAY_CALLS, 2);
            assert_eq!(DISPATCH, (0xa5, 2));
        }
    }

    #[test]
    fn unflagged_entry_clears_the_worker_flag() {
        let _lock = EVENT_CODE_DISPATCH_TEST_LOCK.lock();
        let _reset = Reset;
        unsafe {
            EVENT_CODE_MAP = map_seven;
            EVENT_CODE_DISPATCH = record_dispatch;
            event_code_dispatch_unflagged(u32::MAX);
            assert_eq!(MAP_INPUT, u32::MAX);
            assert_eq!(DISPATCH, (0xa5, 0));
        }
    }
}
