//! Stop a selection owner's timer, optionally querying selection readiness.
//!
//! Original `FUN_08130a60` @ 0x08130a60; true extent 56 bytes
//! [0x08130a60,0x08130a98). The next body is the independently ported
//! virtual_dispatch_zero. Whole-image raw A32 decoding finds two incoming
//! plain BLs (0x08130a40, 0x08131710), zero predicated incoming BLs;
//! the body has two plain BLs, zero predicated BLs, and a BEQ tail call.
//! Stop the timer at +0xc0. Nonzero skip_query returns the stop call's r0.
//! Otherwise reload selection at +0xbc, return its byte predicate when set,
//! or reload selection and tail-call the readiness query at 0x08132670.
//!
//! Deviations: native host pointers in repr(C) slots; host retail callees
//! are injected. The timer call uses the original address rather than the
//! void Rust timer_stop seam to preserve its residual r0 (mutex_unlock's
//! result). No return value is invented even though both known callers
//! discard it. The unported readiness callee remains a retail seam.

use super::object_bytes_64_or_6c_nonzero::object_bytes_64_or_6c_nonzero;

#[repr(C)]
pub struct SelectionTimerOwner {
    pub prefix: [u32; 0xbc / 4],
    pub selection: *const u8,
    pub timer: *mut u8,
}

type Query = unsafe extern "C" fn(*const u8) -> u32;
type Stop = unsafe extern "C" fn(*mut u8) -> u32;

#[cfg(not(target_os = "none"))]
pub static mut SELECTION_TIMER_STOP: Stop = missing_stop;
#[cfg(not(target_os = "none"))]
pub static mut SELECTION_READY_QUERY: Query = missing_query;
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_stop(_: *mut u8) -> u32 { panic!("install selection timer stop") }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_query(_: *const u8) -> u32 { panic!("install selection readiness query") }

/// # Safety
/// Owner, timer and selection must satisfy their retail layouts. Host seam
/// installation must be serialized. Readiness requires a valid +0x4c handle.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn selection_timer_stop(owner: *const SelectionTimerOwner, skip_query: u32) -> u32 {
    #[cfg(target_os = "none")]
    let (stop, query): (Stop, Query) = (
        core::mem::transmute(0x0812c6b0usize), core::mem::transmute(0x08132670usize));
    #[cfg(not(target_os = "none"))]
    let (stop, query) = (SELECTION_TIMER_STOP, SELECTION_READY_QUERY);
    let result = stop(core::ptr::addr_of!((*owner).timer).read());
    if skip_query != 0 { return result; }
    let selection = core::ptr::addr_of!((*owner).selection).read();
    let blocked = object_bytes_64_or_6c_nonzero(selection);
    if blocked != 0 { return blocked; }
    query(core::ptr::addr_of!((*owner).selection).read())
}

#[cfg(test)]
mod tests {
    use super::*;
    static LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
    unsafe extern "C" fn stop(timer: *mut u8) -> u32 {
        timer.cast::<u32>().write(0);
        0xdeadbeef
    }
    unsafe extern "C" fn query(selection: *const u8) -> u32 {
        selection.cast::<u32>().read()
    }
    #[test]
    fn stops_before_query_and_preserves_short_circuit_results() {
        let _lock = LOCK.lock();
        unsafe {
            let saved = (SELECTION_TIMER_STOP, SELECTION_READY_QUERY);
            SELECTION_TIMER_STOP = stop;
            SELECTION_READY_QUERY = query;
            let mut timer = 17u32;
            let mut selection = [0u32; 28];
            let mut owner = SelectionTimerOwner { prefix: [0; 47],
                selection: core::ptr::null(), timer: (&mut timer as *mut u32).cast() };
            for flag in [1, 2, u32::MAX] {
                timer = 17;
                assert_eq!(selection_timer_stop(&owner, flag), 0xdeadbeef);
                assert_eq!(timer, 0);
            }
            owner.selection = selection.as_ptr().cast();
            for (a, b, expected) in [(0, 0, 0x87654321), (255, 0, 1), (0, 128, 1), (3, 7, 1)] {
                selection[0] = 0x87654321;
                selection.as_mut_ptr().cast::<u8>().add(0x64).write(a);
                selection.as_mut_ptr().cast::<u8>().add(0x6c).write(b);
                timer = 17;
                assert_eq!(selection_timer_stop(&owner, 0), expected);
                assert_eq!(timer, 0);
            }
            // The stop side effect clears the selection's first word before
            // the readiness query, rather than querying a stale snapshot.
            owner.timer = selection.as_mut_ptr().cast();
            selection.as_mut_ptr().cast::<u8>().add(0x64).write(0);
            selection.as_mut_ptr().cast::<u8>().add(0x6c).write(0);
            assert_eq!(selection_timer_stop(&owner, 0), 0);
            (SELECTION_TIMER_STOP, SELECTION_READY_QUERY) = saved;
        }
    }
}
