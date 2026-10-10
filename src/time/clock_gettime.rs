//! POSIX clock query — `FUN_082c372c` @ 0x082c372c.
//!
//! True extent: 96 bytes, 0x082c372c..0x082c378c (92 bytes of code and
//! one literal word). Raw aligned-word census finds two inbound plain BLs
//! (0x080c97c0, 0x080cdddc), no predicated BLs. The body has one plain BL,
//! no predicated BLs, one BLX-register call, and a tail B to 0x080f4fbc.
//! Null output yields error 26; otherwise validate the clock ID, dispatch
//! gettime through the five-word table at 0x088fa8ec (+8), then publish the
//! error even on success and return 0 or -1. Callback writes are not rolled
//! back on error. The next independent prologue is at 0x082c378c.
//!
//! Deliberate deviations: the errno/result helper stays a fixed-address call
//! on target. Validation uses the ported clock_id_validate on target and host;
//! host callback slots retain native pointer width in repr(C) records.
//! Host-only seams substitute the firmware table and errno/result helper.

use core::ptr;

type GettimeFn = unsafe extern "C" fn(*mut ClockTimespec) -> i32;
type FinishFn = unsafe extern "C" fn(i32, i32) -> i32;

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClockTimespec {
    pub seconds: i32,
    pub nanoseconds: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ClockDispatch {
    pub reserved_00: u32,
    pub reserved_04: u32,
    pub gettime: GettimeFn,
    pub reserved_0c: u32,
    pub reserved_10: u32,
}

#[cfg(target_os = "none")]
const _: () = assert!(core::mem::size_of::<ClockDispatch>() == 20);

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_gettime(_: *mut ClockTimespec) -> i32 {
    panic!("firmware clock callback not installed")
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn host_finish(error: i32, result: i32) -> i32 {
    crate::runtime::errno::errno_set(error);
    result
}
#[cfg(not(target_os = "none"))]
pub static mut CLOCK_DISPATCH: [ClockDispatch; 4] = [ClockDispatch {
    reserved_00: 0, reserved_04: 0, gettime: unavailable_gettime,
    reserved_0c: 0, reserved_10: 0,
}; 4];
#[cfg(not(target_os = "none"))]
pub static mut CLOCK_QUERY_FINISH: FinishFn = host_finish;

/// Query a validated clock; errno is replaced on every path, including success.
/// Original: 0x082c372c, 96 bytes; two plain BL callers, no predicated callers.
/// `out` must be null or writable for the selected firmware callback.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn clock_gettime(clock_id: i32, out: *mut ClockTimespec) -> i32 {
    let error = if out.is_null() {
        26
    } else {
        let validation = super::clock_id_validate::clock_id_validate(clock_id);
        if validation != 0 {
            validation
        } else {
            #[cfg(target_os = "none")]
            let table = 0x088f_a8ecusize as *const ClockDispatch;
            #[cfg(not(target_os = "none"))]
            let table = ptr::addr_of!(CLOCK_DISPATCH).cast::<ClockDispatch>();
            let callback = ptr::read_volatile(ptr::addr_of!((*table.add(clock_id as usize)).gettime));
            callback(out)
        }
    };
    let result = if error == 0 { 0 } else { -1 };
    #[cfg(target_os = "none")]
    let finish: FinishFn = core::mem::transmute(0x080f_4fbcusize);
    #[cfg(not(target_os = "none"))]
    let finish = ptr::read_volatile(ptr::addr_of!(CLOCK_QUERY_FINISH));
    finish(error, result)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use core::sync::atomic::{AtomicI32, AtomicU32, Ordering};

    static ERROR: AtomicI32 = AtomicI32::new(0);
    static CALLS: AtomicU32 = AtomicU32::new(0);
    unsafe extern "C" fn finish(error: i32, result: i32) -> i32 {
        ERROR.store(error, Ordering::Relaxed);
        result
    }
    unsafe extern "C" fn success(out: *mut ClockTimespec) -> i32 {
        CALLS.fetch_add(1, Ordering::Relaxed);
        out.write(ClockTimespec { seconds: -7, nanoseconds: 999_999_999 });
        0
    }
    unsafe extern "C" fn failure(out: *mut ClockTimespec) -> i32 {
        CALLS.fetch_add(1, Ordering::Relaxed);
        (*out).seconds = 42;
        -123
    }

    #[test]
    fn validation_dispatch_and_errno_transitions() {
        unsafe {
            let saved_table = CLOCK_DISPATCH;
            let saved_finish = CLOCK_QUERY_FINISH;
            CLOCK_QUERY_FINISH = finish;
            for slot in &mut *ptr::addr_of_mut!(CLOCK_DISPATCH) { slot.gettime = success; }
            CALLS.store(0, Ordering::Relaxed);
            let sentinel = ClockTimespec { seconds: 10, nanoseconds: 20 };
            let mut out = sentinel;
            for id in [i32::MIN, -1, 4, i32::MAX] {
                assert_eq!(clock_gettime(id, &mut out), -1);
                assert_eq!(ERROR.load(Ordering::Relaxed), 26);
                assert_eq!(out, sentinel);
            }
            for id in [0, 3, -1] {
                assert_eq!(clock_gettime(id, ptr::null_mut()), -1);
                assert_eq!(ERROR.load(Ordering::Relaxed), 26);
            }
            assert_eq!(CALLS.load(Ordering::Relaxed), 0);
            for id in 0..4 {
                CLOCK_DISPATCH[id as usize].gettime = failure;
                out = sentinel;
                assert_eq!(clock_gettime(id, &mut out), -1);
                assert_eq!(ERROR.load(Ordering::Relaxed), -123);
                assert_eq!(out, ClockTimespec { seconds: 42, nanoseconds: 20 });
                CLOCK_DISPATCH[id as usize].gettime = success;
                assert_eq!(clock_gettime(id, &mut out), 0);
                assert_eq!(ERROR.load(Ordering::Relaxed), 0);
                assert_eq!(out, ClockTimespec { seconds: -7, nanoseconds: 999_999_999 });
            }
            assert_eq!(CALLS.load(Ordering::Relaxed), 8);
            // Exercise the wait/timer wrapper in this same fixture: a separate
            // test would race the shared firmware callback table and finish seam.
            let query = super::super::wait_clock_gettime::wait_clock_gettime;
            for id in [i32::MIN, -256, -1, 4, 255, 256, i32::MAX] {
                out = sentinel;
                assert_eq!(query(id, &mut out), -1);
                assert_eq!(ERROR.load(Ordering::Relaxed), 26);
                assert_eq!(out, sentinel);
            }
            for id in [0, 3, -1, 4] {
                assert_eq!(query(id, ptr::null_mut()), -1);
                assert_eq!(ERROR.load(Ordering::Relaxed), 26);
            }
            assert_eq!(CALLS.load(Ordering::Relaxed), 8);
            for id in 0..4 {
                CLOCK_DISPATCH[id as usize].gettime = failure;
                out = sentinel;
                assert_eq!(query(id, &mut out), -1);
                assert_eq!(ERROR.load(Ordering::Relaxed), -123);
                assert_eq!(out, ClockTimespec { seconds: 42, nanoseconds: 20 });
                CLOCK_DISPATCH[id as usize].gettime = success;
                assert_eq!(query(id, &mut out), 0);
                assert_eq!(ERROR.load(Ordering::Relaxed), 0);
                assert_eq!(out, ClockTimespec { seconds: -7, nanoseconds: 999_999_999 });
            }
            assert_eq!(CALLS.load(Ordering::Relaxed), 16);
            CLOCK_DISPATCH = saved_table;
            CLOCK_QUERY_FINISH = saved_finish;
        }
    }
}
