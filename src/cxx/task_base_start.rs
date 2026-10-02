//! Launch the common retailOS task base.
//!
//! Original: FUN_082906b4 @ 0x082906b4, 72 code bytes plus eight literal
//! bytes; the next function starts at 0x08290704. Raw A32 words verify two
//! outgoing plain BLs, zero predicated BLs, and two incoming plain BLs
//! (0x08112c50, 0x0819bed8), zero predicated incoming BLs.
//!
//! Clear flag +0x20, publish this at 0x089cc920, obtain the embedded name,
//! invoke 0x080e9cbc with name, entry 0x082857cc, NULL arguments, scheduler,
//! priority, active byte and timeout, then store the returned handle at +4.
//! There is no already-started or failure guard.
//!
//! Deviations: repr(C) preserves target offsets while widening the embedded
//! StringObject on hosts. The unported task creator uses its verified fixed
//! address on target and a replaceable host seam; the publication slot is
//! modeled on hosts. The existing name accessor models the empty string.
//! ARM structural review preserves all field offsets and call ordering;
//! LLVM adds a frame and uses BLX for the fixed-address task creator.

use core::ptr;
use crate::cxx::string_object::{string_object_c_str, StringObject};

#[repr(C)]
pub struct TaskBase {
    pub vtable: u32,
    pub handle: u32,
    pub name: StringObject,
    pub scheduler: u32,
    pub priority: u32,
    pub active: u8,
    pub padding: [u8; 3],
    pub timeout: u32,
    pub flag: u8,
}

const TASK_ENTRY: u32 = 0x0828_57cc;
pub type TaskCreate = unsafe extern "C" fn(*const u8, u32, u32, u32, u32, u32, u32) -> u32;
#[cfg(not(target_os = "none"))]
static mut PUBLISHED_TASK: *mut TaskBase = ptr::null_mut();
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_task_create(_: *const u8, _: u32, _: u32, _: u32, _: u32, _: u32, _: u32) -> u32 {
    panic!("retailOS task creator requires a host seam")
}
#[cfg(not(target_os = "none"))]
pub static mut TASK_CREATE: TaskCreate = unavailable_task_create;

/// `this` must be a valid, writable task base; its name must be valid for
/// string_object_c_str. The task creator may synchronously observe this.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn task_base_start(this: *mut TaskBase) {
    (*this).flag = 0;
    #[cfg(target_os = "none")]
    (0x089c_c920 as *mut *mut TaskBase).write_volatile(this);
    #[cfg(not(target_os = "none"))]
    ptr::addr_of_mut!(PUBLISHED_TASK).write_volatile(this);
    let name = string_object_c_str(ptr::addr_of!((*this).name));
    #[cfg(target_os = "none")]
    let create: TaskCreate = core::mem::transmute(0x080e_9cbcusize);
    #[cfg(not(target_os = "none"))]
    let create = ptr::addr_of!(TASK_CREATE).read_volatile();
    let handle = create(name, TASK_ENTRY, 0, (*this).scheduler,
                        (*this).priority, (*this).active as u32, (*this).timeout);
    (*this).handle = handle;
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut RESULT: u32 = 0;
    static mut EXPECT_EMPTY: bool = false;

    unsafe extern "C" fn observe_start(name: *const u8, entry: u32, args: u32,
                                      scheduler: u32, priority: u32, active: u32, timeout: u32) -> u32 {
        let task = ptr::addr_of!(PUBLISHED_TASK).read_volatile();
        // Publication and flag clearing must precede task creation, but the
        // previous handle must survive until creation returns.
        assert!(!task.is_null());
        assert_eq!((*task).flag, 0);
        assert_eq!((*task).handle, 0x12345678);
        assert_eq!((entry, args, scheduler, priority, active, timeout),
                   (TASK_ENTRY, 0, 0x20, 0x8000, 0xff, u32::MAX));
        if ptr::addr_of!(EXPECT_EMPTY).read() {
            assert_eq!(*name, 0);
        } else {
            assert_eq!(name, (*task).name.payload.cast::<u8>());
            assert_eq!(*name, b'T');
        }
        // A synchronously started task can update its flag. Do not clear it
        // again after the creator returns.
        (*task).flag = 7;
        ptr::addr_of!(RESULT).read()
    }

    #[test]
    fn publishes_before_creation_and_preserves_callback_state_even_on_zero_handle() {
        let _lock = LOCK.lock();
        unsafe {
            let previous = ptr::addr_of!(TASK_CREATE).read();
            ptr::addr_of_mut!(TASK_CREATE).write(observe_start);
            for (payload, result) in [(ptr::null_mut(), 0), (b"Task\0".as_ptr() as *mut u8, u32::MAX)] {
                let mut task = TaskBase {
                    vtable: 0x089a7160, handle: 0x12345678,
                    name: StringObject { vtable: ptr::null(), payload: payload.cast() },
                    scheduler: 0x20, priority: 0x8000, active: 0xff,
                    padding: [0xa5; 3], timeout: u32::MAX, flag: 0xff,
                };
                ptr::addr_of_mut!(RESULT).write(result);
                ptr::addr_of_mut!(EXPECT_EMPTY).write(payload.is_null());
                task_base_start(&mut task);
                assert_eq!(ptr::addr_of!(PUBLISHED_TASK).read(), &mut task as *mut TaskBase);
                assert_eq!(task.handle, result);
                assert_eq!(task.flag, 7);
                assert_eq!(task.vtable, 0x089a7160);
                assert_eq!(task.padding, [0xa5; 3]);
                assert_eq!(task.name.payload.cast::<u8>(), payload);
            }
            ptr::addr_of_mut!(TASK_CREATE).write(previous);
            ptr::addr_of_mut!(PUBLISHED_TASK).write(ptr::null_mut());
        }
    }
}
