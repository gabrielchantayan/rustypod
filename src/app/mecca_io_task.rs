//! Mecca I/O task singleton accessor — `FUN_081f465c` @ **0x081f465c**.
//!
//! True size: 88 bytes (72 instruction bytes and 16 literal bytes), ending
//! at the next real prologue at 0x081f46b4. Raw aligned ARM decoding verifies
//! two inbound plain BLs, four outbound plain BLs, and zero predicated BLs.
//! Test guard bit zero; if clear and acquired, construct object 0x08ae48e8,
//! register the constructor result for shutdown, and release the guard.
//! Always return the fixed object, even when the constructor returns another
//! pointer or shutdown registration fails. The constructor starts MeCCAIOTask.
//!
//! Deliberate deviations: the unported constructor executes at its verified
//! retailOS address; the destructor remains the opaque word 0x081e9da4.
//! Host builds substitute aligned object storage and explicit constructor and
//! shutdown seams; they do not emulate the unported constructor or destructor.

use core::ffi::c_void;
use crate::runtime::cxa_guard::{cxa_guard_acquire, cxa_guard_release};
use crate::runtime::shutdown_chain::{cxa_atexit, ShutdownHandlerFn};

const DSO_HANDLE: i32 = 0x089c_a09c;
pub type MeccaIoTaskConstructor = unsafe extern "C" fn(*mut u8) -> *mut u8;

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_constructor(this: *mut u8) -> *mut u8 {
    let constructor: MeccaIoTaskConstructor = core::mem::transmute(0x081f_4b54usize);
    constructor(this)
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_constructor(_this: *mut u8) -> *mut u8 {
    panic!("mecca_io_task_get requires retailOS constructor 0x081f4b54")
}
#[cfg(target_os = "none")]
pub static mut MECCA_IO_TASK_CTOR: MeccaIoTaskConstructor = firmware_constructor;
#[cfg(not(target_os = "none"))]
pub static mut MECCA_IO_TASK_CTOR: MeccaIoTaskConstructor = missing_constructor;

#[cfg(not(target_os = "none"))]
static mut HOST_GUARD: u32 = 0;
#[cfg(not(target_os = "none"))]
static mut HOST_OBJECT: [u32; 25] = [0; 25];
#[cfg(not(target_os = "none"))]
static mut HOST_ATEXIT: unsafe extern "C" fn(*mut c_void, ShutdownHandlerFn, i32) -> i32 = cxa_atexit;
#[cfg(not(target_os = "none"))]
static mut HOST_RELEASE: unsafe extern "C" fn(*mut u32) = cxa_guard_release;
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn host_destructor(_object: *mut c_void) {}

/// Return the fixed task object, lazily constructing it through the ADS guard.
///
/// # Safety
/// retailOS globals and constructor must be available on target. Host callers
/// must install a constructor and serialize access to this singleton's seams.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn mecca_io_task_get() -> *mut u8 {
    #[cfg(target_os = "none")]
    let (guard, object) = (0x08a0_9d4cusize as *mut u32, 0x08ae_48e8usize as *mut u8);
    #[cfg(not(target_os = "none"))]
    let (guard, object) = (core::ptr::addr_of_mut!(HOST_GUARD), core::ptr::addr_of_mut!(HOST_OBJECT).cast::<u8>());
    if core::ptr::read_volatile(guard) & 1 == 0 && cxa_guard_acquire(guard) != 0 {
        let constructor = core::ptr::read_volatile(core::ptr::addr_of!(MECCA_IO_TASK_CTOR));
        let initialized = constructor(object);
        #[cfg(target_os = "none")]
        {
            let destructor: ShutdownHandlerFn = core::mem::transmute(0x081e_9da4usize);
            cxa_atexit(initialized.cast::<c_void>(), destructor, DSO_HANDLE);
            cxa_guard_release(guard);
        }
        #[cfg(not(target_os = "none"))]
        {
            core::ptr::read_volatile(core::ptr::addr_of!(HOST_ATEXIT))(initialized.cast::<c_void>(), host_destructor, DSO_HANDLE);
            core::ptr::read_volatile(core::ptr::addr_of!(HOST_RELEASE))(guard);
        }
    }
    object
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use core::ptr;
    use std::sync::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut EVENTS: std::vec::Vec<u32> = std::vec::Vec::new();
    static mut RESULT: u32 = 0;

    unsafe extern "C" fn construct(object: *mut u8) -> *mut u8 {
        assert_eq!(object, ptr::addr_of_mut!(HOST_OBJECT).cast::<u8>());
        assert_eq!(ptr::read(ptr::addr_of!(HOST_GUARD)), 1);
        object.cast::<u32>().add(24).write(0x41);
        (*ptr::addr_of_mut!(EVENTS)).push(1);
        ptr::addr_of_mut!(RESULT).cast::<u8>()
    }
    unsafe extern "C" fn register(object: *mut c_void, handler: ShutdownHandlerFn, dso: i32) -> i32 {
        assert_eq!(object, ptr::addr_of_mut!(RESULT).cast::<c_void>());
        assert_eq!(handler as usize, host_destructor as usize);
        assert_eq!(dso, DSO_HANDLE);
        assert_eq!((*ptr::addr_of!(EVENTS)).as_slice(), &[1]);
        (*ptr::addr_of_mut!(EVENTS)).push(2);
        -1 // Failure must not prevent release or change the returned object.
    }
    unsafe extern "C" fn release(guard: *mut u32) {
        assert_eq!(guard, ptr::addr_of_mut!(HOST_GUARD));
        assert_eq!((*ptr::addr_of!(EVENTS)).as_slice(), &[1, 2]);
        (*ptr::addr_of_mut!(EVENTS)).push(3);
        cxa_guard_release(guard);
    }

    #[test]
    fn initialization_returns_fixed_object_and_does_not_retry_failed_registration() {
        let _lock = LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            HOST_GUARD = 0;
            HOST_OBJECT = [0; 25];
            (*ptr::addr_of_mut!(EVENTS)).clear();
            MECCA_IO_TASK_CTOR = construct;
            HOST_ATEXIT = register;
            HOST_RELEASE = release;
            let object = ptr::addr_of_mut!(HOST_OBJECT).cast::<u8>();
            assert_eq!(mecca_io_task_get(), object);
            assert_ne!(object, ptr::addr_of_mut!(RESULT).cast::<u8>());
            assert_eq!(ptr::read(ptr::addr_of!(HOST_OBJECT)).get(24), Some(&0x41));
            assert_eq!(mecca_io_task_get(), object);
            assert_eq!((*ptr::addr_of!(EVENTS)).as_slice(), &[1, 2, 3]);
            MECCA_IO_TASK_CTOR = missing_constructor;
            HOST_ATEXIT = cxa_atexit;
            HOST_RELEASE = cxa_guard_release;
            HOST_GUARD = 0;
        }
    }

    #[test]
    fn completed_and_incomplete_nonzero_guards_skip_all_initialization() {
        let _lock = LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            (*ptr::addr_of_mut!(EVENTS)).clear();
            MECCA_IO_TASK_CTOR = construct;
            HOST_ATEXIT = register;
            HOST_RELEASE = release;
            for guard in [1, 3, 2, 0x8000_0000, u32::MAX] {
                HOST_GUARD = guard;
                assert_eq!(mecca_io_task_get(), ptr::addr_of_mut!(HOST_OBJECT).cast::<u8>());
                assert_eq!(ptr::read(ptr::addr_of!(HOST_GUARD)), guard);
                assert!((*ptr::addr_of!(EVENTS)).is_empty());
            }
            MECCA_IO_TASK_CTOR = missing_constructor;
            HOST_ATEXIT = cxa_atexit;
            HOST_RELEASE = cxa_guard_release;
            HOST_GUARD = 0;
        }
    }
}
