//! Lazy opaque-object accessor — `FUN_080f5564` @ `0x080f5564`.
//!
//! True extent: 96 bytes, [0x080f5564, 0x080f55c4): 76 instruction bytes
//! plus five literal words. Raw decoding verifies four outbound plain BLs,
//! zero predicated BLs. Ghidra identifies two inbound callers, one initializing
//! object resources and one retaining the object in a video-decoder context.
//!
//! Test guard bit zero at 0x08a09d3c + 12, acquire that same word at
//! 0x08a09d48, construct fixed object 0x08ae4848 with argument 6, register
//! the constructor return with opaque handler word 0x080eaf5c and DSO handle
//! 0x089ca09c, then release. Every path returns the fixed object, not the
//! constructor result. Registration failure is deliberately ignored.
//!
//! Deliberate deviations: host storage and test callbacks replace inaccessible
//! firmware addresses. Target builds retain the verified unported constructor
//! 0x080f5d5c and opaque handler word verbatim; no class/destructor identity is
//! claimed (the handler word decodes inside an instruction sequence). Volatile
//! runtime bindings preserve the registration and otherwise-empty release calls.

use core::ffi::c_void;
use core::ptr;
use crate::runtime::cxa_guard::{cxa_guard_acquire, cxa_guard_release};
use crate::runtime::shutdown_chain::{cxa_atexit, ShutdownHandlerFn};

type Constructor = unsafe extern "C" fn(*mut u8, u32) -> *mut u8;
type Register = unsafe extern "C" fn(*mut c_void, ShutdownHandlerFn, i32) -> i32;
type Release = unsafe extern "C" fn(*mut u32);
static mut REGISTER: Register = cxa_atexit;
static mut RELEASE: Release = cxa_guard_release;

#[cfg(not(target_os = "none"))]
static mut HOST_GUARD: u32 = 0;
// Constructor accesses through byte 0x9c, including the subobject at +0x84.
#[cfg(not(target_os = "none"))]
static mut HOST_OBJECT: [u32; 40] = [0; 40];
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_constructor(_: *mut u8, _: u32) -> *mut u8 {
    panic!("unported firmware constructor requires a host binding")
}
#[cfg(not(target_os = "none"))]
static mut HOST_CONSTRUCTOR: Constructor = unavailable_constructor;
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_handler(_: *mut c_void) {
    panic!("opaque firmware shutdown handler is not host-callable")
}

/// Return the lazily constructed fixed firmware object.
///
/// # Safety
/// Target firmware storage and unported call targets must be resident. This
/// preserves the single-threaded ADS guard protocol; concurrent access is unsafe.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn lazy_static_object_08ae4848_get() -> *mut u8 {
    #[cfg(target_os = "none")]
    let (guard, object, constructor, handler) = (
        0x08a0_9d48 as *mut u32,
        0x08ae_4848 as *mut u8,
        core::mem::transmute::<usize, Constructor>(0x080f_5d5c),
        core::mem::transmute::<usize, ShutdownHandlerFn>(0x080e_af5c),
    );
    #[cfg(not(target_os = "none"))]
    let (guard, object, constructor, handler) = (
        ptr::addr_of_mut!(HOST_GUARD),
        ptr::addr_of_mut!(HOST_OBJECT).cast::<u8>(),
        ptr::read_volatile(ptr::addr_of!(HOST_CONSTRUCTOR)),
        unavailable_handler as ShutdownHandlerFn,
    );
    if ptr::read_volatile(guard) & 1 == 0 && cxa_guard_acquire(guard) != 0 {
        let constructed = constructor(object, 6);
        ptr::read_volatile(ptr::addr_of!(REGISTER))(constructed.cast(), handler, 0x089c_a09c);
        ptr::read_volatile(ptr::addr_of!(RELEASE))(guard);
    }
    object
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use parking_lot::Mutex;
    static LOCK: Mutex<()> = Mutex::new(());
    static mut EVENTS: u32 = 0;
    static mut REGISTERED: *mut c_void = ptr::null_mut();

    unsafe extern "C" fn construct(object: *mut u8, bits: u32) -> *mut u8 {
        assert_eq!(bits, 6);
        assert_eq!(ptr::addr_of!(HOST_GUARD).read(), 1);
        // Reentrant acquisition must return the same half-built object without
        // invoking construction again: acquire publishes before construction.
        assert_eq!(lazy_static_object_08ae4848_get(), object);
        EVENTS = EVENTS * 10 + 1;
        object.add(0x9c).write(0x5a);
        object.add(4)
    }
    unsafe extern "C" fn fail_registration(object: *mut c_void, handler: ShutdownHandlerFn, dso: i32) -> i32 {
        assert_eq!(handler as usize, unavailable_handler as *const () as usize);
        assert_eq!(dso, 0x089c_a09c);
        REGISTERED = object;
        EVENTS = EVENTS * 10 + 2;
        -1
    }
    unsafe extern "C" fn release(guard: *mut u32) {
        assert_eq!(guard, ptr::addr_of_mut!(HOST_GUARD));
        cxa_guard_release(guard);
        EVENTS = EVENTS * 10 + 3;
    }

    #[test]
    fn initialization_reentrancy_registration_failure_and_guard_edges() {
        let _lock = LOCK.lock();
        unsafe {
            HOST_CONSTRUCTOR = construct;
            REGISTER = fail_registration;
            RELEASE = release;
            let object = ptr::addr_of_mut!(HOST_OBJECT).cast::<u8>();
            for initial_guard in [1, 3, 2, 0x8000_0000, 0] {
                HOST_GUARD = initial_guard;
                HOST_OBJECT = [0; 40];
                EVENTS = 0;
                REGISTERED = ptr::null_mut();
                assert_eq!(lazy_static_object_08ae4848_get(), object);
                if initial_guard == 0 {
                    assert_eq!(ptr::addr_of!(EVENTS).read(), 123);
                    assert_eq!(ptr::addr_of!(REGISTERED).read(), object.add(4).cast());
                    assert_eq!(object.add(0x9c).read(), 0x5a);
                    assert_eq!(ptr::addr_of!(HOST_GUARD).read(), 1);
                    assert_eq!(lazy_static_object_08ae4848_get(), object);
                    assert_eq!(ptr::addr_of!(EVENTS).read(), 123);
                } else {
                    assert_eq!(ptr::addr_of!(EVENTS).read(), 0);
                    assert_eq!(ptr::addr_of!(HOST_GUARD).read(), initial_guard);
                    assert_eq!(object.add(0x9c).read(), 0);
                    assert!(ptr::addr_of!(REGISTERED).read().is_null());
                }
            }
            HOST_CONSTRUCTOR = unavailable_constructor;
            REGISTER = cxa_atexit;
            RELEASE = cxa_guard_release;
            HOST_GUARD = 0;
        }
    }
}
