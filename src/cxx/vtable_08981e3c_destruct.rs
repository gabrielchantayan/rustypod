//! `vtable_08981e3c_destruct` — retailOS `FUN_0839be5c` @ `0x0839be5c`.
//!
//! ## Verified extent and calls
//!
//! Raw `osos.dec` decodes nine ARM words: eight instructions from `0x0839be5c`
//! through the tail `b` at `0x0839be7c`, followed by vtable literal
//! `0x08981e3c`; `0x0839be84` starts the next independently entered function.
//! The true size is **36 bytes** (32 instruction bytes plus the literal). The
//! body has one plain `bl` to `container_dispose_elements` (`0x0839bdb4`) and
//! no predicated `bl`; two inbound plain `bl` sites are given by the assignment.
//!
//! ## Algorithm
//!
//! Install the derived destruction vtable, dispose every enabled container
//! element, then tail-chain to the registry-container base destructor. Its
//! return value is forwarded unchanged.
//!
//! ## Deliberate deviations
//!
//! Rust uses direct calls to the already ported callees on ARM instead of the
//! original tail branch. Host builds use narrow replaceable seams because the
//! target container has four-byte pointer fields while host pointers are wider.

use crate::app::class_registry::registry_container_destruct;
use crate::app::registry::Registry;
use crate::cxx::container_dispose_elements::container_dispose_elements;

const VTABLE_WORD: u32 = 0x0898_1e3c;

type DisposeElements = unsafe extern "C" fn(*mut u32);
type DestroyBase = unsafe extern "C" fn(*mut u32) -> *mut u32;

#[cfg(target_os = "none")]
unsafe fn dispose_elements(this: *mut u32) {
    unsafe { container_dispose_elements(this.cast()) };
}

#[cfg(target_os = "none")]
unsafe fn destroy_base(this: *mut u32) -> *mut u32 {
    unsafe { registry_container_destruct(this.cast::<Registry>()).cast() }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_dispose_elements(_this: *mut u32) {
    panic!("install vtable_08981e3c_destruct host seams before calling this port")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_destroy_base(_this: *mut u32) -> *mut u32 {
    panic!("install vtable_08981e3c_destruct host seams before calling this port")
}

/// Host replacements for direct calls to `0x0839bdb4` and `0x08135380`.
#[cfg(not(target_os = "none"))]
pub static mut VTABLE_08981E3C_DESTRUCT_OPS: (DisposeElements, DestroyBase) =
    (missing_dispose_elements, missing_destroy_base);

/// Disposes derived elements then chains to the registry-container destructor.
///
/// Original: `FUN_0839be5c` @ `0x0839be5c` (36 bytes including its literal;
/// two plain inbound `bl` sites and no predicated inbound `bl` sites).
///
/// # Safety
///
/// `this` must point to a writable aligned vtable word and satisfy both callee
/// contracts.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn vtable_08981e3c_destruct(this: *mut u32) -> *mut u32 {
    unsafe {
        this.write_volatile(VTABLE_WORD);
        #[cfg(target_os = "none")]
        {
            dispose_elements(this);
            destroy_base(this)
        }
        #[cfg(not(target_os = "none"))]
        {
            let (dispose, destroy) =
                core::ptr::read_volatile(core::ptr::addr_of!(VTABLE_08981E3C_DESTRUCT_OPS));
            dispose(this);
            destroy(this)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static STEP: AtomicUsize = AtomicUsize::new(0);
    static DISPOSED: AtomicUsize = AtomicUsize::new(0);
    static DESTROYED: AtomicUsize = AtomicUsize::new(0);
    static mut BASE_RETURN: *mut u32 = core::ptr::null_mut();

    unsafe extern "C" fn record_dispose(this: *mut u32) {
        assert_eq!(unsafe { this.read_volatile() }, VTABLE_WORD);
        DISPOSED.store(this as usize, Ordering::SeqCst);
        STEP.store(1, Ordering::SeqCst);
    }

    unsafe extern "C" fn record_base(this: *mut u32) -> *mut u32 {
        assert_eq!(STEP.load(Ordering::SeqCst), 1);
        DESTROYED.store(this as usize, Ordering::SeqCst);
        unsafe { BASE_RETURN }
    }

    #[test]
    fn installs_vtable_disposes_elements_then_forwards_base_return() {
        let _lock = LOCK.lock();
        let old = unsafe {
            core::ptr::read_volatile(core::ptr::addr_of!(VTABLE_08981E3C_DESTRUCT_OPS))
        };
        unsafe {
            core::ptr::addr_of_mut!(VTABLE_08981E3C_DESTRUCT_OPS)
                .write((record_dispose, record_base));
        }
        let mut object = [0xfeed_face; 11];
        let mut base_result = [0u32; 11];
        STEP.store(0, Ordering::SeqCst);
        DISPOSED.store(0, Ordering::SeqCst);
        DESTROYED.store(0, Ordering::SeqCst);
        unsafe { BASE_RETURN = base_result.as_mut_ptr(); }

        let result = unsafe { vtable_08981e3c_destruct(object.as_mut_ptr()) };

        assert_eq!(result, base_result.as_mut_ptr());
        assert_eq!(object[0], VTABLE_WORD);
        assert_eq!(DISPOSED.load(Ordering::SeqCst), object.as_ptr() as usize);
        assert_eq!(DESTROYED.load(Ordering::SeqCst), object.as_ptr() as usize);
        unsafe { core::ptr::addr_of_mut!(VTABLE_08981E3C_DESTRUCT_OPS).write(old); }
    }
}
