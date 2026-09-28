//! `vtable_089824fc_destruct` — retailOS `FUN_0839c5e8` @ `0x0839c5e8`.
//!
//! ## Verified extent and calls
//!
//! Raw `osos.dec` decodes ten ARM words: nine instructions from `0x0839c5e8`
//! through the tail `b` at `0x0839c608`, followed by vtable literal
//! `0x089824fc`; `0x0839c610` is the next real function. The true size is
//! **40 bytes** (36 instruction bytes plus the literal). The body has one
//! plain `bl` to `container_release_enabled_elements` (`0x0839c540`) and no
//! predicated `bl`; the final `b` chains to `registry_container_destruct`
//! (`0x08135380`). Full-image decoding finds two inbound plain `bl` sites
//! (`0x0811d9a0`, `0x08179070`) and no predicated inbound `bl` sites.
//!
//! ## Algorithm
//!
//! Install the derived destruction vtable, release every enabled element in
//! the container, then tail-chain to the registry-container base destructor.
//! Its return value is returned unchanged.
//!
//! ## Deliberate deviations
//!
//! Rust uses direct calls to the already ported callees on ARM instead of the
//! original tail branch. Host builds use narrow replaceable seams because the
//! target container has four-byte pointer fields while host pointers are wider.

use crate::app::registry::Registry;
use crate::app::class_registry::registry_container_destruct;
use crate::cxx::templates::{container_release_enabled_elements, ContainerReleaseEnabledElements};

const VTABLE_WORD: u32 = 0x0898_24fc;

type ReleaseElements = unsafe extern "C" fn(*mut u32);
type DestroyBase = unsafe extern "C" fn(*mut u32) -> *mut u32;

#[cfg(target_os = "none")]
unsafe fn release_elements(this: *mut u32) {
    unsafe { container_release_enabled_elements(this.cast::<ContainerReleaseEnabledElements>()) };
}

#[cfg(target_os = "none")]
unsafe fn destroy_base(this: *mut u32) -> *mut u32 {
    unsafe { registry_container_destruct(this.cast::<Registry>()).cast() }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_release_elements(_this: *mut u32) {
    panic!("install vtable_089824fc_destruct host seams before calling this port")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_destroy_base(_this: *mut u32) -> *mut u32 {
    panic!("install vtable_089824fc_destruct host seams before calling this port")
}

/// Host replacements for direct calls to `0x0839c540` and `0x08135380`.
#[cfg(not(target_os = "none"))]
pub static mut VTABLE_089824FC_DESTRUCT_OPS: (ReleaseElements, DestroyBase) =
    (missing_release_elements, missing_destroy_base);

/// Releases derived elements then chains to the registry-container destructor.
///
/// Original: `FUN_0839c5e8` @ `0x0839c5e8` (40 bytes including its literal;
/// two plain inbound `bl` sites and no predicated inbound `bl` sites).
///
/// # Safety
///
/// `this` must point to a writable aligned vtable word and satisfy both callee
/// contracts.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn vtable_089824fc_destruct(this: *mut u32) -> *mut u32 {
    unsafe {
        this.write_volatile(VTABLE_WORD);
        #[cfg(target_os = "none")]
        {
            release_elements(this);
            destroy_base(this)
        }
        #[cfg(not(target_os = "none"))]
        {
            let (release, destroy) =
                core::ptr::read_volatile(core::ptr::addr_of!(VTABLE_089824FC_DESTRUCT_OPS));
            release(this);
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
    static RELEASED: AtomicUsize = AtomicUsize::new(0);
    static DESTROYED: AtomicUsize = AtomicUsize::new(0);
    static mut BASE_RETURN: *mut u32 = core::ptr::null_mut();

    unsafe extern "C" fn record_release(this: *mut u32) {
        assert_eq!(unsafe { this.read_volatile() }, VTABLE_WORD);
        RELEASED.store(this as usize, Ordering::SeqCst);
        STEP.store(1, Ordering::SeqCst);
    }

    unsafe extern "C" fn record_base(this: *mut u32) -> *mut u32 {
        assert_eq!(STEP.load(Ordering::SeqCst), 1);
        DESTROYED.store(this as usize, Ordering::SeqCst);
        unsafe { BASE_RETURN }
    }

    #[test]
    fn installs_vtable_releases_elements_then_forwards_base_return() {
        let _lock = LOCK.lock();
        let old = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(VTABLE_089824FC_DESTRUCT_OPS)) };
        unsafe {
            core::ptr::addr_of_mut!(VTABLE_089824FC_DESTRUCT_OPS).write((record_release, record_base));
        }
        let mut object = [0xfeed_face; 10];
        let mut base_result = [0u32; 10];
        STEP.store(0, Ordering::SeqCst);
        RELEASED.store(0, Ordering::SeqCst);
        DESTROYED.store(0, Ordering::SeqCst);
        unsafe { BASE_RETURN = base_result.as_mut_ptr(); }

        let result = unsafe { vtable_089824fc_destruct(object.as_mut_ptr()) };

        assert_eq!(result, base_result.as_mut_ptr());
        assert_eq!(object[0], VTABLE_WORD);
        assert_eq!(RELEASED.load(Ordering::SeqCst), object.as_ptr() as usize);
        assert_eq!(DESTROYED.load(Ordering::SeqCst), object.as_ptr() as usize);
        unsafe { core::ptr::addr_of_mut!(VTABLE_089824FC_DESTRUCT_OPS).write(old); }
    }
}
