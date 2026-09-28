//! `vtable_08982424_destruct` — retailOS `FUN_0839c518` @ `0x0839c518`.
//!
//! ## Verified extent and calls
//!
//! Raw `osos.dec` decodes nine ARM words: eight instructions from `0x0839c518`
//! through the tail `b` at `0x0839c538`, followed by vtable literal
//! `0x08982424`; `0x0839c540` is the next real function. The true size is
//! **36 bytes** (32 instruction bytes plus the literal). The body has one
//! plain `bl` to `vtable_slot_40_release_each` (`0x0839c470`) and no
//! predicated `bl`; full-image branch decoding finds two inbound plain `bl`
//! sites (`0x0811d988`, `0x08179068`) and no predicated inbound `bl` sites.
//!
//! ## Algorithm
//!
//! Install the derived destruction vtable, release each allocation supplied
//! through vtable slot `+0x40`, then tail-chain to the registry-container base
//! destructor. Its return value is forwarded unchanged.
//!
//! ## Deliberate deviations
//!
//! Rust uses direct calls to the already ported callees on ARM instead of the
//! original tail branch. Host builds use narrow replaceable seams because the
//! target container has four-byte pointer fields while host pointers are wider.

use crate::app::class_registry::registry_container_destruct;
use crate::app::registry::Registry;
use crate::util::vtable_slot_40_release_each::vtable_slot_40_release_each;

const VTABLE_WORD: u32 = 0x0898_2424;

type ReleaseEach = unsafe extern "C" fn(*mut u32);
type DestroyBase = unsafe extern "C" fn(*mut u32) -> *mut u32;

#[cfg(target_os = "none")]
unsafe fn release_each(this: *mut u32) {
    unsafe { vtable_slot_40_release_each(this.cast()) };
}

#[cfg(target_os = "none")]
unsafe fn destroy_base(this: *mut u32) -> *mut u32 {
    unsafe { registry_container_destruct(this.cast::<Registry>()).cast() }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_release_each(_this: *mut u32) {
    panic!("install vtable_08982424_destruct host seams before calling this port")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_destroy_base(_this: *mut u32) -> *mut u32 {
    panic!("install vtable_08982424_destruct host seams before calling this port")
}

/// Host replacements for direct calls to `0x0839c470` and `0x08135380`.
#[cfg(not(target_os = "none"))]
pub static mut VTABLE_08982424_DESTRUCT_OPS: (ReleaseEach, DestroyBase) =
    (missing_release_each, missing_destroy_base);

/// Releases derived allocations then chains to the registry-container destructor.
///
/// Original: `FUN_0839c518` @ `0x0839c518` (36 bytes including its literal;
/// two plain inbound `bl` sites and no predicated inbound `bl` sites).
///
/// # Safety
///
/// `this` must point to a writable aligned vtable word and satisfy both callee
/// contracts.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn vtable_08982424_destruct(this: *mut u32) -> *mut u32 {
    unsafe {
        this.write_volatile(VTABLE_WORD);
        #[cfg(target_os = "none")]
        {
            release_each(this);
            destroy_base(this)
        }
        #[cfg(not(target_os = "none"))]
        {
            let (release, destroy) =
                core::ptr::read_volatile(core::ptr::addr_of!(VTABLE_08982424_DESTRUCT_OPS));
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
    fn installs_vtable_releases_each_then_forwards_base_return() {
        let _lock = LOCK.lock();
        let old = unsafe {
            core::ptr::read_volatile(core::ptr::addr_of!(VTABLE_08982424_DESTRUCT_OPS))
        };
        unsafe {
            core::ptr::addr_of_mut!(VTABLE_08982424_DESTRUCT_OPS)
                .write((record_release, record_base));
        }
        let mut object = [0xfeed_face; 11];
        let mut base_result = [0u32; 11];
        STEP.store(0, Ordering::SeqCst);
        RELEASED.store(0, Ordering::SeqCst);
        DESTROYED.store(0, Ordering::SeqCst);
        unsafe { BASE_RETURN = base_result.as_mut_ptr(); }

        let result = unsafe { vtable_08982424_destruct(object.as_mut_ptr()) };

        assert_eq!(result, base_result.as_mut_ptr());
        assert_eq!(object[0], VTABLE_WORD);
        assert_eq!(RELEASED.load(Ordering::SeqCst), object.as_ptr() as usize);
        assert_eq!(DESTROYED.load(Ordering::SeqCst), object.as_ptr() as usize);
        unsafe { core::ptr::addr_of_mut!(VTABLE_08982424_DESTRUCT_OPS).write(old); }
    }
}
