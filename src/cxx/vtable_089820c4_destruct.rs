//! `vtable_089820c4_destruct` — retailOS `FUN_0839c1a0` @ `0x0839c1a0`.
//!
//! ## Verified extent and calls
//!
//! Raw `osos.dec` decodes nine ARM words: eight instructions from `0x0839c1a0`
//! through the tail `b` at `0x0839c1c0`, followed by vtable literal
//! `0x089820c4`; `0x0839c1c8` is the next real function. The true size is
//! **36 bytes** (32 instruction bytes plus the literal). The body has one
//! plain `bl` to the unported release stage at `0x0839c0ec`, no predicated
//! `bl`, and one tail `b` to `registry_container_destruct` (`0x08135380`).
//!
//! ## Algorithm
//!
//! Install the derived destruction vtable, release each enabled item through
//! the preceding release stage, then tail-chain to the registry-container base
//! destructor and forward its return value.
//!
//! ## Deliberate deviations
//!
//! The unported release stage remains a fixed-address call on ARM and an
//! injectable host seam. The stock tail branch is a regular Rust call to the
//! already ported base destructor.

use crate::app::class_registry::registry_container_destruct;
use crate::app::registry::Registry;

const VTABLE_WORD: u32 = 0x0898_20c4;
const RETAIL_RELEASE_ENABLED_ITEMS: usize = 0x0839_c0ec;

type ReleaseEnabledItems = unsafe extern "C" fn(*mut u32);
type DestroyBase = unsafe extern "C" fn(*mut u32) -> *mut u32;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn release_enabled_items(this: *mut u32) {
    let release: ReleaseEnabledItems = unsafe { core::mem::transmute(RETAIL_RELEASE_ENABLED_ITEMS) };
    unsafe { release(this) };
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn destroy_base(this: *mut u32) -> *mut u32 {
    unsafe { registry_container_destruct(this.cast::<Registry>()).cast() }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_release_enabled_items(_this: *mut u32) {
    panic!("install vtable_089820c4_destruct host seams before calling this port")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_destroy_base(_this: *mut u32) -> *mut u32 {
    panic!("install vtable_089820c4_destruct host seams before calling this port")
}

/// Host replacements for the direct calls to `0x0839c0ec` and `0x08135380`.
#[cfg(not(target_os = "none"))]
pub static mut VTABLE_089820C4_DESTRUCT_OPS: (ReleaseEnabledItems, DestroyBase) =
    (missing_release_enabled_items, missing_destroy_base);

/// Releases enabled items then chains to the registry-container destructor.
///
/// Original: `FUN_0839c1a0` @ `0x0839c1a0` (36 bytes including its literal;
/// one plain body `bl`, no predicated body `bl`, and one tail `b`).
///
/// # Safety
///
/// `this` must point to a writable aligned vtable word and satisfy both callee
/// contracts.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn vtable_089820c4_destruct(this: *mut u32) -> *mut u32 {
    unsafe {
        this.write_volatile(VTABLE_WORD);
        #[cfg(target_os = "none")]
        {
            release_enabled_items(this);
            destroy_base(this)
        }
        #[cfg(not(target_os = "none"))]
        {
            let (release, destroy) =
                core::ptr::read_volatile(core::ptr::addr_of!(VTABLE_089820C4_DESTRUCT_OPS));
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
    fn installs_vtable_releases_enabled_items_then_forwards_base_return() {
        let _lock = LOCK.lock();
        let old = unsafe {
            core::ptr::read_volatile(core::ptr::addr_of!(VTABLE_089820C4_DESTRUCT_OPS))
        };
        unsafe {
            core::ptr::addr_of_mut!(VTABLE_089820C4_DESTRUCT_OPS)
                .write((record_release, record_base));
        }
        let mut object = [0xfeed_face; 11];
        let mut base_result = [0u32; 11];
        STEP.store(0, Ordering::SeqCst);
        RELEASED.store(0, Ordering::SeqCst);
        DESTROYED.store(0, Ordering::SeqCst);
        unsafe { BASE_RETURN = base_result.as_mut_ptr(); }

        let result = unsafe { vtable_089820c4_destruct(object.as_mut_ptr()) };

        assert_eq!(result, base_result.as_mut_ptr());
        assert_eq!(object[0], VTABLE_WORD);
        assert_eq!(RELEASED.load(Ordering::SeqCst), object.as_ptr() as usize);
        assert_eq!(DESTROYED.load(Ordering::SeqCst), object.as_ptr() as usize);
        unsafe { core::ptr::addr_of_mut!(VTABLE_089820C4_DESTRUCT_OPS).write(old); }
    }
}
