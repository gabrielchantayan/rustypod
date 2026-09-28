//! `vtable_08981fec_destruct` — retailOS `FUN_0839c0c4` @ `0x0839c0c4`.
//!
//! ## Verified extent and calls
//!
//! Raw `osos.dec` decodes nine ARM words: eight instructions from `0x0839c0c4`
//! through the tail `b` at `0x0839c0e4`, followed by vtable literal
//! `0x08981fec`; `0x0839c0ec` begins the next real function. The true size is
//! **36 bytes** (32 instruction bytes plus the literal). The body has one
//! plain `bl` to the unported assertion stage at `0x0839bfdc`, no predicated
//! `bl`, and one tail `b` to `registry_container_destruct` (`0x08135380`).
//! Whole-image A32 decoding finds two plain inbound `bl` sites (`0x08101bdc`
//! and `0x0811d910`) and no predicated inbound `bl` sites.
//!
//! ## Algorithm
//!
//! Install the derived destruction vtable, assert that every enabled element
//! has already been released, then tail-chain to the registry-container base
//! destructor and forward its return value.
//!
//! ## Deliberate deviations
//!
//! The assertion stage remains unported, so ARM reaches its verified fixed
//! address through a typed function pointer rather than the stock direct
//! `bl`. Rust calls the stock tail target normally. Host tests replace both
//! calls because host pointers do not preserve the target container layout.

use crate::app::class_registry::registry_container_destruct;
use crate::app::registry::Registry;

const VTABLE_WORD: u32 = 0x0898_1fec;

type AssertElementsReleased = unsafe extern "C" fn(*mut u32);
type DestroyBase = unsafe extern "C" fn(*mut u32) -> *mut u32;

#[cfg(target_os = "none")]
unsafe fn assert_elements_released(this: *mut u32) {
    let assert: AssertElementsReleased = unsafe { core::mem::transmute(0x0839_bfdcusize) };
    unsafe { assert(this) };
}

#[cfg(target_os = "none")]
unsafe fn destroy_base(this: *mut u32) -> *mut u32 {
    unsafe { registry_container_destruct(this.cast::<Registry>()).cast() }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_assert_elements_released(_this: *mut u32) {
    panic!("install vtable_08981fec_destruct host seams before calling this port")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_destroy_base(_this: *mut u32) -> *mut u32 {
    panic!("install vtable_08981fec_destruct host seams before calling this port")
}

/// Host replacements for direct calls to `0x0839bfdc` and `0x08135380`.
#[cfg(not(target_os = "none"))]
pub static mut VTABLE_08981FEC_DESTRUCT_OPS: (AssertElementsReleased, DestroyBase) =
    (missing_assert_elements_released, missing_destroy_base);

/// Asserts the derived elements are released, then chains to the base destructor.
///
/// Original: `FUN_0839c0c4` @ `0x0839c0c4` (36 bytes including its literal;
/// two plain inbound `bl` sites, no predicated inbound `bl` sites, one plain
/// body `bl`, and one tail `b`).
///
/// # Safety
///
/// `this` must point to a writable aligned vtable word and satisfy both callee
/// contracts.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn vtable_08981fec_destruct(this: *mut u32) -> *mut u32 {
    unsafe {
        this.write_volatile(VTABLE_WORD);
        #[cfg(target_os = "none")]
        {
            assert_elements_released(this);
            destroy_base(this)
        }
        #[cfg(not(target_os = "none"))]
        {
            let (assert, destroy) =
                core::ptr::read_volatile(core::ptr::addr_of!(VTABLE_08981FEC_DESTRUCT_OPS));
            assert(this);
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
    static ASSERTED: AtomicUsize = AtomicUsize::new(0);
    static DESTROYED: AtomicUsize = AtomicUsize::new(0);
    static mut BASE_RETURN: *mut u32 = core::ptr::null_mut();

    unsafe extern "C" fn record_assert(this: *mut u32) {
        assert_eq!(unsafe { this.read_volatile() }, VTABLE_WORD);
        ASSERTED.store(this as usize, Ordering::SeqCst);
        STEP.store(1, Ordering::SeqCst);
    }

    unsafe extern "C" fn record_base(this: *mut u32) -> *mut u32 {
        assert_eq!(STEP.load(Ordering::SeqCst), 1);
        DESTROYED.store(this as usize, Ordering::SeqCst);
        unsafe { BASE_RETURN }
    }

    #[test]
    fn installs_vtable_asserts_then_forwards_base_return() {
        let _lock = LOCK.lock();
        let old = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(VTABLE_08981FEC_DESTRUCT_OPS)) };
        unsafe {
            core::ptr::addr_of_mut!(VTABLE_08981FEC_DESTRUCT_OPS).write((record_assert, record_base));
        }
        let mut object = [0xfeed_face; 10];
        let mut base_result = [0u32; 10];
        STEP.store(0, Ordering::SeqCst);
        ASSERTED.store(0, Ordering::SeqCst);
        DESTROYED.store(0, Ordering::SeqCst);
        unsafe { BASE_RETURN = base_result.as_mut_ptr(); }

        let result = unsafe { vtable_08981fec_destruct(object.as_mut_ptr()) };

        assert_eq!(result, base_result.as_mut_ptr());
        assert_eq!(object[0], VTABLE_WORD);
        assert_eq!(ASSERTED.load(Ordering::SeqCst), object.as_ptr() as usize);
        assert_eq!(DESTROYED.load(Ordering::SeqCst), object.as_ptr() as usize);
        unsafe { core::ptr::addr_of_mut!(VTABLE_08981FEC_DESTRUCT_OPS).write(old); }
    }
}
