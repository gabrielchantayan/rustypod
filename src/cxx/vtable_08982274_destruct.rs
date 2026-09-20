//! `vtable_08982274_destruct` — retailOS `FUN_0839c358` @ `0x0839c358`.
//!
//! ## Verified extent and calls
//!
//! Raw `osos.dec` decodes nine ARM words: eight instructions from `0x0839c358`
//! through the tail `b` at `0x0839c378`, followed by vtable literal
//! `0x08982274` at `0x0839c37c`; `0x0839c380` starts the next real function.
//! The true size is **36 bytes**. Its body has one plain `bl` to the derived
//! validation destructor at `0x0839c298` and a tail `b` to the unresolved base
//! destructor at `0x08135380`. Decoding every ARM B/BL word finds three inbound
//! plain `bl` sites and no predicated `bl` sites.
//!
//! ## Algorithm
//!
//! Install the derived destruction vtable, validate that the derived indexed
//! state has no live elements through `0x0839c298`, then tail-chain into the
//! base destructor at `0x08135380`. The complete class identity is not
//! established, so the name describes the observed vtable destructor role.
//!
//! Deliberate deviations: Rust represents both unported direct calls as fixed-
//! address firmware calls and replaceable host seams; it cannot retain the
//! literal ARM tail branch.

const VTABLE_WORD: u32 = 0x0898_2274;

type ValidateDerivedState = unsafe extern "C" fn(*mut u32);
type DestroyBase = unsafe extern "C" fn(*mut u32) -> *mut u32;

#[cfg(target_os = "none")]
unsafe fn validate_derived_state(this: *mut u32) {
    let validate: ValidateDerivedState = unsafe { core::mem::transmute(0x0839_c298usize) };
    unsafe { validate(this) };
}

#[cfg(target_os = "none")]
unsafe fn destroy_base(this: *mut u32) -> *mut u32 {
    let destroy: DestroyBase = unsafe { core::mem::transmute(0x0813_5380usize) };
    unsafe { destroy(this) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_validate_derived_state(_this: *mut u32) {
    panic!("install vtable_08982274_destruct host seams before calling this port")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_destroy_base(_this: *mut u32) -> *mut u32 {
    panic!("install vtable_08982274_destruct host seams before calling this port")
}

/// Host replacements for direct calls to `0x0839c298` and `0x08135380`.
#[cfg(not(target_os = "none"))]
pub static mut VTABLE_08982274_DESTRUCT_OPS: (ValidateDerivedState, DestroyBase) =
    (missing_validate_derived_state, missing_destroy_base);

/// Validates derived state then tail-chains into its unresolved base destructor.
///
/// Original: `FUN_0839c358` @ `0x0839c358` (36 bytes; three plain inbound
/// `bl` sites, no predicated inbound `bl` sites).
///
/// # Safety
///
/// `this` must point to a writable aligned vtable word and satisfy both
/// unported destructor contracts.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn vtable_08982274_destruct(this: *mut u32) -> *mut u32 {
    unsafe {
        this.write_volatile(VTABLE_WORD);
        #[cfg(target_os = "none")]
        {
            validate_derived_state(this);
            destroy_base(this)
        }
        #[cfg(not(target_os = "none"))]
        {
            let (validate_derived, destroy_base) =
                core::ptr::read_volatile(core::ptr::addr_of!(VTABLE_08982274_DESTRUCT_OPS));
            validate_derived(this);
            destroy_base(this)
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
    static VALIDATED: AtomicUsize = AtomicUsize::new(0);
    static BASE: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn record_validation(this: *mut u32) {
        assert_eq!(unsafe { this.read_volatile() }, VTABLE_WORD);
        VALIDATED.store(this as usize, Ordering::SeqCst);
        STEP.store(1, Ordering::SeqCst);
    }

    unsafe extern "C" fn record_base(this: *mut u32) -> *mut u32 {
        assert_eq!(STEP.load(Ordering::SeqCst), 1);
        BASE.store(this as usize, Ordering::SeqCst);
        this
    }

    #[test]
    fn installs_vtable_then_validates_and_forwards_base_return() {
        let _lock = LOCK.lock();
        let old = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(VTABLE_08982274_DESTRUCT_OPS)) };
        unsafe { core::ptr::addr_of_mut!(VTABLE_08982274_DESTRUCT_OPS).write((record_validation, record_base)); }
        let mut object = [0xfeed_face, 0xdead_beef];
        STEP.store(0, Ordering::SeqCst);
        VALIDATED.store(0, Ordering::SeqCst);
        BASE.store(0, Ordering::SeqCst);
        let result = unsafe { vtable_08982274_destruct(object.as_mut_ptr()) };
        assert_eq!(result, object.as_mut_ptr());
        assert_eq!(object[0], VTABLE_WORD);
        assert_eq!(VALIDATED.load(Ordering::SeqCst), object.as_ptr() as usize);
        assert_eq!(BASE.load(Ordering::SeqCst), object.as_ptr() as usize);
        unsafe { core::ptr::addr_of_mut!(VTABLE_08982274_DESTRUCT_OPS).write(old); }
    }
}
