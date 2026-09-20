//! `vtable_08982784_destruct` — retailOS `FUN_0839c888` @ `0x0839c888`.
//!
//! ## Verified extent and calls
//!
//! Raw `osos.dec` decodes nine ARM words: eight instruction bytes from
//! `0x0839c888` through the tail `b` at `0x0839c8a8`, followed by the vtable
//! literal `0x08982784` at `0x0839c8ac`; `0x0839c8b0` starts the next real
//! function. The true size is **36 bytes**. Its body has one plain `bl` to
//! `0x0839c7d4` and a tail `b` to `0x08275380`. Decoding every ARM B/BL word
//! finds three inbound plain `bl` sites and no predicated `bl` sites.
//!
//! ## Algorithm
//!
//! Install the derived destruction vtable, destroy the derived indexed state
//! through `0x0839c7d4`, then tail-chain into the unresolved base destructor
//! at `0x08275380`. Neither callee's complete class identity is established,
//! so the names describe only the observed destructor roles.
//!
//! Deliberate deviations: Rust represents both unported direct calls as
//! fixed-address firmware calls and replaceable host seams; it cannot retain
//! the literal ARM tail branch.

const VTABLE_WORD: u32 = 0x0898_2784;

type DestroyDerivedState = unsafe extern "C" fn(*mut u32);
type DestroyBase = unsafe extern "C" fn(*mut u32) -> *mut u32;

#[cfg(target_os = "none")]
unsafe fn destroy_derived_state(this: *mut u32) {
    let destroy: DestroyDerivedState = unsafe { core::mem::transmute(0x0839_c7d4usize) };
    unsafe { destroy(this) };
}

#[cfg(target_os = "none")]
unsafe fn destroy_base(this: *mut u32) -> *mut u32 {
    let destroy: DestroyBase = unsafe { core::mem::transmute(0x0827_5380usize) };
    unsafe { destroy(this) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_destroy_derived_state(_this: *mut u32) {
    panic!("install vtable_08982784_destruct host seams before calling this port")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_destroy_base(_this: *mut u32) -> *mut u32 {
    panic!("install vtable_08982784_destruct host seams before calling this port")
}

/// Host replacements for direct calls to `0x0839c7d4` and `0x08275380`.
#[cfg(not(target_os = "none"))]
pub static mut VTABLE_08982784_DESTRUCT_OPS: (DestroyDerivedState, DestroyBase) =
    (missing_destroy_derived_state, missing_destroy_base);

/// Destroys derived indexed state and tail-chains into its unresolved base.
///
/// Original: `FUN_0839c888` @ `0x0839c888` (36 bytes; three plain inbound
/// `bl` sites, no predicated inbound `bl` sites).
///
/// # Safety
///
/// `this` must point to a writable aligned vtable word and satisfy both
/// unported destructor contracts.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn vtable_08982784_destruct(this: *mut u32) -> *mut u32 {
    unsafe {
        this.write_volatile(VTABLE_WORD);
        #[cfg(target_os = "none")]
        {
            destroy_derived_state(this);
            destroy_base(this)
        }
        #[cfg(not(target_os = "none"))]
        {
            let (destroy_derived, destroy_base) =
                core::ptr::read_volatile(core::ptr::addr_of!(VTABLE_08982784_DESTRUCT_OPS));
            destroy_derived(this);
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
    static DERIVED: AtomicUsize = AtomicUsize::new(0);
    static BASE: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn record_derived(this: *mut u32) {
        DERIVED.store(this as usize, Ordering::SeqCst);
        STEP.store(1, Ordering::SeqCst);
    }

    unsafe extern "C" fn record_base(this: *mut u32) -> *mut u32 {
        assert_eq!(STEP.load(Ordering::SeqCst), 1);
        BASE.store(this as usize, Ordering::SeqCst);
        this
    }

    #[test]
    fn installs_vtable_then_runs_destructors_in_order_and_forwards_return() {
        let _lock = LOCK.lock();
        let old = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(VTABLE_08982784_DESTRUCT_OPS)) };
        unsafe { core::ptr::addr_of_mut!(VTABLE_08982784_DESTRUCT_OPS).write((record_derived, record_base)); }
        let mut object = [0xfeed_face, 0xdead_beef];
        STEP.store(0, Ordering::SeqCst);
        DERIVED.store(0, Ordering::SeqCst);
        BASE.store(0, Ordering::SeqCst);
        let result = unsafe { vtable_08982784_destruct(object.as_mut_ptr()) };
        assert_eq!(result, object.as_mut_ptr());
        assert_eq!(object[0], VTABLE_WORD);
        assert_eq!(DERIVED.load(Ordering::SeqCst), object.as_ptr() as usize);
        assert_eq!(BASE.load(Ordering::SeqCst), object.as_ptr() as usize);
        unsafe { core::ptr::addr_of_mut!(VTABLE_08982784_DESTRUCT_OPS).write(old); }
    }
}
