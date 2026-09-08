//! `global_observer_unregister` — original: `FUN_081bb510` @ `0x081bb510`
//! (40 bytes, `0x081bb510..0x081bb538`; Ghidra reports 39 bytes).
//!
//! Raw ARM saves the incoming object pointer, stores it in a stack-local word,
//! obtains the global observer through `FUN_080b43e8`, and calls vtable slot
//! `+0x28` with the observer and the address of that local word. It then returns
//! the original object pointer even if the callback rewrites the local value.
//! The adjacent tick-accumulator constructor registers the same pointer form
//! through slot `+0x1c`; therefore `unregister` is an inferred role, not a
//! claimed concrete observer identity.
//!
//! **20 direct `bl` call sites, all unconditional and no predicated `bl`**,
//! verified by decoding every ARM B/BL word in `work/firmware/osos.dec`.
//! Deliberate deviation: `FUN_080b43e8` remains in retailOS, so target builds
//! call its fixed address while host tests install a getter seam.

use core::ptr::{addr_of, addr_of_mut};

const RETAIL_GLOBAL_OBSERVER_GETTER: usize = 0x080b_43e8;

/// Opaque global observer whose first word is its vtable.
#[repr(C)]
pub struct GlobalObserver {
    pub vtable: *const GlobalObserverVtable,
}

/// Recovered portion of the global observer vtable.
///
/// On the 32-bit target, `unregister` is exactly slot `+0x28`. Host pointer
/// widths differ, so this structural layout deliberately models the slot role.
#[repr(C)]
pub struct GlobalObserverVtable {
    pub unresolved_00_24: [usize; 10],
    pub unregister: unsafe extern "C" fn(*mut GlobalObserver, *mut *mut u8),
}

/// ABI of the still-unported global-observer getter at `0x080b43e8`.
pub type GlobalObserverGetter = unsafe extern "C" fn() -> *mut GlobalObserver;

/// Host seam for the global observer getter.
#[derive(Clone, Copy)]
pub struct GlobalObserverUnregisterOps {
    pub get_observer: GlobalObserverGetter,
}

#[cfg(target_os = "none")]
unsafe fn retail_global_observer() -> *mut GlobalObserver {
    let getter: GlobalObserverGetter = core::mem::transmute(RETAIL_GLOBAL_OBSERVER_GETTER);
    getter()
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_global_observer() -> *mut GlobalObserver {
    panic!("install global observer host operations before unregistering")
}

/// Host default before a test installs the retail observer equivalent.
#[cfg(not(target_os = "none"))]
pub const DEFAULT_GLOBAL_OBSERVER_UNREGISTER_OPS: GlobalObserverUnregisterOps =
    GlobalObserverUnregisterOps { get_observer: missing_global_observer };

/// Host-side getter seam. Callers on the target always use `0x080b43e8`.
#[cfg(not(target_os = "none"))]
pub static mut GLOBAL_OBSERVER_UNREGISTER_OPS: GlobalObserverUnregisterOps =
    DEFAULT_GLOBAL_OBSERVER_UNREGISTER_OPS;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn host_global_observer() -> *mut GlobalObserver {
    let getter = core::ptr::read_volatile(addr_of!(GLOBAL_OBSERVER_UNREGISTER_OPS.get_observer));
    getter()
}

/// global_observer_unregister — original: `FUN_081bb510` @ `0x081bb510`
/// (40 bytes; **20 unconditional direct `bl` sites and no predicated forms**).
///
/// Passes the address of a temporary object-pointer word to the global
/// observer's `+0x28` callback, then returns `object` unchanged. The original
/// dereferences neither `object` nor its contents; a NULL object is forwarded
/// unchanged. It has no guards for the observer, vtable, or callback.
///
/// # Safety
///
/// The global observer getter must return a non-NULL object with a readable
/// vtable and a valid `+0x28` callback. The callback receives a pointer to a
/// stack-local `object` word and must not retain it after returning.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn global_observer_unregister(object: *mut u8) -> *mut u8 {
    let mut callback_object = object;
    #[cfg(target_os = "none")]
    let observer = retail_global_observer();
    #[cfg(not(target_os = "none"))]
    let observer = host_global_observer();
    let vtable = core::ptr::read_volatile(addr_of!((*observer).vtable));
    ((*vtable).unregister)(observer, addr_of_mut!(callback_object));
    object
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr::{addr_of, addr_of_mut};
    use std::sync::{Mutex, MutexGuard};

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut GETTER_CALLS: u32 = 0;
    static mut UNREGISTER_CALLS: u32 = 0;
    static mut SEEN_OBSERVER: *mut GlobalObserver = core::ptr::null_mut();
    static mut SEEN_OBJECT: *mut u8 = core::ptr::null_mut();

    unsafe extern "C" fn record_unregister(
        observer: *mut GlobalObserver,
        object: *mut *mut u8,
    ) {
        UNREGISTER_CALLS += 1;
        SEEN_OBSERVER = observer;
        SEEN_OBJECT = object.read();
        object.write(core::ptr::null_mut());
    }

    static VTABLE: GlobalObserverVtable = GlobalObserverVtable {
        unresolved_00_24: [0; 10],
        unregister: record_unregister,
    };
    static mut OBSERVER: GlobalObserver = GlobalObserver { vtable: &VTABLE };

    unsafe extern "C" fn record_get_observer() -> *mut GlobalObserver {
        GETTER_CALLS += 1;
        addr_of_mut!(OBSERVER)
    }

    fn install_recorder() -> MutexGuard<'static, ()> {
        let guard = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            addr_of_mut!(GETTER_CALLS).write(0);
            addr_of_mut!(UNREGISTER_CALLS).write(0);
            addr_of_mut!(SEEN_OBSERVER).write(core::ptr::null_mut());
            addr_of_mut!(SEEN_OBJECT).write(core::ptr::null_mut());
            addr_of_mut!(OBSERVER).write(GlobalObserver { vtable: &VTABLE });
            addr_of_mut!(GLOBAL_OBSERVER_UNREGISTER_OPS).write(GlobalObserverUnregisterOps {
                get_observer: record_get_observer,
            });
        }
        guard
    }

    fn restore_default(guard: MutexGuard<'static, ()>) {
        unsafe {
            addr_of_mut!(GLOBAL_OBSERVER_UNREGISTER_OPS)
                .write(DEFAULT_GLOBAL_OBSERVER_UNREGISTER_OPS);
        }
        drop(guard);
    }

    #[test]
    fn invokes_slot_28_once_with_an_indirect_object_word() {
        let guard = install_recorder();
        let mut object = [0x5au8; 4];
        let returned = unsafe { global_observer_unregister(object.as_mut_ptr()) };

        unsafe {
            assert_eq!(addr_of!(GETTER_CALLS).read(), 1);
            assert_eq!(addr_of!(UNREGISTER_CALLS).read(), 1);
            assert_eq!(addr_of!(SEEN_OBSERVER).read(), addr_of_mut!(OBSERVER));
            assert_eq!(addr_of!(SEEN_OBJECT).read(), object.as_mut_ptr());
        }
        assert_eq!(returned, object.as_mut_ptr());
        restore_default(guard);
    }

    #[test]
    fn forwards_and_returns_a_null_object_without_dereferencing_it() {
        let guard = install_recorder();
        let returned = unsafe { global_observer_unregister(core::ptr::null_mut()) };

        unsafe {
            assert_eq!(addr_of!(GETTER_CALLS).read(), 1);
            assert_eq!(addr_of!(UNREGISTER_CALLS).read(), 1);
            assert!(addr_of!(SEEN_OBJECT).read().is_null());
        }
        assert!(returned.is_null());
        restore_default(guard);
    }
}
