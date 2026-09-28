//! `class_6280_owned_element_array_destruct` — retailOS `FUN_0839ca74` @
//! `0x0839ca74`.
//!
//! ## Verified extent and calls
//!
//! Raw `osos.dec` words establish the 36-byte extent
//! `0x0839ca74..0x0839ca97`: eight instruction words followed by vtable
//! literal `0x08982934` at `0x0839ca98`; the next independent function starts
//! at `0x0839ca9c`. It has one direct plain `bl` (to
//! [`owned_element_array_dispose`]), no predicated `bl`, and one tail `b` to
//! [`registry_container_destruct`].
//!
//! ## Algorithm
//!
//! Install the class-0x6280 embedded owned-element-array vtable, dispose its
//! enabled owned elements, then tail-chain to the registry-container
//! destructor. The original preserves `this` in r4 across the direct call and
//! returns the tail callee's result.
//!
//! Deliberate deviation: host tests replace the final direct tail branch with
//! a local seam because the registry destructor's host layout contains
//! native-width pointers; firmware builds call it directly.

use crate::app::class_registry::registry_container_destruct;
use crate::cxx::owned_element_array_dispose::{owned_element_array_dispose, OwnedElementArrayDispose};

/// Vtable literal at `0x0839ca98`, installed before disposal.
pub const CLASS_6280_OWNED_ELEMENT_ARRAY_VTABLE: u32 = 0x0898_2934;

#[cfg(test)]
unsafe extern "C" fn host_class_6280_registry_destruct(this: *mut u8) -> *mut u8 {
    this
}

#[cfg(test)]
static mut CLASS_6280_REGISTRY_DESTRUCT: unsafe extern "C" fn(*mut u8) -> *mut u8 =
    host_class_6280_registry_destruct;

/// Destructs the class-0x6280 owned-element-array subobject.
///
/// # Safety
///
/// `this` must address a writable `OwnedElementArrayDispose` prefix and a
/// valid registry-container base accepted by `registry_container_destruct`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn class_6280_owned_element_array_destruct(this: *mut u8) -> *mut u8 {
    unsafe { this.cast::<u32>().write_volatile(CLASS_6280_OWNED_ELEMENT_ARRAY_VTABLE) };
    unsafe { owned_element_array_dispose(this.cast::<OwnedElementArrayDispose>()) };

    #[cfg(test)]
    {
        let destruct = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(CLASS_6280_REGISTRY_DESTRUCT)) };
        unsafe { destruct(this) }
    }

    #[cfg(not(test))]
    unsafe { registry_container_destruct(this.cast()).cast() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut OBSERVED_THIS: *mut u8 = core::ptr::null_mut();
    static mut OBSERVED_VTABLE: u32 = 0;

    unsafe extern "C" fn observe_registry_destruct(this: *mut u8) -> *mut u8 {
        unsafe {
            OBSERVED_THIS = this;
            OBSERVED_VTABLE = this.cast::<u32>().read_volatile();
        }
        this
    }

    #[test]
    fn installs_embedded_vtable_before_tail_chaining_when_array_is_disabled() {
        let _guard = LOCK.lock();
        let mut object = [0u32; 11];
        object[0] = 0xdead_beef;
        unsafe {
            OBSERVED_THIS = core::ptr::null_mut();
            OBSERVED_VTABLE = 0;
            let old = core::ptr::read_volatile(core::ptr::addr_of!(CLASS_6280_REGISTRY_DESTRUCT));
            CLASS_6280_REGISTRY_DESTRUCT = observe_registry_destruct;

            let this = object.as_mut_ptr().cast::<u8>();
            assert_eq!(class_6280_owned_element_array_destruct(this), this);
            assert_eq!(OBSERVED_THIS, this);
            assert_eq!(OBSERVED_VTABLE, CLASS_6280_OWNED_ELEMENT_ARRAY_VTABLE);
            assert_eq!(object[0], CLASS_6280_OWNED_ELEMENT_ARRAY_VTABLE);

            CLASS_6280_REGISTRY_DESTRUCT = old;
        }
    }
}
