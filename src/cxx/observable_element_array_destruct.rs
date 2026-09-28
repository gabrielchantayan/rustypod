//! `observable_element_array_destruct` — retailOS `FUN_0839c270` @
//! `0x0839c270`.
//!
//! Raw ARM is exactly 40 bytes, `0x0839c270..0x0839c294`: nine code words
//! followed by the vtable literal `0x0898219c`; the next real function begins
//! with `push {r4,r5,r6,lr}` at `0x0839c298`. Decoding every aligned ARM
//! B/BL-immediate word in `osos.dec` finds two plain inbound `bl` sites
//! (`0x0811d940`, `0x081282e4`) and zero predicated `bl` sites.
//!
//! # Algorithm
//!
//! Install this derived object's vtable, dispose its indexed elements through
//! `FUN_0839c1c8`, then tail-branch to the ported
//! [`registry_container_destruct`] at `0x08135380`. The raw words prove the
//! final target and the call order, but do not establish a more specific class
//! identity for the `0x0898219c` vtable.
//!
//! Deliberate deviation: the stock direct `bl` to the unresolved element
//! disposal stage uses the existing direct-call seam so host tests can model
//! it; target builds still call its verified retailOS address. The final stock
//! tail branch is a regular Rust call into the existing port.

use crate::app::class_registry::registry_container_destruct;
use crate::app::registry::{Registry, RegistryVtable};
use crate::cxx::observable_element_array_clear::OBSERVABLE_ELEMENT_ARRAY_DISPOSE_ITEMS;
use crate::cxx::observable_array::ObservableArray;

/// Vtable literal loaded from `0x0839c294` and installed at object offset
/// `+0x00` before the element-disposal stage.
pub const OBSERVABLE_ELEMENT_ARRAY_VTABLE_ADDRESS: usize = 0x0898_219c;

/// Disposes indexed elements, then destructs the registry-container base.
///
/// Original: `FUN_0839c270` @ `0x0839c270` (40 bytes: nine instructions and
/// the trailing vtable literal; two plain inbound `bl` sites and no predicated
/// inbound `bl` sites, binary-decoded from `osos.dec`).
///
/// # Safety
///
/// `this` must be a writable instance accepted by both the unresolved element
/// disposal stage and [`registry_container_destruct`]. Neither stock stage
/// guards `this`, its observer, or the observer vtable.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.observable_element_array_destruct")]
pub unsafe extern "C" fn observable_element_array_destruct(this: *mut Registry) -> *mut Registry {
    core::ptr::write_volatile(
        core::ptr::addr_of_mut!((*this).vtable),
        OBSERVABLE_ELEMENT_ARRAY_VTABLE_ADDRESS as *const RegistryVtable,
    );
    let dispose_items = core::ptr::read_volatile(core::ptr::addr_of!(
        OBSERVABLE_ELEMENT_ARRAY_DISPOSE_ITEMS
    ));
    dispose_items(this.cast::<ObservableArray>());
    registry_container_destruct(this)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::app::class_registry::{RegistryObserver, RegistryObserverVtable, REGISTRY_CONTAINER_VTABLE_ADDRESS};
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static EVENTS: Mutex<std::vec::Vec<usize>> = Mutex::new(std::vec::Vec::new());

    unsafe extern "C" fn record_dispose_items(this: *mut ObservableArray) {
        EVENTS.lock().push(unsafe { (*(this.cast::<Registry>())).vtable as usize });
    }

    unsafe extern "C" fn record_detach(_this: *mut RegistryObserver) -> *mut u8 {
        EVENTS.lock().push(0);
        core::ptr::null_mut()
    }

    #[test]
    fn installs_derived_vtable_before_disposal_then_destructs_base() {
        let _guard = TEST_LOCK.lock();
        EVENTS.lock().clear();
        let observer_vtable = RegistryObserverVtable {
            unresolved_00: [0; 6],
            attach: record_detach,
            detach: record_detach,
        };
        let mut observer = RegistryObserver { vtable: &observer_vtable, state: 0 };
        let mut registry = Registry {
            vtable: core::ptr::null(),
            container: [0; 7],
            changed: 0,
            notify_enabled: 0,
            reserved: [0; 2],
            observer: (&mut observer as *mut RegistryObserver).cast(),
        };

        unsafe { OBSERVABLE_ELEMENT_ARRAY_DISPOSE_ITEMS = record_dispose_items };
        let returned = unsafe { observable_element_array_destruct(&mut registry) };
        unsafe {
            OBSERVABLE_ELEMENT_ARRAY_DISPOSE_ITEMS =
                crate::cxx::observable_element_array_clear::DEFAULT_OBSERVABLE_ELEMENT_ARRAY_DISPOSE_ITEMS;
        }

        assert_eq!(returned, &mut registry as *mut Registry);
        assert_eq!(*EVENTS.lock(), std::vec![OBSERVABLE_ELEMENT_ARRAY_VTABLE_ADDRESS, 0]);
        assert_eq!(registry.vtable as usize, REGISTRY_CONTAINER_VTABLE_ADDRESS);
        assert!(registry.observer.is_null());
    }
}
