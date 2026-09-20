//! `opaque_observable_array_destroy` — retailOS `FUN_083d1df4` @
//! `0x083d1df4`.
//!
//! ## Verified extent and calls
//!
//! Raw `osos.dec` contains fourteen ARM words from `0x083d1df4` through the
//! vtable literal `0x089a5640` at `0x083d1e2c`; the next real function starts
//! at `0x083d1e30` (`push {r4,r5,r6,lr}`), so the true size is **56 bytes**.
//! The body has one plain direct `bl` (to `0x083d1d3c`), one predicated
//! `blxne` through the payload vtable at `+0x1c`, and a tail `b` to
//! `observable_array_destruct` at `0x08271d2c`. Binary decoding finds three
//! inbound plain `bl` sites and no predicated direct `bl` sites.
//!
//! ## Algorithm
//!
//! Install the derived destruction vtable, conditionally run the payload's
//! virtual destructor at vtable slot `+0x1c`, invoke the unresolved indexed
//! element-disposal stage at `0x083d1d3c`, then tail-chain into the ported
//! observable-array destructor. The concrete class identity and the first
//! stage's complete receiver contract remain unestablished, so their names
//! deliberately describe only observed behavior.
//!
//! Deliberate deviations: the unresolved direct call is an explicit seam on
//! hosts and a fixed-address call on firmware. The host virtual dispatch is
//! likewise a seam because target-width vtable/function-pointer words cannot
//! contain x86-64 function pointers; ARM retains the exact `ldrne; ldrne;
//! blxne` dispatch.

use super::observable_array::{observable_array_destruct, ObservableArray};

/// Destruction vtable literal installed before any member teardown.
pub const OPAQUE_OBSERVABLE_ARRAY_DESTROY_VTABLE: u32 = 0x089a_5640;

/// Firmware load address of the unresolved indexed element-disposal stage.
pub const OPAQUE_OBSERVABLE_ARRAY_DISPOSE_ITEMS_ADDRESS: usize = 0x083d_1d3c;

/// Direct-call boundary for `FUN_083d1d3c`.
pub type OpaqueObservableArrayDisposeItems = unsafe extern "C" fn(*mut ObservableArray);

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_opaque_observable_array_dispose_items(this: *mut ObservableArray) {
    let dispose_items: OpaqueObservableArrayDisposeItems = unsafe {
        core::mem::transmute(OPAQUE_OBSERVABLE_ARRAY_DISPOSE_ITEMS_ADDRESS)
    };
    unsafe { dispose_items(this) };
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_opaque_observable_array_dispose_items(_this: *mut ObservableArray) {
    panic!("opaque_observable_array_destroy requires unresolved FUN_083d1d3c")
}

#[cfg(target_os = "none")]
pub const DEFAULT_OPAQUE_OBSERVABLE_ARRAY_DISPOSE_ITEMS: OpaqueObservableArrayDisposeItems =
    firmware_opaque_observable_array_dispose_items;
#[cfg(not(target_os = "none"))]
pub const DEFAULT_OPAQUE_OBSERVABLE_ARRAY_DISPOSE_ITEMS: OpaqueObservableArrayDisposeItems =
    missing_opaque_observable_array_dispose_items;

/// Active direct-call boundary for the unresolved element-disposal stage.
pub static mut OPAQUE_OBSERVABLE_ARRAY_DISPOSE_ITEMS: OpaqueObservableArrayDisposeItems =
    DEFAULT_OPAQUE_OBSERVABLE_ARRAY_DISPOSE_ITEMS;

#[cfg(not(target_arch = "arm"))]
pub type OpaqueObservableArrayReleasePayload = unsafe extern "C" fn(*mut u8);

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_opaque_observable_array_release_payload(_payload: *mut u8) {
    panic!("opaque_observable_array_destroy requires a host payload-release seam")
}

/// Host-only model of the target's predicated payload virtual dispatch.
#[cfg(not(target_arch = "arm"))]
pub static mut OPAQUE_OBSERVABLE_ARRAY_RELEASE_PAYLOAD: OpaqueObservableArrayReleasePayload =
    missing_opaque_observable_array_release_payload;

/// Destroys the opaque derived state then its [`ObservableArray`] base.
///
/// Original: `FUN_083d1df4` @ `0x083d1df4` (56 bytes; three unconditional
/// inbound `bl` sites, no predicated direct callers).
///
/// # Safety
///
/// `this` must point to at least 24 writable target-width bytes. The word at
/// `+0x14`, when nonzero, must name a live payload whose vtable has a callable
/// destructor at `+0x1c` on ARM. It must also satisfy the unresolved disposal
/// stage and [`observable_array_destruct`] contracts.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn opaque_observable_array_destroy(
    this: *mut ObservableArray,
) -> *mut ObservableArray {
    let words = this.cast::<u32>();
    unsafe { words.write_volatile(OPAQUE_OBSERVABLE_ARRAY_DESTROY_VTABLE) };

    let payload = unsafe { words.add(5).read_volatile() };
    if payload != 0 {
        #[cfg(target_arch = "arm")]
        unsafe {
            let payload = payload as usize as *mut u32;
            let vtable = payload.read_volatile() as usize as *const u32;
            let release: unsafe extern "C" fn(*mut u8) =
                core::mem::transmute(vtable.add(0x1c / 4).read_volatile() as usize);
            release(payload.cast());
        }
        #[cfg(not(target_arch = "arm"))]
        unsafe {
            let release = core::ptr::read_volatile(core::ptr::addr_of!(OPAQUE_OBSERVABLE_ARRAY_RELEASE_PAYLOAD));
            release(payload as usize as *mut u8);
        }
    }

    let dispose_items = unsafe {
        core::ptr::read_volatile(core::ptr::addr_of!(OPAQUE_OBSERVABLE_ARRAY_DISPOSE_ITEMS))
    };
    unsafe { dispose_items(this) };
    unsafe { observable_array_destruct(this) }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, try_map_u32_slab};
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static EVENTS: Mutex<std::vec::Vec<u32>> = Mutex::new(std::vec::Vec::new());

    unsafe extern "C" fn record_dispose_items(_this: *mut ObservableArray) {
        EVENTS.lock().push(1);
    }

    unsafe extern "C" fn record_release_payload(payload: *mut u8) {
        EVENTS.lock().push(2);
        EVENTS.lock().push(payload as usize as u32);
    }

    #[test]
    fn installs_vtable_releases_payload_disposes_then_destroys_base() {
        let _guard = TEST_LOCK.lock();
        let Some(bytes) = try_map_u32_slab(hints::OPAQUE_OBSERVABLE_ARRAY_DESTROY, 0x1000) else {
            return;
        };
        let words = bytes.cast::<u32>();
        unsafe {
            core::ptr::write_bytes(bytes, 0, 0x1000);
            words.add(5).write_volatile((bytes as usize + 0x100) as u32);
            OPAQUE_OBSERVABLE_ARRAY_DISPOSE_ITEMS = record_dispose_items;
            OPAQUE_OBSERVABLE_ARRAY_RELEASE_PAYLOAD = record_release_payload;
            EVENTS.lock().clear();

            let result = opaque_observable_array_destroy(bytes.cast());

            assert_eq!(result, bytes.cast());
            assert_eq!(words.read_volatile(), super::super::observable_array::OBSERVABLE_ARRAY_VTABLE);
            assert_eq!(*EVENTS.lock(), std::vec![2, bytes as usize as u32 + 0x100, 1]);
            OPAQUE_OBSERVABLE_ARRAY_DISPOSE_ITEMS = DEFAULT_OPAQUE_OBSERVABLE_ARRAY_DISPOSE_ITEMS;
            OPAQUE_OBSERVABLE_ARRAY_RELEASE_PAYLOAD = missing_opaque_observable_array_release_payload;
        }
    }

    #[test]
    fn skips_payload_release_when_the_target_word_is_null() {
        let _guard = TEST_LOCK.lock();
        let Some(bytes) = try_map_u32_slab(hints::OPAQUE_OBSERVABLE_ARRAY_DESTROY_NULL, 0x1000) else {
            return;
        };
        unsafe {
            core::ptr::write_bytes(bytes, 0, 0x1000);
            OPAQUE_OBSERVABLE_ARRAY_DISPOSE_ITEMS = record_dispose_items;
            OPAQUE_OBSERVABLE_ARRAY_RELEASE_PAYLOAD = record_release_payload;
            EVENTS.lock().clear();

            opaque_observable_array_destroy(bytes.cast());

            assert_eq!(*EVENTS.lock(), std::vec![1]);
            OPAQUE_OBSERVABLE_ARRAY_DISPOSE_ITEMS = DEFAULT_OPAQUE_OBSERVABLE_ARRAY_DISPOSE_ITEMS;
            OPAQUE_OBSERVABLE_ARRAY_RELEASE_PAYLOAD = missing_opaque_observable_array_release_payload;
        }
    }
}
