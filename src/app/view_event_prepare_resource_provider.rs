//! Prepares a view's resource-provider state before applying its mapped staged
//! flags.
//!
//! `view_event_prepare_resource_provider` — original: `FUN_0822e00c` @
//! `0x0822e00c`, 140 bytes (`0x0822e00c..0x0822e097`; the literal pool starts
//! at `0x0822e098`). Raw ARM decoding finds seven direct calls: six
//! unconditional `bl` instructions and one predicated `bleq`; there are three
//! direct `bl` callers. The routine ensures the view belongs to the 0x7f80
//! resource provider, updates that provider's pending-state byte, throttles a
//! zero-state refresh every 50 calls, then applies the view's mapped staged
//! flags and returns the framework handled verdict.
//!
//! Deliberate deviations: `resource_provider_attach_view` (`0x08124af4`) and
//! the provider refresh (`0x081b6ee8`) remain firmware seams. The 32-bit
//! global refresh counter at `0x08a09dcc + 4` is represented by host storage
//! in tests; target builds access the retail word directly. The original
//! tail-branches to `view_event_apply_mapped_staged_flags` at `0x0810de48`;
//! Rust calls the existing ported wrapper, whose documented ABI establishes
//! that the preserved `r1` is dead.

use core::ptr::{read_volatile, write_volatile};
#[cfg(not(target_os = "none"))]
use core::ptr::addr_of_mut;

use super::resource_provider_contains_view::resource_provider_contains_view;
use super::singletons::{app_screen_get, singleton_class_7f80};
use super::view_event::view_event_apply_mapped_staged_flags;

const PROVIDER_PENDING_OFFSET: usize = 0xc5;
const PROVIDER_REFRESHED_OFFSET: usize = 0xeb;
const REFRESH_INTERVAL: u32 = 50;
const RETAIL_REFRESH_COUNTER: *mut u32 = 0x08a0_9dd0 as *mut u32;

pub struct ViewEventPrepareResourceProviderOps {
    pub app_screen_get: unsafe extern "C" fn() -> *mut u8,
    pub provider_get: unsafe extern "C" fn() -> *mut u8,
    pub provider_contains_view: unsafe extern "C" fn(*mut u8, *mut u8) -> u32,
    pub provider_attach_view: unsafe extern "C" fn(*mut u8, *mut u8),
    pub provider_refresh: unsafe extern "C" fn(*mut u8),
    pub apply_mapped_staged_flags: unsafe extern "C" fn(*mut u8) -> u32,
}

#[cfg(target_arch = "arm")]
unsafe extern "C" fn provider_contains_view_adapter(provider: *mut u8, view: *mut u8) -> u32 {
    unsafe { resource_provider_contains_view(provider.cast(), view) }
}

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn provider_contains_view_adapter(provider: *mut u8, view: *mut u8) -> u32 {
    unsafe { resource_provider_contains_view(provider.cast(), view) }
}

unsafe extern "C" fn provider_attach_view(provider: *mut u8, view: *mut u8) {
    #[cfg(target_os = "none")]
    {
        let f: unsafe extern "C" fn(*mut u8, *mut u8) = unsafe { core::mem::transmute(0x0812_4af4usize) };
        unsafe { f(provider, view) };
    }
    #[cfg(not(target_os = "none"))]
    panic!("view_event_prepare_resource_provider requires resource_provider_attach_view 0x08124af4")
}

unsafe extern "C" fn provider_refresh(provider: *mut u8) {
    #[cfg(target_os = "none")]
    {
        let f: unsafe extern "C" fn(*mut u8) = unsafe { core::mem::transmute(0x081b_6ee8usize) };
        unsafe { f(provider) };
    }
    #[cfg(not(target_os = "none"))]
    panic!("view_event_prepare_resource_provider requires provider refresh 0x081b6ee8")
}

pub static mut VIEW_EVENT_PREPARE_RESOURCE_PROVIDER_OPS: ViewEventPrepareResourceProviderOps = ViewEventPrepareResourceProviderOps {
    app_screen_get,
    provider_get: singleton_class_7f80,
    provider_contains_view: provider_contains_view_adapter,
    provider_attach_view,
    provider_refresh,
    apply_mapped_staged_flags: view_event_apply_mapped_staged_flags,
};

#[cfg(not(target_os = "none"))]
static mut HOST_REFRESH_COUNTER: u32 = 0;

unsafe fn refresh_counter() -> *mut u32 {
    #[cfg(target_os = "none")]
    { RETAIL_REFRESH_COUNTER }
    #[cfg(not(target_os = "none"))]
    { addr_of_mut!(HOST_REFRESH_COUNTER) }
}

unsafe fn update_provider_refreshed(provider: *mut u8) {
    let refreshed = unsafe { provider.add(0xe8).read_volatile() != 0 }
        && unsafe { provider.add(0xe9).read_volatile() != 0 };
    unsafe { provider.add(PROVIDER_REFRESHED_OFFSET).write_volatile(refreshed as u8) };
}

/// Ensures `view` is attached to the class-0x7f80 resource provider, refreshes
/// its pending state, applies mapped staged flags, and returns one.
///
/// # Safety
/// `view` must be valid for every callee. The provider returned by the active
/// operation table must be valid through byte offset `0xeb`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn view_event_prepare_resource_provider(view: *mut u8) -> u32 {
    let ops = unsafe { &VIEW_EVENT_PREPARE_RESOURCE_PROVIDER_OPS };
    unsafe { (ops.app_screen_get)() };
    let provider = unsafe { (ops.provider_get)() };
    if unsafe { (ops.provider_contains_view)(provider, view) } == 0 {
        unsafe { (ops.provider_attach_view)(provider, view) };
    }

    if unsafe { provider.add(PROVIDER_PENDING_OFFSET).read_volatile() } == 0 {
        let counter = unsafe { refresh_counter() };
        let next = unsafe { read_volatile(counter).wrapping_add(1) };
        unsafe { write_volatile(counter, next) };
        if next == REFRESH_INTERVAL {
            unsafe { (ops.provider_refresh)(provider) };
            unsafe { update_provider_refreshed(provider) };
            unsafe { write_volatile(counter, 0) };
        }
    } else {
        unsafe { (ops.provider_get)() };
        unsafe { (ops.provider_refresh)(provider) };
        unsafe { update_provider_refreshed(provider) };
        unsafe { provider.add(PROVIDER_PENDING_OFFSET).write_volatile(0) };
    }
    unsafe { (ops.apply_mapped_staged_flags)(view) }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use parking_lot::Mutex;
    use std::vec::Vec;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut PROVIDER: [u8; 0xec] = [0; 0xec];
    static mut CONTAINS: u32 = 0;
    static mut CALLS: Vec<&'static str> = Vec::new();

    unsafe extern "C" fn screen() -> *mut u8 { CALLS.push("screen"); core::ptr::null_mut() }
    unsafe extern "C" fn provider() -> *mut u8 { CALLS.push("provider"); PROVIDER.as_mut_ptr() }
    unsafe extern "C" fn contains(_provider: *mut u8, _view: *mut u8) -> u32 { CALLS.push("contains"); CONTAINS }
    unsafe extern "C" fn attach(_provider: *mut u8, _view: *mut u8) { CALLS.push("attach") }
    unsafe extern "C" fn refresh(_provider: *mut u8) { CALLS.push("refresh") }
    unsafe extern "C" fn apply(_view: *mut u8) -> u32 { CALLS.push("apply"); 1 }

    unsafe fn install() {
        PROVIDER = [0; 0xec];
        CONTAINS = 0;
        CALLS.clear();
        HOST_REFRESH_COUNTER = 0;
        addr_of_mut!(VIEW_EVENT_PREPARE_RESOURCE_PROVIDER_OPS).write(ViewEventPrepareResourceProviderOps {
            app_screen_get: screen, provider_get: provider, provider_contains_view: contains,
            provider_attach_view: attach, provider_refresh: refresh, apply_mapped_staged_flags: apply,
        });
    }

    #[test]
    fn attaches_missing_view_and_refreshes_on_fiftieth_idle_event() {
        let _guard = LOCK.lock();
        unsafe {
            install();
            HOST_REFRESH_COUNTER = 49;
            let mut view = [0u8; 1];
            assert_eq!(view_event_prepare_resource_provider(view.as_mut_ptr()), 1);
            assert_eq!(CALLS, ["screen", "provider", "contains", "attach", "refresh", "apply"]);
            assert_eq!(HOST_REFRESH_COUNTER, 0);
        }
    }

    #[test]
    fn pending_provider_refreshes_immediately_clears_pending_and_skips_counter() {
        let _guard = LOCK.lock();
        unsafe {
            install();
            CONTAINS = 1;
            PROVIDER[PROVIDER_PENDING_OFFSET] = 0xa5;
            HOST_REFRESH_COUNTER = 17;
            let mut view = [0u8; 1];
            assert_eq!(view_event_prepare_resource_provider(view.as_mut_ptr()), 1);
            assert_eq!(CALLS, ["screen", "provider", "contains", "provider", "refresh", "apply"]);
            assert_eq!(PROVIDER[PROVIDER_PENDING_OFFSET], 0);
            assert_eq!(HOST_REFRESH_COUNTER, 17);
        }
    }
}
