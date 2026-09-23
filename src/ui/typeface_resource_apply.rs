//! `typeface_resource_apply` — original: `FUN_08140c9c` @ `0x08140c9c`
//! (120 bytes: 116 code bytes plus the trailing `'Type'` literal; **4 plain
//! `bl` calls and zero predicated `bl` calls**, binary-decoded from `osos.dec`).
//!
//! Raw ARM starts at `0x08140c9c`, returns at `0x08140d0c`, then reads its
//! `'Type'` resource-kind literal at `0x08140d10`; the next real function
//! starts at `0x08140d14`. Ghidra's 116-byte body omits that literal.
//!
//! # Algorithm
//!
//! When `owner + 0xf0` is nonzero, look up `typeface_id` as a `'Type'`
//! resource, first through the owner provider at +0x38 or otherwise through
//! the current task. A found resource is passed to the unported renderer
//! helper @ `0x0826de74` with `owner`, `draw_state`, and `owner + 0xf4`.
//! Afterwards, store the signed sum of the three tagged-payload metrics plus
//! three at `owner + 0xf8`.
//!
//! # Deliberate deviations
//!
//! The unported helper's concrete class identity is not inferred. Its decoded
//! ABI and argument roles are represented by a target-address call and host
//! seam; the remaining three calls use their existing typed ports.

use crate::app::resource_chain::{resource_chain_find, resource_chain_find_on_current_task, ResourceKind, ResourceProvider};
#[cfg(test)]
use crate::app::resource_chain::ResourceProviderVTable;
use crate::util::tagged_payload_signed_field_sum::tagged_payload_signed_field_sum;

const OWNER_RESOURCE_PROVIDER: usize = 0x38;
const OWNER_ENABLE_WORD: usize = 0xf0;
const OWNER_HELPER_STATE: usize = 0xf4;
const OWNER_METRIC: usize = 0xf8;
const TYPEFACE_KIND: ResourceKind = ResourceKind(0x6570_7954);
const RETAIL_TYPEFACE_RESOURCE_APPLY: usize = 0x0826_de74;

/// ABI of the unported renderer helper @ `0x0826de74`.
pub type TypefaceResourceApplyFn = unsafe extern "C" fn(*mut u8, *mut u8, *mut u8, *mut u8);

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn apply_typeface_resource(owner: *mut u8, resource: *mut u8, draw_state: *mut u8, state: *mut u8) {
    let apply: TypefaceResourceApplyFn = unsafe { core::mem::transmute(RETAIL_TYPEFACE_RESOURCE_APPLY) };
    unsafe { apply(owner, resource, draw_state, state); }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_typeface_resource_apply(_owner: *mut u8, _resource: *mut u8, _draw_state: *mut u8, _state: *mut u8) {
    panic!("FUN_0826de74 is unported; install TYPEFACE_RESOURCE_APPLY")
}

/// Active host boundary for the unported helper @ `0x0826de74`.
#[cfg(not(target_os = "none"))]
pub static mut TYPEFACE_RESOURCE_APPLY: TypefaceResourceApplyFn = missing_typeface_resource_apply;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn apply_typeface_resource(owner: *mut u8, resource: *mut u8, draw_state: *mut u8, state: *mut u8) {
    let apply = unsafe { core::ptr::addr_of!(TYPEFACE_RESOURCE_APPLY).read_volatile() };
    unsafe { apply(owner, resource, draw_state, state); }
}

/// Resolve an owner's typeface resource and apply it to `draw_state`.
///
/// `owner` must be readable through +0xf8 and writable at +0xf8; its +0x38
/// provider field is a target-width word. `metrics` must be valid for the
/// tagged-payload metric helper only after a resource was found. All other
/// malformed pointers fault as they do in retailOS.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn typeface_resource_apply(owner: *mut u8, draw_state: *mut u8, typeface_id: u32, metrics: *const u32) {
    if unsafe { (owner.add(OWNER_ENABLE_WORD) as *const u32).read() } == 0 {
        return;
    }

    let provider = unsafe { (owner.add(OWNER_RESOURCE_PROVIDER) as *const u32).read() } as usize as *mut ResourceProvider;
    let resource = if provider.is_null() {
        unsafe { resource_chain_find_on_current_task(TYPEFACE_KIND, typeface_id) }
    } else {
        unsafe { resource_chain_find(provider, TYPEFACE_KIND, typeface_id) }
    };
    if resource.is_null() {
        return;
    }

    unsafe { apply_typeface_resource(owner, resource, draw_state, owner.add(OWNER_HELPER_STATE)); }
    let metric = unsafe { tagged_payload_signed_field_sum(metrics).wrapping_add(3) };
    unsafe { (owner.add(OWNER_METRIC) as *mut i32).write(metric); }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use parking_lot::Mutex;
    use core::ptr;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut EXPECTED_RESOURCE: *mut u8 = ptr::null_mut();
    static mut APPLY_ARGS: (*mut u8, *mut u8, *mut u8, *mut u8) = (ptr::null_mut(), ptr::null_mut(), ptr::null_mut(), ptr::null_mut());

    unsafe extern "C" fn find_typeface(_provider: *mut ResourceProvider, kind: ResourceKind, id: u32, found: *mut *mut u8) -> u32 {
        assert_eq!(kind, TYPEFACE_KIND);
        assert_eq!(id, 0x81a4);
        unsafe { found.write(EXPECTED_RESOURCE); }
        1
    }
    unsafe extern "C" fn unused_read(_provider: *mut ResourceProvider, _kind: ResourceKind, _id: u32) -> u32 { 0 }
    unsafe extern "C" fn unused_replace(_provider: *mut ResourceProvider, _replacement: *mut ResourceProvider) -> u32 { 0 }
    unsafe extern "C" fn unused_write(_provider: *mut ResourceProvider, _kind: ResourceKind, _id: u32, _value: u32, _flags: u32) -> u32 { 0 }
    unsafe extern "C" fn record_apply(owner: *mut u8, resource: *mut u8, draw_state: *mut u8, state: *mut u8) {
        unsafe { APPLY_ARGS = (owner, resource, draw_state, state); }
    }

    #[test]
    fn applies_found_typeface_and_updates_signed_metric() {
        let _lock = LOCK.lock();
        let Some(slab) = try_map_u32_slab(hints::TYPEFACE_RESOURCE_APPLY, 0x800) else {
            note_missing_u32_fixture(module_path!());
            return;
        };
        let owner = slab;
        let provider = unsafe { slab.add(0x100) as *mut ResourceProvider };
        let metrics = unsafe { slab.add(0x200) as *mut u32 };
        let payload = unsafe { slab.add(0x400) };
        let resource = unsafe { slab.add(0x700) };
        let vtable = ResourceProviderVTable {
            slots_below: [None; 22], read: unused_read, slot_5c: None,
            replacement_allowed: unused_replace, find: find_typeface, write: unused_write,
        };
        unsafe {
            provider.write(ResourceProvider { vtable: &vtable, state_below_next: [ptr::null_mut(); 4], next: ptr::null_mut() });
            (owner.add(OWNER_ENABLE_WORD) as *mut u32).write(1);
            (owner.add(OWNER_RESOURCE_PROVIDER) as *mut u32).write(provider as usize as u32);
            metrics.add(0x20 / 4).write(payload as usize as u32 | 1);
            (payload.add(0x52) as *mut i16).write(-7);
            (payload.add(0x54) as *mut i16).write(11);
            (payload.add(0x56) as *mut i16).write(-2);
            EXPECTED_RESOURCE = resource;
            APPLY_ARGS = (ptr::null_mut(), ptr::null_mut(), ptr::null_mut(), ptr::null_mut());
            TYPEFACE_RESOURCE_APPLY = record_apply;
            typeface_resource_apply(owner, slab.add(0x80), 0x81a4, metrics);
            assert_eq!(APPLY_ARGS, (owner, resource, slab.add(0x80), owner.add(OWNER_HELPER_STATE)));
            assert_eq!((owner.add(OWNER_METRIC) as *const i32).read(), 5);
            TYPEFACE_RESOURCE_APPLY = missing_typeface_resource_apply;
        }
    }

    #[test]
    fn disabled_owner_does_not_resolve_or_touch_metric() {
        let _lock = LOCK.lock();
        let mut owner = [0u8; OWNER_METRIC + 4];
        unsafe { (owner.as_mut_ptr().add(OWNER_METRIC) as *mut u32).write(0xfeed_beef); }
        unsafe { typeface_resource_apply(owner.as_mut_ptr(), ptr::null_mut(), 0x81a4, ptr::null()); }
        assert_eq!(unsafe { (owner.as_ptr().add(OWNER_METRIC) as *const u32).read() }, 0xfeed_beef);
    }
}
