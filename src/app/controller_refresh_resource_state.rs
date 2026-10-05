//! Controller resource-state refresh — FUN_0819ab14 at 0x0819ab14.
//! True extent: 140 bytes, [0x0819ab14, 0x0819aba0): 124 code bytes
//! and four literal words. Whole-image A32 decoding finds two inbound plain
//! BLs (0x0819aa24, 0x0819ab00), zero predicated BLs. Body: seven plain
//! BLs, zero predicated BLs, one BLX, and one tail B to 0x082879b0.
//!
//! Resolve key 0x0dad017f through the demo manager's +0xf8 slot and require
//! class 0x1700. On failure return zero without touching the controller.
//! Update keys 0x0dad0d08 and 0x0dad0d0b from the current element's +0x48
//! nonzero flag query, reloading controller+0xb0 each time. Update key
//! 0x0dad0d0a from the nonzero status of the element's +0x2c subobject.
//! Return that last update's result; earlier update results are ignored.
//!
//! Deviations: the final tail transfer is expressed as a Rust call; native
//! pointer fields expand on host via repr(C). Host lookup/cast/update models
//! replace firmware dispatch, while the existing flag/status ports run directly.
//! Resource ids occupy the forwarder's pointer-typed r0 ABI; they are not
//! dereferenced here. No new guards or inferred callee identities.

use core::ptr::{addr_of, read_volatile};
use crate::ui::nonzero_flags::ui_element_has_nonzero_flags;
use super::service_status_word::service_status_word;

#[repr(C)]
pub struct ResourceStateController {
    pub reserved: [u32; 0xb0 / 4],
    pub element: *mut u8,
}

#[cfg(target_os = "none")]
unsafe extern "C" fn lookup(key: u32) -> *mut u8 {
    let demo = super::registry::demo_mode_instance();
    let vtable = read_volatile(demo.cast::<*const u32>());
    let method: unsafe extern "C" fn(*mut u8, u32) -> *mut u8 =
        core::mem::transmute(read_volatile(vtable.add(0xf8 / 4)));
    method(demo, key)
}
#[cfg(target_os = "none")]
unsafe extern "C" fn cast(object: *mut u8, class: u32) -> *mut u8 {
    super::registry::object_cast_to_class(object.cast(), class)
}
#[cfg(target_os = "none")]
unsafe extern "C" fn update(key: u32, enabled: u32) -> u32 {
    extern "C" { fn ui_flag_update_forwarder(object: *mut u8, flag: u32) -> u32; }
    ui_flag_update_forwarder(key as usize as *mut u8, enabled)
}

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
pub struct ResourceStateOps {
    pub lookup: unsafe extern "C" fn(u32) -> *mut u8,
    pub cast: unsafe extern "C" fn(*mut u8, u32) -> *mut u8,
    pub update: unsafe extern "C" fn(u32, u32) -> u32,
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_lookup(_: u32) -> *mut u8 { panic!("install resource state lookup") }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_cast(_: *mut u8, _: u32) -> *mut u8 { panic!("install resource state cast") }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_update(_: u32, _: u32) -> u32 { panic!("install resource state update") }
#[cfg(not(target_os = "none"))]
pub static mut RESOURCE_STATE_OPS: ResourceStateOps = ResourceStateOps {
    lookup: missing_lookup, cast: missing_cast, update: missing_update,
};

/// # Safety
/// The demo manager and registry must be initialized. After successful lookup
/// and cast, controller+0xb0 must point to an aligned element readable through
/// +0x4b, including after each synchronous resource update.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn controller_refresh_resource_state(controller: *mut ResourceStateController) -> u32 {
    #[cfg(not(target_os = "none"))]
    let ResourceStateOps { lookup, cast, update } = read_volatile(addr_of!(RESOURCE_STATE_OPS));
    let object = lookup(0x0dad017f);
    if object.is_null() { return 0; }
    if cast(object, 0x1700).is_null() { return 0; }
    let element = read_volatile(addr_of!((*controller).element));
    update(0x0dad0d08, ui_element_has_nonzero_flags(element));
    let element = read_volatile(addr_of!((*controller).element));
    update(0x0dad0d0b, ui_element_has_nonzero_flags(element));
    let element = read_volatile(addr_of!((*controller).element));
    update(0x0dad0d0a, (service_status_word(element.add(0x2c)) != 0) as u32)
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr::addr_of_mut;
    use parking_lot::Mutex;
    static LOCK: Mutex<()> = Mutex::new(());
    static mut REJECTION: u32 = 0;
    static mut FLAGS: u32 = 0;
    static mut OWNER: *mut ResourceStateController = core::ptr::null_mut();
    static mut NEXT: *mut u8 = core::ptr::null_mut();
    static mut LAST: *mut u8 = core::ptr::null_mut();
    unsafe extern "C" fn resolve(_: u32) -> *mut u8 {
        if REJECTION == 1 { core::ptr::null_mut() } else { 1usize as *mut u8 }
    }
    unsafe extern "C" fn validate(_: *mut u8, _: u32) -> *mut u8 {
        if REJECTION == 2 { core::ptr::null_mut() } else { 2usize as *mut u8 }
    }
    unsafe extern "C" fn apply(key: u32, enabled: u32) -> u32 {
        let bit = match key { 0x0dad0d08 => 1, 0x0dad0d0b => 2, 0x0dad0d0a => 4, _ => panic!("unknown resource") };
        assert!(enabled <= 1);
        if enabled == 0 { FLAGS &= !bit; } else { FLAGS |= bit; }
        if bit == 1 { (*OWNER).element = NEXT; }
        if bit == 2 { (*OWNER).element = LAST; }
        if bit == 4 { 0x87654321 } else { 0 }
    }
    #[test]
    fn rejection_skips_invalid_controller_and_preserves_resources() {
        let _lock = LOCK.lock();
        unsafe {
            let saved = RESOURCE_STATE_OPS;
            RESOURCE_STATE_OPS = ResourceStateOps { lookup: resolve, cast: validate, update: apply };
            for rejection in [1, 2] {
                REJECTION = rejection; FLAGS = 7;
                assert_eq!(controller_refresh_resource_state(core::ptr::null_mut()), 0);
                assert_eq!({ FLAGS }, 7);
            }
            RESOURCE_STATE_OPS = saved;
        }
    }
    #[test]
    fn synchronous_updates_reload_element_and_normalize_full_words() {
        let _lock = LOCK.lock();
        unsafe {
            let saved = RESOURCE_STATE_OPS;
            RESOURCE_STATE_OPS = ResourceStateOps { lookup: resolve, cast: validate, update: apply };
            REJECTION = 0;
            for (first, second, status, expected) in [(0, 0, 0, 0), (u32::MAX, 0, 0x80000000, 5), (0, 0x80000000, 0, 2), (1, 1, u32::MAX, 7)] {
                let mut a = [0u32; 0x4c / 4]; a[0x48 / 4] = first;
                let mut b = [0u32; 0x4c / 4]; b[0x48 / 4] = second;
                let mut c = [0u32; 0x4c / 4]; c[0x34 / 4] = status;
                let mut owner = ResourceStateController { reserved: [0; 0xb0 / 4], element: a.as_mut_ptr().cast() };
                OWNER = addr_of_mut!(owner); NEXT = b.as_mut_ptr().cast(); LAST = c.as_mut_ptr().cast(); FLAGS = 7;
                assert_eq!(controller_refresh_resource_state(OWNER), 0x87654321);
                assert_eq!({ FLAGS }, expected);
            }
            RESOURCE_STATE_OPS = saved;
        }
    }
}
