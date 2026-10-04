//! Applies a controller's resource-enable table — `FUN_081eb204` at
//! **0x081eb204**, true extent **160 bytes** (152 code + 8 literal bytes),
//! ending at the separate function at 0x081eb2a4. Independently decoded
//! inbound calls: one plain BL at 0x081ebf3c and one BLEQ at 0x081e7844.
//! Body: five plain BL, zero predicated BL, one BLX, and a final tail B.
//!
//! Resolve key 0x0dad017f through the demo manager's +0xf8 virtual slot;
//! reject NULL or failure to cast to class 0x1700. Prepare the shared table,
//! then visit exactly 12 twenty-byte records. For nonzero resource ids,
//! apply the enable byte to the resource registry and to the controller's
//! +0x378 store flag selected by the record's +0xc word. Reload the byte
//! after the registry call. Finally invalidate the original resolved object,
//! not the cast result, and return it.
//!
//! Deliberate deviations: unported callees retain their verified retail
//! addresses on device; host operations are installable models. Native
//! pointer fields expand on host using repr(C); table records remain target
//! words. The invalidation tail branch becomes a call to the existing port.
//! The unused r0=13 before the loop is omitted. No new NULL guards.

use core::ptr::{addr_of, read_volatile};
#[cfg(not(target_os = "none"))]
use core::ptr::addr_of_mut;

#[repr(C)]
pub struct ResourceFlagController {
    reserved: [u32; 0x378 / 4],
    pub store: *mut u8,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct ResourceFlagRecord {
    resource_id: u32,
    reserved: [u32; 2],
    flag_selector: u32,
    enabled: u8,
    padding: [u8; 3],
}

#[derive(Clone, Copy)]
struct ApplyOps {
    lookup: unsafe extern "C" fn(u32) -> *mut u8,
    cast: unsafe extern "C" fn(*mut u8, u32) -> *mut u8,
    prepare: unsafe extern "C" fn(*mut ResourceFlagController),
    set_resource: unsafe extern "C" fn(u32, u32) -> u32,
    set_flag: unsafe extern "C" fn(*mut u8, u32, u32),
}

#[cfg(target_os = "none")]
unsafe extern "C" fn lookup(key: u32) -> *mut u8 {
    let demo = crate::app::registry::demo_mode_instance();
    let vtable = read_volatile(demo.cast::<*const u32>());
    let method: unsafe extern "C" fn(*mut u8, u32) -> *mut u8 =
        core::mem::transmute(read_volatile(vtable.add(0xf8 / 4)));
    method(demo, key)
}
#[cfg(target_os = "none")]
unsafe extern "C" fn cast(object: *mut u8, class: u32) -> *mut u8 {
    crate::app::registry::object_cast_to_class(object.cast(), class)
}
#[cfg(target_os = "none")]
unsafe extern "C" fn prepare(controller: *mut ResourceFlagController) {
    core::mem::transmute::<usize, unsafe extern "C" fn(*mut ResourceFlagController)>(0x081ecc5c)(controller)
}
#[cfg(target_os = "none")]
unsafe extern "C" fn set_resource(id: u32, enabled: u32) -> u32 {
    core::mem::transmute::<usize, unsafe extern "C" fn(u32, u32) -> u32>(0x082879b0)(id, enabled)
}
#[cfg(target_os = "none")]
unsafe extern "C" fn set_flag(store: *mut u8, selector: u32, enabled: u32) {
    core::mem::transmute::<usize, unsafe extern "C" fn(*mut u8, u32, u32)>(0x081729bc)(store, selector, enabled)
}
#[cfg(target_os = "none")]
static mut APPLY_OPS: ApplyOps = ApplyOps {
    lookup, cast, prepare, set_resource, set_flag,
};

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn lookup(_: u32) -> *mut u8 { panic!("install resource flag lookup model") }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn cast(_: *mut u8, _: u32) -> *mut u8 { panic!("install resource flag cast model") }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn prepare(_: *mut ResourceFlagController) { panic!("install resource flag preparation model") }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn set_resource(_: u32, _: u32) -> u32 { panic!("install resource enable model") }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn set_flag(_: *mut u8, _: u32, _: u32) { panic!("install store flag model") }
#[cfg(not(target_os = "none"))]
static mut APPLY_OPS: ApplyOps = ApplyOps { lookup, cast, prepare, set_resource, set_flag };

#[cfg(not(target_os = "none"))]
static mut HOST_RECORDS: [ResourceFlagRecord; 13] = [ResourceFlagRecord {
    resource_id: 0, reserved: [0; 2], flag_selector: 0, enabled: 0, padding: [0; 3],
}; 13];

#[inline(always)]
fn records() -> *mut ResourceFlagRecord {
    #[cfg(target_os = "none")]
    { 0x08a79240 as *mut ResourceFlagRecord }
    #[cfg(not(target_os = "none"))]
    { addr_of_mut!(HOST_RECORDS).cast() }
}

/// # Safety
/// `controller` must have a valid +0x378 store; the demo manager, shared table,
/// and callees must be initialized. Resolved objects must be valid UI elements.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn controller_apply_resource_flags(controller: *mut ResourceFlagController) -> *mut u8 {
    let ops = read_volatile(addr_of!(APPLY_OPS));
    let object = (ops.lookup)(0x0dad017f);
    if object.is_null() { return core::ptr::null_mut(); }
    if (ops.cast)(object, 0x1700).is_null() { return core::ptr::null_mut(); }
    (ops.prepare)(controller);
    for index in 0..12 {
        let record = records().add(index);
        let resource = read_volatile(addr_of!((*record).resource_id));
        if resource != 0 {
            (ops.set_resource)(resource, read_volatile(addr_of!((*record).enabled)) as u32);
            let enabled = read_volatile(addr_of!((*record).enabled)) as u32;
            let selector = read_volatile(addr_of!((*record).flag_selector));
            let store = read_volatile(addr_of!((*controller).store));
            (ops.set_flag)(store, selector, enabled);
        }
    }
    crate::ui::invalidate::ui_element_invalidate(object)
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;
    static LOCK: Mutex<()> = Mutex::new(());
    static mut OBJECT: *mut u8 = core::ptr::null_mut();
    static mut REJECT: bool = false;
    static mut PREPARED: bool = false;
    static mut RESOURCE_MASK: u32 = 0;

    unsafe extern "C" fn resolve(_: u32) -> *mut u8 { OBJECT }
    unsafe extern "C" fn validate(_: *mut u8, class: u32) -> *mut u8 {
        assert_eq!(class, 0x1700);
        if REJECT { core::ptr::null_mut() } else { 1usize as *mut u8 }
    }
    unsafe extern "C" fn populate(_: *mut ResourceFlagController) {
        PREPARED = true;
        // The thirteenth record must never be consumed. Nonboolean enable
        // bytes must reach both operations without boolean normalization.
        for index in 0..13 {
            records().add(index).write(ResourceFlagRecord {
                resource_id: if index == 4 { 0 } else { 1 << index },
                reserved: [0; 2], flag_selector: 1 << index,
                enabled: if index == 2 { 0 } else { 0x80 }, padding: [0; 3],
            });
        }
    }
    unsafe extern "C" fn enable(resource: u32, mode: u32) -> u32 {
        assert!(PREPARED);
        assert!(mode == 0 || mode == 0x80);
        if mode == 0 { RESOURCE_MASK &= !resource; } else { RESOURCE_MASK |= resource; }
        // A registry observer changes the record between calls: the store
        // operation must read the new enable byte, not a cached snapshot.
        if resource == 1 { (*records()).enabled = 0; }
        0 // ignored failure/status result, matching firmware
    }
    unsafe extern "C" fn update(store: *mut u8, selector: u32, mode: u32) {
        let flags = store.cast::<u32>();
        if mode == 0 { flags.write(flags.read() & !selector); }
        else { flags.write(flags.read() | selector); }
    }

    #[test]
    fn rejection_and_live_twelve_record_application() {
        let _lock = LOCK.lock();
        unsafe {
            let saved = read_volatile(addr_of!(APPLY_OPS));
            APPLY_OPS = ApplyOps { lookup: resolve, cast: validate, prepare: populate, set_resource: enable, set_flag: update };
            let mut flags = u32::MAX;
            let mut controller = ResourceFlagController { reserved: [0; 0x378 / 4], store: addr_of_mut!(flags).cast() };
            // Hidden element exercises the real invalidation early-out, with
            // sufficient storage for every field used by that helper.
            let mut element = [0u32; 0x200 / 4];
            OBJECT = core::ptr::null_mut(); REJECT = false; PREPARED = false;
            assert!(controller_apply_resource_flags(&mut controller).is_null());
            assert!(!PREPARED);
            OBJECT = element.as_mut_ptr().cast(); REJECT = true;
            assert!(controller_apply_resource_flags(&mut controller).is_null());
            assert!(!PREPARED);
            REJECT = false; RESOURCE_MASK = u32::MAX;
            assert_eq!(controller_apply_resource_flags(&mut controller), element.as_mut_ptr().cast());
            assert_eq!(read_volatile(addr_of!(RESOURCE_MASK)), u32::MAX & !(1 << 2));
            assert_eq!(flags, u32::MAX & !((1 << 2) | 1));
            // Initially clear skipped and out-of-range bits must stay clear.
            flags = 0; RESOURCE_MASK = 0;
            controller_apply_resource_flags(&mut controller);
            assert_eq!(read_volatile(addr_of!(RESOURCE_MASK)), 0xfff & !((1 << 4) | (1 << 2)));
            assert_eq!(flags, 0xfff & !((1 << 4) | (1 << 2) | 1));
            APPLY_OPS = saved;
            OBJECT = core::ptr::null_mut();
        }
    }
}
