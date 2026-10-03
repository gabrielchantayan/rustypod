//! Conditional class-0x1700 virtual dispatch — FUN_08219e50 @ 0x08219e50.
//! True extent: 132 bytes (124 code bytes and two literals), ending at the
//! next function at 0x08219ed4. Raw A32: five plain BLs, one BLEQ, one BLX
//! and one BLXNE; inbound: one plain BL and one BLEQ.
//!
//! For mode zero, construct the runtime key at 0x089cfe54, test for a nonempty
//! value in table 0x08a79c10, and release the temporary before dispatching.
//! On a hit, obtain TCDemoMode, invoke slot +0xe4, fail fatally on NULL,
//! cast to class 0x1700, and invoke slot +0x174 with zero if the cast succeeds.
//! Always return 1. The meanings of those virtual methods remain unresolved.
//!
//! Deviations: unused incoming r0/r2/r3 and the constructor's unused third
//! argument are omitted. Host vtables use native-width entries at target word
//! indices; host-only operations replace runtime globals and dependencies.

use crate::cxx::string::{cxx_string_from_cstr, cxx_string_release};
use crate::heap::veneers::heap_panic;
use super::registry::{demo_mode_instance, object_cast_to_class};
use super::string_table::string_table_has_string;

#[derive(Clone, Copy)]
pub struct Class1700ClearOps {
    pub key: unsafe extern "C" fn() -> *const u8,
    pub create: unsafe extern "C" fn(*mut *mut u8, *const u8) -> *mut *mut u8,
    pub release: unsafe extern "C" fn(*mut *mut u8),
    pub has_string: unsafe extern "C" fn(*mut u8, *const u32) -> u32,
    pub instance: unsafe extern "C" fn() -> *mut u8,
}
unsafe extern "C" fn runtime_key() -> *const u8 {
    #[cfg(target_os = "none")]
    return (0x089c_fe54usize as *const *const u8).read();
    #[cfg(not(target_os = "none"))]
    panic!("runtime key requires host dependency injection")
}
const DEFAULT_OPS: Class1700ClearOps = Class1700ClearOps {
    key: runtime_key, create: cxx_string_from_cstr, release: cxx_string_release,
    has_string: string_table_has_string, instance: demo_mode_instance,
};
#[cfg(not(target_os = "none"))]
pub static mut CLASS_1700_CLEAR_OPS: Class1700ClearOps = DEFAULT_OPS;

unsafe fn clear(mode: i32, ops: Class1700ClearOps) -> u32 {
    if mode == 0 {
        let mut string = core::ptr::null_mut();
        let key = (ops.create)(&mut string, (ops.key)());
        let present = (ops.has_string)(0x08a7_9c10 as *mut u8, key.cast());
        (ops.release)(&mut string);
        if present != 0 {
            let manager = (ops.instance)();
            let vtable = (manager as *const *const usize).read();
            let get: unsafe extern "C" fn(*mut u8) -> *mut u8 =
                core::mem::transmute(vtable.add(0xe4 / 4).read());
            let object = get(manager);
            if object.is_null() { heap_panic(); }
            let cast = object_cast_to_class(object.cast(), 0x1700);
            if !cast.is_null() {
                let vtable = (cast as *const *const usize).read();
                let method: unsafe extern "C" fn(*mut u8, u32) =
                    core::mem::transmute(vtable.add(0x174 / 4).read());
                method(cast, 0);
            }
        }
    }
    1
}

/// Dispatch class-0x1700 slot +0x174 with zero when mode and configuration allow.
/// # Safety
/// Dependencies must satisfy their port contracts; returned objects must have
/// valid vtables through the slots documented above. A NULL +0xe4 result is fatal.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn class_1700_clear_when_configured(_owner: *mut u8, mode: i32) -> u32 {
    #[cfg(target_os = "none")]
    let ops = DEFAULT_OPS;
    #[cfg(not(target_os = "none"))]
    let ops = core::ptr::read_volatile(core::ptr::addr_of!(CLASS_1700_CLEAR_OPS));
    clear(mode, ops)
}

#[cfg(test)]
mod tests {
    use super::*;
    static LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
    static mut PRESENT: u32 = 0;
    static mut LIVE: bool = false;
    static mut OBJECT: *mut u8 = core::ptr::null_mut();
    #[repr(C)]
    struct Object { vtable: *const usize, accepted: bool, value: u32, calls: u32 }
    unsafe extern "C" fn key() -> *const u8 { b"configured\0".as_ptr() }
    unsafe extern "C" fn create(s: *mut *mut u8, p: *const u8) -> *mut *mut u8 {
        assert!(!LIVE); LIVE = true; s.write(p as *mut u8); s
    }
    unsafe extern "C" fn release(_: *mut *mut u8) { assert!(LIVE); LIVE = false; }
    unsafe extern "C" fn has(_: *mut u8, _: *const u32) -> u32 { assert!(LIVE); PRESENT }
    unsafe extern "C" fn instance() -> *mut u8 { assert!(!LIVE); OBJECT }
    unsafe extern "C" fn get(p: *mut u8) -> *mut u8 { assert!(!LIVE); p }
    unsafe extern "C" fn cast(p: *mut super::super::registry::FrameworkObject, id: u32) -> *mut u8 {
        assert_eq!(id, 0x1700);
        if (*(p as *mut Object)).accepted { p.cast() } else { core::ptr::null_mut() }
    }
    unsafe extern "C" fn set(p: *mut u8, value: u32) {
        let o = &mut *p.cast::<Object>(); o.value = value; o.calls += 1;
    }
    #[test]
    fn mode_configuration_and_failed_cast_preserve_state() {
        let _lock = LOCK.lock();
        let mut vtable = [0usize; 0x174 / 4 + 1];
        vtable[5] = cast as *const () as usize;
        vtable[0xe4 / 4] = get as *const () as usize;
        vtable[0x174 / 4] = set as *const () as usize;
        let mut object = Object { vtable: vtable.as_ptr(), accepted: true, value: 99, calls: 0 };
        let ops = Class1700ClearOps { key, create, release, has_string: has, instance };
        unsafe {
            OBJECT = (&mut object as *mut Object).cast();
            for mode in [1, -1, i32::MIN, i32::MAX] {
                PRESENT = u32::MAX;
                assert_eq!(clear(mode, ops), 1);
                assert_eq!((object.value, object.calls), (99, 0));
                assert!(!LIVE);
            }
            PRESENT = 0;
            assert_eq!(clear(0, ops), 1);
            assert_eq!((object.value, object.calls), (99, 0));
            PRESENT = 1; object.accepted = false;
            assert_eq!(clear(0, ops), 1);
            assert_eq!((object.value, object.calls), (99, 0));
            object.accepted = true;
            for present in [1, 0x80000000, u32::MAX] {
                PRESENT = present; object.value = 99;
                let before = object.calls;
                assert_eq!(clear(0, ops), 1);
                assert_eq!((object.value, object.calls), (0, before + 1));
                assert!(!LIVE);
            }
            OBJECT = core::ptr::null_mut();
        }
    }
}
