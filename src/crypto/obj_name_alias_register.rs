//! Register the short and long object names of a two-NID alias.
//!
//! `obj_name_alias_register` — original: `FUN_0804b15c` @ 0x0804b15c
//! (148 bytes: 37 instructions through the literal-pool word @ 0x0804b1f0;
//! the next separately linked function begins at 0x0804b1f4). The raw ARM
//! image has four plain `bl` callers (0x0805f510, 0x0805f53c, 0x0805f544,
//! and 0x082d426c), zero predicated `bl` callers, and seven direct calls in
//! the body.
//!
//! The routine registers the primary NID's short and long names under key
//! flag one with the supplied two-word pair. If both NIDs differ, it then
//! registers the secondary names under flag 0x8001, each aliased to the
//! corresponding primary name. Every registration failure short-circuits;
//! the final registration's result is returned. Deliberate deviation: the
//! still-unidentified name-registration callee at 0x0805e7dc is a typed
//! volatile seam; the two established NID-name ports are reached through
//! likewise typed target/host dispatch rather than exposing its internal map.

use crate::crypto::obj_dat::{obj_nid2ln, obj_nid2sn};

/// The two target-width NID words consumed by `obj_name_alias_register`.
#[repr(C)]
pub struct ObjNameAliasPair {
    pub primary_nid: i32,
    pub secondary_nid: i32,
}

type ObjNidName = unsafe extern "C" fn(i32) -> *const u8;
type ObjNameRegister = unsafe extern "C" fn(*const u8, u32, *const u32) -> u32;

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_obj_name_register(
    name: *const u8,
    flags: u32,
    value: *const u32,
) -> u32 {
    let register: ObjNameRegister = unsafe { core::mem::transmute(0x0805_e7dcusize) };
    unsafe { register(name, flags, value) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_obj_name_register(
    _name: *const u8,
    _flags: u32,
    _value: *const u32,
) -> u32 {
    panic!("obj_name_alias_register requires name registration at 0x0805e7dc")
}

#[cfg(target_os = "none")]
static mut OBJ_NAME_REGISTER: ObjNameRegister = firmware_obj_name_register;
#[cfg(not(target_os = "none"))]
static mut OBJ_NAME_REGISTER: ObjNameRegister = missing_obj_name_register;

#[cfg(target_os = "none")]
static mut OBJ_NID2SN: ObjNidName = obj_nid2sn;
#[cfg(not(target_os = "none"))]
static mut OBJ_NID2SN: ObjNidName = missing_obj_nid_name;
#[cfg(target_os = "none")]
static mut OBJ_NID2LN: ObjNidName = obj_nid2ln;
#[cfg(not(target_os = "none"))]
static mut OBJ_NID2LN: ObjNidName = missing_obj_nid_name;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_obj_nid_name(_nid: i32) -> *const u8 {
    panic!("obj_name_alias_register requires an installed NID-name fixture")
}

#[inline(always)]
unsafe fn obj_name_register() -> ObjNameRegister {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(OBJ_NAME_REGISTER)) }
}

#[inline(always)]
unsafe fn obj_nid2short_name() -> ObjNidName {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(OBJ_NID2SN)) }
}

#[inline(always)]
unsafe fn obj_nid2long_name() -> ObjNidName {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(OBJ_NID2LN)) }
}

#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn obj_name_alias_register(pair: *const ObjNameAliasPair) -> u32 {
    let primary_nid = unsafe { (*pair).primary_nid };
    let primary_short_name = unsafe { obj_nid2short_name()(primary_nid) };
    if unsafe { obj_name_register()(primary_short_name, 1, pair.cast()) } == 0 {
        return 0;
    }

    let primary_long_name = unsafe { obj_nid2long_name()(primary_nid) };
    if unsafe { obj_name_register()(primary_long_name, 1, pair.cast()) } == 0 {
        return 0;
    }

    let secondary_nid = unsafe { (*pair).secondary_nid };
    if primary_nid == secondary_nid {
        return 1;
    }

    let secondary_short_name = unsafe { obj_nid2short_name()(secondary_nid) };
    if unsafe { obj_name_register()(secondary_short_name, 0x8001, primary_short_name.cast()) } == 0 {
        return 0;
    }

    let secondary_long_name = unsafe { obj_nid2long_name()(secondary_nid) };
    unsafe { obj_name_register()(secondary_long_name, 0x8001, primary_long_name.cast()) }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut NAMES: [[u8; 1]; 4] = [[11], [12], [21], [22]];
    static mut CALLS: [(usize, u32, usize); 4] = [(0, 0, 0); 4];
    static mut CALL_COUNT: usize = 0;
    static mut RESULTS: [u32; 4] = [1; 4];

    unsafe extern "C" fn short_name(nid: i32) -> *const u8 {
        unsafe { NAMES[(nid as usize - 1) * 2].as_ptr() }
    }

    unsafe extern "C" fn long_name(nid: i32) -> *const u8 {
        unsafe { NAMES[(nid as usize - 1) * 2 + 1].as_ptr() }
    }

    unsafe extern "C" fn record_register(name: *const u8, flags: u32, value: *const u32) -> u32 {
        unsafe {
            CALLS[CALL_COUNT] = (name as usize, flags, value as usize);
            let result = RESULTS[CALL_COUNT];
            CALL_COUNT += 1;
            result
        }
    }

    fn install(results: [u32; 4]) {
        unsafe {
            OBJ_NID2SN = short_name;
            OBJ_NID2LN = long_name;
            OBJ_NAME_REGISTER = record_register;
            CALL_COUNT = 0;
            RESULTS = results;
        }
    }

    fn restore() {
        unsafe {
            OBJ_NID2SN = missing_obj_nid_name;
            OBJ_NID2LN = missing_obj_nid_name;
            OBJ_NAME_REGISTER = missing_obj_name_register;
        }
    }

    #[test]
    fn registers_both_name_forms_for_distinct_nids() {
        let _guard = TEST_LOCK.lock();
        install([1; 4]);
        let pair = ObjNameAliasPair { primary_nid: 1, secondary_nid: 2 };

        assert_eq!(unsafe { obj_name_alias_register(&pair) }, 1);
        unsafe {
            assert_eq!(CALL_COUNT, 4);
            assert_eq!(CALLS[0], (NAMES[0].as_ptr() as usize, 1, (&pair as *const ObjNameAliasPair).cast::<u32>() as usize));
            assert_eq!(CALLS[1], (NAMES[1].as_ptr() as usize, 1, (&pair as *const ObjNameAliasPair).cast::<u32>() as usize));
            assert_eq!(CALLS[2], (NAMES[2].as_ptr() as usize, 0x8001, NAMES[0].as_ptr() as usize));
            assert_eq!(CALLS[3], (NAMES[3].as_ptr() as usize, 0x8001, NAMES[1].as_ptr() as usize));
        }
        restore();
    }

    #[test]
    fn stops_at_the_first_failed_registration() {
        let _guard = TEST_LOCK.lock();
        install([1, 0, 1, 1]);
        let pair = ObjNameAliasPair { primary_nid: 1, secondary_nid: 2 };

        assert_eq!(unsafe { obj_name_alias_register(&pair) }, 0);
        assert_eq!(unsafe { CALL_COUNT }, 2);
        restore();
    }

    #[test]
    fn equal_nids_only_register_the_primary_names() {
        let _guard = TEST_LOCK.lock();
        install([1; 4]);
        let pair = ObjNameAliasPair { primary_nid: 1, secondary_nid: 1 };

        assert_eq!(unsafe { obj_name_alias_register(&pair) }, 1);
        assert_eq!(unsafe { CALL_COUNT }, 2);
        restore();
    }
}
