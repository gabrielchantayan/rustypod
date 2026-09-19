//! OpenSSL ASN.1 template auxiliary database selection.
//!
//! `asn1_do_adb` — original: `FUN_082b4b14` @ 0x082b4b14 (176 bytes,
//! 0x082b4b14..0x082b4bc4; the next separately linked function begins at
//! 0x082b4bc4). Raw ARM has three plain internal `bl` instructions and no
//! predicated `bl`; decoding every inbound ARM branch word finds five plain
//! `bl` callers and no predicated forms.
//!
//! OpenSSL's `asn1_do_adb`: templates without ADB flags pass through. For an
//! ADB template, select `null_tt` if the containing value's offset slot is
//! NULL; otherwise derive the selector from an OID or ASN1_INTEGER, scan the
//! 24-byte ADB table for its matching value, then use `default_tt`. A missing
//! selector returns NULL and records `(13, 110, 164, 0, 0)` when requested.
//!
//! Deliberate deviations: `ASN1_INTEGER_get` @ 0x08039f74 and
//! `OBJ_obj2nid` are called directly on target and represented by volatile
//! host seams. Target pointer fields remain raw `u32` words, avoiding 64-bit
//! host-layout drift.

use crate::crypto::asn1_integer_get::asn1_integer_get;
#[cfg(target_os = "none")]
use crate::crypto::obj_dat::{obj_obj2nid, Asn1Object};
use crate::kernel::diag_ring_record::diag_ring_record;

const ADB_MASK: u32 = 0x300;
const ADB_OID: u32 = 0x100;


type Selector = unsafe extern "C" fn(*const u32) -> i32;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_asn1_integer_get(_value: *const u32) -> i32 {
    panic!("asn1_do_adb requires OBJ_obj2nid 0x0805f074")
}

#[cfg(not(target_os = "none"))]
pub static mut ASN1_OBJECT_TO_NID: Selector = missing_asn1_integer_get;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn asn1_object_to_nid(value: *const u32) -> i32 {
    unsafe { obj_obj2nid(value.cast::<Asn1Object>()) }
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn asn1_object_to_nid(value: *const u32) -> i32 {
    let function = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(ASN1_OBJECT_TO_NID)) };
    unsafe { function(value) }
}

#[inline(always)]
unsafe fn word(pointer: *const u32, index: usize) -> u32 {
    unsafe { pointer.add(index).read() }
}

/// asn1_do_adb — original: `FUN_082b4b14` @ 0x082b4b14.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn asn1_do_adb(
    value_slot: *const u32,
    template: *const u32,
    null_error: i32,
) -> *const u32 {
    let flags = unsafe { word(template, 0) };
    if flags & ADB_MASK == 0 {
        return template;
    }

    let adb = unsafe { word(template, 4) as usize as *const u32 };
    let containing_value = unsafe { word(value_slot, 0) };
    let offset = unsafe { word(adb, 1) };
    if containing_value.wrapping_add(offset) == 0 {
        return unsafe { word(adb, 6) as usize as *const u32 };
    }

    let selector_value = unsafe {
        if flags & ADB_OID != 0 {
            asn1_object_to_nid(containing_value as usize as *const u32)
        } else {
            asn1_integer_get(containing_value as usize as *const u32)
        }
    };
    let mut entry = unsafe { word(adb, 3) as usize as *const u32 };
    let entries = unsafe { word(adb, 4) };
    for _ in 0..entries {
        if unsafe { word(entry, 0) } == selector_value as u32 {
            return unsafe { entry.add(1) };
        }
        entry = unsafe { entry.add(6) };
    }

    let default_template = unsafe { word(adb, 5) as usize as *const u32 };
    if !default_template.is_null() {
        return default_template;
    }
    if null_error != 0 {
        unsafe { diag_ring_record(13, 110, 164, 0, 0) };
    }
    core::ptr::null()
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use parking_lot::Mutex;
    use std::sync::LazyLock;

    const SLAB_LEN: usize = 0x1000;
    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::ASN1_DO_ADB, SLAB_LEN).map(|pointer| pointer as usize)
    });
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    unsafe extern "C" fn selector_42(_value: *const u32) -> i32 { 42 }
    unsafe extern "C" fn selector_99(_value: *const u32) -> i32 { 99 }

    unsafe fn fixture() -> Option<*mut u32> {
        let slab = *SLAB;
        if slab.is_none() {
            assert!(note_missing_u32_fixture("crypto/asn1_adb"));
        }
        let base = slab? as *mut u32;
        unsafe { core::ptr::write_bytes(base.cast::<u8>(), 0, SLAB_LEN); }
        Some(base)
    }

    #[test]
    fn non_adb_template_passes_through() {
        let _guard = TEST_LOCK.lock();
        let Some(base) = (unsafe { fixture() }) else { return };
        unsafe { base.add(8).write(0); }
        assert_eq!(unsafe { asn1_do_adb(base, base.add(8), 0) }, unsafe { base.add(8) });
    }

    #[test]
    fn oid_selector_returns_matching_table_template() {
        let _guard = TEST_LOCK.lock();
        let Some(base) = (unsafe { fixture() }) else { return };
        let template = unsafe { base.add(8) };
        let adb = unsafe { base.add(32) };
        let table = unsafe { base.add(64) };
        unsafe {
            ASN1_OBJECT_TO_NID = selector_42;
            base.write(base.add(160) as usize as u32);
            template.write(ADB_OID);
            template.add(4).write(adb as usize as u32);
            adb.add(1).write(4);
            adb.add(3).write(table as usize as u32);
            adb.add(4).write(2);
            table.write(7);
            table.add(6).write(42);
        }
        assert_eq!(unsafe { asn1_do_adb(base, template, 0) }, unsafe { table.add(7) });
    }

    #[test]
    fn integer_selector_uses_default_after_table_miss() {
        let _guard = TEST_LOCK.lock();
        let Some(base) = (unsafe { fixture() }) else { return };
        let template = unsafe { base.add(8) };
        let adb = unsafe { base.add(32) };
        let table = unsafe { base.add(64) };
        let default_template = unsafe { base.add(128) };
        unsafe {
            base.add(160).write(1);
            base.add(161).write(2);
            base.add(162).write(base.add(164) as usize as u32);
            (base.add(164) as *mut u8).write(99);
            base.write(base.add(160) as usize as u32);
            template.write(0x200);
            template.add(4).write(adb as usize as u32);
            adb.add(3).write(table as usize as u32);
            adb.add(4).write(1);
            adb.add(5).write(default_template as usize as u32);
            table.write(42);
        }
        assert_eq!(unsafe { asn1_do_adb(base, template, 0) }, default_template);
    }

    #[test]
    fn null_containing_value_returns_null_template() {
        let _guard = TEST_LOCK.lock();
        let Some(base) = (unsafe { fixture() }) else { return };
        let template = unsafe { base.add(8) };
        let adb = unsafe { base.add(32) };
        let null_template = unsafe { base.add(128) };
        unsafe {
            template.write(ADB_MASK);
            template.add(4).write(adb as usize as u32);
            adb.add(1).write(0);
            adb.add(6).write(null_template as usize as u32);
        }
        assert_eq!(unsafe { asn1_do_adb(base, template, 0) }, null_template);
    }
}
