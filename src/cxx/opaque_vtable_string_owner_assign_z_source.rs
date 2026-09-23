//! Assign an opaque StringObject owner from a source only for the `"Z"` tag.
//!
//! Original: `FUN_0816ddb4` at load address `0x0816ddb4` (108 bytes,
//! `0x0816ddb4..0x0816de1f`). Raw `osos.dec` words establish four plain,
//! unconditional `bl` calls (to `utf8_strcmp_safe`, `record_lookup_value_word`,
//! the unrecovered trailing-pair advance helper, and `string_object_c_str`),
//! one indirect `blx` through owner vtable slot +0x08, and zero predicated
//! `bl` calls. `0x0816de20` is the `"Z\\0"` literal; the next real function
//! begins at `0x0816de24`.
//!
//! The owner first dispatches its vtable +0x08 slot, then proceeds only when
//! its embedded StringObject payload UTF-8-compares equal to `"Z"`. A non-NULL
//! source is looked up under key zero; that value advances the trailing pair,
//! and the source's NULL-safe C string is assigned into the embedded string.
//!
//! Deliberate deviations: the vtable slot and the unrecovered helper at
//! `0x081b4d54` remain explicit host seams. Target builds invoke their verified
//! firmware addresses directly; all identified calls use existing Rust ports.

use core::mem;

use super::opaque_vtable_string_owner_destroy::OpaqueVtableStringOwner;
use super::string_object::{string_object_assign_payload, string_object_c_str, utf8_strcmp_safe, StringObject};
use crate::ui::record_lookup_value_word::record_lookup_value_word;

type OwnerSlot8 = unsafe extern "C" fn(*mut OpaqueVtableStringOwner);
type TrailingPairAdvance = unsafe extern "C" fn(*mut u32, u32);

const TRAILING_PAIR_ADVANCE_ADDRESS: usize = 0x081b_4d54;

#[cfg(target_os = "none")]
unsafe fn owner_slot_8(this: *mut OpaqueVtableStringOwner) {
    let vtable = (*this).vtable as *const usize;
    let callback: OwnerSlot8 = mem::transmute(vtable.add(2).read_volatile());
    callback(this);
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_owner_slot_8(_: *mut OpaqueVtableStringOwner) {
    panic!("opaque owner slot +0x08 seam was not configured")
}

#[cfg(not(target_os = "none"))]
pub static mut OPAQUE_VTABLE_STRING_OWNER_SLOT_8: OwnerSlot8 = missing_owner_slot_8;
#[cfg(not(target_os = "none"))]
unsafe fn owner_slot_8(this: *mut OpaqueVtableStringOwner) {
    OPAQUE_VTABLE_STRING_OWNER_SLOT_8(this);
}


unsafe fn advance_trailing_pair(pair: *mut u32, value: u32) {
    #[cfg(target_os = "none")]
    {
        let advance: TrailingPairAdvance = mem::transmute(TRAILING_PAIR_ADVANCE_ADDRESS);
        advance(pair, value);
    }
    #[cfg(not(target_os = "none"))]
    {
        OPAQUE_VTABLE_STRING_OWNER_TRAILING_PAIR_ADVANCE(pair, value);
    }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_trailing_pair_advance(_: *mut u32, _: u32) {
    panic!("opaque owner trailing-pair advance seam was not configured")
}

#[cfg(not(target_os = "none"))]
pub static mut OPAQUE_VTABLE_STRING_OWNER_TRAILING_PAIR_ADVANCE: TrailingPairAdvance = missing_trailing_pair_advance;

/// `opaque_vtable_string_owner_assign_z_source` — original: `FUN_0816ddb4` @
/// `0x0816ddb4` (108 bytes; four plain BL calls, zero predicated BL calls).
///
/// # Safety
///
/// `this` must be a valid owner. When non-NULL, `source` must be a valid
/// StringObject. The firmware does not guard either object before dereference.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn opaque_vtable_string_owner_assign_z_source(
    this: *mut OpaqueVtableStringOwner,
    source: *mut StringObject,
) {
    owner_slot_8(this);

    if utf8_strcmp_safe((*this).string.payload, b"Z\0".as_ptr()) != 0 || source.is_null() {
        return;
    }

    let value = record_lookup_value_word(source.cast(), 0);
    advance_trailing_pair((*this).trailing_pair.as_mut_ptr(), value);
    string_object_assign_payload(&mut (*this).string, string_object_c_str(source));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cxx::string_object::StringObject;
    use parking_lot::Mutex;
    use core::ptr;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut SLOT_CALLS: usize = 0;

    unsafe extern "C" fn record_slot_call(_: *mut OpaqueVtableStringOwner) {
        SLOT_CALLS += 1;
    }

    fn owner(payload: *mut u8) -> OpaqueVtableStringOwner {
        OpaqueVtableStringOwner {
            vtable: 0,
            opaque_words: [0; 4],
            string: StringObject { vtable: ptr::null(), payload },
            trailing_pair: [0x1234_5678, 0x9abc_def0],
        }
    }

    #[test]
    fn non_z_tag_dispatches_slot_but_leaves_owner_unchanged() {
        let _guard = TEST_LOCK.lock();
        unsafe {
            OPAQUE_VTABLE_STRING_OWNER_SLOT_8 = record_slot_call;
            SLOT_CALLS = 0;
            let mut owner = owner(b"X\0".as_ptr().cast_mut());
            opaque_vtable_string_owner_assign_z_source(&mut owner, ptr::null_mut());
            assert_eq!(SLOT_CALLS, 1);
            assert_eq!(owner.trailing_pair, [0x1234_5678, 0x9abc_def0]);
        }
    }

    #[test]
    fn z_tag_with_null_source_stops_after_slot_dispatch() {
        let _guard = TEST_LOCK.lock();
        unsafe {
            OPAQUE_VTABLE_STRING_OWNER_SLOT_8 = record_slot_call;
            SLOT_CALLS = 0;
            let mut owner = owner(b"Z\0".as_ptr().cast_mut());
            opaque_vtable_string_owner_assign_z_source(&mut owner, ptr::null_mut());
            assert_eq!(SLOT_CALLS, 1);
            assert_eq!(owner.trailing_pair, [0x1234_5678, 0x9abc_def0]);
        }
    }
}
