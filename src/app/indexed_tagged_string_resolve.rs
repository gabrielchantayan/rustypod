//! Indexed tagged-string override resolution — `FUN_081002cc` @ `0x081002cc`.
//!
//! True extent 172 bytes: 168 code bytes and a table-pointer literal at
//! 0x08100374; the next function starts at 0x08100378. Whole-image decoding
//! finds two incoming plain BLs (0x0810054c, 0x08101284), zero predicated
//! BLs. The body has seven plain BLs, zero predicated BLs and two tail calls.
//! Reject negative/out-of-range indices, fetch the indexed record, then search
//! its string pairs for the key at runtime table 0x089ca6e4 indexed by the
//! class-0x6000 property minus 0x6067. Return the first matching nonempty value;
//! an empty first match or no match resolves the original tagged record.
//!
//! Deliberate deviations: the identity accessor at 0x082a1df4 (`bx lr`) is
//! eliminated, and the +8 accessor is represented by the second repr(C) field.
//! Host record range pointers are separate fields; ARM uses the existing opaque
//! words at +0x3c/+0x40. String pairs and collection pointers widen on hosts.
//! No bounds check is added to the firmware property-table lookup.

use crate::app::class_6000_property::class6000_dirp_property_6066_or_default;
use crate::app::tagged_string_resolve::{tagged_string_resolve, TaggedStringRecord};
use crate::cxx::templates::container_element_at_alias_5f14;
use crate::cxx::string_object::{StringObject, string_object_c_str, string_object_is_empty, utf8_strcmp_safe};

#[repr(C)]
pub struct StringOverridePair {
    pub key: StringObject,
    pub value: StringObject,
}

#[repr(C)]
pub struct IndexedTaggedRecord {
    pub tagged: TaggedStringRecord,
    #[cfg(not(target_os = "none"))]
    pub begin: *const StringOverridePair,
    #[cfg(not(target_os = "none"))]
    pub end: *const StringOverridePair,
}

#[repr(C)]
pub struct IndexedTaggedStringOwner {
    pub opaque: [u32; 10],
    pub collection_vtable: *const u8,
    pub count: i32,
}

unsafe fn resolve_override(record: *const IndexedTaggedRecord, key: *const u8) -> *const u8 {
    #[cfg(target_os = "none")]
    let (mut cursor, end) = (
        (*record).tagged.opaque[12] as *const StringOverridePair,
        (*record).tagged.opaque[13] as *const StringOverridePair,
    );
    #[cfg(not(target_os = "none"))]
    let (mut cursor, end) = ((*record).begin, (*record).end);
    while cursor != end {
        if utf8_strcmp_safe((*cursor).key.payload, key) == 0 {
            let value = core::ptr::addr_of!((*cursor).value);
            if !string_object_is_empty(value) {
                return string_object_c_str(value);
            }
            break;
        }
        cursor = cursor.add(1);
    }
    tagged_string_resolve(core::ptr::addr_of!((*record).tagged))
}

/// # Safety
/// The owner, its slot +0x40, selected record and pair range must be valid.
/// A valid selected record also requires the current class-0x6000 context,
/// runtime key table and (for non-inline fallback) task resource context.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn indexed_tagged_string_resolve(
    owner: *mut IndexedTaggedStringOwner, index: i32,
) -> *const u8 {
    if index < 0 || (*owner).count <= index { return core::ptr::null(); }
    let collection = core::ptr::addr_of_mut!((*owner).collection_vtable).cast();
    let record = container_element_at_alias_5f14(collection, index as usize)
        as *const IndexedTaggedRecord;
    if record.is_null() { return core::ptr::null(); }
    let property = class6000_dirp_property_6066_or_default();
    let entry = 0x089c_a6e4u32.wrapping_add(property.wrapping_sub(0x6067).wrapping_mul(8));
    let key = (entry.wrapping_add(4) as usize as *const *const u8).read();
    resolve_override(record, key)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn string(text: *const u8) -> StringObject {
        StringObject { vtable: core::ptr::null(), payload: text as *mut u8 }
    }

    #[test]
    fn first_match_empty_value_and_missing_key_fall_back() {
        unsafe {
            let mut pairs = [
                StringOverridePair { key: string(b"other\0".as_ptr()), value: string(b"wrong\0".as_ptr()) },
                StringOverridePair { key: string(b"\xc3\xa9\0".as_ptr()), value: string(b"override\0".as_ptr()) },
                StringOverridePair { key: string(b"\xc3\xa9\0".as_ptr()), value: string(b"later\0".as_ptr()) },
            ];
            let mut record = IndexedTaggedRecord {
                tagged: TaggedStringRecord { tag: 1, reserved: [0; 3],
                    inline_string: string(b"fallback\0".as_ptr()), opaque: [0; 15], resource_id: 0 },
                begin: pairs.as_ptr(), end: pairs.as_ptr().add(pairs.len()),
            };
            assert_eq!(resolve_override(&record, b"\xc3\xa9\0".as_ptr()), pairs[1].value.payload);
            assert_eq!(resolve_override(&record, b"missing\0".as_ptr()), record.tagged.inline_string.payload);
            pairs[1].value.payload = core::ptr::null_mut();
            assert_eq!(resolve_override(&record, b"\xc3\xa9\0".as_ptr()), record.tagged.inline_string.payload);
            pairs[1].value.payload = b"\0".as_ptr() as *mut u8;
            assert_eq!(resolve_override(&record, b"\xc3\xa9\0".as_ptr()), record.tagged.inline_string.payload);
            record.end = record.begin;
            assert_eq!(resolve_override(&record, core::ptr::null()), record.tagged.inline_string.payload);
            record.tagged.inline_string.payload = core::ptr::null_mut();
            assert_eq!(*resolve_override(&record, core::ptr::null()), 0);
            record.end = record.begin.add(1);
            pairs[0].key.payload = core::ptr::null_mut();
            assert_eq!(resolve_override(&record, core::ptr::null()), pairs[0].value.payload);
        }
    }

    unsafe extern "C" fn absent(_: *mut u8, _: usize) -> *mut *mut u8 {
        static mut CELL: *mut u8 = core::ptr::null_mut();
        core::ptr::addr_of_mut!(CELL)
    }

    #[test]
    fn signed_bounds_and_absent_element_return_null() {
        unsafe {
            assert!(indexed_tagged_string_resolve(core::ptr::null_mut(), -1).is_null());
            let vtable = [absent as unsafe extern "C" fn(*mut u8, usize) -> *mut *mut u8; 17];
            let mut owner = IndexedTaggedStringOwner { opaque: [0; 10],
                collection_vtable: vtable.as_ptr().cast(), count: 2 };
            for index in [0, 1, 2, i32::MAX] {
                assert!(indexed_tagged_string_resolve(&mut owner, index).is_null());
            }
            owner.count = -1;
            assert!(indexed_tagged_string_resolve(&mut owner, 0).is_null());
        }
    }
}
