//! Attribute-list replacement by object identifier.
//!
//! FUN_08081aa8 @ 0x08081aa8, 180 bytes (through 0x08081b5c, whose
//! first instruction starts the next function). Raw A32 scan: two incoming
//! plain BLs (0x0805fd3c, 0x0805fd7c), nine outgoing plain BLs, no predicated
//! BLs in either direction. Lazily allocate a stack; otherwise scan its signed
//! count for the first attribute whose object resolves to the requested NID.
//! Free that attribute before constructing and storing its replacement. If no
//! match exists, construct and append. Ignore failures and always return 1.
//!
//! Deviations: unported attribute create/free routines are direct firmware
//! calls on device and injectable host seams. Reuse the existing stack factory,
//! push and object-to-NID ports. Host stack/attribute slots are pointer-sized,
//! matching the existing push fixture convention; count/value/set accessors
//! use that layout on hosts because their existing ports use target offsets.

use super::obj_dat::{obj_obj2nid, Asn1Object};
use crate::cxx::object_flags::namespace_provider_push;
use crate::drivers::ata_cmd::ata_call_with_zero;

pub type AttributeCreate = unsafe extern "C" fn(i32, i32, usize) -> *mut usize;
pub type AttributeFree = unsafe extern "C" fn(*mut usize);

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_create(_: i32, _: i32, _: usize) -> *mut usize {
    panic!("attribute_list_upsert requires attribute constructor 0x0806f0a4")
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_free(_: *mut usize) {
    panic!("attribute_list_upsert requires attribute destructor 0x0806f148")
}
#[cfg(not(target_os = "none"))]
pub static mut ATTRIBUTE_CREATE: AttributeCreate = missing_create;
#[cfg(not(target_os = "none"))]
pub static mut ATTRIBUTE_FREE: AttributeFree = missing_free;

#[inline(always)]
unsafe fn create(nid: i32, value_type: i32, value: usize) -> *mut usize {
    #[cfg(target_os = "none")]
    let call: AttributeCreate = core::mem::transmute(0x0806_f0a4usize);
    #[cfg(not(target_os = "none"))]
    let call = core::ptr::addr_of!(ATTRIBUTE_CREATE).read_volatile();
    call(nid, value_type, value)
}
#[inline(always)]
unsafe fn free(attribute: *mut usize) {
    #[cfg(target_os = "none")]
    let call: AttributeFree = core::mem::transmute(0x0806_f148usize);
    #[cfg(not(target_os = "none"))]
    let call = core::ptr::addr_of!(ATTRIBUTE_FREE).read_volatile();
    call(attribute);
}

#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn attribute_list_upsert(
    attributes: *mut *mut usize, nid: i32, value_type: i32, value: usize,
) -> i32 {
    if (*attributes).is_null() {
        *attributes = ata_call_with_zero().cast();
    } else {
        let mut index = 0u32;
        loop {
            #[cfg(target_os = "none")]
            let count = crate::cxx::object_flags::namespace_provider_count((*attributes).cast());
            #[cfg(not(target_os = "none"))]
            let count = (*attributes).read_volatile() as i32;
            if count <= index as i32 { break; }
            #[cfg(target_os = "none")]
            let attribute = crate::cxx::object_flags::namespace_provider_at((*attributes).cast(), index) as *mut usize;
            #[cfg(not(target_os = "none"))]
            let attribute = ((*attributes).add(1).read_volatile() as *const usize)
                .add(index as usize).read_volatile() as *mut usize;
            if obj_obj2nid(attribute.read() as *const Asn1Object) == nid {
                free(attribute);
                let replacement = create(nid, value_type, value);
                #[cfg(target_os = "none")]
                crate::cxx::object_flags::namespace_provider_set((*attributes).cast(), index, replacement as u32);
                #[cfg(not(target_os = "none"))]
                ((*attributes).add(1).read_volatile() as *mut usize)
                    .add(index as usize).write_volatile(replacement as usize);
                return 1;
            }
            index = index.wrapping_add(1);
        }
    }
    let attribute = create(nid, value_type, value);
    namespace_provider_push(*attributes, attribute as usize);
    1
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;
    static LOCK: Mutex<()> = Mutex::new(());
    static mut FREED: usize = 0;
    static mut CREATED: usize = 0;
    static mut RESULT: usize = 0;
    unsafe extern "C" fn construct(nid: i32, kind: i32, value: usize) -> *mut usize {
        assert_eq!((nid, kind, value), (42, 4, 123));
        CREATED += 1;
        RESULT as *mut usize
    }
    unsafe extern "C" fn destroy(attribute: *mut usize) {
        assert_eq!(CREATED, 0, "free must precede construction");
        FREED = attribute as usize;
    }
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) { unsafe { ATTRIBUTE_CREATE = missing_create; ATTRIBUTE_FREE = missing_free; } }
    }
    #[test]
    fn replace_first_duplicate_and_preserve_other_entries_even_on_create_failure() {
        let _lock = LOCK.lock();
        let _reset = Reset;
        unsafe {
            ATTRIBUTE_CREATE = construct; ATTRIBUTE_FREE = destroy;
            for result in [0usize, 0x1234] {
                FREED = 0; CREATED = 0; RESULT = result;
                let mut object: Asn1Object = core::mem::zeroed();
                object.nid = 42;
                let mut first = [&object as *const _ as usize, 0, 0];
                let mut second = [&object as *const _ as usize, 0, 0];
                let mut entries = [first.as_mut_ptr() as usize, second.as_mut_ptr() as usize, 0];
                let mut stack = [2usize, entries.as_mut_ptr() as usize, 1, 3, 0];
                let mut pointer = stack.as_mut_ptr();
                assert_eq!(attribute_list_upsert(&mut pointer, 42, 4, 123), 1);
                assert_eq!(FREED, first.as_mut_ptr() as usize);
                assert_eq!(CREATED, 1);
                assert_eq!(entries, [result, second.as_mut_ptr() as usize, 0]);
                assert_eq!(stack[0], 2);
                assert_eq!(stack[2], 1);
            }
        }
    }
    #[test]
    fn append_to_empty_or_unmatched_stack_including_null_constructor_result() {
        let _lock = LOCK.lock();
        let _reset = Reset;
        unsafe {
            ATTRIBUTE_CREATE = construct; ATTRIBUTE_FREE = destroy;
            for count in [0usize, 1] {
                FREED = 0; CREATED = 0; RESULT = 0;
                let mut object: Asn1Object = core::mem::zeroed();
                object.nid = 7;
                let mut attribute = [&object as *const _ as usize, 0, 0];
                let mut entries = [attribute.as_mut_ptr() as usize, 99, 99, 99];
                let mut stack = [count, entries.as_mut_ptr() as usize, 1, 4, 0];
                let mut pointer = stack.as_mut_ptr();
                assert_eq!(attribute_list_upsert(&mut pointer, 42, 4, 123), 1);
                assert_eq!(stack[0], count + 1);
                assert_eq!(stack[2], 0);
                assert_eq!(entries[count], 0);
                if count == 1 { assert_eq!(entries[0], attribute.as_mut_ptr() as usize); }
                assert_eq!(FREED, 0);
                assert_eq!(CREATED, 1);
            }
        }
    }
}
