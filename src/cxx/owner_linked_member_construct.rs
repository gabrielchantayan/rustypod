//! Owner-linked member constructor: FUN_0827c688 @ 0x0827c688.
//! True extent: 60 bytes (56 code + 4 literal), next entry 0x0827c6c4.
//! Raw-word decoding: two outgoing plain BLs, zero predicated BLs; two
//! incoming plain BLs at 0x0827c324/0x0827ca68, zero predicated BLs.
//!
//! Construct the base with the third argument, install vtable 0x089a83e0,
//! clear word +0x8c, store the second argument at +0x88, then construct the
//! three-word member at +0x90 with the base result as its owner. Return the
//! member constructor's result minus 0x90. Ghidra incorrectly declares the
//! member constructor void and omits the live r1 owner argument at the call.
//!
//! Deliberate deviations: none on target. The unported base is a typed call
//! to its verified retail address; the owner member uses the Rust port.
//! Host builds expose the base seam and retain target-width word offsets.

pub type BaseConstruct = unsafe extern "C" fn(*mut u32, u32) -> *mut u32;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_base(_: *mut u32, _: u32) -> *mut u32 {
    panic!("install owner-linked base constructor host seam")
}
#[cfg(not(target_os = "none"))]
pub static mut OWNER_LINKED_BASE_CONSTRUCT: BaseConstruct = missing_base;

/// # Safety
/// Storage and constructor results must be aligned, writable objects with at
/// least 39 target words. The retail constructors' preconditions also apply.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn owner_linked_member_construct(
    this: *mut u32, value: u32, base_value: u32,
) -> *mut u32 {
    #[cfg(target_os = "none")]
    let base: BaseConstruct = unsafe {
        core::mem::transmute(0x0827_c534usize)
    };
    #[cfg(not(target_os = "none"))]
    let base = unsafe {
        core::ptr::addr_of!(OWNER_LINKED_BASE_CONSTRUCT).read_volatile()
    };
    let object = unsafe { base(this, base_value) };
    unsafe {
        object.write_volatile(0x089a_83e0);
        object.add(35).write_volatile(0);
        object.add(34).write_volatile(value);
        super::owner_member_construct::owner_member_construct(
            object.add(36), object as usize as u32,
        ).wrapping_sub(36)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Model only the unported base's observable output: poison every word so
    // the wrapper must preserve all base-owned fields, not zero the object.
    unsafe extern "C" fn base(this: *mut u32, value: u32) -> *mut u32 {
        let object = unsafe { this.add(1) };
        for i in 0..39 {
            unsafe { object.add(i).write(value ^ i as u32) };
        }
        object
    }

    #[test]
    fn preserves_base_fields_and_initializes_owner_member_at_target_offsets() {
        unsafe { OWNER_LINKED_BASE_CONSTRUCT = base };
        for value in [0, 1, 0x8000_0000, u32::MAX] {
            for base_value in [0, 0xa5a5_a5a5, u32::MAX] {
                let mut storage = [0xdead_beef; 41];
                let object = unsafe { storage.as_mut_ptr().add(1) };
                let returned = unsafe {
                    owner_linked_member_construct(storage.as_mut_ptr(), value, base_value)
                };
                assert_eq!(returned, object);
                let mut expected = [0u32; 39];
                for (i, word) in expected.iter_mut().enumerate() {
                    *word = base_value ^ i as u32;
                }
                expected[0] = 0x089a_83e0;
                expected[34] = value;
                expected[35] = 0;
                expected[36] = 0x089a_8354;
                expected[37] = 0;
                expected[38] = object as usize as u32;
                assert_eq!(&storage[1..40], &expected);
                assert_eq!(storage[0], 0xdead_beef);
                assert_eq!(storage[40], 0xdead_beef);
            }
        }
        unsafe {
            OWNER_LINKED_BASE_CONSTRUCT = missing_base;
        }
    }
}
