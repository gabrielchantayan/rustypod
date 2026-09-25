//! Opaque 56-byte record initialization — `FUN_080476b8` @ 0x080476b8.
//!
//! Raw `osos.dec` establishes an 84-byte A32 body from 0x080476b8 through
//! the `pop {r4, r5, r6, pc}` at 0x08047704; the vtable literal at
//! 0x08047708 is data and the next independently entered function starts at
//! 0x0804770c. The body has two plain outgoing `bl` instructions (`bzero`
//! and the unported initializer at 0x080470bc), no predicated `bl`
//! instructions, and three plain inbound `bl` calls (0x08047c68, 0x08058680,
//! and 0x0805e494), with no predicated inbound calls.
//!
//! Algorithm: reject a NULL record with -50. Otherwise clear all 56 bytes,
//! store the supplied values at +48 and +52, initialize the 36-byte embedded
//! subobject at +12 with `(4, 0, 0)`, and install the record vtable on success.
//!
//! Deliberate deviation: 0x080470bc has no recovered semantic identity and
//! remains a direct retailOS call on target builds. Host builds reproduce only
//! its observed output layout so this outer initializer is testable.

use crate::bzero::bzero;
use core::ptr;

const RECORD_BYTES: i32 = 0x38;
const EMBEDDED_SUBOBJECT_OFFSET: usize = 0x0c;
const RECORD_VTABLE: u32 = 0x4d52_6376;
#[cfg(target_os = "none")]
const RETAIL_EMBEDDED_SUBOBJECT_INITIALIZE: usize = 0x0804_70bc;

#[cfg(target_os = "none")]
unsafe fn initialize_embedded_subobject(subobject: *mut u8) -> i32 {
    let initialize: unsafe extern "C" fn(u32, u32, u8, *mut u8) -> i32 =
        core::mem::transmute(RETAIL_EMBEDDED_SUBOBJECT_INITIALIZE);
    initialize(4, 0, 0, subobject)
}

#[cfg(not(target_os = "none"))]
unsafe fn initialize_embedded_subobject(subobject: *mut u8) -> i32 {
    const SUBOBJECT_BYTES: i32 = 0x24;
    const SUBOBJECT_VTABLE: u32 = 0x6172_6179;

    bzero(subobject, SUBOBJECT_BYTES);
    ptr::write(subobject.cast::<u32>(), SUBOBJECT_VTABLE);
    ptr::write(subobject.add(4).cast::<u32>(), 4);
    ptr::write(subobject.add(0x20), 0);
    ptr::write(subobject.add(0x21), 1);
    0
}

/// Initializes a caller-provided opaque 56-byte record.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn opaque_56_byte_record_initialize(
    record: *mut u8,
    first_value: u32,
    second_value: u32,
) -> i32 {
    if record.is_null() {
        return -50;
    }

    bzero(record, RECORD_BYTES);
    ptr::write(record.add(48).cast::<u32>(), first_value);
    ptr::write(record.add(52).cast::<u32>(), second_value);
    let status = initialize_embedded_subobject(record.add(EMBEDDED_SUBOBJECT_OFFSET));
    if status == 0 {
        ptr::write(record.cast::<u32>(), RECORD_VTABLE);
    }
    status
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(C, align(4))]
    struct AlignedRecord([u8; 64]);

    fn word(record: &AlignedRecord, offset: usize) -> u32 {
        u32::from_le_bytes(record.0[offset..offset + 4].try_into().unwrap())
    }

    #[test]
    fn null_record_returns_stock_invalid_argument_status() {
        assert_eq!(unsafe { opaque_56_byte_record_initialize(ptr::null_mut(), 1, 2) }, -50);
    }

    #[test]
    fn initializes_record_embedded_subobject_and_values_without_touching_tail() {
        let mut record = AlignedRecord([0xa5; 64]);

        assert_eq!(unsafe {
            opaque_56_byte_record_initialize(record.0.as_mut_ptr(), 0x1122_3344, 0x5566_7788)
        }, 0);
        assert_eq!(word(&record, 0), RECORD_VTABLE);
        assert_eq!(&record.0[4..12], &[0; 8]);
        assert_eq!(word(&record, 12), 0x6172_6179);
        assert_eq!(word(&record, 16), 4);
        assert_eq!(&record.0[20..44], &[0; 24]);
        assert_eq!(record.0[45], 1);
        assert_eq!(word(&record, 48), 0x1122_3344);
        assert_eq!(word(&record, 52), 0x5566_7788);
        assert_eq!(&record.0[56..], &[0xa5; 8]);
    }
}
