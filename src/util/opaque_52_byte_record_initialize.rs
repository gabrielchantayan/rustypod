//! Opaque 52-byte record initialization — `FUN_0804770c` @ 0x0804770c.
//!
//! Raw `osos.dec` establishes a 60-byte instruction body from 0x0804770c
//! through the `pop {r4,pc}` at 0x08047748; the vtable literal at 0x0804774c
//! is data, and 0x08047750 starts the next independently entered function.
//! The body has two plain outgoing `bl` instructions (`bzero` and the
//! unported initializer at 0x080470bc) and no predicated `bl` instructions.
//! Whole-image disassembly finds three plain inbound `bl` calls (0x08047c50,
//! 0x0805895c, and 0x0805e47c), with no predicated inbound calls.
//!
//! Algorithm: reject a NULL record with -50. Otherwise clear all 52 bytes,
//! initialize the trailing 36-byte subobject at +16 with `(8, 0, 0)`, and on
//! success install the record's opaque vtable word.
//!
//! Deliberate deviation: 0x080470bc has no recovered semantic identity and
//! remains a direct retailOS call on target builds. Host builds reproduce only
//! its observed output layout so the outer initializer's contract is testable.

use crate::bzero::bzero;
use core::ptr;

const RECORD_BYTES: i32 = 0x34;
const TRAILING_SUBOBJECT_OFFSET: usize = 0x10;
const RECORD_VTABLE: u32 = 0x4d53_6e64;
#[cfg(target_os = "none")]
const RETAIL_TRAILING_SUBOBJECT_INITIALIZE: usize = 0x0804_70bc;

#[cfg(target_os = "none")]
unsafe fn initialize_trailing_subobject(subobject: *mut u8) -> i32 {
    let initialize: unsafe extern "C" fn(u32, u32, u8, *mut u8) -> i32 =
        core::mem::transmute(RETAIL_TRAILING_SUBOBJECT_INITIALIZE);
    initialize(8, 0, 0, subobject)
}

#[cfg(not(target_os = "none"))]
unsafe fn initialize_trailing_subobject(subobject: *mut u8) -> i32 {
    const SUBOBJECT_BYTES: i32 = 0x24;
    const SUBOBJECT_VTABLE: u32 = 0x6172_6179;

    bzero(subobject, SUBOBJECT_BYTES);
    ptr::write(subobject.cast::<u32>(), SUBOBJECT_VTABLE);
    ptr::write(subobject.add(4).cast::<u32>(), 8);
    ptr::write(subobject.add(0x20), 0);
    ptr::write(subobject.add(0x21), 1);
    0
}

/// Initializes a caller-provided opaque 52-byte record.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn opaque_52_byte_record_initialize(record: *mut u8) -> i32 {
    if record.is_null() {
        return -50;
    }

    bzero(record, RECORD_BYTES);
    let status = initialize_trailing_subobject(record.add(TRAILING_SUBOBJECT_OFFSET));
    if status == 0 {
        ptr::write(record.cast::<u32>(), RECORD_VTABLE);
    }
    status
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(C, align(4))]
    struct AlignedRecord([u8; 60]);

    fn word(record: &AlignedRecord, offset: usize) -> u32 {
        u32::from_le_bytes(record.0[offset..offset + 4].try_into().unwrap())
    }

    #[test]
    fn null_record_returns_stock_invalid_argument_status() {
        assert_eq!(unsafe { opaque_52_byte_record_initialize(ptr::null_mut()) }, -50);
    }

    #[test]
    fn initializes_record_and_trailing_subobject_without_touching_tail() {
        let mut record = AlignedRecord([0xa5; 60]);

        assert_eq!(unsafe { opaque_52_byte_record_initialize(record.0.as_mut_ptr()) }, 0);
        assert_eq!(word(&record, 0), RECORD_VTABLE);
        assert_eq!(&record.0[4..16], &[0; 12]);
        assert_eq!(word(&record, 16), 0x6172_6179);
        assert_eq!(word(&record, 20), 8);
        assert_eq!(&record.0[24..48], &[0; 24]);
        assert_eq!(record.0[49], 1);
        assert_eq!(&record.0[52..], &[0xa5; 8]);
    }
}
