//! `record_payload_destroy` — original `FUN_08104b88` @ 0x08104b88.
//!
//! True extent: 40 bytes, [0x08104b88,0x08104bb0), followed by a new
//! push/zero-return function. Raw A32 has one outbound BLNE to free_wrapper
//! @ 0x080e7970; two incoming plain BLs @ 0x08063ab8/0x08063e64 and no
//! incoming predicated BLs. Free the non-NULL +8 payload with tag 0 unless
//! byte +12 is 0x3a. Leave all fields unchanged and return the record pointer;
//! callers subsequently delete that record via operator_delete.
//!
//! Deviations: reuse the existing heap port and SlotRecord prefix. repr(C)
//! native pointers widen host fixtures but retain +8/+12 on ARM. No second
//! argument: incoming r1 is unused, overwritten only when payload is non-NULL.

use crate::heap::fifteen_record_slots_clear::SlotRecord;
use crate::heap::veneers::free_wrapper;

/// `record` must point to a readable aligned SlotRecord prefix. Any owned
/// non-NULL payload must satisfy free_wrapper's tag-0 allocation contract.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn record_payload_destroy(record: *mut SlotRecord) -> *mut SlotRecord {
    let payload = core::ptr::addr_of!((*record).payload).read_volatile();
    if !payload.is_null() && core::ptr::addr_of!((*record).kind).read_volatile() != 0x3a {
        free_wrapper(payload, 0);
    }
    record
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::heap::types::HeapDescriptorDescriptor;
    use crate::heap::veneers::{tests::mock_heap, HEAP_OPS};
    use std::vec::Vec;

    static mut RELEASES: Vec<(usize, usize)> = Vec::new();
    unsafe extern "C" fn record_free(_: *mut HeapDescriptorDescriptor, ptr: *mut u8, tag: usize) {
        (*core::ptr::addr_of_mut!(RELEASES)).push((ptr as usize, tag));
    }

    #[test]
    fn all_kind_bytes_and_null_payload_preserve_record_and_return_pointer() {
        let _guard = mock_heap();
        unsafe {
            let old = HEAP_OPS;
            HEAP_OPS.free = record_free;
            for kind in 0..=255u8 {
                for payload in [core::ptr::null_mut(), 0x1234usize as *mut u8] {
                    let mut record = SlotRecord { reserved: [0xabcdef01, 0x98765432], payload, kind };
                    let ptr = &mut record as *mut SlotRecord;
                    (*core::ptr::addr_of_mut!(RELEASES)).clear();
                    assert_eq!(record_payload_destroy(ptr), ptr);
                    let expected = if !payload.is_null() && kind != 0x3a {
                        std::vec![(payload as usize, 0)]
                    } else {
                        Vec::new()
                    };
                    assert_eq!(*core::ptr::addr_of!(RELEASES), expected);
                    assert_eq!(record.reserved, [0xabcdef01, 0x98765432]);
                    assert_eq!(record.payload, payload);
                    assert_eq!(record.kind, kind);
                }
            }
            HEAP_OPS = old;
        }
    }
}
