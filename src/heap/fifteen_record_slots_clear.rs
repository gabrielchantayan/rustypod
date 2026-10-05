//! `fifteen_record_slots_clear` — original `FUN_081cd964` @ 0x081cd964.
//!
//! True extent: 84 bytes, [0x081cd964,0x081cd9b8); the next function is
//! the independently entered indexed load at 0x081cd9b8. Raw A32 has one
//! plain BL (operator_delete), one BLNE (free_wrapper), and a zero-fill tail
//! branch. Two inbound plain BLs at 0x081cda80/0x081cda98; no predicated BLs.
//! Scan fifteen record pointers in order. For each non-NULL record, free its
//! non-NULL +8 payload with tag 0 unless byte +12 is 0x3a, then tag-2 delete
//! the record. Zero the entire pointer table only after all releases.
//!
//! Deviations: use existing Rust heap and memzero ports; the 0x08037db8
//! veneer targets 0x2200027c, the IRAM mirror of memzero_aligned. Native
//! repr(C) pointer fields widen on hosts, so zero-fill uses the table's native
//! size (60 bytes on ARM). A volatile function-pointer call preserves the
//! zero-fill port instead of LLVM substituting a compiler builtin.
//! No invented class identity or extra argument.

use crate::heap::veneers::{free_wrapper, operator_delete};
use crate::libc::memzero::memzero_aligned;

/// Accessed record prefix; payload is +8 and kind is +12 on ARM.
#[repr(C)]
pub struct SlotRecord {
    pub reserved: [u32; 2],
    pub payload: *mut u8,
    pub kind: u8,
}

/// Clear a writable aligned fifteen-slot table. Each non-NULL record must
/// have this prefix and satisfy operator_delete's allocation contract;
/// owned non-NULL payloads must satisfy free_wrapper's tag-0 contract.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn fifteen_record_slots_clear(slots: *mut *mut SlotRecord) {
    for index in 0..15 {
        let record = slots.add(index).read_volatile();
        if !record.is_null() {
            let payload = core::ptr::addr_of!((*record).payload).read_volatile();
            if !payload.is_null() && core::ptr::addr_of!((*record).kind).read_volatile() != 0x3a {
                free_wrapper(payload, 0);
            }
            operator_delete(record.cast());
        }
    }
    let zero = core::ptr::read_volatile(
        &(memzero_aligned as unsafe extern "C" fn(*mut u8, usize) -> *mut u8),
    );
    zero(slots.cast(), core::mem::size_of::<[*mut SlotRecord; 15]>());
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::heap::veneers::{tests::mock_heap, HEAP_OPS};
    use crate::heap::types::HeapDescriptorDescriptor;
    use std::vec::Vec;

    static mut RELEASES: Vec<(usize, usize)> = Vec::new();
    unsafe extern "C" fn record_free(_: *mut HeapDescriptorDescriptor, ptr: *mut u8, tag: usize) {
        (*core::ptr::addr_of_mut!(RELEASES)).push((ptr as usize, tag));
    }

    #[test]
    fn ownership_byte_null_payloads_and_last_slot() {
        let _guard = mock_heap();
        unsafe {
            let old = HEAP_OPS;
            HEAP_OPS.free = record_free;
            for kind in 0..=255u8 {
                let mut records = [
                    SlotRecord { reserved: [0xabcdef01; 2], payload: 0x1234usize as *mut u8, kind },
                    SlotRecord { reserved: [0xabcdef01; 2], payload: core::ptr::null_mut(), kind },
                ];
                let mut slots = [core::ptr::null_mut(); 17];
                slots[0] = 0x5678usize as *mut SlotRecord;
                slots[16] = 0x9abcusize as *mut SlotRecord;
                slots[1] = &mut records[0];
                slots[15] = &mut records[1];
                (*core::ptr::addr_of_mut!(RELEASES)).clear();
                fifteen_record_slots_clear(slots.as_mut_ptr().add(1));
                let mut expected = Vec::new();
                if kind != 0x3a { expected.push((0x1234, 0)); }
                expected.push((&mut records[0] as *mut SlotRecord as usize, 2));
                expected.push((&mut records[1] as *mut SlotRecord as usize, 2));
                assert_eq!(*core::ptr::addr_of!(RELEASES), expected);
                assert_eq!(slots[0] as usize, 0x5678);
                assert_eq!(slots[16] as usize, 0x9abc);
                assert!(slots[1..16].iter().all(|slot| slot.is_null()));
                assert_eq!(records[0].reserved, [0xabcdef01; 2]);
                assert_eq!(records[0].payload as usize, 0x1234);
                assert_eq!(records[0].kind, kind);
                // A second clear must neither release again nor touch guards.
                (*core::ptr::addr_of_mut!(RELEASES)).clear();
                fifteen_record_slots_clear(slots.as_mut_ptr().add(1));
                assert!((*core::ptr::addr_of!(RELEASES)).is_empty());
            }
            HEAP_OPS = old;
        }
    }
}
