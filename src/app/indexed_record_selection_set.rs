//! `indexed_record_selection_set` — `FUN_08203dac` @ **0x08203dac**.
//!
//! True extent: 132 bytes, `0x08203dac..0x08203e30`: 116 code bytes and
//! four literal words. Raw decoding verifies two plain BLs, zero predicated
//! BLs, two indirect BLX calls, and one indirect BX tail call. Whole-image
//! decoding finds two inbound plain BLs and no predicated BLs.
//!
//! Store the selected index at +0x24 and +0x28, resolve its record, pass the
//! unsigned halfword at record +0x0a to the subscription/RTC receiver at +0x44,
//! then dispatch resources 0x8e8c, 0x8e8d, 0x8e8e with category 0x53747220.
//! Reload the virtual slot +0x58 before every dispatch, including the last.
//! No null guards are added. Deliberate deviations: repr(C) pointer fields
//! widen on hosts; target offsets remain exact. Tests inject lookup/sync only
//! to isolate this wrapper from firmware globals; production uses existing
//! Rust ports. LLVM may implement the final virtual tail call as call/return.

use core::ptr;

type Dispatch = unsafe extern "C" fn(*mut IndexedRecordSelection, u32, u32);

#[repr(C)]
pub struct SelectionVtable {
    pub unresolved_00_54: [u32; 22],
    pub dispatch: Dispatch,
}

#[repr(C)]
pub struct IndexedRecordSelection {
    pub vtable: *const SelectionVtable,
    pub unresolved_04_20: [u32; 8],
    pub selected_index: u32,
    pub previous_index: u32,
    pub unresolved_2c_40: [u32; 6],
    pub subscription_receiver: *mut u8,
}

#[cfg(target_pointer_width = "32")]
const _: () = {
    assert!(core::mem::offset_of!(IndexedRecordSelection, selected_index) == 0x24);
    assert!(core::mem::offset_of!(IndexedRecordSelection, previous_index) == 0x28);
    assert!(core::mem::offset_of!(IndexedRecordSelection, subscription_receiver) == 0x44);
    assert!(core::mem::offset_of!(SelectionVtable, dispatch) == 0x58);
};

#[inline(always)]
unsafe fn set_with(
    receiver: *mut IndexedRecordSelection,
    index: u32,
    lookup: impl FnOnce(u32) -> *mut u8,
    sync: impl FnOnce(*mut u8, u32),
) {
    ptr::write(ptr::addr_of_mut!((*receiver).selected_index), index);
    ptr::write(ptr::addr_of_mut!((*receiver).previous_index), index);
    let record = lookup(index);
    let value = ptr::read(record.add(10).cast::<u16>()) as u32;
    sync(ptr::read(ptr::addr_of!((*receiver).subscription_receiver)), value);
    for resource in [0x8e8c, 0x8e8d, 0x8e8e] {
        let vtable = ptr::read(ptr::addr_of!((*receiver).vtable));
        let dispatch = ptr::read(ptr::addr_of!((*vtable).dispatch));
        dispatch(receiver, 0x5374_7220, resource);
    }
}

/// Sets the indexed selection and refreshes its three string resources.
///
/// # Safety
/// `receiver` and its virtual dispatch must be valid. The index must resolve
/// to a non-null, halfword-aligned record readable through +0x0b, and the
/// subscription receiver must satisfy `event_subscription_rtc_sync`'s contract.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn indexed_record_selection_set(receiver: *mut IndexedRecordSelection, index: u32) {
    set_with(receiver, index,
        |index| crate::util::indexed_record_lookup::indexed_record_lookup(index),
        |owner, value| crate::app::event_subscription_rtc_sync::event_subscription_rtc_sync(owner, value));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(C)]
    struct Fixture {
        receiver: IndexedRecordSelection,
        resources: [u32; 3],
        count: usize,
        replacement: *const SelectionVtable,
    }

    unsafe extern "C" fn first(receiver: *mut IndexedRecordSelection, category: u32, resource: u32) {
        assert_eq!(category, 0x5374_7220);
        assert_eq!(resource, 0x8e8c);
        let fixture = receiver.cast::<Fixture>();
        (*fixture).resources[0] = resource;
        (*fixture).count = 1;
        (*receiver).vtable = (*fixture).replacement;
    }

    unsafe extern "C" fn remaining(receiver: *mut IndexedRecordSelection, category: u32, resource: u32) {
        assert_eq!(category, 0x5374_7220);
        let fixture = receiver.cast::<Fixture>();
        let count = (*fixture).count;
        (*fixture).resources[count] = resource;
        (*fixture).count += 1;
    }

    #[test]
    fn unsigned_record_value_and_reentrant_vtable_change() { unsafe {
        let initial = SelectionVtable { unresolved_00_54: [0; 22], dispatch: first };
        let replacement = SelectionVtable { unresolved_00_54: [0; 22], dispatch: remaining };
        for (index, value) in [(0, 0u16), (204, 0x8000), (u32::MAX, u16::MAX)] {
            let mut owner = 0u32;
            let mut record = [0u16; 6]; record[5] = value;
            let mut fixture = Fixture {
                receiver: IndexedRecordSelection {
                    vtable: &initial, unresolved_04_20: [0xa5a5_a5a5; 8],
                    selected_index: 7, previous_index: 9, unresolved_2c_40: [0x5a5a_5a5a; 6],
                    subscription_receiver: ptr::addr_of_mut!(owner).cast(),
                },
                resources: [0; 3], count: 0, replacement: &replacement,
            };
            let receiver = ptr::addr_of_mut!(fixture.receiver);
            set_with(receiver, index, |resolved| {
                assert_eq!(resolved, index);
                assert_eq!((*receiver).selected_index, index);
                assert_eq!((*receiver).previous_index, index);
                record.as_mut_ptr().cast()
            }, |destination, rank| {
                ptr::write(destination.cast::<u32>(), rank);
                // A callee mutation must not be overwritten after synchronization.
                (*receiver).previous_index = 123;
            });
            assert_eq!(owner, value as u32);
            assert_eq!(fixture.receiver.selected_index, index);
            assert_eq!(fixture.receiver.previous_index, 123);
            assert_eq!(fixture.receiver.unresolved_04_20, [0xa5a5_a5a5; 8]);
            assert_eq!(fixture.receiver.unresolved_2c_40, [0x5a5a_5a5a; 6]);
            assert_eq!(fixture.resources, [0x8e8c, 0x8e8d, 0x8e8e]);
            assert_eq!(fixture.count, 3);
        }
    }}
}
