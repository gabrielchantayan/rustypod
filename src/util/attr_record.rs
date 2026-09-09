//! Named attribute-record lookup.
//!
//! `attr_record_lookup` — original: `FUN_080bfb8c` @ `0x080bfb8c` (72 bytes;
//! 16 direct call sites, all unconditional `bl`, binary-scanned from
//! `osos.dec`).
//!
//! # Algorithm
//!
//! The function returns NULL unless the table pointer, its +0x48 nonzero
//! guard, the attribute-name pointer, and the name's first byte are all
//! nonzero. It then calls the already-ported [`super::global_state::global_state_get`]
//! with the name and the table's opaque +0x80 state table. A non-NULL returned
//! state record supplies an index at +0x4; the result is the table's +0x50
//! attribute-record base plus that index times 16. There is deliberately no
//! bounds check on the index, matching the ARM `add r0,r1,r0,lsl #4`.
//!
//! The +0x48 field's semantic identity is not established; it is named only
//! for its verified role as a nonzero guard. Deliberate deviations: none.

/// The observed portion of the named-attribute table consumed by
/// [`attr_record_lookup`]. All fields are target words so this layout remains
/// valid on 64-bit host tests.
#[repr(C)]
pub struct NamedAttributeTable {
    _words_00_to_44: [u32; 18],
    /// Checked only for nonzero before a name lookup.
    pub nonzero_guard: u32,
    _word_4c: u32,
    /// Base address of 16-byte attribute records.
    pub attribute_records: u32,
    _words_54_to_7c: [u32; 11],
    /// Opaque table forwarded to `global_state_get`.
    pub global_state_table: u32,
}

/// attr_record_lookup — original: `FUN_080bfb8c` @ `0x080bfb8c` (72 bytes;
/// 16 direct `bl` call sites, all unconditional).
///
/// Finds the 16-byte attribute record named by `attribute_name`, or returns
/// NULL when the table is unavailable, the name is empty, or its state record
/// is absent. The returned index arithmetic intentionally wraps as ARM `add`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn attr_record_lookup(
    attribute_table: *const NamedAttributeTable,
    attribute_name: *const u8,
) -> *mut u8 {
    if attribute_table.is_null() {
        return core::ptr::null_mut();
    }

    let attribute_table = unsafe { &*attribute_table };
    // The stock code loads this guard before inspecting attribute_name.
    let nonzero_guard = unsafe {
        core::ptr::addr_of!(attribute_table.nonzero_guard).read_volatile()
    };
    if nonzero_guard == 0 {
        return core::ptr::null_mut();
    }
    if attribute_name.is_null() {
        return core::ptr::null_mut();
    }
    if unsafe { *attribute_name } == 0 {
        return core::ptr::null_mut();
    }

    let state_record = unsafe {
        super::global_state::global_state_get(
            attribute_name,
            attribute_table.global_state_table as usize as *const u8,
        )
    };
    if state_record.is_null() {
        return core::ptr::null_mut();
    }

    let attribute_record_index = unsafe { state_record.cast::<u32>().add(1).read() };
    let attribute_record_address = attribute_table.attribute_records
        .wrapping_add(attribute_record_index.wrapping_shl(4));
    attribute_record_address as usize as *mut u8
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab,
                         GLOBAL_STATE_SLOT_FIND_TEST_LOCK};
    use crate::util::global_state::{GlobalStateSlotFind, GLOBAL_STATE_SLOT_FIND};
    extern crate std;
    use std::sync::MutexGuard;

    #[repr(C)]
    struct GlobalStateRecord {
        _word_00: u32,
        attribute_record_index: u32,
    }

    static mut RECORDED_NAME: *const u8 = core::ptr::null();
    static mut RECORDED_TABLE: *const u8 = core::ptr::null();
    static mut RETURNED_SLOT: *const *mut u8 = core::ptr::null();
    static mut SLOT_FIND_CALLS: u32 = 0;

    unsafe extern "C" fn recording_slot_find(
        global_name: *const u8,
        global_state_table: *const u8,
    ) -> *const *mut u8 {
        unsafe {
            RECORDED_NAME = global_name;
            RECORDED_TABLE = global_state_table;
            SLOT_FIND_CALLS += 1;
            RETURNED_SLOT
        }
    }

    struct SlotFindReset;

    impl Drop for SlotFindReset {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(GLOBAL_STATE_SLOT_FIND)
                    .write(super::super::global_state::DEFAULT_GLOBAL_STATE_SLOT_FIND);
            }
        }
    }

    fn install_recording_slot_find() -> MutexGuard<'static, ()> {
        let guard = GLOBAL_STATE_SLOT_FIND_TEST_LOCK.lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        unsafe {
            RECORDED_NAME = core::ptr::null();
            RECORDED_TABLE = core::ptr::null();
            RETURNED_SLOT = core::ptr::null();
            SLOT_FIND_CALLS = 0;
            core::ptr::addr_of_mut!(GLOBAL_STATE_SLOT_FIND)
                .write(recording_slot_find as GlobalStateSlotFind);
        }
        guard
    }

    fn table_with(
        nonzero_guard: u32,
        attribute_records: u32,
        global_state_table: u32,
    ) -> NamedAttributeTable {
        NamedAttributeTable {
            _words_00_to_44: [0; 18],
            nonzero_guard,
            _word_4c: 0,
            attribute_records,
            _words_54_to_7c: [0; 11],
            global_state_table,
        }
    }

    #[test]
    fn returns_indexed_record_and_forwards_name_and_table() {
        let _guard = install_recording_slot_find();
        let _reset = SlotFindReset;
        let Some(slab) = try_map_u32_slab(hints::NAMED_ATTRIBUTE_LOOKUP, 0x1000) else {
            note_missing_u32_fixture("util::attr_record");
            return;
        };

        unsafe {
            core::ptr::write_bytes(slab, 0, 0x1000);
            let attribute_table = slab.cast::<NamedAttributeTable>();
            let attribute_records = slab.add(0x400);
            let global_state_table = slab.add(0x800);
            attribute_table.write(table_with(
                1,
                attribute_records as usize as u32,
                global_state_table as usize as u32,
            ));

            let mut state_record = GlobalStateRecord {
                _word_00: 0,
                attribute_record_index: 3,
            };
            let mut slot = core::ptr::addr_of_mut!(state_record).cast::<u8>();
            RETURNED_SLOT = &mut slot;

            let attribute_name = b"WEIGHT\0";
            assert_eq!(
                attr_record_lookup(attribute_table, attribute_name.as_ptr()),
                attribute_records.add(3 * 16),
            );
            assert_eq!(RECORDED_NAME, attribute_name.as_ptr());
            assert_eq!(RECORDED_TABLE, global_state_table);
            assert_eq!(SLOT_FIND_CALLS, 1);
        }
    }

    #[test]
    fn rejects_null_unready_and_empty_inputs_without_lookup() {
        let _guard = install_recording_slot_find();
        let _reset = SlotFindReset;
        let attribute_name = b"SLANT\0";
        let empty_name = b"\0";
        let unready_table = table_with(0, 0, 0);
        let ready_table = table_with(1, 0, 0);

        unsafe {
            assert!(attr_record_lookup(core::ptr::null(), attribute_name.as_ptr()).is_null());
            assert!(attr_record_lookup(&unready_table, attribute_name.as_ptr()).is_null());
            assert!(attr_record_lookup(&ready_table, core::ptr::null()).is_null());
            assert!(attr_record_lookup(&ready_table, empty_name.as_ptr()).is_null());
            assert_eq!(SLOT_FIND_CALLS, 0);
        }
    }

    #[test]
    fn returns_null_when_global_state_lookup_has_no_record() {
        let _guard = install_recording_slot_find();
        let _reset = SlotFindReset;
        let table = table_with(1, 0x1000, 0x2000);
        let mut slot = core::ptr::null_mut();

        unsafe {
            RETURNED_SLOT = &mut slot;
            assert!(attr_record_lookup(&table, b"ADD_STYLE\0".as_ptr()).is_null());
            assert_eq!(SLOT_FIND_CALLS, 1);
        }
    }

    #[test]
    fn preserves_arm_wrapping_record_address_arithmetic() {
        let _guard = install_recording_slot_find();
        let _reset = SlotFindReset;
        let table = table_with(1, 0x20, 0x2000);
        let mut state_record = GlobalStateRecord {
            _word_00: 0,
            attribute_record_index: u32::MAX,
        };
        let mut slot = core::ptr::addr_of_mut!(state_record).cast::<u8>();

        unsafe {
            RETURNED_SLOT = &mut slot;
            assert_eq!(
                attr_record_lookup(&table, b"SETWIDTH\0".as_ptr()),
                0x10usize as *mut u8,
            );
        }
    }
}
