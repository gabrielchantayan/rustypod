//! `mapped_subobject_for_slot` — original: `FUN_082941a8` @ `0x082941a8`
//! (56 instruction bytes, plus the 4-byte `0x089d04bc` literal pool word at
//! `0x082941e0`; the next independently linked function starts at
//! `0x082941e4`).
//!
//! Raw ARM first rejects a slot greater than four.  A nonzero target-width
//! table index at `context + 0xc4` selects a byte map through the literal
//! table base: `*(0x089d04bc + index * 4 - 4)`.  The selected map byte either
//! equals the sentinel four (return null), or chooses a target-width pointer
//! at `context + 0x38 + map_byte * 4`.
//!
//! Decoding every ARM B/BL immediate in `osos.dec` finds seven direct inbound
//! calls, all unconditional plain `bl` (0x0829301c, 0x08293110, 0x08293c30,
//! 0x08293e84, 0x08293f10, 0x08294320, and 0x08294570); no predicated calls.
//! Deliberate deviation: the fixed table base is modeled by a host-private
//! pointer for tests, while target builds use the literal's exact address.

use core::ptr;

const SLOT_LIMIT: u32 = 4;
const CONTEXT_TABLE_INDEX_OFFSET: usize = 0xc4;
const CONTEXT_SUBOBJECT_OFFSET: usize = 0x38;
const SLOT_MAP_SENTINEL: u8 = 4;

/// The raw table-base literal at `0x082941e0`.
#[cfg(target_os = "none")]
const SLOT_MAP_TABLE_BASE: *const *const u8 = 0x089d_04bc as *const *const u8;

/// Host replacement for [`SLOT_MAP_TABLE_BASE`]. Tests install an ordinary
/// pointer table, retaining the target's one-based table-index convention.
#[cfg(not(target_os = "none"))]
static mut SLOT_MAP_TABLE_BASE: *const *const u8 = ptr::null();

#[inline(always)]
unsafe fn slot_map(table_index: u32) -> *const u8 {
    #[cfg(target_os = "none")]
    let base = SLOT_MAP_TABLE_BASE;
    #[cfg(not(target_os = "none"))]
    let base = unsafe { ptr::read_volatile(ptr::addr_of!(SLOT_MAP_TABLE_BASE)) };

    unsafe { ptr::read_volatile(base.add(table_index as usize - 1)) }
}

/// Resolves one of five logical slots to a context subobject.
///
/// The context must be aligned and readable at +0xc4 and at the mapped
/// target-width pointer slot. As in retailOS, neither the context nor the
/// selected map pointer is NULL-guarded after the slot-range check.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.mapped_subobject_for_slot")]
#[inline(never)]
pub unsafe extern "C" fn mapped_subobject_for_slot(context: *const u8, slot: u32) -> *mut u8 {
    if slot > SLOT_LIMIT {
        return ptr::null_mut();
    }

    let table_index = unsafe {
        ptr::read_volatile(context.add(CONTEXT_TABLE_INDEX_OFFSET).cast::<u32>())
    };
    if table_index == 0 {
        return ptr::null_mut();
    }

    let map = unsafe { slot_map(table_index) };
    let mapped_slot = unsafe { ptr::read_volatile(map.add(slot as usize)) };
    if mapped_slot == SLOT_MAP_SENTINEL {
        return ptr::null_mut();
    }

    unsafe {
        ptr::read_volatile(
            context
                .add(CONTEXT_SUBOBJECT_OFFSET + mapped_slot as usize * size_of::<u32>())
                .cast::<u32>(),
        ) as usize as *mut u8
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, try_map_u32_slab};
    use parking_lot::Mutex;
    static SLOT_MAP_TEST_LOCK: Mutex<()> = Mutex::new(());

    unsafe fn write_word(context: *mut u8, offset: usize, value: u32) {
        unsafe { context.add(offset).cast::<u32>().write(value) };
    }

    #[test]
    fn resolves_mapped_slots_and_preserves_the_sentinel_and_table_index_guards() {
        let _guard = SLOT_MAP_TEST_LOCK.lock();
        let Some(context) = try_map_u32_slab(hints::MAPPED_SUBOBJECT_FOR_SLOT, 0x1000) else {
            return;
        };
        let first_map = [0u8, 1, 3, SLOT_MAP_SENTINEL, 5];
        let second_map = [5u8, SLOT_MAP_SENTINEL, 0, 3, 1];
        let tables = [first_map.as_ptr(), second_map.as_ptr()];
        let saved = unsafe { ptr::read_volatile(ptr::addr_of!(SLOT_MAP_TABLE_BASE)) };
        unsafe { ptr::write_volatile(ptr::addr_of_mut!(SLOT_MAP_TABLE_BASE), tables.as_ptr()) };

        unsafe {
            write_word(context, CONTEXT_TABLE_INDEX_OFFSET, 1);
            for (mapped_slot, value) in [(0, 0x5700_0800), (1, 0x5700_0810), (3, 0x5700_0830), (4, 0x5700_0840), (5, 0x5700_0850)] {
                write_word(context, CONTEXT_SUBOBJECT_OFFSET + mapped_slot * 4, value);
            }

            assert_eq!(mapped_subobject_for_slot(context, 0), 0x5700_0800 as *mut u8);
            assert_eq!(mapped_subobject_for_slot(context, 1), 0x5700_0810 as *mut u8);
            assert_eq!(mapped_subobject_for_slot(context, 2), 0x5700_0830 as *mut u8);
            assert_eq!(mapped_subobject_for_slot(context, 3), ptr::null_mut());
            assert_eq!(mapped_subobject_for_slot(context, 4), 0x5700_0850 as *mut u8);

            write_word(context, CONTEXT_TABLE_INDEX_OFFSET, 2);
            assert_eq!(mapped_subobject_for_slot(context, 0), 0x5700_0850 as *mut u8);
            assert_eq!(mapped_subobject_for_slot(context, 1), ptr::null_mut());

            write_word(context, CONTEXT_TABLE_INDEX_OFFSET, 0);
            assert_eq!(mapped_subobject_for_slot(context, 0), ptr::null_mut());

            ptr::write_volatile(ptr::addr_of_mut!(SLOT_MAP_TABLE_BASE), saved);
        }
    }

    #[test]
    fn rejects_out_of_range_slots_before_dereferencing_context() {
        assert_eq!(
            unsafe { mapped_subobject_for_slot(1usize as *const u8, SLOT_LIMIT + 1) },
            ptr::null_mut(),
        );
    }
}
