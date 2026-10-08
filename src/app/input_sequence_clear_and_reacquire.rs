//! Input-sequence collection clear — FUN_08129ab4 @ 0x08129ab4.
//!
//! True extent [0x08129ab4, 0x08129b44): 144 bytes; the next entry
//! starts with CMP r0,#20. Whole-image raw A32 decoding verifies two inbound
//! plain BLs (0x08129e50, 0x08129f1c), zero predicated BLs. This body has
//! four plain BLs, zero predicated BLs, and one BLX-register (vtable +0x30).
//!
//! Walk the mode-selected collection, remembering the selected item's action
//! byte when encountered. Finish the entire walk, reload the collection, and
//! clear it through slot 12. If the selection was present, reacquire using the
//! saved byte zero-extended to u32 and store the returned selection. Otherwise
//! leave the selection untouched by this function. Invalidate the cursor last.
//! Deviations: native host vtable/pointer widths; owner slots stay u32 words.
//! Reuses canonical Rust callees. No new firmware seams or null guards.

use crate::cursor::{Collection, Cursor, cursor_init, cursor_advance, cursor_invalidate};
use crate::app::input_sequence_item_acquire::input_sequence_item_acquire;

/// # Safety
/// `state` is aligned and writable through +0xb3; its selected collection has
/// valid item-at and clear vtable slots. Yielded matching items are readable
/// through +0x10. The acquisition helper's retail requirements also apply.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn input_sequence_clear_and_reacquire(state: *mut u8, mode: u32) {
    let collection_slot = state.cast::<u32>().add(if mode == 0 { 43 } else { 42 });
    let selected_slot = state.cast::<u32>().add(44);
    let mut cursor = Cursor { collection: core::ptr::null_mut(), index: 0 };
    cursor_init(&mut cursor, collection_slot.read() as usize as *mut Collection);
    let mut item: *mut u8 = core::ptr::null_mut();
    let mut found = false;
    let mut action_index = 0;
    while cursor_advance(&mut cursor, core::ptr::addr_of_mut!(item).cast()) != 0 {
        if selected_slot.read() as usize == item as usize {
            action_index = item.add(0x10).read() as u32;
            found = true;
        }
    }
    let collection = collection_slot.read() as usize as *mut Collection;
    let clear: unsafe extern "C" fn(*mut Collection) =
        core::mem::transmute((*(*collection).vtable).unresolved[12]);
    clear(collection);
    if found {
        selected_slot.write(input_sequence_item_acquire(state, action_index, mode) as u32);
    }
    cursor_invalidate(&mut cursor);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cursor::CollectionVtable;
    use crate::app::input_sequence_item_acquire::{replace_input_sequence_item_ops, InputSequenceItemOp};
    use crate::testing::{hints, try_map_u32_slab, note_missing_u32_fixture, INPUT_SEQUENCE_ITEM_OPS_TEST_LOCK};

    #[repr(C)]
    struct Fixture {
        vtable: *const CollectionVtable,
        items: [*mut u8; 3],
        count: usize,
        visits: usize,
        clears: usize,
    }

    unsafe extern "C" fn item_at(this: *mut Collection, index: i32, out: *mut u8) -> u32 {
        let fixture = &mut *this.cast::<Fixture>();
        fixture.visits += 1;
        if index as usize >= fixture.count { return 0; }
        out.cast::<*mut u8>().write(fixture.items[index as usize]);
        1
    }

    unsafe extern "C" fn clear(this: *mut Collection) {
        let fixture = &mut *this.cast::<Fixture>();
        assert_eq!(fixture.visits, fixture.count + 1);
        fixture.clears += 1;
        for item in fixture.items.iter().take(fixture.count) { item.add(16).write(0); }
        fixture.count = 0;
    }

    // Real acquisition runs with only the unavailable construction boundary
    // substituted. The lookup observes the cleared collection through its cursor.
    unsafe extern "C" fn find(state: *mut u8, index: u32, mode: u32) -> *mut u8 {
        crate::app::input_sequence_find_item::input_sequence_find_item(state, index as i32, mode)
    }
    unsafe extern "C" fn build(state: *mut u8, index: u32, mode: u32) -> *mut u8 {
        let fixture = &mut *(state.cast::<u32>().add(if mode == 0 { 43 } else { 42 }).read() as usize as *mut Fixture);
        assert_eq!(fixture.count, 0);
        assert_eq!(fixture.clears, 1);
        let replacement = state.add(0x700);
        replacement.add(16).write(index as u8);
        fixture.items[0] = replacement;
        fixture.count = 1;
        replacement
    }
    struct Restore(InputSequenceItemOp, InputSequenceItemOp);
    impl Drop for Restore {
        fn drop(&mut self) { unsafe { replace_input_sequence_item_ops(self.0, self.1); } }
    }

    #[test]
    fn clear_preserves_absent_selection_and_rebuilds_present_selection_with_saved_byte() {
        let _lock = INPUT_SEQUENCE_ITEM_OPS_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let Some(state) = try_map_u32_slab(hints::INPUT_SEQUENCE_CLEAR_REACQUIRE, 0x1000) else {
            assert!(note_missing_u32_fixture("input_sequence_clear_and_reacquire"));
            return;
        };
        let previous = unsafe { replace_input_sequence_item_ops(find, build) };
        let _restore = Restore(previous.0, previous.1);
        let mut vtable = CollectionVtable { unresolved: [0; 15], item_at };
        vtable.unresolved[12] = clear as *const () as usize;
        unsafe {
            for mode in [0, 1, 2, u32::MAX] {
                for count in 0..=3 {
                    for selected in 0..=3 {
                        for byte in [0, 1, 127, 128, 255] {
                            let primary = state.add(0x200).cast::<Fixture>();
                            let alternate = state.add(0x300).cast::<Fixture>();
                            let items = [state.add(0x400), state.add(0x500), state.add(0x600)];
                            for item in items { item.add(16).write(byte); }
                            for collection in [primary, alternate] {
                                collection.write(Fixture { vtable: &vtable, items, count, visits: 0, clears: 0 });
                            }
                            state.cast::<u32>().add(42).write(primary as u32);
                            state.cast::<u32>().add(43).write(alternate as u32);
                            let old = if selected == 3 { core::ptr::null_mut() } else { items[selected] };
                            state.cast::<u32>().add(44).write(old as u32);
                            input_sequence_clear_and_reacquire(state, mode);
                            let chosen = if mode == 0 { alternate } else { primary };
                            let other = if mode == 0 { primary } else { alternate };
                            assert_eq!((*chosen).clears, 1);
                            assert_eq!((*other).clears, 0);
                            assert_eq!((*other).visits, 0);
                            let present = selected < count;
                            assert_eq!((*chosen).count, usize::from(present));
                            assert_eq!(state.cast::<u32>().add(44).read(), if present { state.add(0x700) as u32 } else { old as u32 });
                            if present { assert_eq!(state.add(0x710).read(), byte); }
                        }
                    }
                }
            }
        }
    }
}
