//! Clears saved overflow-key allocations from every cursor in a list.

use crate::sqlite::clear_saved_overflow::clear_saved_overflow;

/// clear_cursor_saved_overflows — original `FUN_082d6c90` @ 0x082d6c90 (36 bytes).
///
/// Raw `osos.dec` establishes the complete extent 0x082d6c90..0x082d6cb4:
/// it loads the target-width list head at `cursors + 0x08`, calls
/// [`clear_saved_overflow`] once per node, then follows each node's `+0x08`
/// next word until NULL. There is one plain `bl` and no predicated calls in
/// the body; three inbound calls are all plain `bl` instructions
/// (0x082b58b8, 0x082bd9a0, and 0x0838a78c). The following function begins
/// with `push {r4, r5, r6, lr}` at 0x082d6cb4.
///
/// Deliberate deviation: cursor-list links are read as `u32` target pointers,
/// preserving their target offsets on 64-bit host fixtures.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn clear_cursor_saved_overflows(cursors: *mut u8) {
    let mut cursor = cursors.add(8).cast::<u32>().read() as usize as *mut u8;
    while !cursor.is_null() {
        clear_saved_overflow(cursor);
        cursor = cursor.add(8).cast::<u32>().read() as usize as *mut u8;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;

    #[test]
    fn clears_each_linked_cursor_saved_overflow() {
        let _heap_guard = crate::heap::veneers::tests::mock_heap();
        let Some(slab) = crate::testing::try_map_u32_slab(
            crate::testing::hints::SQLITE_CLEAR_CURSOR_SAVED_OVERFLOWS,
            0x1000,
        ) else {
            crate::testing::note_missing_u32_fixture("sqlite/clear_cursor_saved_overflows");
            return;
        };
        unsafe {
            core::ptr::write_bytes(slab, 0, 0x1000);
            let cursors = slab.add(0x100);
            let first = slab.add(0x200);
            let second = slab.add(0x300);
            let raw = slab.add(0x600);
            let payload = raw.add(8);
            raw.cast::<i32>().write(23);
            raw.add(4).cast::<i32>().write(0);
            payload.sub(4).cast::<u32>().write(0);
            cursors.add(8).cast::<u32>().write(first as u32);
            first.add(8).cast::<u32>().write(second as u32);
            second.add(8).cast::<u32>().write(0);
            first.add(0x58).cast::<u32>().write(payload as u32);
            second.add(0x58).cast::<u32>().write(0);

            clear_cursor_saved_overflows(cursors);

            assert_eq!(first.add(0x58).cast::<u32>().read(), 0);
            assert_eq!(second.add(0x58).cast::<u32>().read(), 0);
            assert_eq!(cursors.add(8).cast::<u32>().read(), first as u32);
        }
        let (calls, freed, tag) = crate::heap::veneers::tests::free_log();
        assert_eq!((calls, freed, tag), (1, unsafe { slab.add(0x600) }, 57));
    }

    #[test]
    fn empty_cursor_list_does_not_free() {
        let _heap_guard = crate::heap::veneers::tests::mock_heap();
        let Some(slab) = crate::testing::try_map_u32_slab(
            crate::testing::hints::SQLITE_CLEAR_CURSOR_SAVED_OVERFLOWS_EMPTY,
            0x1000,
        ) else {
            crate::testing::note_missing_u32_fixture("sqlite/clear_cursor_saved_overflows");
            return;
        };
        unsafe {
            core::ptr::write_bytes(slab, 0, 0x1000);
            clear_cursor_saved_overflows(slab.add(0x100));
        }
        assert_eq!(crate::heap::veneers::tests::free_log().0, 0);
    }
}
