//! Clears a saved BtCursor overflow-key allocation.

use crate::heap::tracked::tracked_free;

/// clear_saved_overflow — original `FUN_082d6d08` @ 0x082d6d08 (28 bytes).
///
/// Verified from `osos.dec`: one plain `bl` (none predicated) calls
/// `tracked_free` with the target-width pointer word at `cursor + 0x58`, then
/// stores zero back to that word. The next separately linked function starts
/// at 0x082d6d24. There are three inbound plain-BL call sites
/// (0x082d6ca0, 0x083685a8, and 0x08370bac).
///
/// This releases the saved overflow-key cache owned by a SQLite BtCursor and
/// clears its field even when it was already NULL. Deliberate deviation: the
/// target's 32-bit pointer field is represented as a `u32` word so the
/// `+0x58` offset remains correct on 64-bit host fixtures.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn clear_saved_overflow(cursor: *mut u8) {
    let saved_overflow = cursor.add(0x58).cast::<u32>();
    tracked_free(saved_overflow.read() as usize as *mut u8);
    saved_overflow.write(0);
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;

    const SLAB_SIZE: usize = 0x1000;

    unsafe fn fixture() -> Option<(*mut u8, *mut u8, *mut u8)> {
        let slab = crate::testing::try_map_u32_slab(
            crate::testing::hints::SQLITE_CLEAR_SAVED_OVERFLOW,
            SLAB_SIZE,
        )?;
        core::ptr::write_bytes(slab, 0, SLAB_SIZE);
        let raw = ((slab.add(0x200) as usize + 31) & !31) as *mut u8;
        let base = raw.add(8);
        let payload = ((base as usize + 36) & !31) as *mut u8;
        raw.cast::<i32>().write(23);
        raw.add(4).cast::<i32>().write(0);
        payload.sub(4).cast::<u32>().write((payload as usize - base as usize) as u32);
        Some((slab, raw, payload))
    }

    #[test]
    fn frees_saved_overflow_and_clears_target_word() {
        let _heap_guard = crate::heap::veneers::tests::mock_heap();
        let Some((cursor, raw, payload)) = (unsafe { fixture() }) else {
            crate::testing::note_missing_u32_fixture("sqlite/clear_saved_overflow");
            return;
        };
        unsafe {
            cursor.add(0x58).cast::<u32>().write(payload as u32);
            clear_saved_overflow(cursor);
            assert_eq!(cursor.add(0x58).cast::<u32>().read(), 0);
        }
        let (calls, freed, tag) = crate::heap::veneers::tests::free_log();
        assert_eq!((calls, freed, tag), (1, raw, 57));
    }

    #[test]
    fn null_saved_overflow_is_cleared_without_freeing() {
        let _heap_guard = crate::heap::veneers::tests::mock_heap();
        let Some((cursor, _, _)) = (unsafe { fixture() }) else {
            crate::testing::note_missing_u32_fixture("sqlite/clear_saved_overflow");
            return;
        };
        unsafe {
            clear_saved_overflow(cursor);
            assert_eq!(cursor.add(0x58).cast::<u32>().read(), 0);
        }
        assert_eq!(crate::heap::veneers::tests::free_log().0, 0);
    }
}
