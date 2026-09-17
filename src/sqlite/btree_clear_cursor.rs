//! Clear a SQLite B-tree cursor's saved page.
//!
//! `btree_clear_cursor` — retailOS `FUN_082c3528` at load address
//! `0x082c3528` (32 bytes, `0x082c3528..0x082c3548`). Raw words establish
//! the next separately linked function begins with `push {r4-r9,lr}` at
//! `0x082c3548`. Decoding every ARM `B`/`BL` word in `osos.dec` finds four
//! inbound plain `bl` calls (0x082d9b30, 0x08370b6c, 0x08371678, and
//! 0x08372db0) and no predicated `bl` calls. Its one outbound plain `bl` is
//! `tracked_free` @ 0x083906f4.
//!
//! SQLite's `sqlite3BtreeClearCursor`: free the cursor's saved overflow-page
//! list, then clear its target-width pointer word and set `eState` invalid.
//! Deliberate deviation: none; `tracked_free` is the direct port of the raw
//! allocator callee.

use crate::heap::tracked::tracked_free;

const CURSOR_E_STATE: usize = 0x43;
const CURSOR_OVERFLOW_PAGE_LIST: usize = 0x44;

/// `sqlite3BtreeClearCursor` — retailOS `FUN_082c3528` @ `0x082c3528` (32
/// bytes; four inbound plain-`bl` calls, no predicated calls).
///
/// `cursor` must reference the target-layout `BtCursor`; its +0x44 word is a
/// tracked allocation or NULL. The allocation is released before the word and
/// adjacent `eState` byte are cleared.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn btree_clear_cursor(cursor: *mut u8) {
    tracked_free(cursor.add(CURSOR_OVERFLOW_PAGE_LIST).cast::<u32>().read() as usize as *mut u8);
    cursor.add(CURSOR_OVERFLOW_PAGE_LIST).cast::<u32>().write_volatile(0);
    cursor.add(CURSOR_E_STATE).write_volatile(0);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clears_state_and_null_overflow_list() {
        let mut cursor = [0xffu8; 0x48];
        unsafe {
            cursor.as_mut_ptr().add(CURSOR_OVERFLOW_PAGE_LIST).cast::<u32>().write(0);
            btree_clear_cursor(cursor.as_mut_ptr());
            assert_eq!(cursor[CURSOR_E_STATE], 0);
            assert_eq!(cursor.as_ptr().add(CURSOR_OVERFLOW_PAGE_LIST).cast::<u32>().read(), 0);
        }
    }
}
