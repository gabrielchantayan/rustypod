//! Assigning SQLite source-list cursors.
//!
//! `src_list_assign_cursors` — retailOS `FUN_08384380` @ 0x08384380,
//! 104 bytes, with three direct `bl` call sites (two plain inbound calls and
//! one predicated recursive `blne`). Raw ARM spans 0x08384380..0x083843e7;
//! `src_list_delete` begins at 0x083843e8.
//!
//! SQLite 3.5.x's `sqlite3SrcListAssignCursors`: a NULL list is a no-op.
//! For each inline 0x30-byte `SrcListItem` while its signed `nSrc` exceeds
//! the index, stop at the first non-negative `iCursor`; otherwise assign the
//! current `Parse.nTab` (+0x44), increment it, then recurse into the item's
//! SELECT source-list at `pSelect + 0x0c`. Target pointers are deliberately
//! read as aligned `u32` words, rather than host pointers, so target offsets
//! remain exact on 64-bit test hosts. No deliberate behavioral deviations.

const N_SRC: usize = 0x00;
const FIRST_ITEM: usize = 0x08;
const ITEM_STRIDE: usize = 0x30;
const ITEM_SELECT: usize = 0x10;
const ITEM_CURSOR: usize = 0x18;
const SELECT_SOURCE_LIST: usize = 0x0c;
const PARSE_N_TAB: usize = 0x44;

#[inline(always)]
unsafe fn word(object: *const u8, offset: usize) -> u32 {
    core::ptr::read((object.add(offset)).cast::<u32>())
}

#[inline(always)]
unsafe fn set_word(object: *mut u8, offset: usize, value: u32) {
    core::ptr::write((object.add(offset)).cast::<u32>(), value);
}

/// `sqlite3SrcListAssignCursors` — retailOS `FUN_08384380` @ 0x08384380
/// (104 bytes; three direct `bl` call sites, one predicated recursive call).
///
/// # Safety
/// `parse` must provide a writable target-layout `nTab` word at +0x44.
/// A non-null `source_list` must provide a signed `nSrc` halfword at +0x00
/// and enough inline 0x30-byte items; non-null `pSelect` words must name a
/// SELECT with a source-list word at +0x0c.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn src_list_assign_cursors(parse: *mut u8, source_list: *mut u8) {
    if source_list.is_null() {
        return;
    }

    let mut index = 0i32;
    let mut item = source_list.add(FIRST_ITEM);
    while i32::from(core::ptr::read(source_list.cast::<i16>())) > index {
        if (word(item, ITEM_CURSOR) as i32) >= 0 {
            return;
        }
        let cursor = word(parse, PARSE_N_TAB);
        set_word(item, ITEM_CURSOR, cursor);
        set_word(parse, PARSE_N_TAB, cursor.wrapping_add(1));

        let select = word(item, ITEM_SELECT) as usize as *mut u8;
        if !select.is_null() {
            src_list_assign_cursors(parse, word(select, SELECT_SOURCE_LIST) as usize as *mut u8);
        }
        index += 1;
        item = item.add(ITEM_STRIDE);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, try_map_u32_slab};

    const FIXTURE_LEN: usize = 0x400;
    const PARSE: usize = 0x00;
    const ROOT: usize = 0x80;
    const CHILD: usize = 0x140;
    const SELECT: usize = 0x260;

    unsafe fn put_word(base: *mut u8, offset: usize, value: u32) {
        core::ptr::write(base.add(offset).cast::<u32>(), value);
    }

    unsafe fn put_count(base: *mut u8, offset: usize, value: i16) {
        core::ptr::write(base.add(offset).cast::<i16>(), value);
    }

    #[test]
    fn null_list_leaves_parse_counter_unchanged() {
        let Some(slab) = try_map_u32_slab(hints::SQLITE_SRC_LIST_ASSIGN_CURSORS, FIXTURE_LEN) else {
            return;
        };
        unsafe {
            put_word(slab, PARSE + PARSE_N_TAB, 9);
            src_list_assign_cursors(slab.add(PARSE), core::ptr::null_mut());
            assert_eq!(word(slab.add(PARSE), PARSE_N_TAB), 9);
        }
    }

    #[test]
    fn assigns_depth_first_cursors() {
        let Some(slab) = try_map_u32_slab(hints::SQLITE_SRC_LIST_ASSIGN_CURSORS_DEPTH_FIRST, FIXTURE_LEN) else {
            return;
        };
        unsafe {
            put_word(slab, PARSE + PARSE_N_TAB, 4);
            put_count(slab, ROOT + N_SRC, 2);
            put_word(slab, ROOT + FIRST_ITEM + ITEM_CURSOR, u32::MAX);
            put_word(slab, ROOT + FIRST_ITEM + ITEM_SELECT, (slab.add(SELECT)) as usize as u32);
            put_word(slab, SELECT + SELECT_SOURCE_LIST, (slab.add(CHILD)) as usize as u32);
            put_count(slab, CHILD + N_SRC, 1);
            put_word(slab, CHILD + FIRST_ITEM + ITEM_CURSOR, u32::MAX);
            put_word(slab, ROOT + FIRST_ITEM + ITEM_STRIDE + ITEM_CURSOR, u32::MAX);

            src_list_assign_cursors(slab.add(PARSE), slab.add(ROOT));

            assert_eq!(word(slab.add(ROOT + FIRST_ITEM), ITEM_CURSOR), 4);
            assert_eq!(word(slab.add(CHILD + FIRST_ITEM), ITEM_CURSOR), 5);
            assert_eq!(word(slab.add(ROOT + FIRST_ITEM + ITEM_STRIDE), ITEM_CURSOR), 6);
            assert_eq!(word(slab.add(PARSE), PARSE_N_TAB), 7);
        }
    }

    #[test]
    fn assigned_cursor_stops_the_entire_walk() {
        let Some(slab) = try_map_u32_slab(hints::SQLITE_SRC_LIST_ASSIGN_CURSORS_STOP, FIXTURE_LEN) else {
            return;
        };
        unsafe {
            put_word(slab, PARSE + PARSE_N_TAB, 12);
            put_count(slab, ROOT + N_SRC, 2);
            put_word(slab, ROOT + FIRST_ITEM + ITEM_CURSOR, 0);
            put_word(slab, ROOT + FIRST_ITEM + ITEM_STRIDE + ITEM_CURSOR, u32::MAX);

            src_list_assign_cursors(slab.add(PARSE), slab.add(ROOT));

            assert_eq!(word(slab.add(ROOT + FIRST_ITEM), ITEM_CURSOR), 0);
            assert_eq!(word(slab.add(ROOT + FIRST_ITEM + ITEM_STRIDE), ITEM_CURSOR), u32::MAX);
            assert_eq!(word(slab.add(PARSE), PARSE_N_TAB), 12);
        }
    }
}
