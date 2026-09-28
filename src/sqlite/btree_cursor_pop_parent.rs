//! Pop a SQLite b-tree cursor from its current parent-page record.
//!
//! `btree_cursor_pop_parent` — retailOS `FUN_08371e18` at `0x08371e18` (60
//! bytes; `0x08371e18..0x08371e53`, with the next separately linked function
//! at `0x08371e54`). Raw ARM decoding finds two calls in the body: plain `bl`
//! to `retain_object` at `0x0837e8dc` and `release_via_field_0x48` at
//! `0x0836761c`; neither is predicated. Whole-image ARM decoding finds two
//! inbound plain `bl` calls (0x08372360 and 0x083729e8), with no predicated
//! calls.
//!
//! The routine retains the replacement page's object, releases the outgoing
//! page through its `+0x48` child field, installs the replacement page, clears
//! the cursor cell-cache fields, and restores the saved parent cell index.
//! Target pointers stay as four-byte little-endian words, so host fixtures use
//! a below-4-GiB slab. There are no deliberate behavioral deviations.

use crate::cxx::release::release_via_field_0x48;
use crate::cxx::retain::retain_object;

const CURSOR_PAGE: usize = 0x18;
const CURSOR_INDEX: usize = 0x1c;
const CURSOR_INFO_N_SIZE: usize = 0x3e;
const CURSOR_VALID_N_KEY: usize = 0x42;
const PAGE_PARENT: usize = 0x50;
const PAGE_SAVED_PARENT_INDEX: usize = 0x10;
const PAGE_OBJECT: usize = 0x48;

#[inline(always)]
unsafe fn read_u32(base: *const u8, offset: usize) -> u32 {
    u32::from_le(base.add(offset).cast::<u32>().read())
}

#[inline(always)]
unsafe fn write_u32_volatile(base: *mut u8, offset: usize, value: u32) {
    base.add(offset).cast::<u32>().write_volatile(value.to_le());
}

#[inline(always)]
unsafe fn write_u32(base: *mut u8, offset: usize, value: u32) {
    base.add(offset).cast::<u32>().write(value.to_le());
}

/// `btree_cursor_pop_parent` — original: `FUN_08371e18` @ `0x08371e18` (60
/// bytes; two verified plain `bl` calls in the body and two inbound plain
/// `bl` calls).
///
/// Replace `cursor`'s current page with its parent page while restoring the
/// outgoing page's saved parent cell index. The cursor, pages, and both objects must be live and
/// target-aligned; the retail code's initial loads perform no NULL checks.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn btree_cursor_pop_parent(cursor: *mut u8) {
    let old_page = read_u32(cursor, CURSOR_PAGE) as usize as *mut u8;
    let parent_page = read_u32(old_page, PAGE_PARENT) as usize as *mut u8;
    let parent_index = old_page.add(PAGE_SAVED_PARENT_INDEX).cast::<u16>().read_volatile();
    let parent_object = read_u32(parent_page, PAGE_OBJECT) as usize as *mut u8;

    retain_object(parent_object);
    release_via_field_0x48(old_page);
    write_u32_volatile(cursor, CURSOR_PAGE, parent_page as usize as u32);
    cursor.add(CURSOR_INFO_N_SIZE).cast::<u16>().write_volatile(0);
    cursor.add(CURSOR_VALID_N_KEY).write_volatile(0);
    write_u32_volatile(cursor, CURSOR_INDEX, parent_index as u32);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use std::sync::LazyLock;

    const SLAB_LEN: usize = 0x1000;
    const CURSOR: usize = 0x000;
    const OLD_PAGE: usize = 0x100;
    const PARENT_PAGE: usize = 0x200;
    const OLD_OBJECT: usize = 0x400;
    const PARENT_OBJECT: usize = 0x500;
    const OLD_CONTEXT: usize = 0x600;
    const PARENT_CONTEXT: usize = 0x700;
    const OBJECT_CONTEXT: usize = 0;
    const OBJECT_REFCOUNT: usize = 0x22;
    const CONTEXT_ACTIVITY: usize = 0xe0;

    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::BTREE_CURSOR_POP_PARENT, SLAB_LEN).map(|pointer| pointer as usize)
    });

    unsafe fn fixture() -> Option<*mut u8> {
        let Some(base) = *SLAB else {
            return None;
        };
        let base = base as *mut u8;
        base.write_bytes(0, SLAB_LEN);
        let cursor = base.add(CURSOR);
        let old_page = base.add(OLD_PAGE);
        let parent_page = base.add(PARENT_PAGE);
        let old_object = base.add(OLD_OBJECT);
        let parent_object = base.add(PARENT_OBJECT);
        let old_context = base.add(OLD_CONTEXT);
        let parent_context = base.add(PARENT_CONTEXT);

        write_u32(cursor, CURSOR_PAGE, old_page as usize as u32);
        old_page.add(0x48 / 4 * core::mem::size_of::<*mut u8>()).cast::<*mut u8>().write(old_object);
        write_u32(cursor, CURSOR_INDEX, 0xfeed_face);
        cursor.add(CURSOR_INFO_N_SIZE).cast::<u16>().write(0xffff);
        cursor.add(CURSOR_VALID_N_KEY).write(1);
        write_u32(old_page, PAGE_PARENT, parent_page as usize as u32);
        write_u32(old_page, PAGE_OBJECT, old_object as usize as u32);
        old_page.add(PAGE_SAVED_PARENT_INDEX).cast::<u16>().write(0xbeef);
        write_u32(parent_page, PAGE_OBJECT, parent_object as usize as u32);
        write_u32(old_object, OBJECT_CONTEXT, old_context as usize as u32);
        write_u32(parent_object, OBJECT_CONTEXT, parent_context as usize as u32);
        old_object.add(OBJECT_REFCOUNT).cast::<u16>().write(2);
        parent_object.add(OBJECT_REFCOUNT).cast::<u16>().write(1);
        Some(cursor)
    }

    #[test]
    fn replaces_page_resets_cache_and_balances_object_references() {
        let Some(cursor) = (unsafe { fixture() }) else {
            assert!(note_missing_u32_fixture(module_path!()));
            return;
        };
        unsafe {
            let base = SLAB.expect("fixture slab checked above") as *mut u8;
            btree_cursor_pop_parent(cursor);

            assert_eq!(read_u32(cursor, CURSOR_PAGE), base.add(PARENT_PAGE) as usize as u32);
            assert_eq!(read_u32(cursor, CURSOR_INDEX), 0xbeef);
            assert_eq!(cursor.add(CURSOR_INFO_N_SIZE).cast::<u16>().read(), 0);
            assert_eq!(cursor.add(CURSOR_VALID_N_KEY).read(), 0);
            assert_eq!(base.add(OLD_OBJECT + OBJECT_REFCOUNT).cast::<u16>().read(), 1);
            assert_eq!(base.add(PARENT_OBJECT + OBJECT_REFCOUNT).cast::<u16>().read(), 2);
            assert_eq!(base.add(OLD_CONTEXT + CONTEXT_ACTIVITY).cast::<u32>().read(), 0);
            assert_eq!(base.add(PARENT_CONTEXT + CONTEXT_ACTIVITY).cast::<u32>().read(), 0);
        }
    }
}
