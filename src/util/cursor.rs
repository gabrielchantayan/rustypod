//! Collection cursor — the three-function iterator glue
//! @ 0x081ee138..0x081ee194.
//!
//! A *cursor* is an 8-byte stack local (callers always pass `&local`):
//! word 0 is the collection being walked, word 1 is the current index.
//! Two sentinels drive the state machine: [`CURSOR_BEFORE_FIRST`] (-2)
//! means "not started", [`CURSOR_EXHAUSTED`] (-1) means "walked off the
//! end". The collection is a C++ object whose vtable slot +0x3c is an
//! `item_at(index, out)` accessor: it stores the item into the caller's
//! out-slot and returns nonzero while `index` is in range.
//!
//! The canonical loop (e.g. the flag-list updater @ 0x0810e0ac):
//!
//! ```text
//! cursor_init(&cursor, &obj->collection);
//! item = NULL;
//! while (cursor_advance(&cursor, &item)) { ... }
//! cursor_invalidate(&cursor);
//! ```
//!
//! Originals (sizes from decomp/functions.csv; call-site counts from
//! decoding every `bl` word in osos.dec — osos.asm drops lines, and the
//! earlier scouting note in names.yaml had these three counts rotated):
//!
//! - `cursor_advance`    — `FUN_081ee138` @ 0x081ee138 (68 bytes;
//!   113 `bl` call sites).
//! - `cursor_init`       — `FUN_081ee17c` @ 0x081ee17c (16 bytes;
//!   111 `bl` call sites).
//! - `cursor_invalidate` — `FUN_081ee18c` @ 0x081ee18c (12 bytes;
//!   129 `bl` call sites).
//!
//! Deviations / recovered ABI:
//! - Ghidra types `cursor_advance` as `void`. It is not: the original
//!   never touches r0 after `blx r3`, so the accessor's result *is* the
//!   return value, and callers rely on it (0x0810e0ac branches on it to
//!   decide whether to append a new element). The port returns it.
//! - `cursor_init` and `cursor_invalidate` likewise leave r0 = `cursor`.
//!   No caller consumes that, so both are declared `void` here.
//! - Advancing an exhausted cursor is *not* a no-op in the original:
//!   -1 + 1 = 0, so it restarts at the first item. Faithfully preserved
//!   (see the `restarts_from_exhausted` test).
//! - Fields are typed struct members, never literal byte offsets, so
//!   the 32-bit target layout is exact (asserted in `layout_checks`)
//!   while 64-bit host tests get disjoint, wider fields.

/// Index sentinel stored by [`cursor_init`]: the cursor has not yet
/// produced an item, so the next advance yields index 0.
pub const CURSOR_BEFORE_FIRST: i32 = -2;

/// Index sentinel stored when the accessor reports the index is out of
/// range (also what [`cursor_invalidate`] writes).
pub const CURSOR_EXHAUSTED: i32 = -1;

/// The collection object, modeled down to its vtable pointer.
#[repr(C)]
pub struct Collection {
    pub vtable: *const CollectionVtable,
}

/// The collection's vtable, modeled down to the one slot this cluster
/// dispatches (+0x3c). The preceding slots are untouched by these three
/// functions, so their contents stay unresolved.
#[repr(C)]
pub struct CollectionVtable {
    /// Slots +0x00..+0x38: not dispatched here.
    pub unresolved: [usize; 15],
    /// Slot +0x3c: stores the item at `index` into `out` and returns
    /// nonzero while `index` is in range.
    pub item_at: unsafe extern "C" fn(this: *mut Collection, index: i32, out: *mut u8) -> u32,
}

/// The 8-byte cursor local.
#[repr(C)]
pub struct Cursor {
    /// +0x0: the collection being walked.
    pub collection: *mut Collection,
    /// +0x4: current index, or one of the two sentinels.
    pub index: i32,
}

// Target-exact layout.
#[cfg(target_pointer_width = "32")]
mod layout_checks {
    use super::*;
    const _: [u8; 0x04] = [0; core::mem::offset_of!(Cursor, index)];
    const _: [u8; 0x08] = [0; core::mem::size_of::<Cursor>()];
    const _: [u8; 0x3c] = [0; core::mem::offset_of!(CollectionVtable, item_at)];
}

/// cursor_init — original: `FUN_081ee17c` @ 0x081ee17c (16 bytes).
///
/// Binds `cursor` to `collection` and arms the "before first" sentinel,
/// so the first [`cursor_advance`] fetches index 0.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn cursor_init(cursor: *mut Cursor, collection: *mut Collection) {
    (*cursor).collection = collection;
    (*cursor).index = CURSOR_BEFORE_FIRST;
}

/// cursor_invalidate — original: `FUN_081ee18c` @ 0x081ee18c
/// (12 bytes).
///
/// Marks the cursor exhausted without touching the collection. Callers
/// run it at the end of a walk (and on every early exit).
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn cursor_invalidate(cursor: *mut Cursor) {
    (*cursor).index = CURSOR_EXHAUSTED;
}

/// cursor_advance — original: `FUN_081ee138` @ 0x081ee138 (68 bytes).
///
/// Steps to the next index (0 straight after [`cursor_init`], else
/// current + 1), asks the collection for that item through vtable slot
/// +0x3c, and marks the cursor exhausted when the accessor returns 0.
/// Returns the accessor's result: nonzero while `out` was filled.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn cursor_advance(cursor: *mut Cursor, out: *mut u8) -> u32 {
    let next = if (*cursor).index == CURSOR_BEFORE_FIRST {
        0
    } else {
        (*cursor).index.wrapping_add(1)
    };
    (*cursor).index = next;

    let collection = (*cursor).collection;
    let item_at = (*(*collection).vtable).item_at;
    let found = item_at(collection, next, out);
    if found == 0 {
        (*cursor).index = CURSOR_EXHAUSTED;
    }
    found
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use core::ptr;
    use std::vec::Vec;

    /// A collection whose items are the small integers 100, 101, 102:
    /// `item_at` writes the item into `*out` and returns 1 in range.
    #[repr(C)]
    struct TestCollection {
        vtable: *const CollectionVtable,
        items: [u32; 3],
        /// Every index the accessor was asked for, in order.
        seen: Vec<i32>,
    }

    unsafe extern "C" fn test_item_at(this: *mut Collection, index: i32, out: *mut u8) -> u32 {
        let coll = this as *mut TestCollection;
        (*coll).seen.push(index);
        if index < 0 || index as usize >= (*coll).items.len() {
            return 0;
        }
        (out as *mut u32).write_unaligned((*coll).items[index as usize]);
        1
    }

    static TEST_VTABLE: CollectionVtable = CollectionVtable {
        unresolved: [0; 15],
        item_at: test_item_at,
    };

    fn collection() -> TestCollection {
        TestCollection {
            vtable: &TEST_VTABLE,
            items: [100, 101, 102],
            seen: Vec::new(),
        }
    }

    fn blank_cursor() -> Cursor {
        Cursor { collection: ptr::null_mut(), index: 0x5555_5555 }
    }

    #[test]
    fn init_stores_the_collection_and_the_before_first_sentinel() {
        let mut coll = collection();
        let mut cursor = blank_cursor();
        unsafe { cursor_init(&mut cursor, &mut coll as *mut _ as *mut Collection) };
        assert_eq!(cursor.collection, &mut coll as *mut _ as *mut Collection);
        assert_eq!(cursor.index, -2);
    }

    #[test]
    fn invalidate_only_writes_the_index() {
        let mut coll = collection();
        let target = &mut coll as *mut _ as *mut Collection;
        let mut cursor = Cursor { collection: target, index: 7 };
        unsafe { cursor_invalidate(&mut cursor) };
        assert_eq!(cursor.index, -1);
        assert_eq!(cursor.collection, target, "the collection slot is untouched");
    }

    #[test]
    fn a_full_walk_yields_every_item_then_stops() {
        let mut coll = collection();
        let mut cursor = blank_cursor();
        let mut item: u32 = 0;
        let mut got = Vec::new();
        unsafe {
            cursor_init(&mut cursor, &mut coll as *mut _ as *mut Collection);
            while cursor_advance(&mut cursor, &mut item as *mut u32 as *mut u8) != 0 {
                got.push(item);
            }
        }
        assert_eq!(got, std::vec![100, 101, 102]);
        assert_eq!(coll.seen, std::vec![0, 1, 2, 3], "indices 0.. until one is refused");
        assert_eq!(cursor.index, -1, "the refused advance marks the cursor exhausted");
    }

    #[test]
    fn the_first_advance_asks_for_index_zero_not_minus_one() {
        let mut coll = collection();
        let mut cursor = blank_cursor();
        let mut item: u32 = 0;
        unsafe {
            cursor_init(&mut cursor, &mut coll as *mut _ as *mut Collection);
            assert_eq!(cursor_advance(&mut cursor, &mut item as *mut u32 as *mut u8), 1);
        }
        assert_eq!(coll.seen, std::vec![0]);
        assert_eq!(cursor.index, 0);
        assert_eq!(item, 100);
    }

    #[test]
    fn the_accessor_result_is_the_return_value() {
        let mut coll = collection();
        let mut cursor = blank_cursor();
        let mut item: u32 = 0;
        unsafe {
            cursor_init(&mut cursor, &mut coll as *mut _ as *mut Collection);
            for _ in 0..3 {
                assert_eq!(cursor_advance(&mut cursor, &mut item as *mut u32 as *mut u8), 1);
            }
            assert_eq!(cursor_advance(&mut cursor, &mut item as *mut u32 as *mut u8), 0);
        }
    }

    #[test]
    fn an_empty_collection_refuses_the_first_advance() {
        let mut coll = collection();
        coll.items = [0; 3];
        // Model emptiness by making every index out of range.
        unsafe extern "C" fn refuse(this: *mut Collection, index: i32, _out: *mut u8) -> u32 {
            (*(this as *mut TestCollection)).seen.push(index);
            0
        }
        static EMPTY_VTABLE: CollectionVtable =
            CollectionVtable { unresolved: [0; 15], item_at: refuse };
        coll.vtable = &EMPTY_VTABLE;

        let mut cursor = blank_cursor();
        let mut item: u32 = 0;
        unsafe {
            cursor_init(&mut cursor, &mut coll as *mut _ as *mut Collection);
            assert_eq!(cursor_advance(&mut cursor, &mut item as *mut u32 as *mut u8), 0);
        }
        assert_eq!(coll.seen, std::vec![0]);
        assert_eq!(cursor.index, -1);
    }

    #[test]
    fn restarts_from_exhausted() {
        // -1 + 1 = 0: the original has no guard, so a walk restarted
        // after exhaustion (or after cursor_invalidate) fetches item 0.
        let mut coll = collection();
        let target = &mut coll as *mut _ as *mut Collection;
        let mut cursor = Cursor { collection: target, index: CURSOR_EXHAUSTED };
        let mut item: u32 = 0;
        unsafe {
            assert_eq!(cursor_advance(&mut cursor, &mut item as *mut u32 as *mut u8), 1);
        }
        assert_eq!(cursor.index, 0);
        assert_eq!(item, 100);
    }

    #[test]
    fn a_mid_walk_cursor_resumes_from_its_index() {
        let mut coll = collection();
        let target = &mut coll as *mut _ as *mut Collection;
        let mut cursor = Cursor { collection: target, index: 1 };
        let mut item: u32 = 0;
        unsafe {
            assert_eq!(cursor_advance(&mut cursor, &mut item as *mut u32 as *mut u8), 1);
        }
        assert_eq!(cursor.index, 2);
        assert_eq!(item, 102);
    }

    #[test]
    fn the_index_wraps_like_the_originals_add() {
        // `addne r0, r0, #1` wraps; only i32::MAX can reach it.
        let mut coll = collection();
        let target = &mut coll as *mut _ as *mut Collection;
        let mut cursor = Cursor { collection: target, index: i32::MAX };
        let mut item: u32 = 0;
        unsafe { cursor_advance(&mut cursor, &mut item as *mut u32 as *mut u8) };
        // The accessor refuses i32::MIN, so the cursor ends exhausted.
        assert_eq!(coll.seen, std::vec![i32::MIN]);
        assert_eq!(cursor.index, -1);
    }

    #[test]
    fn out_is_passed_through_untouched() {
        // The original moves r1 (the out pointer) straight into r2 for
        // the accessor and never writes through it itself.
        let mut coll = collection();
        let mut cursor = blank_cursor();
        let mut slot: u32 = 0xdead_beef;
        unsafe {
            cursor_init(&mut cursor, &mut coll as *mut _ as *mut Collection);
            // A refusing accessor must leave the caller's slot alone.
            cursor.index = 9;
            assert_eq!(cursor_advance(&mut cursor, &mut slot as *mut u32 as *mut u8), 0);
        }
        assert_eq!(slot, 0xdead_beef);
    }
}
