//! Collect row masks and emit scaled rectangles — FUN_0812a450 @ 0x0812a450.
//! Raw extent: 140 bytes, ending at the real function boundary 0x0812a4dc.
//! Verified direct BLs: two inbound (both unconditional), six outgoing
//! (all unconditional). Zero 15 words, walk the owner's collection, overwrite
//! each valid signed row's mask, invalidate the cursor, expand neighboring
//! masks, then extract rectangles using the owner's horizontal/vertical scale.
//! Deviations: native pointers widen host layouts; zero initialization replaces
//! the IRAM memzero veneer. The two unported algorithms remain stock calls at
//! raw-verified addresses, with explicit host injection rather than substitutes.

use crate::util::cursor::{Collection, Cursor, cursor_init, cursor_advance, cursor_invalidate};

#[repr(C)]
pub struct RowMaskRecord {
    pub unresolved_00: [u32; 2],
    pub mask: u32,
    pub unresolved_0c: u32,
    pub row: i8,
}

#[repr(C)]
pub struct RowMaskOwner {
    pub unresolved_00: [u32; 42],
    pub collection: *mut Collection,
    pub unresolved_ac: [u32; 6],
    pub vertical_scale: u32,
    pub horizontal_scale: u32,
}

#[cfg(target_pointer_width = "32")]
const _: () = {
    assert!(core::mem::offset_of!(RowMaskOwner, collection) == 0xa8);
    assert!(core::mem::offset_of!(RowMaskOwner, vertical_scale) == 0xc4);
    assert!(core::mem::offset_of!(RowMaskOwner, horizontal_scale) == 0xc8);
};

type ExpandMasks = unsafe extern "C" fn(*mut u32);
type ExtractRectangles = unsafe extern "C" fn(*mut u32, *mut u8, u32, u32);

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_expand(_rows: *mut u32) {
    panic!("install stock row-mask expansion host seam")
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_extract(_rows: *mut u32, _output: *mut u8, _x: u32, _y: u32) {
    panic!("install stock row-mask rectangle extraction host seam")
}
#[cfg(not(target_os = "none"))]
pub static mut ROW_MASK_EXPAND: ExpandMasks = missing_expand;
#[cfg(not(target_os = "none"))]
pub static mut ROW_MASK_EXTRACT: ExtractRectangles = missing_extract;

unsafe fn collect_masks(collection: *mut Collection) -> [u32; 15] {
    let mut rows = [0; 15];
    let mut cursor = Cursor { collection: core::ptr::null_mut(), index: 0 };
    cursor_init(&mut cursor, collection);
    let mut record: *const RowMaskRecord = core::ptr::null();
    while cursor_advance(&mut cursor, core::ptr::addr_of_mut!(record).cast()) != 0 {
        let row = (*record).row;
        if row >= 0 && row < 15 {
            rows[row as usize] = (*record).mask;
        }
    }
    cursor_invalidate(&mut cursor);
    rows
}

/// Collect the owner's dirty row masks into the supplied rectangle collection.
/// Owner, records, and output must satisfy the stock collection/algorithm ABIs.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn row_mask_rectangles_collect(owner: *const RowMaskOwner, output: *mut u8) {
    let mut rows = collect_masks((*owner).collection);
    #[cfg(target_os = "none")]
    let (expand, extract): (ExpandMasks, ExtractRectangles) = (
        core::mem::transmute(0x0812_a388usize),
        core::mem::transmute(0x0812_a504usize),
    );
    #[cfg(not(target_os = "none"))]
    let (expand, extract) = (
        core::ptr::addr_of!(ROW_MASK_EXPAND).read(),
        core::ptr::addr_of!(ROW_MASK_EXTRACT).read(),
    );
    expand(rows.as_mut_ptr());
    extract(rows.as_mut_ptr(), output, (*owner).horizontal_scale, (*owner).vertical_scale);
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::util::cursor::CollectionVtable;

    #[repr(C)]
    struct Fixture {
        collection: Collection,
        records: std::vec::Vec<RowMaskRecord>,
    }
    unsafe extern "C" fn item_at(collection: *mut Collection, index: i32, out: *mut u8) -> u32 {
        let fixture = &mut *collection.cast::<Fixture>();
        if let Some(record) = fixture.records.get(index as usize) {
            out.cast::<*const RowMaskRecord>().write(record);
            1
        } else { 0 }
    }
    static VTABLE: CollectionVtable = CollectionVtable { unresolved: [0; 15], item_at };

    fn collect(records: std::vec::Vec<RowMaskRecord>) -> [u32; 15] {
        let mut fixture = Fixture { collection: Collection { vtable: &VTABLE }, records };
        unsafe { collect_masks(&mut fixture.collection) }
    }
    fn record(row: i8, mask: u32) -> RowMaskRecord {
        RowMaskRecord { unresolved_00: [0; 2], mask, unresolved_0c: 0, row }
    }

    #[test]
    fn empty_collection_has_no_dirty_rows() {
        assert_eq!(collect(std::vec![]), [0; 15]);
    }
    #[test]
    fn signed_row_domain_and_endpoint_masks() {
        let records = (-128i16..=127).map(|row| record(row as i8, 0x8000_0001 | ((row as u32) << 8))).collect();
        let rows = collect(records);
        for row in 0..15 { assert_eq!(rows[row], 0x8000_0001 | ((row as u32) << 8)); }
    }
    #[test]
    fn repeated_rows_replace_rather_than_union_and_can_clear() {
        let rows = collect(std::vec![record(0, u32::MAX), record(14, 0x8000_0000),
            record(0, 1), record(14, 0), record(-1, u32::MAX), record(15, u32::MAX)]);
        let mut expected = [0; 15];
        expected[0] = 1;
        assert_eq!(rows, expected);
    }
}
