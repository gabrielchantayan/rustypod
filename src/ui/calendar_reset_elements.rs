//! Reset calendar elements — FUN_08126c4c @ 0x08126c4c.
//!
//! True extent: 180 bytes, [0x08126c4c,0x08126d00), including four
//! literals after the return. Whole-image ARM-word decoding verifies two
//! plain inbound BLs (0x08228b10, 0x082362fc), zero predicated inbound BLs;
//! body has five plain BLs, zero predicated BLs and two virtual BLX calls.
//! Construct the zero-extended inclusive range [0, 0x10b6c2], clear the
//! embedded observable array, snapshot collection count minus one, then
//! append each group's matching elements. Notify VMax and VVal with 0x369a.
//! Reload collection and vtable on every use to preserve reentrant changes.
//! Deviations: existing Rust ports replace four BL targets; the unported
//! group range collector remains a verified fixed-address firmware seam.
//! Host tests inject dependencies instead of invoking firmware addresses.

use crate::util::expand_u32_pair_to_u64_pair::expand_u32_pair_to_u64_pair;
use crate::app::opaque_collection_item_at::opaque_collection_item_at;
use crate::app::opaque_collection_item_count::opaque_collection_item_count;
use crate::cxx::observable_element_array_clear::observable_element_array_clear;

type Clear = unsafe extern "C" fn(*mut u32);
type Count = unsafe extern "C" fn(*mut u32) -> u32;
type Item = unsafe extern "C" fn(*mut u32, usize) -> *mut u8;
type Collect = unsafe extern "C" fn(*mut u8, *const u32, *mut u32);
type Notify = unsafe extern "C" fn(*mut u32, u32, u32);

unsafe extern "C" fn clear(array: *mut u32) {
    observable_element_array_clear(array.cast());
}
unsafe extern "C" fn count(collection: *mut u32) -> u32 {
    opaque_collection_item_count(collection.cast())
}
unsafe extern "C" fn item(collection: *mut u32, index: usize) -> *mut u8 {
    opaque_collection_item_at(collection.cast(), index)
}
#[cfg(target_os = "none")]
unsafe extern "C" fn collect_group_elements_in_range(group: *mut u8, range: *const u32, array: *mut u32) {
    core::mem::transmute::<usize, Collect>(0x0828_4878)(group, range, array);
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn collect_group_elements_in_range(_: *mut u8, _: *const u32, _: *mut u32) {
    panic!("calendar range collector requires retailOS");
}
unsafe extern "C" fn notify(view: *mut u32, property: u32, value: u32) {
    let vtable = view.read() as usize as *const u32;
    let dispatch: Notify = core::mem::transmute(vtable.add(0x58 / 4).read() as usize);
    dispatch(view, property, value);
}

/// Clear and repopulate the calendar's embedded element array.
///
/// # Safety
/// `view` must have the retailOS calendar layout, a valid collection at
/// +0xbc, observable array at +0xc0, and notification vtable slot +0x58.
/// Collection items must obey the firmware group range-collector contract.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn calendar_reset_elements(view: *mut u32) {
    reset_with(view, clear, count, item, collect_group_elements_in_range, notify);
}

#[inline(always)]
unsafe fn reset_with(view: *mut u32, clear: Clear, count: Count, item: Item,
    collect: Collect, notify: Notify,
) {
    let mut range = [0u32; 4];
    expand_u32_pair_to_u64_pair(range.as_mut_ptr(), &0, &0x10b6c2);
    let array = view.add(0xc0 / 4);
    clear(array);
    let last = count(view.add(0xbc / 4).read() as usize as *mut u32).wrapping_sub(1) as i32;
    let mut index = 0i32;
    while index <= last {
        let group = item(view.add(0xbc / 4).read() as usize as *mut u32, index as usize);
        collect(group, range.as_ptr(), array);
        index = index.wrapping_add(1);
    }
    notify(view, 0x564d6178, 0x369a);
    notify(view, 0x5656616c, 0x369a);
}

#[cfg(test)]
mod tests {
    use super::*;
    unsafe extern "C" fn clear(array: *mut u32) {
        array.add(1).write(0);
        // Clearing may replace the collection before its count is read.
        array.sub(1).write(array.add(2).read());
    }
    unsafe extern "C" fn count(collection: *mut u32) -> u32 { collection as usize as u32 }
    unsafe extern "C" fn item(collection: *mut u32, index: usize) -> *mut u8 {
        (collection as usize * 16 + index) as *mut u8
    }
    unsafe extern "C" fn collect(group: *mut u8, range: *const u32, array: *mut u32) {
        assert_eq!(core::slice::from_raw_parts(range, 4), &[0, 0, 0x10b6c2, 0]);
        let index = array.add(1).read() as usize;
        array.add(4 + index).write(group as usize as u32);
        array.add(1).write(index as u32 + 1);
        // New collection must be used for the next lookup, not its count.
        array.sub(1).write(7);
    }
    unsafe extern "C" fn notify(view: *mut u32, property: u32, value: u32) {
        assert_eq!(value, 0x369a);
        let n = view.add(80).read() as usize;
        view.add(81 + n).write(property);
        view.add(80).write(n as u32 + 1);
        assert_eq!(view.add(49).read(), view.add(83).read());
    }
    #[test]
    fn clears_snapshots_signed_bound_and_reloads_collection() {
        for (count, expected) in [(0, &[][..]), (1, &[16][..]),
            (3, &[48, 113, 114][..]), (0x80000001, &[][..]), (u32::MAX, &[][..])] {
            let mut view = [0u32; 84];
            view[47] = 9;
            view[49] = 99;
            view[50] = count;
            view[83] = expected.len() as u32;
            unsafe { reset_with(view.as_mut_ptr(), clear, self::count, item, collect, notify); }
            assert_eq!(view[49], expected.len() as u32);
            assert_eq!(&view[52..52 + expected.len()], expected);
            assert_eq!(&view[80..83], &[2, 0x564d6178, 0x5656616c]);
        }
    }
}
