//! PLST element item loading and completion notification.

#[cfg(not(target_os = "none"))]
use core::ptr;

use crate::heap::veneers::free_tag4;

const FLAGS_OFFSET: usize = 0x18c;
const LOAD_COUNT_OFFSET: usize = 0x188;
const ITEM_SOURCE_OFFSET: usize = 0x40;
const ITEM_COUNT_OFFSET: usize = 0x2e;
const ITEM_LIST_OFFSET: usize = 0x48;
const ITEM_INDEX_OFFSET: usize = 0x24;
const COMPLETE_NOTIFY_TAG: u32 = 0x6373_6866;

type LoadItem = unsafe extern "C" fn(*mut u8, u32, u32, u8, u32) -> *mut u8;
type ResetItemState = unsafe extern "C" fn(*mut u8, u32, u32, u32);
type TaggedListNotify = unsafe extern "C" fn(*mut u8, u32, *mut u8, u32, u32);

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_load_item(
    element: *mut u8, item: u32, mode: u32, source_flag: u8, arg: u32,
) -> *mut u8 {
    let call: LoadItem = core::mem::transmute(0x0804_7844usize);
    call(element, item, mode, source_flag, arg)
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn retail_load_item(
    _element: *mut u8, _item: u32, _mode: u32, _source_flag: u8, _arg: u32,
) -> *mut u8 { ptr::null_mut() }

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_reset_item_state(element: *mut u8, count: u32, flags: u32, arg: u32) {
    let call: ResetItemState = core::mem::transmute(0x0806_48e0usize);
    call(element, count, flags, arg)
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn retail_reset_item_state(_element: *mut u8, _count: u32, _flags: u32, _arg: u32) {}

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_tagged_list_notify(
    list: *mut u8, tag: u32, context: *mut u8, item: u32, stack_arg: u32,
) {
    let call: TaggedListNotify = core::mem::transmute(0x0806_6bb8usize);
    call(list, tag, context, item, stack_arg)
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn retail_tagged_list_notify(
    _list: *mut u8, _tag: u32, _context: *mut u8, _item: u32, _stack_arg: u32,
) {}

/// plst_element_load_item — original: `FUN_08067d7c` @ `0x08067d7c` (220 bytes).
///
/// Raw `osos.dec` establishes the body from `0x08067d7c` through the return at
/// `0x08067e54`; `0x08067e58` is its `0x63736866` notification-tag literal and
/// `0x08067e5c` starts the next function. It has four direct calls: three plain
/// `bl` and one predicated `blne` (`free_tag4`).
///
/// Algorithm: unless loading is already active or inhibited, clear active when
/// requested, require a nonzero item count, set active, increment the load
/// count, and load the requested item. On success, write each non-NULL returned
/// item's ordinal, conditionally release the returned list, reset element state,
/// and notify its tagged list with the unrecovered `"fhsc"` key. Return one only
/// after that complete path.
///
/// Deliberate deviations: `0x08047844`, `0x080648e0`, and `0x08066bb8` have no
/// ported ledger entries, so target dispatch uses their verified retail addresses;
/// host tests inject those boundaries. `free_tag4` is already ported directly.
///
/// # Safety
/// `element` must point to writable target-layout storage through `+0x18c`; its
/// `+0x40` word must be a valid target pointer when non-NULL. A successful load
/// result must contain a count at `+0xc` and that many target-width item pointers
/// beginning at `+0x10`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn plst_element_load_item(element: *mut u8, item: u32, clear_active: u32, arg: u32) -> u32 {
    plst_element_load_item_with(element, item, clear_active, arg, retail_load_item, free_tag4, retail_reset_item_state, retail_tagged_list_notify)
}

unsafe fn plst_element_load_item_with(
    element: *mut u8, item: u32, clear_active: u32, arg: u32, load: LoadItem,
    free: unsafe extern "C" fn(*mut u8), reset: ResetItemState, notify: TaggedListNotify,
) -> u32 {
    if clear_active != 0 {
        *element.add(FLAGS_OFFSET) &= !4;
    }
    let flags = *element.add(FLAGS_OFFSET);
    if flags & 0xc != 0 { return 0; }
    let source = *(element.add(ITEM_SOURCE_OFFSET) as *const u32) as *const u8;
    if source.is_null() || *(source.add(ITEM_COUNT_OFFSET) as *const u16) == 0 { return 0; }
    *element.add(FLAGS_OFFSET) = flags | 4;
    *(element.add(LOAD_COUNT_OFFSET) as *mut u32) += 1;
    let result = load(element, item, (flags as u32 >> 1) & 1, *element.add(8 + 0x8f), arg);
    if result.is_null() { return 0; }
    let count = *(result.add(0xc) as *const u32);
    for index in 0..count {
        let entry = *(result.add(0x10 + index as usize * 4) as *const u32) as *mut u8;
        if !entry.is_null() { *(entry.add(ITEM_INDEX_OFFSET) as *mut u32) = index; }
    }
    free(result);
    reset(element, count, 0x1000, 0);
    notify(element.add(ITEM_LIST_OFFSET), COMPLETE_NOTIFY_TAG, element, item, 0);
    1
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use core::ptr;

    static mut LOAD_ARGS: (usize, u32, u32, u8, u32) = (0, 0, 0, 0, 0);
    static mut RESET_ARGS: (usize, u32, u32, u32) = (0, 0, 0, 0);
    static mut NOTIFY_ARGS: (usize, u32, usize, u32, u32) = (0, 0, 0, 0, 0);
    static mut FREED: usize = 0;
    static mut RESULT: *mut u8 = ptr::null_mut();
    unsafe extern "C" fn load(e: *mut u8, i: u32, m: u32, s: u8, a: u32) -> *mut u8 { LOAD_ARGS = (e as usize, i, m, s, a); RESULT }
    unsafe extern "C" fn free(p: *mut u8) { FREED = p as usize; }
    unsafe extern "C" fn reset(e: *mut u8, c: u32, f: u32, a: u32) { RESET_ARGS = (e as usize, c, f, a); }
    unsafe extern "C" fn notify(l: *mut u8, t: u32, c: *mut u8, i: u32, a: u32) { NOTIFY_ARGS = (l as usize, t, c as usize, i, a); }

    #[test]
    fn active_or_empty_elements_do_not_dispatch() {
        let mut element = [0u8; 0x190];
        unsafe {
            *element.as_mut_ptr().add(FLAGS_OFFSET) = 4;
            assert_eq!(plst_element_load_item_with(element.as_mut_ptr(), 3, 0, 9, load, free, reset, notify), 0);
            assert_eq!(LOAD_ARGS.0, 0);
        }
    }

    #[test]
    fn success_marks_items_and_forwards_exact_abi() {
        let Some(slab) = try_map_u32_slab(hints::PLST_ELEMENT_LOAD_ITEM, 0x1000) else { note_missing_u32_fixture("ui::plst_element_load_item"); return; };
        unsafe {
            ptr::write_bytes(slab, 0, 0x1000);
            let element = slab;
            let source = slab.add(0x200);
            let result = slab.add(0x400);
            let entry = slab.add(0x600);
            *(element.add(ITEM_SOURCE_OFFSET) as *mut u32) = source as usize as u32;
            *(source.add(ITEM_COUNT_OFFSET) as *mut u16) = 2;
            *element.add(FLAGS_OFFSET) = 2;
            *element.add(0x97) = 0xa5;
            *(result.add(0xc) as *mut u32) = 2;
            *(result.add(0x10) as *mut u32) = entry as usize as u32;
            RESULT = result;
            LOAD_ARGS = (0, 0, 0, 0, 0); RESET_ARGS = (0, 0, 0, 0); NOTIFY_ARGS = (0, 0, 0, 0, 0); FREED = 0;
            assert_eq!(plst_element_load_item_with(element, 7, 0, 0x55, load, free, reset, notify), 1);
            assert_eq!(*(entry.add(ITEM_INDEX_OFFSET) as *const u32), 0);
            assert_eq!(*(element.add(LOAD_COUNT_OFFSET) as *const u32), 1);
            assert_eq!(*element.add(FLAGS_OFFSET), 6);
            assert_eq!(LOAD_ARGS, (element as usize, 7, 1, 0xa5, 0x55));
            assert_eq!(FREED, result as usize);
            assert_eq!(RESET_ARGS, (element as usize, 2, 0x1000, 0));
            assert_eq!(NOTIFY_ARGS, (element.add(ITEM_LIST_OFFSET) as usize, COMPLETE_NOTIFY_TAG, element as usize, 7, 0));
        }
    }
}
