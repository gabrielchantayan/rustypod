//! Removes inactive entries from registry class 0x9300's embedded container.

#[cfg(target_os = "none")]
use crate::cxx::templates::container_element_at_alias_6a68;

#[cfg(not(target_os = "none"))]
type ContainerElementAt = unsafe extern "C" fn(*mut u8, usize) -> *mut u8;
type ItemPredicate = unsafe extern "C" fn(*mut u8) -> u32;
type ItemAction = unsafe extern "C" fn(*mut u8);
type RemoveItemAt = unsafe extern "C" fn(*mut u8, usize);

const ITEMS_OFFSET: usize = 0x18;
const ITEM_COUNT_OFFSET: usize = 0x1c;
const INACTIVE_COUNT_OFFSET: usize = 0x34;
const PREDICATE_VTABLE_WORD: usize = 0x178 / 4;
const ACTION_VTABLE_WORD: usize = 0x180 / 4;
const RETAINED_VTABLE_WORD: usize = 0x194 / 4;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_container_element_at(_this: *mut u8, _index: usize) -> *mut u8 { core::ptr::null_mut() }
#[cfg(not(target_os = "none"))]
static mut CONTAINER_ELEMENT_AT: ContainerElementAt = missing_container_element_at;
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_remove_item_at(_this: *mut u8, _index: usize) {}
#[cfg(not(target_os = "none"))]
static mut REMOVE_ITEM_AT: RemoveItemAt = missing_remove_item_at;

#[inline(always)]
unsafe fn container_element_at(this: *mut u8, index: usize) -> *mut u8 {
    #[cfg(target_os = "none")]
    { container_element_at_alias_6a68(this, index) }
    #[cfg(not(target_os = "none"))]
    { core::ptr::read_volatile(core::ptr::addr_of!(CONTAINER_ELEMENT_AT))(this, index) }
}

#[inline(always)]
unsafe fn remove_item_at(this: *mut u8, index: usize) {
    #[cfg(target_os = "none")]
    {
        let retail_remove: RemoveItemAt = core::mem::transmute(0x0812_fbf0usize);
        retail_remove(this, index);
    }
    #[cfg(not(target_os = "none"))]
    { core::ptr::read_volatile(core::ptr::addr_of!(REMOVE_ITEM_AT))(this, index); }
}

/// class_9300_remove_inactive_items — original: `FUN_0812fda0` @ 0x0812fda0
/// (200 bytes; 6 plain `blx` calls, 2 plain `bl` calls, no predicated call
/// instructions).
///
/// Scans class-0x9300's embedded container backward. NULL entries and items
/// whose +0x178 virtual predicate is nonzero remain. For each other item, a
/// nonzero +0x194 virtual query skips it; otherwise the +0x180 action runs,
/// then +0x178 is checked again. A still-zero result increments +0x34. Every
/// reached entry is removed through retail `FUN_0812fbf0` with its index; the
/// result is one when any entry was removed.
///
/// Raw `osos.dec` establishes 0x0812fda0..0x0812fe68 as the true extent; the
/// next function starts at 0x0812fe68. Direct calls are the verified
/// `container_element_at_alias_6a68` and unported `FUN_0812fbf0`; all six
/// virtual calls are unconditional `blx`. Deliberate deviation: the unported
/// helper is a fixed-address target call and a host-only recording seam.
///
/// # Safety
/// `this` must be a class-0x9300 object with a valid container at +0x18,
/// signed count at +0x1c, writable count at +0x34, and valid item vtables.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.class_9300_remove_inactive_items")]
#[inline(never)]
pub unsafe extern "C" fn class_9300_remove_inactive_items(this: *mut u8) -> u32 {
    let mut index = (this.add(ITEM_COUNT_OFFSET) as *const i32).read() - 1;
    let mut removed = 0;
    while index >= 0 {
        let item = container_element_at(this.add(ITEMS_OFFSET), index as usize);
        if !item.is_null() {
            let vtable = (item as *const *const usize).read();
            let predicate: ItemPredicate = core::mem::transmute(vtable.add(PREDICATE_VTABLE_WORD).read());
            if predicate(item) == 0 {
                let retained: ItemPredicate = core::mem::transmute(vtable.add(RETAINED_VTABLE_WORD).read());
                if retained(item) == 0 {
                    let action: ItemAction = core::mem::transmute(vtable.add(ACTION_VTABLE_WORD).read());
                    action(item);
                    if predicate(item) == 0 {
                        let inactive_count = this.add(INACTIVE_COUNT_OFFSET) as *mut u32;
                        inactive_count.write(inactive_count.read().wrapping_add(1));
                    }
                    remove_item_at(this, index as usize);
                    removed = 1;
                }
            }
        }
        index -= 1;
    }
    removed
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut ITEMS: [*mut u8; 3] = [core::ptr::null_mut(); 3];
    static mut REMOVED: [usize; 3] = [usize::MAX; 3];
    static mut REMOVED_COUNT: usize = 0;

    unsafe extern "C" fn fixture_element_at(_container: *mut u8, index: usize) -> *mut u8 { ITEMS[index] }
    unsafe extern "C" fn inactive(_item: *mut u8) -> u32 { 0 }
    unsafe extern "C" fn active(item: *mut u8) -> u32 { *(item.add(core::mem::size_of::<usize>()) as *const u32) }
    unsafe extern "C" fn always_active(_item: *mut u8) -> u32 { 1 }
    unsafe extern "C" fn not_retained(_item: *mut u8) -> u32 { 0 }
    unsafe extern "C" fn retained(_item: *mut u8) -> u32 { 1 }
    unsafe extern "C" fn activate(item: *mut u8) { *(item.add(core::mem::size_of::<usize>()) as *mut u32) = 1; }
    unsafe extern "C" fn record_remove(_this: *mut u8, index: usize) {
        REMOVED[REMOVED_COUNT] = index;
        REMOVED_COUNT += 1;
    }

    unsafe fn item(predicate: ItemPredicate, retained_query: ItemPredicate, action: ItemAction) -> ([usize; 102], [u8; 16]) {
        let mut vtable = [0usize; 102];
        vtable[PREDICATE_VTABLE_WORD] = predicate as usize;
        vtable[ACTION_VTABLE_WORD] = action as usize;
        vtable[RETAINED_VTABLE_WORD] = retained_query as usize;
        (vtable, [0; 16])
    }

    #[test]
    fn removes_inactive_entries_backwards_and_counts_only_after_action() {
        let _guard = TEST_LOCK.lock();
        unsafe {
            REMOVED = [usize::MAX; 3];
            REMOVED_COUNT = 0;
            CONTAINER_ELEMENT_AT = fixture_element_at;
            REMOVE_ITEM_AT = record_remove;
            let (mut first_vtable, mut first) = item(active, not_retained, activate);
            let (mut second_vtable, mut second) = item(inactive, retained, activate);
            let (mut third_vtable, mut third) = item(always_active, not_retained, activate);
            (first.as_mut_ptr() as *mut *const usize).write(first_vtable.as_ptr());
            (second.as_mut_ptr() as *mut *const usize).write(second_vtable.as_ptr());
            (third.as_mut_ptr() as *mut *const usize).write(third_vtable.as_ptr());
            ITEMS = [first.as_mut_ptr(), second.as_mut_ptr(), third.as_mut_ptr()];
            let mut object = [0u8; 0x38];
            let this = object.as_mut_ptr();
            (this.add(ITEM_COUNT_OFFSET) as *mut i32).write(3);
            (this.add(INACTIVE_COUNT_OFFSET) as *mut u32).write(9);
            assert_eq!(class_9300_remove_inactive_items(this), 1);
            assert_eq!(&REMOVED[..REMOVED_COUNT], [0]);
            assert_eq!((this.add(INACTIVE_COUNT_OFFSET) as *const u32).read(), 9);
            CONTAINER_ELEMENT_AT = missing_container_element_at;
            REMOVE_ITEM_AT = missing_remove_item_at;
        }
    }
}
