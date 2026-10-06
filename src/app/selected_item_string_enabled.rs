//! Selected item string predicate — FUN_0815b118 @ 0x0815b118.
//! True extent: 124 bytes, ending at 0x0815b194's independent push.
//! Verified calls: six internal plain BL, zero predicated BL; two inbound
//! plain BL (0x081f62d4, 0x081f640c), zero predicated inbound BL.
//! If the owner's deque at +0xa0 is nonempty and its back pointer is non-NULL,
//! use the pointed object's signed i16 index to fetch an item. COW-copy its
//! string at +8 (selector zero) or +12 (any nonzero selector), look up/insert
//! a zero-default value in the map at +0x84, release the copy, and return
//! whether the value is nonzero. The lookup can mutate the map.
//! Deliberate deviations: typed temporary; retain stock 0x081cb408 because
//! the existing Rust port returns an element slot instead of its contents.
//! Host tests inject deque/item/map operations without widening target offsets.

use crate::cxx::string::{cxx_string_copy_ctor, cxx_string_release};
use crate::cxx::templates::{container_is_empty, deque_back_elem4};
use crate::cxx::string_value_map_lookup_or_insert::string_value_map_lookup_or_insert;

type ElementAt = unsafe extern "C" fn(*const u8, i32) -> *mut u8;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_element_at(_: *const u8, _: i32) -> *mut u8 {
    panic!("requires retailOS element lookup at 0x081cb408")
}
#[cfg(not(target_os = "none"))]
pub static mut SELECTED_ITEM_ELEMENT_AT: ElementAt = missing_element_at;

/// # Safety
/// Owner must contain valid target-layout map/deque members at +0x84/+0xa0.
/// A non-NULL back object must expose a signed i16 index and its fetched item
/// must contain live COW strings at +8 and +12. The map must support insertion.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn selected_item_string_enabled(owner: *mut u8, selector: u32) -> u32 {
    #[cfg(target_os = "none")]
    let element: ElementAt = core::mem::transmute(0x081c_b408usize);
    #[cfg(not(target_os = "none"))]
    let element = core::ptr::addr_of!(SELECTED_ITEM_ELEMENT_AT).read_volatile();
    enabled_with(owner, selector,
        |deque| container_is_empty(deque),
        |deque| deque_back_elem4(deque.cast()).cast::<*mut u8>().read(),
        |object, index| element(object, index),
        |map, key| string_value_map_lookup_or_insert(map, key).cast::<u32>().read())
}

unsafe fn enabled_with(
    owner: *mut u8, selector: u32,
    mut empty: impl FnMut(*const u8) -> u32,
    mut back: impl FnMut(*const u8) -> *mut u8,
    mut element: impl FnMut(*const u8, i32) -> *mut u8,
    mut lookup: impl FnMut(*mut u8, *const *mut u8) -> u32,
) -> u32 {
    let deque = owner.add(0xa0);
    if empty(deque) != 0 { return 0; }
    let object = back(deque);
    if object.is_null() { return 0; }
    let item = element(object, object.cast::<i16>().read() as i32);
    let source = item.wrapping_add(if selector == 0 { 8 } else { 12 }).cast::<*mut u8>();
    let mut key = core::ptr::null_mut();
    cxx_string_copy_ctor(&mut key, source);
    let value = lookup(owner.add(0x84), &key);
    cxx_string_release(&mut key);
    u32::from(value != 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cxx::string::StringRep;
    use crate::heap::veneers::tests::mock_heap;

    #[test]
    fn empty_and_null_back_short_circuit() {
        let mut owner = [0u32; 50];
        unsafe {
            assert_eq!(selected_item_string_enabled(owner.as_mut_ptr().cast(), 0), 0);
            assert_eq!(enabled_with(owner.as_mut_ptr().cast(), 1, |_| 1,
                |_| panic!("empty deque read"), |_, _| panic!("element read"),
                |_, _| panic!("map read")), 0);
            assert_eq!(enabled_with(owner.as_mut_ptr().cast(), 1, |_| 0,
                |_| core::ptr::null_mut(), |_, _| panic!("element read"),
                |_, _| panic!("map read")), 0);
        }
    }

    #[test]
    fn signed_index_nonzero_selectors_and_cow_lifetime() {
        let _heap = mock_heap();
        for selector in [0, 1, 2, u32::MAX] {
            for value in [0, 1, 0x8000_0000, u32::MAX] {
                let mut owner = [0u32; 50];
                let mut index = -32768i16;
                let mut allocation = [0u32; 8];
                unsafe {
                    let rep = allocation.as_mut_ptr().cast::<StringRep>();
                    (*rep).refcount = 0;
                    (*rep).capacity = 8;
                    (*rep).length = 1;
                    let data = rep.add(1).cast::<u8>();
                    data.write(b'x'); data.add(1).write(0);
                    // Host string pointers occupy 8 bytes: supply only the chosen
                    // slot at the exact target offset rather than overlapping fields.
                    let mut item = [0usize; 4];
                    let item_ptr = item.as_mut_ptr().cast::<u8>();
                    let offset = if selector == 0 { 8 } else { 12 };
                    // +12 is not host-pointer aligned; choose a shifted base.
                    let item_ptr = item_ptr.add(if selector == 0 { 0 } else { 4 });
                    item_ptr.add(offset).cast::<*mut u8>().write(data);
                    let base = owner.as_mut_ptr().cast::<u8>();
                    let index_ptr = core::ptr::addr_of_mut!(index).cast::<u8>();
                    let result = enabled_with(base, selector,
                        |deque| { assert_eq!(deque, base.add(0xa0)); 0 },
                        |_| index_ptr,
                        |object, signed| {
                            assert_eq!(object, index_ptr);
                            assert_eq!(signed, -32768); item_ptr
                        },
                        |map, key| {
                            assert_eq!(map, base.add(0x84));
                            assert_eq!(*key, data);
                            assert_eq!((*rep).refcount, 1);
                            value
                        });
                    assert_eq!(result, u32::from(value != 0));
                    assert_eq!((*rep).refcount, 0);
                }
            }
        }
    }
}
