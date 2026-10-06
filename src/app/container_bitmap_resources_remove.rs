//! Removes the bitmap resources belonging to a container.
//!
//! Original: `FUN_0815b27c` @ `0x0815b27c`, 100 bytes through
//! `0x0815b2e0` (96 instruction bytes and the `BMap` literal). Verified:
//! two internal plain BLs and one BLNE; two inbound plain BLs, no predicated
//! inbound calls. Snapshot the signed item count, visit each signed-i16 index,
//! skip NULL elements, and remove each element's bitmap ID at +0x14 from
//! the resource manager stored in the owner's target word at +0xcc.
//!
//! Deliberate deviations: stock deque lookup is retained because the existing
//! Rust deque_element_at returns a slot rather than the stock dereferenced
//! element. Stock removal at 0x0811cca0 takes three meaningful arguments;
//! Ghidra's fourth argument is only an uninitialized output stack slot.
//! Host builds substitute behavioral implementations for these stock calls.

use crate::cxx::container_item_count_or_zero::container_item_count_or_zero;
use core::ptr;

type ElementAt = unsafe extern "C" fn(*const u8, i32) -> *mut u8;
type RemoveResource = unsafe extern "C" fn(u32, u32, u32);

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_element_at(_: *const u8, _: i32) -> *mut u8 {
    panic!("requires stock deque lookup at 0x081cb408")
}
#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_remove(_: u32, _: u32, _: u32) {
    panic!("requires stock resource removal at 0x0811cca0")
}
#[cfg(not(target_arch = "arm"))]
pub static mut CONTAINER_BITMAP_ELEMENT_AT: ElementAt = missing_element_at;
#[cfg(not(target_arch = "arm"))]
pub static mut CONTAINER_BITMAP_REMOVE_RESOURCE: RemoveResource = missing_remove;

#[inline(always)]
unsafe fn element_at(container: *const u8, index: i32) -> *mut u8 {
    #[cfg(target_arch = "arm")]
    let lookup: ElementAt = core::mem::transmute(0x081c_b408usize);
    #[cfg(not(target_arch = "arm"))]
    let lookup = ptr::read_volatile(ptr::addr_of!(CONTAINER_BITMAP_ELEMENT_AT));
    lookup(container, index)
}

#[inline(always)]
unsafe fn remove_resource(manager: u32, id: u32) {
    #[cfg(target_arch = "arm")]
    let remove: RemoveResource = core::mem::transmute(0x0811_cca0usize);
    #[cfg(not(target_arch = "arm"))]
    let remove = ptr::read_volatile(ptr::addr_of!(CONTAINER_BITMAP_REMOVE_RESOURCE));
    remove(manager, 0x424d_6170, id);
}

/// # Safety
/// A non-NULL container must have a valid embedded target-layout deque and
/// elements readable through +0x14. For each non-NULL element, owner must be
/// readable through +0xcc and its manager must satisfy stock removal's contract.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn container_bitmap_resources_remove(owner: *const u8, container: *const u8) {
    if container.is_null() {
        return;
    }
    let count = container_item_count_or_zero(container);
    let mut index = 0i16;
    while i32::from(index) < count {
        let element = element_at(container, i32::from(index));
        if !element.is_null() {
            let id = element.cast::<u32>().add(5).read();
            let manager = owner.cast::<u32>().add(0xcc / 4).read();
            remove_resource(manager, id);
        }
        index = index.wrapping_add(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    static LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
    static mut ELEMENTS: [[u32; 6]; 3] = [[0; 6]; 3];
    static mut LIVE: [bool; 3] = [false; 3];
    static mut CONTAINER: *mut u32 = ptr::null_mut();
    static mut OWNER: *mut u32 = ptr::null_mut();
    static mut VISITED: u32 = 0;

    unsafe extern "C" fn lookup(_: *const u8, index: i32) -> *mut u8 {
        VISITED |= 1 << index;
        if index == 1 { ptr::null_mut() }
        else { ptr::addr_of_mut!(ELEMENTS).cast::<u32>().add(index as usize * 6).cast() }
    }
    unsafe extern "C" fn remove(manager: u32, kind: u32, id: u32) {
        assert_eq!(kind, 0x424d_6170);
        assert_eq!(manager, if id == 17 { 0x1000 } else { 0x2000 });
        LIVE[if id == 17 { 0 } else { 2 }] = false;
        // Both fields can change during removal: count remains snapshotted,
        // while the manager is freshly loaded for each non-NULL element.
        CONTAINER.add(9).write(0);
        OWNER.add(0xcc / 4).write(0x2000);
    }

    #[test]
    fn null_empty_and_negative_count_never_touch_owner_or_elements() {
        let _lock = LOCK.lock();
        unsafe {
            VISITED = 0;
            CONTAINER_BITMAP_ELEMENT_AT = lookup;
            container_bitmap_resources_remove(ptr::null(), ptr::null());
            let mut words = [0u32; 10];
            container_bitmap_resources_remove(ptr::null(), words.as_ptr().cast());
            words[9] = 0xffff;
            container_bitmap_resources_remove(ptr::null(), words.as_ptr().cast());
            assert_eq!(VISITED, 0);
        }
    }

    #[test]
    fn removes_non_null_resources_using_snapshot_count_and_current_manager() {
        let _lock = LOCK.lock();
        unsafe {
            let mut container = [0u32; 10];
            container[9] = 0xabcd_0003;
            let mut owner = [0u32; 52];
            owner[51] = 0x1000;
            CONTAINER = container.as_mut_ptr();
            OWNER = owner.as_mut_ptr();
            ELEMENTS = [[0, 0, 0, 0, 0, 17], [0; 6], [0, 0, 0, 0, 0, 23]];
            LIVE = [true, false, true];
            VISITED = 0;
            CONTAINER_BITMAP_ELEMENT_AT = lookup;
            CONTAINER_BITMAP_REMOVE_RESOURCE = remove;
            container_bitmap_resources_remove(owner.as_ptr().cast(), container.as_ptr().cast());
            assert_eq!(LIVE, [false; 3]);
            assert_eq!(VISITED, 0b111);
            assert_eq!(container[9], 0);
            assert_eq!(owner[51], 0x2000);
        }
    }
}
