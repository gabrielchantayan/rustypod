//! FreeType size release.

use core::ffi::c_void;
use core::ptr;
use crate::ft::face::FtDriver;
use crate::ft::glyph_slot::FtFace;
use crate::ft::list::{ft_list_find, ft_list_remove, FtList};
use crate::ft::memory::{ft_mem_free, FtMemory};
use crate::ft::size::FtSize;

/// Face prefix extended through the size list (+0x6c on ARM).
#[repr(C)]
pub struct FtSizeFace {
    pub root: FtFace,
    pub stream: *mut c_void,
    pub sizes: FtList,
}

type SizeDestroy = unsafe extern "C" fn(*mut FtMemory, *mut FtSize, *mut FtDriver);

/// FT_Done_Size — FUN_0804c42c @ 0x0804c42c, 164 bytes,
/// [0x0804c42c, 0x0804c4d0); the next function starts with CMP then PUSH.
/// Raw A32 decoding verifies four outgoing plain BLs, zero predicated BLs,
/// and two incoming plain BLs (0x08080a34, 0x08080ed8).
/// Reject null size (0x24), missing face (0x23), or missing driver (0x22).
/// Find and unlink the size's list node, free it with the saved driver
/// allocator, replace the active size with the remaining head if necessary,
/// then destroy the size. Missing membership returns 0x24 without mutation.
/// Deliberate deviations: use existing Rust list/allocator ports; the
/// unported size destructor at 0x0807c3bc remains a fixed-address ABI seam.
/// It runs the generic and driver finalizers and releases internal/size data.
/// Host tests inject that boundary, preserving native repr(C) pointer fields.
///
/// # Safety
/// Non-null objects must have valid prefixes and list links. A listed size
/// must also satisfy the firmware destructor's full driver-specific layout.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ft_done_size(size: *mut FtSize) -> i32 {
    let destroy: SizeDestroy = core::mem::transmute(0x0807_c3bcusize);
    done_size_with(size, destroy)
}

#[inline(always)]
unsafe fn done_size_with(size: *mut FtSize, destroy: SizeDestroy) -> i32 {
    if size.is_null() { return 0x24; }
    let face = (*size).face.cast::<FtSizeFace>();
    if face.is_null() { return 0x23; }
    let driver = (*face).root.driver.cast::<FtDriver>();
    if driver.is_null() { return 0x22; }
    let memory = (*driver).memory;
    let list = ptr::addr_of_mut!((*face).sizes);
    let node = ft_list_find(list, size.cast());
    if node.is_null() { return 0x24; }
    ft_list_remove(list, node);
    ft_mem_free(memory, node.cast());
    if ptr::read_volatile(ptr::addr_of!((*face).root.size)) == size.cast() {
        ptr::write_volatile(ptr::addr_of_mut!((*face).root.size), ptr::null_mut());
        let head = ptr::read_volatile(ptr::addr_of!((*list).head));
        if !head.is_null() {
            ptr::write_volatile(ptr::addr_of_mut!((*face).root.size), (*head).data);
        }
    }
    destroy(memory, size, driver);
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ft::list::FtListNode;

    struct State {
        face: *mut FtSizeFace,
        expected_active: *mut c_void,
        expected_head: *mut FtListNode,
        freed: *mut u8,
        destroyed: bool,
    }
    unsafe extern "C" fn unused_alloc(_: *mut FtMemory, _: i32) -> *mut u8 { panic!("allocation"); }
    unsafe extern "C" fn unused_realloc(_: *mut FtMemory, _: i32, _: i32, _: *mut u8) -> *mut u8 { panic!("reallocation"); }
    unsafe extern "C" fn release(memory: *mut FtMemory, block: *mut u8) {
        let state = &mut *((*memory).user as *mut State);
        assert!(state.freed.is_null());
        assert_eq!((*state.face).sizes.head, state.expected_head);
        state.freed = block;
    }
    unsafe extern "C" fn destroy(memory: *mut FtMemory, size: *mut FtSize, driver: *mut FtDriver) {
        let state = &mut *((*memory).user as *mut State);
        assert!(!state.freed.is_null());
        assert_eq!((*state.face).root.size, state.expected_active);
        assert_eq!((*size).face.cast::<FtSizeFace>(), state.face);
        assert_eq!((*state.face).root.driver, driver.cast());
        state.destroyed = true;
    }
    unsafe extern "C" fn forbidden(_: *mut FtMemory, _: *mut FtSize, _: *mut FtDriver) { panic!("destructor on invalid size"); }

    #[test]
    fn invalid_handles_and_absent_membership_are_inert() {
        unsafe {
            assert_eq!(ft_done_size(ptr::null_mut()), 0x24);
            let mut size = FtSize { face: ptr::null_mut() };
            assert_eq!(ft_done_size(&mut size), 0x23);
            let mut face: FtSizeFace = core::mem::zeroed();
            size.face = (&mut face as *mut FtSizeFace).cast();
            assert_eq!(ft_done_size(&mut size), 0x22);
            let mut driver: FtDriver = core::mem::zeroed();
            face.root.driver = (&mut driver as *mut FtDriver).cast();
            face.root.size = (&mut size as *mut FtSize).cast();
            assert_eq!(done_size_with(&mut size, forbidden), 0x24);
            assert_eq!(face.root.size, (&mut size as *mut FtSize).cast());
        }
    }

    #[test]
    fn removal_updates_active_size_before_destruction() {
        for active in [false, true] {
            for remaining in [false, true] {
                unsafe {
                    let mut face: FtSizeFace = core::mem::zeroed();
                    let mut size = FtSize { face: (&mut face as *mut FtSizeFace).cast() };
                    let mut other = FtSize { face: (&mut face as *mut FtSizeFace).cast() };
                    let other_ptr = (&mut other as *mut FtSize).cast();
                    let mut next = FtListNode { prev: ptr::null_mut(), next: ptr::null_mut(), data: other_ptr };
                    let mut node = FtListNode { prev: ptr::null_mut(), next: if remaining { &mut next } else { ptr::null_mut() }, data: (&mut size as *mut FtSize).cast() };
                    next.prev = &mut node;
                    face.sizes = FtList { head: &mut node, tail: if remaining { &mut next } else { &mut node } };
                    face.root.size = if active { node.data } else { other_ptr };
                    let mut state = State {
                        face: &mut face,
                        expected_active: if active && !remaining { ptr::null_mut() } else { other_ptr },
                        expected_head: node.next, freed: ptr::null_mut(), destroyed: false,
                    };
                    let mut memory = FtMemory { user: (&mut state as *mut State).cast(), alloc: unused_alloc, free: release, realloc: unused_realloc };
                    let mut driver: FtDriver = core::mem::zeroed();
                    driver.memory = &mut memory;
                    face.root.driver = (&mut driver as *mut FtDriver).cast();
                    assert_eq!(done_size_with(&mut size, destroy), 0);
                    assert_eq!(state.freed, (&mut node as *mut FtListNode).cast());
                    assert!(state.destroyed);
                    assert_eq!(face.root.size, state.expected_active);
                    assert_eq!(face.sizes.tail, if remaining { &mut next as *mut FtListNode } else { ptr::null_mut() });
                    assert!(next.prev.is_null() || !remaining);
                }
            }
        }
    }
}
