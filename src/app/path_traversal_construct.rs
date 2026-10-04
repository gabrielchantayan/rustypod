//! Construction of the path traversal state used by recursive path callers.

use core::mem::{offset_of, MaybeUninit};
use super::path_probe::{interface_guard_base_construct, InterfaceGuard};
use super::path_object_construct::{path_object_copy_construct, path_object_default_construct};
use crate::cxx::string_object::{StringObject, string_object_destroy_veneer};
use crate::heap::block_deque::{BlockDeque, DequeIter};
use crate::heap::deque_construct_elem12::block_deque_construct_elem12;
use crate::heap::deque_construct_range_elem12::deque_construct_range_elem12;

#[repr(C)]
pub struct PathTraversal {
    pub base: [u32; 3],
    pub pending: BlockDeque,
    pub mode: u8,
    pub padding: [u8; 3],
    pub root: StringObject,
}

type CopyDeque = unsafe extern "C" fn(*mut BlockDeque, *const DequeIter) -> *mut BlockDeque;
type Pop = unsafe extern "C" fn(*mut BlockDeque);
type Initialize = unsafe extern "C" fn(*mut PathTraversal, *const StringObject);

unsafe extern "C" fn pop_pending(deque: *mut BlockDeque) {
    #[cfg(target_os = "none")]
    { let call: Pop = core::mem::transmute(0x083de03cusize); call(deque); }
    #[cfg(not(target_os = "none"))]
    { let _ = deque; panic!("retailOS path-record pop requires a host implementation"); }
}

unsafe extern "C" fn initialize_traversal(this: *mut PathTraversal, path: *const StringObject) {
    #[cfg(target_os = "none")]
    { let call: Initialize = core::mem::transmute(0x081ef764usize); call(this, path); }
    #[cfg(not(target_os = "none"))]
    { let _ = (this, path); panic!("retailOS traversal initialization requires a host implementation"); }
}

/// Original `FUN_081ef938` at load address 0x081ef938: 160-byte true extent
/// (156 code bytes and vtable literal 0x0898ff40; next entry 0x081ef9d8).
/// Whole-image A32 decoding finds two inbound plain BLs and no predicated BLs;
/// the body has nine plain BLs and no predicated BLs.
/// Constructs the interface base with flag zero, installs the traversal vtable,
/// copies an empty temporary deque, drains the temporary, stores the low mode
/// byte, copies the root path, then initializes traversal with an empty path.
/// Return threading follows the deque and path constructor results.
/// Deliberate deviations: native-pointer repr(C) layout on host; the unported
/// path-record pop (0x083de03c) and traversal initializer (0x081ef764) remain
/// fixed-address device calls. Host invocation requires those implementations.
///
/// # Safety
/// `this` must be writable object storage, `root` a valid StringObject, and
/// `base_hint` must satisfy the interface resolver's firmware contract.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn path_traversal_construct(
    this: *mut PathTraversal, root: *const StringObject, mode: u32, base_hint: u32,
) -> *mut PathTraversal {
    construct_with(this, root, mode, base_hint, deque_construct_range_elem12, pop_pending, initialize_traversal)
}

unsafe fn construct_with(
    this: *mut PathTraversal, root: *const StringObject, mode: u32, base_hint: u32,
    copy: CopyDeque, pop: Pop, initialize: Initialize,
) -> *mut PathTraversal {
    let base = interface_guard_base_construct(this.cast::<InterfaceGuard>(), base_hint, 0);
    base.cast::<u32>().write(0x0898ff40);
    let mut temporary = MaybeUninit::<BlockDeque>::uninit();
    let temporary = block_deque_construct_elem12(temporary.as_mut_ptr());
    let pending = copy(core::ptr::addr_of_mut!((*this).pending), temporary.cast::<DequeIter>());
    let this = pending.cast::<u8>().sub(offset_of!(PathTraversal, pending)).cast::<PathTraversal>();
    while (*temporary).count != 0 { pop(temporary); }
    (*this).mode = mode as u8;
    let member = path_object_copy_construct(core::ptr::addr_of_mut!((*this).root), root);
    let this = member.cast::<u8>().sub(offset_of!(PathTraversal, root)).cast::<PathTraversal>();
    let mut empty = MaybeUninit::<StringObject>::uninit();
    let path = path_object_default_construct(empty.as_mut_ptr());
    initialize(this, path);
    string_object_destroy_veneer(empty.as_mut_ptr());
    this
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe extern "C" fn empty_copy(dst: *mut BlockDeque, _: *const DequeIter) -> *mut BlockDeque {
        block_deque_construct_elem12(dst)
    }
    unsafe extern "C" fn populated_copy(dst: *mut BlockDeque, range: *const DequeIter) -> *mut BlockDeque {
        // Model a range-copy boundary leaving temporary records to retire.
        (*range.cast_mut().cast::<BlockDeque>()).count = 3;
        let dst = block_deque_construct_elem12(dst);
        (*dst).map = range.cast_mut().cast::<*mut u8>();
        dst
    }
    unsafe extern "C" fn pop(deque: *mut BlockDeque) { (*deque).count -= 1; }
    unsafe extern "C" fn reject_pop(_: *mut BlockDeque) { panic!("empty range must not be popped"); }
    unsafe extern "C" fn seed(this: *mut PathTraversal, path: *const StringObject) {
        assert!((*path).payload.is_null());
        assert_eq!((*this).pending.count, 0);
        if !(*this).pending.map.is_null() {
            assert_eq!((*(*this).pending.map.cast::<BlockDeque>()).count, 0);
            (*this).pending.map = core::ptr::null_mut();
        }
        // Initialization is permitted to populate the newly constructed deque.
        (*this).pending.count = 7;
    }

    #[test]
    fn empty_and_retired_temporaries_preserve_padding_and_truncate_mode() {
        for (copy, pop) in [(empty_copy as CopyDeque, reject_pop as Pop), (populated_copy as CopyDeque, pop as Pop)] {
            for mode in [0, 1, 0xff, 0x12345680] {
                let mut storage = MaybeUninit::<PathTraversal>::uninit();
                unsafe {
                    core::ptr::write_bytes(storage.as_mut_ptr().cast::<u8>(), 0xa5, core::mem::size_of::<PathTraversal>());
                    let mut source = MaybeUninit::<StringObject>::uninit();
                    path_object_default_construct(source.as_mut_ptr());
                    let returned = construct_with(storage.as_mut_ptr(), source.as_ptr(), mode, 0, copy, pop, seed);
                    assert_eq!(returned, storage.as_mut_ptr());
                    assert_eq!((*returned).base[0], 0x0898ff40);
                    assert_eq!((*returned).mode, mode as u8);
                    assert_eq!((*returned).padding, [0xa5; 3]);
                    assert_eq!((*returned).pending.count, 7);
                    assert!((*returned).root.payload.is_null());
                    assert_eq!((*returned).base[2], 0xa5a50000);
                }
            }
        }
    }
}
