//! Owning destruction of a 'tdat' UI element.
//!
//! Original FUN_08049468 @ 0x08049468: 280 bytes (256 code + 24 literals),
//! ending at the independently called NULL-free veneer @ 0x08049580.
//! Raw-word scan: 2 inbound plain BL, 0 predicated BL; body: 16 plain BL,
//! 0 predicated BL. Ghidra's 68-byte extent stops inside this function.

use core::ptr;
use super::tdat_class_check::ui_element_is_tdat_class;
use super::tdat_message_dispatch::tdat_dispatch_message;
use super::tdat_first_plst::ui_tdat_first_plst;
use super::tdat_flag_20_bit_2::tdat_element_set_flag_20_bit_2;
use super::tdat_element_teardown::{TdatTeardownNotify, TDAT_ELEMENT_TEARDOWN_OPS};
use crate::util::singly_linked_list_remove::singly_linked_list_remove;
use crate::libc::bzero::bzero;
use crate::heap::veneers::free_tag4;
use super::clear_tagged_list::clear_tagged_list;
use super::clear_tagged_target::clear_tagged_target;

/// Unported child destruction and embedded/resource cleanup boundaries.
#[derive(Clone, Copy)]
pub struct TdatDestroyOps {
    pub destroy_plst: unsafe extern "C" fn(*mut u8, u32),
    pub clear_tagged_list: unsafe extern "C" fn(*mut u8),
    pub clear_tagged_target: unsafe extern "C" fn(*mut u8),
    pub release_resources: unsafe extern "C" fn(*mut u8),
}

unsafe extern "C" fn retail_destroy_plst(node: *mut u8, mode: u32) {
    #[cfg(target_os = "none")]
    {
        let call: unsafe extern "C" fn(*mut u8, u32) = core::mem::transmute(0x0804_91dcusize);
        call(node, mode);
    }
    #[cfg(not(target_os = "none"))]
    { let _ = (node, mode); panic!("retail plst destruction requires target or installed ops"); }
}

macro_rules! cleanup_boundary {
    ($name:ident, $address:expr) => {
        unsafe extern "C" fn $name(object: *mut u8) {
            #[cfg(target_os = "none")]
            {
                let call: unsafe extern "C" fn(*mut u8) = core::mem::transmute($address as usize);
                call(object);
            }
            #[cfg(not(target_os = "none"))]
            { let _ = object; panic!("retail cleanup requires target or installed ops"); }
        }
    };
}
cleanup_boundary!(retail_release_resources, 0x080d_a928);

pub const DEFAULT_TDAT_DESTROY_OPS: TdatDestroyOps = TdatDestroyOps {
    destroy_plst: retail_destroy_plst,
    clear_tagged_list,
    clear_tagged_target,
    release_resources: retail_release_resources,
};
pub static mut TDAT_DESTROY_OPS: TdatDestroyOps = DEFAULT_TDAT_DESTROY_OPS;

/// Destroy a matching element: save owner and identity, mark destruction at
/// +0x21, send 'tdao'/'tdad', notify the owner's list with 'trpa', unlink the
/// element, repeatedly destroy its first plst, send 'tdcl', disable flag bit 2,
/// clear embedded lists/resources, zero all 0x948 bytes, free, then notify the
/// saved owner with 'Trpa' and the saved identity (not the freed pointer).
///
/// Deliberate deviations: ported dependencies are called directly; two
/// unported cleanups use TDAT_DESTROY_OPS. Both tagged cleanups default to
/// Rust ports, and the existing tagged-list notify seam is reused.
/// The two first-plst calls per iteration and notifications after freeing
/// the element are retained.
///
/// # Safety
/// NULL is accepted. Non-NULL pointers must be word aligned and readable at
/// +4. Matching elements must be writable for 0x948 bytes, owned by the tag-4
/// heap, and contain valid owner, child, handler, and resource state.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn tdat_element_destroy(element: *mut u8) {
    if ui_element_is_tdat_class(element) == 0 { return; }
    destroy_checked(element,
        ptr::read_volatile(ptr::addr_of!(TDAT_DESTROY_OPS)),
        ptr::read_volatile(ptr::addr_of!(TDAT_ELEMENT_TEARDOWN_OPS)).tagged_list_notify,
        tdat_dispatch_message, free_tag4);
}

unsafe fn destroy_checked(
    element: *mut u8,
    ops: TdatDestroyOps,
    notify: TdatTeardownNotify,
    dispatch: unsafe extern "C" fn(*mut u8, u32, *mut u8) -> u32,
    free: unsafe extern "C" fn(*mut u8),
) {
    let owner = element.cast::<u32>().add(2).read() as usize as *mut u8;
    let identity = element.cast::<u32>().add(6).read();
    element.add(0x21).write(element.add(0x21).read() | 2);
    dispatch(element, 0x7464_616f, ptr::null_mut());
    dispatch(element, 0x7464_6164, ptr::null_mut());
    let owner_handlers = owner.add(0xbac);
    notify(owner_handlers, 0x6170_7274, element, 0, 0);
    singly_linked_list_remove(owner.add(0xb98).cast(), element.cast());
    while ui_tdat_first_plst(element) != 0 {
        let child = ui_tdat_first_plst(element);
        (ops.destroy_plst)(child as usize as *mut u8, 0);
    }
    dispatch(element, 0x7464_636c, ptr::null_mut());
    tdat_element_set_flag_20_bit_2(element, 0);
    (ops.clear_tagged_list)(element.add(0x54));
    (ops.clear_tagged_target)(element.add(0x88));
    (ops.release_resources)(element);
    bzero(element, 0x948);
    free(element);
    notify(owner_handlers, 0x6170_7254, identity as usize as *mut u8, 0, 0);
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::cell::RefCell;
    std::thread_local! { static EVENTS: RefCell<std::vec::Vec<u32>> = const { RefCell::new(std::vec::Vec::new()) }; }
    fn event(value: u32) { EVENTS.with(|e| e.borrow_mut().push(value)); }
    unsafe extern "C" fn dispatch(element: *mut u8, tag: u32, args: *mut u8) -> u32 {
        assert!(args.is_null());
        assert_eq!(element.add(0x21).read(), 0xa2);
        // A handler may mutate these words: final notification must use snapshots.
        element.cast::<u32>().add(2).write(0);
        element.cast::<u32>().add(6).write(0);
        event(tag); 0
    }
    unsafe extern "C" fn notify(_: *mut u8, tag: u32, context: *mut u8, flags: u32, extra: u32) {
        assert_eq!((flags, extra), (0, 0));
        if tag == 0x6170_7254 { assert_eq!(context as usize, 0x12345678); }
        event(tag);
    }
    unsafe extern "C" fn clear_list(_: *mut u8) { event(1); }
    unsafe extern "C" fn clear_target(_: *mut u8) { event(2); }
    unsafe extern "C" fn resources(_: *mut u8) { event(3); }
    unsafe extern "C" fn child(node: *mut u8, mode: u32) {
        assert_eq!(mode, 0);
        let parent = node.cast::<u32>().read() as usize as *mut u32;
        parent.add(0x34 / 4).write(0);
        event(5);
    }
    unsafe extern "C" fn free(element: *mut u8) {
        assert!(core::slice::from_raw_parts(element, 0x948).iter().all(|b| *b == 0));
        assert_eq!(element.add(0x948).read(), 0x5a);
        event(4);
    }
    #[test]
    fn rejected_objects_are_untouched() {
        let mut foreign = [0x55555555u32; 8];
        unsafe {
            tdat_element_destroy(ptr::null_mut());
            tdat_element_destroy(foreign.as_mut_ptr().cast());
        }
        assert_eq!(foreign, [0x55555555; 8]);
    }
    #[test]
    fn teardown_preserves_snapshots_and_zeroes_before_free() {
        let Some(owner) = crate::testing::try_map_u32_slab(crate::testing::hints::TDAT_DESTROY, 0x3000) else { return; };
        let element = unsafe { owner.add(0x1000) };
        let object = unsafe { core::slice::from_raw_parts_mut(element.cast::<u32>(), 0x94c / 4) };
        object.fill(0x5a5a5a5a);
        unsafe {
            owner.add(0xb98).cast::<u32>().write(element as usize as u32);
            element.cast::<u32>().write(0);
            object[1] = 0x74646174;
            object[2] = owner as usize as u32;
            object[6] = 0x12345678;
            let node = owner.add(0x2000);
            node.cast::<u32>().write(element as usize as u32);
            object[0x34 / 4] = node as usize as u32;
            element.add(0x20).write(0);
            element.add(0x21).write(0xa0);
            EVENTS.with(|e| e.borrow_mut().clear());
            destroy_checked(element, TdatDestroyOps {
                destroy_plst: child, clear_tagged_list: clear_list,
                clear_tagged_target: clear_target, release_resources: resources,
            }, notify, dispatch, free);
            assert_eq!(owner.add(0xb98).cast::<u32>().read(), 0);
        }
        EVENTS.with(|e| assert_eq!(&*e.borrow(), &[
            0x7464616f, 0x74646164, 0x61707274, 5, 0x7464636c, 1, 2, 3, 4, 0x61707254,
        ]));
    }
}
