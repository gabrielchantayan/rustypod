//! `list_iterator_remove_if_owner_matches` — retailOS `FUN_083d5c90` @ `0x083d5c90`.
//!
//! Raw `osos.dec` establishes the exact 124-byte extent
//! `0x083d5c90..0x083d5d0b`: 31 A32 words from `push {r3-r7,lr}` through the
//! final `bl operator_delete`; `0x083d5d0c` begins the next independently
//! entered function. The body has two direct plain `bl` calls, to `iter_owner`
//! @ `0x083d5e5c` and `operator_delete` @ `0x082aad24`, plus one predicated
//! indirect `blxne` through a node element's vtable slot `+0x04`.
//!
//! # Algorithm
//!
//! Reads the candidate iterator's owning-list identity and compares it to
//! `*expected_owner`. On mismatch, writes the candidate node to `output`. On
//! equality it unlinks the node from its doubly linked ring, invokes the
//! optional element destructor through vtable slot `+0x04`, and deletes it.
//!
//! # Deliberate deviations
//!
//! The original `operator_delete` tail path does not return to this body. Rust
//! calls the already ported veneer normally, so a host heap mock that returns
//! observes `output` receiving the deleted node.

use crate::cxx::list_splice::iter_owner;
use crate::heap::veneers::operator_delete;

#[cfg(not(target_os = "none"))]
#[repr(C)]
struct HostLinkedNode {
    owner: *mut u8,
    next: *mut HostLinkedNode,
    previous: *mut HostLinkedNode,
    element: *mut HostElement,
}

#[cfg(not(target_os = "none"))]
#[repr(C)]
struct HostElement {
    vtable: *const usize,
}

type ElementDestructor = unsafe extern "C" fn(*mut u8);

#[inline(always)]
unsafe fn unlink_node(node: *mut u8) {
    #[cfg(target_os = "none")]
    {
        let next = unsafe { node.add(4).cast::<*mut u8>().read() };
        let previous = unsafe { node.add(8).cast::<*mut u8>().read() };
        unsafe {
            previous.add(4).cast::<*mut u8>().write(next);
            next.add(8).cast::<*mut u8>().write(previous);
        }
    }
    #[cfg(not(target_os = "none"))]
    {
        let node = node.cast::<HostLinkedNode>();
        let next = unsafe { (*node).next };
        let previous = unsafe { (*node).previous };
        unsafe {
            (*previous).next = next;
            (*next).previous = previous;
        }
    }
}

#[inline(always)]
unsafe fn invoke_optional_element_destructor(node: *mut u8) {
    #[cfg(target_os = "none")]
    {
        let element = unsafe { node.add(12).cast::<*mut u8>().read() };
        if !element.is_null() {
            let vtable = unsafe { element.cast::<*const u32>().read() };
            let destructor_address = unsafe { (vtable as usize as *const u32).add(1).read() };
            let destructor: ElementDestructor = unsafe { core::mem::transmute(destructor_address as usize) };
            unsafe { destructor(element) };
        }
    }
    #[cfg(not(target_os = "none"))]
    {
        let element = unsafe { (*node.cast::<HostLinkedNode>()).element };
        if !element.is_null() {
            let destructor_address = unsafe { (*element).vtable.add(1).read() };
            let destructor: ElementDestructor = unsafe { core::mem::transmute(destructor_address) };
            unsafe { destructor(element.cast()) };
        }
    }
}

/// Removes the node in `candidate_iterator` only when its owner equals `*expected_owner`.
///
/// # Safety
///
/// All non-NULL pointers must designate the target's linked-node and element
/// layouts. Matching nodes must be linked into a writable ring.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn list_iterator_remove_if_owner_matches(
    output: *mut *mut u8,
    expected_owner: *const *mut u8,
    candidate_iterator: *mut *mut u8,
) {
    let node = unsafe { candidate_iterator.read() };
    if unsafe { expected_owner.read() } == unsafe { iter_owner(candidate_iterator) } {
        unsafe {
            unlink_node(node);
            invoke_optional_element_destructor(node);
            operator_delete(node);
        }
    }
    unsafe { output.write(node) };
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());


    static mut DESTRUCTED_ELEMENT: *mut u8 = core::ptr::null_mut();
    static mut DESTRUCTOR_CALLS: usize = 0;

    unsafe extern "C" fn destruct(element: *mut u8) {
        unsafe {
            DESTRUCTED_ELEMENT = element;
            DESTRUCTOR_CALLS += 1;
        }
    }

    #[test]
    fn mismatch_preserves_ring_and_skips_destructor() {
        let _test_lock = TEST_LOCK.lock();
        unsafe { DESTRUCTED_ELEMENT = core::ptr::null_mut(); DESTRUCTOR_CALLS = 0; }

        let mut anchor = HostLinkedNode { owner: 1usize as *mut u8, next: core::ptr::null_mut(), previous: core::ptr::null_mut(), element: core::ptr::null_mut() };
        let mut node = HostLinkedNode { owner: 2usize as *mut u8, next: &mut anchor, previous: &mut anchor, element: core::ptr::null_mut() };
        anchor.next = &mut node;
        anchor.previous = &mut node;
        let expected_owner = anchor.owner;
        let mut candidate = (&mut node as *mut HostLinkedNode).cast();
        let mut output = core::ptr::null_mut();

        unsafe { list_iterator_remove_if_owner_matches(&mut output, &expected_owner, &mut candidate) };

        assert_eq!(output, candidate);
        assert!(core::ptr::eq(anchor.next, &mut node));
        assert!(core::ptr::eq(node.previous, &mut anchor));
        assert_eq!(unsafe { DESTRUCTOR_CALLS }, 0);
    }

    #[test]
    fn matching_owner_unlinks_destroys_element_and_deletes_node() {
        let _test_lock = TEST_LOCK.lock();
        let _heap = crate::heap::veneers::tests::mock_heap();
        let vtable = [0usize, destruct as usize];
        let mut element = HostElement { vtable: vtable.as_ptr() };
        let mut anchor = HostLinkedNode { owner: 9usize as *mut u8, next: core::ptr::null_mut(), previous: core::ptr::null_mut(), element: core::ptr::null_mut() };
        let mut node = HostLinkedNode { owner: anchor.owner, next: &mut anchor, previous: &mut anchor, element: &mut element };
        anchor.next = &mut node;
        anchor.previous = &mut node;
        let expected_owner = node.owner;
        let mut candidate = (&mut node as *mut HostLinkedNode).cast();
        let mut output = core::ptr::null_mut();
        unsafe { DESTRUCTED_ELEMENT = core::ptr::null_mut(); DESTRUCTOR_CALLS = 0; }

        unsafe { list_iterator_remove_if_owner_matches(&mut output, &expected_owner, &mut candidate) };

        assert_eq!(output, candidate);
        assert!(core::ptr::eq(anchor.previous, &mut anchor));
        assert!(core::ptr::eq(anchor.next, &mut anchor));
        assert_eq!(unsafe { DESTRUCTED_ELEMENT }, (&mut element as *mut HostElement).cast());
        assert_eq!(unsafe { DESTRUCTOR_CALLS }, 1);
        assert_eq!(crate::heap::veneers::tests::free_log(), (1, candidate, 2));
    }
}
