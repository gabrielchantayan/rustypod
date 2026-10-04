//! Recursive collection of eligible child views for a container's selection list.

use crate::app::registry::{object_cast_to_class, FrameworkObject};
use crate::app::vtable_set::{iterator_state_construct, iterator_state_next, iterator_state_cleanup};

// Monomorphized backend keeps the firmware calls direct while allowing host
// tree fixtures without truncating native pointers into firmware iterator words.
trait Children {
    type Cursor;
    fn cursor() -> Self::Cursor;
    unsafe fn begin(&mut self, container: *mut u8, cursor: &mut Self::Cursor);
    unsafe fn next(&mut self, cursor: &mut Self::Cursor, child: &mut *mut u8) -> bool;
    unsafe fn cast(&mut self, child: *mut u8) -> *mut u8;
    unsafe fn invalidate(&mut self, child: *mut u8);
    unsafe fn flags(&mut self, child: *mut u8) -> u32;
    unsafe fn append(&mut self, output: *mut u8, child: &mut *mut u8);
    unsafe fn end(&mut self, cursor: &mut Self::Cursor);
}

struct Firmware;
impl Children for Firmware {
    type Cursor = core::mem::MaybeUninit<[u32; 5]>;
    fn cursor() -> Self::Cursor { core::mem::MaybeUninit::uninit() }
    unsafe fn begin(&mut self, container: *mut u8, cursor: &mut Self::Cursor) {
        iterator_state_construct(cursor.as_mut_ptr().cast(), container.add(0xa8), -2);
    }
    unsafe fn next(&mut self, cursor: &mut Self::Cursor, child: &mut *mut u8) -> bool {
        iterator_state_next(cursor.as_mut_ptr().cast(), (child as *mut *mut u8).cast()) != 0
    }
    unsafe fn cast(&mut self, child: *mut u8) -> *mut u8 {
        object_cast_to_class(child.cast::<FrameworkObject>(), 0x1100)
    }
    unsafe fn invalidate(&mut self, child: *mut u8) {
        crate::ui::invalidate::ui_element_invalidate(child);
    }
    unsafe fn flags(&mut self, child: *mut u8) -> u32 {
        child.add(0x48).cast::<u32>().read_volatile()
    }
    unsafe fn append(&mut self, output: *mut u8, child: &mut *mut u8) {
        let table = output.cast::<*const usize>().read();
        let append: unsafe extern "C" fn(*mut u8, *mut *mut u8) =
            core::mem::transmute(table.add(7).read());
        append(output, child);
    }
    unsafe fn end(&mut self, cursor: &mut Self::Cursor) {
        iterator_state_cleanup(cursor.as_mut_ptr().cast());
    }
}

unsafe fn collect<C: Children>(ops: &mut C, container: *mut u8, output: *mut u8) {
    let mut cursor = C::cursor();
    ops.begin(container, &mut cursor);
    let mut child = core::ptr::null_mut();
    while ops.next(&mut cursor, &mut child) {
        let nested = ops.cast(child);
        ops.invalidate(child);
        if ops.flags(child) & 1 != 0 {
            ops.append(output, &mut child);
        } else if !nested.is_null() {
            collect(ops, nested, output);
        }
    }
    ops.end(&mut cursor);
}

/// collect_eligible_descendants — FUN_0820358c @ 0x0820358c.
/// True extent: 164 bytes, through 0x08203630's distinct prologue; no literals.
/// Raw image scan: one plain inbound BL and one predicated recursive BL.
/// Body: six plain BLs, one BLNE and one indirect BLX.
///
/// Walk the +0xa8 child registry with a five-word iterator starting at -2.
/// Cast every child to class 0x1100, invalidate it, then read flags at +0x48.
/// Append flagged children through output slot +0x1c (passing the address of
/// the child pointer); otherwise recursively traverse successful casts.
/// Clean up every iterator, including empty registries. The receiver is
/// carried by the original recursion but has no observable use.
///
/// Deliberate deviations: a monomorphized backend permits native-pointer host
/// fixtures; firmware uses the existing ports directly. LLVM may inline the
/// private recursive worker rather than call this exported wrapper recursively.
/// No additional null checks, cycle handling, or eligibility rules are added.
///
/// # Safety
/// Containers, children, and output must satisfy the firmware registry, view,
/// and virtual append contracts, with an acyclic traversable child hierarchy.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn collect_eligible_descendants(
    _receiver: *mut u8, container: *mut u8, output: *mut u8,
) {
    collect(&mut Firmware, container, output);
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;
    use std::vec;

    struct Node { flags: u32, container: bool, children: Vec<usize> }
    struct Tree { nodes: Vec<Node>, visited: Vec<usize>, selected: Vec<usize>, closed: Vec<usize> }
    impl Children for Tree {
        type Cursor = (usize, usize);
        fn cursor() -> Self::Cursor { (0, 0) }
        unsafe fn begin(&mut self, container: *mut u8, cursor: &mut Self::Cursor) { *cursor = (container as usize, 0); }
        unsafe fn next(&mut self, cursor: &mut Self::Cursor, child: &mut *mut u8) -> bool {
            let children = &self.nodes[cursor.0].children;
            if cursor.1 == children.len() { return false; }
            *child = children[cursor.1] as *mut u8;
            cursor.1 += 1;
            true
        }
        unsafe fn cast(&mut self, child: *mut u8) -> *mut u8 {
            if self.nodes[child as usize].container { child } else { core::ptr::null_mut() }
        }
        unsafe fn invalidate(&mut self, child: *mut u8) {
            let index = child as usize;
            self.visited.push(index);
            // Invalidation can change eligibility; the walker must read afterward.
            if self.nodes[index].flags & 0x80000000 != 0 { self.nodes[index].flags |= 1; }
        }
        unsafe fn flags(&mut self, child: *mut u8) -> u32 { self.nodes[child as usize].flags }
        unsafe fn append(&mut self, _: *mut u8, child: &mut *mut u8) {
            self.selected.push(*child as usize);
            *child = core::ptr::null_mut(); // callback may overwrite the stack local
        }
        unsafe fn end(&mut self, cursor: &mut Self::Cursor) { self.closed.push(cursor.0); }
    }
    fn node(flags: u32, container: bool, children: &[usize]) -> Node {
        Node { flags, container, children: children.into() }
    }
    #[test]
    fn depth_first_selection_stops_at_eligible_containers_and_skips_uncast_leaves() {
        let mut tree = Tree {
            nodes: vec![node(0, true, &[1, 2, 3, 4]), node(0, true, &[5, 6]),
                node(1, true, &[7]), node(2, false, &[]), node(0x80000000, false, &[]),
                node(1, false, &[]), node(0, true, &[]), node(1, false, &[])],
            visited: vec![], selected: vec![], closed: vec![],
        };
        unsafe { collect(&mut tree, core::ptr::null_mut(), core::ptr::null_mut()); }
        assert_eq!(tree.visited, [1, 5, 6, 2, 3, 4]);
        assert_eq!(tree.selected, [5, 2, 4]);
        assert_eq!(tree.closed, [6, 1, 0]);
    }
    #[test]
    fn empty_registry_is_cleaned_without_visiting_or_appending() {
        let mut tree = Tree { nodes: vec![node(0, true, &[])], visited: vec![], selected: vec![], closed: vec![] };
        unsafe { collect(&mut tree, core::ptr::null_mut(), core::ptr::null_mut()); }
        assert_eq!(tree.closed, [0]);
        assert_eq!(tree.visited, []);
        assert_eq!(tree.selected, []);
    }
}
