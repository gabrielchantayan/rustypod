//! Union shown child bounds into the primary accumulator — `FUN_08184064`.
//!
//! Load address 0x08184064; true extent 112 bytes, [0x08184064, 0x081840d4).
//! The next function starts with push {r4,lr}. Raw ARM verifies six plain
//! outbound BLs and one predicated BL (rect_union); inbound BLs are one plain
//! and one predicated, at 0x08182414 and 0x081811b4 respectively.
//! Walk the container's +0xa8 child collection. For each shown child whose
//! class-0x1280 cast fails, union its +0x80 rectangle into owner+0xa8 without
//! clearing the accumulator. Invalidate the cursor after collection exhaustion.
//! Deviations: Ghidra's extra arguments are saved registers used as stack
//! locals, not inputs. Host cursor and vtable pointers use native widths;
//! geometry and embedded collection offsets remain target-exact.

use crate::app::registry::object_cast_to_class;
use crate::ui::container_view::{container_view_children, ContainerView};
use crate::ui::rect::{rect_union, Rect};
use crate::ui::shown_state::ui_element_is_shown;
use crate::util::cursor::{cursor_init, cursor_advance, cursor_invalidate, Cursor};

/// # Safety
/// `owner` has a writable aligned Rect at +0xa8. `container` has a valid
/// child collection. Each child has a framework vtable, flags at +0x48,
/// and an aligned Rect at +0x80. Callbacks must preserve these objects.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn shown_children_primary_bounds_union(owner: *mut u8, container: *mut ContainerView) {
    let mut cursor = Cursor { collection: core::ptr::null_mut(), index: 0 };
    cursor_init(&mut cursor, container_view_children(container).cast());
    let mut child: *mut u8 = core::ptr::null_mut();
    while cursor_advance(&mut cursor, core::ptr::addr_of_mut!(child).cast()) != 0 {
        if ui_element_is_shown(child) != 0
            && object_cast_to_class(child.cast(), 0x1280).is_null()
        {
            rect_union(owner.add(0xa8).cast::<Rect>(), child.add(0x80).cast::<Rect>());
        }
    }
    cursor_invalidate(&mut cursor);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::registry::{FrameworkObject, FrameworkObjectVtable};
    use crate::util::cursor::{Collection, CollectionVtable};

    #[repr(C)]
    struct Child {
        vtable: *const FrameworkObjectVtable,
        padding: [u8; 0x48 - core::mem::size_of::<usize>()],
        flags: u32,
        rest: [u8; 0x34],
        bounds: Rect,
        excluded: bool,
        casts: u32,
    }
    unsafe extern "C" fn cast(object: *mut FrameworkObject, class: u32) -> *mut u8 {
        assert_eq!(class, 0x1280);
        let child = &mut *object.cast::<Child>();
        child.casts += 1;
        if child.excluded { object.cast() } else { core::ptr::null_mut() }
    }
    static CHILD_VTABLE: FrameworkObjectVtable = FrameworkObjectVtable {
        unresolved_00: [0; 5], cast_to_class: cast,
    };
    #[repr(C)]
    struct Children {
        vtable: *const CollectionVtable,
        items: [*mut u8; 5],
        count: usize,
        next: i32,
    }
    unsafe extern "C" fn item_at(collection: *mut Collection, index: i32, out: *mut u8) -> u32 {
        let children = &mut *collection.cast::<Children>();
        assert_eq!(index, children.next);
        children.next += 1;
        if index as usize >= children.count { return 0; }
        out.cast::<*mut u8>().write(children.items[index as usize]);
        1
    }
    static COLLECTION_VTABLE: CollectionVtable = CollectionVtable {
        unresolved: [0; 15], item_at,
    };
    #[repr(C)]
    struct Container {
        prefix: [usize; 0xa8 / core::mem::size_of::<usize>()],
        children: Children,
    }
    fn rect(top: i32, left: i32, bottom: i32, right: i32) -> Rect {
        Rect { top, left, bottom, right }
    }
    fn child(flags: u32, excluded: bool, bounds: Rect) -> Child {
        Child { vtable: &CHILD_VTABLE, padding: [0; 0x48 - core::mem::size_of::<usize>()],
            flags, rest: [0; 0x34], bounds, excluded, casts: 0 }
    }
    #[test]
    fn filters_children_and_preserves_existing_accumulator_and_neighbors() {
        unsafe {
            let mut children = [
                child(0, false, rect(-300, -300, 300, 300)),
                child(0x800, true, rect(-200, -200, 200, 200)),
                child(0x800, false, rect(2, 3, 8, 9)),
                child(0x800, false, rect(-4, -5, 4, 5)),
                child(0x800, false, rect(-100, -100, -100, 100)),
            ];
            let mut container = Container { prefix: [0; 0xa8 / core::mem::size_of::<usize>()],
                children: Children { vtable: &COLLECTION_VTABLE,
                    items: children.each_mut().map(|c| (c as *mut Child).cast()), count: 5, next: 0 } };
            let mut owner = [0x13579bdfu32; 0xc8 / 4];
            let bounds = owner.as_mut_ptr().cast::<u8>().add(0xa8).cast::<Rect>();
            let seed = rect(1, 1, 20, 30);
            bounds.write(seed);
            shown_children_primary_bounds_union(owner.as_mut_ptr().cast(), (&mut container as *mut Container).cast());
            assert_eq!(bounds.read(), rect(-4, -5, 20, 30));
            assert_eq!(children.each_ref().map(|c| c.casts), [0, 1, 1, 1, 1]);
            assert_eq!(container.children.next, 6);
            assert!(owner[..0xa8 / 4].iter().all(|&v| v == 0x13579bdf));
            assert!(owner[0xb8 / 4..].iter().all(|&v| v == 0x13579bdf));

            container.children.count = 0;
            container.children.next = 0;
            bounds.write(seed);
            shown_children_primary_bounds_union(owner.as_mut_ptr().cast(), (&mut container as *mut Container).cast());
            assert_eq!(bounds.read(), seed);
            assert_eq!(container.children.next, 1);

            container.children.items[0] = (&mut children[2] as *mut Child).cast();
            container.children.count = 1;
            container.children.next = 0;
            bounds.write(Rect::default());
            shown_children_primary_bounds_union(owner.as_mut_ptr().cast(), (&mut container as *mut Container).cast());
            assert_eq!(bounds.read(), rect(2, 3, 8, 9));
        }
    }
}
