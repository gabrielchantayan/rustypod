//! Child shown-state synchronization — FUN_081584f0 @ 0x081584f0.
//!
//! True extent: 208 bytes, [0x081584f0, 0x081585c0), followed by a new
//! PUSH prologue. Raw A32: two plain incoming BLs, no predicated incoming
//! BLs; ten plain outgoing BLs, no predicated BLs, two indirect BLX sites.
//! Normalize request to 0/1. Activation synchronizes the owner first, then
//! tests its shown state and walks its embedded collection at +0xa8,
//! calling each child's vtable slot +0xa4. Deactivation tests/walks first,
//! then synchronizes the owner. The shown test is not repeated during a walk.
//! Deviations: discard Ghidra's spurious third/fourth arguments (saved
//! stack words); merge duplicate loops. Host collection/vtable entries use
//! native pointer widths; element vtable words retain target u32 width.

use super::shown_state::ui_element_is_shown;
use super::view_base::ViewBase;
use super::view_transition_sync::view_sync_transition_mode;
use crate::util::cursor::{Collection, Cursor, cursor_init, cursor_advance, cursor_invalidate};

#[repr(C)]
pub struct ChildTransitionVtable {
    pub preceding_slots: [usize; 41],
    pub synchronize: unsafe extern "C" fn(*mut u8, u32),
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 0xa4] = [0; core::mem::offset_of!(ChildTransitionVtable, synchronize)];

/// # Safety
/// `view` satisfies view_sync_transition_mode's contract and has a valid
/// aligned Collection at +0xa8 whenever shown. Yielded children have a u32
/// vtable word pointing to a valid ChildTransitionVtable. Callbacks must
/// preserve the owner, collection, and subsequent children for the walk.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn view_sync_children_transition(view: *mut ViewBase, request: u32) {
    let active = (request != 0) as u32;
    if active != 0 { view_sync_transition_mode(view, 1); }
    if ui_element_is_shown(view.cast()) != 0 {
        let mut cursor = Cursor { collection: core::ptr::null_mut(), index: 0 };
        cursor_init(&mut cursor, view.cast::<u8>().add(0xa8).cast::<Collection>());
        let mut child: *mut u8 = core::ptr::null_mut();
        while cursor_advance(&mut cursor, core::ptr::addr_of_mut!(child).cast()) != 0 {
            let table = child.cast::<u32>().read() as usize as *const ChildTransitionVtable;
            ((*table).synchronize)(child, active);
        }
        cursor_invalidate(&mut cursor);
    }
    if active == 0 { view_sync_transition_mode(view, 0); }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::util::cursor::CollectionVtable;
    use super::super::view_transition_sync::ViewTransitionVtable;
    use std::vec::Vec;

    #[repr(C)]
    struct Children {
        table: *const CollectionVtable,
        items: [*mut u8; 2],
        count: usize,
        fetches: usize,
    }
    #[repr(C)]
    struct Child {
        table: u32,
        id: u32,
        owner: *mut ViewBase,
        log: *mut Vec<(u32, u32, u32)>,
        mutate: bool,
    }
    unsafe extern "C" fn fetch(collection: *mut Collection, index: i32, out: *mut u8) -> u32 {
        let children = &mut *collection.cast::<Children>();
        assert_eq!(index as usize, children.fetches);
        children.fetches += 1;
        if index as usize == children.count { return 0; }
        out.cast::<*mut u8>().write(children.items[index as usize]);
        7
    }
    unsafe extern "C" fn child_changed(child: *mut u8, active: u32) {
        let child = &mut *child.cast::<Child>();
        (*child.log).push((child.id, active, (*child.owner).flags & 0x1800));
        if child.mutate { (*child.owner).flags = ((*child.owner).flags & !0x1800) | 0x1000; }
    }
    unsafe extern "C" fn owner_changed(owner: *mut ViewBase, active: u32) {
        let log = owner.cast::<u8>().add(0x200).cast::<*mut Vec<(u32, u32, u32)>>().read();
        (*log).push((99, active, (*owner).flags & 0x1800));
    }
    static COLLECTION_TABLE: CollectionVtable = CollectionVtable { unresolved: [0; 15], item_at: fetch };

    #[test]
    fn ordering_normalization_empty_hidden_and_callback_mutation() {
        let Some(slab) = crate::testing::try_map_u32_slab(crate::testing::hints::VIEW_CHILDREN_SYNC, 4096) else { return; };
        unsafe {
            let owner = slab.cast::<ViewBase>();
            let parent = slab.add(0x300).cast::<ViewBase>();
            let owner_table = slab.add(0x500).cast::<ViewTransitionVtable>();
            let child_table = slab.add(0x800).cast::<ChildTransitionVtable>();
            owner_table.write(ViewTransitionVtable { preceding_slots: [0; 42], shown_changed: owner_changed });
            child_table.write(ChildTransitionVtable { preceding_slots: [0; 41], synchronize: child_changed });
            (*owner).vtable = owner_table as usize as u32;
            slab.add(0xa0).write(1); // Real invalidation's documented suppression flag.
            owner.cast::<u32>().add(13).write(parent as usize as u32);
            let collection = slab.add(0xa8).cast::<Children>();
            let mut log = Vec::new();
            slab.add(0x200).cast::<*mut Vec<(u32, u32, u32)>>().write(&mut log);
            let mut children = [
                Child { table: child_table as usize as u32, id: 0, owner, log: &mut log, mutate: false },
                Child { table: child_table as usize as u32, id: 1, owner, log: &mut log, mutate: false },
            ];
            for mode in [0, 0x800, 0x1000, 0x1800] {
                for parent_mode in [0x800, 0x1000] {
                    for request in [0, 1, 2, u32::MAX] {
                        for count in [0, 2] {
                            for mutate in [false, true] {
                                log.clear();
                                children[0].mutate = mutate;
                                (*owner).flags = 0x4000_0000 | mode;
                                (*parent).flags = parent_mode;
                                collection.write(Children { table: &COLLECTION_TABLE,
                                    items: children.each_mut().map(|c| (c as *mut Child).cast()), count, fetches: 0 });
                                let active = (request != 0) as u32;
                                let mut expected = Vec::new();
                                let mut resulting = mode;
                                if active != 0 && mode == 0x1800 {
                                    resulting = if parent_mode == 0x800 { 0x800 } else { 0x1000 };
                                    if resulting == 0x800 { expected.push((99, 1, 0x800)); }
                                }
                                let walked = resulting == 0x800;
                                if walked {
                                    for id in 0..count {
                                        expected.push((id as u32, active, resulting));
                                        if id == 0 && mutate { resulting = 0x1000; }
                                    }
                                }
                                if active == 0 {
                                    if resulting == 0x800 { expected.push((99, 0, 0x1800)); }
                                    resulting = 0x1800;
                                }
                                view_sync_children_transition(owner, request);
                                assert_eq!(log, expected, "mode={mode:x}, parent={parent_mode:x}, request={request}, count={count}, mutate={mutate}");
                                assert_eq!((*owner).flags, 0x4000_0000 | resulting);
                                assert_eq!((*collection).fetches, if walked { count + 1 } else { 0 });
                                assert_eq!((*parent).flags, parent_mode);
                            }
                        }
                    }
                }
            }
        }
    }
}
