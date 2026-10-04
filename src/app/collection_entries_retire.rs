//! Retire collection entries — FUN_08211d34 @ 0x08211d34.
//! Raw extent: 152 bytes, ending at the next prologue at 0x08211dcc.
//! Seven outbound plain BLs, zero predicated BLs; two inbound plain BLs.
//! Walk the group's collection at +8. If entry +8 and context +0x72 are
//! both zero, activate the entry through 0x08211bac. Otherwise assign an
//! empty refcounted handle to entry +4, release the temporary, and set
//! entry +9 to 2. The context flag is read afresh for each eligible entry.
//! Deviations: typed pointer fields widen on hosts; unused saved-register
//! return values are omitted (both raw callers ignore them). Only the
//! unported activation helper uses a fixed-address call / host seam.

use crate::util::cursor::{Collection, Cursor, cursor_init, cursor_advance, cursor_invalidate};
use crate::cxx::handle::{RefcountedBody, refcounted_ptr_construct_tertiary_variant,
    refcounted_ptr_copy_assign_retain_count, refcounted_body_release_retain_count};

#[repr(C)]
pub struct EntryGroup {
    pub unresolved: [u32; 2],
    pub entries: Collection,
}

#[repr(C)]
pub struct RetirableEntry {
    pub unresolved: u32,
    pub handle: *mut RefcountedBody,
    pub retire_requested: u8,
    pub state: u8,
}

#[cfg(target_pointer_width = "32")]
const _: () = {
    assert!(core::mem::offset_of!(EntryGroup, entries) == 8);
    assert!(core::mem::offset_of!(RetirableEntry, handle) == 4);
    assert!(core::mem::offset_of!(RetirableEntry, retire_requested) == 8);
    assert!(core::mem::offset_of!(RetirableEntry, state) == 9);
};

pub type ActivateEntry = unsafe extern "C" fn(*mut u8, *mut RetirableEntry);
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_activate_entry(_: *mut u8, _: *mut RetirableEntry) {
    panic!("entry activation requires a host implementation")
}
#[cfg(not(target_os = "none"))]
pub static mut ACTIVATE_ENTRY: ActivateEntry = missing_activate_entry;

#[inline(always)]
unsafe fn activate_entry(context: *mut u8, entry: *mut RetirableEntry) {
    #[cfg(target_os = "none")]
    {
        let activate: ActivateEntry = core::mem::transmute(0x0821_1bacusize);
        activate(context, entry);
    }
    #[cfg(not(target_os = "none"))]
    core::ptr::read_volatile(core::ptr::addr_of!(ACTIVATE_ENTRY))(context, entry);
}

/// # Safety
/// `context` exposes a live flag at +0x72; `group` exposes a collection
/// yielding valid mutable entries. Handles and activation satisfy their
/// respective callee contracts. No NULL guards exist in the original.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn collection_entries_retire(context: *mut u8, group: *mut EntryGroup) {
    let mut cursor = Cursor { collection: core::ptr::null_mut(), index: 0 };
    cursor_init(&mut cursor, core::ptr::addr_of_mut!((*group).entries));
    let mut entry: *mut RetirableEntry = core::ptr::null_mut();
    while cursor_advance(&mut cursor, core::ptr::addr_of_mut!(entry).cast()) != 0 {
        if (*entry).retire_requested == 0 && context.add(0x72).read() == 0 {
            activate_entry(context, entry);
        } else {
            let mut empty = core::ptr::null_mut();
            let source = refcounted_ptr_construct_tertiary_variant(&mut empty, 0, 0);
            refcounted_ptr_copy_assign_retain_count(core::ptr::addr_of_mut!((*entry).handle), source);
            refcounted_body_release_retain_count(&mut empty);
            (*entry).state = 2;
        }
    }
    cursor_invalidate(&mut cursor);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::cursor::CollectionVtable;
    static LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
    #[repr(C)]
    struct Fixture {
        group: EntryGroup,
        entries: [RetirableEntry; 3],
        count: usize,
    }
    unsafe extern "C" fn item_at(collection: *mut Collection, index: i32, out: *mut u8) -> u32 {
        let fixture = collection.cast::<u8>().sub(core::mem::offset_of!(EntryGroup, entries)).cast::<Fixture>();
        if index < 0 || index as usize >= (*fixture).count { return 0; }
        out.cast::<*mut RetirableEntry>().write(core::ptr::addr_of_mut!((*fixture).entries[index as usize]));
        1
    }
    unsafe extern "C" fn activate(context: *mut u8, entry: *mut RetirableEntry) {
        (*entry).state = 1;
        // Activation may change the context: subsequent entries must see it.
        context.add(0x72).write(1);
    }
    #[test]
    fn empty_mixed_and_forced_retirement() {
        let _lock = LOCK.lock();
        unsafe {
            let old = ACTIVATE_ENTRY;
            ACTIVATE_ENTRY = activate;
            let vtable = CollectionVtable { unresolved: [0; 15], item_at };
            for count in [0, 3] {
                for forced in [0, 1] {
                    let mut bodies = core::array::from_fn::<_, 3, _>(|_| RefcountedBody {
                        opaque0: 0, refcount: 2, mutex: core::ptr::null_mut(),
                    });
                    let mut fixture = Fixture {
                        group: EntryGroup { unresolved: [0; 2], entries: Collection { vtable: &vtable } },
                        entries: core::array::from_fn(|i| RetirableEntry {
                            unresolved: 0xfeed, handle: &mut bodies[i], retire_requested: if i == 2 { 7 } else { 0 }, state: 9,
                        }), count,
                    };
                    let mut context = [0u8; 0x73];
                    context[0x72] = forced;
                    collection_entries_retire(context.as_mut_ptr(), &mut fixture.group);
                    for i in 0..3 {
                        let retired = count != 0 && (forced != 0 || i != 0);
                        assert_eq!(bodies[i].refcount, if retired { 1 } else { 2 });
                        assert_eq!(fixture.entries[i].handle.is_null(), retired);
                        assert_eq!(fixture.entries[i].state, if retired { 2 } else if count != 0 { 1 } else { 9 });
                        assert_eq!(fixture.entries[i].unresolved, 0xfeed);
                    }
                }
            }
            ACTIVATE_ENTRY = old;
        }
    }
}
