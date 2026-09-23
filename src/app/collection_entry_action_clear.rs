//! Collection entry action dispatch and owner state clear.

use core::ptr;

/// collection_entry_action_clear — original: `FUN_08130134` @ 0x08130134 (92
/// bytes exactly, 0x08130134..0x08130190; the following `push {r4-r8,lr}`
/// opens the next function).
///
/// Raw ARM has 3 plain direct `bl` callers and 0 predicated direct `bl`
/// callers. Its body constructs a 20-byte iterator over `owner + 0x18` at
/// position -2, calls each yielded entry's vtable +0x180 action, drops the
/// iterator, and clears the byte at `owner + 0x70`. The body has two direct
/// calls to the established iterator seams and one unconditional indirect
/// `blx` dispatch.
///
/// Deliberate deviations: Rust zero-initializes the iterator local instead of
/// retaining ARM's uninitialized stack bytes; the iterator constructor owns
/// every field read during real traversal. Host dispatch uses a native-width
/// vtable so test function pointers are not truncated; target dispatch reads
/// the target's four-byte vtable and slot words.
///
/// # Safety
///
/// `owner + 0x18` must be a valid iterator owner. Every yielded entry must
/// contain a valid vtable with a callable +0x180 action slot, as in retailOS.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn collection_entry_action_clear(owner: *mut u8) {
    let mut iterator = [0u32; 5];
    crate::app::vtable_set::iterator_state_construct(iterator.as_mut_ptr(), owner.add(0x18), -2);

    let mut entry = ptr::null_mut::<u8>();
    while crate::app::vtable_set::iterator_state_next(
        iterator.as_mut_ptr(),
        ptr::addr_of_mut!(entry).cast(),
    ) != 0 {
        entry_action(entry);
    }

    crate::app::vtable_set::iterator_state_cleanup(iterator.as_mut_ptr());
    owner.add(0x70).write(0);
}

#[cfg(target_os = "none")]
unsafe fn entry_action(entry: *mut u8) {
    let vtable = entry.cast::<u32>().read() as usize as *const u32;
    let action: unsafe extern "C" fn(*mut u8) = core::mem::transmute(vtable.add(0x180 / 4).read());
    action(entry);
}

#[cfg(not(target_os = "none"))]
unsafe fn entry_action(entry: *mut u8) {
    let vtable = entry.cast::<*const EntryVtable>().read();
    ((*vtable).action)(entry);
}

#[cfg(not(target_os = "none"))]
#[repr(C)]
struct EntryVtable {
    _slots_before_action: [usize; 0x180 / 4],
    action: unsafe extern "C" fn(*mut u8),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::vtable_set::{tests::{SLOT_TEST_LOCK, SlotGuard}, ITERATOR_STATE_FETCH};
    use crate::testing::{hints, try_map_u32_slab};

    static mut SCRIPT: [*mut u8; 3] = [ptr::null_mut(); 3];
    static mut SCRIPT_INDEX: usize = 0;
    static mut EVENTS: [u8; 2] = [0; 2];
    static mut EVENT_COUNT: usize = 0;

    unsafe extern "C" fn scripted_fetch(_state: *mut u32, out: *mut u8) -> u32 {
        let entry = SCRIPT[SCRIPT_INDEX];
        SCRIPT_INDEX += 1;
        if entry.is_null() { return 0; }
        out.cast::<*mut u8>().write(entry);
        1
    }

    unsafe extern "C" fn record_first_action(_entry: *mut u8) {
        EVENTS[EVENT_COUNT] = 1;
        EVENT_COUNT += 1;
    }

    unsafe extern "C" fn record_second_action(_entry: *mut u8) {
        EVENTS[EVENT_COUNT] = 2;
        EVENT_COUNT += 1;
    }

    #[repr(C)]
    struct Entry { vtable: *const EntryVtable }

    #[test]
    fn collection_entry_action_clear_dispatches_every_entry_and_clears_owner_byte() {
        let Some(owner) = try_map_u32_slab(hints::COLLECTION_ENTRY_ACTION_CLEAR, 0x1000) else { return; };
        let _lock = SLOT_TEST_LOCK.lock();
        let _restore = SlotGuard;
        let fetch = unsafe { ptr::read_volatile(ptr::addr_of!(ITERATOR_STATE_FETCH)) };
        let first_vtable = EntryVtable { _slots_before_action: [0; 0x180 / 4], action: record_first_action };
        let second_vtable = EntryVtable { _slots_before_action: [0; 0x180 / 4], action: record_second_action };
        let mut first = Entry { vtable: &first_vtable };
        let mut second = Entry { vtable: &second_vtable };
        unsafe {
            SCRIPT = [ptr::addr_of_mut!(first).cast(), ptr::addr_of_mut!(second).cast(), ptr::null_mut()];
            SCRIPT_INDEX = 0;
            EVENTS = [0; 2];
            EVENT_COUNT = 0;
            ptr::addr_of_mut!(ITERATOR_STATE_FETCH).write_volatile(scripted_fetch);
            ptr::write_bytes(owner, 0, 0x1000);
            owner.add(0x70).write(0xff);
            collection_entry_action_clear(owner);
            assert_eq!(&EVENTS[..EVENT_COUNT], &[1, 2]);
            assert_eq!(owner.add(0x70).read(), 0);
            ptr::addr_of_mut!(ITERATOR_STATE_FETCH).write_volatile(fetch);
        }
    }

    #[test]
    fn collection_entry_action_clear_clears_owner_byte_for_an_empty_collection() {
        let _lock = SLOT_TEST_LOCK.lock();
        let _restore = SlotGuard;
        let Some(owner) = try_map_u32_slab(hints::COLLECTION_ENTRY_ACTION_CLEAR, 0x1000) else { return; };
        let fetch = unsafe { ptr::read_volatile(ptr::addr_of!(ITERATOR_STATE_FETCH)) };
        unsafe {
            SCRIPT = [ptr::null_mut(); 3];
            SCRIPT_INDEX = 0;
            ptr::addr_of_mut!(ITERATOR_STATE_FETCH).write_volatile(scripted_fetch);
            ptr::write_bytes(owner, 0, 0x1000);
            owner.add(0x70).write(1);
            collection_entry_action_clear(owner);
            assert_eq!(owner.add(0x70).read(), 0);
            ptr::addr_of_mut!(ITERATOR_STATE_FETCH).write_volatile(fetch);
        }
    }
}
