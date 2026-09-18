//! Collection entry teardown and owner finalization.

use core::ptr;

/// Unported direct tail of [`collection_entry_teardown`], `FUN_0826d48c` @
/// 0x0826d48c. Its only established contract here is `fn(owner)`.
pub static mut COLLECTION_OWNER_FINALIZE: unsafe extern "C" fn(owner: *mut u8) =
    collection_owner_finalize_unported;

unsafe extern "C" fn collection_owner_finalize_unported(_owner: *mut u8) {}

/// collection_entry_teardown — original: `FUN_0815770c` @ 0x0815770c (92
/// bytes exactly, 0x0815770c..0x08157768; the following `push {r1,r2,r3,lr}`
/// opens the next function).
///
/// Raw ARM contains 4 plain direct `bl` instructions, 0 predicated direct
/// `bl` instructions, and one unconditional indirect `blx` through each
/// yielded entry's vtable slot +0x94. It constructs a 20-byte iterator over
/// `owner + 0xa8` at position -2, dispatches that slot for every yielded
/// entry, drops the iterator, then calls `FUN_0826d48c(owner)`.
///
/// Deliberate deviations: Rust zero-initializes the iterator local instead of
/// retaining ARM's uninitialized stack bytes; the iterator constructor owns
/// every field read on a real collection traversal. The unresolved final
/// direct callee remains the named [`COLLECTION_OWNER_FINALIZE`] address
/// boundary; its identity is not inferred from this sole call site. Host
/// dispatch uses a native-width vtable so test function pointers are not
/// truncated; target dispatch reads the target's four-byte vtable and slot
/// words.
///
/// # Safety
///
/// `owner + 0xa8` must be a valid iterator owner. Every yielded entry must
/// contain a valid vtable with a callable +0x94 slot, exactly as retailOS.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn collection_entry_teardown(owner: *mut u8) {
    let mut iterator = [0u32; 5];
    crate::app::vtable_set::iterator_state_construct(iterator.as_mut_ptr(), owner.add(0xa8), -2);

    let mut entry = ptr::null_mut::<u8>();
    while crate::app::vtable_set::iterator_state_next(
        iterator.as_mut_ptr(),
        ptr::addr_of_mut!(entry).cast(),
    ) != 0 {
        entry_teardown(entry);
    }

    crate::app::vtable_set::iterator_state_cleanup(iterator.as_mut_ptr());
    let finalize = ptr::read_volatile(ptr::addr_of!(COLLECTION_OWNER_FINALIZE));
    finalize(owner);
}

#[cfg(target_os = "none")]
unsafe fn entry_teardown(entry: *mut u8) {
    let vtable = (entry.cast::<u32>()).read() as usize as *const u32;
    let teardown: unsafe extern "C" fn(*mut u8) = core::mem::transmute(vtable.add(0x94 / 4).read());
    teardown(entry);
}

#[cfg(not(target_os = "none"))]
unsafe fn entry_teardown(entry: *mut u8) {
    let vtable = (entry.cast::<*const EntryVtable>()).read();
    ((*vtable).teardown)(entry);
}

#[cfg(not(target_os = "none"))]
#[repr(C)]
struct EntryVtable {
    _slots_before_teardown: [usize; 0x94 / 4],
    teardown: unsafe extern "C" fn(*mut u8),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::vtable_set::{tests::{SLOT_TEST_LOCK, SlotGuard}, ITERATOR_STATE_FETCH};
    use crate::testing::{hints, try_map_u32_slab};

    static mut SCRIPT: [*mut u8; 3] = [ptr::null_mut(); 3];
    static mut SCRIPT_INDEX: usize = 0;
    static mut EVENTS: [u8; 4] = [0; 4];
    static mut EVENT_COUNT: usize = 0;

    unsafe extern "C" fn scripted_fetch(_state: *mut u32, out: *mut u8) -> u32 {
        let entry = SCRIPT[SCRIPT_INDEX];
        SCRIPT_INDEX += 1;
        if entry.is_null() { return 0; }
        out.cast::<*mut u8>().write(entry);
        1
    }

    unsafe extern "C" fn record_teardown_first(_entry: *mut u8) {
        EVENTS[EVENT_COUNT] = 1;
        EVENT_COUNT += 1;
    }

    unsafe extern "C" fn record_teardown_second(_entry: *mut u8) {
        EVENTS[EVENT_COUNT] = 2;
        EVENT_COUNT += 1;
    }

    unsafe extern "C" fn record_finalize(_owner: *mut u8) {
        EVENTS[EVENT_COUNT] = 3;
        EVENT_COUNT += 1;
    }

    #[repr(C)]
    struct Entry { vtable: *const EntryVtable }

    struct SeamGuard {
        fetch: unsafe extern "C" fn(*mut u32, *mut u8) -> u32,
        finalize: unsafe extern "C" fn(*mut u8),
    }

    impl Drop for SeamGuard {
        fn drop(&mut self) {
            unsafe {
                ptr::addr_of_mut!(ITERATOR_STATE_FETCH).write_volatile(self.fetch);
                ptr::addr_of_mut!(COLLECTION_OWNER_FINALIZE).write_volatile(self.finalize);
            }
        }
    }


    #[test]
    fn collection_entry_teardown_dispatches_every_entry_before_finalizing_owner() {
        let Some(owner) = try_map_u32_slab(hints::COLLECTION_ENTRY_TEARDOWN, 0x1000) else { return; };
        let _lock = SLOT_TEST_LOCK.lock();
        let _restore = SlotGuard;
        let _seams = unsafe {
            SeamGuard {
                fetch: ptr::read_volatile(ptr::addr_of!(ITERATOR_STATE_FETCH)),
                finalize: ptr::read_volatile(ptr::addr_of!(COLLECTION_OWNER_FINALIZE)),
            }
        };
        let first_vtable = EntryVtable { _slots_before_teardown: [0; 0x94 / 4], teardown: record_teardown_first };
        let second_vtable = EntryVtable { _slots_before_teardown: [0; 0x94 / 4], teardown: record_teardown_second };
        let mut first = Entry { vtable: &first_vtable };
        let mut second = Entry { vtable: &second_vtable };
        unsafe {
            SCRIPT = [ptr::addr_of_mut!(first).cast(), ptr::addr_of_mut!(second).cast(), ptr::null_mut()];
            SCRIPT_INDEX = 0;
            EVENTS = [0; 4];
            EVENT_COUNT = 0;
            ptr::addr_of_mut!(ITERATOR_STATE_FETCH).write_volatile(scripted_fetch);
            ptr::addr_of_mut!(COLLECTION_OWNER_FINALIZE).write_volatile(record_finalize);
            ptr::write_bytes(owner, 0, 0x1000);
            collection_entry_teardown(owner);
            assert_eq!(&EVENTS[..EVENT_COUNT], &[1, 2, 3]);
        }
    }

    #[test]
    fn collection_entry_teardown_finalizes_an_empty_collection() {
        let Some(owner) = try_map_u32_slab(hints::COLLECTION_ENTRY_TEARDOWN, 0x1000) else { return; };
        let _lock = SLOT_TEST_LOCK.lock();
        let _restore = SlotGuard;
        let _seams = unsafe {
            SeamGuard {
                fetch: ptr::read_volatile(ptr::addr_of!(ITERATOR_STATE_FETCH)),
                finalize: ptr::read_volatile(ptr::addr_of!(COLLECTION_OWNER_FINALIZE)),
            }
        };
        unsafe {
            SCRIPT = [ptr::null_mut(); 3];
            SCRIPT_INDEX = 0;
            EVENTS = [0; 4];
            EVENT_COUNT = 0;
            ptr::addr_of_mut!(ITERATOR_STATE_FETCH).write_volatile(scripted_fetch);
            ptr::addr_of_mut!(COLLECTION_OWNER_FINALIZE).write_volatile(record_finalize);
            ptr::write_bytes(owner, 0, 0x1000);
            collection_entry_teardown(owner);
            assert_eq!(&EVENTS[..EVENT_COUNT], &[3]);
        }
    }
}
