//! Collection eligibility count.

use core::ptr;

/// collection_count_eligible_entries — original: `FUN_08130090` @ 0x08130090
/// (156 bytes exactly, 0x08130090..0x0813012c: 152 bytes of instructions plus
/// its trailing threshold literal; the veneer at 0x0813012c is a distinct
/// function boundary).
///
/// Raw ARM has 3 plain direct `bl` callers and 0 predicated direct `bl`
/// callers. The body constructs a 20-byte iterator over `owner + 0x18` at
/// position -2. For each yielded entry, it calls vtable +0x178; a nonzero
/// result below 0x69780 counts, while a zero result counts only if vtable
/// +0xc4 returns nonzero. It drops the iterator before returning.
///
/// Deliberate deviations: Rust zero-initializes the iterator local instead of
/// retaining ARM's uninitialized stack bytes; its constructor owns every
/// field later read. Host dispatch uses a native-width vtable so test function
/// pointers are not truncated; target dispatch reads four-byte vtable words
/// at the retailOS slots.
///
/// # Safety
///
/// `owner + 0x18` must be a valid iterator owner. Every yielded entry must
/// contain a valid vtable with callable +0xc4 and +0x178 slots.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn collection_count_eligible_entries(owner: *mut u8, count_out: *mut u32) {
    count_out.write(0);
    let mut iterator = [0u32; 5];
    crate::app::vtable_set::iterator_state_construct(iterator.as_mut_ptr(), owner.add(0x18), -2);

    let mut entry = ptr::null_mut::<u8>();
    while crate::app::vtable_set::iterator_state_next(
        iterator.as_mut_ptr(),
        ptr::addr_of_mut!(entry).cast(),
    ) != 0 {
        let target = entry_current_target(entry);
        if (target != 0 && target < 0x69780) || (target == 0 && entry_is_eligible(entry) != 0) {
            count_out.write(count_out.read() + 1);
        }
    }

    crate::app::vtable_set::iterator_state_cleanup(iterator.as_mut_ptr());
}

#[cfg(target_os = "none")]
unsafe fn entry_current_target(entry: *mut u8) -> u32 {
    let vtable = entry.cast::<u32>().read() as usize as *const u32;
    let current_target: unsafe extern "C" fn(*mut u8) -> u32 =
        core::mem::transmute(vtable.add(0x178 / 4).read());
    current_target(entry)
}

#[cfg(not(target_os = "none"))]
unsafe fn entry_current_target(entry: *mut u8) -> u32 {
    let vtable = entry.cast::<*const EntryVtable>().read();
    ((*vtable).current_target)(entry)
}

#[cfg(target_os = "none")]
unsafe fn entry_is_eligible(entry: *mut u8) -> u32 {
    let vtable = entry.cast::<u32>().read() as usize as *const u32;
    let is_eligible: unsafe extern "C" fn(*mut u8) -> u32 =
        core::mem::transmute(vtable.add(0xc4 / 4).read());
    is_eligible(entry)
}

#[cfg(not(target_os = "none"))]
unsafe fn entry_is_eligible(entry: *mut u8) -> u32 {
    let vtable = entry.cast::<*const EntryVtable>().read();
    ((*vtable).is_eligible)(entry)
}

#[cfg(not(target_os = "none"))]
#[repr(C)]
struct EntryVtable {
    _slots_before_is_eligible: [usize; 0xc4 / 4],
    is_eligible: unsafe extern "C" fn(*mut u8) -> u32,
    _slots_between: [usize; (0x178 - 0xc8) / 4],
    current_target: unsafe extern "C" fn(*mut u8) -> u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::vtable_set::{tests::{SLOT_TEST_LOCK, SlotGuard}, ITERATOR_STATE_FETCH};
    use crate::testing::{hints, try_map_u32_slab};

    static mut SCRIPT: [*mut u8; 5] = [ptr::null_mut(); 5];
    static mut SCRIPT_INDEX: usize = 0;
    static mut CURRENT_CALLS: usize = 0;
    static mut ELIGIBILITY_CALLS: usize = 0;

    unsafe extern "C" fn scripted_fetch(_state: *mut u32, out: *mut u8) -> u32 {
        let entry = SCRIPT[SCRIPT_INDEX];
        SCRIPT_INDEX += 1;
        if entry.is_null() { return 0; }
        out.cast::<*mut u8>().write(entry);
        1
    }

    unsafe extern "C" fn current_below_threshold(_entry: *mut u8) -> u32 {
        CURRENT_CALLS += 1;
        0x6977f
    }

    unsafe extern "C" fn current_at_threshold(_entry: *mut u8) -> u32 {
        CURRENT_CALLS += 1;
        0x69780
    }

    unsafe extern "C" fn current_none(_entry: *mut u8) -> u32 {
        CURRENT_CALLS += 1;
        0
    }

    unsafe extern "C" fn eligible(_entry: *mut u8) -> u32 {
        ELIGIBILITY_CALLS += 1;
        1
    }

    unsafe extern "C" fn ineligible(_entry: *mut u8) -> u32 {
        ELIGIBILITY_CALLS += 1;
        0
    }

    #[repr(C)]
    struct Entry { vtable: *const EntryVtable }

    fn vtable(current_target: unsafe extern "C" fn(*mut u8) -> u32, is_eligible: unsafe extern "C" fn(*mut u8) -> u32) -> EntryVtable {
        EntryVtable {
            _slots_before_is_eligible: [0; 0xc4 / 4],
            is_eligible,
            _slots_between: [0; (0x178 - 0xc8) / 4],
            current_target,
        }
    }

    #[test]
    fn collection_count_eligible_entries_applies_target_and_fallback_rules() {
        let Some(owner) = try_map_u32_slab(hints::COLLECTION_COUNT_ELIGIBLE_ENTRIES, 0x1000) else { return; };
        let _lock = SLOT_TEST_LOCK.lock();
        let _restore = SlotGuard;
        let fetch = unsafe { ptr::read_volatile(ptr::addr_of!(ITERATOR_STATE_FETCH)) };
        let below_vtable = vtable(current_below_threshold, ineligible);
        let at_vtable = vtable(current_at_threshold, eligible);
        let fallback_yes_vtable = vtable(current_none, eligible);
        let fallback_no_vtable = vtable(current_none, ineligible);
        let mut below = Entry { vtable: &below_vtable };
        let mut at = Entry { vtable: &at_vtable };
        let mut fallback_yes = Entry { vtable: &fallback_yes_vtable };
        let mut fallback_no = Entry { vtable: &fallback_no_vtable };
        let mut count = u32::MAX;
        unsafe {
            SCRIPT = [ptr::addr_of_mut!(below).cast(), ptr::addr_of_mut!(at).cast(), ptr::addr_of_mut!(fallback_yes).cast(), ptr::addr_of_mut!(fallback_no).cast(), ptr::null_mut()];
            SCRIPT_INDEX = 0;
            CURRENT_CALLS = 0;
            ELIGIBILITY_CALLS = 0;
            ptr::addr_of_mut!(ITERATOR_STATE_FETCH).write_volatile(scripted_fetch);
            ptr::write_bytes(owner, 0, 0x1000);
            collection_count_eligible_entries(owner, ptr::addr_of_mut!(count));
            assert_eq!(count, 2);
            assert_eq!(CURRENT_CALLS, 4);
            assert_eq!(ELIGIBILITY_CALLS, 2);
            ptr::addr_of_mut!(ITERATOR_STATE_FETCH).write_volatile(fetch);
        }
    }

    #[test]
    fn collection_count_eligible_entries_zeroes_output_for_empty_collection() {
        let Some(owner) = try_map_u32_slab(hints::COLLECTION_COUNT_ELIGIBLE_ENTRIES_EMPTY, 0x1000) else { return; };
        let _lock = SLOT_TEST_LOCK.lock();
        let _restore = SlotGuard;
        let fetch = unsafe { ptr::read_volatile(ptr::addr_of!(ITERATOR_STATE_FETCH)) };
        let mut count = u32::MAX;
        unsafe {
            SCRIPT = [ptr::null_mut(); 5];
            SCRIPT_INDEX = 0;
            ptr::addr_of_mut!(ITERATOR_STATE_FETCH).write_volatile(scripted_fetch);
            ptr::write_bytes(owner, 0, 0x1000);
            collection_count_eligible_entries(owner, ptr::addr_of_mut!(count));
            assert_eq!(count, 0);
            ptr::addr_of_mut!(ITERATOR_STATE_FETCH).write_volatile(fetch);
        }
    }
}
