//! entry_table_finalize_and_append — retailOS `FUN_080cd984` @ 0x080cd984.
//!
//! Raw `osos.dec` establishes the 36-byte extent from 0x080cd984 through
//! `pop {r3,r4,r5,pc}` at 0x080cd9a4; 0x080cd9a8 begins the next function.
//! Whole-image A32 decoding finds three incoming plain `bl` calls
//! (0x0809c100, 0x0809c118, and 0x080d9ccc) and no predicated incoming `bl`
//! calls. The body has two plain `bl` calls, to 0x080c1050 and 0x080b089c,
//! and no predicated calls.
//!
//! Algorithm: finalize the prior entry using `completed_entry_value`, then
//! append and initialize a 16-byte entry in the state word-3 entry table with
//! `context`, returning the append status.
//!
//! Deliberate deviations: finalization uses the Rust port; the unidentified
//! append helper retains its verified retail address and host ABI seam.

use core::mem::MaybeUninit;

pub type AppendEntry = unsafe extern "C" fn(*mut u32, u32, *mut u32) -> u32;

const RETAIL_APPEND_ENTRY: usize = 0x080b_089c;

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
pub struct EntryTableOps {
    pub append_entry: AppendEntry,
}


#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_append_entry(_table: *mut u32, _context: u32, _entry: *mut u32) -> u32 {
    panic!("install entry-table host operations before appending an entry")
}

#[cfg(not(target_os = "none"))]
pub static mut ENTRY_TABLE_OPS: EntryTableOps = EntryTableOps {
    append_entry: missing_append_entry,
};


#[inline(always)]
unsafe fn append_entry(table: *mut u32, context: u32, entry: *mut u32) -> u32 {
    #[cfg(target_os = "none")]
    {
        let helper: AppendEntry = unsafe { core::mem::transmute(RETAIL_APPEND_ENTRY) };
        return unsafe { helper(table, context, entry) };
    }
    #[cfg(not(target_os = "none"))]
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(ENTRY_TABLE_OPS.append_entry))(table, context, entry) }
}

/// Finalizes the current entry and appends an entry-table slot.
///
/// # Safety
///
/// `state` must identify the retail state layout: its word-3 field is the
/// target-width `{length, capacity, data}` entry table required by the append
/// helper. Both helper calls retain retailOS's unchecked pointer semantics.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn entry_table_finalize_and_append(
    state: *mut u32,
    completed_entry_value: u32,
    context: u32,
) -> u32 {
    unsafe { super::entry_table_finalize_last::entry_table_finalize_last(state, completed_entry_value) };
    let mut entry = MaybeUninit::<u32>::uninit();
    unsafe { append_entry(state.add(3), context, entry.as_mut_ptr()) }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use parking_lot::Mutex;
    use std::sync::LazyLock;

    static LOCK: Mutex<()> = Mutex::new(());
    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| try_map_u32_slab(hints::ENTRY_TABLE_FINALIZE_AND_APPEND, 0x1000).map(|p| p as usize));
    static mut APPEND_RESULT: u32 = 0;
    static mut OUTPUT_ENTRY: u32 = 0;


    unsafe extern "C" fn record_append(table: *mut u32, _context: u32, entry: *mut u32) -> u32 {
        unsafe {
            let data = table.add(2).read() as usize as *const u32;
            assert_eq!(data.add(3).read(), 0);
            entry.write(OUTPUT_ENTRY);
            APPEND_RESULT
        }
    }

    fn install() {
        unsafe {
            ENTRY_TABLE_OPS = EntryTableOps { append_entry: record_append };
            APPEND_RESULT = 0;
            OUTPUT_ENTRY = 0;
        }
    }


    #[test]
    fn returns_append_failure_after_finalizing_current_entry() {
        let _guard = LOCK.lock();
        let Some(slab) = *SLAB else { assert!(note_missing_u32_fixture("util/entry_table_finalize_and_append")); return; };
        install();
        let state = slab as *mut u32;
        unsafe {
            let entries = state.add(16);
            state.add(3).write(1);
            state.add(5).write(entries as u32);
            entries.add(3).write(0xdead_beef);
            APPEND_RESULT = 0x15;
            assert_eq!(entry_table_finalize_and_append(state, 0, 0), 0x15);
            assert_eq!(entries.add(3).read(), 0);
        }
    }
}
