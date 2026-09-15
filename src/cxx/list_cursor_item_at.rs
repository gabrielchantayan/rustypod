//! Indexed-item accessor on the cursor attached to a block-backed list.
//!
//! `list_cursor_item_at` — original: `FUN_081f0700` @ `0x081f0700` (36
//! bytes; true extent `0x081f0700..0x081f0724`, followed by the independent
//! `push {r3,r4,r5,r6,r7,lr}` prologue at `0x081f0724`). Raw ARM decoding
//! establishes five direct inbound `bl` call sites, all plain unconditional
//! `bl`; there are no predicated calls or tail-branch transfers.
//!
//! ```text
//! 081f0700  push    {r4,lr}
//! 081f0704  ldr     r0,[r0,#0x30]
//! 081f0708  mov     r2,#0
//! 081f070c  cmp     r0,#0
//! 081f0710  beq     0x081f071c
//! 081f0714  bl      0x081fcab0
//! 081f0718  mov     r2,r0
//! 081f071c  mov     r0,r2
//! 081f0720  pop     {r4,pc}
//! ```
//!
//! Algorithm: load the cursor target word at `list + 0x30`. A NULL cursor
//! returns zero without calling or dereferencing the cursor. Otherwise forward
//! the cursor and unchanged index to the direct indexed lookup at `0x081fcab0`.
//! Deliberate deviation: the unrecovered lookup is represented by a host-test
//! dispatch seam; target builds call its verified retailOS address directly.

#[cfg(not(target_os = "none"))]
use core::ptr;

const CURSOR_OFFSET: usize = 0x30;
#[cfg(target_os = "none")]
const RETAIL_CURSOR_INDEXED_LOOKUP: usize = 0x081f_cab0;

/// ABI of the unrecovered direct cursor indexed lookup at `0x081fcab0`.
pub type CursorIndexedLookup = unsafe extern "C" fn(*mut u8, u32) -> u32;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn cursor_indexed_lookup(cursor: *mut u8, index: u32) -> u32 {
    let lookup: CursorIndexedLookup = unsafe { core::mem::transmute(RETAIL_CURSOR_INDEXED_LOOKUP) };
    unsafe { lookup(cursor, index) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_cursor_indexed_lookup(_cursor: *mut u8, _index: u32) -> u32 {
    panic!("list_cursor_item_at requires retailOS cursor lookup")
}

#[cfg(not(target_os = "none"))]
pub static mut CURSOR_INDEXED_LOOKUP: CursorIndexedLookup = missing_cursor_indexed_lookup;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn cursor_indexed_lookup(cursor: *mut u8, index: u32) -> u32 {
    let lookup = unsafe { ptr::read_volatile(ptr::addr_of!(CURSOR_INDEXED_LOOKUP)) };
    unsafe { lookup(cursor, index) }
}

/// Returns the item selected by `index` from the cursor attached at `list +
/// 0x30`, or zero when no cursor is attached.
///
/// # Safety
/// `list` must be readable through +0x30 with 4-byte alignment. A nonzero
/// cursor word must identify a cursor valid for the retail indexed lookup.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn list_cursor_item_at(list: *const u8, index: u32) -> u32 {
    let cursor = unsafe { list.add(CURSOR_OFFSET).cast::<u32>().read() };
    if cursor == 0 {
        return 0;
    }
    unsafe { cursor_indexed_lookup(cursor as usize as *mut u8, index) }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use std::sync::{LazyLock, Mutex, MutexGuard};

    const FIXTURE_LEN: usize = 0x1000;
    const CURSOR_OFFSET_IN_FIXTURE: usize = 0x400;
    static FIXTURE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::LIST_CURSOR_ITEM_AT, FIXTURE_LEN).map(|pointer| pointer as usize)
    });
    static FIXTURE_LOCK: Mutex<()> = Mutex::new(());
    static mut CALLS: u32 = 0;
    static mut SEEN_CURSOR: usize = 0;
    static mut SEEN_INDEX: u32 = 0;
    static mut LOOKUP_RESULT: u32 = 0;

    unsafe extern "C" fn recording_lookup(cursor: *mut u8, index: u32) -> u32 {
        unsafe {
            CALLS += 1;
            SEEN_CURSOR = cursor as usize;
            SEEN_INDEX = index;
            LOOKUP_RESULT
        }
    }

    fn try_fixture() -> Option<(*mut u8, MutexGuard<'static, ()>)> {
        let guard = FIXTURE_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        (*FIXTURE).map(|base| (base as *mut u8, guard))
    }

    fn reset(result: u32) {
        unsafe {
            CALLS = 0;
            SEEN_CURSOR = 0;
            SEEN_INDEX = 0;
            LOOKUP_RESULT = result;
            CURSOR_INDEXED_LOOKUP = recording_lookup;
        }
    }

    fn write_cursor(list: *mut u8, cursor: u32) {
        unsafe { list.add(CURSOR_OFFSET).cast::<u32>().write(cursor) };
    }

    #[test]
    fn null_cursor_returns_zero_without_lookup() {
        let Some((list, _guard)) = try_fixture() else {
            note_missing_u32_fixture("list_cursor_item_at");
            return;
        };
        reset(0xfeed_face);
        write_cursor(list, 0);
        assert_eq!(unsafe { list_cursor_item_at(list, 17) }, 0);
        assert_eq!(unsafe { CALLS }, 0);
    }

    #[test]
    fn present_cursor_forwards_pointer_index_and_result() {
        let Some((list, _guard)) = try_fixture() else {
            note_missing_u32_fixture("list_cursor_item_at");
            return;
        };
        let cursor = unsafe { list.add(CURSOR_OFFSET_IN_FIXTURE) };
        reset(0xcafe_babe);
        write_cursor(list, cursor as u32);
        assert_eq!(unsafe { list_cursor_item_at(list, 0x8000_0001) }, 0xcafe_babe);
        assert_eq!(unsafe { CALLS }, 1);
        assert_eq!(unsafe { SEEN_CURSOR }, cursor as usize);
        assert_eq!(unsafe { SEEN_INDEX }, 0x8000_0001);
    }

    #[test]
    fn detach_reattach_reloads_cursor_word() {
        let Some((list, _guard)) = try_fixture() else {
            note_missing_u32_fixture("list_cursor_item_at");
            return;
        };
        let cursor = unsafe { list.add(CURSOR_OFFSET_IN_FIXTURE) };
        reset(7);
        write_cursor(list, cursor as u32);
        assert_eq!(unsafe { list_cursor_item_at(list, 1) }, 7);
        write_cursor(list, 0);
        assert_eq!(unsafe { list_cursor_item_at(list, 2) }, 0);
        unsafe { LOOKUP_RESULT = 9 };
        write_cursor(list, cursor as u32);
        assert_eq!(unsafe { list_cursor_item_at(list, 3) }, 9);
        assert_eq!(unsafe { CALLS }, 2);
    }
}
