//! Base-index reader on the cursor attached to a block-backed list.
//!
//! `list_cursor_base_index` — original: `FUN_081f0e78` @ 0x081f0e78 (24
//! bytes, exact: 0x081f0e90 starts the separately linked bounds predicate),
//! **6 direct `bl` call sites**, all plain unconditional `bl` — no predicated
//! forms and no tail-branch transfers — verified by decoding every ARM B/BL
//! word in `osos.dec`.
//!
//! ```text
//! 081f0e78  mov     r1,r0
//! 081f0e7c  ldr     r1,[r1,#0x30]
//! 081f0e80  mvn     r0,#0
//! 081f0e84  cmp     r1,#0
//! 081f0e88  ldrne   r0,[r1,#0x18]
//! 081f0e8c  bx      lr
//! ```
//!
//! Algorithm: load the cursor pointer stored as a 32-bit target word at
//! `list + 0x30`. A NULL cursor returns -1 without dereferencing it;
//! otherwise return the cursor's signed base index at `cursor + 0x18`.
//! The base-index identity is grounded by all six callers in the list-widget
//! range-update path: each adds it to `list_cursor_index`, divides by a row
//! span, then subtracts it to derive a range boundary.
//!
//! Deliberate deviations: none. The result is `i32`, preserving the original
//! r0 bit pattern including the 0xFFFF_FFFF sentinel.
//!
//! # Safety
//!
//! `list` must be readable through +0x30 with 4-byte alignment. If its cursor
//! word is non-NULL, it must name a record readable through +0x18 with 4-byte
//! alignment; the retail function has no nested-pointer guard.

/// Byte offset of the list's 32-bit cursor pointer (`ldr r1,[r1,#0x30]`).
const CURSOR_OFFSET: usize = 0x30;
/// Byte offset of the cursor's signed base index (`ldrne r0,[r1,#0x18]`).
const CURSOR_BASE_INDEX_OFFSET: usize = 0x18;

/// Reads the base index of the cursor attached to `list`, or -1 when absent.
///
/// Original: `FUN_081f0e78` @ 0x081f0e78 (24 bytes).
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn list_cursor_base_index(list: *const u8) -> i32 {
    // `ldr r1,[r1,#0x30]; cmp r1,#0` short-circuits before any cursor access.
    let cursor = unsafe { list.add(CURSOR_OFFSET).cast::<u32>().read() };
    if cursor == 0 {
        return -1;
    }

    // `ldrne r0,[r1,#0x18]` returns the signed word without range checks.
    unsafe {
        (cursor as usize as *const u8)
            .add(CURSOR_BASE_INDEX_OFFSET)
            .cast::<u32>()
            .read() as i32
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use parking_lot::{Mutex, MutexGuard};
    use std::sync::LazyLock;

    const FIXTURE_LEN: usize = 0x1000;
    const CURSOR_RECORD_OFFSET: usize = 0x400;

    /// Both words are target-width pointers. The mapping stays alive for the
    /// process, so this function owns a distinct hint.
    static FIXTURE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::LIST_CURSOR_BASE_INDEX, FIXTURE_LEN).map(|pointer| pointer as usize)
    });
    static FIXTURE_LOCK: Mutex<()> = Mutex::new(());

    fn try_fixture() -> Option<(*mut u8, MutexGuard<'static, ()>)> {
        let guard = FIXTURE_LOCK.lock();
        (*FIXTURE).map(|base| (base as *mut u8, guard))
    }

    fn write_word(record: *mut u8, offset: usize, value: u32) {
        unsafe { record.add(offset).cast::<u32>().write(value) };
    }

    /// The NULL path must not dereference the poisoned cursor record.
    #[test]
    fn absent_cursor_returns_sentinel() {
        let Some((base, _guard)) = try_fixture() else {
            note_missing_u32_fixture("list_cursor_base_index");
            return;
        };
        let cursor = unsafe { base.add(CURSOR_RECORD_OFFSET) };
        write_word(base, CURSOR_OFFSET, 0);
        write_word(cursor, CURSOR_BASE_INDEX_OFFSET, 42);
        assert_eq!(unsafe { list_cursor_base_index(base) }, -1);
    }

    /// Every cursor field bit pattern is returned; there is no sign or range
    /// guard after the cursor NULL check.
    #[test]
    fn present_cursor_returns_base_index_verbatim() {
        let Some((base, _guard)) = try_fixture() else {
            note_missing_u32_fixture("list_cursor_base_index");
            return;
        };
        let cursor = unsafe { base.add(CURSOR_RECORD_OFFSET) };
        write_word(base, CURSOR_OFFSET, cursor as u32);
        for bits in [0u32, 1, 42, 0x7fff_ffff, 0xffff_fffe, 0x8000_0000] {
            write_word(cursor, CURSOR_BASE_INDEX_OFFSET, bits);
            assert_eq!(unsafe { list_cursor_base_index(base) }, bits as i32);
        }
    }

    /// The function reloads the list's cursor word on every call rather than
    /// caching either the pointer or its field.
    #[test]
    fn detach_and_reattach_are_observed() {
        let Some((base, _guard)) = try_fixture() else {
            note_missing_u32_fixture("list_cursor_base_index");
            return;
        };
        let cursor = unsafe { base.add(CURSOR_RECORD_OFFSET) };
        write_word(cursor, CURSOR_BASE_INDEX_OFFSET, 7);
        write_word(base, CURSOR_OFFSET, cursor as u32);
        assert_eq!(unsafe { list_cursor_base_index(base) }, 7);
        write_word(base, CURSOR_OFFSET, 0);
        assert_eq!(unsafe { list_cursor_base_index(base) }, -1);
        write_word(cursor, CURSOR_BASE_INDEX_OFFSET, 9);
        write_word(base, CURSOR_OFFSET, cursor as u32);
        assert_eq!(unsafe { list_cursor_base_index(base) }, 9);
    }
}
