//! Item-count reader on the cursor attached to a block-backed list.
//!
//! `list_cursor_count` — original: `FUN_081f0a84` @ 0x081f0a84 (24 bytes,
//! exact: 0x081f0a9c opens the next separately linked function's
//! `push {r4,r5,r6,r7,r8,r9,sl,lr}` prologue; **5 direct `bl` call sites**,
//! all plain unconditional `bl` — no predicated forms and no tail-branch
//! transfers — verified by decoding every ARM B/BL word in `osos.dec`).
//!
//! ```text
//! 081f0a84  mov     r1,r0
//! 081f0a88  ldr     r1,[r1,#0x30]
//! 081f0a8c  mov     r0,#0
//! 081f0a90  cmp     r1,#0
//! 081f0a94  ldrne   r0,[r1,#0x2b8]
//! 081f0a98  bx      lr
//! ```
//!
//! Algorithm: load the cursor pointer stored as a 32-bit target word at
//! `list + 0x30`. A NULL cursor returns zero without any further dereference.
//! Otherwise return the word at `cursor + 0x2b8`, the cursor's item count.
//!
//! The field identity is sibling-grounded: `FUN_081fcc64` clamps the cursor's
//! signed current index at +0x2b4 against this count; the adjacent
//! `FUN_081f0354` reads that index with a -1 NULL sentinel. Deliberate
//! deviations: the target pointer remains a `u32` wire word on host and ARM,
//! avoiding host pointer-width layout changes; the return is `u32`, preserving
//! the original r0 bits exactly.
//!
//! # Safety
//!
//! `list` must be readable through +0x30 with 4-byte alignment. If the cursor
//! word is non-NULL it must name a record readable through +0x2b8 with 4-byte
//! alignment; retailOS does not guard the nested record.

/// Byte offset of the list's 32-bit cursor pointer (`ldr r1,[r1,#0x30]`).
const CURSOR_OFFSET: usize = 0x30;
/// Byte offset of the cursor's item count (`ldrne r0,[r1,#0x2b8]`).
const CURSOR_COUNT_OFFSET: usize = 0x2b8;

/// list_cursor_count — original: `FUN_081f0a84` @ 0x081f0a84 (24 bytes).
///
/// Returns the cursor's item count, or zero when the list has no cursor.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn list_cursor_count(list: *const u8) -> u32 {
    let cursor = unsafe { list.add(CURSOR_OFFSET).cast::<u32>().read() };
    if cursor == 0 {
        return 0;
    }
    unsafe {
        (cursor as usize as *const u8)
            .add(CURSOR_COUNT_OFFSET)
            .cast::<u32>()
            .read()
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


    static FIXTURE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::LIST_CURSOR_COUNT, FIXTURE_LEN).map(|pointer| pointer as usize)
    });
    static FIXTURE_LOCK: Mutex<()> = Mutex::new(());

    fn try_fixture() -> Option<(*mut u8, MutexGuard<'static, ()>)> {
        let guard = FIXTURE_LOCK.lock();
        (*FIXTURE).map(|base| (base as *mut u8, guard))
    }

    fn cursor(base: *mut u8) -> *mut u8 {
        base.wrapping_add(CURSOR_RECORD_OFFSET)
    }

    fn write_word(record: *mut u8, offset: usize, value: u32) {
        unsafe { record.add(offset).cast::<u32>().write(value) };
    }

    #[test]
    fn null_cursor_returns_zero_without_reading_record() {
        let Some((base, _guard)) = try_fixture() else {
            note_missing_u32_fixture("list_cursor_count");
            return;
        };
        write_word(base, CURSOR_OFFSET, 0);
        write_word(cursor(base), CURSOR_COUNT_OFFSET, 42);
        assert_eq!(unsafe { list_cursor_count(base) }, 0);
    }

    #[test]
    fn present_cursor_returns_count_bits_verbatim() {
        let Some((base, _guard)) = try_fixture() else {
            note_missing_u32_fixture("list_cursor_count");
            return;
        };
        write_word(base, CURSOR_OFFSET, cursor(base) as u32);
        for count in [0u32, 1, 42, 399, u32::MAX] {
            write_word(cursor(base), CURSOR_COUNT_OFFSET, count);
            assert_eq!(unsafe { list_cursor_count(base) }, count);
        }
    }

    #[test]
    fn detach_reattach_rereads_cursor_word() {
        let Some((base, _guard)) = try_fixture() else {
            note_missing_u32_fixture("list_cursor_count");
            return;
        };
        write_word(cursor(base), CURSOR_COUNT_OFFSET, 7);
        write_word(base, CURSOR_OFFSET, cursor(base) as u32);
        assert_eq!(unsafe { list_cursor_count(base) }, 7);
        write_word(base, CURSOR_OFFSET, 0);
        assert_eq!(unsafe { list_cursor_count(base) }, 0);
        write_word(cursor(base), CURSOR_COUNT_OFFSET, 9);
        write_word(base, CURSOR_OFFSET, cursor(base) as u32);
        assert_eq!(unsafe { list_cursor_count(base) }, 9);
    }
}
