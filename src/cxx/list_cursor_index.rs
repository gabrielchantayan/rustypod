//! Current-index reader on the cursor attached to a block-backed list.
//!
//! `list_cursor_index` — original: `FUN_081f0354` @ 0x081f0354 (24 bytes,
//! exact: 0x081f036c opens the next separately linked function's
//! `push {r4,r5,r6,lr}` prologue; **16 direct `bl` call sites**, all plain
//! unconditional `bl` — no predicated forms and no tail-branch transfers —
//! verified by decoding every ARM B/BL word in `osos.dec`).
//!
//! ```text
//! 081f0354  mov     r1,r0
//! 081f0358  ldr     r1,[r1,#0x30]
//! 081f035c  mvn     r0,#0
//! 081f0360  cmp     r1,#0
//! 081f0364  ldrne   r0,[r1,#0x2b4]
//! 081f0368  bx      lr
//! ```
//!
//! Algorithm: load the cursor pointer stored as a 32-bit target word at
//! `list + 0x30`. A NULL cursor returns -1 (the `mvn r0,#0` sentinel)
//! without any further dereference. Otherwise return the signed word at
//! `cursor + 0x2b4`.
//!
//! Field identities are sibling-grounded, not guessed: the cursor record's
//! own setter `FUN_081fcc64` (0x081fcc64) treats +0x2b4 as a signed current
//! index (negative means "no position") and clamps moves against the count
//! at +0x2b8; the element accessor `FUN_081f0700` (0x081f0700) forwards
//! (cursor, index) to the cursor's indexed lookup `FUN_081fcab0`; and the
//! adjacent sibling getter `FUN_081f0a84` (0x081f0a84) reads +0x2b8 with a
//! 0 default where +0x2b4 here defaults to -1. The list object itself is
//! constructed by `FUN_081f13b8` (0x081f13b8) with the cursor word +0x30
//! born NULL; writers at 0x081f07bc / 0x081f0bb8 / 0x081f10c4 / 0x081f1430
//! attach the cursor later. All 16 callers (0x0821a9e0 family of list
//! widgets) use the result as a signed position: cached at widget +0x08 by
//! 0x0821a9e0, compared against scroll-range fields elsewhere.
//!
//! Deviation: none of substance. The result word is returned as `i32` —
//! bit-identical to the original's r0 (0xFFFFFFFF sentinel included) and
//! matching the signed comparisons every caller performs.
//!
//! # Safety
//!
//! `list` must be readable through +0x30 with 4-byte alignment. If the
//! cursor word is non-NULL it must name a record readable through +0x2b4
//! with 4-byte alignment; the original does not guard the nested record.

/// Byte offset of the list's 32-bit cursor pointer (`ldr r1,[r1,#0x30]`).
const CURSOR_OFFSET: usize = 0x30;

/// Byte offset of the cursor's signed current index (`ldrne r0,[r1,#0x2b4]`).
const CURSOR_INDEX_OFFSET: usize = 0x2b4;

/// list_cursor_index — original: `FUN_081f0354` @ 0x081f0354 (24 bytes).
///
/// Returns the current index of the cursor attached at `list + 0x30`, or -1
/// when the list has no cursor.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn list_cursor_index(list: *const u8) -> i32 {
    // ldr r1,[r1,#0x30]; cmp r1,#0 — the NULL cursor short-circuits to the
    // mvn r0,#0 sentinel without touching the cursor record.
    let cursor = unsafe { list.add(CURSOR_OFFSET).cast::<u32>().read() };
    if cursor == 0 {
        return -1;
    }
    // ldrne r0,[r1,#0x2b4] — signed index word, returned verbatim.
    unsafe {
        (cursor as usize as *const u8)
            .add(CURSOR_INDEX_OFFSET)
            .cast::<u32>()
            .read() as i32
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use std::sync::{LazyLock, Mutex, MutexGuard};

    const FIXTURE_LEN: usize = 0x1000;
    const CURSOR_RECORD_OFFSET: usize = 0x400;

    /// Maps the fixture slab once per process. Both pointers the port
    /// dereferences are target `u32` words widened to host pointers, so the
    /// slab must live below 4 GiB; `None` means this host cannot supply
    /// such a mapping and the tests skip rather than crash.
    static FIXTURE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::LIST_CURSOR_INDEX, FIXTURE_LEN).map(|pointer| pointer as usize)
    });
    /// The shared slab fixture is global, so the tests serialize on one lock.
    static FIXTURE_LOCK: Mutex<()> = Mutex::new(());

    fn try_fixture() -> Option<(*mut u8, MutexGuard<'static, ()>)> {
        let guard = FIXTURE_LOCK.lock().unwrap();
        (*FIXTURE).map(|base| (base as *mut u8, guard))
    }

    fn list(base: *mut u8) -> *mut u8 {
        base
    }

    fn cursor(base: *mut u8) -> *mut u8 {
        base.wrapping_add(CURSOR_RECORD_OFFSET)
    }

    fn write_word(record: *mut u8, offset: usize, value: u32) {
        unsafe { record.add(offset).cast::<u32>().write(value) };
    }

    /// A NULL cursor yields the -1 sentinel and must not touch the record
    /// region: the index word is poisoned with a value that would be visible
    /// if the port dereferenced anyway.
    #[test]
    fn null_cursor_returns_sentinel() {
        let Some((base, _guard)) = try_fixture() else {
            note_missing_u32_fixture("list_cursor_index");
            return;
        };
        write_word(list(base), CURSOR_OFFSET, 0);
        write_word(cursor(base), CURSOR_INDEX_OFFSET, 42);
        assert_eq!(unsafe { list_cursor_index(list(base)) }, -1);
    }

    /// A present cursor's index word comes back verbatim, including zero.
    #[test]
    fn present_cursor_returns_index() {
        let Some((base, _guard)) = try_fixture() else {
            note_missing_u32_fixture("list_cursor_index");
            return;
        };
        write_word(list(base), CURSOR_OFFSET, cursor(base) as u32);
        for index in [0u32, 1, 42, 399, 0x7fff_ffff] {
            write_word(cursor(base), CURSOR_INDEX_OFFSET, index);
            assert_eq!(unsafe { list_cursor_index(list(base)) }, index as i32);
        }
    }

    /// A negative index word (the cursor's own "no position" state) passes
    /// through unchanged: the port must read the field, not gate on its sign.
    #[test]
    fn negative_index_passes_through() {
        let Some((base, _guard)) = try_fixture() else {
            note_missing_u32_fixture("list_cursor_index");
            return;
        };
        write_word(list(base), CURSOR_OFFSET, cursor(base) as u32);
        for bits in [0xffff_ffffu32, 0xffff_fffe, 0x8000_0000] {
            write_word(cursor(base), CURSOR_INDEX_OFFSET, bits);
            assert_eq!(unsafe { list_cursor_index(list(base)) }, bits as i32);
        }
    }

    /// The sentinel -1 and a real index of -1 are indistinguishable by value
    /// but take different paths; re-attaching after detach must observe the
    /// cursor word again (no caching in the port).
    #[test]
    fn detach_reattach_transitions() {
        let Some((base, _guard)) = try_fixture() else {
            note_missing_u32_fixture("list_cursor_index");
            return;
        };
        write_word(cursor(base), CURSOR_INDEX_OFFSET, 7);
        write_word(list(base), CURSOR_OFFSET, cursor(base) as u32);
        assert_eq!(unsafe { list_cursor_index(list(base)) }, 7);
        write_word(list(base), CURSOR_OFFSET, 0);
        assert_eq!(unsafe { list_cursor_index(list(base)) }, -1);
        write_word(cursor(base), CURSOR_INDEX_OFFSET, 9);
        write_word(list(base), CURSOR_OFFSET, cursor(base) as u32);
        assert_eq!(unsafe { list_cursor_index(list(base)) }, 9);
    }
}
