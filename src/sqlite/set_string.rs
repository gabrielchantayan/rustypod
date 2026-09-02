//! Replace a caller-owned string with the concatenation of a
//! NULL-terminated vararg list — SQLite's `sqlite3SetString`.
//!
//! - `sqlite3_set_string` — original: `FUN_08384158` @ 0x08384158
//!   (148 bytes; 23 `bl` call sites, binary-scanned: 20 plain `bl`,
//!   one `blne` @ 0x08387314 and two `bleq` @ 0x0838a868 /
//!   0x0838b2a8 — the predicated sites gate the call on a computed
//!   condition, not on a pointer; the callee itself has no NULL guard
//!   on `pz`). SQLite's `sqlite3SetString` (`void
//!   sqlite3SetString(char **pz, ...)` in util.c of the 3.5.x line).
//!
//! Algorithm: spill r0-r3 into a varargs home area (`stmdb sp!,
//! {r0-r3}`) and walk the string list starting at the spilled r1
//! twice. Pass 1 sums `1 + Σ strlen(z)` (unguarded strlen @
//! 0x08392478) into the request size. The OLD string is then released
//! first — `sqlite3_free(*pz)` (the ported [`tracked_free`] @
//! 0x083906f4, called unconditionally; its own NULL guard covers a
//! fresh `pz`) — and the replacement is allocated (`sqlite3_malloc` @
//! 0x08390b14) and stored through `pz` EVEN WHEN NULL: a failed
//! allocation leaves `*pz == NULL`, so the caller never holds a stale
//! pointer. On success the buffer gets `dst[0] = 0` up front, pass 2
//! appends each string with `__rt_memcpy` (ROM veneer @ 0x08037db0)
//! over exactly `strlen(z)` bytes — no per-string NUL — and a single
//! terminator is stored at the final position. The epilogue (`ldm
//! sp!, {r4-r8}` + `ldr pc, [sp], #20`) returns void and pops the
//! home area; r0 carries nothing back.
//!
//! Deviations:
//! - The original is C-variadic; the Rust signature replaces the `...`
//!   with an explicit `args: VaList` — exactly the pointer the original
//!   builds on its stack (&spilled-r1; house convention, see
//!   `printf/printf_api.rs` for the rationale and the trampoline note
//!   for calling from firmware code).
//! - `sqlite3_malloc` goes through the shared [`DB_MEM_OPS`] dispatch
//!   whose wired default IS the ported entry @ 0x08390b14 (house
//!   pattern, see `sqlite/mem.rs`); `strlen`, [`tracked_free`] and
//!   `__rt_memcpy` are called directly through their ported twins.
//! - The size accumulator wraps like the 32-bit r6 it was
//!   (`wrapping_add`); the host `usize` length is truncated to a word
//!   exactly as the ARM `add` would.

use crate::heap::tracked::tracked_free;
use crate::libc::rt_memcpy::__rt_memcpy;
use crate::libc::strlen::strlen;
use crate::sqlite::error_msg::VaList;
use crate::sqlite::mem::db_malloc_op;

/// sqlite3_set_string — original: `FUN_08384158` @ 0x08384158
/// (148 bytes; 23 `bl` call sites, binary-scanned).
///
/// `sqlite3SetString`: free `*pz`, then store through `pz` a freshly
/// allocated string holding the concatenation of the NULL-terminated
/// string list at `args` (the spilled r1 onwards). On allocation
/// failure `*pz` becomes NULL. `pz` itself is never NULL-checked —
/// matching the original, whose callers always pass a valid slot.
///
/// Register usage: r0 = pz, r1/r2/r3/stack = the string list (the
/// original builds `ap` = &spilled-r1; here `args` IS that pointer).
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn sqlite3_set_string(pz: *mut *mut u8, args: VaList) {
    // Pass 1: request size = 1 + Σ strlen(z).
    let mut size: i32 = 1;
    let mut ap = args;
    loop {
        let z = ap.read() as *const u8;
        ap = ap.add(1);
        if z.is_null() {
            break;
        }
        size = size.wrapping_add(strlen(z) as i32);
    }

    tracked_free(pz.read());
    let result = (db_malloc_op())(size);
    // Stored even on failure: *pz is NULL, never stale.
    pz.write(result);
    if result.is_null() {
        return;
    }

    // Pass 2: append each string without its NUL; terminate once.
    result.write(0);
    let mut dst = result;
    let mut ap = args;
    loop {
        let z = ap.read() as *const u8;
        ap = ap.add(1);
        if z.is_null() {
            break;
        }
        let len = strlen(z);
        __rt_memcpy(dst, z, len);
        dst = dst.add(len);
    }
    dst.write(0);
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::heap::tracked::ALLOC_STATS;
    use crate::heap::veneers::tests as heap_tests;
    use crate::sqlite::mem::tests::{install_recorder, realloc_log};
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};

    /// Source strings cross the `VaList` as u32 words, so they must
    /// live below 4 GiB: one shared slab (mapped once, read-only
    /// during the parallel tests) holds every string the tests use.
    /// The result arenas never travel through a u32 field — the
    /// recording malloc returns a host pointer — and stay on the
    /// stack.
    fn strings() -> Option<*mut u8> {
        static ONCE: std::sync::Once = std::sync::Once::new();
        static mut BASE: *mut u8 = core::ptr::null_mut();
        ONCE.call_once(|| unsafe {
            if let Some(p) = try_map_u32_slab(hints::SET_STRING, 0x1000) {
                let put = |off: usize, s: &[u8]| {
                    core::ptr::copy_nonoverlapping(s.as_ptr(), p.add(off), s.len());
                };
                put(0x000, b"abc\0");
                put(0x010, b"\0");
                put(0x020, b"defgh\0");
                put(0x030, b"i\0");
                put(0x040, b"a\0");
                put(0x048, b"bb\0");
                put(0x050, b"ccc\0");
                put(0x058, b"dddd\0");
                put(0x060, b"eeeee\0");
                put(0x080, b"wxyz\0");
                put(0x090, b"abcdef\0");
                put(0x0a0, b"xy\0");
                BASE = p;
            }
        });
        unsafe {
            let base = core::ptr::read(core::ptr::addr_of!(BASE));
            if base.is_null() {
                None
            } else {
                Some(base)
            }
        }
    }

    fn word(base: *mut u8, off: usize) -> u32 {
        base.wrapping_add(off) as usize as u32
    }

    /// A freeable stand-in tracked block (layout per
    /// `heap::tracked::tracked_free`: signed size cookie at raw+0, pad
    /// word at payload-4, raw = payload - pad - 8).
    #[repr(C)]
    struct FakeBlock {
        size: i32,
        sign: i32,
        _pad_bytes: [u8; 20],
        pad: u32,
        payload: [u8; 64],
    }

    impl FakeBlock {
        fn new(size: i32) -> Self {
            FakeBlock { size, sign: 0, _pad_bytes: [0; 20], pad: 24, payload: [0xa5; 64] }
        }
        fn data(&mut self) -> *mut u8 {
            self.payload.as_mut_ptr()
        }
        fn raw(&mut self) -> *mut u8 {
            (self as *mut FakeBlock).cast::<u8>()
        }
    }

    /// The list terminator alone: one request of 1 byte, result is
    /// the empty string.
    #[test]
    fn an_empty_list_yields_a_one_byte_empty_string() {
        let mut arena = [0xa5u8; 16];
        let _guard = install_recorder(arena.as_mut_ptr());
        let args: [u32; 1] = [0];
        let mut slot: *mut u8 = core::ptr::null_mut();

        unsafe {
            sqlite3_set_string(&mut slot, args.as_ptr());
            assert_eq!(slot, arena.as_mut_ptr());
            assert_eq!(realloc_log(), std::vec![(0, 1)], "1 + nothing");
            assert_eq!(arena[0], 0, "the lone terminator");
            assert!(arena[1..].iter().all(|&b| b == 0xa5), "nothing past byte 1 is written");
        }
    }

    /// The common path: several strings land back to back, sized
    /// exactly, terminated once.
    #[test]
    fn concatenates_the_list_into_an_exactly_sized_block() {
        let Some(s) = strings() else {
            assert!(note_missing_u32_fixture("sqlite::set_string"));
            return;
        };
        let mut arena = [0xa5u8; 32];
        let _guard = install_recorder(arena.as_mut_ptr());
        // "abc" + "" + "defgh" + "i": empty strings contribute 0.
        let args: [u32; 5] =
            [word(s, 0x000), word(s, 0x010), word(s, 0x020), word(s, 0x030), 0];
        let mut slot: *mut u8 = core::ptr::null_mut();

        unsafe {
            sqlite3_set_string(&mut slot, args.as_ptr());
            assert_eq!(slot, arena.as_mut_ptr());
            assert_eq!(realloc_log(), std::vec![(0, 1 + 3 + 0 + 5 + 1)], "1 + Σ strlen(z)");
            assert_eq!(&arena[..9], b"abcdefghi", "back to back, no inner NULs");
            assert_eq!(arena[9], 0, "single terminator at the end");
            assert!(arena[10..].iter().all(|&b| b == 0xa5), "nothing past the terminator");
        }
    }

    /// A failed allocation still frees the old string and stores NULL
    /// through pz — never a stale pointer.
    #[test]
    fn allocation_failure_stores_null_and_copies_nothing() {
        let Some(s) = strings() else {
            assert!(note_missing_u32_fixture("sqlite::set_string"));
            return;
        };
        let _mem = install_recorder(core::ptr::null_mut());
        let _heap = heap_tests::mock_heap();
        let mut old = FakeBlock::new(24);
        let mut slot: *mut u8 = old.data();
        let args: [u32; 2] = [word(s, 0x080), 0]; // "wxyz"

        unsafe {
            sqlite3_set_string(&mut slot, args.as_ptr());
            assert!(slot.is_null(), "NULL stored through pz on failure");
            assert_eq!(realloc_log(), std::vec![(0, 5)], "the request was still made");
            let (calls, ptr, tag) = heap_tests::free_log();
            assert_eq!(calls, 1, "the old string is freed even on failure");
            assert_eq!(ptr, old.raw(), "tracked_free recovered the raw block");
            assert_eq!(tag, 57, "tag-57 tracked free");
        }
    }

    /// The old string is released BEFORE the new allocation: the free
    /// reaches the heap veneer ahead of the malloc.
    #[test]
    fn frees_the_old_string_before_allocating_the_new_one() {
        let Some(s) = strings() else {
            assert!(note_missing_u32_fixture("sqlite::set_string"));
            return;
        };
        let mut arena = [0xa5u8; 16];
        let _mem = install_recorder(arena.as_mut_ptr());
        let _heap = heap_tests::mock_heap();
        let mut old = FakeBlock::new(40);
        let mut slot: *mut u8 = old.data();
        let args: [u32; 2] = [word(s, 0x090), 0]; // "abcdef"

        unsafe {
            let before = (*core::ptr::addr_of!(ALLOC_STATS)).current_bytes;
            sqlite3_set_string(&mut slot, args.as_ptr());
            let (calls, ptr, tag) = heap_tests::free_log();
            assert_eq!((calls, ptr, tag), (1, old.raw(), 57), "old block freed, tag 57");
            let after = (*core::ptr::addr_of!(ALLOC_STATS)).current_bytes;
            assert_eq!(before - after, 40, "the old block's cookie left the byte counter");
            assert_eq!(slot, arena.as_mut_ptr(), "the replacement is installed");
            assert_eq!(&arena[..6], b"abcdef");
            assert_eq!(arena[6], 0);
        }
    }

    /// A NULL old value is passed to tracked_free verbatim — its own
    /// NULL guard makes that a no-op, nothing reaches the heap.
    #[test]
    fn a_null_old_value_never_reaches_the_heap() {
        let Some(s) = strings() else {
            assert!(note_missing_u32_fixture("sqlite::set_string"));
            return;
        };
        let mut arena = [0xa5u8; 8];
        let _mem = install_recorder(arena.as_mut_ptr());
        let _heap = heap_tests::mock_heap();
        let mut slot: *mut u8 = core::ptr::null_mut();
        let args: [u32; 2] = [word(s, 0x0a0), 0]; // "xy"

        unsafe {
            sqlite3_set_string(&mut slot, args.as_ptr());
            assert_eq!(heap_tests::free_log().0, 0, "tracked_free(NULL) is a no-op");
            assert_eq!(slot, arena.as_mut_ptr());
            assert_eq!(&arena[..3], b"xy\0");
        }
    }

    /// A long list walks the full word sequence; the terminator word
    /// is the only stop.
    #[test]
    fn walks_every_word_until_the_terminator() {
        let Some(s) = strings() else {
            assert!(note_missing_u32_fixture("sqlite::set_string"));
            return;
        };
        let mut arena = [0xa5u8; 32];
        let _guard = install_recorder(arena.as_mut_ptr());
        let args: [u32; 6] = [
            word(s, 0x040),
            word(s, 0x048),
            word(s, 0x050),
            word(s, 0x058),
            word(s, 0x060),
            0,
        ];
        let mut slot: *mut u8 = core::ptr::null_mut();

        unsafe {
            sqlite3_set_string(&mut slot, args.as_ptr());
            assert_eq!(realloc_log(), std::vec![(0, 1 + 1 + 2 + 3 + 4 + 5)]);
            assert_eq!(&arena[..15], b"abbcccddddeeeee");
            assert_eq!(arena[15], 0, "terminated at Σ strlen");
            assert!(arena[16..].iter().all(|&b| b == 0xa5));
        }
    }
}
