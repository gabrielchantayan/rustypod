//! Localized-string table membership test — the predicate Silver UI code
//! runs before fetching a string value for a key.
//!
//! - [`string_table_has_string`] — original: `FUN_08101edc` @
//!   0x08101edc (184 bytes, 0x08101edc..0x08101f94 — extent confirmed
//!   against raw bytes: the next function's `push` sits at 0x08101f94;
//!   **38 `bl` call sites**, all unconditional, verified by decoding
//!   every B/BL word in osos.dec — zero predicated forms, so no caller
//!   gates the call on a flag and the callee needs no NULL guard).
//!
//! # Object under test
//!
//! `this` is the localization string-table singleton (the global callers
//! load as `DAT_08219384` / `DAT_081de518`): an inline array of
//! string-keyed maps (the `StringKeyMap` family of `cxx/string_map.rs`,
//! 0x1c-byte stride, header-node pointer at map + 0x10, one-word
//! comparator object at map + 0x19) plus a selector:
//!
//! ```text
//! +0x00  table[0]  StringKeyMap (0x1c bytes)
//! +0x1c  table[1]  StringKeyMap
//! +0x38  table[2]  StringKeyMap — the fallback (default-language) table
//! +0x54  current table index (word)
//! ```
//!
//! Keys and mapped values are COW `basic_string`s (rep data pointer;
//! size word at data - 4). Callers build a key with
//! `cxx_string_from_cstr` @ 0x083d8b5c (e.g. `"AlarmToneAt"`,
//! `"RefreshingGenius"`, `"CreatingGeniusMix"`), run this predicate, and
//! only then fetch the value through the getter family @ 0x08102168 /
//! the veneer @ 0x08101ed4 (`this + 0x38; b 0x083c4778` — the
//! fallback-table `operator[]`).
//!
//! # Algorithm (from the raw bytes)
//!
//! ```text
//! map  = table + table->current_index * 0x1c        // index re-read
//! find(&node, map, key)                             //   across the call
//! if node != map->header && !empty(node->value):    // value at node+0x14
//!     return 1
//! find(&node, table + 0x38, key)                    // fallback table
//! return node != fallback->header && !empty(node->value)
//! ```
//!
//! i.e. 1 iff `key` resolves to a **non-empty** string, looking in the
//! current table first and in the fallback table otherwise (a hit whose
//! value is empty also falls through to the fallback). The
//! iterator-equality compare against the map header is the miss test:
//! `find` returns the header node when the key is absent.
//!
//! # Callees (all real `bl` boundaries in the original)
//!
//! - `FUN_083db55c` @ 0x083db55c — `map<string,string>::find`:
//!   lower_bound walk from the root (header + 4) comparing
//!   `cxx_string_less` @ 0x083d74f4 (ported) of node key at node + 0x10
//!   vs the query, then the equal-range recheck via the node-key
//!   accessor @ 0x083b6acc (`node + 16`); writes the found node — or
//!   the header node on a miss — through its first argument. **Not
//!   ported**; Ghidra's C for our function mis-renders this call as a
//!   buffer copy, which it is not.
//! - `FUN_083cf848` @ 0x083cf848 — iterator equality: `*a == *b` (the
//!   equal twin of the ported `not_equal_deref` family @ 0x083d6f40
//!   and the one-word compare @ 0x083cf818 `cxx/string_map.rs`
//!   inlines). **Not ported.**
//! - `FUN_083d6f0c` @ 0x083d6f0c — `basic_string::empty`: reads the
//!   size word at `(*string) - 4`, returns 1 iff it is 0
//!   (`rsbs r0, r0, #1; movcc r0, #0` — 1 for size 0, 0 for any
//!   nonzero size). **Not ported.**
//!
//! # Deviations
//!
//! - The three unported callees ride the [`STRING_TABLE_OPS`]
//!   `read_volatile` dispatch table (house pattern). The target
//!   defaults transmute the real firmware addresses 0x083db55c /
//!   0x083cf848 / 0x083d6f0c, so the port **is hook-ready on device**;
//!   the host defaults panic until a test installs mocks.
//! - The original spills r0..r3 on entry and reuses those stack slots
//!   as the two `find` out-slots and the header-temporary; the port
//!   uses ordinary locals.
//! - The current-index word at `this + 0x54` is re-read after the first
//!   `find` call for the header compare, exactly as the original
//!   reloads `ldr r0, [r4, #84]` across the `bl`.
//! - Pointer-to-word seam arguments are typed `*const u32`, not
//!   `*const *mut u8`: the pointees are 32-bit target words (node
//!   pointers, string data pointers) on both target and host fixtures.

/// Word index of the current-table selector at `this + 0x54`.
const CURRENT_TABLE_INDEX_WORD: usize = 0x54 / 4;

/// Byte stride of one inline `StringKeyMap` (7 words).
const TABLE_STRIDE: usize = 0x1c;

/// Word index of the header-node pointer inside a map (+ 0x10).
const MAP_HEADER_WORD: usize = 0x10 / 4;

/// Byte offset of the fixed fallback table (`this + 0x38` == table[2]).
const FALLBACK_TABLE_OFFSET: usize = 0x38;

/// Byte offset of the mapped-value string word inside a node (+ 0x14).
const NODE_VALUE_OFFSET: usize = 0x14;

/// Reads the word at `base + index * 4`. All fields touched here are
/// word-aligned in the original (`ldr`/`str`, never `ldrb`), so these
/// are aligned reads on target.
#[inline(always)]
unsafe fn word(base: *const u8, index: usize) -> u32 {
    (base as *const u32).add(index).read()
}

/// The retailOS dependencies of [`string_table_has_string`]. Every
/// pointee behind a `*const u32` is a 32-bit firmware word.
#[derive(Clone, Copy)]
pub struct StringTableOps {
    /// `FUN_083db55c` @ 0x083db55c — the string-map `find`: writes the
    /// found node pointer, or the map's header node on a miss, to
    /// `*out`. `key` points at the query string's data-pointer word.
    pub find: unsafe extern "C" fn(out: *mut u32, map: *mut u8, key: *const u32),
    /// `FUN_083cf848` @ 0x083cf848 — iterator equality: 1 iff the two
    /// pointee words are equal (node == header is the miss test).
    pub iter_eq: unsafe extern "C" fn(a: *const u32, b: *const u32) -> u32,
    /// `FUN_083d6f0c` @ 0x083d6f0c — `basic_string::empty` on the word
    /// at `string`: 1 iff the size word at `(*string) - 4` is 0.
    pub string_empty: unsafe extern "C" fn(string: *const u32) -> u32,
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_string_map_find(out: *mut u32, map: *mut u8, key: *const u32) {
    let find: unsafe extern "C" fn(*mut u32, *mut u8, *const u32) =
        unsafe { core::mem::transmute(0x083d_b55cusize) };
    unsafe { find(out, map, key) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_string_map_find(_out: *mut u32, _map: *mut u8, _key: *const u32) {
    panic!("string_table_has_string requires string-map find 0x083db55c")
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_iter_eq(a: *const u32, b: *const u32) -> u32 {
    let eq: unsafe extern "C" fn(*const u32, *const u32) -> u32 =
        unsafe { core::mem::transmute(0x083c_f848usize) };
    unsafe { eq(a, b) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_iter_eq(_a: *const u32, _b: *const u32) -> u32 {
    panic!("string_table_has_string requires iterator equality 0x083cf848")
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_string_empty(string: *const u32) -> u32 {
    let empty: unsafe extern "C" fn(*const u32) -> u32 =
        unsafe { core::mem::transmute(0x083d_6f0cusize) };
    unsafe { empty(string) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_string_empty(_string: *const u32) -> u32 {
    panic!("string_table_has_string requires basic_string::empty 0x083d6f0c")
}

/// Wired defaults for [`STRING_TABLE_OPS`]: the retail firmware bodies.
#[cfg(target_os = "none")]
pub const DEFAULT_STRING_TABLE_OPS: StringTableOps = StringTableOps {
    find: firmware_string_map_find,
    iter_eq: firmware_iter_eq,
    string_empty: firmware_string_empty,
};

/// Wired defaults for [`STRING_TABLE_OPS`]: unported on host, so panic
/// until a test installs faithful mocks.
#[cfg(not(target_os = "none"))]
pub const DEFAULT_STRING_TABLE_OPS: StringTableOps = StringTableOps {
    find: missing_string_map_find,
    iter_eq: missing_iter_eq,
    string_empty: missing_string_empty,
};

/// Active model of the unported retailOS dependencies. Target
/// integration may replace the slots as 0x083db55c / 0x083cf848 /
/// 0x083d6f0c are ported; host tests install mocks.
pub static mut STRING_TABLE_OPS: StringTableOps = DEFAULT_STRING_TABLE_OPS;

#[inline(always)]
unsafe fn string_table_ops() -> StringTableOps {
    core::ptr::read_volatile(core::ptr::addr_of!(STRING_TABLE_OPS))
}

/// string_table_has_string — original: `FUN_08101edc` @ 0x08101edc
/// (184 bytes; 38 unconditional `bl` call sites, binary-scanned).
///
/// Returns 1 iff `key` maps to a non-empty string in the current table
/// (selected by the index word at `this + 0x54`), or — on a miss or an
/// empty value there — in the fallback table at `this + 0x38`; 0
/// otherwise. See the module header for the object layout, the callee
/// contracts, and the deviations.
///
/// There is no NULL guard on `this` or `key`, as in the original.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn string_table_has_string(table: *mut u8, key: *const u32) -> u32 {
    let ops = string_table_ops();
    let mut node: u32 = 0;

    let index = word(table, CURRENT_TABLE_INDEX_WORD) as usize;
    let current = table.add(index * TABLE_STRIDE);
    (ops.find)(&mut node, current, key);
    // The original reloads the index word across the find call.
    let header = word(
        table.add(word(table, CURRENT_TABLE_INDEX_WORD) as usize * TABLE_STRIDE),
        MAP_HEADER_WORD,
    );
    if (ops.iter_eq)(&node, &header) == 0
        && (ops.string_empty)((node as usize + NODE_VALUE_OFFSET) as *const u32) == 0
    {
        return 1;
    }

    let fallback = table.add(FALLBACK_TABLE_OFFSET);
    (ops.find)(&mut node, fallback, key);
    let header = word(fallback, MAP_HEADER_WORD);
    ((ops.iter_eq)(&node, &header) == 0
        && (ops.string_empty)((node as usize + NODE_VALUE_OFFSET) as *const u32) == 0)
        as u32
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use core::ptr;
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    static OPS_LOCK: Mutex<()> = Mutex::new(());

    /// Restores the seam table even if a test panics mid-run.
    struct SeamGuard;

    impl Drop for SeamGuard {
        fn drop(&mut self) {
            unsafe {
                ptr::write_volatile(ptr::addr_of_mut!(STRING_TABLE_OPS), DEFAULT_STRING_TABLE_OPS);
            }
        }
    }

    fn lock() -> (MutexGuard<'static, ()>, SeamGuard) {
        let guard = OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        (guard, SeamGuard)
    }

    // ---- Fixture layout inside the u32 slab -----------------------------
    //
    // table base T:
    //   T + 0x00  map[0]   (header word at T + 0x10)
    //   T + 0x1c  map[1]   (header word at T + 0x2c)
    //   T + 0x38  map[2]   (fallback; header word at T + 0x48)
    //   T + 0x54  current index
    // then three header nodes, two value-string reps and two result
    // nodes, all as u32 words:
    //   header node H<n>: only its address matters (the miss sentinel).
    //   result node N:    value string pointer word at N + 0x14.
    //   string rep:       size word at S - 4, data at S.

    const SLAB_SIZE: usize = 0x1000;
    const MAP0: usize = 0x000;
    const MAP1: usize = 0x01c;
    const MAP2: usize = 0x038;
    const INDEX_WORD: usize = 0x054;
    const HEADER0: usize = 0x100;
    const HEADER1: usize = 0x120;
    const HEADER2: usize = 0x140;
    const NODE_A: usize = 0x200; // non-empty value
    const NODE_B: usize = 0x240; // empty value
    const REP_A_SIZE: usize = 0x300; // size word; data follows at +4
    const REP_B_SIZE: usize = 0x310;

    struct Fixture {
        base: *mut u8,
    }

    impl Fixture {
        fn map() -> Option<Fixture> {
            try_map_u32_slab(hints::STRING_TABLE, SLAB_SIZE).map(|base| {
                unsafe { ptr::write_bytes(base, 0, SLAB_SIZE) };
                let f = Fixture { base };
                // Header pointers at map + 0x10.
                f.set_word(MAP0 + 0x10, f.addr(HEADER0));
                f.set_word(MAP1 + 0x10, f.addr(HEADER1));
                f.set_word(MAP2 + 0x10, f.addr(HEADER2));
                // Node value string pointers at node + 0x14.
                f.set_word(NODE_A + NODE_VALUE_OFFSET, f.addr(REP_A_SIZE + 4));
                f.set_word(NODE_B + NODE_VALUE_OFFSET, f.addr(REP_B_SIZE + 4));
                // String reps: non-empty vs empty size words.
                f.set_word(REP_A_SIZE, 7);
                f.set_word(REP_B_SIZE, 0);
                f
            })
        }

        fn addr(&self, off: usize) -> u32 {
            unsafe { self.base.add(off) as usize as u32 }
        }

        fn set_word(&self, off: usize, value: u32) {
            unsafe {
                (self.base.add(off) as *mut u32).write(value);
            }
        }

        fn set_index(&self, index: u32) {
            self.set_word(INDEX_WORD, index);
        }
    }

    // ---- Faithful-semantics mocks ----------------------------------------
    //
    // iter_eq and string_empty implement the exact decoded semantics of
    // 0x083cf848 / 0x083d6f0c over fixture memory; find is scripted
    // (the tree walk itself is the unported 0x083db55c's business) but
    // records every argument tuple.

    /// (map address, key address) of every find call, in order.
    static mut FIND_CALLS: Vec<(u32, u32)> = Vec::new();
    /// Scripted results: find call N writes RESULTS[N] to *out.
    static mut FIND_RESULTS: Vec<u32> = Vec::new();
    /// When set, the find mock rewrites the table index word mid-call.
    static mut FIND_SETS_INDEX: Option<(*mut u8, u32)> = None;

    fn find_calls() -> &'static mut Vec<(u32, u32)> {
        unsafe { &mut *ptr::addr_of_mut!(FIND_CALLS) }
    }

    fn find_results() -> &'static mut Vec<u32> {
        unsafe { &mut *ptr::addr_of_mut!(FIND_RESULTS) }
    }

    unsafe extern "C" fn mock_find(out: *mut u32, map: *mut u8, key: *const u32) {
        find_calls().push((map as usize as u32, key as usize as u32));
        let call = find_calls().len() - 1;
        if let Some((table, index)) = FIND_SETS_INDEX {
            (table.add(INDEX_WORD) as *mut u32).write(index);
        }
        out.write(find_results()[call]);
    }

    /// 0x083cf848 exactly: 1 iff *a == *b.
    unsafe extern "C" fn mock_iter_eq(a: *const u32, b: *const u32) -> u32 {
        (a.read() == b.read()) as u32
    }

    /// 0x083d6f0c exactly: 1 iff the size word at (*string) - 4 is 0.
    unsafe extern "C" fn mock_string_empty(string: *const u32) -> u32 {
        let data = string.read() as usize;
        (((data - 4) as *const u32).read() == 0) as u32
    }

    /// Installs the mocks and scripts `find`. `results` are u32 node (or
    /// header) addresses written to *out on successive calls.
    unsafe fn install(results: &[u32]) {
        find_calls().clear();
        find_results().clear();
        find_results().extend_from_slice(results);
        FIND_SETS_INDEX = None;
        ptr::write_volatile(
            ptr::addr_of_mut!(STRING_TABLE_OPS),
            StringTableOps {
                find: mock_find,
                iter_eq: mock_iter_eq,
                string_empty: mock_string_empty,
            },
        );
    }

    const KEY: u32 = 0xcafe;

    #[test]
    fn hit_current_nonempty_returns_one_without_fallback() {
        let (_guard, _seam) = lock();
        let Some(f) = Fixture::map() else {
            assert!(note_missing_u32_fixture("app/string_table"));
            return;
        };
        f.set_index(0);
        unsafe { install(&[f.addr(NODE_A)]) };
        let result = unsafe { string_table_has_string(f.base, KEY as *const u32) };
        assert_eq!(result, 1);
        assert_eq!(find_calls().as_slice(), &[(f.addr(MAP0), KEY)]);
    }

    #[test]
    fn miss_current_falls_back_to_table_two() {
        let (_guard, _seam) = lock();
        let Some(f) = Fixture::map() else {
            assert!(note_missing_u32_fixture("app/string_table"));
            return;
        };
        f.set_index(1);
        // Miss in table[1] (find returns the header), hit in fallback.
        unsafe { install(&[f.addr(HEADER1), f.addr(NODE_A)]) };
        let result = unsafe { string_table_has_string(f.base, KEY as *const u32) };
        assert_eq!(result, 1);
        assert_eq!(
            find_calls().as_slice(),
            &[(f.addr(MAP1), KEY), (f.addr(MAP2), KEY)]
        );
    }

    #[test]
    fn miss_in_both_returns_zero() {
        let (_guard, _seam) = lock();
        let Some(f) = Fixture::map() else {
            assert!(note_missing_u32_fixture("app/string_table"));
            return;
        };
        f.set_index(0);
        unsafe { install(&[f.addr(HEADER0), f.addr(HEADER2)]) };
        let result = unsafe { string_table_has_string(f.base, KEY as *const u32) };
        assert_eq!(result, 0);
        assert_eq!(
            find_calls().as_slice(),
            &[(f.addr(MAP0), KEY), (f.addr(MAP2), KEY)]
        );
    }

    #[test]
    fn empty_value_in_current_still_falls_back() {
        let (_guard, _seam) = lock();
        let Some(f) = Fixture::map() else {
            assert!(note_missing_u32_fixture("app/string_table"));
            return;
        };
        f.set_index(2);
        // Hit in the current table (table[2] here) but with an empty
        // value; the fallback (also table[2]) then hits non-empty.
        unsafe { install(&[f.addr(NODE_B), f.addr(NODE_A)]) };
        let result = unsafe { string_table_has_string(f.base, KEY as *const u32) };
        assert_eq!(result, 1);
        assert_eq!(
            find_calls().as_slice(),
            &[(f.addr(MAP2), KEY), (f.addr(MAP2), KEY)]
        );
    }

    #[test]
    fn empty_value_in_both_returns_zero() {
        let (_guard, _seam) = lock();
        let Some(f) = Fixture::map() else {
            assert!(note_missing_u32_fixture("app/string_table"));
            return;
        };
        f.set_index(0);
        unsafe { install(&[f.addr(NODE_B), f.addr(NODE_B)]) };
        let result = unsafe { string_table_has_string(f.base, KEY as *const u32) };
        assert_eq!(result, 0);
    }

    #[test]
    fn empty_fallback_value_returns_zero() {
        let (_guard, _seam) = lock();
        let Some(f) = Fixture::map() else {
            assert!(note_missing_u32_fixture("app/string_table"));
            return;
        };
        f.set_index(1);
        unsafe { install(&[f.addr(HEADER1), f.addr(NODE_B)]) };
        let result = unsafe { string_table_has_string(f.base, KEY as *const u32) };
        assert_eq!(result, 0);
    }

    #[test]
    fn current_index_selects_the_map() {
        let (_guard, _seam) = lock();
        let Some(f) = Fixture::map() else {
            assert!(note_missing_u32_fixture("app/string_table"));
            return;
        };
        for index in 0..3u32 {
            f.set_index(index);
            let header = [HEADER0, HEADER1, HEADER2][index as usize];
            // Miss everywhere: isolate the map address each index picks.
            unsafe { install(&[f.addr(header), f.addr(HEADER2)]) };
            let result = unsafe { string_table_has_string(f.base, KEY as *const u32) };
            assert_eq!(result, 0);
            assert_eq!(
                find_calls().as_slice(),
                &[
                    (f.addr(TABLE_STRIDE * index as usize), KEY),
                    (f.addr(MAP2), KEY)
                ],
                "index {index}"
            );
        }
    }

    #[test]
    fn index_word_is_reloaded_across_the_first_find() {
        let (_guard, _seam) = lock();
        let Some(f) = Fixture::map() else {
            assert!(note_missing_u32_fixture("app/string_table"));
            return;
        };
        f.set_index(0);
        // The original re-reads this + 0x54 after the first find call
        // for the header compare. Script find to bump the index to 1
        // and to return table[1]'s header as the "found" node: with the
        // reload this reads as a miss (node == header) and the fallback
        // runs; without it the stale index-0 header compares unequal
        // and the port would wrongly probe node + 0x14 as a hit.
        unsafe {
            install(&[f.addr(HEADER1), f.addr(NODE_A)]);
            FIND_SETS_INDEX = Some((f.base, 1));
        };
        let result = unsafe { string_table_has_string(f.base, KEY as *const u32) };
        assert_eq!(result, 1);
        assert_eq!(
            find_calls().as_slice(),
            &[(f.addr(MAP0), KEY), (f.addr(MAP2), KEY)]
        );
    }

    #[test]
    fn short_circuit_never_probes_value_on_a_miss() {
        let (_guard, _seam) = lock();
        let Some(f) = Fixture::map() else {
            assert!(note_missing_u32_fixture("app/string_table"));
            return;
        };
        f.set_index(0);
        // A miss hands back the header node, and the port must not
        // even evaluate string_empty on that path — the original
        // branches away first. Prove the short-circuit by counting
        // empty probes.
        static mut EMPTY_CALLS: u32 = 0;
        unsafe extern "C" fn counting_empty(string: *const u32) -> u32 {
            EMPTY_CALLS += 1;
            mock_string_empty(string)
        }
        unsafe {
            EMPTY_CALLS = 0;
            install(&[f.addr(HEADER0), f.addr(NODE_A)]);
            ptr::write_volatile(
                ptr::addr_of_mut!(STRING_TABLE_OPS),
                StringTableOps {
                    find: mock_find,
                    iter_eq: mock_iter_eq,
                    string_empty: counting_empty,
                },
            );
        }
        let result = unsafe { string_table_has_string(f.base, KEY as *const u32) };
        assert_eq!(result, 1);
        // One probe total: the fallback hit. The current-table miss
        // must not have probed.
        unsafe { assert_eq!(EMPTY_CALLS, 1) };
    }

}
