//! SQLite statement-LRU unlink — `stmtLruRemove` from `vdbeapi.c`.
//!
//! `stmt_lru_remove` — original: `FUN_08391d64` @ `0x08391d64`
//! (104 bytes; **4 direct `bl` call sites, all unconditional, zero
//! predicated** — verified by decoding every ARM `BL` immediate word in
//! `osos.dec`: `0x08384b94`, `0x083906e4`, `0x0839107c`, `0x083974d4`).
//!
//! Raw `osos.dec` disassembly confirms the body is exactly
//! `0x08391d64..0x08391dc8` (26 words); the word at `0x08391dcc` is this
//! function's own literal pool (the anchor address `0x08a09944`) and the
//! separately linked statement-name hasher begins at `0x08391dec`.
//!
//! SQLite keeps every prepared `Vdbe` on a global doubly linked LRU for
//! statement-memory reclamation: links at `+0x150` (previous) and `+0x154`
//! (next), head and tail in the two-word anchor `0x08a09944`/`0x08a09948`
//! (shared with the unported insertion sibling `FUN_083910a4` and the
//! reclaim walk `FUN_0839100c`, which load the same literal — scanning the
//! image for `44 99 a0 08` finds exactly three pool words). This function
//! splices one statement out:
//!
//! - both links null: if the anchor head is not this statement, return
//!   without touching anything (orphan); otherwise clear the tail;
//! - next non-null: `next->prev = prev`;
//! - next null (with prev non-null): tail = prev;
//! - then, from a *reloaded* prev: prev null -> head = next, else
//!   `prev->next = next`;
//! - finally both link words of the statement are cleared.
//!
//! The reload of `prev` after the first half is in the original
//! (`ldr r1,[r0,#0x150]` at `0x08391da4`) and is preserved.
//!
//! Deliberate deviations: the anchor is reached through the fixed runtime
//! address on target (the unported siblings still use it); host builds use
//! a crate-owned stand-in word pair. Statement pointers are manipulated as
//! raw target-layout words, not as `Vdbe` struct fields, matching
//! `pcache_remove_from_lru_list`.

/// `Vdbe` offset of the LRU previous-statement link.
const VDBE_LRU_PREV: usize = 0x150;
/// `Vdbe` offset of the LRU next-statement link.
const VDBE_LRU_NEXT: usize = 0x154;

/// RetailOS runtime address of the statement-LRU anchor: head word at
/// `0x08a09944`, tail word at `0x08a09948`.
#[cfg(target_os = "none")]
const LRU_ANCHOR_ADDRESS: usize = 0x08a0_9944;

/// Host stand-in for the retail anchor word pair.
#[cfg(not(target_os = "none"))]
static mut LRU_ANCHOR: [u32; 2] = [0; 2];

#[inline(always)]
unsafe fn lru_anchor() -> *mut u8 {
    #[cfg(target_os = "none")]
    {
        LRU_ANCHOR_ADDRESS as *mut u8
    }
    #[cfg(not(target_os = "none"))]
    {
        core::ptr::addr_of_mut!(LRU_ANCHOR).cast::<u8>()
    }
}

#[inline(always)]
unsafe fn read_target_pointer(base: *const u8, offset: usize) -> *mut u8 {
    unsafe { base.add(offset).cast::<u32>().read() as usize as *mut u8 }
}

#[inline(always)]
unsafe fn write_target_pointer(base: *mut u8, offset: usize, value: *mut u8) {
    unsafe { base.add(offset).cast::<u32>().write(value as usize as u32) };
}

#[inline(always)]
unsafe fn lru_head() -> *mut u8 {
    unsafe { read_target_pointer(lru_anchor(), 0) }
}

#[inline(always)]
unsafe fn set_lru_head(head: *mut u8) {
    unsafe { write_target_pointer(lru_anchor(), 0, head) };
}

#[inline(always)]
unsafe fn set_lru_tail(tail: *mut u8) {
    unsafe { write_target_pointer(lru_anchor(), 4, tail) };
}

/// `stmtLruRemove` — original: `FUN_08391d64` @ `0x08391d64` (104 bytes;
/// 4 direct `bl` call sites, all unconditional).
///
/// Detaches `statement` from SQLite's global statement-memory LRU. An
/// orphan statement (both links null, not the anchor head) is left
/// completely untouched. Every other case requires valid writable
/// target-layout link words at `+0x150`/`+0x154` and, when a neighbour is
/// non-null, in that neighbour.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.stmt_lru_remove")]
pub unsafe extern "C" fn stmt_lru_remove(statement: *mut u8) {
    let prev = unsafe { read_target_pointer(statement, VDBE_LRU_PREV) };
    let next = unsafe { read_target_pointer(statement, VDBE_LRU_NEXT) };
    if prev.is_null() && next.is_null() {
        if unsafe { lru_head() } != statement {
            return;
        }
        unsafe { set_lru_tail(prev) };
    } else if !next.is_null() {
        unsafe { write_target_pointer(next, VDBE_LRU_PREV, prev) };
    } else {
        unsafe { set_lru_tail(prev) };
    }

    let prev = unsafe { read_target_pointer(statement, VDBE_LRU_PREV) };
    let next = unsafe { read_target_pointer(statement, VDBE_LRU_NEXT) };
    if prev.is_null() {
        unsafe { set_lru_head(next) };
    } else {
        unsafe { write_target_pointer(prev, VDBE_LRU_NEXT, next) };
    }
    unsafe { write_target_pointer(statement, VDBE_LRU_NEXT, core::ptr::null_mut()) };
    unsafe { write_target_pointer(statement, VDBE_LRU_PREV, core::ptr::null_mut()) };
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use core::ptr;
    use std::sync::{LazyLock, Mutex, MutexGuard};

    const FIXTURE_LEN: usize = 0x1000;
    const HEAD_OFFSET: usize = 0x200;
    const MIDDLE_OFFSET: usize = 0x300;
    const TAIL_OFFSET: usize = 0x400;

    static FIXTURE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::SQLITE_STMT_LRU_REMOVE, FIXTURE_LEN)
            .map(|pointer| pointer as usize)
    });
    static FIXTURE_LOCK: Mutex<()> = Mutex::new(());

    fn fixture() -> Option<(*mut u8, MutexGuard<'static, ()>)> {
        let guard = FIXTURE_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let base = (*FIXTURE)? as *mut u8;
        unsafe { ptr::write_bytes(base, 0, FIXTURE_LEN) };
        unsafe { ptr::write_bytes(core::ptr::addr_of_mut!(LRU_ANCHOR), 0, 1) };
        Some((base, guard))
    }

    unsafe fn node(base: *mut u8, offset: usize) -> *mut u8 {
        unsafe { base.add(offset) }
    }

    unsafe fn word(base: *const u8, offset: usize) -> u32 {
        unsafe { base.add(offset).cast::<u32>().read() }
    }

    unsafe fn set_pointer(base: *mut u8, offset: usize, value: *mut u8) {
        unsafe { base.add(offset).cast::<u32>().write(value as usize as u32) };
    }

    unsafe fn link(node: *mut u8, prev: *mut u8, next: *mut u8) {
        unsafe {
            set_pointer(node, VDBE_LRU_PREV, prev);
            set_pointer(node, VDBE_LRU_NEXT, next);
        }
    }

    unsafe fn anchor(head: *mut u8, tail: *mut u8) {
        unsafe {
            set_lru_head(head);
            set_lru_tail(tail);
        }
    }

    unsafe fn head_word() -> u32 {
        unsafe { word(lru_anchor(), 0) }
    }

    unsafe fn tail_word() -> u32 {
        unsafe { word(lru_anchor(), 4) }
    }

    /// Three-node list: head <-> middle <-> tail, anchor set.
    unsafe fn three_node_list(base: *mut u8) -> (*mut u8, *mut u8, *mut u8) {
        let head = unsafe { node(base, HEAD_OFFSET) };
        let middle = unsafe { node(base, MIDDLE_OFFSET) };
        let tail = unsafe { node(base, TAIL_OFFSET) };
        unsafe {
            link(head, ptr::null_mut(), middle);
            link(middle, head, tail);
            link(tail, middle, ptr::null_mut());
            anchor(head, tail);
        }
        (head, middle, tail)
    }

    #[test]
    fn middle_node_splices_neighbours_and_clears_own_links() {
        let Some((base, _guard)) = fixture() else {
            assert!(note_missing_u32_fixture(module_path!()));
            return;
        };
        let (head, middle, tail) = unsafe { three_node_list(base) };
        unsafe { stmt_lru_remove(middle) };
        unsafe {
            assert_eq!(word(head, VDBE_LRU_NEXT), tail as usize as u32);
            assert_eq!(word(tail, VDBE_LRU_PREV), head as usize as u32);
            assert_eq!(word(middle, VDBE_LRU_PREV), 0);
            assert_eq!(word(middle, VDBE_LRU_NEXT), 0);
            assert_eq!(head_word(), head as usize as u32);
            assert_eq!(tail_word(), tail as usize as u32);
        }
    }

    #[test]
    fn head_node_moves_anchor_head_and_nulls_next_prev() {
        let Some((base, _guard)) = fixture() else {
            assert!(note_missing_u32_fixture(module_path!()));
            return;
        };
        let (head, middle, tail) = unsafe { three_node_list(base) };
        unsafe { stmt_lru_remove(head) };
        unsafe {
            assert_eq!(head_word(), middle as usize as u32);
            assert_eq!(word(middle, VDBE_LRU_PREV), 0);
            assert_eq!(word(head, VDBE_LRU_PREV), 0);
            assert_eq!(word(head, VDBE_LRU_NEXT), 0);
            assert_eq!(tail_word(), tail as usize as u32);
            assert_eq!(word(middle, VDBE_LRU_NEXT), tail as usize as u32);
        }
    }

    #[test]
    fn tail_node_moves_anchor_tail_and_nulls_prev_next() {
        let Some((base, _guard)) = fixture() else {
            assert!(note_missing_u32_fixture(module_path!()));
            return;
        };
        let (head, middle, tail) = unsafe { three_node_list(base) };
        unsafe { stmt_lru_remove(tail) };
        unsafe {
            assert_eq!(tail_word(), middle as usize as u32);
            assert_eq!(word(middle, VDBE_LRU_NEXT), 0);
            assert_eq!(word(tail, VDBE_LRU_PREV), 0);
            assert_eq!(word(tail, VDBE_LRU_NEXT), 0);
            assert_eq!(head_word(), head as usize as u32);
        }
    }

    #[test]
    fn only_node_empties_anchor() {
        let Some((base, _guard)) = fixture() else {
            assert!(note_missing_u32_fixture(module_path!()));
            return;
        };
        let only = unsafe { node(base, MIDDLE_OFFSET) };
        unsafe {
            link(only, ptr::null_mut(), ptr::null_mut());
            anchor(only, only);
            stmt_lru_remove(only);
            assert_eq!(head_word(), 0);
            assert_eq!(tail_word(), 0);
            assert_eq!(word(only, VDBE_LRU_PREV), 0);
            assert_eq!(word(only, VDBE_LRU_NEXT), 0);
        }
    }

    #[test]
    fn orphan_node_is_left_untouched() {
        let Some((base, _guard)) = fixture() else {
            assert!(note_missing_u32_fixture(module_path!()));
            return;
        };
        let (head, _middle, tail) = unsafe { three_node_list(base) };
        let orphan = unsafe { node(base, 0x600) };
        unsafe {
            link(orphan, ptr::null_mut(), ptr::null_mut());
            stmt_lru_remove(orphan);
            // Early return: anchor and the whole list must be byte-identical.
            assert_eq!(head_word(), head as usize as u32);
            assert_eq!(tail_word(), tail as usize as u32);
            assert_eq!(word(head, VDBE_LRU_PREV), 0);
            assert_eq!(word(head, VDBE_LRU_NEXT), MIDDLE_OFFSET as u32 + base as usize as u32);
            assert_eq!(word(tail, VDBE_LRU_NEXT), 0);
        }
    }
}
