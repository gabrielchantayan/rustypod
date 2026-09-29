//! SQLite 3.5.x outer-join expression annotation.
//!
//! `expr_set_join_table` — retailOS `FUN_08368f40` @ `0x08368f40` (60 bytes,
//! `0x08368f40..0x08368f7b`). Raw `osos.dec` establishes the next function at
//! `0x08368f7c`. Whole-image A32 branch decoding finds two target call sites:
//! one plain `bl` (the recursive call at `0x08368f68`) and one predicated
//! `blne` (`0x08391b24`). SQLite's `setJoinExpr` walks an expression's
//! right-child chain, sets `EP_FromJoin` at `+0x02`, records the supplied
//! right-join cursor at `+0x34`, and recursively annotates left children at
//! `+0x08`.
//!
//! # Deliberate deviations
//!
//! Target pointers are represented as `u32` words and offsets are word
//! indices, preserving the retail 32-bit layout on 64-bit host tests.

const FLAGS_OFFSET: usize = 2;
const LEFT_WORD: usize = 2;
const RIGHT_WORD: usize = 3;
const RIGHT_JOIN_TABLE_WORD: usize = 13;
const EP_FROM_JOIN: u16 = 1;

/// Marks an expression hierarchy as originating from an outer join.
///
/// # Safety
///
/// Every nonzero target-word expression address must be a valid aligned
/// writable expression record with readable child words at `+0x08` and
/// `+0x0c`, and a writable right-join-table word at `+0x34`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.expr_set_join_table")]
pub unsafe extern "C" fn expr_set_join_table(mut expr: u32, right_join_table: u32) {
    while expr != 0 {
        let node = expr as usize as *mut u32;
        unsafe {
            let flags = node.cast::<u8>().add(FLAGS_OFFSET).cast::<u16>();
            flags.write_volatile(flags.read_volatile() | EP_FROM_JOIN);
            node.add(RIGHT_JOIN_TABLE_WORD).write_volatile(right_join_table);
            expr_set_join_table(node.add(LEFT_WORD).read_volatile(), right_join_table);
            expr = node.add(RIGHT_WORD).read_volatile();
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::expr_set_join_table;
    use crate::testing::{hints, try_map_u32_slab};
    use parking_lot::Mutex;
    use std::sync::LazyLock;

    const WORDS: usize = 0x1000;
    const ROOT: usize = 16;
    const LEFT: usize = 32;
    const RIGHT: usize = 48;
    const LEFT_LEFT: usize = 64;
    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::SQLITE_EXPR_SET_JOIN_TABLE, WORDS * core::mem::size_of::<u32>())
            .map(|pointer| pointer as usize)
    });
    static LOCK: Mutex<()> = Mutex::new(());

    fn slab() -> Option<*mut u32> {
        (*SLAB).map(|address| address as *mut u32)
    }

    #[test]
    fn null_expression_leaves_fixture_unchanged() {
        let _lock = LOCK.lock();
        let Some(base) = slab() else { return };
        unsafe {
            base.add(ROOT).write(0xa5a5_5a5a);
            expr_set_join_table(0, 17);
            assert_eq!(base.add(ROOT).read(), 0xa5a5_5a5a);
        }
    }

    #[test]
    fn marks_right_chain_and_left_subtrees_without_clobbering_other_flag_bits() {
        let _lock = LOCK.lock();
        let Some(base) = slab() else { return };
        unsafe {
            for index in [ROOT, LEFT, RIGHT, LEFT_LEFT] {
                base.add(index).write(0xa5a4_5a5a);
                base.add(index + 2).write(0);
                base.add(index + 3).write(0);
                base.add(index + 13).write(0xdead_beef);
            }
            base.add(ROOT + 2).write(base.add(LEFT) as usize as u32);
            base.add(ROOT + 3).write(base.add(RIGHT) as usize as u32);
            base.add(LEFT + 2).write(base.add(LEFT_LEFT) as usize as u32);

            expr_set_join_table(base.add(ROOT) as usize as u32, 0x1234_5678);

            for index in [ROOT, LEFT, RIGHT, LEFT_LEFT] {
                assert_eq!(base.add(index).read(), 0xa5a5_5a5a);
                assert_eq!(base.add(index + 13).read(), 0x1234_5678);
            }
        }
    }
}
