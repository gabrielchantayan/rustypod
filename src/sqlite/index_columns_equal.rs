//! Equality of SQLite index key definitions.
//!
//! `index_columns_equal` — original: `FUN_08398d4c` @ 0x08398d4c, 132 bytes;
//! two inbound direct `bl` sites (both unconditional, none predicated), and no
//! outbound `bl` instructions. Raw `osos.dec` establishes the exact extent
//! `0x08398d4c..0x08398dd0`.
//!
//! Algorithm: require equal `Index.nColumn` (+0x04) and `onError` (+0x18),
//! then compare every `aiColumn` word (+0x08), collation-name byte (+0x28),
//! and collation sequence word (+0x2c). The count is a signed loop bound: a
//! zero or negative equal count succeeds without dereferencing either array.
//!
//! Deliberate deviation: target-layout fields and nested pointers are read by
//! their recovered byte offsets as u32 words. This preserves the 32-bit ARM
//! layout on 64-bit hosts, where native pointers would otherwise widen.

const INDEX_N_COLUMN_OFFSET: usize = 0x04;
const INDEX_ON_ERROR_OFFSET: usize = 0x18;
const INDEX_AI_COLUMN_OFFSET: usize = 0x08;
const INDEX_COLLATION_NAME_OFFSET: usize = 0x28;
const INDEX_COLLATION_SEQUENCE_OFFSET: usize = 0x2c;

/// index_columns_equal — original: `FUN_08398d4c` @ 0x08398d4c.
///
/// # Safety
/// `left` and `right` must name target-layout SQLite `Index` objects. When
/// their equal `nColumn` values are positive, their three recovered arrays
/// must each be valid for that many entries.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn index_columns_equal(
    left: *const u8,
    right: *const u8,
    _unused: u32,
    _unused_flags: u32,
) -> u32 {
    let left_count = (left.add(INDEX_N_COLUMN_OFFSET) as *const i32).read();
    let right_count = (right.add(INDEX_N_COLUMN_OFFSET) as *const i32).read();
    if left_count != right_count
        || left.add(INDEX_ON_ERROR_OFFSET).read() != right.add(INDEX_ON_ERROR_OFFSET).read()
    {
        return 0;
    }

    let left_columns = (left.add(INDEX_AI_COLUMN_OFFSET) as *const u32).read() as usize as *const u32;
    let right_columns = (right.add(INDEX_AI_COLUMN_OFFSET) as *const u32).read() as usize as *const u32;
    let left_collation_names = (left.add(INDEX_COLLATION_NAME_OFFSET) as *const u32).read() as usize as *const u8;
    let right_collation_names = (right.add(INDEX_COLLATION_NAME_OFFSET) as *const u32).read() as usize as *const u8;
    let left_collation_sequences = (left.add(INDEX_COLLATION_SEQUENCE_OFFSET) as *const u32).read() as usize as *const u32;
    let right_collation_sequences = (right.add(INDEX_COLLATION_SEQUENCE_OFFSET) as *const u32).read() as usize as *const u32;

    for index in 0..left_count {
        let index = index as usize;
        if left_columns.add(index).read() != right_columns.add(index).read()
            || left_collation_names.add(index).read() != right_collation_names.add(index).read()
            || left_collation_sequences.add(index).read() != right_collation_sequences.add(index).read()
        {
            return 0;
        }
    }
    1
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::{
        index_columns_equal, INDEX_AI_COLUMN_OFFSET, INDEX_COLLATION_NAME_OFFSET,
        INDEX_COLLATION_SEQUENCE_OFFSET, INDEX_N_COLUMN_OFFSET, INDEX_ON_ERROR_OFFSET,
    };
    use crate::testing::{hints, try_map_u32_slab};
    use std::sync::LazyLock;
    const LEFT_INDEX: usize = 0x000;
    const RIGHT_INDEX: usize = 0x040;
    const LEFT_COLUMNS: usize = 0x100;
    const RIGHT_COLUMNS: usize = 0x120;
    const LEFT_NAMES: usize = 0x140;
    const RIGHT_NAMES: usize = 0x150;
    const LEFT_SEQUENCES: usize = 0x160;
    const RIGHT_SEQUENCES: usize = 0x180;

    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::SQLITE_INDEX_COLUMNS_EQUAL, 0x1000).map(|p| p as usize)
    });

    unsafe fn word(base: *mut u8, offset: usize) -> *mut u32 { base.add(offset).cast() }

    unsafe fn initialize(base: *mut u8, count: i32, on_error: u8) {
        core::ptr::write_bytes(base, 0, 0x1000);
        word(base, LEFT_INDEX + INDEX_N_COLUMN_OFFSET).write(count as u32);
        word(base, RIGHT_INDEX + INDEX_N_COLUMN_OFFSET).write(count as u32);
        base.add(LEFT_INDEX + INDEX_ON_ERROR_OFFSET).write(on_error);
        base.add(RIGHT_INDEX + INDEX_ON_ERROR_OFFSET).write(on_error);
        word(base, LEFT_INDEX + INDEX_AI_COLUMN_OFFSET).write((base.add(LEFT_COLUMNS)) as usize as u32);
        word(base, RIGHT_INDEX + INDEX_AI_COLUMN_OFFSET).write((base.add(RIGHT_COLUMNS)) as usize as u32);
        word(base, LEFT_INDEX + INDEX_COLLATION_NAME_OFFSET).write((base.add(LEFT_NAMES)) as usize as u32);
        word(base, RIGHT_INDEX + INDEX_COLLATION_NAME_OFFSET).write((base.add(RIGHT_NAMES)) as usize as u32);
        word(base, LEFT_INDEX + INDEX_COLLATION_SEQUENCE_OFFSET).write((base.add(LEFT_SEQUENCES)) as usize as u32);
        word(base, RIGHT_INDEX + INDEX_COLLATION_SEQUENCE_OFFSET).write((base.add(RIGHT_SEQUENCES)) as usize as u32);
        for index in 0..count.max(0) as usize {
            word(base, LEFT_COLUMNS + index * 4).write(index as u32 + 4);
            word(base, RIGHT_COLUMNS + index * 4).write(index as u32 + 4);
            base.add(LEFT_NAMES + index).write(b'B' + index as u8);
            base.add(RIGHT_NAMES + index).write(b'B' + index as u8);
            word(base, LEFT_SEQUENCES + index * 4).write(0x1000 + index as u32);
            word(base, RIGHT_SEQUENCES + index * 4).write(0x1000 + index as u32);
        }
    }

    #[test]
    fn compares_every_recovered_index_key_field() {
        let Some(base) = *SLAB else { return };
        unsafe {
            let base = base as *mut u8;
            initialize(base, 3, 2);
            assert_eq!(index_columns_equal(base.add(LEFT_INDEX), base.add(RIGHT_INDEX), 0, 0), 1);
            word(base, RIGHT_COLUMNS + 4).write(99);
            assert_eq!(index_columns_equal(base.add(LEFT_INDEX), base.add(RIGHT_INDEX), 0, 0), 0);
            initialize(base, 3, 2);
            base.add(RIGHT_NAMES + 2).write(b'Z');
            assert_eq!(index_columns_equal(base.add(LEFT_INDEX), base.add(RIGHT_INDEX), 0, 0), 0);
            initialize(base, 3, 2);
            word(base, RIGHT_SEQUENCES + 8).write(0xbeef);
            assert_eq!(index_columns_equal(base.add(LEFT_INDEX), base.add(RIGHT_INDEX), 0, 0), 0);
        }
    }

    #[test]
    fn rejects_header_mismatches_and_accepts_nonpositive_equal_counts() {
        let Some(base) = *SLAB else { return };
        unsafe {
            let base = base as *mut u8;
            initialize(base, 1, 2);
            word(base, RIGHT_INDEX + INDEX_N_COLUMN_OFFSET).write(2);
            assert_eq!(index_columns_equal(base.add(LEFT_INDEX), base.add(RIGHT_INDEX), 0, 0), 0);
            initialize(base, 1, 2);
            base.add(RIGHT_INDEX + INDEX_ON_ERROR_OFFSET).write(3);
            assert_eq!(index_columns_equal(base.add(LEFT_INDEX), base.add(RIGHT_INDEX), 0, 0), 0);
            initialize(base, 0, 2);
            assert_eq!(index_columns_equal(base.add(LEFT_INDEX), base.add(RIGHT_INDEX), 0, 0), 1);
            initialize(base, -1, 2);
            assert_eq!(index_columns_equal(base.add(LEFT_INDEX), base.add(RIGHT_INDEX), 0, 0), 1);
        }
    }
}
