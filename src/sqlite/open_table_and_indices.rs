//! SQLite's table-and-index cursor opener.
//!
//! `open_table_and_indices` — original: `FUN_0837d99c` @ `0x0837d99c`.
//! Raw `osos.dec` words establish the 184-byte extent
//! `0x0837d99c..0x0837da54`; the next separately linked function begins at
//! `0x0837da54`. It contains five unconditional plain `bl` instructions and
//! no predicated `bl`: `schema_to_index`, `sqlite3GetVdbe`, `open_table`,
//! `index_key_info`, and `vdbe_add_op4`. There are three inbound direct-call
//! sites (at `0x08374ae0`, `0x0837b9ec`, and `0x0837f25c`).
//!
//! SQLite 3.5's `sqlite3OpenTableAndIndices`: virtual tables return zero.
//! For ordinary tables it maps the schema to a database index, opens the table
//! at `base`, then emits one cursor-opening opcode per linked index, handing
//! each newly allocated `KeyInfo` to the VDBE. Finally it raises `Parse.nTab`
//! to cover the table and all index cursors and returns the index count.
//!
//! Deliberate deviation: `sqlite3GetVdbe` has no Rust export despite its
//! ledger status. As in `open_table`, this reads the already-stored target
//! `Parse.pVdbe`; NULL is preserved and the operation emitters retain their
//! existing OOM behavior.

use crate::sqlite::index_key_info::index_key_info;
use crate::sqlite::open_table::{open_table, Parse as OpenTableParse, Table as OpenTable};
use crate::sqlite::schema_to_index::schema_to_index;
use crate::sqlite::vdbe::{vdbe_add_op4, Vdbe};

const TABLE_INDEX_OFFSET: usize = 0x10;
const TABLE_SCHEMA_OFFSET: usize = 0x4c;
const TABLE_IS_VIRTUAL_OFFSET: usize = 0x39;
const INDEX_TNUM_OFFSET: usize = 0x14;
const INDEX_NEXT_OFFSET: usize = 0x20;
const PARSE_DB_OFFSET: usize = 0x00;
const PARSE_VDBE_OFFSET: usize = 0x0c;
const PARSE_N_TAB_OFFSET: usize = 0x44;
const P4_KEYINFO_HANDOFF: i32 = -9;

/// sqlite3OpenTableAndIndices — original: `FUN_0837d99c` @ `0x0837d99c`
/// (184 bytes; five unconditional direct `bl` instructions).
///
/// # Safety
/// `parse` and `table` must be target-layout SQLite objects. Pointer fields
/// are target-width words, so host fixtures must reside below 4 GiB. For an
/// ordinary table, each linked `Index` must expose `tnum` at +0x14 and `pNext`
/// at +0x20; `parse` must hold a valid VDBE at +0x0c.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn open_table_and_indices(
    parse: *mut u8,
    table: *mut u8,
    base: i32,
    opcode: i32,
) -> i32 {
    if table.add(TABLE_IS_VIRTUAL_OFFSET).read() != 0 {
        return 0;
    }

    let db = parse.add(PARSE_DB_OFFSET).cast::<u32>().read() as usize as *const u8;
    let schema = table.add(TABLE_SCHEMA_OFFSET).cast::<u32>().read() as usize as *const u8;
    let database_index = schema_to_index(db, schema);
    open_table(
        parse.cast::<OpenTableParse>(),
        base,
        database_index,
        table.cast::<OpenTable>(),
        opcode,
    );

    let vdbe = parse.add(PARSE_VDBE_OFFSET).cast::<u32>().read() as usize as *mut Vdbe;
    let mut index = table.add(TABLE_INDEX_OFFSET).cast::<u32>().read() as usize as *mut u8;
    let mut count = 0i32;
    while !index.is_null() {
        let key_info = index_key_info(parse, index);
        vdbe_add_op4(
            vdbe,
            opcode,
            base.wrapping_add(count).wrapping_add(1),
            index.add(INDEX_TNUM_OFFSET).cast::<i32>().read(),
            database_index,
            key_info,
            P4_KEYINFO_HANDOFF,
        );
        index = index.add(INDEX_NEXT_OFFSET).cast::<u32>().read() as usize as *mut u8;
        count = count.wrapping_add(1);
    }

    let n_tab = parse.add(PARSE_N_TAB_OFFSET).cast::<i32>();
    let needed = base.wrapping_add(count).wrapping_add(1);
    if n_tab.read() <= needed {
        n_tab.write(needed);
    }
    count
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, try_map_u32_slab};
    use parking_lot::Mutex;
    use std::sync::LazyLock;

    static SLAB_LOCK: Mutex<()> = Mutex::new(());
    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::SQLITE_OPEN_TABLE_AND_INDICES, 0x1000).map(|p| p as usize)
    });
    #[test]
    fn virtual_table_returns_zero_without_reading_parse() {
        let _lock = SLAB_LOCK.lock();
        let Some(address) = *SLAB else { return };
        let table = address as *mut u8;
        unsafe {
            core::ptr::write_bytes(table, 0xa5, 0x1000);
            table.add(TABLE_IS_VIRTUAL_OFFSET).write(1);
            assert_eq!(open_table_and_indices(core::ptr::null_mut(), table, -7, 9), 0);
        }
    }
}
