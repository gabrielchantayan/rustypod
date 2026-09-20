//! Constructing a one-item SQLite source list from a table descriptor.
//!
//! - `src_list_from_table` — original: `FUN_08393b10` @ 0x08393b10.
//!   Raw `osos.dec` establishes the exact 116-byte body
//!   `0x08393b10..0x08393b84`; the next separately linked function starts at
//!   `0x08393b84`. It has three unconditional direct `bl` instructions
//!   (`sqlite3SchemaToIndex`, `strlen`, and `sqlite3SrcListAppend`) and no
//!   predicated `bl` instructions.
//!
//! The wrapper maps a table schema to its database slot. Slots below two keep
//! the caller's database token; later attached databases synthesize one from
//! `aDb[i].zName`, preserving the caller's Token dynamic bit. It then invokes
//! SQLite's source-list appender with no pre-existing list. Deliberate
//! deviation: the unported appender at 0x083841ec remains a volatile seam;
//! target builds call its verified retail entry and host builds require a test
//! model.

use super::schema_to_index::schema_to_index;

const WORD: usize = core::mem::size_of::<*const u8>();
const TABLE_SCHEMA_OWNER_INDEX: usize = 2;
const SCHEMA_OWNER_SCHEMA_INDEX: usize = 7;
const TABLE_NAME_TOKEN_OFFSET: usize = 4;
const DB_ARRAY_INDEX: usize = 2;
const DB_ENTRY_SIZE: usize = 0x18;

pub type SrcListAppendFn = unsafe extern "C" fn(*mut u8, *mut u8, *const u8, *const u8) -> *mut u8;

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_src_list_append(parse: *mut u8, list: *mut u8, table: *const u8, database: *const u8) -> *mut u8 {
    core::mem::transmute::<usize, SrcListAppendFn>(0x0838_41ec)(parse, list, table, database)
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_src_list_append(_: *mut u8, _: *mut u8, _: *const u8, _: *const u8) -> *mut u8 {
    panic!("src_list_from_table requires sqlite3SrcListAppend @ 0x083841ec")
}
#[cfg(target_os = "none")]
pub static mut SQLITE_SRC_LIST_APPEND: SrcListAppendFn = retail_src_list_append;
#[cfg(not(target_os = "none"))]
pub static mut SQLITE_SRC_LIST_APPEND: SrcListAppendFn = missing_src_list_append;

#[inline(always)]
unsafe fn src_list_append_op() -> SrcListAppendFn {
    core::ptr::read_volatile(core::ptr::addr_of!(SQLITE_SRC_LIST_APPEND))
}

/// `src_list_from_table` — original: `FUN_08393b10` @ 0x08393b10 (116 bytes;
/// 3 direct `bl` calls, all unconditional).
///
/// Builds the database token required by `sqlite3SrcListAppend` when `table`'s
/// schema belongs to an attached database, then returns the one-item list.
/// All pointers must meet the retail readable-pointer contract.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn src_list_from_table(parse: *mut u8, table: *mut u8, table_token: *const u8, token_dynamic: u32) -> *mut u8 {
    let db = (parse as *const *mut u8).read();
    let schema_owner = (table.add(TABLE_SCHEMA_OWNER_INDEX * WORD) as *const *const u8).read();
    let schema = (schema_owner.add(SCHEMA_OWNER_SCHEMA_INDEX * WORD) as *const *const u8).read();
    let index = schema_to_index(db, schema);
    let database_token = if index < 2 {
        table_token
    } else {
        let db_array = (db.add(DB_ARRAY_INDEX * 4) as *const u32).read() as usize as *const u8;
        let database_name = (db_array.add(index as usize * DB_ENTRY_SIZE) as *const *const u8).read();
        let mut token = [database_name as usize, ((crate::libc::strlen::strlen(database_name) as u32) << 1 | (token_dynamic & 1)) as usize];
        return src_list_append_op()(parse, core::ptr::null_mut(), token.as_mut_ptr().cast(), table.add(TABLE_NAME_TOKEN_OFFSET * WORD));
    };
    src_list_append_op()(parse, core::ptr::null_mut(), database_token, table.add(TABLE_NAME_TOKEN_OFFSET * WORD))
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut SEEN: (*const u8, *const u8) = (core::ptr::null(), core::ptr::null());
    unsafe extern "C" fn record(_: *mut u8, _: *mut u8, database: *const u8, table: *const u8) -> *mut u8 {
        SEEN = (database, table);
        0x1234usize as *mut u8
    }

    #[test]
    fn transient_schema_preserves_the_callers_database_token() {
        let _guard = LOCK.lock();
        unsafe {
            let saved = SQLITE_SRC_LIST_APPEND;
            SQLITE_SRC_LIST_APPEND = record;
            let mut parse = [0usize; 1];
            let mut owner = [0usize; 8];
            let mut table = [0usize; 6];
            table[2] = owner.as_mut_ptr() as usize;
            let token = [0x11usize, 0x22usize];
            assert_eq!(src_list_from_table(parse.as_mut_ptr().cast(), table.as_mut_ptr().cast(), token.as_ptr().cast(), 1), 0x1234usize as *mut u8);
            assert_eq!(SEEN.0, token.as_ptr().cast());
            assert_eq!(SEEN.1, table.as_ptr().add(4).cast());
            SQLITE_SRC_LIST_APPEND = saved;
        }
    }
}
