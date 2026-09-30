//! SQLite virtual-table argument extension.
//!
//! `vtab_arg_extend` — `FUN_082b2c50` @ **0x082b2c50**, 68 bytes
//! (`0x082b2c50..0x082b2c94`). Raw-word decoding finds two inbound plain
//! BL sites (0x0838d4e8, 0x0839b594), one outbound plain BL, and no
//! predicated BL. The next independently called function begins at
//! 0x082b2c94; the restored-stack fall-through is a tail call to it.
//! If Parse.sArg.z or Parse.pNewTable is NULL, do nothing. Otherwise
//! duplicate the argument using its packed token length shifted right one,
//! then append the owned copy to the table's NULL-terminated argument array.
//! Deliberate deviations: explicit u32 pointer words preserve target layout
//! on hosts; the ARM fall-through is an ordinary final call to the existing
//! append helper. Both callees are existing ports, with no new dispatch seam.

use super::append_owned_pointer::append_owned_pointer;
use super::strdup::db_str_ndup;

const NEW_TABLE_WORD: usize = 0x180 / 4;
const ARG_TEXT_WORD: usize = 0x190 / 4;
const ARG_PACKED_WORD: usize = 0x194 / 4;

/// Extends the in-progress virtual table's argument list.
///
/// # Safety
/// `parse` is an aligned target-layout Parse readable through +0x198.
/// Its connection, token span, and table must satisfy the existing duplication
/// and owned-pointer append contracts. NULL token/table pointers skip all work.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vtab_arg_extend(parse: *mut u32) {
    let text = parse.add(ARG_TEXT_WORD).read() as usize as *const u8;
    if text.is_null() {
        return;
    }
    if parse.add(NEW_TABLE_WORD).read() == 0 {
        return;
    }
    let length = parse.add(ARG_PACKED_WORD).read() >> 1;
    let db = parse.read() as usize as *mut u8;
    let argument = db_str_ndup(db, text, length as i32);
    // Reload after duplication, matching the stock ldr at 0x082b2c84.
    let table = parse.add(NEW_TABLE_WORD).read() as usize as *mut u8;
    append_owned_pointer(db, table, argument);
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::sqlite::mem::{DbMemOps, DB_MEM_OPS};
    use crate::sqlite::mem::tests::{install_recorder, realloc_log};
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};

    unsafe extern "C" fn grow_array(old: *mut u8, bytes: i32) -> *mut u8 {
        assert_eq!(bytes, 8);
        old
    }

    #[test]
    fn absent_token_or_table_preserves_parse_and_never_allocates() {
        let _guard = install_recorder(core::ptr::null_mut());
        for (text, table) in [(0, 1), (1, 0), (0, 0)] {
            let mut parse = [0xa5a5a5a5u32; 0x198 / 4];
            parse[ARG_TEXT_WORD] = text;
            parse[NEW_TABLE_WORD] = table;
            let before = parse;
            unsafe { vtab_arg_extend(parse.as_mut_ptr()); }
            assert_eq!(parse, before);
            assert!(realloc_log().is_empty());
        }
    }

    #[test]
    fn copies_exact_packed_span_and_appends_including_empty_argument() {
        let Some(base) = (unsafe { try_map_u32_slab(hints::SQLITE_VTAB_ARG_EXTEND, 0x1000) }) else {
            assert!(note_missing_u32_fixture("sqlite/vtab_arg_extend"));
            return;
        };
        for length in [0usize, 1, 5, 31] {
            for flag in [0u32, 1] {
                unsafe {
                    base.write_bytes(0, 0x1000);
                    let parse = base.cast::<u32>();
                    let db = base.add(0x200);
                    let table = base.add(0x300);
                    let text = base.add(0x400);
                    let copy = base.add(0x500);
                    let items = base.add(0x600).cast::<u32>();
                    text.write_bytes(b'x', 64);
                    copy.write_bytes(0xa5, 64);
                    parse.write(db as usize as u32);
                    parse.add(NEW_TABLE_WORD).write(table as usize as u32);
                    parse.add(ARG_TEXT_WORD).write(text as usize as u32);
                    parse.add(ARG_PACKED_WORD).write((length as u32 * 2) | flag);
                    table.add(0x48).cast::<u32>().write(items as usize as u32);
                    let before = core::slice::from_raw_parts(parse, 0x198 / 4).to_vec();
                    let _guard = install_recorder(copy);
                    core::ptr::write_volatile(core::ptr::addr_of_mut!(DB_MEM_OPS.realloc), grow_array);
                    vtab_arg_extend(parse);
                    assert_eq!(core::slice::from_raw_parts(copy, length), std::vec![b'x'; length]);
                    assert_eq!(copy.add(length).read(), 0);
                    assert_eq!(copy.add(length + 1).read(), 0xa5);
                    assert_eq!(table.add(0x44).cast::<u32>().read(), 1);
                    assert_eq!(items.read(), copy as usize as u32);
                    assert_eq!(items.add(1).read(), 0);
                    assert_eq!(db.add(0x1e).read(), 0);
                    assert_eq!(core::slice::from_raw_parts(parse, 0x198 / 4), before);
                    assert_eq!(realloc_log(), std::vec![(0, length as i32 + 1)]);
                    core::ptr::write_volatile(core::ptr::addr_of_mut!(DB_MEM_OPS), DbMemOps {
                        malloc: crate::sqlite::mem::tests::recording_malloc,
                        realloc: crate::sqlite::mem::tests::recording_realloc,
                    });
                }
            }
        }
        unsafe {
            // Duplication failure latches mallocFailed; append still runs and
            // clears the initially empty list without attempting reallocation.
            base.write_bytes(0, 0x1000);
            let parse = base.cast::<u32>();
            let db = base.add(0x200);
            let table = base.add(0x300);
            parse.write(db as usize as u32);
            parse.add(NEW_TABLE_WORD).write(table as usize as u32);
            parse.add(ARG_TEXT_WORD).write(base.add(0x400) as usize as u32);
            parse.add(ARG_PACKED_WORD).write(6);
            let _guard = install_recorder(core::ptr::null_mut());
            vtab_arg_extend(parse);
            assert_eq!(db.add(0x1e).read(), 1);
            assert_eq!(table.add(0x44).cast::<u32>().read(), 0);
            assert_eq!(table.add(0x48).cast::<u32>().read(), 0);
            assert_eq!(realloc_log(), std::vec![(0, 4)]);
        }
    }
}
