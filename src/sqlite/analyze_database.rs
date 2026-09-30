//! Database-wide SQLite ANALYZE code generation.
//!
//! `FUN_082b4094` @ 0x082b4094, 144 bytes through 0x082b4120;
//! the next real function starts at 0x082b4124. Raw words verify three
//! unconditional BL instructions, zero predicated BLs, and a tail B to
//! 0x082d80a4. Snapshot the schema, begin a write, reserve a cursor, open
//! sqlite_stat1, then analyze each table using one shared register base.
//! Finally emit the analysis-reload operation. Ghidra omits both fourth
//! arguments and incorrectly inlines the tail. Deliberate deviation:
//! LLVM chooses call versus tail-call lowering; all target layouts and
//! helper effects are preserved. Unported helpers execute retail code;
//! begin_write_operation also uses retail code because its Rust seam's
//! default schema verification is a no-op, not equivalent firmware behavior.

#[derive(Clone, Copy)]
struct AnalysisOps {
    begin_write: unsafe extern "C" fn(*mut u8, i32, i32),
    open_stat_table: unsafe extern "C" fn(*mut u8, i32, i32, *const u8),
    analyze_table: unsafe extern "C" fn(*mut u8, *mut u8, i32, i32),
    reload_analysis: unsafe extern "C" fn(*mut u8, i32),
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn retail_ops() -> AnalysisOps {
    AnalysisOps {
        begin_write: core::mem::transmute(0x0837_021cusize),
        open_stat_table: core::mem::transmute(0x082d_c100usize),
        analyze_table: core::mem::transmute(0x082b_4124usize),
        reload_analysis: core::mem::transmute(0x082d_80a4usize),
    }
}

/// Generate ANALYZE for every table in database `i_db`.
///
/// # Safety
/// `parse` and all linked records must be writable/readable retail-layout
/// objects, with 32-bit aligned pointers and a valid database index.
/// Retail helper addresses must be executable on the target.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn analyze_database(parse: *mut u8, i_db: i32) {
    #[cfg(target_os = "none")]
    analyze_database_with_ops(parse, i_db, retail_ops());
    #[cfg(not(target_os = "none"))]
    {
        let _ = (parse, i_db);
        panic!("analyze_database requires retailOS helpers; host tests use explicit operations");
    }
}

unsafe fn analyze_database_with_ops(parse: *mut u8, i_db: i32, ops: AnalysisOps) {
    let db = parse.cast::<u32>().read() as *mut u8;
    let entries = db.add(8).cast::<u32>().read() as *mut u8;
    let schema = entries.add(i_db as usize * 24 + 20).cast::<u32>().read() as *mut u8;
    (ops.begin_write)(parse, 0, i_db);
    let cursor = parse.add(0x44).cast::<i32>().read();
    parse.add(0x44).cast::<i32>().write(cursor.wrapping_add(1));
    (ops.open_stat_table)(parse, i_db, cursor, core::ptr::null());
    let register_base = parse.add(0x48).cast::<i32>().read().wrapping_add(1);
    let mut element = schema.add(0x10).cast::<u32>().read() as *mut u8;
    while !element.is_null() {
        let table = element.add(8).cast::<u32>().read() as *mut u8;
        (ops.analyze_table)(parse, table, cursor, register_base);
        element = element.cast::<u32>().read() as *mut u8;
    }
    (ops.reload_analysis)(parse, i_db);
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};

    unsafe extern "C" fn begin(parse: *mut u8, statement: i32, db: i32) {
        assert_eq!((statement, db), (0, 1));
        // Beginning the write can allocate cursors; reserve after this call.
        parse.add(0x44).cast::<i32>().write(i32::MAX);
    }
    unsafe extern "C" fn open(parse: *mut u8, db: i32, cursor: i32, name: *const u8) {
        assert_eq!((db, cursor), (1, i32::MAX));
        assert!(name.is_null());
        assert_eq!(parse.add(0x44).cast::<i32>().read(), i32::MIN);
        // Opening sqlite_stat1 can allocate registers; snapshot afterwards.
        parse.add(0x48).cast::<i32>().write(20);
    }
    unsafe extern "C" fn table(parse: *mut u8, table: *mut u8, cursor: i32, base: i32) {
        assert_eq!((cursor, base), (i32::MAX, 21));
        let visits = parse.add(0x50).cast::<u32>();
        assert_eq!(table.cast::<u32>().read(), visits.read() + 100);
        visits.write(visits.read() + 1);
        // Later tables must not receive a newly computed register base.
        parse.add(0x48).cast::<i32>().write(90);
        table.add(4).cast::<i32>().write(base);
    }
    unsafe extern "C" fn reload(parse: *mut u8, db: i32) {
        assert_eq!(db, 1);
        parse.add(0x54).cast::<u32>().write(parse.add(0x50).cast::<u32>().read() + 1);
    }

    #[test]
    fn empty_and_multiple_tables_preserve_allocation_order_and_shared_registers() {
        let Some(base) = try_map_u32_slab(hints::SQLITE_ANALYZE_DATABASE, 0x1000) else {
            assert!(note_missing_u32_fixture("sqlite/analyze_database"));
            return;
        };
        unsafe {
            let parse = base;
            let db = base.add(0x200);
            let entries = base.add(0x300);
            let schema = base.add(0x400);
            let first = base.add(0x500);
            let second = base.add(0x520);
            let first_table = base.add(0x600);
            let second_table = base.add(0x620);
            for populated in [false, true] {
                base.write_bytes(0, 0x1000);
                parse.cast::<u32>().write(db as usize as u32);
                db.add(8).cast::<u32>().write(entries as usize as u32);
                // Only database 1 is initialized; wrong stride/index faults.
                entries.add(24 + 20).cast::<u32>().write(schema as usize as u32);
                if populated {
                    schema.add(0x10).cast::<u32>().write(first as usize as u32);
                    first.cast::<u32>().write(second as usize as u32);
                    first.add(8).cast::<u32>().write(first_table as usize as u32);
                    second.add(8).cast::<u32>().write(second_table as usize as u32);
                    first_table.cast::<u32>().write(100);
                    second_table.cast::<u32>().write(101);
                }
                analyze_database_with_ops(parse, 1, AnalysisOps {
                    begin_write: begin, open_stat_table: open,
                    analyze_table: table, reload_analysis: reload,
                });
                let expected = if populated { 2 } else { 0 };
                assert_eq!(parse.add(0x50).cast::<u32>().read(), expected);
                assert_eq!(parse.add(0x54).cast::<u32>().read(), expected + 1);
                assert_eq!(parse.add(0x44).cast::<i32>().read(), i32::MIN);
                if populated {
                    assert_eq!(first_table.add(4).cast::<i32>().read(), 21);
                    assert_eq!(second_table.add(4).cast::<i32>().read(), 21);
                } else {
                    assert_eq!(parse.add(0x48).cast::<i32>().read(), 20);
                }
            }
        }
    }
}
