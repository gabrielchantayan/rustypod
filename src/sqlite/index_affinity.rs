//! Index affinity materialization for the VDBE.
//!
//! `Index` keeps its `zColAff` cache at +0x1c. Unlike a table affinity
//! string, it follows the signed `aiColumn` word array at +0x08 to select
//! affinities from the owning table's 20-byte `Column` records.

use crate::sqlite::mem::db_malloc_raw;
use crate::sqlite::vdbe::{vdbe_change_p4, Vdbe};

const INDEX_N_COLUMN_OFFSET: usize = 0x04;
const INDEX_AI_COLUMN_OFFSET: usize = 0x08;
const INDEX_TABLE_OFFSET: usize = 0x10;
const INDEX_AFFINITY_OFFSET: usize = 0x1c;
const TABLE_COLUMNS_OFFSET: usize = 0x08;
const COLUMN_SIZE: usize = 0x14;
const COLUMN_AFFINITY_OFFSET: usize = 0x12;

/// vdbe_attach_index_affinity — original: `FUN_0837b254` @ 0x0837b254
/// (160 bytes; **3 inbound direct `bl` call sites: 3 unconditional, 0
/// predicated**, binary-scanned from `osos.dec`; one internal `bl` and one
/// tail `b` to `vdbe_change_p4`).
///
/// Lazily allocates `index.nColumn + 2` bytes through `sqlite3DbMallocRaw`,
/// gathers each selected table-column affinity through `index.aiColumn`, then
/// appends `'b'` and a NUL and caches the result in `index.zColAff`. It
/// tail-calls `sqlite3VdbeChangeP4(vdbe, -1, zColAff, 0)`. Allocation failure
/// leaves the cache and last op untouched. Deliberate deviation: target-width
/// Index and Table pointers are read as u32 words rather than host pointers,
/// preserving their 4-byte target offsets on 64-bit test hosts.
///
/// # Safety
/// `vdbe` must be a recovered VDBE. `index` must name a target-layout Index;
/// its table, column-index, and column-array words must be valid when the
/// affinity cache is NULL.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vdbe_attach_index_affinity(vdbe: *mut Vdbe, index: *mut u8) {
    let affinity_slot = index.add(INDEX_AFFINITY_OFFSET) as *mut u32;
    if affinity_slot.read() == 0 {
        let n_column = (index.add(INDEX_N_COLUMN_OFFSET) as *const i32).read();
        let table = (index.add(INDEX_TABLE_OFFSET) as *const u32).read() as usize as *mut u8;
        let affinity = db_malloc_raw((*vdbe).db, n_column.wrapping_add(2));
        if affinity.is_null() {
            return;
        }

        let ai_column = (index.add(INDEX_AI_COLUMN_OFFSET) as *const u32).read() as usize as *const i32;
        let columns = (table.add(TABLE_COLUMNS_OFFSET) as *const u32).read() as usize as *const u8;
        let mut column_index = 0i32;
        while column_index < n_column {
            let table_column = ai_column.add(column_index as usize).read();
            affinity.add(column_index as usize).write(
                columns.add(table_column as usize * COLUMN_SIZE + COLUMN_AFFINITY_OFFSET).read(),
            );
            column_index = column_index.wrapping_add(1);
        }
        affinity.add(column_index as usize).write(b'b');
        affinity.add(column_index as usize + 1).write(0);
        affinity_slot.write(affinity as usize as u32);
    }

    vdbe_change_p4(vdbe, -1, affinity_slot.read() as usize as *mut u8, 0);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::sqlite::mem::{DbMemOps, DEFAULT_DB_MEM_OPS, DB_MEM_OPS};
    use crate::sqlite::mem::tests::OPS_LOCK;
    use crate::sqlite::vdbe::{P4_DYNAMIC, P4_NOTUSED, VdbeOp};
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use std::sync::LazyLock;

    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::SQLITE_INDEX_AFFINITY, 0x2000).map(|p| p as usize)
    });
    static mut ALLOCATIONS: usize = 0;
    static mut CACHE: *mut u8 = core::ptr::null_mut();
    static mut P4_COPY: *mut u8 = core::ptr::null_mut();

    unsafe extern "C" fn sequential_malloc(_n: i32) -> *mut u8 {
        let allocation = ALLOCATIONS;
        ALLOCATIONS += 1;
        match allocation {
            0 => CACHE,
            1 => P4_COPY,
            _ => core::ptr::null_mut(),
        }
    }

    struct AllocatorReset;
    impl Drop for AllocatorReset {
        fn drop(&mut self) {
            unsafe { core::ptr::write_volatile(core::ptr::addr_of_mut!(DB_MEM_OPS), DEFAULT_DB_MEM_OPS) };
        }
    }

    #[test]
    fn gathers_indexed_affinities_and_appends_record_affinity() {
        let _lock = OPS_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(slab) = (*SLAB).map(|address| address as *mut u8) else {
            if note_missing_u32_fixture(module_path!()) { return; }
            unreachable!();
        };
        let _reset = AllocatorReset;
        unsafe {
            ALLOCATIONS = 0;
            CACHE = slab.add(0x900);
            P4_COPY = slab.add(0xa00);
            core::ptr::write_volatile(core::ptr::addr_of_mut!(DB_MEM_OPS), DbMemOps {
                malloc: sequential_malloc, realloc: DEFAULT_DB_MEM_OPS.realloc,
            });
            let db = slab.add(0x100);
            db.add(0x1e).write(0);
            let table = slab.add(0x200);
            let columns = slab.add(0x300);
            table.add(TABLE_COLUMNS_OFFSET).cast::<u32>().write(columns as u32);
            columns.add(COLUMN_AFFINITY_OFFSET).write(b'A');
            columns.add(COLUMN_SIZE + COLUMN_AFFINITY_OFFSET).write(b'C');
            columns.add(2 * COLUMN_SIZE + COLUMN_AFFINITY_OFFSET).write(b'E');
            let ai_column = slab.add(0x600).cast::<i32>();
            ai_column.write(2);
            ai_column.add(1).write(0);
            let index = slab.add(0x700);
            index.add(INDEX_N_COLUMN_OFFSET).cast::<i32>().write(2);
            index.add(INDEX_AI_COLUMN_OFFSET).cast::<u32>().write(ai_column as u32);
            index.add(INDEX_TABLE_OFFSET).cast::<u32>().write(table as u32);
            index.add(INDEX_AFFINITY_OFFSET).cast::<u32>().write(0);
            let mut ops = [VdbeOp { opcode: 0x55, p4type: P4_NOTUSED, opflags: 0, p5: 0, p1: 0, p2: 0, p3: 0, p4: core::ptr::null_mut() }];
            let mut program: Vdbe = core::mem::zeroed();
            program.db = db;
            program.a_op = ops.as_mut_ptr();
            program.n_op = 1;

            vdbe_attach_index_affinity(&mut program, index);

            assert_eq!(core::slice::from_raw_parts(CACHE, 4), b"EAb\0");
            assert_eq!(index.add(INDEX_AFFINITY_OFFSET).cast::<u32>().read(), CACHE as u32);
            assert_eq!(core::slice::from_raw_parts(P4_COPY, 4), b"EAb\0");
            assert_eq!(ops[0].p4type, P4_DYNAMIC as i8);
        }
    }
}
