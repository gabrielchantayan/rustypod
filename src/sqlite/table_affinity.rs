//! VDBE table-affinity materialization from the retail SQLite amalgamation.
//!
//! The target's `Table` holds an affinity byte for each 20-byte `Column` and
//! caches the resulting NUL-terminated string at +0x28.  An `OP_MakeRecord`
//! emitted immediately before this helper receives its own dynamic P4 copy;
//! the table cache remains owned by the table.

use crate::sqlite::mem::db_malloc_raw;
use crate::sqlite::vdbe::{vdbe_change_p4, Vdbe};

/// The recovered prefix of SQLite's `Column`: only the affinity byte at
/// +0x12 is read here.  The full record is 20 bytes, so affinity collection
/// walks `columns` with the same stride as the firmware.
#[repr(C)]
pub struct Column {
    _prefix: [u8; 0x12],
    pub affinity: u8,
    _suffix: u8,
}

/// The fields of SQLite's `Table` used by [`vdbe_attach_table_affinity`].
///
/// The unmodeled +0x0c..+0x27 span keeps `z_col_aff` at its recovered target
/// offset. The cache is table-owned: this helper creates it once and never
/// releases it.
#[repr(C)]
pub struct Table {
    pub z_name: *mut u8,
    pub n_col: i32,
    pub columns: *mut Column,
    _gap_0c: [u8; 0x1c],
    pub z_col_aff: *mut u8,
}

#[cfg(target_pointer_width = "32")]
const _: () = {
    assert!(core::mem::offset_of!(Column, affinity) == 0x12);
    assert!(core::mem::size_of::<Column>() == 0x14);
    assert!(core::mem::offset_of!(Table, n_col) == 0x04);
    assert!(core::mem::offset_of!(Table, columns) == 0x08);
    assert!(core::mem::offset_of!(Table, z_col_aff) == 0x28);
};

/// vdbe_attach_table_affinity — original: `FUN_08385004` @ 0x08385004
/// (128 bytes).
///
/// Source: `ipod-decomp/decomp/c/033/08385004_FUN_08385004.c`, corroborated
/// against the 128-byte block at this load address in `decomp/osos.asm`.
/// This is the SQLite 3.6-era table-affinity helper: lazily allocate
/// `table.n_col + 1` bytes through `sqlite3DbMallocRaw`, copy every
/// `Column.affinity` at the target's 20-byte stride, terminate it, and cache
/// it in `table.zColAff`. It then tail-calls the ported
/// [`vdbe_change_p4`] with `addr = -1` and `n = 0`. That existing VDBE seam
/// handles all guards, releases the former P4 payload, clears it, duplicates
/// the string, and updates P4 to `P4_DYNAMIC` (-1); a P4-copy allocation
/// failure therefore retains the dynamic tag with a NULL payload, as in the
/// firmware.
///
/// # Safety
/// `vdbe` and `table` must point to writable recovered SQLite objects. When
/// `table.z_col_aff` is NULL, `table.columns` must name `table.n_col` valid
/// [`Column`] records. If `vdbe.a_op` is non-NULL, it must name at least
/// `vdbe.n_op` valid VDBE op records.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vdbe_attach_table_affinity(vdbe: *mut Vdbe, table: *mut Table) {
    if (*table).z_col_aff.is_null() {
        let n_col = (*table).n_col;
        let affinity = db_malloc_raw((*vdbe).db, n_col.wrapping_add(1));
        if affinity.is_null() {
            return;
        }
        for index in 0..n_col {
            affinity.add(index as usize).write((*(*table).columns.add(index as usize)).affinity);
        }
        affinity.add(n_col as usize).write(0);
        (*table).z_col_aff = affinity;
    }

    let affinity = (*table).z_col_aff;
    vdbe_change_p4(vdbe, -1, affinity, 0);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::sqlite::mem::{DbMemOps, DEFAULT_DB_MEM_OPS, DB_MEM_OPS};
    use crate::sqlite::mem::tests::{Connection, OPS_LOCK};
    use crate::sqlite::vdbe::{VdbeOp, P4_DYNAMIC, P4_NOTUSED};
    use core::mem::MaybeUninit;

    static mut ALLOCATION_COUNT: usize = 0;
    static mut REQUESTS: [i32; 2] = [0; 2];
    static mut CACHE: [u8; 16] = [0; 16];
    static mut P4_COPY: [u8; 16] = [0; 16];

    unsafe extern "C" fn sequential_malloc(n: i32) -> *mut u8 {
        let index = ALLOCATION_COUNT;
        ALLOCATION_COUNT += 1;
        REQUESTS[index] = n;
        match index {
            0 => core::ptr::addr_of_mut!(CACHE).cast(),
            1 => core::ptr::addr_of_mut!(P4_COPY).cast(),
            _ => core::ptr::null_mut(),
        }
    }

    unsafe extern "C" fn always_fail(_n: i32) -> *mut u8 {
        core::ptr::null_mut()
    }

    struct AllocatorReset;

    impl Drop for AllocatorReset {
        fn drop(&mut self) {
            unsafe {
                core::ptr::write_volatile(core::ptr::addr_of_mut!(DB_MEM_OPS), DEFAULT_DB_MEM_OPS);
            }
        }
    }

    fn install_allocator(malloc: unsafe extern "C" fn(i32) -> *mut u8) {
        unsafe {
            ALLOCATION_COUNT = 0;
            REQUESTS = [0; 2];
            CACHE = [0xa5; 16];
            P4_COPY = [0x5a; 16];
            core::ptr::write_volatile(
                core::ptr::addr_of_mut!(DB_MEM_OPS),
                DbMemOps { malloc, realloc: DEFAULT_DB_MEM_OPS.realloc },
            );
        }
    }

    fn column(affinity: u8) -> Column {
        Column { _prefix: [0; 0x12], affinity, _suffix: 0 }
    }

    fn table(columns: *mut Column, n_col: i32) -> Table {
        Table {
            z_name: core::ptr::null_mut(),
            n_col,
            columns,
            _gap_0c: [0; 0x1c],
            z_col_aff: core::ptr::null_mut(),
        }
    }

    fn vdbe(db: *mut u8, ops: *mut VdbeOp, n_op: i32) -> Vdbe {
        let mut vdbe = unsafe { MaybeUninit::<Vdbe>::zeroed().assume_init() };
        vdbe.db = db;
        vdbe.a_op = ops;
        vdbe.n_op = n_op;
        vdbe
    }

    #[test]
    fn lazily_caches_column_affinities_and_attaches_a_distinct_dynamic_p4_copy() {
        let _guard = OPS_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let _reset = AllocatorReset;
        install_allocator(sequential_malloc);
        let mut db = Connection::healthy();
        let mut columns = [column(b'A'), column(b'C'), column(b'E')];
        let mut table = table(columns.as_mut_ptr(), columns.len() as i32);
        let mut ops = [VdbeOp {
            opcode: 0x55,
            p4type: P4_NOTUSED,
            opflags: 0,
            p5: 0,
            p1: 0,
            p2: 0,
            p3: 0,
            p4: core::ptr::null_mut(),
        }];
        let mut program = vdbe(db.ptr(), ops.as_mut_ptr(), 1);

        unsafe { vdbe_attach_table_affinity(&mut program, &mut table) };

        unsafe {
            assert_eq!(REQUESTS, [4, 4], "cache then P4 duplicate request nCol + 1");
            assert_eq!(&CACHE[..4], b"ACE\0", "Column affinity is read at +0x12 / stride 20");
            assert_eq!(&P4_COPY[..4], b"ACE\0", "the operation owns a separate copy");
        }
        assert_eq!(table.z_col_aff, unsafe { core::ptr::addr_of_mut!(CACHE).cast() });
        assert_eq!(ops[0].p4, unsafe { core::ptr::addr_of_mut!(P4_COPY).cast() });
        assert_eq!(ops[0].p4type, P4_DYNAMIC as i8);
    }

    #[test]
    fn cache_is_reused_without_rebuilding_before_replacing_the_last_p4() {
        let _guard = OPS_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let _reset = AllocatorReset;
        install_allocator(sequential_malloc);
        let mut db = Connection::healthy();
        let mut columns = [column(b'X')];
        let mut table = table(columns.as_mut_ptr(), 1);
        table.z_col_aff = b"Q\0".as_ptr() as *mut u8;
        let mut ops = [VdbeOp {
            opcode: 0x55,
            p4type: P4_NOTUSED,
            opflags: 0,
            p5: 0,
            p1: 0,
            p2: 0,
            p3: 0,
            p4: core::ptr::null_mut(),
        }];
        let mut program = vdbe(db.ptr(), ops.as_mut_ptr(), 1);

        unsafe { vdbe_attach_table_affinity(&mut program, &mut table) };

        unsafe {
            assert_eq!(ALLOCATION_COUNT, 1, "an existing table cache is not rebuilt");
            assert_eq!(REQUESTS[0], 2, "only the NUL-terminated P4 copy is allocated");
            assert_eq!(&CACHE[..2], b"Q\0");
        }
        assert_eq!(ops[0].p4type, P4_DYNAMIC as i8);
    }

    #[test]
    fn allocation_failure_leaves_the_table_uncached_and_the_op_untouched() {
        let _guard = OPS_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let _reset = AllocatorReset;
        install_allocator(always_fail);
        let mut db = Connection::healthy();
        let mut columns = [column(b'A')];
        let mut table = table(columns.as_mut_ptr(), 1);
        let mut ops = [VdbeOp {
            opcode: 0x55,
            p4type: P4_NOTUSED,
            opflags: 0,
            p5: 0,
            p1: 0,
            p2: 0,
            p3: 0,
            p4: 0x1234usize as *mut u8,
        }];
        let mut program = vdbe(db.ptr(), ops.as_mut_ptr(), 1);

        unsafe { vdbe_attach_table_affinity(&mut program, &mut table) };

        assert!(table.z_col_aff.is_null());
        assert_eq!(ops[0].p4, 0x1234usize as *mut u8, "P4 release is not reached");
        assert_eq!(ops[0].p4type, P4_NOTUSED);
        assert_eq!(db.failed_flag(), 1, "sqlite3DbMallocRaw records OOM");
    }

    #[test]
    fn missing_op_array_failed_connection_or_no_ops_do_not_attach_a_p4() {
        let _guard = OPS_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let _reset = AllocatorReset;
        install_allocator(sequential_malloc);
        let mut columns = [column(b'A')];
        let mut table = table(columns.as_mut_ptr(), 1);
        table.z_col_aff = b"A\0".as_ptr() as *mut u8;

        let mut healthy = Connection::healthy();
        let mut no_array = vdbe(healthy.ptr(), core::ptr::null_mut(), 1);
        unsafe { vdbe_attach_table_affinity(&mut no_array, &mut table) };

        let mut failed = Connection::failed();
        let mut ops = [VdbeOp {
            opcode: 0x55,
            p4type: P4_NOTUSED,
            opflags: 0,
            p5: 0,
            p1: 0,
            p2: 0,
            p3: 0,
            p4: core::ptr::null_mut(),
        }];
        let mut failed_program = vdbe(failed.ptr(), ops.as_mut_ptr(), 1);
        unsafe { vdbe_attach_table_affinity(&mut failed_program, &mut table) };

        let mut empty_program = vdbe(healthy.ptr(), ops.as_mut_ptr(), 0);
        unsafe { vdbe_attach_table_affinity(&mut empty_program, &mut table) };

        unsafe { assert_eq!(ALLOCATION_COUNT, 0) };
        assert!(ops[0].p4.is_null());
        assert_eq!(ops[0].p4type, P4_NOTUSED);
    }
}
