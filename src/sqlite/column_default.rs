//! Attach a column's constant default value to the newest VDBE op.
//!
//! `column_default` — original: `FUN_0837354c` @ `0x0837354c` (108
//! bytes, `0x0837354c..0x083735b7`; the next independent entry is
//! `expr_compare_affinity` @ `0x083735b8`, itself an identified seam
//! target). Raw ARM decoding finds four direct inbound `bl` call
//! sites (0x08376e24, 0x08379fd8, 0x08385d20, 0x08385eec), all
//! unconditional, no predicated `bl` forms and no tail branches; the
//! body holds two outbound calls, one `bl` and one `blne`. Ghidra's
//! 108-byte size and 4-call-site report agree with the raw image.
//!
//! SQLite 3.5.9's `sqlite3ColumnDefault`: when the table is real (not
//! a view — `Table.pSelect` at +0x18 is NULL), evaluate column
//! `i_col`'s default expression (`Column.pDflt` at +0x04 of the
//! 0x14-byte `Column` at `Table.aCol + i_col*0x14`, the affinity byte
//! at +0x12) into a fresh `sqlite3_value` with the connection
//! encoding (`[[db+0x08]+0x14]+0x59` — `aDb[0].pSchema->enc`, the
//! same chain `locate_coll_seq` decodes), and attach that value as
//! `P4_MEM` (-8) of the most recently emitted op (addr -1). The
//! original listing:
//!
//! ```text
//! 0837354c: stmdb sp!,{r2,r3,r4,lr}   08373580: add r1,r1,r3,lsl#2
//! 08373550: cmp r1,#0x0               08373584: ldrb r2,[r2,#0x59]
//! 08373554: mov r4,r0                 08373588: add r3,sp,#0x4
//! 08373558: mov r3,r2                 0837358c: str r3,[sp,#0x0]
//! 0837355c: beq 0x083735b4            08373590: ldrb r3,[r1,#0x12]
//! 08373560: ldr r0,[r1,#0x18]         08373594: ldr r1,[r1,#0x4]
//! 08373564: cmp r0,#0x0               08373598: bl 0x08386524
//! 08373568: bne 0x083735b4            0837359c: ldr r2,[sp,#0x4]
//! 0837356c: ldr r0,[r4,#0x0]          083735a0: cmp r2,#0x0
//! 08373570: ldr r1,[r1,#0x8]          083735a4: mvnne r3,#0x7
//! 08373574: ldr r2,[r0,#0x8]          083735a8: mvnne r1,#0x0
//! 08373578: add r3,r3,r3,lsl#2        083735ac: movne r0,r4
//! 0837357c: ldr r2,[r2,#0x14]         083735b0: blne 0x08386aa4
//! 083735b4: ldmia sp!,{r2,r3,r4,pc}
//! ```
//!
//! Deliberate deviations from the original instruction stream:
//!
//! - `valueFromExpr` @ `0x08386524` (static in SQLite's `insert.c`;
//!   no ledger entry, not ported) remains a volatile dispatch seam.
//!   Target builds call that exact retail address; host tests install
//!   a recorder and the shipped host default panics — the house
//!   pattern of `expr_code_compare`'s seams. `vdbe_change_p4` @
//!   `0x08386aa4` is ported and called directly.
//! - The `Table`/`Column` layouts are typed `#[repr(C)]` records
//!   rather than raw byte offsets, so the pointer fields cannot
//!   overlap on a 64-bit host; the encoding chain is read as
//!   target-width words exactly as `locate_coll_seq` does.

use core::ptr;

use super::vdbe::{vdbe_change_p4, Vdbe};

/// `P4_MEM`: the `VdbeOp.p4type` tag for an owned `sqlite3_value`
/// (`mvnne r3,#0x7` in the original — `~7 == -8`). freeP4 releases it
/// through `sqlite3ValueFree`.
pub const P4_MEM: i32 = -8;

/// Target address of the unported constant-expression evaluator
/// (`valueFromExpr`, static in SQLite 3.5.9's `insert.c`).
pub const VALUE_FROM_EXPR_ADDRESS: usize = 0x0838_6524;

/// The fields of SQLite's `Table` this helper touches. The unmodeled
/// spans keep the recovered offsets (`aCol` at +0x08, `pSelect` at
/// +0x18 — both witnessed by the raw listing above).
#[repr(C)]
pub struct Table {
    /// +0x00..+0x08: unmodeled (`zName`, `zFile`).
    pub _gap_00: [u8; 0x08],
    /// +0x08: the column array (`aCol`), 0x14 bytes per [`Column`].
    pub a_col: *mut Column,
    /// +0x0c..+0x18: unmodeled (`nCol`, `nRef`, ...).
    pub _gap_0c: [u8; 0x18 - 0x0c],
    /// +0x18: non-NULL when this "table" is actually a view
    /// (`pSelect`); views carry no column defaults.
    pub p_select: *mut u8,
}

/// The fields of SQLite's `Column` this helper touches; the retail
/// stride is 0x14 (`add r3,r3,r3,lsl#2; add r1,r1,r3,lsl#2` — the
/// `i_col * 5 * 4` indexing in the listing).
#[repr(C)]
pub struct Column {
    /// +0x00: column name (`zName`).
    pub z_name: *mut u8,
    /// +0x04: the constant default expression (`pDflt`), NULL when the
    /// column has no DEFAULT clause.
    pub p_dflt: *const u8,
    /// +0x08..+0x12: unmodeled (`zType`, `zColl`, `notNull`,
    /// `isPrimKey`).
    pub _gap_08: [u8; 0x12 - 0x08],
    /// +0x12: the column affinity (`'a'..='e'`; `SQLITE_AFF_NONE` is
    /// `'e'`, the byte `sqlite3ExprCodeGetColumn` compares against).
    pub affinity: u8,
    /// +0x13..+0x14: `isStored` plus padding to the 0x14 stride.
    pub _tail_13: [u8; 0x14 - 0x13],
}

#[cfg(target_pointer_width = "32")]
const _: () = {
    assert!(core::mem::size_of::<Column>() == 0x14);
    assert!(core::mem::offset_of!(Table, a_col) == 0x08);
    assert!(core::mem::offset_of!(Table, p_select) == 0x18);
    assert!(core::mem::offset_of!(Column, p_dflt) == 0x04);
    assert!(core::mem::offset_of!(Column, affinity) == 0x12);
};

/// `valueFromExpr(db, pExpr, enc, aff, ppVal)`: evaluate the constant
/// expression `expr` into a fresh `sqlite3_value`, written to `*out`.
/// Returns `SQLITE_OK`/`SQLITE_NOMEM`; this caller ignores the code
/// and keys off `*out` exactly like the original (`ldr r2,[sp,#4];
/// cmp r2,#0`).
pub type ValueFromExpr = unsafe extern "C" fn(
    db: *mut u8,
    expr: *const u8,
    enc: u32,
    aff: u32,
    out: *mut *mut u8,
) -> i32;

/// Target default: call the retail evaluator at its load address.
#[cfg(target_os = "none")]
unsafe extern "C" fn retail_value_from_expr(
    db: *mut u8,
    expr: *const u8,
    enc: u32,
    aff: u32,
    out: *mut *mut u8,
) -> i32 {
    let op: ValueFromExpr = core::mem::transmute(VALUE_FROM_EXPR_ADDRESS);
    op(db, expr, enc, aff, out)
}

/// Host default: no retail code exists here; tests install a recorder.
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_value_from_expr(
    _db: *mut u8,
    _expr: *const u8,
    _enc: u32,
    _aff: u32,
    _out: *mut *mut u8,
) -> i32 {
    panic!("column_default requires retail helper @ 0x08386524")
}

/// The active model of the unavailable callee. Volatile so LLVM cannot
/// fold the dispatch to the default (the house pattern —
/// `sqlite/expr_code_compare.rs`).
pub static mut VALUE_FROM_EXPR_OP: ValueFromExpr = {
    #[cfg(target_os = "none")]
    { retail_value_from_expr }
    #[cfg(not(target_os = "none"))]
    { missing_value_from_expr }
};

/// Reads the `valueFromExpr` slot.
#[inline(always)]
unsafe fn value_from_expr_op() -> ValueFromExpr {
    ptr::read_volatile(ptr::addr_of!(VALUE_FROM_EXPR_OP))
}

/// `sqlite3ColumnDefault` — original: `FUN_0837354c` @ 0x0837354c
/// (108 bytes; 4 direct unconditional inbound `bl` call sites,
/// binary-verified).
///
/// Evaluate column `i_col`'s default expression and attach the
/// resulting value as `P4_MEM` of the newest op in `v`. Does nothing
/// for a NULL table, for a view (`pSelect` non-NULL), or when the
/// evaluator produces no value.
///
/// # Safety
/// `v` must be a valid [`Vdbe`] whose `db` names a live connection
/// with a valid `aDb[0].pSchema` chain; it is dereferenced only when
/// the table passes the guards. A non-NULL `tab` must name the
/// recovered [`Table`] layout with at least `i_col + 1` [`Column`]s
/// in `a_col`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn column_default(v: *mut Vdbe, tab: *mut Table, i_col: i32) {
    if tab.is_null() || !(*tab).p_select.is_null() {
        return;
    }
    let col = (*tab).a_col.offset(i_col as isize);
    let db = (*v).db;
    // `ldr r0,[r4]; ldr r0,[r0,#8]; ldr r0,[r0,#0x14]; ldrb
    // r2,[r0,#0x59]` — the schema encoding, read as target-width
    // words to survive host pointer width (see locate_coll_seq).
    let a_db = db.cast::<u32>().add(2).read() as usize as *mut u8;
    let schema = a_db.cast::<u32>().add(5).read() as usize as *const u8;
    let encoding = schema.add(0x59).read() as u32;
    let mut value: *mut u8 = ptr::null_mut();
    (value_from_expr_op())(db, (*col).p_dflt, encoding, (*col).affinity as u32, &mut value);
    if !value.is_null() {
        vdbe_change_p4(v, -1, value, P4_MEM);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::sqlite::vdbe::{VdbeOp, P4_NOTUSED};
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use std::sync::LazyLock;
    use std::vec::Vec;

    /// Serializes tests that swap the dispatch slot: it is
    /// process-global.
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    static SLAB: LazyLock<Option<usize>> =
        LazyLock::new(|| try_map_u32_slab(hints::SQLITE_COLUMN_DEFAULT, 0x1000).map(|p| p as usize));

    /// Every call the recording `valueFromExpr` saw:
    /// `(db, expr, enc, aff)`.
    static mut SEEN: Vec<(*mut u8, *const u8, u32, u32)> = Vec::new();

    /// What the recording `valueFromExpr` writes to `*out`.
    static mut RESULT: *mut u8 = ptr::null_mut();

    unsafe extern "C" fn recording_value_from_expr(
        db: *mut u8,
        expr: *const u8,
        enc: u32,
        aff: u32,
        out: *mut *mut u8,
    ) -> i32 {
        (*ptr::addr_of_mut!(SEEN)).push((db, expr, enc, aff));
        *out = *ptr::addr_of!(RESULT);
        0
    }

    /// Installs the recorder and restores the shipped default on
    /// drop, matching the other SQLite seam tests.
    struct Bench {
        _guard: std::sync::MutexGuard<'static, ()>,
    }

    fn bench(result: *mut u8) -> Bench {
        let guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            (*ptr::addr_of_mut!(SEEN)).clear();
            *ptr::addr_of_mut!(RESULT) = result;
            ptr::write_volatile(ptr::addr_of_mut!(VALUE_FROM_EXPR_OP), recording_value_from_expr);
        }
        Bench { _guard: guard }
    }

    impl Drop for Bench {
        fn drop(&mut self) {
            unsafe {
                let default: ValueFromExpr = {
                    #[cfg(target_os = "none")]
                    { retail_value_from_expr }
                    #[cfg(not(target_os = "none"))]
                    { missing_value_from_expr }
                };
                ptr::write_volatile(ptr::addr_of_mut!(VALUE_FROM_EXPR_OP), default);
            }
        }
    }

    fn slab_or_skip() -> Option<*mut u8> {
        if SLAB.is_none() && note_missing_u32_fixture(module_path!()) {
            return None;
        }
        (*SLAB).map(|p| p as *mut u8)
    }

    /// db at slab+0x000, aDb at slab+0x100, schema at slab+0x200,
    /// three columns at slab+0x300. Returns `(db, columns)`; the
    /// columns carry `p_dflt` markers 0x11/0x22/0x33 and affinities
    /// 'd'/'e'/'b'.
    unsafe fn db_fixture(slab: *mut u8, encoding: u8) -> (*mut u8, *mut Column) {
        let a_db = slab.add(0x100);
        let schema = slab.add(0x200);
        slab.cast::<u32>().add(2).write(a_db as u32);
        slab.add(0x13).write(0); // sqlite3.mallocFailed
        a_db.cast::<u32>().add(5).write(schema as u32);
        schema.add(0x59).write(encoding);
        let cols = slab.add(0x300).cast::<Column>();
        for i in 0..3isize {
            let col = cols.offset(i);
            (*col).z_name = ptr::null_mut();
            (*col).p_dflt = (0x11 * (i + 1)) as usize as *const u8;
            (*col).affinity = [b'd', b'e', b'b'][i as usize];
        }
        (slab, cols)
    }

    fn table(a_col: *mut Column, p_select: *mut u8) -> Table {
        Table { _gap_00: [0; 8], a_col, _gap_0c: [0; 0xc], p_select }
    }

    fn vdbe(db: *mut u8, op: *mut VdbeOp, n_op: i32) -> Vdbe {
        let mut v: Vdbe = unsafe { core::mem::zeroed() };
        v.db = db;
        v.n_op = n_op;
        v.a_op = op;
        v
    }

    fn blank_op() -> VdbeOp {
        VdbeOp {
            opcode: 0xff,
            p4type: P4_NOTUSED,
            opflags: 0,
            p5: 0,
            p1: 0,
            p2: 0,
            p3: 0,
            p4: ptr::null_mut(),
        }
    }

    #[test]
    fn null_table_is_a_noop() {
        let _bench = bench(ptr::null_mut());
        let Some(slab) = slab_or_skip() else { unreachable!() };
        unsafe {
            let (db, _cols) = db_fixture(slab, 1);
            let mut op = blank_op();
            let mut v = vdbe(db, &mut op, 1);
            column_default(&mut v, ptr::null_mut(), 0);
            assert!((*ptr::addr_of!(SEEN)).is_empty(), "no table, no evaluation");
            assert_eq!(op.p4, ptr::null_mut());
            assert_eq!(op.p4type, P4_NOTUSED);
        }
    }

    #[test]
    fn view_has_no_column_defaults() {
        let Some(slab) = slab_or_skip() else { unreachable!() };
        unsafe {
            let (db, cols) = db_fixture(slab, 1);
            let _bench = bench(0x5555usize as *mut u8);
            let mut op = blank_op();
            let mut v = vdbe(db, &mut op, 1);
            let mut tab = table(cols, slab.add(0x500)); // pSelect != NULL
            column_default(&mut v, &mut tab, 0);
            assert!((*ptr::addr_of!(SEEN)).is_empty(), "views never evaluate defaults");
            assert_eq!(op.p4, ptr::null_mut());
            assert_eq!(op.p4type, P4_NOTUSED);
        }
    }

    #[test]
    fn default_value_is_attached_as_p4_mem() {
        let Some(slab) = slab_or_skip() else { unreachable!() };
        unsafe {
            let (db, cols) = db_fixture(slab, 2);
            let value = slab.add(0x600);
            let _bench = bench(value);
            let mut op = blank_op();
            let mut v = vdbe(db, &mut op, 1);
            let mut tab = table(cols, ptr::null_mut());
            column_default(&mut v, &mut tab, 2);
            let seen = &*ptr::addr_of!(SEEN);
            assert_eq!(seen.len(), 1);
            assert_eq!(
                seen[0],
                (db, 0x33usize as *const u8, 2, b'b' as u32),
                "column 2's pDflt, the schema encoding, the column affinity"
            );
            assert_eq!(op.p4, value, "P4 gets the evaluated value");
            assert_eq!(op.p4type, P4_MEM as i8);
        }
    }

    #[test]
    fn column_zero_uses_first_column() {
        let Some(slab) = slab_or_skip() else { unreachable!() };
        unsafe {
            let (db, cols) = db_fixture(slab, 1);
            let value = slab.add(0x600);
            let _bench = bench(value);
            let mut op = blank_op();
            let mut v = vdbe(db, &mut op, 1);
            let mut tab = table(cols, ptr::null_mut());
            column_default(&mut v, &mut tab, 0);
            let seen = &*ptr::addr_of!(SEEN);
            assert_eq!(seen.len(), 1);
            assert_eq!(seen[0].1, 0x11usize as *const u8);
            assert_eq!(seen[0].3, b'd' as u32);
            assert_eq!(op.p4, value);
            assert_eq!(op.p4type, P4_MEM as i8);
        }
    }

    #[test]
    fn null_value_leaves_the_op_alone() {
        let Some(slab) = slab_or_skip() else { unreachable!() };
        unsafe {
            let (db, cols) = db_fixture(slab, 1);
            let _bench = bench(ptr::null_mut());
            let mut op = blank_op();
            let mut v = vdbe(db, &mut op, 1);
            let mut tab = table(cols, ptr::null_mut());
            column_default(&mut v, &mut tab, 1);
            assert_eq!((*ptr::addr_of!(SEEN)).len(), 1, "still evaluates");
            assert_eq!(op.p4, ptr::null_mut(), "no P4 when no value came back");
            assert_eq!(op.p4type, P4_NOTUSED);
        }
    }
}
