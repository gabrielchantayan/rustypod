//! Starting a write transaction on the databases a statement touches.
//!
//! - `begin_write_operation` — original: `FUN_0837021c` @ 0x0837021c
//!   (124 bytes, 0x0837021c..0x08370297 in the raw image; the next
//!   function starts at 0x08370298). 17 `bl` call sites, zero
//!   predicated — verified by decoding every B/BL word in osos.dec,
//!   not from Ghidra's listing. SQLite's `sqlite3BeginWriteOperation`,
//!   the 3.5.x-era shape: it works on `pParse` directly (no
//!   `sqlite3ParseToplevel` walk, no `isWrite` store).
//!
//! For database `i_db` the function
//!
//! 1. fetches the statement under construction (`sqlite3GetVdbe`),
//!    bailing out when there is none;
//! 2. emits the schema-cookie verification for `i_db`
//!    (`sqlite3CodeVerifySchema`);
//! 3. sets bit `i_db` in `Parse.writeMask` (+0x100) so the prologue
//!    later opens a write transaction on that database;
//! 4. when the caller asked for statement journaling (`set_statement`)
//!    AND this is not a nested parse (`Parse.nested`, byte at +0x13),
//!    appends `OP_Statement i_db` (opcode 0x2a — this build's
//!    numbering, see `sqlite/vdbe_opcode_has_property.rs`);
//! 5. and finally, whenever `i_db != 1` and the temp database is
//!    attached (`db->aDb[1].pBt != NULL` — `aDb` at +0x08 of the
//!    connection, `Db` stride 0x18, `pBt` at +0x04, i.e. the word at
//!    aDb+0x1c), repeats the whole sequence for the temp database.
//!    Upstream recurses; the firmware's compiler folded the tail
//!    recursion into a loop (`movne r5,#1; bne` back to the top),
//!    which this port keeps.
//!
//! The `Db` stride of 0x18 is corroborated independently by
//! `sqlite3CodeVerifySchema` @ 0x083734bc, which indexes `aDb` with
//! `iDb*24` (`add r1,r5,r5,lsl#1; add r0,r0,r1,lsl#3`).
//!
//! Deliberate deviations from the original instruction stream:
//!
//! - `sqlite3GetVdbe` @ 0x0837acf4 rides the [`BEGIN_WRITE_OPS`]
//!   dispatch boundary (house pattern — see `sqlite/error_msg.rs`).
//!   Its names.yaml entry claims `status: ported` in `sqlite/vdbe`,
//!   but no such symbol exists in `src/` on any branch: the entry was
//!   added as `identified` in dda6c20 and a later merge flipped the
//!   status without the code ever landing. The shipped default,
//!   [`stored_p_vdbe`], returns `Parse.pVdbe` (+0x0c) verbatim — exact
//!   whenever a statement is already under construction (every real
//!   caller has run the code generator's own `sqlite3GetVdbe` by this
//!   point). When `pVdbe` is NULL the original attempts creation
//!   through the unported `sqlite3VdbeCreate` @ 0x08386c44, whose own
//!   documented default fails (OOM end state: `pVdbe` stays NULL and
//!   NULL is returned) — the stand-in reaches the same end state.
//! - `sqlite3CodeVerifySchema` @ 0x083734bc is UNPORTED and rides the
//!   second slot. Its shipped default is the documented no-op
//!   [`missing_code_verify_schema`]: no cookie-verification ops are
//!   emitted and `cookieMask`/`cookieValue` are untouched. The
//!   load-bearing effects of this function itself (the `writeMask`
//!   update, the `OP_Statement` emission, the temp-database pass) are
//!   unaffected.
//! - `sqlite3VdbeAddOp1` @ 0x08386810 is ported
//!   ([`crate::sqlite::vdbe::vdbe_add_op1`]) and is called directly,
//!   per the house precedent (direct calls for ported callees).
//! - The mask update is `1 << iDb` where the original's
//!   `orr r0,r0,r1,lsl r5` takes the shift amount from the low byte of
//!   the register and yields 0 for amounts 32..=255. The port uses
//!   `checked_shl(i_db & 0xff)`, which matches the ARM semantics
//!   exactly (Rust's `<<` would instead be an overflow for >= 32).
//! - `Parse`, the connection and `Db` are typed `#[repr(C)]` records
//!   rather than raw byte offsets, so the pointer fields cannot
//!   overlap on a 64-bit host. The original offsets are asserted on
//!   the 32-bit target.

use crate::sqlite::vdbe::{vdbe_add_op1, Vdbe};

/// `OP_Statement` in this build's opcode numbering (original:
/// `moveq r1,#0x2a`; corroborated by the opcode-property table in
/// `sqlite/vdbe_opcode_has_property.rs`). Marks database `p1` as being
/// in a statement transaction so a later failure can roll back to the
/// statement boundary instead of aborting the whole transaction.
pub const OP_STATEMENT: i32 = 0x2a;

/// The fields of SQLite's `Parse` this helper touches. The unmodeled
/// spans keep the recovered offsets.
#[repr(C)]
pub struct Parse {
    /// +0x000: the owning connection (`sqlite3 *`).
    pub db: *mut Connection,
    /// +0x004..+0x00c: unmodeled.
    pub _gap_04: [u8; 0x0c - 0x04],
    /// +0x00c: the VDBE under construction (`pVdbe`).
    pub p_vdbe: *mut Vdbe,
    /// +0x010..+0x013: unmodeled.
    pub _gap_10: [u8; 0x13 - 0x10],
    /// +0x013: non-zero while parsing a nested (trigger/fkey) program —
    /// suppresses `OP_Statement` (original: `ldrb r0,[r4,#19]`).
    pub nested: u8,
    /// +0x014..+0x100: unmodeled.
    pub _gap_14: [u8; 0x100 - 0x14],
    /// +0x100: bitmask of databases this statement writes
    /// (`writeMask`); the prologue starts a write transaction per bit.
    pub write_mask: u32,
}

/// The fields of the connection (`sqlite3`) this helper touches.
#[repr(C)]
pub struct Connection {
    /// +0x000..+0x008: unmodeled (`pVfs`, `nDb`).
    pub _gap_00: [u8; 8],
    /// +0x008: the attached-database array (`aDb`), `nDb` entries.
    pub a_db: *mut Db,
}

/// One attached database (SQLite's `Db`), 0x18 bytes on target. Only
/// `pBt` is read here; the stride itself is load-bearing because the
/// original reaches `aDb[1].pBt` as the word at `aDb + 0x1c`.
#[repr(C)]
pub struct Db {
    /// +0x00: the attachment name ("main", "temp", ...), borrowed.
    pub z_name: *const u8,
    /// +0x04: the B-tree backing the database; NULL while unattached.
    pub p_bt: *mut u8,
    /// +0x08..+0x18: unmodeled (`inTrans`, `safety_level`, `pSchema`,
    /// the schema cookie...).
    pub _gap_08: [u8; 0x18 - 0x08],
}

// The original's layout, asserted on the 32-bit target. On a 64-bit
// host the pointer fields widen and these shift — harmless, because
// every access goes through the typed structs.
#[cfg(target_pointer_width = "32")]
const _: () = {
    assert!(core::mem::offset_of!(Parse, p_vdbe) == 0x0c);
    assert!(core::mem::offset_of!(Parse, nested) == 0x13);
    assert!(core::mem::offset_of!(Parse, write_mask) == 0x100);
    assert!(core::mem::offset_of!(Connection, a_db) == 0x08);
    assert!(core::mem::size_of::<Db>() == 0x18);
    assert!(core::mem::offset_of!(Db, p_bt) == 0x04);
};

/// Indirect dispatch for the two callees of the original that are not
/// available as Rust symbols, kept behind the table so host tests can
/// observe the calls' arguments (the house pattern —
/// `sqlite/cell_size.rs`).
#[derive(Clone, Copy)]
pub struct BeginWriteOps {
    /// `sqlite3GetVdbe` @ 0x0837acf4 (claimed ported by names.yaml but
    /// absent from the tree — see the module header): fetch the
    /// statement under construction, or NULL.
    pub get_vdbe: unsafe extern "C" fn(parse: *mut Parse) -> *mut Vdbe,
    /// `sqlite3CodeVerifySchema` @ 0x083734bc (UNPORTED): emit the
    /// schema-cookie verification for database `i_db`.
    pub code_verify_schema: unsafe extern "C" fn(parse: *mut Parse, i_db: i32),
}

/// Stand-in for the absent `sqlite3GetVdbe` port: return the stored
/// `Parse.pVdbe` verbatim. Exact whenever a statement is already under
/// construction; on NULL it reaches the same end state the original
/// reaches when the (unported) constructor fails — see the module
/// header.
unsafe extern "C" fn stored_p_vdbe(parse: *mut Parse) -> *mut Vdbe {
    (*parse).p_vdbe
}

/// Stand-in for the unported `sqlite3CodeVerifySchema` @ 0x083734bc
/// (same reasoning as `sqlite/blob_to_hex.rs`'s no-op): no
/// cookie-verification ops are emitted. `begin_write_operation`'s own
/// observable effects are unchanged.
unsafe extern "C" fn missing_code_verify_schema(_parse: *mut Parse, _i_db: i32) {}

/// Wired default for [`BEGIN_WRITE_OPS`]: the 0x0837acf4 stored-value
/// stand-in and the 0x083734bc no-op (both target and host) until the
/// callees are ported for real.
pub const DEFAULT_BEGIN_WRITE_OPS: BeginWriteOps = BeginWriteOps {
    get_vdbe: stored_p_vdbe,
    code_verify_schema: missing_code_verify_schema,
};

/// Active models of the original's two unavailable callees. Host tests
/// replace the slots to observe the exact arguments.
pub static mut BEGIN_WRITE_OPS: BeginWriteOps = DEFAULT_BEGIN_WRITE_OPS;

/// Reads the `sqlite3GetVdbe` slot. Volatile so LLVM cannot
/// constant-fold the load to the stand-in default (the house pattern —
/// `sqlite/cell_size.rs`).
#[inline(always)]
pub(crate) unsafe fn get_vdbe_op() -> unsafe extern "C" fn(*mut Parse) -> *mut Vdbe {
    core::ptr::read_volatile(core::ptr::addr_of!(BEGIN_WRITE_OPS.get_vdbe))
}

/// Reads the `sqlite3CodeVerifySchema` slot (volatile, as above).
#[inline(always)]
pub(crate) unsafe fn code_verify_schema_op() -> unsafe extern "C" fn(*mut Parse, i32) {
    core::ptr::read_volatile(core::ptr::addr_of!(BEGIN_WRITE_OPS.code_verify_schema))
}

/// begin_write_operation — original: `FUN_0837021c` @ 0x0837021c
/// (124 bytes; 17 `bl` call sites, binary-verified).
///
/// `sqlite3BeginWriteOperation`: declare that the statement being
/// compiled writes database `i_db`. Sets bit `i_db` in
/// `Parse.writeMask`, emits the schema-cookie verification for the
/// database, and — for a top-level parse when `set_statement` is
/// requested — appends `OP_Statement i_db`. When the temp database is
/// attached and `i_db != 1`, the sequence repeats once with `i_db = 1`
/// (the original's tail recursion, folded into a loop by its
/// compiler). Does nothing when there is no VDBE under construction.
///
/// # Safety
/// `parse` must point to a writable recovered [`Parse`] whose `db`
/// names a live [`Connection`] holding at least two [`Db`] entries
/// (the temp-database probe reads `aDb[1]` unconditionally when
/// `i_db != 1`).
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn begin_write_operation(
    parse: *mut Parse,
    set_statement: i32,
    i_db: i32,
) {
    let mut i_db = i_db;
    loop {
        let v = (get_vdbe_op())(parse);
        if v.is_null() {
            return;
        }
        (code_verify_schema_op())(parse, i_db);
        // `orr r0,r0,r1,lsl r5`: shift amount is the low byte of the
        // register, amounts 32..=255 yield 0. `checked_shl` matches.
        (*parse).write_mask |= 1u32.checked_shl(i_db as u32 & 0xff).unwrap_or(0);
        if set_statement != 0 && (*parse).nested == 0 {
            vdbe_add_op1(v, OP_STATEMENT, i_db);
        }
        // `cmp r5,#1; ldrne r0,[r4]; ldrne r0,[r0,#8]; ldrne
        // r0,[r0,#0x1c]; cmpne r0,#0; movne r5,#1; bne <top>` — the
        // temp database gets the same treatment when it is attached.
        if i_db != 1 && !(*(*(*parse).db).a_db.add(1)).p_bt.is_null() {
            i_db = 1;
        } else {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::sqlite::vdbe::VdbeOp;
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    /// Serializes tests that swap the dispatch slots: the seams are
    /// process-global.
    static OPS_LOCK: Mutex<()> = Mutex::new(());

    /// Every `i_db` the recording `sqlite3CodeVerifySchema` was called
    /// with, in order.
    static mut VERIFY_CALLS: Vec<i32> = Vec::new();

    /// How often the recording `sqlite3GetVdbe` ran.
    static mut GET_VDBE_CALLS: u32 = 0;

    /// What the recording `sqlite3GetVdbe` returns.
    static mut MOCK_VDBE: *mut Vdbe = core::ptr::null_mut();

    unsafe extern "C" fn recording_verify_schema(_parse: *mut Parse, i_db: i32) {
        (*core::ptr::addr_of_mut!(VERIFY_CALLS)).push(i_db);
    }

    unsafe extern "C" fn recording_get_vdbe(_parse: *mut Parse) -> *mut Vdbe {
        *core::ptr::addr_of_mut!(GET_VDBE_CALLS) += 1;
        *core::ptr::addr_of!(MOCK_VDBE)
    }

    fn verify_calls() -> Vec<i32> {
        unsafe { (*core::ptr::addr_of!(VERIFY_CALLS)).clone() }
    }

    fn get_vdbe_calls() -> u32 {
        unsafe { *core::ptr::addr_of!(GET_VDBE_CALLS) }
    }

    /// Installs the recording mocks and returns the lock guard, which
    /// must stay alive for the whole test. Restores the shipped
    /// defaults on drop, matching the other SQLite seam tests.
    struct Bench {
        _guard: MutexGuard<'static, ()>,
    }

    fn bench(vdbe: *mut Vdbe) -> Bench {
        let guard = OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            (*core::ptr::addr_of_mut!(VERIFY_CALLS)).clear();
            *core::ptr::addr_of_mut!(GET_VDBE_CALLS) = 0;
            *core::ptr::addr_of_mut!(MOCK_VDBE) = vdbe;
            core::ptr::write_volatile(
                core::ptr::addr_of_mut!(BEGIN_WRITE_OPS),
                BeginWriteOps {
                    get_vdbe: recording_get_vdbe,
                    code_verify_schema: recording_verify_schema,
                },
            );
        }
        Bench { _guard: guard }
    }

    impl Drop for Bench {
        fn drop(&mut self) {
            unsafe {
                core::ptr::write_volatile(
                    core::ptr::addr_of_mut!(BEGIN_WRITE_OPS),
                    DEFAULT_BEGIN_WRITE_OPS,
                );
            }
        }
    }

    /// A `Vdbe` with room for two ops (growth is `vdbe_add_op3`'s
    /// business, covered by its own tests).
    struct Statement {
        ops: [VdbeOp; 2],
        vdbe: Vdbe,
    }

    impl Statement {
        fn new() -> Self {
            Statement {
                ops: [VdbeOp {
                    opcode: 0xff,
                    p4type: 0x7f,
                    opflags: 0xee,
                    p5: 0xdd,
                    p1: -1,
                    p2: -1,
                    p3: -1,
                    p4: 0x1usize as *mut u8,
                }; 2],
                vdbe: Vdbe {
                    db: core::ptr::null_mut(),
                    _gap_04: [0; 8],
                    n_op: 0,
                    n_op_alloc: 2,
                    a_op: core::ptr::null_mut(),
                    n_label: 0,
                    n_label_alloc: 0,
                    a_label: core::ptr::null_mut(),
                    _gap_24: [0; 4],
                    a_col_name: core::ptr::null_mut(),
                    _gap_2c: [0; 0xec - 0x2c],
                    n_res_column: 0,
                    _gap_f0: [0; 0xff - 0xf0],
                    expired: 1,
                },
            }
        }
        /// The `Vdbe` pointer, with `a_op` re-pinned to `ops` (the
        /// `Statement` moves after `new()` returns, so wiring `a_op`
        /// inside `new()` would leave it pointing at the dead slot).
        fn ptr(&mut self) -> *mut Vdbe {
            self.vdbe.a_op = self.ops.as_mut_ptr();
            &mut self.vdbe
        }
    }

    /// A connection with a two-entry `aDb` ("main" and "temp").
    struct DbPair {
        dbs: [Db; 2],
        conn: Connection,
    }

    impl DbPair {
        fn new(temp_p_bt: *mut u8) -> Self {
            DbPair {
                dbs: [
                    Db {
                        z_name: core::ptr::null(),
                        p_bt: 0xb7_0001usize as *mut u8,
                        _gap_08: [0; 0x10],
                    },
                    Db {
                        z_name: core::ptr::null(),
                        p_bt: temp_p_bt,
                        _gap_08: [0; 0x10],
                    },
                ],
                conn: Connection {
                    _gap_00: [0; 8],
                    a_db: core::ptr::null_mut(),
                },
            }
        }
        /// The `Connection` pointer, with `a_db` re-pinned to `dbs`
        /// (same move-after-`new()` hazard as `Statement::ptr`).
        fn ptr(&mut self) -> *mut Connection {
            self.conn.a_db = self.dbs.as_mut_ptr();
            &mut self.conn
        }
    }

    fn parse(db: *mut Connection, p_vdbe: *mut Vdbe, nested: u8) -> Parse {
        Parse {
            db,
            _gap_04: [0; 8],
            p_vdbe,
            _gap_10: [0; 3],
            nested,
            _gap_14: [0; 0xec],
            write_mask: 0,
        }
    }

    #[test]
    fn sets_mask_and_emits_op_statement() {
        let mut stmt = Statement::new();
        let mut pair = DbPair::new(core::ptr::null_mut());
        let _bench = bench(stmt.ptr());
        let mut parse = parse(pair.ptr(), core::ptr::null_mut(), 0);
        unsafe { begin_write_operation(&mut parse, 1, 0) };
        assert_eq!(parse.write_mask, 0x1, "bit 0 set for the main database");
        assert_eq!(stmt.vdbe.n_op, 1, "exactly one op appended");
        let op = &stmt.ops[0];
        assert_eq!(op.opcode, OP_STATEMENT as u8, "opcode 0x2a = OP_Statement");
        assert_eq!(op.p1, 0, "p1 = database index");
        assert_eq!(op.p2, 0, "vdbe_add_op1 zeroes p2");
        assert_eq!(op.p3, 0, "vdbe_add_op1 zeroes p3");
        assert_eq!(verify_calls(), [0], "schema verified for iDb = 0");
        assert_eq!(get_vdbe_calls(), 1, "one Vdbe fetch, no temp pass");
    }

    #[test]
    fn set_statement_zero_skips_the_op_but_keeps_the_rest() {
        let mut stmt = Statement::new();
        let mut pair = DbPair::new(core::ptr::null_mut());
        let _bench = bench(stmt.ptr());
        let mut parse = parse(pair.ptr(), core::ptr::null_mut(), 0);
        unsafe { begin_write_operation(&mut parse, 0, 0) };
        assert_eq!(parse.write_mask, 0x1, "mask still updated");
        assert_eq!(stmt.vdbe.n_op, 0, "no OP_Statement");
        assert_eq!(verify_calls(), [0], "schema still verified");
    }

    #[test]
    fn nested_parse_skips_the_op_but_keeps_the_rest() {
        let mut stmt = Statement::new();
        let mut pair = DbPair::new(core::ptr::null_mut());
        let _bench = bench(stmt.ptr());
        let mut parse = parse(pair.ptr(), core::ptr::null_mut(), 1);
        unsafe { begin_write_operation(&mut parse, 1, 0) };
        assert_eq!(parse.write_mask, 0x1, "mask still updated");
        assert_eq!(stmt.vdbe.n_op, 0, "nested parse emits no OP_Statement");
        assert_eq!(verify_calls(), [0]);
    }

    #[test]
    fn no_vdbe_returns_before_touching_anything() {
        let mut pair = DbPair::new(core::ptr::null_mut());
        let _bench = bench(core::ptr::null_mut());
        let mut parse = parse(pair.ptr(), core::ptr::null_mut(), 0);
        parse.write_mask = 0xdead_beef;
        unsafe { begin_write_operation(&mut parse, 1, 0) };
        assert_eq!(parse.write_mask, 0xdead_beef, "mask untouched");
        assert_eq!(verify_calls(), Vec::<i32>::new(), "schema never verified");
        assert_eq!(get_vdbe_calls(), 1, "the NULL check is the only work done");
    }

    #[test]
    fn attached_temp_db_repeats_the_sequence_with_idb_1() {
        let mut stmt = Statement::new();
        let mut pair = DbPair::new(0xb7_0002usize as *mut u8);
        let _bench = bench(stmt.ptr());
        let mut parse = parse(pair.ptr(), core::ptr::null_mut(), 0);
        unsafe { begin_write_operation(&mut parse, 1, 2) };
        assert_eq!(
            parse.write_mask,
            (1 << 2) | (1 << 1),
            "both the requested database and temp are marked"
        );
        assert_eq!(stmt.vdbe.n_op, 2, "one OP_Statement per database");
        assert_eq!(stmt.ops[0].opcode, OP_STATEMENT as u8);
        assert_eq!(stmt.ops[0].p1, 2, "first pass: the requested database");
        assert_eq!(stmt.ops[1].opcode, OP_STATEMENT as u8);
        assert_eq!(stmt.ops[1].p1, 1, "second pass: the temp database");
        assert_eq!(verify_calls(), [2, 1], "schema verified per database");
        assert_eq!(get_vdbe_calls(), 2, "the Vdbe is re-fetched on the temp pass");
    }

    #[test]
    fn idb_1_does_not_recurse_even_with_temp_attached() {
        // `cmp r5,#1` short-circuits the temp probe: the ldr chain is
        // predicated `ne`, so iDb == 1 never even reads aDb.
        let mut stmt = Statement::new();
        let mut pair = DbPair::new(0xb7_0002usize as *mut u8);
        let _bench = bench(stmt.ptr());
        let mut parse = parse(pair.ptr(), core::ptr::null_mut(), 0);
        unsafe { begin_write_operation(&mut parse, 1, 1) };
        assert_eq!(parse.write_mask, 1 << 1, "only the temp bit");
        assert_eq!(stmt.vdbe.n_op, 1, "a single pass");
        assert_eq!(verify_calls(), [1]);
    }

    #[test]
    fn shift_amounts_of_32_or_more_leave_the_mask_unchanged() {
        // ARM register shift semantics: `1 lsl r5` is 0 when the low
        // byte of the amount is 32..=255. Callers never pass such an
        // iDb, but the port must not trap on one.
        let mut stmt = Statement::new();
        let mut pair = DbPair::new(core::ptr::null_mut());
        let _bench = bench(stmt.ptr());
        let mut parse = parse(pair.ptr(), core::ptr::null_mut(), 0);
        unsafe { begin_write_operation(&mut parse, 1, 33) };
        assert_eq!(parse.write_mask, 0, "1 << 33 is 0 on ARM");
        assert_eq!(stmt.vdbe.n_op, 1, "the op still goes out with p1 = 33");
        assert_eq!(stmt.ops[0].p1, 33);
        assert_eq!(verify_calls(), [33]);
    }

    #[test]
    fn default_get_vdbe_returns_the_stored_p_vdbe() {
        // Full pipeline on the shipped defaults: only the
        // schema-verification no-op stands between the port and the
        // real `vdbe_add_op1`.
        let _guard = OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut stmt = Statement::new();
        let mut pair = DbPair::new(core::ptr::null_mut());
        let vdbe = stmt.ptr();
        let mut parse = parse(pair.ptr(), vdbe, 0);
        assert_eq!(unsafe { stored_p_vdbe(&mut parse) }, vdbe);
        unsafe { begin_write_operation(&mut parse, 1, 3) };
        assert_eq!(parse.write_mask, 1 << 3);
        assert_eq!(stmt.vdbe.n_op, 1);
        assert_eq!(stmt.ops[0].opcode, OP_STATEMENT as u8);
        assert_eq!(stmt.ops[0].p1, 3);
    }

    #[test]
    fn default_ops_use_the_stand_ins() {
        let get_vdbe: unsafe extern "C" fn(*mut Parse) -> *mut Vdbe =
            DEFAULT_BEGIN_WRITE_OPS.get_vdbe;
        let verify: unsafe extern "C" fn(*mut Parse, i32) =
            DEFAULT_BEGIN_WRITE_OPS.code_verify_schema;
        assert_eq!(get_vdbe as usize, stored_p_vdbe as usize);
        assert_eq!(verify as usize, missing_code_verify_schema as usize);
    }
}
