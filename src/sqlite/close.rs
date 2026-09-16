//! SQLite connection shutdown.
//!
//! `sqlite3_close` — original `FUN_083824b0` at load address `0x083824b0`.
//! Raw ARM establishes the exact 208-byte extent `0x083824b0..0x08382580`:
//! the next function starts with `push` at `0x08382580`. Decoding every ARM
//! B/BL word in that range finds **7 plain unconditional `bl` calls** and no
//! predicated calls (not the four Ghidra reported).
//!
//! The routine enters a benign allocation-fault region, closes every non-null
//! `Db.pBt` in the target-width 24-byte `aDb` array, clears those fields,
//! releases the virtual-table unlock list, and leaves the benign region. When
//! `SQLITE_InternChanges` is set it expires prepared statements and resets the
//! internal schema. Finally it invokes `xCommitCallback(pCommitArg)` if a
//! Btree close reported work or no active Vdbe remains.
//!
//! Deliberate deviation: the three unported direct callees and callback are a
//! volatile dispatch table on the host. Target builds preserve their absolute
//! retailOS boundaries; target-width words are used for all pointer fields.

use crate::sqlite::expire_prepared_statements::{sqlite3_expire_prepared_statements, Connection};
use crate::sqlite::mem::{fault_begin_benign, fault_end_benign};

const INTERN_CHANGES: u32 = 0x10;
const DB_STRIDE: usize = 0x18;
const DB_BTREE: usize = 4;
const ACTIVE_VDBE: usize = 0x1c;
const A_DB: usize = 8;
const N_DB: usize = 4;
const FLAGS: usize = 0xc;
const COMMIT_ARG: usize = 0xac;
const COMMIT_CALLBACK: usize = 0xb0;

pub type BtreeClose = unsafe extern "C" fn(*mut u8) -> i32;
pub type VtabUnlockList = unsafe extern "C" fn(*mut u8, i32);
pub type ResetInternalSchema = unsafe extern "C" fn(*mut u8, i32);
pub type CommitCallback = unsafe extern "C" fn(*mut u8);

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_btree_close(btree: *mut u8) -> i32 {
    core::mem::transmute::<usize, BtreeClose>(0x0837_2b50)(btree)
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn retail_btree_close(_: *mut u8) -> i32 { panic!("sqlite3_close requires sqlite3BtreeClose @ 0x08372b50") }
#[cfg(target_os = "none")]
unsafe extern "C" fn retail_vtab_unlock_list(db: *mut u8, offset: i32) {
    core::mem::transmute::<usize, VtabUnlockList>(0x082b_ead4)(db, offset)
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn retail_vtab_unlock_list(_: *mut u8, _: i32) { panic!("sqlite3_close requires sqlite3VtabUnlockList @ 0x082bead4") }
#[cfg(target_os = "none")]
unsafe extern "C" fn retail_reset_internal_schema(db: *mut u8, flags: i32) {
    core::mem::transmute::<usize, ResetInternalSchema>(0x0838_209c)(db, flags)
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn retail_reset_internal_schema(_: *mut u8, _: i32) { panic!("sqlite3_close requires sqlite3ResetInternalSchema @ 0x0838209c") }

pub struct CloseOps {
    pub btree_close: BtreeClose,
    pub vtab_unlock_list: VtabUnlockList,
    pub reset_internal_schema: ResetInternalSchema,
    pub commit_callback: Option<CommitCallback>,
}

pub static mut SQLITE_CLOSE_OPS: CloseOps = CloseOps {
    btree_close: retail_btree_close,
    vtab_unlock_list: retail_vtab_unlock_list,
    reset_internal_schema: retail_reset_internal_schema,
    commit_callback: None,
};

#[inline(always)]
unsafe fn word(object: *mut u8, offset: usize) -> u32 {
    core::ptr::read(object.add(offset).cast())
}
#[inline(always)]
unsafe fn set_word(object: *mut u8, offset: usize, value: u32) {
    core::ptr::write(object.add(offset).cast(), value);
}
#[inline(always)]
unsafe fn close_ops() -> CloseOps {
    core::ptr::read_volatile(core::ptr::addr_of!(SQLITE_CLOSE_OPS))
}

/// Close a SQLite connection. `db` is the target-layout `sqlite3` object.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn sqlite3_close(db: *mut u8) {
    fault_begin_benign(0);
    let ops = close_ops();
    let count = word(db, N_DB) as i32;
    let databases = word(db, A_DB) as usize as *mut u8;
    let mut closed_work = false;
    let mut index = 0;
    while index < count {
        let entry = databases.add(index as usize * DB_STRIDE);
        let btree = word(entry, DB_BTREE) as usize as *mut u8;
        if !btree.is_null() {
            closed_work |= (ops.btree_close)(btree) != 0;
            set_word(entry, DB_BTREE, 0);
        }
        index += 1;
    }
    (ops.vtab_unlock_list)(db, 0x44);
    fault_end_benign(0);
    if word(db, FLAGS) & INTERN_CHANGES != 0 {
        sqlite3_expire_prepared_statements(db.cast::<Connection>());
        (ops.reset_internal_schema)(db, 0);
    }
    if word(db, COMMIT_CALLBACK) != 0 && (closed_work || *db.add(ACTIVE_VDBE) == 0) {
        if let Some(callback) = ops.commit_callback {
            callback(word(db, COMMIT_ARG) as usize as *mut u8);
        } else {
            core::mem::transmute::<usize, CommitCallback>(word(db, COMMIT_CALLBACK) as usize)(word(db, COMMIT_ARG) as usize as *mut u8);
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::testing::{hints, try_map_u32_slab};
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut CALLS: [(u8, usize); 8] = [(0, 0); 8];
    static mut COUNT: usize = 0;
    unsafe fn record(kind: u8, value: usize) { CALLS[COUNT] = (kind, value); COUNT += 1; }
    unsafe extern "C" fn btree(p: *mut u8) -> i32 { record(1, p as usize); if p as usize & 1 != 0 { 1 } else { 0 } }
    unsafe extern "C" fn unlock(p: *mut u8, n: i32) { record(2, p as usize | n as usize); }
    unsafe extern "C" fn reset(p: *mut u8, n: i32) { record(3, p as usize | n as usize); }
    unsafe extern "C" fn callback(p: *mut u8) { record(4, p as usize); }
    unsafe fn install() { COUNT = 0; core::ptr::write_volatile(core::ptr::addr_of_mut!(SQLITE_CLOSE_OPS), CloseOps { btree_close: btree, vtab_unlock_list: unlock, reset_internal_schema: reset, commit_callback: Some(callback) }); }
    unsafe fn restore() { core::ptr::write_volatile(core::ptr::addr_of_mut!(SQLITE_CLOSE_OPS), CloseOps { btree_close: retail_btree_close, vtab_unlock_list: retail_vtab_unlock_list, reset_internal_schema: retail_reset_internal_schema, commit_callback: None }); }

    #[test]
    fn closes_each_btree_then_releases_and_calls_commit_when_worked() {
        let _lock = LOCK.lock();
        let Some(slab) = try_map_u32_slab(hints::SQLITE_CLOSE, 0x1000) else { return };
        unsafe {
            core::ptr::write_bytes(slab, 0, 0x1000);
            let db = slab;
            let entries = slab.add(0x400);
            set_word(db, N_DB, 2); set_word(db, A_DB, entries as usize as u32);
            set_word(entries, DB_BTREE, slab.add(0x801) as usize as u32);
            set_word(entries.add(DB_STRIDE), DB_BTREE, slab.add(0x802) as usize as u32);
            set_word(db, COMMIT_ARG, slab.add(0x900) as usize as u32); set_word(db, COMMIT_CALLBACK, 1);
            *db.add(ACTIVE_VDBE) = 9;
            install(); sqlite3_close(db); restore();
            assert_eq!(word(entries, DB_BTREE), 0); assert_eq!(word(entries.add(DB_STRIDE), DB_BTREE), 0);
            assert_eq!(&CALLS[..COUNT], &[(1, slab.add(0x801) as usize), (1, slab.add(0x802) as usize), (2, db as usize | 0x44), (4, slab.add(0x900) as usize)]);
        }
    }

    #[test]
    fn schema_change_expires_statements_and_resets_before_idle_callback() {
        let _lock = LOCK.lock();
        let Some(slab) = try_map_u32_slab(hints::SQLITE_CLOSE_SCHEMA, 0x1000) else { return };
        unsafe {
            core::ptr::write_bytes(slab, 0, 0x1000);
            set_word(slab, N_DB, 0); set_word(slab, A_DB, slab.add(0x400) as usize as u32); set_word(slab, FLAGS, INTERN_CHANGES);
            set_word(slab, COMMIT_ARG, slab.add(0x900) as usize as u32); set_word(slab, COMMIT_CALLBACK, 1);
            install(); sqlite3_close(slab); restore();
            assert_eq!(&CALLS[..COUNT], &[(2, slab as usize | 0x44), (3, slab as usize), (4, slab.add(0x900) as usize)]);
        }
    }
}
