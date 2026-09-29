//! SQLite temporary-storage reset.
//!
//! `change_temp_storage` — original `FUN_082d6d24` at load address
//! `0x082d6d24`. Raw ARM establishes the exact 92-byte extent
//! `0x082d6d24..0x082d6d80`: the following bytes are the NUL-terminated
//! diagnostic string, not instructions. Decoding every ARM B/BL-immediate
//! word finds **3 plain unconditional `bl` calls** and no predicated calls;
//! complete-image decoding finds two inbound plain `bl` instructions at
//! `0x0837fb4c` and `0x0837fc34`.
//!
//! When the temporary database has a Btree, reject the change while an active
//! Vdbe exists; otherwise close that Btree, clear its target-width `aDb[1]`
//! pointer, and reset the connection's internal schema. It returns one only
//! for the active-statement rejection.
//!
//! Deliberate deviations: `sqlite3BtreeClose` @ `0x08370a20` and
//! `sqlite3ResetInternalSchema` @ `0x0838209c` remain volatile dispatch seams
//! on the host; target builds invoke their retailOS addresses. `sqlite3ErrorMsg`
//! @ `0x083767a0` is ported and called directly. Target pointer fields are u32
//! words so their offsets remain correct on 64-bit host fixtures.

use crate::sqlite::error_msg::{sqlite_error_msg, Parse};

const A_DB: usize = 8;
const TEMP_BTREE: usize = 0x1c;
const ACTIVE_VDBE: usize = 0x1c;
const TEMP_STORAGE_CHANGE_MESSAGE: &[u8] = b"temporary storage cannot be changed from within a transaction\0";

pub type BtreeClose = unsafe extern "C" fn(*mut u8) -> i32;
pub type ResetInternalSchema = unsafe extern "C" fn(*mut u8, i32);

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_btree_close(btree: *mut u8) -> i32 {
    core::mem::transmute::<usize, BtreeClose>(0x0837_0a20)(btree)
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn retail_btree_close(_: *mut u8) -> i32 { panic!("change_temp_storage requires sqlite3BtreeClose @ 0x08370a20") }
#[cfg(target_os = "none")]
unsafe extern "C" fn retail_reset_internal_schema(db: *mut u8, flags: i32) {
    core::mem::transmute::<usize, ResetInternalSchema>(0x0838_209c)(db, flags)
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn retail_reset_internal_schema(_: *mut u8, _: i32) { panic!("change_temp_storage requires sqlite3ResetInternalSchema @ 0x0838209c") }

pub struct TempStorageOps {
    pub btree_close: BtreeClose,
    pub reset_internal_schema: ResetInternalSchema,
}

pub static mut SQLITE_TEMP_STORAGE_OPS: TempStorageOps = TempStorageOps {
    btree_close: retail_btree_close,
    reset_internal_schema: retail_reset_internal_schema,
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
unsafe fn temp_storage_ops() -> TempStorageOps {
    core::ptr::read_volatile(core::ptr::addr_of!(SQLITE_TEMP_STORAGE_OPS))
}

/// Close the temporary Btree before its storage mode changes.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn change_temp_storage(parse: *mut Parse) -> i32 {
    let db = (*parse).db;
    let temp_btree_slot = (word(db, A_DB) as usize as *mut u8).add(TEMP_BTREE);
    let temp_btree = word(temp_btree_slot, 0) as usize as *mut u8;
    if temp_btree.is_null() {
        return 0;
    }
    if *db.add(ACTIVE_VDBE) == 0 {
        let ops = temp_storage_ops();
        (ops.btree_close)(temp_btree);
        set_word(temp_btree_slot, 0, 0);
        (ops.reset_internal_schema)(db, 0);
        return 0;
    }
    sqlite_error_msg(parse, TEMP_STORAGE_CHANGE_MESSAGE.as_ptr(), core::ptr::null());
    1
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::testing::{hints, try_map_u32_slab};
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut CALLS: [(u8, usize); 2] = [(0, 0); 2];
    static mut COUNT: usize = 0;

    unsafe extern "C" fn close(btree: *mut u8) -> i32 {
        CALLS[COUNT] = (1, btree as usize);
        COUNT += 1;
        0
    }
    unsafe extern "C" fn reset(db: *mut u8, flags: i32) {
        CALLS[COUNT] = (2, db as usize | flags as usize);
        COUNT += 1;
    }
    unsafe fn install() {
        COUNT = 0;
        core::ptr::write_volatile(core::ptr::addr_of_mut!(SQLITE_TEMP_STORAGE_OPS), TempStorageOps { btree_close: close, reset_internal_schema: reset });
    }
    unsafe fn restore() {
        core::ptr::write_volatile(core::ptr::addr_of_mut!(SQLITE_TEMP_STORAGE_OPS), TempStorageOps { btree_close: retail_btree_close, reset_internal_schema: retail_reset_internal_schema });
    }
    unsafe fn parse(db: *mut u8) -> Parse {
        Parse { db, rc: 0, z_err_msg: core::ptr::null_mut(), _gap_0c: [0; 6], check_schema: 0, _gap_13: [0; 0x2d], n_err: 0 }
    }

    #[test]
    fn closes_temporary_btree_and_resets_schema() {
        let _lock = LOCK.lock();
        let Some(slab) = try_map_u32_slab(hints::SQLITE_TEMP_STORAGE, 0x1000) else { return };
        unsafe {
            core::ptr::write_bytes(slab, 0, 0x1000);
            let databases = slab.add(0x400);
            set_word(slab, A_DB, databases as usize as u32);
            set_word(databases, TEMP_BTREE, slab.add(0x800) as usize as u32);
            let mut parse = parse(slab);
            install();
            assert_eq!(change_temp_storage(&mut parse), 0);
            restore();
            assert_eq!(word(databases, TEMP_BTREE), 0);
            assert_eq!(&CALLS[..COUNT], &[(1, slab.add(0x800) as usize), (2, slab as usize)]);
        }
    }

    #[test]
    fn rejects_change_during_active_statement_without_closing() {
        let _lock = LOCK.lock();
        let Some(slab) = try_map_u32_slab(hints::SQLITE_TEMP_STORAGE_ACTIVE, 0x1000) else { return };
        unsafe {
            core::ptr::write_bytes(slab, 0, 0x1000);
            let databases = slab.add(0x400);
            set_word(slab, A_DB, databases as usize as u32);
            set_word(databases, TEMP_BTREE, slab.add(0x800) as usize as u32);
            *slab.add(ACTIVE_VDBE) = 1;
            let mut parse = parse(slab);
            install();
            assert_eq!(change_temp_storage(&mut parse), 1);
            restore();
            assert_eq!(word(databases, TEMP_BTREE), slab.add(0x800) as usize as u32);
            assert_eq!(COUNT, 0);
            assert_eq!(parse.n_err, 1);
            assert_eq!(parse.rc, 1);
        }
    }

    #[test]
    fn leaves_connection_untouched_without_temporary_btree() {
        let _lock = LOCK.lock();
        let Some(slab) = try_map_u32_slab(hints::SQLITE_TEMP_STORAGE_EMPTY, 0x1000) else { return };
        unsafe {
            core::ptr::write_bytes(slab, 0, 0x1000);
            let databases = slab.add(0x400);
            set_word(slab, A_DB, databases as usize as u32);
            let mut parse = parse(slab);
            install();
            assert_eq!(change_temp_storage(&mut parse), 0);
            restore();
            assert_eq!(COUNT, 0);
            assert_eq!(parse.n_err, 0);
        }
    }
}
