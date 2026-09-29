//! Register a virtual-table module by name.
//!
//! `sqlite3_create_module_v2` — original `FUN_082c53a4` at load address
//! `0x082c53a4`, 160 bytes (`0x082c53a4..0x082c5440`). Raw A32 decoding
//! establishes six unconditional `bl` instructions and one predicated `blxne`;
//! `push` at `0x082c5444` begins the next independently linked function.
//!
//! The routine allocates a 16-byte `{module, name, auxiliary, destroy}` record,
//! copies the NUL-terminated module name, replaces that name's entry in the
//! connection's module hash, destroys and frees a replaced record, then calls
//! the resident connection-reset operation at `0x0838209c`. Its `b` tail calls
//! `sqlite3ApiExit` with result zero. Deliberate deviation: the unported hash
//! insertion and connection-reset callees are volatile host seams and direct
//! resident calls on firmware; the original's predicated destructor call is an
//! ordinary conditional Rust call.

use super::api_exit::sqlite_api_exit;
use super::mem::db_malloc_raw;
use crate::heap::tracked::tracked_free;
use crate::libc::rt_memcpy_returning_destination::rt_memcpy_returning_destination;

pub type HashInsertFn = unsafe extern "C" fn(*mut u8, *mut u8, i32, *mut u8) -> *mut u8;
pub type ResetConnectionFn = unsafe extern "C" fn(*mut u8, i32);

type DestroyFn = unsafe extern "C" fn(*mut u8);

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_hash_insert(hash: *mut u8, key: *mut u8, key_len: i32, data: *mut u8) -> *mut u8 {
    let function: HashInsertFn = core::mem::transmute(0x0837_ae08usize);
    function(hash, key, key_len, data)
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_hash_insert(_: *mut u8, _: *mut u8, _: i32, _: *mut u8) -> *mut u8 {
    panic!("sqlite3_create_module_v2 requires sqlite3HashInsert @ 0x0837ae08")
}

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_reset_connection(db: *mut u8, mode: i32) {
    let function: ResetConnectionFn = core::mem::transmute(0x0838_209cusize);
    function(db, mode)
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_reset_connection(_: *mut u8, _: i32) {
    panic!("sqlite3_create_module_v2 requires resident operation @ 0x0838209c")
}

#[cfg(target_os = "none")]
const DEFAULT_HASH_INSERT: HashInsertFn = retail_hash_insert;
#[cfg(not(target_os = "none"))]
const DEFAULT_HASH_INSERT: HashInsertFn = missing_hash_insert;
#[cfg(target_os = "none")]
const DEFAULT_RESET_CONNECTION: ResetConnectionFn = retail_reset_connection;
#[cfg(not(target_os = "none"))]
const DEFAULT_RESET_CONNECTION: ResetConnectionFn = missing_reset_connection;

pub static mut SQLITE_HASH_INSERT_OP: HashInsertFn = DEFAULT_HASH_INSERT;
pub static mut SQLITE_CONNECTION_RESET_OP: ResetConnectionFn = DEFAULT_RESET_CONNECTION;

#[inline(always)]
unsafe fn hash_insert_op() -> HashInsertFn {
    core::ptr::read_volatile(core::ptr::addr_of!(SQLITE_HASH_INSERT_OP))
}
#[inline(always)]
unsafe fn reset_connection_op() -> ResetConnectionFn {
    core::ptr::read_volatile(core::ptr::addr_of!(SQLITE_CONNECTION_RESET_OP))
}

#[inline(always)]
unsafe fn c_string_len(text: *const u8) -> usize {
    let mut len = 0;
    while core::ptr::read_volatile(text.add(len)) != 0 {
        len += 1;
    }
    len
}

/// Register `module` under `name` with `auxiliary` and its replacement
/// destructor. The caller transfers ownership of `destroy` only after a
/// successful allocation, as in retailOS.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn sqlite3_create_module_v2(
    db: *mut u8,
    name: *mut u8,
    module: *mut u8,
    auxiliary: *mut u8,
    destroy: *mut u8,
) -> i32 {
    let name_len = c_string_len(name);
    let record = db_malloc_raw(db, (name_len + 17) as i32);
    if !record.is_null() {
        let copied_name = record.add(16);
        rt_memcpy_returning_destination(copied_name, name, name_len + 1);
        record.cast::<u32>().write(module as u32);
        record.add(4).cast::<u32>().write(copied_name as u32);
        record.add(8).cast::<u32>().write(auxiliary as u32);
        record.add(12).cast::<u32>().write(destroy as u32);
        let previous = hash_insert_op()(db.add(0xf4), copied_name, name_len as i32, record);
        if !previous.is_null() {
            let previous_destroy = previous.add(12).cast::<u32>().read();
            if previous_destroy != 0 {
                let destroy_previous: DestroyFn = core::mem::transmute(previous_destroy as usize);
                destroy_previous(previous.add(8).cast::<u32>().read() as usize as *mut u8);
            }
            tracked_free(previous);
        }
        reset_connection_op()(db, 0);
    }
    sqlite_api_exit(db, 0)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::sqlite::mem::{DbMemOps, DB_MEM_OPS};
    use parking_lot::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static ALLOCATION: AtomicUsize = AtomicUsize::new(0);
    static HASH_RECORD: AtomicUsize = AtomicUsize::new(0);
    static HASH_KEY: AtomicUsize = AtomicUsize::new(0);
    static HASH_LEN: AtomicUsize = AtomicUsize::new(0);
    static PREVIOUS: AtomicUsize = AtomicUsize::new(0);
    static RESET_DB: AtomicUsize = AtomicUsize::new(0);
    static DESTROY_ARG: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn allocate(_: i32) -> *mut u8 { ALLOCATION.load(Ordering::SeqCst) as *mut u8 }
    unsafe extern "C" fn hash(_: *mut u8, key: *mut u8, len: i32, record: *mut u8) -> *mut u8 {
        HASH_KEY.store(key as usize, Ordering::SeqCst);
        HASH_LEN.store(len as usize, Ordering::SeqCst);
        HASH_RECORD.store(record as usize, Ordering::SeqCst);
        PREVIOUS.load(Ordering::SeqCst) as *mut u8
    }
    unsafe extern "C" fn reset(db: *mut u8, mode: i32) {
        assert_eq!(mode, 0);
        RESET_DB.store(db as usize, Ordering::SeqCst);
    }
    unsafe extern "C" fn destroy(arg: *mut u8) { DESTROY_ARG.store(arg as usize, Ordering::SeqCst); }

    #[test]
    fn registers_a_copied_name_and_resets_the_connection() { unsafe {
        let _guard = OPS_LOCK.lock();
        let mut db = [0u8; 0x100];
        let mut allocation = [0u8; 64];
        ALLOCATION.store(allocation.as_mut_ptr() as usize, Ordering::SeqCst);
        PREVIOUS.store(0, Ordering::SeqCst);
        HASH_RECORD.store(0, Ordering::SeqCst);
        RESET_DB.store(0, Ordering::SeqCst);
        core::ptr::write_volatile(core::ptr::addr_of_mut!(DB_MEM_OPS), DbMemOps { malloc: allocate, realloc: core::ptr::read(core::ptr::addr_of!(DB_MEM_OPS)).realloc });
        core::ptr::write_volatile(core::ptr::addr_of_mut!(SQLITE_HASH_INSERT_OP), hash);
        core::ptr::write_volatile(core::ptr::addr_of_mut!(SQLITE_CONNECTION_RESET_OP), reset);
        assert_eq!(sqlite3_create_module_v2(db.as_mut_ptr(), b"media\0".as_ptr() as *mut u8, 0x10usize as *mut u8, 0x20usize as *mut u8, 0x30usize as *mut u8), 0);
        assert_eq!(HASH_RECORD.load(Ordering::SeqCst), allocation.as_mut_ptr() as usize);
        assert_eq!(HASH_KEY.load(Ordering::SeqCst), allocation.as_mut_ptr().add(16) as usize);
        assert_eq!(HASH_LEN.load(Ordering::SeqCst), 5);
        assert_eq!(&allocation[16..22], b"media\0");
        assert_eq!(RESET_DB.load(Ordering::SeqCst), db.as_mut_ptr() as usize);
    } }

    #[test]
    fn allocation_failure_skips_hash_replacement_and_reset() { unsafe {
        let _guard = OPS_LOCK.lock();
        let mut db = [0u8; 0x100];
        ALLOCATION.store(0, Ordering::SeqCst);
        HASH_RECORD.store(0, Ordering::SeqCst);
        RESET_DB.store(0, Ordering::SeqCst);
        core::ptr::write_volatile(core::ptr::addr_of_mut!(DB_MEM_OPS), DbMemOps { malloc: allocate, realloc: core::ptr::read(core::ptr::addr_of!(DB_MEM_OPS)).realloc });
        core::ptr::write_volatile(core::ptr::addr_of_mut!(SQLITE_HASH_INSERT_OP), hash);
        core::ptr::write_volatile(core::ptr::addr_of_mut!(SQLITE_CONNECTION_RESET_OP), reset);
        assert_eq!(sqlite3_create_module_v2(db.as_mut_ptr(), b"x\0".as_ptr() as *mut u8, core::ptr::null_mut(), core::ptr::null_mut(), core::ptr::null_mut()), 0);
        assert_eq!(HASH_RECORD.load(Ordering::SeqCst), 0);
        assert_eq!(RESET_DB.load(Ordering::SeqCst), 0);
    } }
}
