//! Looking up an index by name across the attached databases — SQLite's
//! `sqlite3FindIndex` from the SQLite 3.4.x/3.5.x util.c resolver path.
//!
//! `find_index` — original: `FUN_08378f8c` @ **0x08378f8c** (152 bytes;
//! raw extent 0x08378f8c..0x08379024, where `find_table` begins). Binary
//! scanning every ARM B/BL word in `osos.dec` finds **8 direct `bl` call
//! sites**, all unconditional: 0x082b3d20, 0x0836ef48, 0x08373f3c,
//! 0x083754e4, 0x0837b5c4, 0x0838002c, 0x08381f1c, and 0x0838477c. There
//! are no predicated or tail-B references.
//!
//! The function searches `sqlite3.aDb` in TEMP-before-MAIN order (1, 0, 2,
//! 3, ...). A non-NULL database name filters entries through the ported
//! case-insensitive comparison. Each accepted schema is probed through its
//! `idxHash` at `pSchema + 0x18`, with the NUL included in the name's hash
//! key length; the first non-NULL `Index *` is returned.
//!
//! Deliberate deviations: the retail body directly `bl`s `str_icmp` and
//! `hash_find`; this port obtains those already-ported services through its
//! own volatile hook slots, so host tests can observe the calls without
//! sharing mutable hooks with another module. Target pointers remain u32
//! words, widened only when dereferenced on the host.

use super::hash_clear::Hash;
use super::hash_find::hash_find;
use super::stricmp::str_icmp;
use crate::libc::strlen::strlen;

const N_DB_OFFSET: usize = 0x04;
const A_DB_OFFSET: usize = 0x08;
const DB_SIZE: usize = 0x18;
const DB_Z_NAME_OFFSET: usize = 0x00;
const DB_P_SCHEMA_OFFSET: usize = 0x14;
/// `Schema.idxHash`; `schema_cookie` is at +0x00 and `tblHash` at +0x04.
const SCHEMA_IDX_HASH_OFFSET: u32 = 0x18;

/// Services called by [`find_index`]. The module owns these slots so its
/// tests cannot race another port's hook replacement.
#[derive(Clone, Copy)]
pub struct FindIndexHooks {
    /// `sqlite3StrICmp` @ 0x08384f14, called `(database, aDb[j].zName)`.
    pub icmp: unsafe extern "C" fn(left: *const u8, right: *const u8) -> i32,
    /// `sqlite3HashFind` @ 0x0837ad88, called with `&pSchema->idxHash` and
    /// `strlen(name) + 1`.
    pub find: unsafe extern "C" fn(
        hash: *const Hash,
        key: *const u8,
        key_len: i32,
    ) -> *mut u8,
}

/// The firmware-equivalent services used outside host tests.
pub const DEFAULT_FIND_INDEX_HOOKS: FindIndexHooks = FindIndexHooks {
    icmp: str_icmp,
    find: hash_find,
};

/// Active callback pair for [`find_index`]. Reads are volatile to preserve
/// the indirection in release device code.
pub static mut FIND_INDEX_HOOKS: FindIndexHooks = DEFAULT_FIND_INDEX_HOOKS;

#[inline(always)]
unsafe fn icmp_op() -> unsafe extern "C" fn(*const u8, *const u8) -> i32 {
    core::ptr::read_volatile(core::ptr::addr_of!(FIND_INDEX_HOOKS.icmp))
}

#[inline(always)]
unsafe fn find_op() -> unsafe extern "C" fn(*const Hash, *const u8, i32) -> *mut u8 {
    core::ptr::read_volatile(core::ptr::addr_of!(FIND_INDEX_HOOKS.find))
}

/// `sqlite3FindIndex` — original: `FUN_08378f8c` @ 0x08378f8c (152 bytes;
/// 8 unconditional `bl` call sites).
///
/// Return the `Index *` named `name`, scanning the attached databases in
/// TEMP-first order. If `database` is non-NULL, only its case-insensitive
/// name match is searched. Returns NULL for no hit or `db->nDb <= 0`.
///
/// # Safety
/// `db` must reference a readable sqlite3 handle whose `aDb` points to at
/// least `nDb` 24-byte `Db` entries. `name`, and non-NULL `database`, must
/// be readable NUL-terminated C strings. Default hooks call firmware code on
/// target; host tests replace the hash hook before using synthetic layouts.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn find_index(
    db: *const u8,
    name: *const u8,
    database: *const u8,
) -> *mut u8 {
    let mut result = core::ptr::null_mut();
    let mut i = 0u32;
    loop {
        // `ldr r0,[r7,#4]` / `cmp r0,r4` / signed `bgt`: reload nDb on
        // every loop condition and do not enter for zero or negatives.
        let n_db = db.add(N_DB_OFFSET).cast::<i32>().read();
        if n_db <= i as i32 {
            break;
        }
        // `cmp r4,#2; movge; eorlt #1`: TEMP precedes MAIN only.
        let j = if (i as i32) < 2 { i ^ 1 } else { i };
        let entry = db.add(A_DB_OFFSET).cast::<u32>().read() as usize
            + j as usize * DB_SIZE;
        let filtered = !database.is_null()
            && icmp_op()(database, ((entry + DB_Z_NAME_OFFSET) as *const u32).read() as *const u8) != 0;
        if !filtered {
            // `strlen(name) + 1` includes the terminator in the hash key.
            let key_len = (strlen(name) as u32).wrapping_add(1) as i32;
            let schema = (entry + DB_P_SCHEMA_OFFSET) as *const u32;
            let hash = schema.read().wrapping_add(SCHEMA_IDX_HASH_OFFSET) as *const Hash;
            let found = find_op()(hash, name, key_len);
            if !found.is_null() {
                result = found;
                break;
            }
        }
        i = i.wrapping_add(1);
    }
    result
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use parking_lot::Mutex;
    use std::sync::LazyLock;
    use std::vec::Vec;

    static HOOK_LOCK: Mutex<()> = Mutex::new(());
    static SLAB_LOCK: Mutex<()> = Mutex::new(());
    const ENTRY_COUNT: usize = 4;
    static mut ICMP_CALLS: Vec<(*const u8, *const u8)> = Vec::new();
    static mut FIND_CALLS: Vec<(*const Hash, *const u8, i32)> = Vec::new();
    static mut FIND_RESULT: *mut u8 = core::ptr::null_mut();
    static mut FIND_HIT_HASH: *const Hash = core::ptr::null();

    unsafe extern "C" fn mock_icmp(left: *const u8, right: *const u8) -> i32 {
        (*core::ptr::addr_of_mut!(ICMP_CALLS)).push((left, right));
        let mut a = left;
        let mut b = right;
        loop {
            let x = a.read();
            let y = b.read();
            if x != y || x == 0 {
                return x as i32 - y as i32;
            }
            a = a.add(1);
            b = b.add(1);
        }
    }

    unsafe extern "C" fn mock_find(hash: *const Hash, key: *const u8, key_len: i32) -> *mut u8 {
        (*core::ptr::addr_of_mut!(FIND_CALLS)).push((hash, key, key_len));
        let wanted = *core::ptr::addr_of!(FIND_HIT_HASH);
        if wanted.is_null() || wanted == hash {
            *core::ptr::addr_of!(FIND_RESULT)
        } else {
            core::ptr::null_mut()
        }
    }

    fn icmp_calls() -> Vec<(*const u8, *const u8)> {
        unsafe { (*core::ptr::addr_of!(ICMP_CALLS)).clone() }
    }

    fn find_calls() -> Vec<(*const Hash, *const u8, i32)> {
        unsafe { (*core::ptr::addr_of!(FIND_CALLS)).clone() }
    }

    struct HookGuard;
    impl Drop for HookGuard {
        fn drop(&mut self) {
            unsafe { FIND_INDEX_HOOKS = DEFAULT_FIND_INDEX_HOOKS };
        }
    }

    fn with_mock_hooks() -> HookGuard {
        unsafe {
            FIND_INDEX_HOOKS = FindIndexHooks { icmp: mock_icmp, find: mock_find };
            (*core::ptr::addr_of_mut!(ICMP_CALLS)).clear();
            (*core::ptr::addr_of_mut!(FIND_CALLS)).clear();
            FIND_RESULT = core::ptr::null_mut();
            FIND_HIT_HASH = core::ptr::null();
        }
        HookGuard
    }

    fn try_slab() -> Option<*mut u8> {
        static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
            crate::testing::try_map_u32_slab(crate::testing::hints::SQLITE_FIND_INDEX, 0x1000)
                .map(|p| p as usize)
        });
        SLAB.map(|p| p as *mut u8)
    }

    fn slab() -> *mut u8 {
        try_slab().expect("fixture slab checked by the caller's skip guard")
    }

    const NAMES: [&[u8]; ENTRY_COUNT] = [b"main\0", b"temp\0", b"aux1\0", b"aux2\0"];

    unsafe fn build_fixture(n_db: i32) {
        let base = slab();
        base.add(N_DB_OFFSET).cast::<i32>().write(n_db);
        base.add(A_DB_OFFSET).cast::<u32>().write(base.add(0x40) as u32);
        for (e, name) in NAMES.iter().enumerate() {
            let z_name = base.add(0x100 + e * 0x10);
            core::ptr::copy_nonoverlapping(name.as_ptr(), z_name, name.len());
            let entry = base.add(0x40 + e * DB_SIZE);
            entry.cast::<u32>().write(z_name as u32);
            entry.add(DB_P_SCHEMA_OFFSET).cast::<u32>()
                .write(base.add(0x200 + e * 0x40) as u32);
        }
    }

    unsafe fn idx_hash(j: usize) -> *const Hash {
        let schema_word = slab().add(0x40 + j * DB_SIZE + DB_P_SCHEMA_OFFSET).cast::<u32>();
        schema_word.read().wrapping_add(SCHEMA_IDX_HASH_OFFSET) as *const Hash
    }

    unsafe fn z_name(j: usize) -> *const u8 {
        slab().add(0x100 + j * 0x10)
    }

    #[test]
    fn temp_index_is_found_before_main_and_uses_idx_hash() {
        let _slab_guard = SLAB_LOCK.lock();
        if try_slab().is_none() { return; }
        let _hook_guard = HOOK_LOCK.lock();
        let _hooks = with_mock_hooks();
        unsafe {
            build_fixture(2);
            let payload = 0x1122_3344usize as *mut u8;
            FIND_RESULT = payload;
            FIND_HIT_HASH = idx_hash(1);
            let found = find_index(slab(), b"ix_widgets\0".as_ptr(), core::ptr::null());
            assert_eq!(found, payload);
            let calls = find_calls();
            assert_eq!(calls.len(), 1, "the first hit terminates the loop");
            assert_eq!(calls[0].0, idx_hash(1), "TEMP's Schema.idxHash, not tblHash");
            assert_eq!(calls[0].1, b"ix_widgets\0".as_ptr());
            assert_eq!(calls[0].2, 11, "key length includes the NUL");
            assert!(icmp_calls().is_empty(), "NULL database skips filtering");
        }
    }

    #[test]
    fn miss_scans_temp_main_then_attached_databases() {
        let _slab_guard = SLAB_LOCK.lock();
        if try_slab().is_none() { return; }
        let _hook_guard = HOOK_LOCK.lock();
        let _hooks = with_mock_hooks();
        unsafe {
            build_fixture(4);
            assert!(find_index(slab(), b"x\0".as_ptr(), core::ptr::null()).is_null());
            let calls = find_calls();
            assert_eq!(calls.len(), 4);
            for (position, expected) in [1usize, 0, 2, 3].iter().enumerate() {
                assert_eq!(calls[position].0, idx_hash(*expected));
                assert_eq!(calls[position].2, 2);
            }
        }
    }

    #[test]
    fn database_filter_has_left_argument_and_skips_nonmatches() {
        let _slab_guard = SLAB_LOCK.lock();
        if try_slab().is_none() { return; }
        let _hook_guard = HOOK_LOCK.lock();
        let _hooks = with_mock_hooks();
        unsafe {
            build_fixture(4);
            let payload = 0x5566_7788usize as *mut u8;
            FIND_RESULT = payload;
            assert_eq!(find_index(slab(), b"x\0".as_ptr(), b"main\0".as_ptr()), payload);
            assert_eq!(icmp_calls(), std::vec![(b"main\0".as_ptr(), z_name(1)), (b"main\0".as_ptr(), z_name(0))]);
            let calls = find_calls();
            assert_eq!(calls.len(), 1);
            assert_eq!(calls[0].0, idx_hash(0));
        }
    }

    #[test]
    fn filter_uses_real_case_fold_and_can_reject_every_database() {
        let _slab_guard = SLAB_LOCK.lock();
        if try_slab().is_none() { return; }
        let _hook_guard = HOOK_LOCK.lock();
        let _hooks = with_mock_hooks();
        unsafe {
            FIND_INDEX_HOOKS.icmp = str_icmp;
            build_fixture(2);
            FIND_RESULT = 0x0bad_f00dusize as *mut u8;
            assert_eq!(find_index(slab(), b"x\0".as_ptr(), b"MAIN\0".as_ptr()), FIND_RESULT);
            assert_eq!(find_calls()[0].0, idx_hash(0));
            (*core::ptr::addr_of_mut!(FIND_CALLS)).clear();
            assert!(find_index(slab(), b"x\0".as_ptr(), b"none\0".as_ptr()).is_null());
            assert!(find_calls().is_empty(), "rejected names never reach hash_find");
        }
    }

    #[test]
    fn nonpositive_database_count_does_not_read_entries() {
        let _slab_guard = SLAB_LOCK.lock();
        if try_slab().is_none() { return; }
        let _hook_guard = HOOK_LOCK.lock();
        let _hooks = with_mock_hooks();
        unsafe {
            for n_db in [0, -1] {
                build_fixture(n_db);
                assert!(find_index(slab(), b"x\0".as_ptr(), core::ptr::null()).is_null());
                assert!(icmp_calls().is_empty());
                assert!(find_calls().is_empty());
            }
        }
    }

    #[test]
    fn defaults_are_the_ported_services() {
        assert_eq!(DEFAULT_FIND_INDEX_HOOKS.icmp as usize, str_icmp as usize);
        assert_eq!(DEFAULT_FIND_INDEX_HOOKS.find as usize, hash_find as usize);
    }
}
