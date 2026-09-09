//! Looking up a table by name across the attached databases —
//! `sqlite3FindTable` from SQLite 3.4.x/3.5.x's util.c, the resolver
//! every `SELECT`/`INSERT`/DDL parse runs to turn a (possibly
//! schema-qualified) table name into a `Table` object.
//!
//! - `find_table` — original: `FUN_08379024` @ 0x08379024 (148 bytes;
//!   the next function starts at 0x083790b8, confirming the extent.
//!   **17 `bl` call sites, binary-scanned — every one unconditional**,
//!   no predicated forms). SQLite 3.4.x/3.5.x's `sqlite3FindTable`:
//!
//! ```c
//! Table *sqlite3FindTable(sqlite3 *db, const char *zName, const char *zDatabase){
//!   int i;
//!   Table *p = 0;
//!   for(i=0; i<db->nDb && p==0; i++){
//!     int j = (i<2) ? i^1 : i;   /* Search TEMP before MAIN */
//!     if( zDatabase && sqlite3StrICmp(zDatabase, db->aDb[j].zName) ) continue;
//!     p = sqlite3HashFind(&db->aDb[j].pSchema->tblHash, zName, strlen(zName)+1);
//!   }
//!   return p;
//! }
//! ```
//!
//! The whole body, NDEBUG (no upstream asserts):
//!
//! ```text
//! 08379024:  push {r4,r5,r6,r7,r8,r9,sl,lr}
//! 08379028:  mov  r9,r1            ; zName
//! 0837902c:  mov  r8,r2            ; zDatabase
//! 08379030:  mov  r7,#0            ; result = NULL
//! 08379034:  mov  r5,r0            ; db
//! 08379038:  mov  r4,#0            ; i = 0
//! 0837903c:  b    0x083790a4
//! 08379040:  cmp  r4,#2
//! 08379044:  movge r6,r4           ; j = i        (i >= 2)
//! 08379048:  eorlt r6,r4,#1        ; j = i ^ 1    (i < 2): TEMP before MAIN
//! 0837904c:  cmp  r8,#0
//! 08379050:  beq  0x08379070       ; zDatabase == NULL -> no schema filter
//! 08379054:  ldr  r0,[r5,#8]       ; db->aDb
//! 08379058:  add  r1,r6,r6,lsl #1
//! 0837905c:  ldr  r1,[r0,r1,lsl #3]; aDb[j].zName (stride 0x18)
//! 08379060:  mov  r0,r8
//! 08379064:  bl   0x08384f14       ; str_icmp(zDatabase, aDb[j].zName) (ported)
//! 08379068:  cmp  r0,#0
//! 0837906c:  bne  0x083790a0       ; name mismatch -> next db
//! 08379070:  mov  r0,r9
//! 08379074:  bl   0x08392478       ; strlen(zName) (ported)
//! 08379078:  add  r2,r0,#1         ; key_len = strlen(zName) + 1
//! 0837907c:  ldr  r0,[r5,#8]       ; db->aDb (reloaded)
//! 08379080:  add  r1,r6,r6,lsl #1
//! 08379084:  add  r0,r0,r1,lsl #3
//! 08379088:  ldr  r0,[r0,#0x14]    ; aDb[j].pSchema
//! 0837908c:  mov  r1,r9
//! 08379090:  add  r0,r0,#4         ; &pSchema->tblHash
//! 08379094:  bl   0x0837ad88       ; hash_find(tblHash, zName, len+1) (ported)
//! 08379098:  movs r7,r0
//! 0837909c:  bne  0x083790b0       ; hit -> return
//! 083790a0:  add  r4,r4,#1
//! 083790a4:  ldr  r0,[r5,#4]       ; db->nDb (reloaded per iteration)
//! 083790a8:  cmp  r0,r4
//! 083790ac:  bgt  0x08379040       ; while (nDb > i), signed
//! 083790b0:  mov  r0,r7
//! 083790b4:  pop  {r4,r5,r6,r7,r8,r9,sl,pc}
//! ```
//!
//! Behavioural facts the listing pins:
//!
//! - **TEMP is searched before MAIN**: the `cmp r4,#2` / `movge` /
//!   `eorlt ...,#1` triple maps loop counter 0,1,2,3,... onto database
//!   index 1,0,2,3,... — upstream's `(i<2) ? i^1 : i` comment "Search
//!   TEMP before MAIN". Indices >= 2 (attached databases) are not
//!   reordered.
//! - The `zDatabase` filter is a case-insensitive compare against
//!   `aDb[j].zName` with `zDatabase` as the LEFT argument (the sign of
//!   a mismatch is `fold(*zDatabase) - fold(*zName)`, see
//!   [`super::stricmp`]); a NULL `zDatabase` skips the compare
//!   entirely and every database is tried.
//! - `strlen(zName)` runs only after the filter passes, and the key
//!   length handed to the hash is `strlen + 1` — the NUL is part of
//!   the key, so "abc" and "abcd" never collide in the table hash.
//! - The hash probed is `aDb[j].pSchema + 4`: `Schema.schema_cookie`
//!   sits at +0x00 and `tblHash` at +0x04, the layout
//!   [`super::hash_init`]/[`super::hash_clear`] pin.
//! - `db->nDb` is reloaded every iteration and the loop compare is a
//!   signed `bgt`: a zero or negative `nDb` returns NULL without
//!   touching `aDb`.
//! - The `Db` layout is the one [`super::schema_to_index`] pins:
//!   24-byte entries, `zName` @ +0x00, `pSchema` @ +0x14.
//!
//! Callers (17 `bl` sites, all binary-scanned, all unconditional):
//! 0x082dc140, 0x0836ec3c, 0x0836ef30, 0x0836f0f4, 0x0836f2bc,
//! 0x08373f10, 0x0837560c, 0x08375970, 0x0837b678, 0x0837d280,
//! 0x0837fd10, 0x0838017c, 0x08380534, 0x08381ee8, 0x0838474c,
//! 0x0838a914, 0x0838a9a8 — the parser/resolver half of the SQLite
//! unit (the same neighbourhood [`super::hash_find`] documents for
//! its 0x08379094 site, which is this function's own lookup).
//!
//! Deviations:
//!
//! - The original's `bl 0x08384f14` (str_icmp) and `bl 0x0837ad88`
//!   (hash_find) are direct calls; the port reaches both through the
//!   volatile hook slots of [`FIND_TABLE_HOOKS`] (the house seam
//!   convention — `sqlite/cell_size.rs`), so the shipped image's
//!   indirect `blx` replaces two direct `bl`s. The defaults are the
//!   real ported [`str_icmp`] and [`hash_find`], making the
//!   indirection behaviorally transparent. Host tests substitute the
//!   slots: this module gets its own seam rather than reusing
//!   [`super::hash_find::HASH_FIND_HOOKS`] because test threads run
//!   concurrently in one process and two modules swapping one static
//!   would race.
//! - `strlen` is called directly (ported and host-callable — the
//!   `sqlite/strdup.rs` precedent), not through a slot.
//! - Struct words are read as `u32` because the target's pointers are
//!   32-bit (the `schema_to_index` convention); on-target the widened
//!   value IS the pointer.

use super::hash_clear::Hash;
use super::hash_find::hash_find;
use super::stricmp::str_icmp;
use crate::libc::strlen::strlen;

/// Byte offset of `sqlite3.nDb` (original: `ldr r0, [r5, #4]`).
const N_DB_OFFSET: usize = 0x04;
/// Byte offset of `sqlite3.aDb` (original: `ldr r0, [r5, #8]`).
const A_DB_OFFSET: usize = 0x08;
/// `sizeof(Db)` in this build (original: `j*3 << 3` index arithmetic).
const DB_SIZE: usize = 0x18;
/// Byte offset of `Db.zName` (original: `ldr r1, [aDb + j*0x18]`).
const DB_Z_NAME_OFFSET: usize = 0x00;
/// Byte offset of `Db.pSchema` (original: `ldr r0, [entry, #0x14]`).
const DB_P_SCHEMA_OFFSET: usize = 0x14;
/// Byte offset of `Schema.tblHash` — `schema_cookie` at +0x00
/// (original: `add r0, r0, #4`).
const SCHEMA_TBL_HASH_OFFSET: u32 = 0x04;

/// The services `find_table` reaches, replaceable by host tests. All
/// defaults are the real ports; see the module header for why this
/// module does not reuse `hash_find`'s own seam.
#[derive(Clone, Copy)]
pub struct FindTableHooks {
    /// `sqlite3StrICmp` @ 0x08384f14 (ported —
    /// [`super::stricmp::str_icmp`] is the shipped default): the
    /// case-insensitive schema-name filter, called
    /// `(zDatabase, aDb[j].zName)` exactly like the original's
    /// `mov r0,r8` / `ldr r1,...` / `bl 0x08384f14`.
    pub icmp: unsafe extern "C" fn(left: *const u8, right: *const u8) -> i32,
    /// `sqlite3HashFind` @ 0x0837ad88 (ported —
    /// [`super::hash_find::hash_find`] is the shipped default): probe
    /// `&aDb[j].pSchema->tblHash` for `(zName, strlen(zName)+1)` and
    /// return the `Table *` payload or NULL. Note the default's own
    /// dispatcher resolves firmware runtime addresses (see its doc
    /// header), callable on-target only — host tests substitute this
    /// slot.
    pub find: unsafe extern "C" fn(
        hash: *const Hash,
        key: *const u8,
        key_len: i32,
    ) -> *mut u8,
}

/// Wired default for [`FIND_TABLE_HOOKS`]: the real ported
/// `str_icmp` and `hash_find`.
pub const DEFAULT_FIND_TABLE_HOOKS: FindTableHooks = FindTableHooks {
    icmp: str_icmp,
    find: hash_find,
};

/// Active model of the filter and lookup calls in [`find_table`].
/// Host tests replace the slots to observe the exact arguments.
pub static mut FIND_TABLE_HOOKS: FindTableHooks = DEFAULT_FIND_TABLE_HOOKS;

/// Reads the `str_icmp` slot. Volatile so LLVM cannot constant-fold
/// the load to the default (the house pattern — `sqlite/blob_to_hex.rs`).
#[inline(always)]
unsafe fn icmp_op() -> unsafe extern "C" fn(*const u8, *const u8) -> i32 {
    core::ptr::read_volatile(core::ptr::addr_of!(FIND_TABLE_HOOKS.icmp))
}

/// Reads the `hash_find` slot. Volatile, same rationale as
/// [`icmp_op`] above.
#[inline(always)]
unsafe fn find_op() -> unsafe extern "C" fn(*const Hash, *const u8, i32) -> *mut u8 {
    core::ptr::read_volatile(core::ptr::addr_of!(FIND_TABLE_HOOKS.find))
}

/// find_table — original: `FUN_08379024` @ 0x08379024 (148 bytes; 17
/// `bl` call sites, all unconditional).
///
/// `sqlite3FindTable`: return the `Table *` named `name`, searching
/// the attached databases TEMP-first (index order 1, 0, 2, 3, ...),
/// restricted to the database whose `zName` case-insensitively equals
/// `database` when `database` is non-NULL. Returns NULL when no
/// database yields a hit (or `db->nDb <= 0`).
///
/// # Safety
/// `db` must point at a readable `sqlite3` handle whose `aDb` array
/// holds at least `nDb` 24-byte `Db` entries with live `zName` and
/// `pSchema` words; `name` must be a readable NUL-terminated string;
/// `database`, when non-NULL, likewise. With the default hook table
/// the lookup's key hash is firmware code, callable on-target only.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn find_table(
    db: *const u8,
    name: *const u8,
    database: *const u8,
) -> *mut u8 {
    let mut result: *mut u8 = core::ptr::null_mut();
    let mut i: u32 = 0;
    // The original is a while loop (`b 0x083790a4` enters at the
    // condition): nDb is reloaded per iteration and the compare is a
    // signed `bgt`, so nDb <= 0 never enters the body.
    loop {
        let n_db = db.add(N_DB_OFFSET).cast::<i32>().read();
        if n_db <= i as i32 {
            break;
        }
        // `cmp r4,#2` + `movge r6,r4` + `eorlt r6,r4,#1`: TEMP (index
        // 1) is searched before MAIN (index 0); attached databases
        // keep their order.
        let j = if (i as i32) < 2 { i ^ 1 } else { i };
        let entry = || {
            db.add(A_DB_OFFSET)
                .cast::<u32>()
                .read() as usize
                + j as usize * DB_SIZE
        };
        // `cmp r8,#0` + `beq`: a NULL zDatabase matches every schema.
        let filtered = !database.is_null() && {
            let z_name = (entry() + DB_Z_NAME_OFFSET) as *const u32;
            // `bl 0x08384f14` with (zDatabase, aDb[j].zName); any
            // nonzero difference skips this database.
            icmp_op()(database, z_name.read() as *const u8) != 0
        };
        if !filtered {
            // `bl 0x08392478` + `add r2,r0,#1`: the NUL is part of
            // the hash key.
            let key_len = (strlen(name) as u32).wrapping_add(1) as i32;
            let schema = (entry() + DB_P_SCHEMA_OFFSET) as *const u32;
            // `ldr r0,[entry,#0x14]` + `add r0,r0,#4` +
            // `bl 0x0837ad88`: probe &pSchema->tblHash.
            let hash = schema.read().wrapping_add(SCHEMA_TBL_HASH_OFFSET) as *const Hash;
            let found = find_op()(hash, name, key_len);
            // `movs r7,r0` + `bne`: the first hit ends the search.
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

    /// Serializes the tests that swap [`FIND_TABLE_HOOKS`] (the
    /// static is private to this module, so a module-local lock
    /// suffices — the `hash_find` precedent).
    static HOOK_LOCK: Mutex<()> = Mutex::new(());
    /// Serializes the fixture slab users; [`HOOK_LOCK`] is always
    /// taken first, never the reverse.
    static SLAB_LOCK: Mutex<()> = Mutex::new(());

    /// Number of `Db` entries in the fixture array.
    const ENTRY_COUNT: usize = 4;

    /// Every (left, right) pair the mock str_icmp was called with.
    static mut ICMP_CALLS: Vec<(*const u8, *const u8)> = Vec::new();
    /// Every (hash, key, key_len) the mock hash_find was called with.
    static mut FIND_CALLS: Vec<(*const Hash, *const u8, i32)> = Vec::new();
    /// Result the mock hash_find returns; may be set per schema.
    static mut FIND_RESULT: *mut u8 = core::ptr::null_mut();
    /// When non-NULL, the mock hash_find returns [`FIND_RESULT`] only
    /// for this hash pointer and NULL otherwise.
    static mut FIND_HIT_HASH: *const Hash = core::ptr::null();

    unsafe extern "C" fn mock_icmp(left: *const u8, right: *const u8) -> i32 {
        (*core::ptr::addr_of_mut!(ICMP_CALLS)).push((left, right));
        // Case-sensitive match on the fixture bytes: the fixtures give
        // every database a distinct zName, so a byte compare models
        // "is this the named schema" well enough (a separate test
        // drives the real ported str_icmp for the folding itself).
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

    /// Installs the mock hooks and clears the call logs; the returned
    /// guard restores the defaults on drop. Caller must hold
    /// [`HOOK_LOCK`].
    struct HookGuard;
    impl Drop for HookGuard {
        fn drop(&mut self) {
            unsafe { FIND_TABLE_HOOKS = DEFAULT_FIND_TABLE_HOOKS };
        }
    }

    fn with_mock_hooks() -> HookGuard {
        unsafe {
            FIND_TABLE_HOOKS = FindTableHooks {
                icmp: mock_icmp,
                find: mock_find,
            };
            (*core::ptr::addr_of_mut!(ICMP_CALLS)).clear();
            (*core::ptr::addr_of_mut!(FIND_CALLS)).clear();
            FIND_RESULT = core::ptr::null_mut();
            FIND_HIT_HASH = core::ptr::null();
        }
        HookGuard
    }

    /// Maps the fixture slab once per process. The port widens `u32`
    /// words into host pointers, so the handle, the `Db` array, the
    /// zName strings and the fake `Schema` addresses must all live
    /// below 4 GiB; `None` means this host cannot supply such a
    /// mapping and the tests skip rather than crash.
    fn try_slab() -> Option<*mut u8> {
        static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
            crate::testing::try_map_u32_slab(crate::testing::hints::SQLITE_FIND_TABLE, 0x1000)
                .map(|p| p as usize)
        });
        SLAB.map(|p| p as *mut u8)
    }

    /// The fixture base. Only reached once [`try_slab`] has confirmed
    /// the mapping exists.
    fn slab() -> *mut u8 {
        try_slab().expect("fixture slab checked by the caller's skip guard")
    }

    // Fixture layout inside the 0x1000-byte slab:
    //   +0x000        fake sqlite3 handle (nDb @ +4, aDb @ +8)
    //   +0x040..0x0a0 four 24-byte Db entries
    //   +0x100..      zName strings ("temp", "main", "aux1", "aux2")
    //   +0x200..      fake Schema bases (one per entry, 0x40 apart) —
    //                 their tblHash address (base+4) is only compared,
    //                 never dereferenced, while find is mocked

    /// The database names, in entry order. Entry 0 is "main" and
    /// entry 1 is "temp", matching openDatabase's inline aDb.
    const NAMES: [&[u8]; ENTRY_COUNT] = [b"main\0", b"temp\0", b"aux1\0", b"aux2\0"];

    /// Builds the fixture: `n_db` into the handle, the `Db` array with
    /// zName pointers and distinct fake pSchema words.
    unsafe fn build_fixture(n_db: i32) {
        let base = slab();
        base.add(N_DB_OFFSET).cast::<i32>().write(n_db);
        base.add(A_DB_OFFSET)
            .cast::<u32>()
            .write(base.add(0x40) as u32);
        for (e, name) in NAMES.iter().enumerate() {
            let z = base.add(0x100 + e * 0x10);
            core::ptr::copy_nonoverlapping(name.as_ptr(), z, name.len());
            let entry = base.add(0x40 + e * DB_SIZE);
            entry.cast::<u32>().write(z as u32);
            entry
                .add(DB_P_SCHEMA_OFFSET)
                .cast::<u32>()
                .write(base.add(0x200 + e * 0x40) as u32);
        }
    }

    /// The `&aDb[j].pSchema->tblHash` pointer the port must compute
    /// for fixture entry `j`.
    unsafe fn tbl_hash(j: usize) -> *const Hash {
        let entry = slab().add(0x40 + j * DB_SIZE + DB_P_SCHEMA_OFFSET);
        entry.cast::<u32>().read().wrapping_add(SCHEMA_TBL_HASH_OFFSET) as *const Hash
    }

    /// The fixture zName pointer of entry `j`.
    unsafe fn z_name(j: usize) -> *const u8 {
        slab().add(0x100 + j * 0x10)
    }

    #[test]
    fn temp_is_searched_before_main() {
        let _slab_guard = SLAB_LOCK.lock();
        if try_slab().is_none() {
            return; // host cannot map below 4 GiB; skip
        }
        let _hook_guard = HOOK_LOCK.lock();
        let _hooks = with_mock_hooks();
        unsafe {
            build_fixture(2);
            let payload = 0x1122_3344usize as *mut u8;
            FIND_RESULT = payload;
            FIND_HIT_HASH = tbl_hash(1); // only TEMP holds the table
            let found = find_table(slab(), b"widgets\0".as_ptr(), core::ptr::null());
            assert_eq!(found, payload, "TEMP's hit is returned");
            let calls = find_calls();
            assert_eq!(calls.len(), 1, "the first hit ends the search");
            assert_eq!(calls[0].0, tbl_hash(1), "TEMP (index 1) first, not MAIN");
            assert_eq!(
                calls[0].2,
                "widgets".len() as i32 + 1,
                "key_len = strlen(zName) + 1"
            );
            assert_eq!(calls[0].1, b"widgets\0".as_ptr(), "the key is zName itself");
            assert!(icmp_calls().is_empty(), "NULL zDatabase skips the filter");
        }
    }

    #[test]
    fn miss_scans_temp_main_then_attach_order() {
        let _slab_guard = SLAB_LOCK.lock();
        if try_slab().is_none() {
            return;
        }
        let _hook_guard = HOOK_LOCK.lock();
        let _hooks = with_mock_hooks();
        unsafe {
            build_fixture(4);
            let found = find_table(slab(), b"t\0".as_ptr(), core::ptr::null());
            assert!(found.is_null(), "a miss in every database is NULL");
            let calls = find_calls();
            assert_eq!(calls.len(), 4, "every database probed once");
            let order: Vec<usize> = (0..ENTRY_COUNT)
                .filter(|&j| calls.iter().any(|c| c.0 == tbl_hash(j)))
                .collect();
            assert_eq!(order.len(), 4, "each schema seen");
            for (k, c) in calls.iter().enumerate() {
                let expected = [1usize, 0, 2, 3][k];
                assert_eq!(
                    c.0,
                    tbl_hash(expected),
                    "probe {k} is aDb[{expected}] (i^1 swap only below 2)"
                );
                assert_eq!(c.2, 2, "key_len = strlen(\"t\") + 1");
            }
        }
    }

    #[test]
    fn database_filter_skips_mismatched_schemas() {
        let _slab_guard = SLAB_LOCK.lock();
        if try_slab().is_none() {
            return;
        }
        let _hook_guard = HOOK_LOCK.lock();
        let _hooks = with_mock_hooks();
        unsafe {
            build_fixture(4);
            let payload = 0x5566_7788usize as *mut u8;
            FIND_RESULT = payload;
            let found = find_table(slab(), b"t\0".as_ptr(), b"main\0".as_ptr());
            assert_eq!(found, payload, "the named schema's hit is returned");
            let icmp = icmp_calls();
            assert_eq!(icmp.len(), 2, "TEMP filtered, then MAIN matched");
            assert_eq!(icmp[0], (b"main\0".as_ptr(), z_name(1)), "zDatabase is LEFT");
            assert_eq!(icmp[1], (b"main\0".as_ptr(), z_name(0)));
            let calls = find_calls();
            assert_eq!(calls.len(), 1, "only the matching schema is probed");
            assert_eq!(calls[0].0, tbl_hash(0), "MAIN's tblHash");
        }
    }

    #[test]
    fn database_filter_can_reject_every_schema() {
        let _slab_guard = SLAB_LOCK.lock();
        if try_slab().is_none() {
            return;
        }
        let _hook_guard = HOOK_LOCK.lock();
        let _hooks = with_mock_hooks();
        unsafe {
            build_fixture(2);
            FIND_RESULT = 0x1234_5678usize as *mut u8; // would hit, if probed
            let found = find_table(slab(), b"t\0".as_ptr(), b"nosuchdb\0".as_ptr());
            assert!(found.is_null(), "no schema matched -> NULL, never probed");
            assert_eq!(icmp_calls().len(), 2, "both schemas compared");
            assert!(find_calls().is_empty(), "the hash is never probed");
        }
    }

    #[test]
    fn filter_uses_the_real_case_fold() {
        let _slab_guard = SLAB_LOCK.lock();
        if try_slab().is_none() {
            return;
        }
        let _hook_guard = HOOK_LOCK.lock();
        let _hooks = with_mock_hooks();
        unsafe {
            // The real ported str_icmp @ 0x08384f14 as the filter, the
            // mock only for the hash probe.
            FIND_TABLE_HOOKS.icmp = str_icmp;
            build_fixture(2);
            let payload = 0x0bad_f00dusize as *mut u8;
            FIND_RESULT = payload;
            let found = find_table(slab(), b"t\0".as_ptr(), b"MAIN\0".as_ptr());
            assert_eq!(found, payload, "case-insensitive schema match");
            let calls = find_calls();
            assert_eq!(calls.len(), 1, "TEMP folded-mismatched, MAIN probed");
            assert_eq!(calls[0].0, tbl_hash(0));
        }
    }

    #[test]
    fn empty_db_list_finds_nothing() {
        let _slab_guard = SLAB_LOCK.lock();
        if try_slab().is_none() {
            return;
        }
        let _hook_guard = HOOK_LOCK.lock();
        let _hooks = with_mock_hooks();
        unsafe {
            for n_db in [0, -1] {
                build_fixture(n_db);
                let found = find_table(slab(), b"t\0".as_ptr(), core::ptr::null());
                assert!(found.is_null(), "nDb {n_db} finds nothing");
                assert!(icmp_calls().is_empty(), "aDb never read (nDb {n_db})");
                assert!(find_calls().is_empty(), "aDb never read (nDb {n_db})");
            }
        }
    }

    #[test]
    fn default_hooks_are_the_real_ports() {
        let defaults = DEFAULT_FIND_TABLE_HOOKS;
        assert_eq!(defaults.icmp as usize, str_icmp as usize);
        assert_eq!(defaults.find as usize, hash_find as usize);
    }
}
