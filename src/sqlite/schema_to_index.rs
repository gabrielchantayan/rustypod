//! Mapping a `Schema` back to its database index — `sqlite3SchemaToIndex`
//! from prepare.c, the resolver the expression and select code generators
//! use to turn a table's schema pointer into the `aDb[]` slot number that
//! vdbe opcodes carry.
//!
//! - `schema_to_index` — original: `FUN_08382ddc` @ 0x08382ddc (72 bytes
//!   of code plus one literal-pool word at 0x08382e24; the next function
//!   starts at 0x08382e28. 33 `bl` call sites, binary-scanned — every one
//!   unconditional, no predicated forms). SQLite 3.5.x's
//!   `sqlite3SchemaToIndex`:
//!
//! ```c
//! int sqlite3SchemaToIndex(sqlite3 *db, Schema *pSchema){
//!   int i = -1000000;
//!   assert( pSchema );
//!   if( pSchema ){
//!     for(i=0; i<db->nDb; i++){
//!       if( db->aDb[i].pSchema==pSchema ){
//!         break;
//!       }
//!     }
//!     assert( i>=0 && i<db->nDb );
//!   }
//!   return i;
//! }
//! ```
//!
//! The listing (asserts compiled out, NDEBUG):
//!
//! ```text
//! 08382ddc:  ldr  r2,[pc,#0x40]   ; literal 0xfff0bdc0 = -1000000
//! 08382de0:  cmp  r1,#0
//! 08382de4:  push {lr}
//! 08382de8:  beq  0x08382e1c      ; pSchema == NULL -> return -1000000
//! 08382dec:  ldr  lr,[r0,#0x4]    ; db->nDb
//! 08382df0:  mov  r2,#0           ; i = 0
//! 08382df4:  b    0x08382e14
//! 08382df8:  ldr  r3,[r0,#0x8]    ; db->aDb (reloaded each iteration)
//! 08382dfc:  add  ip,r2,r2,lsl #1
//! 08382e00:  add  r3,r3,ip,lsl #3 ; aDb + i*24
//! 08382e04:  ldr  r3,[r3,#0x14]   ; aDb[i].pSchema
//! 08382e08:  cmp  r3,r1
//! 08382e0c:  beq  0x08382e1c      ; match -> return i
//! 08382e10:  add  r2,r2,#1
//! 08382e14:  cmp  lr,r2
//! 08382e18:  bgt  0x08382df8      ; while (nDb > i), signed
//! 08382e1c:  mov  r0,r2
//! 08382e20:  pop  {pc}
//! 08382e24:  .word 0xfff0bdc0
//! ```
//!
//! Behavioural facts the listing pins:
//!
//! - The NULL-`pSchema` sentinel is `-1000000` and is returned *before*
//!   `db` is dereferenced — upstream's comment says this is how expr.c
//!   resolves references to transient (sub-select) tables, and the
//!   caller may pass a `db` that is not readable in that case.
//! - The loop bound is a signed `bgt`: a zero or negative `nDb`
//!   returns 0.
//! - No match returns `nDb` (the assert that would catch it upstream
//!   is compiled out); callers like FUN_082b45d4 pass the result
//!   straight into `sqlite3VdbeAddOp*` operands, so the out-of-range
//!   index propagates verbatim.
//!
//! It pins this build's `Db` layout (24 bytes, vs upstream's 16):
//!
//! ```text
//! +0x00 zName   (ptr)  aDb[0].zName = "main" in openDatabase
//! +0x04 pBt     (ptr)  handed to sqlite3SchemaGet @ 0x08382d18
//! +0x08 inTrans (u8)
//! +0x09 safety_level (u8)  openDatabase stores 3 here
//! +0x14 pSchema (ptr)  sqlite3SchemaGet's result lands at
//!                      aDb[0]+0x14 and aDb[1]+0x14 (+0x2c)
//! ```
//!
//! Proof of the stride and the +0x14 offset: openDatabase @ 0x082dbda8
//! allocates the 0x180-byte `sqlite3` handle and points `aDb` (+0x08)
//! at handle+0x14c, an inline two-entry array (2 * 0x18 = 0x30;
//! 0x14c + 0x30 = 0x17c <= 0x180), stores aDb[0].pBt (+0x04) through
//! `sqlite3SchemaGet` into +0x14, and writes the second entry's zName
//! at +0x18. Upstream's `Db` is `zName, pBt, inTrans, safety_level,
//! pSchema` at 16 bytes with `pSchema` at +0x0c; this build carries
//! eight extra bytes somewhere in +0x0a..+0x13.
//!
//! Deviation from upstream: none in behaviour; the asserts are absent
//! (NDEBUG) and `db->aDb` is reloaded per iteration in the original,
//! which is not observable. Like the sibling sqlite ports, struct words
//! are read as `u32` because the target's pointers are 32-bit.

/// Index returned for a NULL `pSchema` — transient tables in expr.c
/// (original: literal-pool word 0xfff0bdc0 @ 0x08382e24).
const TRANSIENT_SCHEMA_INDEX: i32 = -1000000;
/// Word offset of `sqlite3.nDb` (original: `ldr lr, [r0, #4]`).
const N_DB_OFFSET: usize = 0x04;
/// Word offset of `sqlite3.aDb` (original: `ldr r3, [r0, #8]`).
const A_DB_OFFSET: usize = 0x08;
/// `sizeof(Db)` in this build (original: `i*3 << 3` index arithmetic).
const DB_SIZE: usize = 0x18;
/// Word offset of `Db.pSchema` (original: `ldr r3, [r3, #0x14]`).
const DB_P_SCHEMA_OFFSET: usize = 0x14;

/// schema_to_index — original: `FUN_08382ddc` @ 0x08382ddc (72 bytes; 33
/// `bl` call sites).
///
/// `sqlite3SchemaToIndex`: return the index of `schema` in `db`'s
/// attached-database array, `-1000000` when `schema` is NULL (transient
/// sub-select table; `db` is not touched in that case), or `db->nDb`
/// when no entry matches. `db` must point at a readable `sqlite3`
/// handle whose `aDb` array holds at least `nDb` 24-byte `Db` entries
/// whenever `schema` is non-NULL.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn schema_to_index(db: *const u8, schema: *const u8) -> i32 {
    if schema.is_null() {
        return TRANSIENT_SCHEMA_INDEX;
    }
    let n_db = db.add(N_DB_OFFSET).cast::<i32>().read();
    let a_db = db.add(A_DB_OFFSET).cast::<u32>().read() as *const u8;
    let mut index: i32 = 0;
    while n_db > index {
        let entry_schema = a_db
            .add(index as usize * DB_SIZE + DB_P_SCHEMA_OFFSET)
            .cast::<u32>()
            .read();
        if entry_schema == schema as u32 {
            break;
        }
        index += 1;
    }
    index
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::{LazyLock, Mutex};

    /// All fixture tests share the one mapped slab; serialize on a
    /// single lock.
    static SLAB_LOCK: Mutex<()> = Mutex::new(());

    /// Number of `Db` entries in the fixture array.
    const ENTRY_COUNT: usize = 3;

    /// Maps the fixture slab once per process. The port widens `u32`
    /// words into host pointers, so the handle, the `Db` array and the
    /// fake `Schema` addresses must all live below 4 GiB; `None` means
    /// this host cannot supply such a mapping and the tests skip rather
    /// than crash.
    fn try_slab() -> Option<*mut u8> {
        static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
            crate::testing::try_map_u32_slab(crate::testing::hints::SCHEMA_TO_INDEX, 0x1000)
                .map(|p| p as usize)
        });
        SLAB.map(|p| p as *mut u8)
    }

    /// The fixture base. Only reached once [`try_slab`] has confirmed
    /// the mapping exists.
    fn slab() -> *mut u8 {
        try_slab().expect("fixture slab checked by the caller's skip guard")
    }

    /// The fake `sqlite3` handle: nDb at +0x04, aDb at +0x08.
    unsafe fn db() -> *mut u8 {
        slab()
    }

    /// The fake `Db` array, three 24-byte entries.
    unsafe fn a_db() -> *mut u8 {
        slab().add(0x40)
    }

    /// Fake `Schema` addresses — compared, never dereferenced.
    unsafe fn schema(entry: usize) -> *mut u8 {
        slab().add(0x200 + entry * 0x10)
    }

    unsafe fn write_word(record: *mut u8, offset: usize, value: u32) {
        record.add(offset).cast::<u32>().write(value);
    }

    /// Stamps `n_db` into the handle and points it at the `Db` array,
    /// whose entries are filled with garbage except for the +0x14
    /// `pSchema` words — proving those are the only words observed.
    unsafe fn prepare(n_db: i32) {
        write_word(db(), N_DB_OFFSET, n_db as u32);
        write_word(db(), A_DB_OFFSET, a_db() as u32);
        for entry in 0..ENTRY_COUNT + 1 {
            let base = a_db().add(entry * DB_SIZE);
            for word in 0..DB_SIZE / 4 {
                write_word(base, word * 4, 0xa5a5_a500 + (entry * 7 + word) as u32);
            }
            write_word(base, DB_P_SCHEMA_OFFSET, schema(entry) as u32);
        }
    }

    #[test]
    fn null_schema_returns_sentinel_without_reading_db() {
        // A NULL db would fault if dereferenced: the sentinel path must
        // return before touching it (upstream resolves transient
        // sub-select tables this way).
        assert_eq!(unsafe { schema_to_index(core::ptr::null(), core::ptr::null()) }, -1000000);
    }

    #[test]
    fn finds_schema_at_every_index() {
        let _lock = SLAB_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        if try_slab().is_none() {
            crate::testing::note_missing_u32_fixture("sqlite::schema_to_index");
            return;
        }
        unsafe {
            prepare(ENTRY_COUNT as i32);
            for entry in 0..ENTRY_COUNT {
                assert_eq!(schema_to_index(db(), schema(entry)), entry as i32);
            }
        }
    }

    #[test]
    fn first_match_wins_over_duplicate_p_schema() {
        let _lock = SLAB_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        if try_slab().is_none() {
            crate::testing::note_missing_u32_fixture("sqlite::schema_to_index");
            return;
        }
        unsafe {
            prepare(ENTRY_COUNT as i32);
            write_word(a_db().add(DB_SIZE), DB_P_SCHEMA_OFFSET, schema(0) as u32);
            assert_eq!(schema_to_index(db(), schema(0)), 0);
        }
    }

    #[test]
    fn unknown_schema_returns_n_db() {
        let _lock = SLAB_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        if try_slab().is_none() {
            crate::testing::note_missing_u32_fixture("sqlite::schema_to_index");
            return;
        }
        unsafe {
            prepare(ENTRY_COUNT as i32);
            let unknown = slab().add(0x300);
            assert_eq!(schema_to_index(db(), unknown), ENTRY_COUNT as i32);
        }
    }

    #[test]
    fn entries_beyond_n_db_are_not_searched() {
        let _lock = SLAB_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        if try_slab().is_none() {
            crate::testing::note_missing_u32_fixture("sqlite::schema_to_index");
            return;
        }
        unsafe {
            // The match lives in entry 2 but nDb stops the loop at 2.
            prepare(2);
            assert_eq!(schema_to_index(db(), schema(2)), 2);
        }
    }

    #[test]
    fn empty_db_returns_zero() {
        let _lock = SLAB_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        if try_slab().is_none() {
            crate::testing::note_missing_u32_fixture("sqlite::schema_to_index");
            return;
        }
        unsafe {
            prepare(0);
            assert_eq!(schema_to_index(db(), schema(0)), 0);
        }
    }

    #[test]
    fn negative_n_db_returns_zero() {
        let _lock = SLAB_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        if try_slab().is_none() {
            crate::testing::note_missing_u32_fixture("sqlite::schema_to_index");
            return;
        }
        unsafe {
            // The original's loop guard is a signed `bgt`: nDb <= 0
            // skips the loop and returns the initial index 0.
            prepare(-1);
            assert_eq!(schema_to_index(db(), schema(0)), 0);
        }
    }
}
