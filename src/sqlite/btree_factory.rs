//! Open a B-tree for one attached database — retailOS `FUN_0837126c` at
//! `0x0837126c` (148 bytes extent, 136 bytes of code plus a 12-byte
//! `":memory:"` literal and padding).
//!
//! Raw ARM establishes the exact extent: `mov r12,r0; push {r3,r4,r5,r6,r7,lr}`
//! begins at `0x0837126c`, its `pop {r3,r4,r5,r6,r7,pc}` is at `0x083712f0`,
//! the `":memory:"` literal (addressed by `adreq r0,0x83712f4`) occupies
//! `0x083712f4..0x08371300`, and the distinct next function's
//! `push {r4,lr}` prologue begins at `0x08371300`. Ghidra reports 136 bytes
//! because it counts only the code; the true extent to the next function is
//! 148 bytes. Decoding every ARM B/BL word in `osos.dec` finds four
//! plain-`bl` callers of this entry (`0x082b5430`, `0x082dbfb0`,
//! `0x0837da94`, `0x08388eac`), all unconditional with no predicated form.
//! The body itself contains two `bl` instructions: one unconditional
//! `bl 0x083723a8` and one predicated `bleq 0x08372cb8`.
//!
//! This is SQLite 3.5.x's `sqlite3BtreeFactory`: derive the B-tree open
//! flags from the request, then open the B-tree and size its page cache.
//!
//! - `btree_flags` starts as `omit_journal != 0` (bit 0,
//!   `BTREE_OMIT_JOURNAL`) and gains bit 1 (`BTREE_NO_READLOCK`) when the
//!   connection's `flags` word (+0x0c) has `0x1000` (`SQLITE_NoReadlock`)
//!   set.
//! - A NULL `filename` becomes `":memory:"` when the connection's
//!   `temp_store` byte (+0x1d) equals 2.
//! - When the VFS `flags` (fifth argument, passed on the stack) carry
//!   `0x100` (`SQLITE_OPEN_MAIN_DB`) and the resolved filename is NULL or
//!   empty, the raw ARM's predicated `bic`/`orr` rewrites them to
//!   `(flags & !0x100) | 0x200` — `SQLITE_OPEN_MAIN_DB` becomes
//!   `SQLITE_OPEN_TEMP_DB`.
//! - `sqlite3BtreeOpen` @ `0x083723a8` runs as
//!   `(filename, db, pp_btree, btree_flags, flags)` — the fifth argument
//!   stacked (`str r3,[sp]`) exactly as received.
//! - On `SQLITE_OK` only, the predicated `bleq` runs
//!   `sqlite3BtreeSetCacheSize` @ `0x08372cb8` as `(*pp_btree, n_cache)`.
//!   The open status is returned either way.
//!
//! Deliberate deviation: both callees are unported stock functions, so all
//! calls ride the [`BTREE_FACTORY_OPS`] dispatch seam (the house pattern —
//! `sqlite/begin_write_operation.rs`). The wired default open fails with
//! `SQLITE_CANTOPEN` (14) without touching `pp_btree`: the factory then
//! propagates the failure and never reaches the cache-size call, which is
//! the same end state the original reaches when the real
//! `sqlite3BtreeOpen` itself fails. No default invents a B-tree. Host
//! tests substitute the slots to observe exact arguments and order.

/// `SQLITE_NoReadlock` — the `sqlite3.flags` bit that maps to
/// `BTREE_NO_READLOCK`.
const SQLITE_NO_READLOCK: u32 = 0x1000;

/// `BTREE_OMIT_JOURNAL` — do not journal this B-tree.
const BTREE_OMIT_JOURNAL: u32 = 0x1;

/// `BTREE_NO_READLOCK` — never take read locks on this B-tree.
const BTREE_NO_READLOCK: u32 = 0x2;

/// `SQLITE_OPEN_MAIN_DB` — VFS flag rewritten to `SQLITE_OPEN_TEMP_DB`
/// when the filename resolves to NULL or empty.
const SQLITE_OPEN_MAIN_DB: u32 = 0x100;

/// `SQLITE_OPEN_TEMP_DB`.
const SQLITE_OPEN_TEMP_DB: u32 = 0x200;

/// `SQLITE_CANTOPEN` — the seam default's synthetic open failure.
const SQLITE_CANTOPEN: u32 = 14;

/// `SQLITE_TEMP_STORE == 2`: temporary tables live in memory.
const TEMP_STORE_MEMORY: u8 = 2;

/// The `":memory:"` filename the original embeds at `0x083712f4`.
static MEMORY_FILENAME: [u8; 9] = *b":memory:\0";

/// The connection (`sqlite3`) fields this function reads.
#[repr(C)]
pub struct Connection {
    /// +0x00..+0x0c: unmodeled (`pVfs`, `nDb`, `aDb`).
    pub _gap_00: [u8; 0x0c],
    /// +0x0c: connection flags (`sqlite3.flags`); `SQLITE_NoReadlock`
    /// (0x1000) gates `BTREE_NO_READLOCK`.
    pub flags: u32,
    /// +0x10..+0x1d: unmodeled.
    pub _gap_10: [u8; 0x1d - 0x10],
    /// +0x1d: `sqlite3.temp_store`; 2 selects the `":memory:"` filename
    /// for a NULL filename argument.
    pub temp_store: u8,
}

#[cfg(target_pointer_width = "32")]
const _: () = {
    assert!(core::mem::offset_of!(Connection, flags) == 0x0c);
    assert!(core::mem::offset_of!(Connection, temp_store) == 0x1d);
};

/// `sqlite3BtreeOpen` @ `0x083723a8` (UNPORTED): open the B-tree.
type BtreeOpen =
    unsafe extern "C" fn(*const u8, *const Connection, *mut *mut u8, u32, u32) -> u32;

/// `sqlite3BtreeSetCacheSize` @ `0x08372cb8` (UNPORTED): clamp and latch
/// the page-cache size (identity verified from its decompilation:
/// enter, `max(n_cache, 10)` into the shared cache size, leave, 0).
type BtreeSetCacheSize = unsafe extern "C" fn(*mut u8, i32) -> u32;

/// Indirect dispatch for the original's two unported callees, kept
/// behind a table so host tests can observe the calls' arguments and
/// order (the house pattern — `sqlite/begin_write_operation.rs`).
#[derive(Clone, Copy)]
pub struct BtreeFactoryOps {
    /// `sqlite3BtreeOpen` @ `0x083723a8` (UNPORTED).
    pub btree_open: BtreeOpen,
    /// `sqlite3BtreeSetCacheSize` @ `0x08372cb8` (UNPORTED).
    pub btree_set_cache_size: BtreeSetCacheSize,
}

/// Stand-in for the unported `sqlite3BtreeOpen`: fail with
/// `SQLITE_CANTOPEN` and leave `pp_btree` untouched. The factory then
/// propagates 14 and skips the cache-size call — the same end state the
/// original reaches when the real open fails. No B-tree is invented.
unsafe extern "C" fn unavailable_btree_open(
    _filename: *const u8,
    _db: *const Connection,
    _pp_btree: *mut *mut u8,
    _btree_flags: u32,
    _flags: u32,
) -> u32 {
    SQLITE_CANTOPEN
}

/// Stand-in for the unported `sqlite3BtreeSetCacheSize`: unreachable
/// behind the default open (which always fails), but reports success if
/// a test wires it without wiring the open.
unsafe extern "C" fn unavailable_btree_set_cache_size(_btree: *mut u8, _n_cache: i32) -> u32 {
    0
}

/// Wired default for [`BTREE_FACTORY_OPS`]: the failing-open stand-in
/// and the unreachable cache-size stand-in, on both target and host,
/// until `sqlite3BtreeOpen` is ported for real.
pub const DEFAULT_BTREE_FACTORY_OPS: BtreeFactoryOps = BtreeFactoryOps {
    btree_open: unavailable_btree_open,
    btree_set_cache_size: unavailable_btree_set_cache_size,
};

/// Active models of the original's two unported callees. Host tests
/// replace the slots to observe the exact arguments.
pub static mut BTREE_FACTORY_OPS: BtreeFactoryOps = DEFAULT_BTREE_FACTORY_OPS;

/// Reads the dispatch table. Volatile so LLVM cannot constant-fold the
/// loads to the stand-in defaults (the house pattern).
#[inline(always)]
unsafe fn ops() -> BtreeFactoryOps {
    core::ptr::read_volatile(core::ptr::addr_of!(BTREE_FACTORY_OPS))
}

/// `sqlite3BtreeFactory` — original: `FUN_0837126c` @ `0x0837126c`
/// (148-byte extent: 136 bytes of code plus the embedded `":memory:"`
/// literal; 4 direct plain-`bl` call sites, binary-verified).
///
/// Opens the B-tree backing one attached database: translates
/// `omit_journal` and the connection's `SQLITE_NoReadlock` flag into
/// B-tree open flags, substitutes `":memory:"` for a NULL filename when
/// `temp_store == 2`, rewrites `SQLITE_OPEN_MAIN_DB` to
/// `SQLITE_OPEN_TEMP_DB` for a NULL/empty filename, opens the B-tree,
/// and on success sizes its page cache to `n_cache`. Returns the open
/// status.
///
/// # Safety
/// `db` must point to a live [`Connection`] — the raw ARM dereferences
/// it without guards. `filename` must be NULL or a NUL-terminated
/// string. `pp_btree` must be a writable out-slot; on success it holds
/// the new B-tree and `*pp_btree` is passed to the cache-size call.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.btree_factory")]
#[inline(never)]
pub unsafe extern "C" fn btree_factory(
    db: *const Connection,
    filename: *const u8,
    omit_journal: i32,
    n_cache: i32,
    flags: u32,
    pp_btree: *mut *mut u8,
) -> u32 {
    let mut btree_flags = (omit_journal != 0) as u32;
    if (*db).flags & SQLITE_NO_READLOCK != 0 {
        btree_flags |= BTREE_NO_READLOCK;
    }
    let mut filename = filename;
    if filename.is_null() && (*db).temp_store == TEMP_STORE_MEMORY {
        filename = MEMORY_FILENAME.as_ptr();
    }
    let mut flags = flags;
    if flags & SQLITE_OPEN_MAIN_DB != 0 && (filename.is_null() || *filename == 0) {
        flags = (flags & !SQLITE_OPEN_MAIN_DB) | SQLITE_OPEN_TEMP_DB;
    }
    let ops = ops();
    let status = (ops.btree_open)(filename, db, pp_btree, btree_flags, flags);
    if status == 0 {
        (ops.btree_set_cache_size)(*pp_btree, n_cache);
    }
    status
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    /// Serializes tests that swap the dispatch slots: the seams are
    /// process-global.
    static OPS_LOCK: Mutex<()> = Mutex::new(());

    /// Every `(btree_flags, flags)` pair the recording open saw, in order.
    static mut OPEN_CALLS: Vec<(u32, u32)> = Vec::new();
    /// The filename pointer each open saw (b"..." sentinel ids, see below).
    static mut OPEN_FILENAME_ID: Vec<u8> = Vec::new();
    /// The db pointer each open saw.
    static mut OPEN_DB_NULL: bool = false;
    /// Every `(btree-null, n_cache)` the recording cache-size call saw.
    static mut CACHE_CALLS: Vec<i32> = Vec::new();
    /// What the recording open returns.
    static mut OPEN_STATUS: u32 = 0;
    /// Whether the recording open writes a fake B-tree into `pp_btree`.
    static mut OPEN_INSTALLS_BTREE: bool = false;

    static FILENAME_A: [u8; 4] = *b"fa\0\0";
    static FILENAME_EMPTY: [u8; 1] = [0];

    unsafe extern "C" fn recording_btree_open(
        filename: *const u8,
        db: *const Connection,
        pp_btree: *mut *mut u8,
        btree_flags: u32,
        flags: u32,
    ) -> u32 {
        OPEN_CALLS.push((btree_flags, flags));
        OPEN_DB_NULL = db.is_null();
        OPEN_FILENAME_ID.push(if filename.is_null() {
            0
        } else if filename == FILENAME_A.as_ptr() {
            1
        } else if filename == FILENAME_EMPTY.as_ptr() {
            2
        } else if filename == MEMORY_FILENAME.as_ptr() {
            3
        } else {
            9
        });
        if OPEN_INSTALLS_BTREE {
            static mut FAKE_BTREE: u32 = 0;
            *pp_btree = core::ptr::addr_of_mut!(FAKE_BTREE).cast();
        }
        OPEN_STATUS
    }

    unsafe extern "C" fn recording_btree_set_cache_size(btree: *mut u8, n_cache: i32) -> u32 {
        assert!(!btree.is_null(), "cache size runs on the opened B-tree");
        CACHE_CALLS.push(n_cache);
        0
    }

    struct Bench {
        _guard: MutexGuard<'static, ()>,
    }

    impl Drop for Bench {
        fn drop(&mut self) {
            unsafe {
                core::ptr::write_volatile(
                    core::ptr::addr_of_mut!(BTREE_FACTORY_OPS),
                    DEFAULT_BTREE_FACTORY_OPS,
                );
            }
        }
    }

    fn bench(open_status: u32, installs_btree: bool) -> Bench {
        let guard = OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            OPEN_CALLS.clear();
            OPEN_FILENAME_ID.clear();
            CACHE_CALLS.clear();
            OPEN_DB_NULL = false;
            OPEN_STATUS = open_status;
            OPEN_INSTALLS_BTREE = installs_btree;
            core::ptr::write_volatile(
                core::ptr::addr_of_mut!(BTREE_FACTORY_OPS),
                BtreeFactoryOps {
                    btree_open: recording_btree_open,
                    btree_set_cache_size: recording_btree_set_cache_size,
                },
            );
        }
        Bench { _guard: guard }
    }

    fn connection(flags: u32, temp_store: u8) -> Connection {
        Connection {
            _gap_00: [0; 0x0c],
            flags,
            _gap_10: [0; 0x1d - 0x10],
            temp_store,
        }
    }

    #[test]
    fn named_file_plain_flags_open_then_cache_size() {
        let db = connection(0, 0);
        let mut out: *mut u8 = core::ptr::null_mut();
        let _bench = bench(0, true);

        let status = unsafe {
            btree_factory(&db, FILENAME_A.as_ptr(), 0, 2000, 0x4, &mut out)
        };

        assert_eq!(status, 0);
        unsafe {
            assert_eq!(OPEN_CALLS.as_slice(), &[(0, 0x4)]);
            assert_eq!(OPEN_FILENAME_ID.as_slice(), &[1]);
            assert!(!OPEN_DB_NULL);
            assert_eq!(CACHE_CALLS.as_slice(), &[2000], "cache size on success");
        }
        assert!(!out.is_null(), "open installed the B-tree");
    }

    #[test]
    fn omit_journal_and_no_readlock_set_btree_flag_bits() {
        let db = connection(SQLITE_NO_READLOCK, 0);
        let mut out: *mut u8 = core::ptr::null_mut();
        let _bench = bench(0, true);

        let status = unsafe {
            btree_factory(&db, FILENAME_A.as_ptr(), 1, 10, 0, &mut out)
        };

        assert_eq!(status, 0);
        unsafe {
            assert_eq!(
                OPEN_CALLS.as_slice(),
                &[(BTREE_OMIT_JOURNAL | BTREE_NO_READLOCK, 0)]
            );
        }
    }

    #[test]
    fn null_filename_temp_store_two_substitutes_memory() {
        let db = connection(0, TEMP_STORE_MEMORY);
        let mut out: *mut u8 = core::ptr::null_mut();
        let _bench = bench(0, true);

        let status = unsafe { btree_factory(&db, core::ptr::null(), 0, 5, 0, &mut out) };

        assert_eq!(status, 0);
        unsafe {
            assert_eq!(OPEN_FILENAME_ID.as_slice(), &[3], "the \":memory:\" literal");
        }
    }

    #[test]
    fn null_filename_other_temp_store_stays_null() {
        for temp_store in [0u8, 1, 3] {
            let db = connection(0, temp_store);
            let mut out: *mut u8 = core::ptr::null_mut();
            let _bench = bench(0, true);

            let status =
                unsafe { btree_factory(&db, core::ptr::null(), 0, 5, 0, &mut out) };

            assert_eq!(status, 0);
            unsafe {
                assert_eq!(OPEN_FILENAME_ID.as_slice(), &[0], "temp_store {temp_store}");
            }
        }
    }

    #[test]
    fn main_db_flag_becomes_temp_db_for_null_filename() {
        let db = connection(0, 0);
        let mut out: *mut u8 = core::ptr::null_mut();
        let _bench = bench(0, true);

        let status = unsafe {
            btree_factory(&db, core::ptr::null(), 0, 5, 0x104, &mut out)
        };

        assert_eq!(status, 0);
        unsafe {
            assert_eq!(OPEN_CALLS.as_slice(), &[(0, 0x204)], "0x100 -> 0x200, rest kept");
        }
    }

    #[test]
    fn main_db_flag_becomes_temp_db_for_empty_filename() {
        let db = connection(0, 0);
        let mut out: *mut u8 = core::ptr::null_mut();
        let _bench = bench(0, true);

        let status = unsafe {
            btree_factory(&db, FILENAME_EMPTY.as_ptr(), 0, 5, 0x100, &mut out)
        };

        assert_eq!(status, 0);
        unsafe {
            assert_eq!(OPEN_CALLS.as_slice(), &[(0, 0x200)]);
        }
    }

    #[test]
    fn main_db_flag_kept_for_named_file() {
        let db = connection(0, 0);
        let mut out: *mut u8 = core::ptr::null_mut();
        let _bench = bench(0, true);

        let status = unsafe {
            btree_factory(&db, FILENAME_A.as_ptr(), 0, 5, 0x100, &mut out)
        };

        assert_eq!(status, 0);
        unsafe {
            assert_eq!(OPEN_CALLS.as_slice(), &[(0, 0x100)], "no rewrite for a name");
        }
    }

    #[test]
    fn open_failure_skips_cache_size_and_propagates() {
        let db = connection(0, 0);
        let mut out: *mut u8 = core::ptr::null_mut();
        let _bench = bench(14, false);

        let status = unsafe {
            btree_factory(&db, FILENAME_A.as_ptr(), 0, 2000, 0, &mut out)
        };

        assert_eq!(status, 14, "open status returned verbatim");
        unsafe {
            assert!(CACHE_CALLS.is_empty(), "no cache-size call on failure");
        }
    }

    #[test]
    fn default_seam_fails_open_without_inventing_a_btree() {
        let db = connection(0, 0);
        let mut out: *mut u8 = core::ptr::null_mut();
        let guard = OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        let status = unsafe {
            btree_factory(&db, FILENAME_A.as_ptr(), 0, 2000, 0, &mut out)
        };

        assert_eq!(status, SQLITE_CANTOPEN);
        assert!(out.is_null(), "no B-tree fabricated");
        drop(guard);
    }
}
