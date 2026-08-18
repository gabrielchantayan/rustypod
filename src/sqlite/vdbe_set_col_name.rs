//! Result-column naming — how a prepared statement records the name and
//! declared type it will report for each column it produces.
//!
//! - `vdbe_set_col_name` — original: `FUN_0838d004` @ 0x0838d004
//!   (140 bytes, 0x0838d004..0x0838d090; **45 `bl` call sites**, all
//!   unconditional, binary-scanned from osos.dec — no predicated or
//!   tail-`b` entries). Upstream SQLite's `sqlite3VdbeSetColName`
//!   (`int sqlite3VdbeSetColName(Vdbe *p, int idx, int var,
//!   const char *zName, int N)` in vdbeaux.c).
//!
//! ### Extent
//!
//! Confirmed from raw words, not from Ghidra's listing. 0x0838d08c is
//! `ldmia sp!, {r3,r4,r5,pc}` (0xe8bd8038) and 0x0838d090 is
//! `stmdb sp!, {r4,r5,r6,lr}` (0xe92d4070) — the entry of
//! `sqlite3VdbeSetNumCols`, which allocates the very array this
//! function writes into. There is no literal pool between them.
//!
//! Ghidra's decompile of this function is wrong in one visible way: it
//! types the function `void` and drops the early return entirely. The
//! raw words are `movne r0,#7 / bne 0x0838d08c` — an `SQLITE_NOMEM`
//! return on the out-of-memory path — and every other path leaves the
//! callee's `r0` untouched, so the original returns a result code.
//!
//! ### Algorithm
//!
//! `p->aColName` (+0x28) is a flat array of `nResColumn * COLNAME_N`
//! 40-byte [`Mem`]s: plane `var` holds one name kind (0 = the column
//! name, 1 = its declared type), so the element for `(idx, var)` is at
//! `idx + var * p->nResColumn`. The original computes that index and
//! then the byte offset with the classic no-multiplier sequence
//! `mla r0,r2,r0,ip` / `add r0,r0,r0 lsl #2` / `add r4,r3,r0 lsl #3` —
//! index times five times eight, i.e. a 40-byte stride.
//!
//! An out-of-memory connection (`p->db->mallocFailed` at +0x1e) is
//! refused up front with `SQLITE_NOMEM`; upstream's two `assert()`s on
//! `idx` and `var` are compiled out, so nothing bounds-checks the
//! index.
//!
//! `N` selects the ownership contract, and the original tests it with
//! `cmn r5,#1` / `cmnne r5,#2`:
//!
//! - `N == P4_DYNAMIC` (-1) or `N == P4_STATIC` (-2): `zName` is a
//!   NUL-terminated string, so the length is `-1` (measure in place)
//!   and the destructor is `SQLITE_STATIC` (NULL) — the `Mem` is told
//!   not to own the bytes.
//! - anything else: `N` is a real byte count and the destructor is
//!   `SQLITE_TRANSIENT` ((void *)-1), so the `Mem` copies.
//!
//! The encoding is always `SQLITE_UTF8`.
//!
//! Then the `P4_DYNAMIC` twist. That tag means the caller handed over a
//! `sqlite3_malloc`'d buffer, but the call above just installed it as
//! `MEM_Static` — nobody would ever free it. So on success the original
//! clears [`MEM_STATIC`] from `flags` (+0x1c) and copies `z` (+0x14)
//! into `zMalloc` (+0x24), which is how a `Mem` says "I own this buffer
//! and will `sqlite3_free` it myself". Ownership transfers without a
//! copy. `P4_STATIC` deliberately skips this — the condition is
//! `cmp r0,#0 / cmneq r5,#1`, i.e. `rc == SQLITE_OK && N == -1` only.
//!
//! ### Deviations
//!
//! - `sqlite3VdbeMemSetStr` @ 0x0838c158 is ported
//!   ([`vdbe_mem_set_str`](super::vdbe_mem_set_str::vdbe_mem_set_str))
//!   and is the shipped default of the existing
//!   [`SQLITE_VDBE_MEM_SET_STR`](super::value_set_str::SQLITE_VDBE_MEM_SET_STR)
//!   dispatch static that `sqlite/value_set_str.rs` owns for the same
//!   callee. The slot remains so host tests can install recording mocks.
//! - `Vdbe` and [`Mem`] are `#[repr(C)]` structs with named fields
//!   rather than byte offsets, so the pointer fields stay disjoint on a
//!   64-bit test host; the original's offsets are statically asserted
//!   on 32-bit targets in `sqlite/vdbe.rs`.
//! - `p->db` is read unconditionally, exactly like the original: a NULL
//!   connection would fault there too.

use super::value_set_str::{vdbe_mem_set_str_op, SQLITE_NOMEM};
use super::vdbe::{Mem, Vdbe, MEM_STATIC, P4_DYNAMIC, P4_STATIC};
use crate::sqlite::mem::MALLOC_FAILED_OFFSET;

/// `SQLITE_OK` — the original's success comparison (`cmp r0,#0`).
pub const SQLITE_OK: i32 = 0;

/// `SQLITE_UTF8`: the encoding every name is installed with
/// (`mov r3,#1`).
pub const SQLITE_UTF8: u8 = 1;

/// `SQLITE_STATIC`: no destructor — the `Mem` does not own the bytes.
pub const SQLITE_STATIC: *mut u8 = core::ptr::null_mut();

/// `SQLITE_TRANSIENT` ((void *)-1): the `Mem` must take its own copy.
pub const SQLITE_TRANSIENT: *mut u8 = usize::MAX as *mut u8;

/// Length passed to the installer when `zName` is NUL-terminated
/// (`mvn r2,#0`) — "measure it yourself".
pub const MEASURE_IN_PLACE: i32 = -1;

/// vdbe_set_col_name — original: `FUN_0838d004` @ 0x0838d004 (140
/// bytes; 45 `bl` call sites).
///
/// `sqlite3VdbeSetColName`: record `z_name` as result column `idx`'s
/// name (`var` 0) or declared type (`var` 1). Returns `SQLITE_OK`, or
/// `SQLITE_NOMEM` when the connection has already failed an allocation
/// or the installer does.
///
/// `n` is both a length and a tag: [`P4_DYNAMIC`] and [`P4_STATIC`]
/// mean "NUL-terminated, do not copy", and [`P4_DYNAMIC`] additionally
/// hands the buffer's ownership to the `Mem`. Any other value is a
/// byte count and the name is copied.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vdbe_set_col_name(
    p: *mut Vdbe,
    idx: i32,
    var: i32,
    z_name: *mut u8,
    n: i32,
) -> i32 {
    if *(*p).db.add(MALLOC_FAILED_OFFSET) != 0 {
        return SQLITE_NOMEM;
    }

    let col: *mut Mem = (*p).a_col_name.offset((idx + var * (*p).n_res_column) as isize);

    let (len, x_del) = if n == P4_DYNAMIC || n == P4_STATIC {
        (MEASURE_IN_PLACE, SQLITE_STATIC)
    } else {
        (n, SQLITE_TRANSIENT)
    };
    let rc = (vdbe_mem_set_str_op())(col as *mut u8, z_name, len, SQLITE_UTF8, x_del);

    // A P4_DYNAMIC name arrived as an owned sqlite3_malloc buffer, but
    // was just installed as MEM_Static. Retake ownership so the Mem
    // frees it: drop the flag and point zMalloc at the same bytes.
    if rc == SQLITE_OK && n == P4_DYNAMIC {
        (*col).flags &= !MEM_STATIC;
        (*col).z_malloc = (*col).z;
    }
    rc
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::super::value_set_str::SQLITE_VDBE_MEM_SET_STR;
    use super::*;
    use core::mem::MaybeUninit;
    use std::vec::Vec;

    /// One forwarded `sqlite3VdbeMemSetStr` call, in the callee's
    /// argument order.
    type Forward = (*mut u8, *mut u8, i32, u8, *mut u8);

    static mut CALL_LOG: Vec<Forward> = Vec::new();
    /// Result the stand-in installer returns.
    static mut CALLEE_RESULT: i32 = SQLITE_OK;
    /// `flags` the stand-in installer leaves behind (the real callee
    /// always writes this field).
    static mut CALLEE_FLAGS: u16 = 0;
    /// `z` the stand-in installer leaves behind.
    static mut CALLEE_Z: *mut u8 = core::ptr::null_mut();

    /// Stands in for `sqlite3VdbeMemSetStr` @ 0x0838c158: records the
    /// call and writes the two fields the port reads back afterwards.
    unsafe extern "C" fn recording_vdbe_mem_set_str(
        mem: *mut u8,
        z: *mut u8,
        n: i32,
        enc: u8,
        x_del: *mut u8,
    ) -> i32 {
        (*core::ptr::addr_of_mut!(CALL_LOG)).push((mem, z, n, enc, x_del));
        let col = mem as *mut Mem;
        (*col).flags = CALLEE_FLAGS;
        (*col).z = CALLEE_Z;
        (*col).z_malloc = core::ptr::null_mut();
        CALLEE_RESULT
    }

    unsafe fn call_log() -> &'static [Forward] {
        (*core::ptr::addr_of!(CALL_LOG)).as_slice()
    }

    /// Install the stand-in installer for `body`, then restore the
    /// shipped real port.
    unsafe fn with_installer(result: i32, flags: u16, z: *mut u8, body: impl FnOnce()) {
        (*core::ptr::addr_of_mut!(CALL_LOG)).clear();
        CALLEE_RESULT = result;
        CALLEE_FLAGS = flags;
        CALLEE_Z = z;
        core::ptr::write_volatile(
            core::ptr::addr_of_mut!(SQLITE_VDBE_MEM_SET_STR),
            recording_vdbe_mem_set_str,
        );
        body();
        core::ptr::write_volatile(
            core::ptr::addr_of_mut!(SQLITE_VDBE_MEM_SET_STR),
            super::super::vdbe_mem_set_str::vdbe_mem_set_str,
        );
    }

    /// A statement with a real `aColName` array behind it. Host
    /// pointers throughout — the port never narrows one to 32 bits.
    struct Statement {
        db: std::boxed::Box<[u8; 0x40]>,
        cols: Vec<Mem>,
        vdbe: Vdbe,
    }

    impl Statement {
        fn new(n_res_column: i32, malloc_failed: u8) -> Self {
            let mut db = std::boxed::Box::new([0u8; 0x40]);
            db[MALLOC_FAILED_OFFSET] = malloc_failed;
            let mut cols = Vec::new();
            for _ in 0..(n_res_column * super::super::vdbe::COLNAME_N).max(0) {
                cols.push(unsafe { MaybeUninit::<Mem>::zeroed().assume_init() });
            }
            let mut vdbe = unsafe { MaybeUninit::<Vdbe>::zeroed().assume_init() };
            vdbe.db = db.as_mut_ptr();
            vdbe.n_res_column = n_res_column;
            Statement { db, cols, vdbe }
        }

        /// Re-pin `aColName` (the `Vec` and the struct both move after
        /// `new()` returns) and hand out the `Vdbe`.
        fn ptr(&mut self) -> *mut Vdbe {
            self.vdbe.db = self.db.as_mut_ptr();
            self.vdbe.a_col_name = self.cols.as_mut_ptr();
            &mut self.vdbe
        }

        fn col(&self, index: usize) -> &Mem {
            &self.cols[index]
        }
    }

    /// Independent reference model of the original's argument choice:
    /// the two P4 tags mean "NUL-terminated, borrowed", everything else
    /// is an explicit length that must be copied.
    fn reference_install(n: i32) -> (i32, *mut u8) {
        if n == -1 || n == -2 {
            (-1, core::ptr::null_mut())
        } else {
            (n, usize::MAX as *mut u8)
        }
    }

    #[test]
    fn a_failed_connection_is_refused_before_the_array_is_touched() {
        let mut stmt = Statement::new(3, 1);
        unsafe {
            with_installer(SQLITE_OK, 0, core::ptr::null_mut(), || {
                let rc = vdbe_set_col_name(stmt.ptr(), 0, 0, b"rowid\0".as_ptr() as *mut u8, -1);
                assert_eq!(rc, SQLITE_NOMEM, "mallocFailed short-circuits with 7");
                assert!(call_log().is_empty(), "the installer is never reached");
            });
        }
    }

    #[test]
    fn any_nonzero_malloc_failed_byte_counts_as_failed() {
        // The original tests the byte, not the value 1 (`ldrb` +
        // `cmp #0`), so every non-zero pattern must refuse.
        for flag in [1u8, 2, 0x7f, 0x80, 0xff] {
            let mut stmt = Statement::new(1, flag);
            unsafe {
                with_installer(SQLITE_OK, 0, core::ptr::null_mut(), || {
                    let rc = vdbe_set_col_name(stmt.ptr(), 0, 0, b"a\0".as_ptr() as *mut u8, -1);
                    assert_eq!(rc, SQLITE_NOMEM, "mallocFailed = {flag:#x}");
                });
            }
        }
    }

    #[test]
    fn the_element_is_indexed_by_idx_plus_var_times_n_res_column() {
        let n_res_column = 4;
        let z = b"name\0".as_ptr() as *mut u8;
        for var in 0..super::super::vdbe::COLNAME_N {
            for idx in 0..n_res_column {
                let mut stmt = Statement::new(n_res_column, 0);
                let expected = (idx + var * n_res_column) as usize;
                let base = stmt.cols.as_ptr();
                unsafe {
                    with_installer(SQLITE_OK, 0, core::ptr::null_mut(), || {
                        let rc = vdbe_set_col_name(stmt.ptr(), idx, var, z, -1);
                        assert_eq!(rc, SQLITE_OK);
                        assert_eq!(call_log().len(), 1, "idx={idx} var={var}");
                        assert_eq!(
                            call_log()[0].0 as usize,
                            base.add(expected) as usize,
                            "idx={idx} var={var}: element idx + var*nResColumn",
                        );
                    });
                }
            }
        }
    }

    #[test]
    fn the_tag_values_borrow_and_every_other_length_copies() {
        let z = b"declared type\0".as_ptr() as *mut u8;
        // The boundary the original draws with `cmn r5,#1` /
        // `cmnne r5,#2`: -1 and -2 borrow, -3 and 0 and positives copy.
        for n in [P4_DYNAMIC, P4_STATIC, -3, 0, 1, 13, i32::MAX, i32::MIN] {
            let mut stmt = Statement::new(2, 0);
            let base = stmt.cols.as_ptr();
            unsafe {
                with_installer(SQLITE_OK, 0, core::ptr::null_mut(), || {
                    let rc = vdbe_set_col_name(stmt.ptr(), 1, 0, z, n);
                    assert_eq!(rc, SQLITE_OK, "n={n}");
                    let (len, x_del) = reference_install(n);
                    assert_eq!(
                        call_log(),
                        &[(base.add(1) as *mut u8, z, len, SQLITE_UTF8, x_del)],
                        "n={n}: (mem, z, n, SQLITE_UTF8, xDel)",
                    );
                });
            }
        }
    }

    #[test]
    fn a_dynamic_name_is_retaken_from_static_into_z_malloc() {
        let owned = b"artist\0".as_ptr() as *mut u8;
        // MEM_Str | MEM_Term | MEM_Static, as the installer leaves it.
        let installed: u16 = 0x0002 | 0x0020 | MEM_STATIC;
        let mut stmt = Statement::new(1, 0);
        unsafe {
            with_installer(SQLITE_OK, installed, owned, || {
                let rc = vdbe_set_col_name(stmt.ptr(), 0, 0, owned, P4_DYNAMIC);
                assert_eq!(rc, SQLITE_OK);
            });
        }
        assert_eq!(
            stmt.col(0).flags,
            installed & !MEM_STATIC,
            "MEM_Static cleared, every other bit kept",
        );
        assert_eq!(stmt.col(0).z_malloc, owned, "zMalloc takes over z");
        assert_eq!(stmt.col(0).z, owned, "z itself is untouched");
    }

    #[test]
    fn no_other_tag_or_length_retakes_ownership() {
        let z = b"album\0".as_ptr() as *mut u8;
        let installed: u16 = 0x0002 | MEM_STATIC;
        // P4_STATIC borrows exactly like P4_DYNAMIC but must NOT be
        // retaken — the original's second test is `cmneq r5,#1` alone.
        for n in [P4_STATIC, -3, 0, 5] {
            let mut stmt = Statement::new(1, 0);
            unsafe {
                with_installer(SQLITE_OK, installed, z, || {
                    assert_eq!(vdbe_set_col_name(stmt.ptr(), 0, 0, z, n), SQLITE_OK);
                });
            }
            assert_eq!(stmt.col(0).flags, installed, "n={n}: flags untouched");
            assert!(stmt.col(0).z_malloc.is_null(), "n={n}: zMalloc untouched");
        }
    }

    #[test]
    fn a_failing_installer_reports_nomem_and_never_retakes() {
        let z = b"title\0".as_ptr() as *mut u8;
        let installed: u16 = MEM_STATIC;
        let mut stmt = Statement::new(1, 0);
        unsafe {
            with_installer(SQLITE_NOMEM, installed, z, || {
                let rc = vdbe_set_col_name(stmt.ptr(), 0, 0, z, P4_DYNAMIC);
                assert_eq!(rc, SQLITE_NOMEM, "the installer's code is returned as-is");
            });
        }
        assert_eq!(stmt.col(0).flags, installed, "no retake on failure");
        assert!(stmt.col(0).z_malloc.is_null(), "no retake on failure");
    }

    #[test]
    fn a_null_name_is_forwarded_untouched() {
        // The original validates nothing but mallocFailed; a NULL name
        // reaches the installer, which turns it into MemSetNull.
        let mut stmt = Statement::new(1, 0);
        let base = stmt.cols.as_ptr();
        unsafe {
            with_installer(SQLITE_OK, 0, core::ptr::null_mut(), || {
                let rc = vdbe_set_col_name(stmt.ptr(), 0, 1, core::ptr::null_mut(), P4_DYNAMIC);
                assert_eq!(rc, SQLITE_OK);
                assert_eq!(
                    call_log(),
                    &[(
                        base.add(1) as *mut u8,
                        core::ptr::null_mut(),
                        MEASURE_IN_PLACE,
                        SQLITE_UTF8,
                        SQLITE_STATIC,
                    )],
                    "plane 1 of a one-column statement, NULL forwarded",
                );
            });
        }
    }

    #[test]
    fn the_callee_seam_ships_the_real_port() {
        unsafe {
            assert_eq!(
                vdbe_mem_set_str_op() as usize,
                super::super::vdbe_mem_set_str::vdbe_mem_set_str as usize,
                "the shared seam ships the 0x0838c158 port",
            );
        }
    }
}
