//! The string installer — how the engine puts text (or a blob) into a
//! `Mem`/`sqlite3_value` it already owns.
//!
//! - `sqlite_value_set_str` — original: `FUN_083866ec` @ 0x083866ec
//!   (44 bytes; 7 `bl` call sites, binary-scanned). Upstream SQLite
//!   3.5.9's `sqlite3ValueSetStr` (`void sqlite3ValueSetStr(
//!   sqlite3_value *v, int n, const void *z, u8 enc,
//!   void (*xDel)(void *))` in vdbemem.c). `sqlite3ValueText` @
//!   0x08386718 follows it immediately.
//!
//! Algorithm: a pure register-shuffle wrapper with a NULL guard. The
//! outgoing argument registers are rebuilt for the callee
//! (`mov r12,r1 / mov r1,r2 / mov r2,r3`), the fifth argument `xDel`
//! is pulled from the caller's stack into the outgoing stack slot
//! (`ldr r3,[sp,#0x8]` / `strne r3,[sp,#0x0]`), and only when `value`
//! is non-NULL does control reach `sqlite3VdbeMemSetStr` @ 0x0838c158
//! with `(value, z, n, enc, xDel)` — the wrapper's `n` and `z` are
//! swapped into the callee's order. A NULL `value` skips the call
//! entirely; nothing else is validated (a NULL `z` with a live `value`
//! is forwarded — the callee turns that into `MemSetNull`). The
//! wrapper has no epilogue write to r0, so the callee's return code
//! (`SQLITE_OK` = 0 / `SQLITE_NOMEM` = 7) leaks out in r0 — and the
//! NULL path leaks the 0 left by `cmp r0,#0`, which is `SQLITE_OK`
//! anyway. No caller reads it; the decompiler types the wrapper `void`
//! and so does this port.
//!
//! The callee (unported, seam-modeled below) is upstream
//! `sqlite3VdbeMemSetStr`: a NULL `z` routes to `MemSetNull` @
//! 0x0838c13c; otherwise base flags are `MEM_Str` (0x2), or `MEM_Blob`
//! (0x10) when `enc` is 0. `n < 0` measures `z` in place — a NUL scan
//! for UTF-8, a double-NUL scan in two-byte steps otherwise — and sets
//! `MEM_Term` (0x20). `xDel == (void *)-1` (`SQLITE_TRANSIENT`) grows
//! the `Mem` (0x0838bdb0) and copies; anything else releases the old
//! content (0x0838c04c) and marks `MEM_Static` (0x80, `xDel` NULL) or
//! `MEM_Dyn` (0x40), storing `xDel` at +0x20 and `z` at +0x14. Finally
//! `n` lands at +0x18, a zero `enc` becomes 1, flags/enc/type
//! (`SQLITE_TEXT` = 3 / `SQLITE_BLOB` = 4) land at +0x1c/+0x1f/+0x1e,
//! and non-UTF-8 encodings are recoded/NUL-terminated through
//! 0x0838be98, with any allocation failure returning `SQLITE_NOMEM`.
//!
//! Call sites (binary-scanned):
//!
//! - 0x082bea7c — FUN_082be9e8 (the user-function result bridge):
//!   `(value_new(db), n=param_3, z=param_2, enc=1, xDel=0)` —
//!   `SQLITE_STATIC`.
//! - 0x0837676c — [`sqlite_error`](super::error::sqlite_error) (ported,
//!   `sqlite/error.rs`): the connection's cached `pErr`.
//! - 0x083865a8 — FUN_08386524 (message formatter): `n=-1`, `enc=1`,
//!   `xDel` = pool literal 0x0838581c (the firmware's `sqlite3_free`
//!   position, see `sqlite/error.rs::SQLITE_FREE_X_DEL`).
//! - 0x0838cb68 and 0x0838cbc8 — FUN_0838cb28: `n=-1`, `enc=1`, same
//!   0x0838581c destructor literal.
//! - 0x0838fec4 — FUN_0838fe88: `n=-1`, caller-chosen `enc`, `xDel=0`.
//! - 0x08390318 — FUN_08390294: `n=-1`, `enc=1`, `xDel=0`.
//!
//! Deviations:
//! - `sqlite3VdbeMemSetStr` @ 0x0838c158 is not ported: the call goes
//!   through the [`SQLITE_VDBE_MEM_SET_STR`] dispatch static whose
//!   default slot is a documented `SQLITE_NOMEM`-shaped stub — the
//!   house seam pattern (`sqlite/error.rs`, `sqlite/error_msg.rs`).
//! - This port is the shipped default of the `SQLITE_VALUE_SET_STR`
//!   dispatch slot in `sqlite/error.rs` (that module's documented
//!   "the real port should replace this default when it lands"
//!   pattern — the same swap this crate made when
//!   [`sqlite_value_new`](super::value_new::sqlite_value_new) landed);
//!   the slot stays so host tests can install recording mocks, and the
//!   old no-op stub is retained there for them.

/// `sqlite3VdbeMemSetStr(mem, z, n, enc, xDel)` @ 0x0838c158: install
/// string/blob `z` into `mem`, returning `SQLITE_OK` (0) or
/// `SQLITE_NOMEM` (7). Note the callee's argument order — `z` before
/// `n` — which is what the wrapper's register shuffle produces.
pub type VdbeMemSetStrFn =
    unsafe extern "C" fn(mem: *mut u8, z: *mut u8, n: i32, enc: u8, x_del: *mut u8) -> i32;

/// The original's `SQLITE_NOMEM` return (`mov r0,#0x7` in the callee's
/// failure paths), the shape of this dispatch stub's default.
pub const SQLITE_NOMEM: i32 = 7;

/// The `SQLITE_NOMEM`-shaped default for an unported
/// `sqlite3VdbeMemSetStr`. The wrapper discards the code, so with this
/// default a call is observably a no-op that claims OOM — the same
/// end state the original reaches when the callee's allocation fails.
pub(crate) unsafe extern "C" fn missing_vdbe_mem_set_str(
    _mem: *mut u8,
    _z: *mut u8,
    _n: i32,
    _enc: u8,
    _x_del: *mut u8,
) -> i32 {
    SQLITE_NOMEM
}

/// Active `sqlite3VdbeMemSetStr` dispatch slot. Host tests install a
/// recording replacement; the real port should replace this default
/// when it lands.
pub static mut SQLITE_VDBE_MEM_SET_STR: VdbeMemSetStrFn = missing_vdbe_mem_set_str;

/// Read the mem-set-string slot volatile so its default remains
/// replaceable.
#[inline(always)]
pub(crate) unsafe fn vdbe_mem_set_str_op() -> VdbeMemSetStrFn {
    core::ptr::read_volatile(core::ptr::addr_of!(SQLITE_VDBE_MEM_SET_STR))
}

/// sqlite_value_set_str — original: `FUN_083866ec` @ 0x083866ec (44
/// bytes; 7 `bl` call sites).
///
/// `sqlite3ValueSetStr`: install `z` (length `n`, encoding `enc`,
/// destructor `x_del`) into `value`. A NULL `value` is ignored;
/// anything else is forwarded to `sqlite3VdbeMemSetStr` as
/// `(value, z, n, enc, x_del)` — `n` and `z` swapped.
///
/// Register usage: r0 = value, r1 = n, r2 = z, r3 = enc, stack = x_del
/// (the original shuffles r1/r2/r3 through r12 and re-homes the stack
/// argument; here the call convention does both).
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn sqlite_value_set_str(
    value: *mut u8,
    n: i32,
    z: *mut u8,
    enc: u8,
    x_del: *mut u8,
) {
    if !value.is_null() {
        (vdbe_mem_set_str_op())(value, z, n, enc, x_del);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;

    /// The callee's forwarded arguments, in the callee's order.
    type Forward = (*mut u8, *mut u8, i32, u8, *mut u8);

    static mut CALL_LOG: Vec<Forward> = Vec::new();
    static mut CALLEE_RESULT: i32 = 0;

    unsafe extern "C" fn recording_vdbe_mem_set_str(
        mem: *mut u8,
        z: *mut u8,
        n: i32,
        enc: u8,
        x_del: *mut u8,
    ) -> i32 {
        (*core::ptr::addr_of_mut!(CALL_LOG)).push((mem, z, n, enc, x_del));
        CALLEE_RESULT
    }

    unsafe fn call_log() -> &'static [Forward] {
        (*core::ptr::addr_of!(CALL_LOG)).as_slice()
    }

    /// Install the recording seam for `body`, then restore the shipped
    /// `SQLITE_NOMEM`-shaped default (the `sqlite/error.rs` convention).
    unsafe fn with_recorder(result: i32, body: impl FnOnce()) {
        (*core::ptr::addr_of_mut!(CALL_LOG)).clear();
        CALLEE_RESULT = result;
        core::ptr::write_volatile(
            core::ptr::addr_of_mut!(SQLITE_VDBE_MEM_SET_STR),
            recording_vdbe_mem_set_str,
        );
        body();
        core::ptr::write_volatile(
            core::ptr::addr_of_mut!(SQLITE_VDBE_MEM_SET_STR),
            missing_vdbe_mem_set_str,
        );
    }

    /// Independent reference model of the original: NULL value drops
    /// the call; otherwise forward `(value, z, n, enc, x_del)` — the
    /// wrapper's `n`/`z` swapped into the callee's order.
    fn reference_forward(
        value: *mut u8,
        n: i32,
        z: *mut u8,
        enc: u8,
        x_del: *mut u8,
    ) -> Option<Forward> {
        if value.is_null() {
            None
        } else {
            Some((value, z, n, enc, x_del))
        }
    }

    /// The firmware's `sqlite3_free`-position destructor literal (see
    /// `sqlite/error.rs::SQLITE_FREE_X_DEL`).
    const FIRMWARE_X_DEL: *mut u8 = 0x0838_581cusize as *mut u8;

    /// `SQLITE_TRANSIENT` — upstream's `(void *)-1`.
    const SQLITE_TRANSIENT: *mut u8 = !0usize as *mut u8;

    #[test]
    fn a_null_value_never_reaches_the_callee() {
        let z = b"media\0".as_ptr() as *mut u8;
        for (n, z_arg, enc, x_del) in [
            (-1, z, 1, FIRMWARE_X_DEL),
            (5, z, 1, SQLITE_TRANSIENT),
            (0, core::ptr::null_mut(), 1, core::ptr::null_mut()),
            (12, z, 0, core::ptr::null_mut()),
            (i32::MAX, z, 3, FIRMWARE_X_DEL),
        ] {
            unsafe {
                with_recorder(0, || {
                    sqlite_value_set_str(core::ptr::null_mut(), n, z_arg, enc, x_del);
                    assert!(
                        call_log().is_empty(),
                        "n={n} enc={enc}: a NULL value must skip the callee",
                    );
                });
            }
        }
    }

    #[test]
    fn arguments_are_forwarded_with_n_and_z_swapped() {
        let value = 0x2000_4000usize as *mut u8;
        let z = b"database disk image is malformed\0".as_ptr() as *mut u8;
        for (n, z_arg, enc, x_del) in [
            // The observed call-site shapes: length -1 with the
            // firmware destructor, explicit length static, NULL
            // string (the callee's MemSetNull route), blob encoding.
            (-1, z, 1, FIRMWARE_X_DEL),
            (32, z, 1, core::ptr::null_mut()),
            (0, core::ptr::null_mut(), 1, core::ptr::null_mut()),
            (-1, z, 1, SQLITE_TRANSIENT),
            (7, z, 0, core::ptr::null_mut()),
            (3, z, 2, SQLITE_TRANSIENT),
        ] {
            unsafe {
                with_recorder(0, || {
                    sqlite_value_set_str(value, n, z_arg, enc, x_del);
                    let expected = reference_forward(value, n, z_arg, enc, x_del);
                    assert_eq!(
                        call_log(),
                        expected.as_slice(),
                        "n={n} enc={enc}: one call, (value, z, n, enc, xDel) order",
                    );
                });
            }
        }
    }

    #[test]
    fn the_callee_result_is_discarded_whatever_it_is() {
        let value = 0x5000usize as *mut u8;
        let z = b"x\0".as_ptr() as *mut u8;
        for result in [0, SQLITE_NOMEM] {
            unsafe {
                with_recorder(result, || {
                    // Returns () both ways — like the ARM, where the
                    // callee's r0 leaks out but no caller reads it.
                    let _: () = sqlite_value_set_str(value, -1, z, 1, FIRMWARE_X_DEL);
                    assert_eq!(call_log().len(), 1, "result {result}: the call still happened");
                });
            }
        }
    }

    #[test]
    fn the_shipped_error_slot_default_is_this_port() {
        unsafe {
            assert_eq!(
                super::super::error::value_set_str_op() as usize,
                sqlite_value_set_str as usize,
                "sqlite/error.rs's SQLITE_VALUE_SET_STR ships the real port",
            );
            assert_eq!(
                vdbe_mem_set_str_op() as usize,
                missing_vdbe_mem_set_str as usize,
                "the callee seam ships the SQLITE_NOMEM-shaped stub",
            );
        }
    }
}
