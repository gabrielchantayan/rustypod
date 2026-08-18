//! VDBE value-to-REAL projection — how SQLite obtains a `double` from a
//! dynamically typed `Mem`/`sqlite3_value` without replacing its storage
//! class.
//!
//! - `vdbe_real_value` — original: `FUN_0838c7ec` @ 0x0838c7ec (136
//!   bytes, 0x0838c7ec..0x0838c874; **5 `bl` call sites** plus the thunk
//!   at 0x08391774). Upstream SQLite 3.5.9's `sqlite3VdbeRealValue`
//!   (`double sqlite3VdbeRealValue(Mem *pMem)` in vdbe.c), identified by
//!   the exact `MEM_Real` / `MEM_Int` / text-or-blob dispatch and by its
//!   immediate caller [`vdbe_mem_realify`](super::vdbe_mem_realify), which
//!   stores this result in `Mem.r`.
//!
//! ### Extent and algorithm
//!
//! The instruction body ends at 0x0838c870; its 8-byte literal pool at
//! 0x0838c874 is the fallback `0.0`, so the full function extent is 136
//! bytes. It samples `Mem.flags` once for dispatch: an existing `MEM_Real`
//! returns `Mem.r`; otherwise `MEM_Int` reinterprets `Mem.u` as signed
//! `i64` and converts it to `double`. A string or blob gains `MEM_Str`, is
//! recoded to UTF-8, double-NUL-terminated, then parsed through
//! `sqlite3AtoF`; a failed recode or termination returns `0.0` without
//! parsing. Every other storage class, including NULL, returns `0.0`.
//!
//! ### Deviations
//!
//! `sqlite3VdbeChangeEncoding` @ 0x083869f4,
//! `sqlite3VdbeMemNulTerminate` @ 0x0838bfb0, and `sqlite3AtoF` @
//! 0x0836f528 are not ported. They are the [`VDBE_REAL_VALUE_OPS`] seam:
//! target builds branch to the retailOS load addresses, and host tests
//! install recording implementations. Named [`Mem`] fields replace the
//! original's +0x00/+0x08/+0x14/+0x1c offsets; `sqlite/vdbe.rs` asserts
//! those target offsets.

use super::error::SQLITE_UTF8;
use super::value_text::{VdbeChangeEncodingFn, VdbeMemNulTerminateFn};
use super::vdbe::Mem;
use super::vdbe_mem_realify::{MEM_REAL, SQLITE_OK};
use super::vdbe_mem_set_int64::MEM_INT;
use super::vdbe_mem_set_str::{MEM_BLOB, MEM_STR};

/// `sqlite3AtoF(z, out)` @ 0x0836f528: parse the NUL-terminated UTF-8
/// numeric text at `z`, place the `double` in `out`, and return consumed
/// input bytes. This caller deliberately ignores the byte count.
pub type SqliteAtoF = unsafe extern "C" fn(z: *const u8, out: *mut f64) -> i32;

/// RetailOS load address of `sqlite3VdbeChangeEncoding`.
pub const VDBE_CHANGE_ENCODING_ADDRESS: usize = 0x0838_69f4;
/// RetailOS load address of `sqlite3VdbeMemNulTerminate`.
pub const VDBE_MEM_NUL_TERMINATE_ADDRESS: usize = 0x0838_bfb0;
/// RetailOS load address of `sqlite3AtoF`.
pub const SQLITE_ATOF_ADDRESS: usize = 0x0836_f528;

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_vdbe_change_encoding(p_mem: *mut u8, desired_enc: u8) -> i32 {
    let change_encoding: VdbeChangeEncodingFn = core::mem::transmute(VDBE_CHANGE_ENCODING_ADDRESS);
    change_encoding(p_mem, desired_enc)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_vdbe_change_encoding(_p_mem: *mut u8, _desired_enc: u8) -> i32 {
    panic!("vdbe_real_value requires sqlite3VdbeChangeEncoding @ 0x083869f4")
}

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_vdbe_mem_nul_terminate(p_mem: *mut u8) -> i32 {
    let nul_terminate: VdbeMemNulTerminateFn =
        core::mem::transmute(VDBE_MEM_NUL_TERMINATE_ADDRESS);
    nul_terminate(p_mem)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_vdbe_mem_nul_terminate(_p_mem: *mut u8) -> i32 {
    panic!("vdbe_real_value requires sqlite3VdbeMemNulTerminate @ 0x0838bfb0")
}

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_sqlite_atof(z: *const u8, out: *mut f64) -> i32 {
    let atof: SqliteAtoF = core::mem::transmute(SQLITE_ATOF_ADDRESS);
    atof(z, out)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_sqlite_atof(_z: *const u8, _out: *mut f64) -> i32 {
    panic!("vdbe_real_value requires sqlite3AtoF @ 0x0836f528")
}

/// Indirect dispatch for the unported recode, terminator, and decimal
/// parser that the text/blob arm invokes. Host tests replace these slots;
/// target defaults call the retailOS entries directly.
#[derive(Clone, Copy)]
pub struct VdbeRealValueOps {
    /// `sqlite3VdbeChangeEncoding(pMem, SQLITE_UTF8)` @ 0x083869f4.
    pub change_encoding: VdbeChangeEncodingFn,
    /// `sqlite3VdbeMemNulTerminate(pMem)` @ 0x0838bfb0.
    pub nul_terminate: VdbeMemNulTerminateFn,
    /// `sqlite3AtoF(pMem->z, &value)` @ 0x0836f528.
    pub atof: SqliteAtoF,
}

/// Target default: branch to the three remaining retailOS helpers.
#[cfg(target_os = "none")]
pub const DEFAULT_VDBE_REAL_VALUE_OPS: VdbeRealValueOps = VdbeRealValueOps {
    change_encoding: retail_vdbe_change_encoding,
    nul_terminate: retail_vdbe_mem_nul_terminate,
    atof: retail_sqlite_atof,
};

/// Host default: fail loudly until a test supplies the unported helpers.
#[cfg(not(target_os = "none"))]
pub const DEFAULT_VDBE_REAL_VALUE_OPS: VdbeRealValueOps = VdbeRealValueOps {
    change_encoding: missing_vdbe_change_encoding,
    nul_terminate: missing_vdbe_mem_nul_terminate,
    atof: missing_sqlite_atof,
};

/// Active recode/terminator/parser triple. Host tests install recorders.
pub static mut VDBE_REAL_VALUE_OPS: VdbeRealValueOps = DEFAULT_VDBE_REAL_VALUE_OPS;

/// Reads the recode slot volatile so host replacements cannot be folded
/// into the default.
#[inline(always)]
unsafe fn change_encoding_op() -> VdbeChangeEncodingFn {
    core::ptr::read_volatile(core::ptr::addr_of!(VDBE_REAL_VALUE_OPS.change_encoding))
}

/// Reads the termination slot volatile (same pattern).
#[inline(always)]
unsafe fn nul_terminate_op() -> VdbeMemNulTerminateFn {
    core::ptr::read_volatile(core::ptr::addr_of!(VDBE_REAL_VALUE_OPS.nul_terminate))
}

/// Reads the decimal-parser slot volatile (same pattern).
#[inline(always)]
unsafe fn atof_op() -> SqliteAtoF {
    core::ptr::read_volatile(core::ptr::addr_of!(VDBE_REAL_VALUE_OPS.atof))
}

/// vdbe_real_value — original: `FUN_0838c7ec` @ 0x0838c7ec (136 bytes;
/// 5 `bl` call sites plus a thunk).
///
/// `sqlite3VdbeRealValue`: return `p_mem` as a `double`. `MEM_Real` wins
/// over every other type bit and returns `Mem.r`; `MEM_Int` comes next and
/// converts signed `Mem.u`; text/blob cells preserve their existing flags
/// while adding `MEM_Str`, then recode to UTF-8, NUL-terminate, and parse
/// their `z` payload. Recode/termination errors and values with none of
/// those type bits return precisely `0.0`; the parser's consumed-byte
/// result is intentionally ignored.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vdbe_real_value(p_mem: *mut Mem) -> f64 {
    let flags = (*p_mem).flags;
    if flags & MEM_REAL != 0 {
        return (*p_mem).r;
    }
    if flags & MEM_INT != 0 {
        return ((*p_mem).u as i64) as f64;
    }
    if flags & (MEM_STR | MEM_BLOB) != 0 {
        (*p_mem).flags |= MEM_STR;
        if (change_encoding_op())(p_mem.cast(), SQLITE_UTF8) == SQLITE_OK
            && (nul_terminate_op())(p_mem.cast()) == SQLITE_OK
        {
            let mut value = 0.0;
            (atof_op())((*p_mem).z, &mut value);
            return value;
        }
    }
    0.0
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    /// Serializes tests that replace the shared helper dispatch slots.
    static OPS_LOCK: Mutex<()> = Mutex::new(());

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Event {
        ChangeEncoding(usize, u8),
        NulTerminate(usize),
        AtoF(usize),
    }

    static mut EVENTS: Vec<Event> = Vec::new();
    static mut CHANGE_ENCODING_RESULT: i32 = SQLITE_OK;
    static mut NUL_TERMINATE_RESULT: i32 = SQLITE_OK;
    static mut ATOF_RESULT: f64 = 0.0;

    unsafe extern "C" fn recording_change_encoding(p_mem: *mut u8, enc: u8) -> i32 {
        (*core::ptr::addr_of_mut!(EVENTS)).push(Event::ChangeEncoding(p_mem as usize, enc));
        *core::ptr::addr_of!(CHANGE_ENCODING_RESULT)
    }

    unsafe extern "C" fn recording_nul_terminate(p_mem: *mut u8) -> i32 {
        (*core::ptr::addr_of_mut!(EVENTS)).push(Event::NulTerminate(p_mem as usize));
        *core::ptr::addr_of!(NUL_TERMINATE_RESULT)
    }

    unsafe extern "C" fn recording_atof(z: *const u8, out: *mut f64) -> i32 {
        (*core::ptr::addr_of_mut!(EVENTS)).push(Event::AtoF(z as usize));
        out.write(*core::ptr::addr_of!(ATOF_RESULT));
        -1
    }

    fn bench() -> MutexGuard<'static, ()> {
        let guard = OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            (*core::ptr::addr_of_mut!(EVENTS)).clear();
            *core::ptr::addr_of_mut!(CHANGE_ENCODING_RESULT) = SQLITE_OK;
            *core::ptr::addr_of_mut!(NUL_TERMINATE_RESULT) = SQLITE_OK;
            *core::ptr::addr_of_mut!(ATOF_RESULT) = 0.0;
            core::ptr::write_volatile(
                core::ptr::addr_of_mut!(VDBE_REAL_VALUE_OPS),
                VdbeRealValueOps {
                    change_encoding: recording_change_encoding,
                    nul_terminate: recording_nul_terminate,
                    atof: recording_atof,
                },
            );
        }
        guard
    }

    fn events() -> Vec<Event> {
        unsafe { (*core::ptr::addr_of!(EVENTS)).clone() }
    }

    fn mem(flags: u16) -> Mem {
        Mem {
            u: 0,
            r: 0.0,
            db: core::ptr::null_mut(),
            z: core::ptr::null_mut(),
            n: 0,
            flags,
            value_type: 0,
            enc: 0,
            x_del: core::ptr::null_mut(),
            z_malloc: core::ptr::null_mut(),
        }
    }

    #[test]
    fn real_arm_wins_and_does_not_touch_the_helpers() {
        let _guard = bench();
        let mut value = mem(MEM_REAL | MEM_INT | MEM_STR | MEM_BLOB);
        value.r = -123.25;
        value.u = 99;

        assert_eq!(unsafe { vdbe_real_value(&mut value) }, -123.25);
        assert_eq!(value.flags, MEM_REAL | MEM_INT | MEM_STR | MEM_BLOB);
        assert!(events().is_empty());
    }

    #[test]
    fn integer_arm_interprets_the_union_as_signed_i64() {
        let _guard = bench();
        for integer in [i64::MIN, -1, 0, 1, i64::MAX] {
            let mut value = mem(MEM_INT);
            value.u = integer as u64;
            assert_eq!(unsafe { vdbe_real_value(&mut value) }, integer as f64);
        }
        assert!(events().is_empty());
    }

    #[test]
    fn text_and_blob_are_recoded_terminated_then_parsed() {
        let _guard = bench();
        let mut text = *b"12.5\0";
        let mut value = mem(MEM_BLOB | 0x0040);
        value.z = text.as_mut_ptr();
        unsafe { *core::ptr::addr_of_mut!(ATOF_RESULT) = 12.5; }

        assert_eq!(unsafe { vdbe_real_value(&mut value) }, 12.5);
        assert_eq!(value.flags, MEM_BLOB | MEM_STR | 0x0040);
        assert_eq!(
            events(),
            std::vec![
                Event::ChangeEncoding((&mut value as *mut Mem) as usize, SQLITE_UTF8),
                Event::NulTerminate((&mut value as *mut Mem) as usize),
                Event::AtoF(text.as_ptr() as usize),
            ],
        );
    }

    #[test]
    fn conversion_errors_short_circuit_the_parser_but_keep_mem_str() {
        let _guard = bench();
        let mut text = *b"4\0";
        let mut value = mem(MEM_BLOB);
        value.z = text.as_mut_ptr();
        unsafe { *core::ptr::addr_of_mut!(CHANGE_ENCODING_RESULT) = 7; }

        assert_eq!(unsafe { vdbe_real_value(&mut value) }, 0.0);
        assert_eq!(value.flags, MEM_BLOB | MEM_STR);
        assert_eq!(
            events(),
            std::vec![Event::ChangeEncoding(
                (&mut value as *mut Mem) as usize,
                SQLITE_UTF8,
            )],
        );

        unsafe {
            (*core::ptr::addr_of_mut!(EVENTS)).clear();
            *core::ptr::addr_of_mut!(CHANGE_ENCODING_RESULT) = SQLITE_OK;
            *core::ptr::addr_of_mut!(NUL_TERMINATE_RESULT) = 7;
        }
        assert_eq!(unsafe { vdbe_real_value(&mut value) }, 0.0);
        assert_eq!(
            events(),
            std::vec![
                Event::ChangeEncoding((&mut value as *mut Mem) as usize, SQLITE_UTF8),
                Event::NulTerminate((&mut value as *mut Mem) as usize),
            ],
        );
    }

    #[test]
    fn non_numeric_non_text_values_return_zero_without_side_effects() {
        let _guard = bench();
        let mut value = mem(0x0421);
        value.r = 98.5;
        value.u = (-17i64) as u64;

        assert_eq!(unsafe { vdbe_real_value(&mut value) }, 0.0);
        assert_eq!(value.flags, 0x0421);
        assert!(events().is_empty());
    }
}
