//! VDBE value-to-INTEGER projection — `sqlite3VdbeIntValue` from the
//! retailOS SQLite 3.5.x cluster.
//!
//! ## Original and extent
//!
//! `FUN_0838b5c4` at load address **0x0838b5c4** is 128 bytes:
//! 0x0838b5c4..0x0838b644, confirmed from the following function's `stmdb`
//! at 0x0838b644; it has no literal pool. Decoding every ARM branch word in
//! `osos.dec` found **13 unconditional `bl` call sites** (0x083653f4,
//! 0x08368280, 0x08387b7c, 0x08387b8c, 0x08387fc8, 0x08387ff8, 0x08389064,
//! 0x0838a250, 0x0838a380, 0x0838bf58, 0x0838fa80, 0x08392730, and
//! 0x08392758), plus two unconditional tail `b` entries at 0x08391778 and
//! 0x0839177c. There are no predicated calls.
//!
//! ## Algorithm
//!
//! The helper samples `Mem.flags` once. `MEM_Int` returns the signed 64-bit
//! integer union arm; otherwise `MEM_Real` passes the floating arm to the
//! retail conversion helper. A `MEM_Str` or `MEM_Blob` value gains `MEM_Str`,
//! is recoded to UTF-8, double-NUL-terminated, and parsed as a signed 64-bit
//! decimal. A recode or terminator error, or every other storage class,
//! returns zero. The parser's status is deliberately ignored.
//!
//! ## Deliberate deviations
//!
//! `FUN_082c67f4` (the observed `f64 -> i64` ABI) and `sqlite3Atoi64` at
//! 0x0836f82c remain unported and use the local volatile dispatch seam.
//! Target defaults branch to their retailOS load addresses; host tests install
//! recorders. `sqlite3VdbeChangeEncoding` at 0x083869f4 is likewise
//! unported. `sqlite3VdbeMemNulTerminate` at 0x0838bfb0 is already ported,
//! so this function calls it directly rather than re-stubbing it. Named
//! `Mem` fields replace the original's +0x00/+0x08/+0x14/+0x1c accesses.

use super::error::SQLITE_UTF8;
use super::value_text::VdbeChangeEncodingFn;
use super::vdbe::Mem;
use super::vdbe_mem_nul_terminate::vdbe_mem_nul_terminate;
use super::vdbe_mem_realify::{MEM_REAL, SQLITE_OK};
use super::vdbe_mem_set_int64::MEM_INT;
use super::vdbe_mem_set_str::{MEM_BLOB, MEM_STR};

/// `FUN_082c67f4`: convert a binary64 value to the signed 64-bit integer ABI
/// returned by the integer-value helper.
pub type F64ToI64 = unsafe extern "C" fn(value: f64) -> i64;

/// `sqlite3Atoi64(z, out)` @ 0x0836f82c: parse a NUL-terminated UTF-8 decimal
/// into `out`. The caller observes its output but deliberately ignores status.
pub type SqliteAtoi64 = unsafe extern "C" fn(z: *const u8, out: *mut i64) -> i32;

/// RetailOS load address of the floating-to-integer conversion helper.
pub const F64_TO_I64_ADDRESS: usize = 0x082c_67f4;
/// RetailOS load address of `sqlite3VdbeChangeEncoding`.
pub const VDBE_CHANGE_ENCODING_ADDRESS: usize = 0x0838_69f4;
/// RetailOS load address of `sqlite3Atoi64`.
pub const SQLITE_ATOI64_ADDRESS: usize = 0x0836_f82c;

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_f64_to_i64(value: f64) -> i64 {
    let convert: F64ToI64 = core::mem::transmute(F64_TO_I64_ADDRESS);
    convert(value)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_f64_to_i64(_value: f64) -> i64 {
    panic!("vdbe_int_value requires FUN_082c67f4")
}

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_vdbe_change_encoding(p_mem: *mut u8, desired_enc: u8) -> i32 {
    let change_encoding: VdbeChangeEncodingFn = core::mem::transmute(VDBE_CHANGE_ENCODING_ADDRESS);
    change_encoding(p_mem, desired_enc)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_vdbe_change_encoding(_p_mem: *mut u8, _desired_enc: u8) -> i32 {
    panic!("vdbe_int_value requires sqlite3VdbeChangeEncoding @ 0x083869f4")
}

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_sqlite_atoi64(z: *const u8, out: *mut i64) -> i32 {
    let atoi64: SqliteAtoi64 = core::mem::transmute(SQLITE_ATOI64_ADDRESS);
    atoi64(z, out)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_sqlite_atoi64(_z: *const u8, _out: *mut i64) -> i32 {
    panic!("vdbe_int_value requires sqlite3Atoi64 @ 0x0836f82c")
}

/// Indirect dispatch for the three unported leaf helpers this function needs.
/// Host tests replace these slots; target defaults branch to retailOS.
#[derive(Clone, Copy)]
pub struct VdbeIntValueOps {
    /// `FUN_082c67f4(f64)` — binary64 to signed 64-bit conversion.
    pub f64_to_i64: F64ToI64,
    /// `sqlite3VdbeChangeEncoding(pMem, SQLITE_UTF8)` @ 0x083869f4.
    pub change_encoding: VdbeChangeEncodingFn,
    /// `sqlite3Atoi64(pMem->z, &value)` @ 0x0836f82c.
    pub atoi64: SqliteAtoi64,
}

#[cfg(target_os = "none")]
pub const DEFAULT_VDBE_INT_VALUE_OPS: VdbeIntValueOps = VdbeIntValueOps {
    f64_to_i64: retail_f64_to_i64,
    change_encoding: retail_vdbe_change_encoding,
    atoi64: retail_sqlite_atoi64,
};

#[cfg(not(target_os = "none"))]
pub const DEFAULT_VDBE_INT_VALUE_OPS: VdbeIntValueOps = VdbeIntValueOps {
    f64_to_i64: missing_f64_to_i64,
    change_encoding: missing_vdbe_change_encoding,
    atoi64: missing_sqlite_atoi64,
};

/// Active unported-helper dispatch. Volatile reads preserve target calls and
/// make host test replacements observable.
pub static mut VDBE_INT_VALUE_OPS: VdbeIntValueOps = DEFAULT_VDBE_INT_VALUE_OPS;

#[inline(always)]
unsafe fn f64_to_i64_op() -> F64ToI64 {
    core::ptr::read_volatile(core::ptr::addr_of!(VDBE_INT_VALUE_OPS.f64_to_i64))
}

#[inline(always)]
unsafe fn change_encoding_op() -> VdbeChangeEncodingFn {
    core::ptr::read_volatile(core::ptr::addr_of!(VDBE_INT_VALUE_OPS.change_encoding))
}

#[inline(always)]
unsafe fn atoi64_op() -> SqliteAtoi64 {
    core::ptr::read_volatile(core::ptr::addr_of!(VDBE_INT_VALUE_OPS.atoi64))
}

/// vdbe_int_value — original: `FUN_0838b5c4` @ 0x0838b5c4 (128 bytes;
/// 13 `bl` call sites and two tail branches).
///
/// `sqlite3VdbeIntValue`: project `p_mem` as an `i64` without changing its
/// storage class except that a text/blob value gains `MEM_Str` before
/// recoding. `MEM_Int` wins over all lower-priority type flags; `MEM_Real`
/// comes next; a recode or NUL-termination failure returns zero before the
/// parser runs; `sqlite3Atoi64`'s status is ignored exactly as in retailOS.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vdbe_int_value(p_mem: *mut Mem) -> i64 {
    let flags = (*p_mem).flags;
    if flags & MEM_INT != 0 {
        return (*p_mem).u as i64;
    }
    if flags & MEM_REAL != 0 {
        return (f64_to_i64_op())((*p_mem).r);
    }
    if flags & (MEM_STR | MEM_BLOB) != 0 {
        (*p_mem).flags = flags | MEM_STR;
        if (change_encoding_op())(p_mem.cast(), SQLITE_UTF8) == SQLITE_OK
            && vdbe_mem_nul_terminate(p_mem) == SQLITE_OK
        {
            let mut value = 0;
            (atoi64_op())((*p_mem).z, &mut value);
            return value;
        }
    }
    0
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use super::super::vdbe_mem_set_str::MEM_TERM;
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    static OPS_LOCK: Mutex<()> = Mutex::new(());

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Event {
        Convert(u64),
        ChangeEncoding(usize, u8),
        Atoi64(usize),
    }

    static mut EVENTS: Vec<Event> = Vec::new();
    static mut CHANGE_ENCODING_RESULT: i32 = SQLITE_OK;
    static mut ATOI64_RESULT: i64 = 0;
    static mut CONVERTED_RESULT: i64 = 0;

    unsafe extern "C" fn recording_f64_to_i64(value: f64) -> i64 {
        (*core::ptr::addr_of_mut!(EVENTS)).push(Event::Convert(value.to_bits()));
        *core::ptr::addr_of!(CONVERTED_RESULT)
    }

    unsafe extern "C" fn recording_change_encoding(p_mem: *mut u8, enc: u8) -> i32 {
        (*core::ptr::addr_of_mut!(EVENTS)).push(Event::ChangeEncoding(p_mem as usize, enc));
        *core::ptr::addr_of!(CHANGE_ENCODING_RESULT)
    }

    unsafe extern "C" fn recording_atoi64(z: *const u8, out: *mut i64) -> i32 {
        (*core::ptr::addr_of_mut!(EVENTS)).push(Event::Atoi64(z as usize));
        out.write(*core::ptr::addr_of!(ATOI64_RESULT));
        -1
    }

    fn bench() -> MutexGuard<'static, ()> {
        let guard = OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            (*core::ptr::addr_of_mut!(EVENTS)).clear();
            *core::ptr::addr_of_mut!(CHANGE_ENCODING_RESULT) = SQLITE_OK;
            *core::ptr::addr_of_mut!(ATOI64_RESULT) = 0;
            *core::ptr::addr_of_mut!(CONVERTED_RESULT) = 0;
            core::ptr::write_volatile(
                core::ptr::addr_of_mut!(VDBE_INT_VALUE_OPS),
                VdbeIntValueOps {
                    f64_to_i64: recording_f64_to_i64,
                    change_encoding: recording_change_encoding,
                    atoi64: recording_atoi64,
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
    fn integer_arm_has_precedence_and_preserves_the_signed_bits() {
        let _guard = bench();
        for integer in [i64::MIN, -1, 0, 1, i64::MAX] {
            let mut value = mem(MEM_INT | MEM_REAL | MEM_STR | MEM_BLOB);
            value.u = integer as u64;
            value.r = 13.5;

            assert_eq!(unsafe { vdbe_int_value(&mut value) }, integer);
            assert_eq!(value.flags, MEM_INT | MEM_REAL | MEM_STR | MEM_BLOB);
        }
        assert!(events().is_empty());
    }

    #[test]
    fn real_arm_uses_the_retail_conversion_abi() {
        let _guard = bench();
        let mut value = mem(MEM_REAL);
        value.r = f64::from_bits(0x7ff8_0000_5a5a_5a5a);
        unsafe { *core::ptr::addr_of_mut!(CONVERTED_RESULT) = i64::MIN; }

        assert_eq!(unsafe { vdbe_int_value(&mut value) }, i64::MIN);
        assert_eq!(events(), std::vec![Event::Convert(value.r.to_bits())]);
    }

    #[test]
    fn text_and_blob_are_recoded_terminated_then_parsed() {
        let _guard = bench();
        let mut text = *b"-42\0\0";
        let mut value = mem(MEM_BLOB | MEM_TERM | 0x0040);
        value.z = text.as_mut_ptr();
        unsafe { *core::ptr::addr_of_mut!(ATOI64_RESULT) = -42; }

        assert_eq!(unsafe { vdbe_int_value(&mut value) }, -42);
        assert_eq!(value.flags, MEM_BLOB | MEM_STR | MEM_TERM | 0x0040);
        assert_eq!(
            events(),
            std::vec![
                Event::ChangeEncoding((&mut value as *mut Mem) as usize, SQLITE_UTF8),
                Event::Atoi64(text.as_ptr() as usize),
            ],
        );
    }

    #[test]
    fn recode_error_skips_termination_and_the_parser() {
        let _guard = bench();
        let mut value = mem(MEM_STR | MEM_TERM);
        unsafe { *core::ptr::addr_of_mut!(CHANGE_ENCODING_RESULT) = 7; }

        assert_eq!(unsafe { vdbe_int_value(&mut value) }, 0);
        assert_eq!(value.flags, MEM_STR | MEM_TERM);
        assert_eq!(
            events(),
            std::vec![Event::ChangeEncoding(
                (&mut value as *mut Mem) as usize,
                SQLITE_UTF8,
            )],
        );
    }

    #[test]
    fn non_numeric_non_text_values_return_zero_without_side_effects() {
        let _guard = bench();
        let mut value = mem(0x0421);
        value.u = (-17i64) as u64;
        value.r = 98.5;

        assert_eq!(unsafe { vdbe_int_value(&mut value) }, 0);
        assert_eq!(value.flags, 0x0421);
        assert!(events().is_empty());
    }
}
