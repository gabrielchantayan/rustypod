//! SQLite numeric affinity — `FUN_082b46f8` @ `0x082b46f8`.
//! True extent: 148 bytes, `0x082b46f8..0x082b478c`, no literal pool;
//! the next function begins with `movs r2,r0`. Raw ARM scan: two incoming
//! plain BL sites (0x082b46dc, 0x08391788), zero predicated BL sites;
//! five outgoing plain BL instructions, zero predicated BL instructions.
//!
//! Leave numeric cells alone. NUL-terminate other cells, recognize numeric
//! text in its current encoding, recode it to UTF-8 (ignoring recode status),
//! and parse integer syntax as i64. Fractional/exponent syntax and integer
//! overflow become REAL. Successful integers replace the low five type bits
//! while preserving ownership/termination flags. Non-numeric text is unchanged.
//! Deviations: named repr(C) fields replace target offsets; the incidental
//! restored r0/r1 pair is not a semantic return value (both callers ignore it).
//! The unported numeric recognizer at 0x0837cb60 uses a volatile dispatch seam;
//! existing encoding/atoi64 seams are reused, and ported helpers called directly.

use super::vdbe::Mem;
use super::vdbe_int_value::VDBE_INT_VALUE_OPS;
use super::vdbe_mem_nul_terminate::vdbe_mem_nul_terminate;
use super::vdbe_mem_realify::vdbe_mem_realify;

/// sqlite3IsNumber(z, real, enc): recognizes signed decimal syntax, reporting
/// whether a decimal point or exponent occurs. Raw callee walks bytes at stride
/// 1 for UTF-8, 2 for UTF-16, with a one-byte start bias for UTF-16BE.
pub type IsNumber = unsafe extern "C" fn(*const u8, *mut i32, u8) -> i32;

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_is_number(z: *const u8, real: *mut i32, enc: u8) -> i32 {
    let f: IsNumber = core::mem::transmute(0x0837_cb60usize);
    f(z, real, enc)
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_is_number(_: *const u8, _: *mut i32, _: u8) -> i32 {
    panic!("numeric affinity requires sqlite3IsNumber @ 0x0837cb60")
}
#[cfg(target_os = "none")]
pub static mut IS_NUMBER_OP: IsNumber = retail_is_number;
#[cfg(not(target_os = "none"))]
pub static mut IS_NUMBER_OP: IsNumber = missing_is_number;

/// Apply numeric affinity without releasing the text representation's storage.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vdbe_mem_apply_numeric_affinity(p_mem: *mut Mem) {
    if (*p_mem).flags & 0x0c != 0 { return; }
    vdbe_mem_nul_terminate(p_mem);
    if (*p_mem).flags & 2 == 0 { return; }
    let recognize = core::ptr::read_volatile(core::ptr::addr_of!(IS_NUMBER_OP));
    let mut real = 0;
    if recognize((*p_mem).z, &mut real, (*p_mem).enc) == 0 { return; }
    let recode = core::ptr::read_volatile(core::ptr::addr_of!(VDBE_INT_VALUE_OPS.change_encoding));
    recode(p_mem.cast(), 1);
    if real == 0 {
        let parse = core::ptr::read_volatile(core::ptr::addr_of!(VDBE_INT_VALUE_OPS.atoi64));
        let mut value = 0;
        if parse((*p_mem).z, &mut value) != 0 {
            (*p_mem).u = value as u64;
            (*p_mem).flags = ((*p_mem).flags & !0x1f) | 4;
            return;
        }
    }
    vdbe_mem_realify(p_mem);
}

#[cfg(test)]
mod tests {
    use super::*;

    // These paths never dispatch, so they are isolated from other seam tests.
    #[test]
    fn numeric_precedence_and_non_string_storage_are_preserved() {
        for flags in [4u16, 8, 12, 0x26, 0x128, 0x21, 0x30, 0x20] {
            let mut cell: Mem = unsafe { core::mem::zeroed() };
            cell.u = i64::MIN as u64;
            cell.r = -1.25;
            cell.flags = flags;
            cell.enc = 3;
            cell.value_type = 5;
            unsafe { vdbe_mem_apply_numeric_affinity(&mut cell); }
            assert_eq!(cell.flags, flags);

            assert_eq!(cell.u, i64::MIN as u64);
            assert_eq!(cell.r, -1.25);
            assert_eq!((cell.enc, cell.value_type), (3, 5));
        }
    }
    unsafe extern "C" fn recognize(z: *const u8, real: *mut i32, enc: u8) -> i32 {
        assert_eq!(enc, 3);
        *real = 0;
        (*z != b'x') as i32
    }
    unsafe extern "C" fn recode(cell: *mut u8, enc: u8) -> i32 {
        assert_eq!(enc, 1);
        (*(cell as *mut Mem)).enc = 1;
        7 // Failure is deliberately ignored by the original.
    }
    unsafe extern "C" fn parse(_: *const u8, value: *mut i64) -> i32 {
        *value = i64::MIN;
        1
    }

    #[test]
    fn integer_commit_and_rejected_syntax_preserve_non_type_fields() {
        let _lock = super::super::vdbe_int_value::tests::OPS_LOCK.lock()
            .unwrap_or_else(|error| error.into_inner());
        struct Restore(super::super::vdbe_int_value::VdbeIntValueOps, IsNumber);
        impl Drop for Restore {
            fn drop(&mut self) {
                unsafe { VDBE_INT_VALUE_OPS = self.0; IS_NUMBER_OP = self.1; }
            }
        }
        unsafe {
            let _restore = Restore(VDBE_INT_VALUE_OPS, IS_NUMBER_OP);
            VDBE_INT_VALUE_OPS.change_encoding = recode;
            VDBE_INT_VALUE_OPS.atoi64 = parse;
            IS_NUMBER_OP = recognize;
            for (text, accepted) in [(b'-', true), (b'x', false)] {
                let mut bytes = [text, 0, 0];
                let mut cell: Mem = core::mem::zeroed();
                cell.z = bytes.as_mut_ptr();
                cell.flags = 0xa2; // static, terminated string
                cell.enc = 3;
                cell.u = 99;
                cell.r = 4.5;
                cell.n = 1;
                cell.value_type = 3;
                vdbe_mem_apply_numeric_affinity(&mut cell);
                assert_eq!(cell.u, if accepted { i64::MIN as u64 } else { 99 });
                assert_eq!(cell.flags, if accepted { 0xa4 } else { 0xa2 });
                assert_eq!(cell.enc, if accepted { 1 } else { 3 });
                assert_eq!(cell.z, bytes.as_mut_ptr());
                assert_eq!((cell.r, cell.n, cell.value_type), (4.5, 1, 3));
            }
        }
    }
}
