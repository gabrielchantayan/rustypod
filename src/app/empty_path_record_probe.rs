//! Initialize a path record and probe its empty path.
//!
//! Original: FUN_0808dac4 @ 0x0808dac4. True extent
//! [0x0808dac4, 0x0808dafc): 52 instruction bytes and a four-byte literal.
//! The next function begins with cmp r0,#0 at 0x0808dafc. Whole-image A32
//! decoding verifies two plain inbound BLs (0x0806e4bc, 0x080a74e8), zero
//! predicated inbound BLs; one plain outbound BL to strcpy, zero predicated
//! outbound BLs, then a tail B to path_exists @ 0x080f4aa8.
//!
//! Clear the leading halfword, copy the empty C string at 0x083e8ba8 into
//! record+2, reload and sign-extend the low flag byte, and return path_exists.
//! Both callers subsequently use this record with the file-open wrapper.
//! Deliberate deviations: a Rust empty-string constant replaces the firmware
//! literal's identity; existing ported callees are called directly. LLVM folds
//! the empty strcpy and known-zero flag reload to stores and a zero argument.
//! Ghidra's extra arguments and inlined tail-target body are not part of this
//! function.

use crate::app::path_exists::path_exists;
use crate::libc::strcpy::strcpy;

/// # Safety
/// `record` must be halfword-aligned and writable for at least three bytes.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn empty_path_record_probe(record: *mut u16) -> u32 {
    record.write(0);
    let path = record.add(1).cast::<u8>();
    strcpy(path, b"\0".as_ptr());
    let flags = record.read() as u8 as i8 as i32 as u32;
    path_exists(path, flags)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clears_only_the_flag_halfword_and_path_terminator() {
        let _exists = crate::app::path_exists::tests::PATH_EXISTS_TEST_LOCK.lock()
            .unwrap_or_else(|e| e.into_inner());
        let _probe = crate::app::path_probe::tests::PATH_PROBE_TEST_LOCK.lock()
            .unwrap_or_else(|e| e.into_inner());
        let _string = crate::cxx::string_object::tests::STRING_OBJECT_OPS_TEST_LOCK.lock()
            .unwrap_or_else(|e| e.into_inner());
        for initial in [0u16, 0x0080, 0xff00, 0xffff] {
            let mut words = [0xa55a, initial, 0x7eab, 0x1234];
            unsafe { empty_path_record_probe(words.as_mut_ptr().add(1)); }
            assert_eq!(words, [0xa55a, 0, 0x7e00, 0x1234]);
        }
        // The minimum legal record has no padding beyond its NUL byte.
        #[repr(C, align(2))]
        struct Minimal { flag: u16, path: u8, canary: u8 }
        let mut record = Minimal { flag: 0xffff, path: 0xff, canary: 0xa5 };
        unsafe { empty_path_record_probe(core::ptr::addr_of_mut!(record.flag)); }
        assert_eq!((record.flag, record.path, record.canary), (0, 0, 0xa5));
    }
}
