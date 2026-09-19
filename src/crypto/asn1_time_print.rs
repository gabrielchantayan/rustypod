//! OpenSSL's `ASN1_TIME_print` — renders a GeneralizedTime value to a BIO.
//!
//! Port: `asn1_time_print` — `FUN_08039cac` @ 0x08039cac (**452 bytes**,
//! `0x08039cac..0x08039e70`; 392 bytes of instructions followed by its
//! 60-byte literal/string pool). The next separately linked function begins
//! at 0x08039e70. A raw whole-image ARM branch-word decode finds **4 direct
//! inbound `bl` call sites: 4 unconditional and 0 predicated**.
//!
//! The first twelve bytes must be decimal digits and the month bytes must
//! encode 01 through 12. It writes `"Mon DD HH:MM:SS YYYY GMT"` through
//! `BIO_printf`; a trailing `Z` (at `data[length - 1]`) selects `" GMT"`,
//! otherwise the suffix is empty. When bytes 12 and 13 are decimal digits,
//! they are rendered as seconds; otherwise the seconds field is zero. A
//! malformed time writes `"Bad time value"` through `BIO_write` and fails.
//!
//! # Deliberate deviations
//!
//! The ARM varargs spill frame is represented by a local seven-word array
//! passed to the existing `bio_printf` seam. `BIO_write` remains unported;
//! target builds call 0x0803da74 and host tests install `BIO_WRITE`.

use crate::crypto::bio_printf::bio_printf;
use crate::printf::printf_api::VaList;
use core::ffi::c_void;

const BIO_WRITE_ADDRESS: usize = 0x0803_da74;
const TIME_FORMAT: &[u8] = b"%s %2d %02d:%02d:%02d %d%s\0";
const BAD_TIME_VALUE: &[u8] = b"Bad time value";
const GMT_SUFFIX: &[u8] = b" GMT\0";
const NO_SUFFIX: &[u8] = b"\0";
const MONTH_NAMES: [&[u8]; 12] = [
    b"Jan\0", b"Feb\0", b"Mar\0", b"Apr\0", b"May\0", b"Jun\0", b"Jul\0", b"Aug\0",
    b"Sep\0", b"Oct\0", b"Nov\0", b"Dec\0",
];

/// Target-layout `ASN1_TIME`: only the first three fields are consumed.
#[repr(C)]
pub struct Asn1Time {
    pub length: i32,
    pub kind: i32,
    pub data: *const u8,
}

/// ABI of retailOS `BIO_write` @ 0x0803da74.
pub type BioWriteFn = unsafe extern "C" fn(*mut c_void, *const u8, i32) -> i32;

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_bio_write(bio: *mut c_void, data: *const u8, len: i32) -> i32 {
    let write: BioWriteFn = unsafe { core::mem::transmute(BIO_WRITE_ADDRESS) };
    unsafe { write(bio, data, len) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_bio_write(_bio: *mut c_void, _data: *const u8, _len: i32) -> i32 {
    panic!("asn1_time_print requires BIO_write at 0x0803da74")
}

#[cfg(target_os = "none")]
pub static mut BIO_WRITE: BioWriteFn = firmware_bio_write;

#[cfg(not(target_os = "none"))]
pub static mut BIO_WRITE: BioWriteFn = missing_bio_write;

#[inline(always)]
unsafe fn bio_write() -> BioWriteFn {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(BIO_WRITE)) }
}

/// `asn1_time_print` — original: `FUN_08039cac` @ 0x08039cac (452 bytes;
/// 4 direct inbound `bl` call sites: 4 unconditional, 0 predicated).
///
/// Formats a GeneralizedTime-like ASN.1 value to `bio`. It requires twelve
/// initial decimal bytes and a month in 01..=12; it deliberately does not
/// range-check day, hour, minute, or seconds. On malformed input it
/// writes the stock 14-byte diagnostic and returns zero. Otherwise it returns
/// one precisely when `BIO_printf` returns a positive value.
///
/// # Safety
///
/// `time` must point to a live target-layout ASN.1 time and its `data` must
/// contain at least `max(length, 14)` readable bytes: stock code always reads
/// bytes 12 and 13 after the twelve-byte validation. `bio` and the formatting
/// seam must meet the requirements of their respective BIO workers.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn asn1_time_print(bio: *mut c_void, time: *const Asn1Time) -> i32 {
    let time = unsafe { &*time };
    let length = time.length;
    let data = time.data;
    if length < 12 {
        unsafe { (bio_write())(bio, BAD_TIME_VALUE.as_ptr(), BAD_TIME_VALUE.len() as i32) };
        return 0;
    }

    let bytes = unsafe { core::slice::from_raw_parts(data, (length as usize).max(14)) };
    if bytes[..12].iter().any(|byte| byte.wrapping_sub(b'0') > 9) {
        unsafe { (bio_write())(bio, BAD_TIME_VALUE.as_ptr(), BAD_TIME_VALUE.len() as i32) };
        return 0;
    }

    let month = (bytes[4] - b'0') * 10 + bytes[5] - b'0';
    if !(1..=12).contains(&month) {
        unsafe { (bio_write())(bio, BAD_TIME_VALUE.as_ptr(), BAD_TIME_VALUE.len() as i32) };
        return 0;
    }

    let timezone = if bytes[12].wrapping_sub(b'0') <= 9 && bytes[13].wrapping_sub(b'0') <= 9 {
        ((bytes[12] - b'0') * 10 + bytes[13] - b'0') as u32
    } else {
        0
    };
    let year = ((bytes[0] - b'0') as u32) * 1000
        + ((bytes[1] - b'0') as u32) * 100
        + ((bytes[2] - b'0') as u32) * 10
        + (bytes[3] - b'0') as u32;
    let args = [
        MONTH_NAMES[(month - 1) as usize].as_ptr() as usize as u32,
        ((bytes[6] - b'0') * 10 + bytes[7] - b'0') as u32,
        ((bytes[8] - b'0') * 10 + bytes[9] - b'0') as u32,
        ((bytes[10] - b'0') * 10 + bytes[11] - b'0') as u32,
        timezone,
        year,
        if bytes[length as usize - 1] == b'Z' { GMT_SUFFIX } else { NO_SUFFIX }.as_ptr() as usize as u32,
    ];
    if unsafe { bio_printf(bio, TIME_FORMAT.as_ptr(), args.as_ptr() as VaList) } > 0 { 1 } else { 0 }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::bio_printf::{BioVprintfFn, BIO_VPRINTF};
    extern crate std;
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut PRINT_RESULT: i32 = 1;
    static mut PRINT_ARGS: [u32; 7] = [0; 7];
    static mut WRITE_RESULT: i32 = 1;
    static mut WRITE_CALL: Option<(*mut c_void, [u8; 14], i32)> = None;

    unsafe extern "C" fn record_printf(_bio: *mut c_void, format: *const u8, args: VaList) -> i32 {
        assert_eq!(unsafe { core::ffi::CStr::from_ptr(format.cast()) }.to_bytes(), &TIME_FORMAT[..TIME_FORMAT.len() - 1]);
        unsafe { PRINT_ARGS.copy_from_slice(core::slice::from_raw_parts(args, 7)); PRINT_RESULT }
    }

    unsafe extern "C" fn record_write(bio: *mut c_void, data: *const u8, len: i32) -> i32 {
        let mut message = [0; 14];
        message.copy_from_slice(unsafe { core::slice::from_raw_parts(data, 14) });
        unsafe { WRITE_CALL = Some((bio, message, len)); WRITE_RESULT }
    }

    struct Seams { printf: BioVprintfFn, write: BioWriteFn }
    impl Seams {
        unsafe fn install() -> Self {
            unsafe {
                let seams = Self { printf: core::ptr::read_volatile(core::ptr::addr_of!(BIO_VPRINTF)), write: core::ptr::read_volatile(core::ptr::addr_of!(BIO_WRITE)) };
                core::ptr::write_volatile(core::ptr::addr_of_mut!(BIO_VPRINTF), record_printf);
                core::ptr::write_volatile(core::ptr::addr_of_mut!(BIO_WRITE), record_write);
                PRINT_RESULT = 1;
                PRINT_ARGS = [0; 7];
                WRITE_CALL = None;
                seams
            }
        }
    }
    impl Drop for Seams {
        fn drop(&mut self) { unsafe { core::ptr::write_volatile(core::ptr::addr_of_mut!(BIO_VPRINTF), self.printf); core::ptr::write_volatile(core::ptr::addr_of_mut!(BIO_WRITE), self.write); } }
    }

    #[test]
    fn formats_valid_zulu_time_and_returns_print_success() {
        let _guard = TEST_LOCK.lock();
        let _seams = unsafe { Seams::install() };
        let data = b"20240229123456Z";
        let time = Asn1Time { length: data.len() as i32, kind: 0, data: data.as_ptr() };
        assert_eq!(unsafe { asn1_time_print(0x40usize as *mut c_void, &time) }, 1);
        assert_eq!(unsafe { &PRINT_ARGS[1..] }, &[29, 12, 34, 56, 2024, GMT_SUFFIX.as_ptr() as usize as u32]);
        assert!(unsafe { WRITE_CALL.is_none() });
    }

    #[test]
    fn accepts_unvalidated_time_fields_and_non_zulu_suffix() {
        let _guard = TEST_LOCK.lock();
        let _seams = unsafe { Seams::install() };
        let data = b"19991299889912+";
        let time = Asn1Time { length: data.len() as i32, kind: 0, data: data.as_ptr() };
        unsafe { PRINT_RESULT = 0 };
        assert_eq!(unsafe { asn1_time_print(core::ptr::null_mut(), &time) }, 0);
        assert_eq!(unsafe { &PRINT_ARGS[1..] }, &[99, 88, 99, 12, 1999, NO_SUFFIX.as_ptr() as usize as u32]);
    }

    #[test]
    fn rejects_short_nondecimal_and_out_of_range_month_values() {
        let _guard = TEST_LOCK.lock();
        let _seams = unsafe { Seams::install() };
        for (data, length) in [(b"20240101000xxx".as_slice(), 11), (b"20240A011234xx", 12), (b"202400011234xx", 12)] {
            let time = Asn1Time { length, kind: 0, data: data.as_ptr() };
            assert_eq!(unsafe { asn1_time_print(0x88usize as *mut c_void, &time) }, 0);
            assert_eq!(unsafe { WRITE_CALL }, Some((0x88usize as *mut c_void, *b"Bad time value", 14)));
        }
    }
}
