//! `utf8_to_pascal_mac_roman` — original: `FUN_08396a04` @ `0x08396a04`.
//!
//! Raw `osos.dec` establishes the exact 84-byte extent
//! `0x08396a04..0x08396a57`; the next function begins at `0x08396a58`.
//! The body has one plain `bl` and one predicated `bleq`. It decodes the
//! supplied UTF-8 through the retail decoder into a 150-byte UTF-16 stack
//! buffer, then on success converts the reported UTF-16 length to a counted
//! MacRoman string. The temporary buffer and decoded-byte-count slot remain
//! uninitialized before the decoder, as in retailOS. Deliberate deviation:
//! both still-retail callees are direct load-address calls on device and
//! replaceable host seams for testing.

use core::{mem::MaybeUninit, ptr::addr_of};

/// Firmware load address of the UTF-8 decoder called at `0x083966e0`.
pub const UTF8_DECODE_TO_UTF16_ADDRESS: usize = 0x0839_66e0;
/// Firmware load address of the UTF-16-to-counted-MacRoman converter at `0x08395d70`.
pub const UTF16_TO_PASCAL_MAC_ROMAN_ADDRESS: usize = 0x0839_5d70;

/// ABI of the retail UTF-8 decoder. The final three arguments are passed on
/// the ARM stack by the original wrapper.
pub type Utf8DecodeToUtf16 = unsafe extern "C" fn(
    source: *const u8,
    context: *mut u8,
    output: *mut u16,
    output_len: *mut u32,
    output_capacity: u32,
    flags: u32,
    zero: u32,
) -> i32;
pub type Utf16ToPascalMacRoman = unsafe extern "C" fn(
    source: *const u16,
    source_len: i32,
    destination: *mut u8,
) -> u32;

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_utf8_decode_to_utf16(
    source: *const u8, context: *mut u8, output: *mut u16, output_len: *mut u32,
    output_capacity: u32, flags: u32, zero: u32,
) -> i32 {
    let decode: Utf8DecodeToUtf16 = core::mem::transmute(UTF8_DECODE_TO_UTF16_ADDRESS);
    decode(source, context, output, output_len, output_capacity, flags, zero)
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_utf16_to_pascal_mac_roman(
    source: *const u16, source_len: i32, destination: *mut u8,
) -> u32 {
    let convert: Utf16ToPascalMacRoman = core::mem::transmute(UTF16_TO_PASCAL_MAC_ROMAN_ADDRESS);
    convert(source, source_len, destination)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_utf8_decode_to_utf16(
    _: *const u8, _: *mut u8, _: *mut u16, _: *mut u32, _: u32, _: u32, _: u32,
) -> i32 {
    panic!("install UTF8_DECODE_TO_UTF16 before calling utf8_to_pascal_mac_roman")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_utf16_to_pascal_mac_roman(_: *const u16, _: i32, _: *mut u8) -> u32 {
    panic!("install UTF16_TO_PASCAL_MAC_ROMAN before calling utf8_to_pascal_mac_roman")
}

#[cfg(target_os = "none")]
pub static mut UTF8_DECODE_TO_UTF16: Utf8DecodeToUtf16 = firmware_utf8_decode_to_utf16;
#[cfg(not(target_os = "none"))]
pub static mut UTF8_DECODE_TO_UTF16: Utf8DecodeToUtf16 = missing_utf8_decode_to_utf16;
#[cfg(target_os = "none")]
pub static mut UTF16_TO_PASCAL_MAC_ROMAN: Utf16ToPascalMacRoman = firmware_utf16_to_pascal_mac_roman;
#[cfg(not(target_os = "none"))]
pub static mut UTF16_TO_PASCAL_MAC_ROMAN: Utf16ToPascalMacRoman = missing_utf16_to_pascal_mac_roman;

/// Decodes `source` with `context` into a temporary UTF-16 buffer, then emits
/// its counted MacRoman representation to `destination` on decoder success.
///
/// # Safety
/// `source`, `context`, and `destination` must satisfy the two retail callees'
/// contracts. The wrapper does not initialize or modify `destination` when
/// decoding fails.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn utf8_to_pascal_mac_roman(
    context: *mut u8, source: *const u8, destination: *mut u8,
) {
    let mut utf16 = MaybeUninit::<[u16; 76]>::uninit();
    let mut utf16_len = MaybeUninit::<u32>::uninit();
    let decode = core::ptr::read_volatile(addr_of!(UTF8_DECODE_TO_UTF16));
    if decode(source, context, utf16.as_mut_ptr().cast(), utf16_len.as_mut_ptr(), 0x96, 0x3a, 0) == 0 {
        let convert = core::ptr::read_volatile(addr_of!(UTF16_TO_PASCAL_MAC_ROMAN));
        convert(utf16.as_ptr().cast(), (utf16_len.assume_init() >> 1) as i32, destination);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use parking_lot::Mutex;

    static SEAM_LOCK: Mutex<()> = Mutex::new(());
    static mut DECODE_ARGS: Option<(usize, usize, u32, u32, u32)> = None;
    static mut CONVERT_ARGS: Option<(std::vec::Vec<u16>, i32, usize)> = None;
    static mut DECODE_STATUS: i32 = 0;

    unsafe extern "C" fn decode(
        source: *const u8, context: *mut u8, output: *mut u16, output_len: *mut u32,
        capacity: u32, flags: u32, zero: u32,
    ) -> i32 {
        DECODE_ARGS = Some((source as usize, context as usize, capacity, flags, zero));
        if DECODE_STATUS == 0 {
            output.write(0x41);
            output.add(1).write(0x00e9);
            output_len.write(4);
        }
        DECODE_STATUS
    }

    unsafe extern "C" fn convert(source: *const u16, source_len: i32, destination: *mut u8) -> u32 {
        CONVERT_ARGS = Some((core::slice::from_raw_parts(source, source_len as usize).to_vec(), source_len, destination as usize));
        destination.write(source_len as u8);
        0
    }

    struct Seams;
    impl Seams {
        unsafe fn install(status: i32) -> Self {
            DECODE_STATUS = status;
            DECODE_ARGS = None;
            CONVERT_ARGS = None;
            core::ptr::addr_of_mut!(UTF8_DECODE_TO_UTF16).write_volatile(decode);
            core::ptr::addr_of_mut!(UTF16_TO_PASCAL_MAC_ROMAN).write_volatile(convert);
            Self
        }
    }
    impl Drop for Seams {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(UTF8_DECODE_TO_UTF16).write_volatile(missing_utf8_decode_to_utf16);
                core::ptr::addr_of_mut!(UTF16_TO_PASCAL_MAC_ROMAN).write_volatile(missing_utf16_to_pascal_mac_roman);
            }
        }
    }

    #[test]
    fn decodes_with_retail_constants_then_converts_code_units() {
        let _lock = SEAM_LOCK.lock();
        let _seams = unsafe { Seams::install(0) };
        let source = b"A\xc3\xa9\0";
        let context = 0x1234usize as *mut u8;
        let mut destination = [0xa5; 32];
        unsafe { utf8_to_pascal_mac_roman(context, source.as_ptr(), destination.as_mut_ptr()) };
        unsafe {
            assert_eq!(DECODE_ARGS, Some((source.as_ptr() as usize, context as usize, 0x96, 0x3a, 0)));
            assert_eq!(CONVERT_ARGS, Some((std::vec![0x41, 0x00e9], 2, destination.as_mut_ptr() as usize)));
        }
        assert_eq!(destination[0], 2);
    }

    #[test]
    fn leaves_destination_untouched_when_decoding_fails() {
        let _lock = SEAM_LOCK.lock();
        let _seams = unsafe { Seams::install(0x16) };
        let mut destination = [0xa5; 4];
        unsafe { utf8_to_pascal_mac_roman(core::ptr::null_mut(), b"\xff\0".as_ptr(), destination.as_mut_ptr()) };
        unsafe { assert_eq!(CONVERT_ARGS, None) };
        assert_eq!(destination, [0xa5; 4]);
    }
}
