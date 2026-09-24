//! Resource-record lookup and decode wrapper @ 0x0805ae6c.
//!
//! The retail body finds a signed-16-bit occurrence through
//! [`resource_record_find_nth`], then hands the resulting byte offset to the
//! stock record decoder. The decoder writes the decoded pointer and byte count
//! through separate output pointers; this wrapper returns the pointer and
//! optionally publishes the byte count.

use core::ptr;

use crate::util::resource_record_find_nth::resource_record_find_nth;

type RetailResourceRecordDecode = unsafe extern "C" fn(
    table_slot: *mut *mut u8,
    record_offset: i32,
    decoded_len_out: *mut u32,
    decoded_out: *mut *mut u8,
) -> u32;

#[cfg(target_arch = "arm")]
extern "C" {
    fn retail_resource_record_decode(
        table_slot: *mut *mut u8,
        record_offset: i32,
        decoded_len_out: *mut u32,
        decoded_out: *mut *mut u8,
    ) -> u32;
}

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn retail_resource_record_decode(
    _table_slot: *mut *mut u8,
    _record_offset: i32,
    _decoded_len_out: *mut u32,
    _decoded_out: *mut *mut u8,
) -> u32 {
    0
}

// The retail decoder remains in stock code. This veneer preserves its four
// AAPCS arguments after this wrapper is linked into the patch payload.
#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .text
    .p2align 2
    .globl retail_resource_record_decode
    .type retail_resource_record_decode, %function
retail_resource_record_decode:
    ldr     pc, [pc, #-4]
    .word   0x0805afd8
    .size retail_resource_record_decode, . - retail_resource_record_decode
"#
);

unsafe fn resource_record_find_and_decode_with(
    table_slot: *mut *mut u8,
    directory_offset: u32,
    record_tag: u32,
    occurrence: i16,
    decoded_len_out: *mut u32,
    find_nth: unsafe extern "C" fn(*mut *mut u8, u32, u32, u32, *mut u8) -> i32,
    decode: RetailResourceRecordDecode,
) -> *mut u8 {
    let mut decoded = ptr::null_mut();
    let mut decoded_len = 0;
    let record_offset = find_nth(
        table_slot,
        directory_offset,
        record_tag,
        occurrence as i32 as u32,
        ptr::null_mut(),
    );

    if record_offset != 0 {
        decode(table_slot, record_offset, &mut decoded_len, &mut decoded);
    }
    if !decoded_len_out.is_null() {
        decoded_len_out.write(decoded_len);
    }
    decoded
}

/// resource_record_find_and_decode — original: `FUN_0805ae6c` @ `0x0805ae6c`
/// (92 bytes, `0x0805ae6c..0x0805aec8`; one plain `bl` and one predicated
/// `blne`, verified from raw osos.dec words).
///
/// Looks up signed-16-bit `occurrence` of `record_tag`, decodes a nonzero
/// record offset through stock `FUN_0805afd8`, and returns its decoded pointer.
/// A non-NULL `decoded_len_out` receives zero when lookup fails, otherwise the
/// decoder's byte count.
///
/// Deliberate deviations: the stock frame holds three separate zeroed words;
/// Rust uses two typed locals, preserving every observable output. The retained
/// decoder is reached through a literal veneer because its stock PC-relative
/// call cannot reach from the patch payload.
///
/// # Safety
/// `table_slot` and `decoded_len_out`, when non-NULL, must satisfy the retail
/// table walker and decoder's readable/writable pointer requirements.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(
    target_os = "none",
    link_section = ".text.resource_record_find_and_decode"
)]
#[inline(never)]
pub unsafe extern "C" fn resource_record_find_and_decode(
    table_slot: *mut *mut u8,
    directory_offset: u32,
    record_tag: u32,
    occurrence: u32,
    decoded_len_out: *mut u32,
) -> *mut u8 {
    resource_record_find_and_decode_with(
        table_slot,
        directory_offset,
        record_tag,
        occurrence as i16,
        decoded_len_out,
        resource_record_find_nth,
        retail_resource_record_decode,
    )
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr;

    static mut FIND_ARGS: (usize, u32, u32, u32, usize) = (0, 0, 0, 0, 0);
    static mut DECODE_ARGS: (usize, i32) = (0, 0);
    static mut FIND_RESULT: i32 = 0;
    static mut DECODED: *mut u8 = ptr::null_mut();
    static mut DECODED_LEN: u32 = 0;

    unsafe extern "C" fn find_nth(
        table_slot: *mut *mut u8,
        directory_offset: u32,
        record_tag: u32,
        occurrence: u32,
        out_record_value: *mut u8,
    ) -> i32 {
        FIND_ARGS = (table_slot as usize, directory_offset, record_tag, occurrence, out_record_value as usize);
        FIND_RESULT
    }

    unsafe extern "C" fn decode(
        table_slot: *mut *mut u8,
        record_offset: i32,
        decoded_len_out: *mut u32,
        decoded_out: *mut *mut u8,
    ) -> u32 {
        DECODE_ARGS = (table_slot as usize, record_offset);
        decoded_len_out.write(DECODED_LEN);
        decoded_out.write(DECODED);
        0
    }

    #[test]
    fn lookup_failure_returns_null_and_publishes_zero_length() {
        unsafe {
            FIND_RESULT = 0;
            DECODE_ARGS = (usize::MAX, i32::MIN);
            let mut length = u32::MAX;
            let decoded = resource_record_find_and_decode_with(
                ptr::null_mut(), 0x10, 0x5245_5343, 1, &mut length, find_nth, decode,
            );
            assert!(decoded.is_null());
            assert_eq!(length, 0);
            assert_eq!(DECODE_ARGS, (usize::MAX, i32::MIN));
        }
    }

    #[test]
    fn signed_occurrence_and_decoder_outputs_are_preserved() {
        unsafe {
            let mut table = [0u8; 4];
            let mut table_slot = table.as_mut_ptr();
            let mut decoded_storage = [0u8; 1];
            FIND_RESULT = -12;
            DECODED = decoded_storage.as_mut_ptr();
            DECODED_LEN = 0x1234;
            let mut length = 0;
            let decoded = resource_record_find_and_decode_with(
                &mut table_slot, 0x20, 0x5441_4721, -2, &mut length, find_nth, decode,
            );
            assert_eq!(FIND_ARGS, (&mut table_slot as *mut *mut u8 as usize, 0x20, 0x5441_4721, 0xffff_fffe, 0));
            assert_eq!(DECODE_ARGS, (&mut table_slot as *mut *mut u8 as usize, -12));
            assert_eq!(decoded, decoded_storage.as_mut_ptr());
            assert_eq!(length, 0x1234);
        }
    }
}
