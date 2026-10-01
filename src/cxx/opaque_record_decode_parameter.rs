//! `opaque_record_decode_parameter` — retailOS `FUN_082a1ec8` at `0x082a1ec8`.
//!
//! True size: 8 bytes. Raw words `e280000c e12fff1e` decode as
//! `add r0, r0, #12; bx lr`; the next real leaf starts at `0x082a1ed0`
//! with `add r0, r0, #20; bx lr`. A raw ARM BL-immediate scan verifies
//! two plain calls (`0x081044c0`, `0x08104860`) and zero predicated calls.
//!
//! Algorithm: return the address of the opaque record's word at byte offset
//! 12, without reading memory. Both callers load this word and pass it as
//! argument four to `FUN_082d74c0` while processing a record's payload.
//! The exact meaning of that decode parameter remains unknown.
//! Deliberate deviations: host pointer arithmetic uses host address width;
//! on ARM the wrapping byte offset retains the original 32-bit behavior.
//! LLVM adds a frame-pointer prologue/epilogue around the same byte addition.
//! A dedicated text section prevents folding into another offset-12 accessor.

#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.opaque_record_decode_parameter")]
#[inline(never)]
pub extern "C" fn opaque_record_decode_parameter(record: *const u8) -> *const u32 {
    record.wrapping_add(12).cast()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn returns_the_parameter_address_not_its_value() {
        for parameter in [0, u32::MAX, 0x1234_5678] {
            let record = [0xaaaa_aaaau32, 0xbbbb_bbbb, 7, parameter, 0xcccc_cccc];
            let field = opaque_record_decode_parameter(record.as_ptr().cast());
            assert_eq!(field, &record[3] as *const u32);
            assert_eq!(unsafe { field.read() }, parameter);
        }
    }

    #[test]
    fn accepts_null_unaligned_and_wrapping_addresses_without_loading() {
        for address in [0usize, 1, 3, usize::MAX - 11, usize::MAX] {
            let field = opaque_record_decode_parameter(address as *const u8);
            assert_eq!(field as usize, address.wrapping_add(12));
        }
    }
}
