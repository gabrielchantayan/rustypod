//! Saturating decrement of a payload's big-endian counter.
//!
//! Original: `FUN_0805b86c` @ 0x0805b86c; true extent 120 bytes through
//! 0x0805b8e3 (116 instruction bytes plus the error literal at 0x0805b8e0).
//! Next real function starts at 0x0805b8e4. Raw whole-image branch decoding
//! verifies two incoming plain BLs (0x0805b408, 0x0805b5cc), no predicated
//! incoming BLs. Outgoing: three plain BLs, one BLLT, to the existing
//! read_u16_le and store_u16_le_last_byte ports.
//! Return -2107 for a NULL handle. Otherwise read the halfword at payload+10
//! twice, assemble it big-endian, decrement, store the low halfword, then
//! overwrite with zero if the signed result is negative. Return zero.
//! Deliberate deviation: the single typed payload-pointer field widens on
//! hosts, as in payload_u16_be_store; ARM retains the original word layout.
//! Release codegen inlines and merges the two ordinary halfword reads into
//! two byte loads; the wrapping store and conditional zero store remain.
//! These are ordinary memory accesses, not volatile/MMIO operations.

use crate::util::le_read::read_u16_le;
use crate::util::u16_le_store_last_byte::store_u16_le_last_byte;

/// # Safety
/// A non-NULL handle must point to a readable payload pointer. Its payload
/// must have readable and writable bytes at offsets 10 and 11; no payload
/// NULL check is performed. The payload need not be aligned.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn payload_counter_decrement(handle: *const *mut u8) -> i32 {
    if handle.is_null() {
        return -2107;
    }
    let high = read_u16_le(handle.read().add(10)) & 0xff;
    let low = (read_u16_le(handle.read().add(10)) & 0xff00) >> 8;
    let decremented = ((high << 8) | low) as i32 - 1;
    store_u16_le_last_byte(handle.read().add(10), (decremented as u16).swap_bytes() as u32);
    if decremented < 0 {
        store_u16_le_last_byte(handle.read().add(10), 0);
    }
    0
}

#[cfg(test)]
mod tests {
    use super::payload_counter_decrement;

    #[test]
    fn null_handle_returns_error() {
        assert_eq!(unsafe { payload_counter_decrement(core::ptr::null()) }, -2107);
    }

    #[test]
    fn all_counter_values_saturate_and_preserve_surrounding_bytes() {
        for offset in 0..4 {
            for count in 0..=u16::MAX {
                let mut bytes = [0xa5u8; 16];
                bytes[offset + 10..offset + 12].copy_from_slice(&count.to_be_bytes());
                let payload = unsafe { bytes.as_mut_ptr().add(offset) };
                let handle = payload;
                let mut expected = bytes;
                expected[offset + 10..offset + 12]
                    .copy_from_slice(&count.saturating_sub(1).to_be_bytes());
                assert_eq!(unsafe { payload_counter_decrement(&handle) }, 0);
                assert_eq!(bytes, expected, "offset={offset}, count={count}");
                assert_eq!(handle, payload);
                assert_eq!(unsafe { payload_counter_decrement(&handle) }, 0);
                expected[offset + 10..offset + 12]
                    .copy_from_slice(&count.saturating_sub(2).to_be_bytes());
                assert_eq!(bytes, expected, "second decrement: offset={offset}, count={count}");
            }
        }
    }
}
