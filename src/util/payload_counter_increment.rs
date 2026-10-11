//! Wrapping increment of a payload's big-endian counter.
//!
//! Original: `FUN_0805b5f0` @ 0x0805b5f0; true extent 120 bytes through
//! 0x0805b667 (116 instruction bytes and the -2107 literal at 0x0805b664).
//! Next real function starts at 0x0805b668. Whole-image raw A32 decoding
//! verifies two incoming plain BLs (0x0805b1e0, 0x0805b428), no predicated
//! incoming BLs. Outgoing: five plain BLs, zero predicated BLs; four to
//! read_u16_le and one to store_u16_le_last_byte.
//! Return -2107 for a NULL handle. Otherwise read payload+10 four times,
//! discard the first two results, assemble the last two reads big-endian,
//! increment, and store the low halfword big-endian. Return zero.
//! Deliberate deviations: the typed payload-pointer field widens on hosts,
//! as in payload_counter_decrement; ARM retains the original word layout.
//! Ordinary memory reads may be inlined, merged, or discarded by LLVM;
//! these are not volatile/MMIO accesses. The 16-bit counter wraps to zero.

use crate::util::le_read::read_u16_le;
use crate::util::u16_le_store_last_byte::store_u16_le_last_byte;

/// # Safety
/// A non-NULL handle must point to a readable payload pointer. Its payload
/// must have readable and writable bytes at offsets 10 and 11; no payload
/// NULL check is performed. The payload need not be aligned.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn payload_counter_increment(handle: *const *mut u8) -> i32 {
    if handle.is_null() {
        return -2107;
    }
    read_u16_le(handle.read().add(10));
    read_u16_le(handle.read().add(10));
    let high = read_u16_le(handle.read().add(10)) << 8;
    let low = (read_u16_le(handle.read().add(10)) & 0xff00) >> 8;
    let incremented = (high | low).wrapping_add(1);
    store_u16_le_last_byte(handle.read().add(10), (incremented as u16).swap_bytes() as u32);
    0
}

#[cfg(test)]
mod tests {
    use super::payload_counter_increment;

    #[test]
    fn null_handle_returns_error() {
        assert_eq!(unsafe { payload_counter_increment(core::ptr::null()) }, -2107);
    }

    #[test]
    fn all_counter_values_wrap_and_preserve_surrounding_bytes() {
        for offset in 0..4 {
            for count in 0..=u16::MAX {
                let mut bytes = [0xa5u8; 16];
                bytes[offset + 10..offset + 12].copy_from_slice(&count.to_be_bytes());
                let payload = unsafe { bytes.as_mut_ptr().add(offset) };
                let handle = payload;
                let mut expected = bytes;
                expected[offset + 10..offset + 12]
                    .copy_from_slice(&count.wrapping_add(1).to_be_bytes());
                assert_eq!(unsafe { payload_counter_increment(&handle) }, 0);
                assert_eq!(bytes, expected, "offset={offset}, count={count}");
                assert_eq!(handle, payload);
                assert_eq!(unsafe { payload_counter_increment(&handle) }, 0);
                expected[offset + 10..offset + 12]
                    .copy_from_slice(&count.wrapping_add(2).to_be_bytes());
                assert_eq!(bytes, expected, "second increment: offset={offset}, count={count}");
            }
        }
    }
}
