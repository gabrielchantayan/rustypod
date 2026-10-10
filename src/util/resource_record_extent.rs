//! Resource record size/address extraction from retailOS.

use crate::util::le_read::read_u32_le;

/// resource_record_extent — original: `FUN_080a3b4c` @ `0x080a3b4c`.
/// True extent [0x080a3b4c, 0x080a3c28): 220 bytes, next boundary verified
/// from raw ARM words. Two inbound plain BLs at 0x0805a348/0x0805b060,
/// zero predicated BLs. Eight outbound plain BLs to read_u32_le @ 0x080ed748,
/// zero predicated BLs (four reads on each of two mutually exclusive paths).
///
/// Resolve the record at `*table_slot + record_offset`, defaulting a zero
/// offset to 12. Optionally return its big-endian size and its address. Any
/// nonzero `payload_only` subtracts the 20-byte header from the size (wrapping)
/// and advances the address by 20. A NULL slot or two NULL outputs returns
/// -50 without reading the table or touching outputs; success returns zero.
///
/// Deliberate deviations: one existing unaligned read plus byte reversal
/// replaces four redundant non-volatile reads of ordinary mapped record data.
/// Native pointer slots support host fixtures; on target they remain four bytes.
///
/// # Safety
/// On valid requests, `table_slot` must be readable as a table-base pointer.
/// When requested, the size field must have four readable bytes and each
/// non-NULL output must be aligned and writable for its declared type.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn resource_record_extent(
    table_slot: *const *const u8,
    record_offset: u32,
    payload_only: u32,
    out_size: *mut u32,
    out_address: *mut *const u8,
) -> i32 {
    if table_slot.is_null() || (out_size.is_null() && out_address.is_null()) {
        return -50;
    }
    let offset = if record_offset == 0 { 12 } else { record_offset };
    let record = table_slot.read().wrapping_add(offset as usize);
    if !out_size.is_null() {
        let size = read_u32_le(record).swap_bytes();
        out_size.write(if payload_only == 0 { size } else { size.wrapping_sub(20) });
    }
    if !out_address.is_null() {
        out_address.write(if payload_only == 0 { record } else { record.wrapping_add(20) });
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr;

    #[test]
    fn invalid_requests_preserve_outputs_without_reading_slot() {
        let mut size = 0x1234_5678;
        let mut address = 0x1234usize as *const u8;
        unsafe {
            assert_eq!(resource_record_extent(ptr::null(), 0, 1, &mut size, &mut address), -50);
            assert_eq!(resource_record_extent(ptr::null(), 0, 0, &mut size, ptr::null_mut()), -50);
            assert_eq!(resource_record_extent(ptr::null(), 0, 0, ptr::null_mut(), &mut address), -50);
            assert_eq!(resource_record_extent(ptr::dangling(), 0, 0, ptr::null_mut(), ptr::null_mut()), -50);
        }
        assert_eq!(size, 0x1234_5678);
        assert_eq!(address, 0x1234usize as *const u8);
    }

    #[test]
    fn sizes_offsets_modes_and_optional_outputs() {
        let mut bytes = [0u8; 64];
        for offset in [0u32, 1, 2, 3, 4, 13] {
            let resolved = if offset == 0 { 12 } else { offset } as usize;
            for size in [0u32, 1, 19, 20, 21, 0x1234_5678, u32::MAX] {
                bytes[resolved..resolved + 4].copy_from_slice(&size.to_be_bytes());
                let base = bytes.as_ptr();
                for mode in [0u32, 1, 2, u32::MAX] {
                    for outputs in [1, 2, 3] {
                        let mut got_size = 0xdead_beef;
                        let mut got_address = ptr::null();
                        let size_out = if outputs & 1 != 0 { &mut got_size } else { ptr::null_mut() };
                        let address_out = if outputs & 2 != 0 { &mut got_address } else { ptr::null_mut() };
                        assert_eq!(unsafe { resource_record_extent(&base, offset, mode, size_out, address_out) }, 0);
                        assert_eq!(got_size, if outputs & 1 == 0 { 0xdead_beef } else if mode == 0 { size } else { size.wrapping_sub(20) });
                        assert_eq!(got_address, if outputs & 2 == 0 { ptr::null() } else { base.wrapping_add(resolved + if mode == 0 { 0 } else { 20 }) });
                    }
                }
            }
        }
    }

    #[test]
    fn address_only_does_not_read_record_and_wraps_target_offset() {
        let base = 0xffff_fff0usize as *const u8;
        let mut address = ptr::null();
        unsafe {
            assert_eq!(resource_record_extent(&base, 0x20, 0, ptr::null_mut(), &mut address), 0);
        }
        assert_eq!(address, base.wrapping_add(0x20));
    }

    #[test]
    fn aliased_size_output_is_written_before_address_output() {
        let mut bytes = [0u8; 32];
        bytes[12..16].copy_from_slice(&40u32.to_be_bytes());
        let base = bytes.as_ptr();
        let mut address = ptr::null();
        let output = &mut address as *mut *const u8;
        unsafe {
            assert_eq!(resource_record_extent(&base, 0, 1, output.cast(), output), 0);
        }
        assert_eq!(address, base.wrapping_add(32));
    }
}
