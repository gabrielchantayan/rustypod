//! USB endpoint packet-size update — retail `FUN_08293264` at 0x08293264.
//! True extent: 0x08293264..0x0829329c (56 bytes), ending in bx lr before
//! the next function's ldr r3,[pc,#116]. Raw A32 verifies two incoming
//! plain BLs (0x08105114, 0x08160abc), zero predicated BLs, and no outgoing calls.
//!
//! Walk length-prefixed USB descriptors until the remaining byte count is
//! zero. For type 5 (endpoint), write the low 16 bits of packet_size to
//! wMaxPacketSize at bytes 4 and 5, little-endian. Receiver is ignored.
//! No behavioral deviations: byte accesses and wrapping subtraction retain
//! retail ordering and arithmetic; malformed chains are not validated.

/// # Safety
/// For nonzero length, descriptors must form a readable chain whose nonzero
/// byte lengths sum exactly to length. Each record needs a readable type
/// byte; endpoint records need writable bytes 4 and 5. A zero length does
/// not access descriptors. The receiver need not point to a valid object.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn usb_endpoint_packet_size(
    _receiver: u32,
    mut descriptors: *mut u8,
    mut length: u32,
    packet_size: u32,
) {
    while length != 0 {
        if descriptors.add(1).read_volatile() == 5 {
            descriptors.add(4).write_volatile(packet_size as u8);
            descriptors.add(5).write_volatile((packet_size >> 8) as u8);
        }
        let record_length = descriptors.read_volatile() as u32;
        length = length.wrapping_sub(record_length);
        descriptors = descriptors.wrapping_add(record_length as usize);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reference(bytes: &mut [u8], packet_size: u32) {
        let mut offset = 0;
        while offset != bytes.len() {
            if bytes[offset + 1] == 5 {
                bytes[offset + 4] = packet_size as u8;
                bytes[offset + 5] = (packet_size >> 8) as u8;
            }
            offset += bytes[offset] as usize;
        }
    }

    #[test]
    fn empty_chain_needs_no_pointer() {
        unsafe { usb_endpoint_packet_size(u32::MAX, core::ptr::null_mut(), 0, u32::MAX); }
    }

    #[test]
    fn mixed_records_unaligned_buffers_and_packet_size_truncation() {
        for alignment in 0..4 {
            for packet_size in [0, 1, 0x40, 0xc0, 0x200, 0x1234, 0xffff, 0xabcd1234, u32::MAX] {
                let mut bytes = [0xa5; 280];
                let start = 4 + alignment;
                let mut offset = start;
                for (length, kind) in [(2, 4), (7, 5), (9, 4), (255, 5)] {
                    bytes[offset] = length as u8;
                    bytes[offset + 1] = kind;
                    offset += length;
                }
                let mut expected = bytes;
                reference(&mut expected[start..offset], packet_size);
                unsafe {
                    usb_endpoint_packet_size(u32::MAX, bytes.as_mut_ptr().add(start),
                        (offset - start) as u32, packet_size);
                }
                assert_eq!(bytes, expected);
            }
        }
    }

    #[test]
    fn non_endpoint_records_and_bytes_after_chain_are_untouched() {
        let mut bytes = [2, 0, 2, 4, 2, 6, 7, 5, 0xaa, 0xbb, 0xcc, 0xdd, 0xee];
        let expected = bytes;
        unsafe { usb_endpoint_packet_size(0, bytes.as_mut_ptr(), 6, 0x1234); }
        assert_eq!(bytes, expected);
    }
}
