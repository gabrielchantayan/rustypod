//! USB high-speed property query — retail `FUN_08294a08` at 0x08294a08.
//! True extent: 0x08294a08..0x08294a4c (68 bytes). Raw aligned A32 decoding
//! verifies two incoming plain BLs, zero predicated BLs, and one outgoing
//! plain BL to `usb_high_speed_mode_active` (0x08107f04).
//!
//! Query 1 with a nonnull buffer and signed capacity >= 1 stores the USB
//! high-speed flag in its first byte, then stores 1 in the result length,
//! returning 0. All other requests return -1 without reading hardware or
//! writing outputs. The receiver is ignored. No behavioral deviations;
//! the existing callee supplies its documented host MMIO stand-in.

use crate::drivers::usb_high_speed_mode::usb_high_speed_mode_active;

/// The length pointer must be writable and word-aligned on success; the
/// buffer must hold one writable byte. Outputs may overlap: byte first,
/// length second, as in retail. Invalid requests need no valid outputs.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn usb_high_speed_query(
    _receiver: u32,
    query: u32,
    buffer: *mut u8,
    capacity: i32,
    result_length: *mut u32,
) -> i32 {
    if query != 1 || buffer.is_null() || capacity < 1 {
        return -1;
    }
    buffer.write_volatile(usb_high_speed_mode_active() as u8);
    result_length.write_volatile(1);
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr;

    #[test]
    fn invalid_queries_and_signed_capacities_preserve_outputs() {
        for query in [0, 1, 2, u32::MAX] {
            for capacity in [i32::MIN, -1, 0, 1, i32::MAX] {
                if query == 1 && capacity > 0 { continue; }
                let mut bytes = [0xa5; 3];
                let mut length = 0xdeadbeef;
                assert_eq!(unsafe {
                    usb_high_speed_query(0, query, bytes.as_mut_ptr().add(1), capacity, &mut length)
                }, -1);
                assert_eq!(bytes, [0xa5; 3]);
                assert_eq!(length, 0xdeadbeef);
                assert_eq!(unsafe {
                    usb_high_speed_query(u32::MAX, query, ptr::null_mut(), capacity, ptr::null_mut())
                }, -1);
            }
        }
        assert_eq!(unsafe {
            usb_high_speed_query(0, 1, ptr::null_mut(), 1, ptr::null_mut())
        }, -1);
    }

    #[test]
    fn successful_query_writes_one_normalized_byte_and_length() {
        let _guard = crate::drivers::usb_high_speed_mode::host_usb_link_status::LOCK.lock();
        for capacity in [1, 2, i32::MAX] {
            let mut bytes = [0xa5; 3];
            let mut length = u32::MAX;
            assert_eq!(unsafe {
                usb_high_speed_query(u32::MAX, 1, bytes.as_mut_ptr().add(1), capacity, &mut length)
            }, 0);
            let status = unsafe {
                core::ptr::addr_of!(crate::drivers::usb_high_speed_mode::host_usb_link_status::WORD).read_volatile()
            };
            assert_eq!(bytes[1], ((status & 6) == 0) as u8);
            assert_eq!(bytes[0], 0xa5);
            assert_eq!(bytes[2], 0xa5);
            assert_eq!(length, 1);
        }
    }

    #[test]
    fn overlapping_outputs_store_length_after_status_byte() {
        let _guard = crate::drivers::usb_high_speed_mode::host_usb_link_status::LOCK.lock();
        let mut length = u32::MAX;
        let address = ptr::addr_of_mut!(length);
        assert_eq!(unsafe {
            usb_high_speed_query(0, 1, address.cast::<u8>().add(1), 1, address)
        }, 0);
        assert_eq!(length, 1);
    }
}
