//! I2S transfer setup IRAM boundary — `thunk_EXT_FUN_220083c4` @ 0x08037ff8.
//!
//! True extent: 8 bytes, [0x08037ff8, 0x08038000). Raw words e51ff004
//! and 220083c4 load PC from the adjacent literal; the next entry is another
//! independent literal veneer. Whole-image aligned A32 decoding verifies two
//! plain inbound BLs (0x080f7d3c, 0x0836b02c), zero predicated inbound BLs,
//! and zero outbound BLs.
//!
//! Dispatch six configuration words and two byte pointers to 0x220083c4,
//! the IRAM mirror of 0x080083c4 installed by 0x080046e0. That unported body
//! locks resource 20, selects a controller/channel when the controller byte
//! is zero, programs the selected controller's transfer configuration, unlocks,
//! and returns zero or 19. It consumes an unsigned controller byte and a
//! signed channel byte; its complete extent includes literals through 0x080084dc.
//!
//! Deliberate deviation: a typed indirect C-ABI call replaces the literal PC
//! load. Hardware behavior stays in the original firmware; hosts reject calls
//! outside tests, which supply the firmware boundary. No callee port is claimed.

#[cfg(test)]
extern crate std;

type TransferSetup = unsafe extern "C" fn(u32, u32, u32, u32, u32, u32, *mut u8, *mut i8) -> u32;

/// # Safety
/// Configuration indices and byte pointers must satisfy the retail setup
/// contract, and the firmware IRAM mirror must be installed before entry.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn i2s_transfer_setup_iram(
    source_endpoint: u32,
    source_width: u32,
    source_burst: u32,
    destination_endpoint: u32,
    destination_width: u32,
    destination_burst: u32,
    controller: *mut u8,
    channel: *mut i8,
) -> u32 {
    #[cfg(target_os = "none")]
    let setup: TransferSetup = unsafe { core::mem::transmute(0x2200_83c4usize) };
    #[cfg(all(not(target_os = "none"), test))]
    let setup = HOST_SETUP.with(|slot| slot.get());
    #[cfg(all(not(target_os = "none"), not(test)))]
    let setup: TransferSetup = unavailable;
    unsafe { setup(source_endpoint, source_width, source_burst, destination_endpoint,
        destination_width, destination_burst, controller, channel) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable(_: u32, _: u32, _: u32, _: u32, _: u32, _: u32,
    _: *mut u8, _: *mut i8) -> u32 {
    panic!("retail IRAM transfer setup is unavailable on hosts")
}

#[cfg(test)]
std::thread_local! {
    static HOST_SETUP: core::cell::Cell<TransferSetup> = core::cell::Cell::new(unavailable);
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    // The boundary consumes exactly one byte at each output pointer. Any
    // widened load/store or pointer truncation in the veneer faults here.
    unsafe extern "C" fn consume_boundary_bytes(_: u32, _: u32, _: u32,
        _: u32, _: u32, _: u32, controller: *mut u8, channel: *mut i8) -> u32 {
        unsafe {
            if controller.read() == 0 {
                controller.write(2);
                channel.write(-1);
                0
            } else {
                19
            }
        }
    }

    #[test]
    fn byte_outputs_at_guard_boundary_preserve_signed_channel_and_error_state() {
        unsafe extern "C" {
            fn getpagesize() -> i32;
            fn mmap(address: usize, length: usize, protection: i32,
                flags: i32, fd: i32, offset: i64) -> usize;
            fn mprotect(address: usize, length: usize, protection: i32) -> i32;
            fn munmap(address: *mut u8, length: usize) -> i32;
        }
        unsafe {
            let page = getpagesize() as usize;
            let mapping = mmap(0, page * 4, 3, 0x22, -1, 0);
            assert_ne!(mapping, usize::MAX);
            assert_eq!(mprotect(mapping + page, page, 0), 0);
            assert_eq!(mprotect(mapping + page * 3, page, 0), 0);
            let mapping = mapping as *mut u8;
            let controller = mapping.add(page - 1);
            let channel = mapping.add(page * 3 - 1).cast::<i8>();
            HOST_SETUP.with(|slot| {
                let previous = slot.replace(consume_boundary_bytes);
                controller.write(0);
                channel.write(127);
                assert_eq!(i2s_transfer_setup_iram(28, 1, 0, 0, 1, 0, controller, channel), 0);
                assert_eq!(controller.read(), 2);
                assert_eq!(channel.read(), -1);
                for invalid in [3, 128, 255] {
                    controller.write(invalid);
                    channel.write(-128);
                    assert_eq!(i2s_transfer_setup_iram(28, 1, 0, 0, 1, 0, controller, channel), 19);
                    assert_eq!(controller.read(), invalid);
                    assert_eq!(channel.read(), -128);
                }
                slot.set(previous);
            });
            assert_eq!(munmap(mapping, page * 4), 0);
        }
    }
}
