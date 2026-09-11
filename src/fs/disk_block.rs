//! Four-slot disk block-read gate and dispatch.
//!
//! `disk_block_read` is retailOS `FUN_082c6244` at load address
//! **0x082c6244**, 120 raw bytes (30 ARM words; the independently entered next
//! function starts at `0x082c62bc`). Decoding every ARM B/BL word in
//! `osos.dec` finds nine direct call sites, all unconditional `bl`; there are
//! no predicated calls or tail branches.
//!
//! The function first invokes the stock readiness helper at `0x082c3174` with
//! the device selector and caller's wait flag. A zero result rejects the
//! request. Only selectors 0 through 3 may then reach stock dispatch wrapper
//! `0x083653cc`; it receives the block coordinates and a fixed final `1`
//! read-operation flag. Any nonzero dispatch result is normalized to one.
//!
//! # Deliberate deviations
//!
//! The two direct callees remain unported and are represented by their verified
//! retailOS addresses. Their identities are not asserted beyond the gating and
//! dispatch roles observable in this wrapper; host tests replace both seams.

#[cfg(not(target_os = "none"))]
use core::ptr;

type DiskReadinessCheck = unsafe extern "C" fn(u32, u32) -> u32;
type DiskReadDispatch = unsafe extern "C" fn(u32, u32, *mut u8, u32, u32) -> u32;

#[cfg(target_os = "none")]
const DISK_READINESS_CHECK_ADDRESS: usize = 0x082c_3174;
#[cfg(target_os = "none")]
const DISK_READ_DISPATCH_ADDRESS: usize = 0x0836_53cc;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_readiness_check(_device: u32, _wait_for_ready: u32) -> u32 {
    panic!("disk_block_read readiness helper called without a host seam")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_read_dispatch(
    _device: u32,
    _block_index: u32,
    _destination: *mut u8,
    _block_count: u32,
    _read_operation: u32,
) -> u32 {
    panic!("disk_block_read dispatch helper called without a host seam")
}

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
struct DiskBlockReadHostOps {
    readiness_check: DiskReadinessCheck,
    dispatch: DiskReadDispatch,
}

#[cfg(not(target_os = "none"))]
const DEFAULT_DISK_BLOCK_READ_HOST_OPS: DiskBlockReadHostOps = DiskBlockReadHostOps {
    readiness_check: unavailable_readiness_check,
    dispatch: unavailable_read_dispatch,
};

#[cfg(not(target_os = "none"))]
static mut DISK_BLOCK_READ_HOST_OPS: DiskBlockReadHostOps = DEFAULT_DISK_BLOCK_READ_HOST_OPS;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn host_ops() -> DiskBlockReadHostOps {
    ptr::read_volatile(ptr::addr_of!(DISK_BLOCK_READ_HOST_OPS))
}

#[inline(always)]
unsafe fn disk_readiness_check(device: u32, wait_for_ready: u32) -> u32 {
    #[cfg(target_os = "none")]
    {
        let check: DiskReadinessCheck = core::mem::transmute(DISK_READINESS_CHECK_ADDRESS);
        check(device, wait_for_ready)
    }

    #[cfg(not(target_os = "none"))]
    {
        (host_ops().readiness_check)(device, wait_for_ready)
    }
}

#[inline(always)]
unsafe fn disk_read_dispatch(
    device: u32,
    block_index: u32,
    destination: *mut u8,
    block_count: u32,
) -> u32 {
    #[cfg(target_os = "none")]
    {
        let dispatch: DiskReadDispatch = core::mem::transmute(DISK_READ_DISPATCH_ADDRESS);
        dispatch(device, block_index, destination, block_count, 1)
    }

    #[cfg(not(target_os = "none"))]
    {
        (host_ops().dispatch)(device, block_index, destination, block_count, 1)
    }
}

/// Gates a disk-block read on readiness and the four valid device slots.
///
/// Original: `FUN_082c6244` at load address `0x082c6244`, 120 bytes, nine
/// direct unconditional `bl` call sites (binary-verified).
///
/// # Safety
///
/// `destination` must satisfy the unported disk dispatcher's buffer contract
/// whenever `device` is below four and its readiness check succeeds. The
/// retailOS body does not inspect or validate this pointer itself.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.disk_block_read")]
#[inline(never)]
pub unsafe extern "C" fn disk_block_read(
    device: u32,
    block_index: u32,
    destination: *mut u8,
    block_count: u32,
    wait_for_ready: u32,
) -> u32 {
    if disk_readiness_check(device, wait_for_ready) == 0 || device >= 4 {
        return 0;
    }

    (disk_read_dispatch(device, block_index, destination, block_count) != 0) as u32
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut READINESS_CALL: Option<(u32, u32)> = None;
    static mut DISPATCH_CALL: Option<(u32, u32, *mut u8, u32, u32)> = None;
    static mut READINESS_RESULT: u32 = 0;
    static mut DISPATCH_RESULT: u32 = 0;

    unsafe extern "C" fn record_readiness_check(device: u32, wait_for_ready: u32) -> u32 {
        READINESS_CALL = Some((device, wait_for_ready));
        READINESS_RESULT
    }

    unsafe extern "C" fn record_dispatch(
        device: u32,
        block_index: u32,
        destination: *mut u8,
        block_count: u32,
        read_operation: u32,
    ) -> u32 {
        DISPATCH_CALL = Some((device, block_index, destination, block_count, read_operation));
        DISPATCH_RESULT
    }

    struct HostOpsReset(DiskBlockReadHostOps);

    impl Drop for HostOpsReset {
        fn drop(&mut self) {
            unsafe {
                DISK_BLOCK_READ_HOST_OPS = self.0;
            }
        }
    }

    unsafe fn install_recorder(readiness_result: u32, dispatch_result: u32) -> HostOpsReset {
        let prior = host_ops();
        DISK_BLOCK_READ_HOST_OPS = DiskBlockReadHostOps {
            readiness_check: record_readiness_check,
            dispatch: record_dispatch,
        };
        READINESS_CALL = None;
        DISPATCH_CALL = None;
        READINESS_RESULT = readiness_result;
        DISPATCH_RESULT = dispatch_result;
        HostOpsReset(prior)
    }

    #[test]
    fn failed_readiness_rejects_before_the_device_range_check() {
        let _lock = TEST_LOCK.lock();
        let _reset = unsafe { install_recorder(0, 1) };

        let result = unsafe { disk_block_read(4, 0x1234_5678, 0x1000usize as *mut u8, 2, 0xa5a5_5a5a) };

        assert_eq!(result, 0);
        unsafe {
            assert_eq!(READINESS_CALL, Some((4, 0xa5a5_5a5a)));
            assert_eq!(DISPATCH_CALL, None);
        }
    }

    #[test]
    fn out_of_range_device_is_rejected_after_successful_readiness() {
        let _lock = TEST_LOCK.lock();
        let _reset = unsafe { install_recorder(1, 1) };

        let result = unsafe { disk_block_read(u32::MAX, 7, 0x2000usize as *mut u8, 1, 0) };

        assert_eq!(result, 0);
        unsafe {
            assert_eq!(READINESS_CALL, Some((u32::MAX, 0)));
            assert_eq!(DISPATCH_CALL, None);
        }
    }

    #[test]
    fn dispatches_fourth_slot_with_fixed_read_flag_and_normalizes_success() {
        let _lock = TEST_LOCK.lock();
        let _reset = unsafe { install_recorder(1, 0xfeed_beef) };
        let destination = 0x1234_5000usize as *mut u8;

        let result = unsafe { disk_block_read(3, 0x89ab_cdef, destination, 0x42, 1) };

        assert_eq!(result, 1);
        unsafe {
            assert_eq!(READINESS_CALL, Some((3, 1)));
            assert_eq!(DISPATCH_CALL, Some((3, 0x89ab_cdef, destination, 0x42, 1)));
        }
    }

    #[test]
    fn dispatch_failure_returns_zero_after_a_valid_request() {
        let _lock = TEST_LOCK.lock();
        let _reset = unsafe { install_recorder(1, 0) };

        let result = unsafe { disk_block_read(0, 0, core::ptr::null_mut(), 0, 0xffff_ffff) };

        assert_eq!(result, 0);
        unsafe {
            assert_eq!(READINESS_CALL, Some((0, 0xffff_ffff)));
            assert_eq!(DISPATCH_CALL, Some((0, 0, core::ptr::null_mut(), 0, 1)));
        }
    }
}
