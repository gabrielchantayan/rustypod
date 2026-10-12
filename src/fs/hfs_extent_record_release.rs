//! HFS/HFS+ extent-record release — `FUN_0806451c` @ 0x0806451c.
//! True extent [0x0806451c, 0x080645a8): 140 bytes, followed by a distinct
//! constant-return tail wrapper. Raw A32 decoding verifies two incoming plain
//! BLs (0x08048158, 0x0806b6fc), one outgoing plain BL (0x08064580),
//! and zero predicated BLs in either direction.
//! Clear both outputs, then release up to eight extents for signature 0x482b
//! at volume+2, otherwise three. Stop at a zero length and mark termination;
//! propagate the first error without counting its extent. Successful lengths
//! accumulate modulo 2^32. Allocation-range release uses the Rust wrapper.
//! No target behavior deviations; host builds substitute firmware bitmap clear.

#[repr(C)]
#[derive(Clone, Copy)]
pub struct AllocationExtent {
    pub start_block: u32,
    pub block_count: u32,
}

use super::hfs_allocation_range_release::hfs_allocation_range_release;

/// Release a target-width extent record, returning the firmware status.
///
/// # Safety
/// `volume` has a readable aligned halfword at +2 and is valid for the firmware
/// allocation-range release. `extents` contains three or eight aligned records,
/// or records through the first zero length. Outputs are writable and aligned
/// as appropriate; aliases must remain valid across the firmware calls.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn hfs_extent_record_release(
    volume: *mut u8,
    extents: *const AllocationExtent,
    released_blocks: *mut u32,
    terminated: *mut u8,
) -> u32 {
    released_blocks.write(0);
    terminated.write(0);
    let limit = if volume.add(2).cast::<u16>().read() == 0x482b { 8 } else { 3 };
    for index in 0..limit {
        let extent = extents.add(index);
        let count = core::ptr::addr_of!((*extent).block_count).read();
        if count == 0 {
            terminated.write(1);
            return 0;
        }
        let start = core::ptr::addr_of!((*extent).start_block).read();
        let status = hfs_allocation_range_release(volume, start, count);
        if status != 0 { return status; }
        released_blocks.write(released_blocks.read().wrapping_add(count));
    }
    0
}

#[cfg(test)]
pub(crate) fn set_test_release_failure(index: usize, status: u32) {
    tests::configure_failure(index, status);
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::cell::RefCell;
    use std::vec::Vec;

    std::thread_local! {
        static STATE: RefCell<(Vec<(u32, u32)>, usize, u32)> =
            RefCell::new((Vec::new(), usize::MAX, 0));
    }

    pub(super) fn configure_failure(index: usize, status: u32) {
        STATE.with(|state| *state.borrow_mut() = (Vec::new(), index, status));
        super::super::hfs_allocation_range_release::set_test_clear(release_range);
    }

    pub unsafe fn release_range(_volume: *mut u8, start: u32, count: u32) -> u32 {
        STATE.with(|state| {
            let mut state = state.borrow_mut();
            let index = state.0.len();
            state.0.push((start, count));
            if index == state.1 { return state.2; }
            0
        })
    }

    #[test]
    fn boundaries_termination_errors_and_wrapping() {
        for signature in [0x482b, 0x4244, 0, 0xffff] {
            let limit = if signature == 0x482b { 8 } else { 3 };
            for stop in 0..=limit {
                for error in [false, true] {
                    let mut volume = [0u32; 0x16c / 4];
                    let volume_ptr = volume.as_mut_ptr().cast::<u8>();
                    unsafe { volume_ptr.add(2).cast::<u16>().write(signature); }
                    let mut extents = [AllocationExtent { start_block: 0, block_count: 0 }; 8];
                    for index in 0..limit {
                        extents[index] = AllocationExtent {
                            start_block: 100 + index as u32 * 17,
                            block_count: if index == 0 { u32::MAX } else { index as u32 + 2 },
                        };
                    }
                    if stop < limit && !error { extents[stop].block_count = 0; }
                    STATE.with(|state| *state.borrow_mut() = (Vec::new(),
                        if error { stop } else { usize::MAX }, 0x8000_001f));
                    super::super::hfs_allocation_range_release::set_test_clear(release_range);
                    let mut total = 0xa5a5_a5a5;
                    let mut marker = [0x55, 0x66, 0x77];
                    let result = unsafe { hfs_extent_record_release(volume_ptr,
                        extents.as_ptr(), &mut total, marker.as_mut_ptr().add(1)) };
                    let failed = error && stop < limit;
                    assert_eq!(result, if failed { 0x8000_001f } else { 0 });
                    assert_eq!(marker, [0x55, u8::from(!error && stop < limit), 0x77]);
                    let successful = if stop < limit { stop } else { limit };
                    let expected = extents[..successful].iter()
                        .fold(0u32, |sum, extent| sum.wrapping_add(extent.block_count));
                    assert_eq!(total, expected);
                    assert_eq!(volume[0x168 / 4], expected);
                    STATE.with(|state| {
                        let state = state.borrow();
                        let called = successful + usize::from(failed);
                        assert_eq!(state.0.as_slice(), &extents[..called].iter()
                            .map(|extent| (extent.start_block, extent.block_count))
                            .collect::<Vec<_>>()[..]);
                    });
                }
            }
        }
    }
}
