//! HFS/HFS+ fork extent release — `FUN_08048138` @ 0x08048138.
//! True extent [0x08048138, 0x08048184): 76 bytes, next word is a new prologue.
//! Whole-image A32 decoding: two incoming plain BLs (0x0804868c, 0x080486ac),
//! two outgoing plain BLs (0x08048158, 0x0804817c), no predicated BLs.
//! Release the inline extent record; propagate errors, or finish on its zero
//! terminator. Only a full record continues into firmware overflow-record
//! release at 0x0806b68c, starting at the wrapping sum of released blocks.
//! That callee searches/releases/deletes overflow records and sets the caller's
//! byte marker after successful deletion. No target behavioral deviations;
//! unlike Ghidra's void declaration, preserve the status in r0. Host builds
//! replace only the firmware-owned overflow operation with a test seam.

use super::hfs_extent_record_release::{AllocationExtent, hfs_extent_record_release};

#[inline(always)]
unsafe fn release_overflow(volume: *mut u8, fork_type: u32, file_id: u32,
    first_block: u32, modified: *mut u8) -> u32 {
    #[cfg(target_os = "none")]
    {
        let release: unsafe extern "C" fn(*mut u8, u32, u32, u32, *mut u8) -> u32 =
            core::mem::transmute(0x0806_b68cusize);
        release(volume, fork_type, file_id, first_block, modified)
    }
    #[cfg(all(not(target_os = "none"), test))]
    { tests::release_overflow(volume, fork_type, file_id, first_block, modified) }
    #[cfg(all(not(target_os = "none"), not(test)))]
    { let _ = (volume, fork_type, file_id, first_block, modified);
      panic!("requires firmware overflow-extent release") }
}

/// Release a fork's inline extent record and, if full, its overflow extents.
///
/// # Safety
/// `volume` and `extents` must satisfy `hfs_extent_record_release`'s contract.
/// For a full record, `volume`, `file_id`, and `fork_type` must identify a valid
/// firmware fork, and `modified` must be a writable byte for overflow deletion.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn hfs_fork_extents_release(volume: *mut u8, file_id: u32,
    fork_type: u32, extents: *const AllocationExtent, modified: *mut u8) -> u32 {
    let mut released_blocks = 0;
    let mut terminated = 0;
    let status = hfs_extent_record_release(volume, extents,
        &mut released_blocks, &mut terminated);
    if status != 0 || terminated != 0 { return status; }
    release_overflow(volume, fork_type, file_id, released_blocks, modified)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use super::super::hfs_extent_record_release::set_test_release_failure;
    use std::cell::Cell;

    std::thread_local! {
        static OVERFLOW: Cell<Option<(u32, u32)>> = const { Cell::new(None) };
    }

    pub unsafe fn release_overflow(volume: *mut u8, fork_type: u32, file_id: u32,
        first_block: u32, modified: *mut u8) -> u32 {
        let (expected_block, status) = OVERFLOW.with(|state| state.get())
            .expect("terminated or failed inline record must not reach overflow");
        assert_eq!((fork_type, file_id, first_block), (0xff, 0x1234_5678, expected_block));
        // Model an overflow record deletion completed before a subsequent error.
        modified.write(1);
        let free = volume.add(0x168).cast::<u32>();
        free.write(free.read().wrapping_add(17));
        status
    }

    #[test]
    fn terminators_errors_full_records_and_wrapping() {
        for signature in [0x482b, 0x4244] {
            let limit = if signature == 0x482b { 8 } else { 3 };
            for stop in 0..=limit {
                for failure in [0, 0x8000_001f] {
                    for overflow_status in [0, 0xffff_fffe] {
                        let mut volume = [0u32; 0x16c / 4];
                        let volume_ptr = volume.as_mut_ptr().cast::<u8>();
                        unsafe { volume_ptr.add(2).cast::<u16>().write(signature); }
                        let mut extents = [AllocationExtent { start_block: 100,
                            block_count: 2 }; 8];
                        extents[0].block_count = u32::MAX;
                        if stop < limit && failure == 0 { extents[stop].block_count = 0; }
                        set_test_release_failure(if failure == 0 { usize::MAX } else { stop }, failure);
                        let total = extents[..stop].iter().fold(0u32,
                            |sum, extent| sum.wrapping_add(extent.block_count));
                        let full = stop == limit;
                        OVERFLOW.with(|state| state.set(if full {
                            Some((total, overflow_status))
                        } else { None }));
                        let mut marker = [0x55, 0xa5, 0x77];
                        let status = unsafe { hfs_fork_extents_release(volume_ptr,
                            0x1234_5678, 0xff, extents.as_ptr(), marker.as_mut_ptr().add(1)) };
                        assert_eq!(status, if full { overflow_status } else { failure });
                        assert_eq!(marker, [0x55, if full { 1 } else { 0xa5 }, 0x77]);
                        assert_eq!(volume[0x168 / 4], total.wrapping_add(if full { 17 } else { 0 }));
                    }
                }
            }
        }
    }
}
