//! HFS allocation-range release — `FUN_08042658` @ 0x08042658.
//! True extent [0x08042658, 0x08042698): 64 bytes; next entry is a PUSH.
//! Raw A32 words verify two incoming plain BLs (0x0804bc2c, 0x08064580),
//! one outgoing plain BL (0x08042674 -> 0x08042b4c), no predicated BLs.
//! Zero count returns success without accessing the volume. Otherwise clear
//! allocation bits through the firmware routine; on success add count modulo
//! 2^32 to volume+0x168, then OR the header halfword with 0xff00.
//! No target behavior deviations. Host tests substitute the unported bitmap
//! clear routine; fixed byte offsets retain the target layout on 64-bit hosts.
#[cfg(test)]
extern crate std;


#[inline(always)]
unsafe fn clear_range(volume: *mut u8, start: u32, count: u32) -> u32 {
    #[cfg(target_os = "none")]
    {
        let clear: unsafe extern "C" fn(*mut u8, u32, u32) -> u32 =
            core::mem::transmute(0x0804_2b4cusize);
        clear(volume, start, count)
    }
    #[cfg(all(not(target_os = "none"), test))]
    { TEST_CLEAR.with(|clear| clear.get()(volume, start, count)) }
    #[cfg(all(not(target_os = "none"), not(test)))]
    { let _ = (volume, start, count); panic!("requires firmware bitmap clear") }
}

/// Release allocation blocks and mark successful volume accounting dirty.
///
/// # Safety
/// For nonzero count, `volume` must be valid for the firmware bitmap routine
/// and writable through +0x16b, with aligned halfword/word fields at 0/+0x168.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn hfs_allocation_range_release(
    volume: *mut u8, start_block: u32, block_count: u32,
) -> u32 {
    if block_count == 0 { return 0; }
    let status = clear_range(volume, start_block, block_count);
    if status == 0 {
        let free_blocks = volume.add(0x168).cast::<u32>();
        free_blocks.write(free_blocks.read().wrapping_add(block_count));
        let flags = volume.cast::<u16>();
        flags.write(flags.read() | 0xff00);
    }
    status
}

#[cfg(test)]
std::thread_local! {
    static TEST_CLEAR: std::cell::Cell<unsafe fn(*mut u8, u32, u32) -> u32> =
        std::cell::Cell::new(missing_clear);
}
#[cfg(test)]
unsafe fn missing_clear(_: *mut u8, _: u32, _: u32) -> u32 {
    panic!("install bitmap clear test seam")
}
#[cfg(test)]
pub(crate) fn set_test_clear(clear: unsafe fn(*mut u8, u32, u32) -> u32) {
    TEST_CLEAR.with(|slot| slot.set(clear));
}

#[cfg(test)]
mod tests {
    use super::*;
    std::thread_local! {
        static BITMAP: std::cell::Cell<u32> = std::cell::Cell::new(u32::MAX);
        static STATUS: std::cell::Cell<u32> = std::cell::Cell::new(0);
    }
    unsafe fn clear(volume: *mut u8, start: u32, count: u32) -> u32 {
        let status = STATUS.with(|slot| slot.get());
        if status != 0 { return status; }
        for bit in start..start + count {
            BITMAP.with(|slot| slot.set(slot.get() & !(0x8000_0000 >> bit)));
        }
        // Accounting must load the post-call fields, not a pre-call snapshot.
        volume.add(0x168).cast::<u32>().write(u32::MAX - 1);
        volume.cast::<u16>().write(0x1234);
        0
    }
    #[test]
    fn zero_count_never_dereferences_volume_or_calls_clear() {
        set_test_clear(missing_clear);
        assert_eq!(unsafe { hfs_allocation_range_release(core::ptr::null_mut(), u32::MAX, 0) }, 0);
    }
    #[test]
    fn success_clears_bits_wraps_accounting_and_preserves_neighbors() {
        set_test_clear(clear);
        STATUS.with(|slot| slot.set(0));
        BITMAP.with(|slot| slot.set(u32::MAX));
        let mut volume = [0xa5a5_a5a5u32; 0x170 / 4];
        let mut expected = volume;
        expected[0] = 0xa5a5_ff34;
        expected[0x168 / 4] = 2;
        assert_eq!(unsafe { hfs_allocation_range_release(volume.as_mut_ptr().cast(), 7, 4) }, 0);
        assert_eq!(volume, expected);
        BITMAP.with(|slot| assert_eq!(slot.get(), u32::MAX & !(0xf << 21)));
    }
    #[test]
    fn errors_leave_flags_and_accounting_unchanged() {
        set_test_clear(clear);
        for status in [1, 0xffff_ffde, 0x8000_0000] {
            STATUS.with(|slot| slot.set(status));
            let mut volume = [0x1234_5678u32; 0x170 / 4];
            let expected = volume;
            assert_eq!(unsafe { hfs_allocation_range_release(volume.as_mut_ptr().cast(), 7, 4) }, status);
            assert_eq!(volume, expected);
        }
    }
}
