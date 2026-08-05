//! Scanner stream scratch setup.
//!
//! Ports:
//! - [`scan_stream_allocate_zeroed_scratch`] — original: `FUN_0804ad80` @
//!   `0x0804ad80` (44 bytes); calls the internal allocator with `(16, 0, 0)`,
//!   clears its four returned words without checking for NULL, and returns the
//!   allocation.
//! - [`scan_stream_setup_scratch`] — original: `FUN_080e9364` @ `0x080e9364`
//!   (44 bytes); obtains the 16-byte work area, installs it in the caller's
//!   state, and clears its two scanner state words.

use crate::stdio::stream_file::STDIO_ALLOC;

/// The 16-byte auxiliary area requested by `FUN_0804ad80`.
const SCAN_STREAM_SCRATCH_SIZE: usize = 16;

/// Caller-owned scanner/stream state touched by [`scan_stream_setup_scratch`].
///
/// Only the three writes recovered for this port are classified. The words at
/// +0x0c and +0x14 remain deliberately named by offset until a caller gives
/// them a reliable role. On the 32-bit firmware target, `scratch` is exactly
/// at +0x20; the explicit byte regions preserve that offset on host tests too.
#[repr(C)]
pub struct ScanStreamState {
    _before_0c: [u8; 0x0c],
    pub field_0c: u32,
    _between_10_14: [u8; 0x04],
    pub field_14: u32,
    _between_18_20: [u8; 0x08],
    pub scratch: *mut u8,
}

/// Function shape of the target's three-register `FUN_08043c18` allocation
/// call. The stdio allocator seam backs the default bridge, preserving test
/// isolation while keeping the target's `(size, 0, 0)` call ABI observable.
pub type ScanStreamBackingAllocFn =
    unsafe extern "C" fn(size: u32, zero_arg: u32, flags_arg: u32) -> *mut u8;

/// Function shape of `FUN_0804ad80`.
pub type ScanStreamScratchAllocFn = unsafe extern "C" fn() -> *mut u8;

/// Bridges the target's internal allocator ABI to stdio's existing allocation
/// seam. `FUN_08043c18` receives all three arguments; the ported malloc
/// boundary needs only the requested byte count.
unsafe extern "C" fn allocate_scan_stream_backing(
    size: u32,
    _zero_arg: u32,
    _flags_arg: u32,
) -> *mut u8 {
    let allocate = core::ptr::read_volatile(core::ptr::addr_of!(STDIO_ALLOC));
    allocate(size as usize)
}

/// Allocation boundary for `FUN_08043c18`; host tests replace it to observe
/// the target ABI. The shipped bridge reaches the real ported stdio allocator.
#[cfg_attr(target_os = "none", no_mangle)]
pub static mut SCAN_STREAM_BACKING_ALLOC: ScanStreamBackingAllocFn = allocate_scan_stream_backing;

/// scan_stream_allocate_zeroed_scratch — original: `FUN_0804ad80` @
/// `0x0804ad80` (44 bytes).
///
/// Calls `FUN_08043c18` with `(16, 0, 0)`, then stores zero to the returned
/// area's four words in ascending-address order and returns its base. The ARM
/// original has no NULL check between the allocation and first store, so this
/// port deliberately retains that fault behavior.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn scan_stream_allocate_zeroed_scratch() -> *mut u8 {
    let allocate = core::ptr::read_volatile(core::ptr::addr_of!(SCAN_STREAM_BACKING_ALLOC));
    let scratch = allocate(SCAN_STREAM_SCRATCH_SIZE as u32, 0, 0);
    let words = scratch.cast::<u32>();
    words.write(0);
    words.add(1).write(0);
    words.add(2).write(0);
    words.add(3).write(0);
    scratch
}

/// Allocation boundary for [`scan_stream_allocate_zeroed_scratch`].
///
/// The shipped default is the real port; host tests install result-controlled
/// helpers for [`scan_stream_setup_scratch`].
#[cfg_attr(target_os = "none", no_mangle)]
pub static mut SCAN_STREAM_SCRATCH_ALLOC: ScanStreamScratchAllocFn =
    scan_stream_allocate_zeroed_scratch;

#[inline(always)]
fn scratch_alloc() -> ScanStreamScratchAllocFn {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(SCAN_STREAM_SCRATCH_ALLOC)) }
}

/// `scan_stream_setup_scratch` — original: `FUN_080e9364` @ `0x080e9364` (44 bytes).
///
/// Obtains a 16-byte zeroed scanner work area. Allocation failure returns
/// `false` without changing `state`; success stores the work area at +0x20,
/// clears +0x0c and +0x14, and returns `true`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn scan_stream_setup_scratch(state: *mut ScanStreamState) -> bool {
    let scratch = scratch_alloc()();
    if scratch.is_null() {
        return false;
    }

    (*state).scratch = scratch;
    (*state).field_0c = 0;
    (*state).field_14 = 0;
    true
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::sync::{Mutex, MutexGuard};

    static ALLOC_LOCK: Mutex<()> = Mutex::new(());
    static mut ALLOC_RESULT: *mut u8 = core::ptr::null_mut();
    static mut BACKING_ALLOC_RESULT: *mut u8 = core::ptr::null_mut();
    static mut BACKING_ALLOC_ARGS: [u32; 3] = [u32::MAX; 3];

    unsafe extern "C" fn recording_backing_alloc(
        size: u32,
        zero_arg: u32,
        flags_arg: u32,
    ) -> *mut u8 {
        BACKING_ALLOC_ARGS = [size, zero_arg, flags_arg];
        BACKING_ALLOC_RESULT
    }


    unsafe extern "C" fn recording_alloc() -> *mut u8 {
        ALLOC_RESULT
    }

    struct AllocGuard(MutexGuard<'static, ()>);

    impl AllocGuard {
        fn install(result: *mut u8) -> Self {
            let lock = ALLOC_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
            unsafe {
                ALLOC_RESULT = result;
                core::ptr::write_volatile(
                    core::ptr::addr_of_mut!(SCAN_STREAM_SCRATCH_ALLOC),
                    recording_alloc,
                );
            }
            Self(lock)
        }
    }

    struct BackingAllocGuard(MutexGuard<'static, ()>);

    impl BackingAllocGuard {
        fn install(result: *mut u8) -> Self {
            let lock = ALLOC_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
            unsafe {
                BACKING_ALLOC_RESULT = result;
                BACKING_ALLOC_ARGS = [u32::MAX; 3];
                core::ptr::write_volatile(
                    core::ptr::addr_of_mut!(SCAN_STREAM_BACKING_ALLOC),
                    recording_backing_alloc,
                );
            }
            Self(lock)
        }
    }

    impl Drop for BackingAllocGuard {
        fn drop(&mut self) {
            unsafe {
                core::ptr::write_volatile(
                    core::ptr::addr_of_mut!(SCAN_STREAM_BACKING_ALLOC),
                    allocate_scan_stream_backing,
                );
            }
        }
    }

    impl Drop for AllocGuard {
        fn drop(&mut self) {
            unsafe {
                core::ptr::write_volatile(
                    core::ptr::addr_of_mut!(SCAN_STREAM_SCRATCH_ALLOC),
                    scan_stream_allocate_zeroed_scratch,
                );
            }
        }
    }

    fn state() -> ScanStreamState {
        ScanStreamState {
            _before_0c: [0xa1; 0x0c],
            field_0c: 0xb2b2_b2b2,
            _between_10_14: [0xc3; 0x04],
            field_14: 0xd4d4_d4d4,
            _between_18_20: [0xe5; 0x08],
            scratch: 0xf6f6_f6f6usize as *mut u8,
        }
    }

    #[repr(align(4))]
    struct AlignedScratch([u8; SCAN_STREAM_SCRATCH_SIZE + 8]);

    #[test]
    fn scratch_allocator_forwards_target_arguments_zeroes_four_words_and_returns_base() {
        let mut allocation = AlignedScratch([0xa5; SCAN_STREAM_SCRATCH_SIZE + 8]);
        let scratch = unsafe { allocation.0.as_mut_ptr().add(4) };
        let _guard = BackingAllocGuard::install(scratch);

        let returned = unsafe { scan_stream_allocate_zeroed_scratch() };

        assert_eq!(returned, scratch);
        assert_eq!(unsafe { BACKING_ALLOC_ARGS }, [16, 0, 0]);
        assert_eq!(&allocation.0[..4], &[0xa5; 4]);
        assert_eq!(&allocation.0[4..20], &[0; SCAN_STREAM_SCRATCH_SIZE]);
        assert_eq!(&allocation.0[20..], &[0xa5; 4]);
        for word in allocation.0[4..20].chunks_exact(4) {
            assert_eq!(u32::from_le_bytes(word.try_into().unwrap()), 0);
        }
    }

    #[test]
    fn success_installs_helper_result_and_clears_only_observed_fields() {
        let mut scratch = [0x7au8; SCAN_STREAM_SCRATCH_SIZE];
        let _guard = AllocGuard::install(scratch.as_mut_ptr());
        let mut fixture = state();

        unsafe {
            assert!(scan_stream_setup_scratch(&mut fixture));
        }
        assert_eq!(fixture.scratch, scratch.as_mut_ptr());
        assert_eq!(fixture.field_0c, 0);
        assert_eq!(fixture.field_14, 0);
        assert_eq!(fixture._before_0c, [0xa1; 0x0c]);
        assert_eq!(fixture._between_10_14, [0xc3; 0x04]);
        assert_eq!(fixture._between_18_20, [0xe5; 0x08]);
        assert_eq!(scratch, [0x7a; SCAN_STREAM_SCRATCH_SIZE]);
    }

    #[test]
    fn failure_leaves_every_state_field_unchanged() {
        let _guard = AllocGuard::install(core::ptr::null_mut());
        let mut fixture = state();
        let original_scratch = fixture.scratch;

        unsafe {
            assert!(!scan_stream_setup_scratch(&mut fixture));
        }
        assert_eq!(fixture.scratch, original_scratch);
        assert_eq!(fixture.field_0c, 0xb2b2_b2b2);
        assert_eq!(fixture.field_14, 0xd4d4_d4d4);
        assert_eq!(fixture._before_0c, [0xa1; 0x0c]);
        assert_eq!(fixture._between_10_14, [0xc3; 0x04]);
        assert_eq!(fixture._between_18_20, [0xe5; 0x08]);
    }

    #[test]
    fn target_layout_places_written_fields_at_firmware_offsets() {
        assert_eq!(core::mem::offset_of!(ScanStreamState, field_0c), 0x0c);
        assert_eq!(core::mem::offset_of!(ScanStreamState, field_14), 0x14);
        assert_eq!(core::mem::offset_of!(ScanStreamState, scratch), 0x20);
    }
}
