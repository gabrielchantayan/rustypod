//! Scanner stream scratch setup — original: `FUN_080e9364` @ `0x080e9364` (44 bytes).
//!
//! Algorithm: request the firmware helper's 16-byte zeroed work area. A NULL
//! result returns false and leaves the caller-owned state untouched. Otherwise
//! install the work-area pointer at +0x20, clear the state words at +0x0c and
//! +0x14, and return true.
//!
//! Deliberate deviation: the allocating helper `FUN_0804ad80` is not ported.
//! Its observed contract (allocate and zero 16 bytes) is represented locally
//! through the existing [`crate::stdio::stream_file::STDIO_ALLOC`] dispatch
//! seam, whose default remains the ported allocator. This keeps the helper
//! replaceable for host tests without exporting or claiming a port of it.

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

/// Function shape of the unported `FUN_0804ad80` helper.
pub type ScanStreamScratchAllocFn = unsafe extern "C" fn() -> *mut u8;

/// Default bridge for the unported helper: allocate through stdio's existing
/// seam, then reproduce the helper's four-word zero initialization.
#[inline(never)]
unsafe extern "C" fn allocate_zeroed_scratch() -> *mut u8 {
    let allocate = core::ptr::read_volatile(core::ptr::addr_of!(STDIO_ALLOC));
    let scratch = allocate(SCAN_STREAM_SCRATCH_SIZE);
    if !scratch.is_null() {
        core::ptr::write_bytes(scratch, 0, SCAN_STREAM_SCRATCH_SIZE);
    }
    scratch
}

/// Allocation boundary standing in for unported `FUN_0804ad80`.
///
/// The shipped default is [`allocate_zeroed_scratch`]; host tests install
/// result-controlled helpers. It is a local implementation seam, not a claim
/// that the helper itself has been ported.
#[cfg_attr(target_os = "none", no_mangle)]
pub static mut SCAN_STREAM_SCRATCH_ALLOC: ScanStreamScratchAllocFn = allocate_zeroed_scratch;

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

    impl Drop for AllocGuard {
        fn drop(&mut self) {
            unsafe {
                core::ptr::write_volatile(
                    core::ptr::addr_of_mut!(SCAN_STREAM_SCRATCH_ALLOC),
                    allocate_zeroed_scratch,
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
