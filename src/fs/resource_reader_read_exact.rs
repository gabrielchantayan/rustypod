//! `resource_reader_read_exact` — original: `FUN_082a6aa4` @ `0x082a6aa4`
//! (52 bytes, `0x082a6aa4..0x082a6ad8`; 15 verified direct `bl` call sites,
//! all unconditional).
//!
//! # Algorithm
//!
//! Loads the resource reader's file handle from target offset `+0x8c`, calls
//! the mode-2 file-read wrapper `FUN_08277c74(handle, count, buffer,
//! &mut transferred)`, and returns one only when that call succeeds (`0`) and
//! reports exactly `count` bytes. The incoming fourth ARM word initializes the
//! transferred local even though all 15 callers leave `r3` as live state rather
//! than deliberately setting it.
//!
//! # Deliberate deviation
//!
//! `FUN_08277c74` is a 28-byte wrapper around the already-modelled unrecovered
//! body at `0x082784d4`; it supplies the fifth body argument `2`. This port
//! reaches that existing volatile body seam directly with the same five-word
//! ABI instead of adding a duplicate seam for the thin wrapper.

use core::ffi::c_void;

/// Prefix and file-handle word of the reader consumed by
/// [`resource_reader_read_exact`].
///
/// `file_handle` is a target pointer, so it remains a `u32`: its offset must
/// stay `0x8c` on both the 32-bit device and the 64-bit host.
#[repr(C)]
pub struct ResourceReader {
    _prefix: [u32; 0x8c / 4],
    pub file_handle: u32,
}

/// `resource_reader_read_exact` — original: `FUN_082a6aa4` @ `0x082a6aa4`
/// (52 bytes; 15 unconditional `bl` call sites, verified by decoding every
/// ARM B/BL word in `osos.dec`).
///
/// Reads exactly `count` bytes through the file handle at reader `+0x8c`.
/// Only body status zero and an exact transferred count yield one; a nonzero
/// status or short success yields zero. The original has no reader, buffer,
/// or output-pointer guard.
///
/// # Safety
///
/// `reader` must point to a valid [`ResourceReader`]. `buffer` and the handle
/// must satisfy the unrecovered file-read body's ABI.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.resource_reader_read_exact")]
#[inline(never)]
pub unsafe extern "C" fn resource_reader_read_exact(
    reader: *const ResourceReader,
    buffer: *mut u8,
    count: u32,
    transferred_initial: u32,
) -> u32 {
    let handle = unsafe { (*reader).file_handle as usize as *mut c_void };
    let mut transferred = transferred_initial;
    let read_body = unsafe {
        core::ptr::read_volatile(core::ptr::addr_of!(crate::fs::file_read::RETAIL_FILE_READ_BODY))
    };
    let status = unsafe { read_body(handle, count, buffer, &mut transferred, 2) };
    (status == 0 && transferred == count) as u32
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::fs::file_read::{reset_retail_file_read_body, RetailFileReadBody, RETAIL_FILE_READ_BODY};
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use std::sync::LazyLock;

    const SLAB_LEN: usize = 0x1000;
    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::RESOURCE_READER_READ_EXACT, SLAB_LEN).map(|base| base as usize)
    });

    static mut CALLS: u32 = 0;
    static mut SEEN_HANDLE: usize = 0;
    static mut SEEN_COUNT: u32 = 0;
    static mut SEEN_BUFFER: usize = 0;
    static mut SEEN_INITIAL: u32 = 0;
    static mut SEEN_CONTROL: u32 = 0;
    static mut STATUS: i32 = 0;
    static mut TRANSFERRED: u32 = 0;

    unsafe extern "C" fn recording_read_body(
        handle: *mut c_void,
        count: u32,
        buffer: *mut u8,
        transferred: *mut u32,
        control: u32,
    ) -> i32 {
        unsafe {
            CALLS += 1;
            SEEN_HANDLE = handle as usize;
            SEEN_COUNT = count;
            SEEN_BUFFER = buffer as usize;
            SEEN_INITIAL = *transferred;
            SEEN_CONTROL = control;
            *transferred = TRANSFERRED;
            STATUS
        }
    }

    struct Reset;

    impl Drop for Reset {
        fn drop(&mut self) {
            unsafe {
                reset_retail_file_read_body();
                CALLS = 0;
                SEEN_HANDLE = 0;
                SEEN_COUNT = 0;
                SEEN_BUFFER = 0;
                SEEN_INITIAL = 0;
                SEEN_CONTROL = 0;
                STATUS = 0;
                TRANSFERRED = 0;
            }
        }
    }

    struct Fixture {
        reader: *mut ResourceReader,
        buffer: *mut u8,
        handle: *mut c_void,
    }

    fn fixture() -> Option<Fixture> {
        let base = (*SLAB)? as *mut u8;
        unsafe {
            core::ptr::write_bytes(base, 0, SLAB_LEN);
            let reader = base.cast::<ResourceReader>();
            let buffer = base.add(0x100);
            let handle = base.add(0x200).cast::<c_void>();
            (*reader).file_handle = handle as usize as u32;
            Some(Fixture { reader, buffer, handle })
        }
    }

    unsafe fn install(status: i32, transferred: u32) {
        unsafe {
            CALLS = 0;
            STATUS = status;
            TRANSFERRED = transferred;
            core::ptr::addr_of_mut!(RETAIL_FILE_READ_BODY)
                .write_volatile(recording_read_body as RetailFileReadBody);
        }
    }

    #[test]
    fn succeeds_only_for_an_exact_successful_transfer() {
        let _guard = crate::ft::system::TEST_OPS_LOCK.lock();
        let Some(fixture) = fixture() else {
            note_missing_u32_fixture("fs::resource_reader_read_exact");
            return;
        };
        let _reset = Reset;

        unsafe {
            install(0, 12);
            assert_eq!(resource_reader_read_exact(fixture.reader, fixture.buffer, 12, 0xa5a5_5a5a), 1);
            assert_eq!(CALLS, 1);
            assert_eq!(SEEN_HANDLE, fixture.handle as usize);
            assert_eq!(SEEN_COUNT, 12);
            assert_eq!(SEEN_BUFFER, fixture.buffer as usize);
            assert_eq!(SEEN_INITIAL, 0xa5a5_5a5a);
            assert_eq!(SEEN_CONTROL, 2);

            install(0, 11);
            assert_eq!(resource_reader_read_exact(fixture.reader, fixture.buffer, 12, 0), 0);
            assert_eq!(CALLS, 1);
        }
    }

    #[test]
    fn rejects_a_complete_transfer_with_an_error_status() {
        let _guard = crate::ft::system::TEST_OPS_LOCK.lock();
        let Some(fixture) = fixture() else {
            note_missing_u32_fixture("fs::resource_reader_read_exact");
            return;
        };
        let _reset = Reset;

        unsafe {
            install(-1, 7);
            assert_eq!(resource_reader_read_exact(fixture.reader, fixture.buffer, 7, u32::MAX), 0);
            assert_eq!(CALLS, 1);
            assert_eq!(SEEN_INITIAL, u32::MAX);
        }
    }
}
