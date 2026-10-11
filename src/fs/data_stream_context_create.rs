//! Data-backed stream context construction.
//!
//! `FUN_0805b764` @ 0x0805b764: 104 bytes (96 instruction bytes plus
//! literals `data` = 0x64617461 and `strm` = 0x7374726d). The next real
//! function starts at 0x0805b7cc. Raw aligned A32 decoding verifies two
//! inbound plain BLs (0x08042f28, 0x08042f94), three outbound plain BLs,
//! and no predicated BLs in either direction.
//!
//! Allocate an eight-byte zeroed tag-4 context, acquire its backing handle
//! with the fixed data tag and the low byte of mode, then stamp the stream
//! tag on success. Acquisition failure frees the context and clears the
//! output; allocation failure returns -108 without touching the output.
//! Host-only deviation: acquisition writes to a native-width local pointer
//! before storing the target-width handle word, avoiding an eight-byte host
//! write into a four-byte field. ARM writes directly into word one. Callees are
//! Rust ports; no firmware-address dispatch or new callee seam is needed.

use crate::cxx::opaque_handle_acquire::opaque_handle_acquire;
use crate::heap::veneers::{calloc_tag4, free_tag4};

#[inline(always)]
unsafe fn create_context(
    out_context: *mut u32,
    mode: u32,
    allocate: impl FnOnce() -> *mut u32,
    acquire: impl FnOnce(u32, *mut *mut u8) -> i32,
    release: impl FnOnce(*mut u32),
) -> i32 {
    let context = allocate();
    if context.is_null() { return -108; }
    #[cfg(not(target_os = "none"))]
    let mut handle = core::ptr::null_mut();
    #[cfg(not(target_os = "none"))]
    let handle_out = &mut handle as *mut *mut u8;
    #[cfg(target_os = "none")]
    let handle_out = context.add(1).cast::<*mut u8>();
    let status = acquire(mode & 0xff, handle_out);
    let result = if status == 0 {
        #[cfg(not(target_os = "none"))]
        context.add(1).write(handle as usize as u32);
        context.write(0x7374_726d);
        context as usize as u32
    } else {
        release(context);
        0
    };
    out_context.write(result);
    status
}

/// Construct an eight-byte firmware stream context from a request record.
///
/// # Safety
/// `out_context` must be writable after successful allocation. `request`
/// must satisfy `opaque_handle_acquire`'s request-record contract. Returned
/// context and handle words are firmware-width pointers.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn data_stream_context_create(
    out_context: *mut u32, request: u32, mode: u32,
) -> i32 {
    create_context(out_context, mode,
        || calloc_tag4(8).cast(),
        |mode, out| opaque_handle_acquire(request as usize as *const u8, 0x6461_7461, mode, out),
        |context| free_tag4(context.cast()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocation_failure_preserves_output_and_skips_acquisition() {
        let mut output = 0xfeed_beef;
        let status = unsafe { create_context(&mut output, 1,
            || core::ptr::null_mut(), |_, _| panic!("acquire after OOM"),
            |_| panic!("free after OOM")) };
        assert_eq!(status, -108);
        assert_eq!(output, 0xfeed_beef);
    }

    #[test]
    fn success_stamps_context_and_truncates_mode_to_low_byte() {
        for mode in [1, 2, 3, 0x101, 0xffff_ff03] {
            let mut context = [0u32; 2];
            let mut output = 0;
            let status = unsafe { create_context(&mut output, mode,
                || context.as_mut_ptr(), |actual_mode, out| {
                    assert_eq!(actual_mode, mode & 255);
                    out.write(0x12345678usize as *mut u8);
                    0
                }, |_| panic!("free accepted handle")) };
            assert_eq!(status, 0);
            assert_eq!(context, [0x7374726d, 0x12345678]);
            assert_eq!(output, context.as_mut_ptr() as usize as u32);
        }
    }

    #[test]
    fn acquisition_failure_frees_before_clearing_output_and_preserves_status() {
        for error in [-50, -108, 7, i32::MIN] {
            let mut context = [0u32; 2];
            let pointer = context.as_mut_ptr();
            let mut output = 0xfeed_beefu32;
            let out = &mut output as *mut u32;
            let mut freed = false;
            let status = unsafe { create_context(out, 0,
                || pointer, |_, _| error, |released| {
                    assert_eq!(released, pointer);
                    assert_eq!(out.read(), 0xfeed_beef);
                    freed = true;
                }) };
            assert!(freed);
            assert_eq!(status, error);
            assert_eq!(output, 0);
            assert_eq!(context, [0, 0]);
        }
    }
}
